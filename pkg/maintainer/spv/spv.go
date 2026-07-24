package spv

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime/debug"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"

	"github.com/keep-network/keep-core/pkg/tbtc"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/maintainer/btcdiff"
)

var logger = log.Logger("keep-maintainer-spv")

// minDifficultyTarget is the decoded Bitcoin minimum-difficulty (DIFF1) target.
// It matches the Bridge's minimum-difficulty target (BTCUtils.DIFF1_TARGET)
// used by BitcoinTx.determineRequestedDifficulty. Decoded targets, not integer
// difficulties, must be compared: multiple compact-bits encodings round to
// integer difficulty 1 while decoding to different targets, so only a header
// whose decoded target equals this exact value is a skippable DIFF1 header.
var minDifficultyTarget = blockchain.CompactToBig(0x1d00ffff)

func Initialize(
	ctx context.Context,
	config Config,
	spvChain Chain,
	btcDiffChain btcdiff.Chain,
	btcChain bitcoin.Chain,
) {
	spvMaintainer := &spvMaintainer{
		config:       config,
		spvChain:     spvChain,
		btcDiffChain: btcDiffChain,
		btcChain:     btcChain,
		proofTypes:   proofTypes,
	}

	go spvMaintainer.startControlLoop(ctx)
}

// globalMetricsRecorder is a package-level variable to access metrics recorder
// from proof submission functions.
var (
	globalMetricsRecorderMu sync.RWMutex
	globalMetricsRecorder   interface {
		IncrementCounter(name string, value float64)
	}
)

// SetMetricsRecorder sets the metrics recorder for the SPV maintainer.
// This allows recording metrics for proof submissions.
func SetMetricsRecorder(recorder interface {
	IncrementCounter(name string, value float64)
}) {
	globalMetricsRecorderMu.Lock()
	defer globalMetricsRecorderMu.Unlock()
	globalMetricsRecorder = recorder
}

// getMetricsRecorder safely retrieves the metrics recorder.
func getMetricsRecorder() interface {
	IncrementCounter(name string, value float64)
} {
	globalMetricsRecorderMu.RLock()
	defer globalMetricsRecorderMu.RUnlock()
	return globalMetricsRecorder
}

// MetricsRecorder returns the metrics recorder currently wired into the SPV
// maintainer, or nil when none is set. It is the exported read counterpart to
// SetMetricsRecorder and lets the maintainer startup path assert that the
// recorder was actually wired, without duplicating the wiring in tests.
func MetricsRecorder() interface {
	IncrementCounter(name string, value float64)
} {
	return getMetricsRecorder()
}

// proofType bundles the unproven-transactions source and the proof submitter
// for a single SPV proof type.
type proofType struct {
	unprovenTransactionsGetter unprovenTransactionsGetter
	transactionProofSubmitter  transactionProofSubmitter
}

// proofTypes holds the information about proof types supported by the
// SPV maintainer.
var proofTypes = map[tbtc.WalletActionType]proofType{
	tbtc.ActionDepositSweep: {
		unprovenTransactionsGetter: getUnprovenDepositSweepTransactions,
		transactionProofSubmitter:  SubmitDepositSweepProof,
	},
	tbtc.ActionRedemption: {
		unprovenTransactionsGetter: getUnprovenRedemptionTransactions,
		transactionProofSubmitter:  SubmitRedemptionProof,
	},
	tbtc.ActionMovingFunds: {
		unprovenTransactionsGetter: getUnprovenMovingFundsTransactions,
		transactionProofSubmitter:  SubmitMovingFundsProof,
	},
	tbtc.ActionMovedFundsSweep: {
		unprovenTransactionsGetter: getUnprovenMovedFundsSweepTransactions,
		transactionProofSubmitter:  SubmitMovedFundsSweepProof,
	},
}

type spvMaintainer struct {
	config       Config
	spvChain     Chain
	btcDiffChain btcdiff.Chain
	btcChain     bitcoin.Chain
	// proofTypes are the proof types processed in each maintainSpv pass. It
	// defaults to the package-level proofTypes map and is a field so tests can
	// drive a real pass with controlled proof types.
	proofTypes map[tbtc.WalletActionType]proofType
}

func (sm *spvMaintainer) startControlLoop(ctx context.Context) {
	sm.runControlLoop(ctx, sm.maintainSpv)
}

// runControlLoop repeatedly runs the given maintainer iteration, backing off by
// RestartBackoffTime between runs and exiting when the context is cancelled.
// Each iteration runs under runMaintainSpv's panic-recovery boundary, so a
// panic in one iteration is logged and converted into a restart rather than
// crashing the dedicated maintainer process. The iteration function is a
// parameter so the loop's restart behavior can be exercised in tests.
func (sm *spvMaintainer) runControlLoop(
	ctx context.Context,
	iteration func(context.Context) error,
) {
	logger.Info("starting SPV maintainer")

	defer func() {
		logger.Info("stopping SPV maintainer")
	}()

	for {
		err := sm.runMaintainSpv(ctx, iteration)
		if err != nil {
			logger.Errorf(
				"error while maintaining SPV: [%v]; restarting maintainer",
				err,
			)
		}

		select {
		case <-time.After(sm.config.RestartBackoffTime):
		case <-ctx.Done():
			return
		}
	}
}

// runMaintainSpv runs a single maintainer iteration under a panic-recovery
// boundary. A panic inside the iteration is recovered, its value and a full Go
// stack trace are logged at error level, and it is converted into a non-nil
// error so the caller can follow the ordinary error/restart path instead of
// letting the panic terminate the dedicated maintainer process (which also runs
// the co-resident Bitcoin-difficulty maintainer). This is residual containment
// only; it does not replace the source-level bounds checks in the SPV
// maintainer. Go runtime fatal errors are not recoverable and are intentionally
// not handled here. The error return is named so the deferred recovery can set
// it.
func (sm *spvMaintainer) runMaintainSpv(
	ctx context.Context,
	iteration func(context.Context) error,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(
				"recovered from panic in SPV maintainer: [%v]\n%s",
				r,
				debug.Stack(),
			)
			err = fmt.Errorf("recovered from SPV maintainer panic: [%v]", r)
		}
	}()

	return iteration(ctx)
}

func (sm *spvMaintainer) maintainSpv(ctx context.Context) error {
	for {
		// Create one header cache per proof-task pass. Transactions with
		// overlapping proof windows - across all proof types processed in this
		// pass - reuse the same cached headers instead of repeatedly fetching
		// them from the Bitcoin backend. The cache is discarded before the idle
		// backoff and rebuilt on the next pass, so height-keyed entries never
		// survive a reorg between passes.
		headerCache := newBlockHeaderCache(sm.btcChain.GetBlockHeader)

		for action, v := range sm.proofTypes {
			logger.Infof("starting [%s] proof task execution...", action)

			if err := sm.proveTransactions(
				v.unprovenTransactionsGetter,
				v.transactionProofSubmitter,
				headerCache,
			); err != nil {
				return fmt.Errorf(
					"error while proving [%s] transactions: [%v]",
					action,
					err,
				)
			}

			logger.Infof("[%s] proof task completed", action)
		}

		logger.Infof(
			"proof tasks completed; next run in [%s]",
			sm.config.IdleBackoffTime,
		)

		select {
		case <-time.After(sm.config.IdleBackoffTime):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// unprovenTransactionsGetter is a type representing a function that is
// used to get unproven Bitcoin transactions.
type unprovenTransactionsGetter func(
	historyDepth uint64,
	transactionLimit int,
	btcChain bitcoin.Chain,
	spvChain Chain,
) (
	[]*bitcoin.Transaction,
	error,
)

// transactionProofSubmitter is a type representing a function that is used
// to submit the constructed SPV proof to the host chain.
type transactionProofSubmitter func(
	transactionHash bitcoin.Hash,
	requiredConfirmations uint,
	btcChain bitcoin.Chain,
	spvChain Chain,
) error

// proveTransactions gets unproven Bitcoin transactions using the provided
// unprovenTransactionsGetter, build the SPV proofs, and submits them using
// the provided transactionProofSubmitter.
func (sm *spvMaintainer) proveTransactions(
	unprovenTransactionsGetter unprovenTransactionsGetter,
	transactionProofSubmitter transactionProofSubmitter,
	headerCache *blockHeaderCache,
) error {
	transactions, err := unprovenTransactionsGetter(
		sm.config.HistoryDepth,
		sm.config.TransactionLimit,
		sm.btcChain,
		sm.spvChain,
	)
	if err != nil {
		return fmt.Errorf("failed to get unproven transactions: [%v]", err)
	}

	logger.Infof("found [%d] unproven transaction(s)", len(transactions))

	for _, transaction := range transactions {
		// Print the transaction in the same endianness as block explorers do.
		transactionHashStr := transaction.Hash().Hex(bitcoin.ReversedByteOrder)

		logger.Infof(
			"proceeding with proof for transaction [%s]",
			transactionHashStr,
		)

		isProofWithinRelayRange, accumulatedConfirmations, requiredConfirmations, err := getProofInfo(
			transaction.Hash(),
			sm.btcChain,
			sm.spvChain,
			sm.btcDiffChain,
			headerCache,
		)
		if err != nil {
			return fmt.Errorf("failed to get proof info: [%v]", err)
		}

		if !isProofWithinRelayRange {
			// The required proof goes outside the previous and current
			// difficulty epochs as seen by the relay. Skip the transaction. It
			// will most likely be proven later.
			logger.Warnf(
				"skipped proving transaction [%s]; the range "+
					"of the required proof goes outside the previous and "+
					"current difficulty epochs as seen by the relay",
				transactionHashStr,
			)
			continue
		}

		if accumulatedConfirmations < requiredConfirmations {
			// Skip the transaction as it has not accumulated enough
			// confirmations. It will be proven later.
			logger.Infof(
				"skipped proving transaction [%s]; transaction "+
					"has [%v/%v] confirmations",
				transactionHashStr,
				accumulatedConfirmations,
				requiredConfirmations,
			)
			continue
		}

		err = transactionProofSubmitter(
			transaction.Hash(),
			requiredConfirmations,
			sm.btcChain,
			sm.spvChain,
		)
		if err != nil {
			return err
		}

		logger.Infof(
			"successfully submitted proof for transaction [%s]",
			transactionHashStr,
		)
	}

	logger.Infof("finished round of proving transactions")

	return nil
}

func isInputCurrentWalletsMainUTXO(
	fundingTxHash bitcoin.Hash,
	fundingOutputIndex uint32,
	walletPublicKeyHash [20]byte,
	btcChain bitcoin.Chain,
	spvChain Chain,
) (bool, error) {
	// Get the transaction the input originated from to calculate the input value.
	previousTransaction, err := btcChain.GetTransaction(fundingTxHash)
	if err != nil {
		return false, fmt.Errorf("failed to get previous transaction: [%v]", err)
	}
	fundingOutput, err := previousTransaction.OutputAt(fundingOutputIndex)
	if err != nil {
		return false, fmt.Errorf(
			"funding output index [%d] invalid for transaction [%s]: [%v]",
			fundingOutputIndex,
			fundingTxHash.String(),
			err,
		)
	}
	fundingOutputValue := fundingOutput.Value

	// Assume the input is the main UTXO and calculate hash.
	mainUtxoHash := spvChain.ComputeMainUtxoHash(&bitcoin.UnspentTransactionOutput{
		Outpoint: &bitcoin.TransactionOutpoint{
			TransactionHash: fundingTxHash,
			OutputIndex:     fundingOutputIndex,
		},
		Value: fundingOutputValue,
	})

	// Get the wallet and check if its main UTXO matches the calculated hash.
	wallet, err := spvChain.GetWallet(walletPublicKeyHash)
	if err != nil {
		return false, fmt.Errorf("failed to get wallet: [%v]", err)
	}

	return bytes.Equal(mainUtxoHash[:], wallet.MainUtxoHash[:]), nil
}

// blockHeaderCache memoizes successful GetBlockHeader lookups by Bitcoin block
// height for the lifetime of a single maintainSpv proof-task pass. Transactions
// with overlapping proof windows - possibly across different proof types in the
// same pass - otherwise re-walk and re-fetch the same headers from the Bitcoin
// backend. Only successful results are cached, so a transient backend failure
// is retried on a later call or pass. The cache is created fresh each pass and
// discarded before the idle backoff, which bounds memory and keeps height-keyed
// entries from surviving a reorg between passes. Access is currently
// single-threaded (proof types are processed sequentially); the mutex makes the
// at-most-one-fetch-per-height guarantee hold if that is ever parallelized.
type blockHeaderCache struct {
	getter  func(blockHeight uint) (*bitcoin.BlockHeader, error)
	mutex   sync.Mutex
	headers map[uint]*bitcoin.BlockHeader
}

// newBlockHeaderCache returns a blockHeaderCache backed by the given header
// getter, typically bitcoin.Chain.GetBlockHeader.
func newBlockHeaderCache(
	getter func(blockHeight uint) (*bitcoin.BlockHeader, error),
) *blockHeaderCache {
	return &blockHeaderCache{
		getter:  getter,
		headers: make(map[uint]*bitcoin.BlockHeader),
	}
}

// getBlockHeader returns the header at the given height, fetching it from the
// backend on the first request and serving the cached value afterwards. Errors
// are not cached.
func (c *blockHeaderCache) getBlockHeader(blockHeight uint) (
	*bitcoin.BlockHeader,
	error,
) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if header, exists := c.headers[blockHeight]; exists {
		return header, nil
	}

	header, err := c.getter(blockHeight)
	if err != nil {
		return nil, err
	}

	c.headers[blockHeight] = header
	return header, nil
}

// getProofInfo returns information about the SPV proof. It includes the
// information whether the transaction proof range is within the previous and
// current difficulty epochs as seen by the relay, the accumulated number of
// confirmations and the required number of confirmations. Block headers are
// read through the provided pass-scoped headerCache; tip, confirmation, and
// difficulty data come directly from the chains.
func getProofInfo(
	transactionHash bitcoin.Hash,
	btcChain bitcoin.Chain,
	spvChain Chain,
	btcDiffChain btcdiff.Chain,
	headerCache *blockHeaderCache,
) (
	bool, uint, uint, error,
) {
	latestBlockHeight, err := btcChain.GetLatestBlockHeight()
	if err != nil {
		return false, 0, 0, fmt.Errorf(
			"failed to get latest block height: [%v]",
			err,
		)
	}

	accumulatedConfirmations, err := btcChain.GetTransactionConfirmations(
		transactionHash,
	)
	if err != nil {
		return false, 0, 0, fmt.Errorf(
			"failed to get transaction confirmations: [%v]",
			err,
		)
	}

	txProofDifficultyFactor, err := spvChain.TxProofDifficultyFactor()
	if err != nil {
		return false, 0, 0, fmt.Errorf(
			"failed to get transaction proof difficulty factor: [%v]",
			err,
		)
	}

	currentEpochDifficulty, previousEpochDifficulty, err :=
		btcDiffChain.GetCurrentAndPrevEpochDifficulty()
	if err != nil {
		return false, 0, 0, fmt.Errorf(
			"failed to get Bitcoin epoch difficulties: [%v]",
			err,
		)
	}

	// Calculate the starting block of the proof.
	proofStartBlock := uint64(latestBlockHeight - accumulatedConfirmations + 1)

	// Walk the header chain forward, mirroring the Bridge's
	// BitcoinTx.determineRequestedDifficulty and evaluateProofDifficulty
	// behavior:
	// - minimum-difficulty (DIFF1) headers are skipped while looking for the
	//   decisive header, but only when both relay epoch difficulties are
	//   above minimum (testnet4 BIP94 blocks in real epochs),
	// - the first decisive header must match the relay's current or previous
	//   epoch difficulty; that value becomes the requested difficulty,
	// - headers are accumulated until their total observed difficulty reaches
	//   requested difficulty times the transaction proof difficulty factor.
	one := big.NewInt(1)
	skipMinDifficulty := currentEpochDifficulty.Cmp(one) > 0 &&
		previousEpochDifficulty.Cmp(one) > 0

	var requestedDiff *big.Int
	observedDiff := big.NewInt(0)
	headerCount := uint(0)

	for {
		blockHeight := proofStartBlock + uint64(headerCount)
		if blockHeight > uint64(latestBlockHeight) {
			// Not enough mined blocks yet to assemble the proof. Report the
			// number of headers needed so far plus one more; the caller will
			// see accumulated < required and skip the transaction for now.
			return true, accumulatedConfirmations, headerCount + 1, nil
		}

		header, err := headerCache.getBlockHeader(uint(blockHeight))
		if err != nil {
			return false, 0, 0, fmt.Errorf(
				"failed to get block header at height [%v]: [%v]",
				blockHeight,
				err,
			)
		}

		// Compare decoded targets, not integer difficulties, when identifying a
		// minimum-difficulty header (see minDifficultyTarget). Reject a
		// non-positive target before calling Difficulty(), which would divide by
		// a zero target.
		headerTarget := header.Target()
		if headerTarget.Sign() <= 0 {
			return false, 0, 0, fmt.Errorf(
				"invalid target [%v] for block header at height [%v]",
				headerTarget,
				blockHeight,
			)
		}

		headerDiff := header.Difficulty()
		headerCount++
		observedDiff.Add(observedDiff, headerDiff)

		if requestedDiff == nil {
			// Still looking for the decisive header.
			if skipMinDifficulty && headerTarget.Cmp(minDifficultyTarget) == 0 {
				continue
			}

			if headerDiff.Cmp(currentEpochDifficulty) == 0 {
				requestedDiff = currentEpochDifficulty
			} else if headerDiff.Cmp(previousEpochDifficulty) == 0 {
				requestedDiff = previousEpochDifficulty
			} else {
				// The Bridge would revert with "Not at current or previous
				// difficulty". The transaction is either too fresh (its epoch
				// is not yet proven in the relay) or too old. Skip it; it may
				// be proven in the future.
				return false, 0, 0, nil
			}
		}

		totalDifficultyRequired := new(big.Int).Mul(
			requestedDiff,
			txProofDifficultyFactor,
		)
		if observedDiff.Cmp(totalDifficultyRequired) >= 0 {
			return true, accumulatedConfirmations, headerCount, nil
		}
	}
}

// walletEvent is a type constraint representing wallet-related chain events.
type walletEvent interface {
	GetWalletPublicKeyHash() [20]byte
}

// uniqueWalletPublicKeyHashes parses the list of wallet-related events and
// returns a list of unique wallet public key hashes.
func uniqueWalletPublicKeyHashes[T walletEvent](events []T) [][20]byte {
	cache := make(map[string]struct{})
	var publicKeyHashes [][20]byte

	for _, event := range events {
		key := event.GetWalletPublicKeyHash()
		strKey := hex.EncodeToString(key[:])

		// Check for uniqueness
		if _, exists := cache[strKey]; !exists {
			cache[strKey] = struct{}{}
			publicKeyHashes = append(publicKeyHashes, key)
		}
	}

	return publicKeyHashes
}

// spvProofAssembler is a type representing a function that is used
// to assemble an SPV proof for the given transaction hash and confirmations
// count.
type spvProofAssembler func(
	transactionHash bitcoin.Hash,
	requiredConfirmations uint,
	btcChain bitcoin.Chain,
) (*bitcoin.Transaction, *bitcoin.SpvProof, error)
