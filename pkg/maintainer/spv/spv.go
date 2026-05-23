package spv

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/keep-network/keep-core/pkg/tbtc"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/maintainer/btcdiff"
)

var logger = log.Logger("keep-maintainer-spv")

// The length of the Bitcoin difficulty epoch in blocks.
const difficultyEpochLength = 2016

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

// proofTypes holds the information about proof types supported by the
// SPV maintainer.
var proofTypes = map[tbtc.WalletActionType]struct {
	unprovenTransactionsGetter unprovenTransactionsGetter
	transactionProofSubmitter  transactionProofSubmitter
}{
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
}

func (sm *spvMaintainer) startControlLoop(ctx context.Context) {
	logger.Info("starting SPV maintainer")

	defer func() {
		logger.Info("stopping SPV maintainer")
	}()

	for {
		err := sm.maintainSpv(ctx)
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

func (sm *spvMaintainer) maintainSpv(ctx context.Context) error {
	for {
		for action, v := range proofTypes {
			logger.Infof("starting [%s] proof task execution...", action)

			if err := sm.proveTransactions(
				v.unprovenTransactionsGetter,
				v.transactionProofSubmitter,
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
	fundingOutputValue := previousTransaction.Outputs[fundingOutputIndex].Value

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

// proofRangeWithinRelayWindow returns true iff [proofStartBlock, proofEndBlock]
// is one of: entirely in previous epoch, entirely in current epoch, or spanning
// exactly previous→current (matches Bridge SPV assumptions).
func proofRangeWithinRelayWindow(
	proofStartBlock, proofEndBlock uint64,
	previousEpoch, currentEpoch uint64,
) bool {
	if proofEndBlock < proofStartBlock {
		return false
	}
	ps := proofStartBlock / difficultyEpochLength
	pe := proofEndBlock / difficultyEpochLength
	if ps < previousEpoch || pe > currentEpoch {
		return false
	}
	if ps == currentEpoch && pe == currentEpoch {
		return true
	}
	if ps == previousEpoch && pe == previousEpoch {
		return true
	}
	if ps == previousEpoch && pe == currentEpoch {
		return true
	}
	return false
}

// getProofInfo returns information about the SPV proof. It includes the
// information whether the transaction proof range is within the previous and
// current difficulty epochs as seen by the relay, the accumulated number of
// confirmations and the required number of confirmations.
//
// Required confirmations are computed to match Bridge.evaluateProofDifficulty:
// the concatenated block headers must sum to at least
// requestedDifficulty * txProofDifficultyFactor, where requestedDifficulty is the
// relay epoch difficulty that matches the first header (same as on-chain).
// Per-block difficulties can vary (e.g. testnet4 min-difficulty blocks), so we
// walk forward summing actual header difficulties instead of assuming a fixed
// block count × epoch-average difficulty.
func getProofInfo(
	transactionHash bitcoin.Hash,
	btcChain bitcoin.Chain,
	spvChain Chain,
	btcDiffChain btcdiff.Chain,
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

	currentEpoch, err := btcDiffChain.CurrentEpoch()
	if err != nil {
		return false, 0, 0, fmt.Errorf("failed to get current epoch: [%v]", err)
	}
	previousEpoch := currentEpoch - 1

	proofStartBlock := uint64(latestBlockHeight) - uint64(accumulatedConfirmations) + 1

	firstHeader, err := btcChain.GetBlockHeader(uint(proofStartBlock))
	if err != nil {
		return false, 0, 0, fmt.Errorf(
			"failed to get block header at proof start: [%v]",
			err,
		)
	}
	firstHeaderDiff := firstHeader.Difficulty()

	var requestedDiff *big.Int
	switch {
	case firstHeaderDiff.Cmp(currentEpochDifficulty) == 0:
		requestedDiff = currentEpochDifficulty
	case firstHeaderDiff.Cmp(previousEpochDifficulty) == 0:
		requestedDiff = previousEpochDifficulty
	default:
		// Bridge would revert "Not at current or previous difficulty".
		// This typically means the proof's first block was mined at a
		// min-difficulty (e.g. testnet4); such a transaction is unprovable
		// against the relay until it is buried under enough work.
		logger.Warnf(
			"skipped proving transaction [%s]; first header difficulty "+
				"[%s] matches neither current epoch [%s] nor previous "+
				"epoch [%s] difficulty",
			transactionHash.Hex(bitcoin.ReversedByteOrder),
			firstHeaderDiff.String(),
			currentEpochDifficulty.String(),
			previousEpochDifficulty.String(),
		)
		return false, 0, 0, nil
	}

	totalDifficultyRequired := new(big.Int).Mul(
		requestedDiff,
		txProofDifficultyFactor,
	)

	// On chains with min-difficulty blocks (e.g. testnet4) the per-header
	// difficulty walk can need many more blocks than txProofDifficultyFactor
	// to accumulate enough work. Emit a warning once the walk grows past a
	// soft threshold so the operator can notice excessive header RPCs.
	rpcWarnThreshold := txProofDifficultyFactor.Uint64() * 4

	// Seed the running sum with firstHeader (already fetched above) so the
	// loop does not refetch the proof-start header on iteration zero.
	sumDifficulty := new(big.Int).Set(firstHeaderDiff)
	requiredBlockCount := uint64(1)
	reached := sumDifficulty.Cmp(totalDifficultyRequired) >= 0
	for height := proofStartBlock + 1; !reached && height <= uint64(latestBlockHeight); height++ {
		hdr, err := btcChain.GetBlockHeader(uint(height))
		if err != nil {
			return false, 0, 0, fmt.Errorf(
				"failed to get block header at height %d: [%v]",
				height,
				err,
			)
		}
		sumDifficulty.Add(sumDifficulty, hdr.Difficulty())
		requiredBlockCount++
		if requiredBlockCount == rpcWarnThreshold+1 {
			logger.Warnf(
				"transaction [%s] still has not accumulated enough "+
					"difficulty after walking [%d] headers; per-block work "+
					"appears unusually low (e.g. min-difficulty blocks)",
				transactionHash.Hex(bitcoin.ReversedByteOrder),
				requiredBlockCount,
			)
		}
		if sumDifficulty.Cmp(totalDifficultyRequired) >= 0 {
			reached = true
		}
	}

	if !reached {
		// Not enough accumulated work in the chain yet; wait for more blocks.
		available := uint64(latestBlockHeight) - proofStartBlock + 1
		return true, accumulatedConfirmations, uint(available + 1), nil
	}

	proofEndBlock := proofStartBlock + requiredBlockCount - 1
	if !proofRangeWithinRelayWindow(
		proofStartBlock,
		proofEndBlock,
		previousEpoch,
		currentEpoch,
	) {
		return false, 0, 0, nil
	}

	return true, accumulatedConfirmations, uint(requiredBlockCount), nil
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
