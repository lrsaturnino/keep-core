package spv

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/keep-network/keep-core/pkg/bitcoin"
)

// populateBlockHeaders adds headers for [fromHeight, toHeight] inclusive using
// difficultyAt(height) for each block's Bits-derived difficulty.
func populateBlockHeaders(
	lbc *localBitcoinChain,
	fromHeight, toHeight uint,
	difficultyAt func(uint) *big.Int,
) error {
	for h := fromHeight; h <= toHeight; h++ {
		header := blockHeaderWithDifficulty(difficultyAt(h))
		if err := lbc.addBlockHeader(h, header); err != nil {
			return err
		}
	}
	return nil
}

// blockHeaderWithDifficulty returns a header whose Difficulty() matches the
// given value (within Bitcoin compact encoding precision). Powers of two and
// small values round-trip exactly.
func blockHeaderWithDifficulty(difficulty *big.Int) *bitcoin.BlockHeader {
	maxTarget := new(big.Int)
	maxTarget.SetString(
		"ffff0000000000000000000000000000000000000000000000000000",
		16,
	)
	target := new(big.Int).Div(maxTarget, difficulty)
	bits := blockchain.BigToCompact(target)
	return &bitcoin.BlockHeader{Bits: bits}
}

type localBitcoinChain struct {
	mutex sync.Mutex

	transactions             []*bitcoin.Transaction
	transactionConfirmations map[bitcoin.Hash]uint
	blockHeaders             map[uint]*bitcoin.BlockHeader
}

func newLocalBitcoinChain() *localBitcoinChain {
	return &localBitcoinChain{
		transactions:             make([]*bitcoin.Transaction, 0),
		transactionConfirmations: make(map[bitcoin.Hash]uint),
		blockHeaders:             make(map[uint]*bitcoin.BlockHeader),
	}
}

func (lbc *localBitcoinChain) GetTransaction(transactionHash bitcoin.Hash) (
	*bitcoin.Transaction,
	error,
) {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	for _, transaction := range lbc.transactions {
		if transaction.Hash() == transactionHash {
			return transaction, nil
		}
	}

	return nil, fmt.Errorf("transaction not found")
}

func (lbc *localBitcoinChain) GetTransactionConfirmations(_ context.Context, transactionHash bitcoin.Hash) (
	uint,
	error,
) {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	if transactionConfirmations, exists :=
		lbc.transactionConfirmations[transactionHash]; exists {
		return transactionConfirmations, nil
	}

	return 0, fmt.Errorf("transaction not found")
}

func (lbc *localBitcoinChain) BroadcastTransaction(transaction *bitcoin.Transaction) error {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	transactionHash := transaction.Hash()

	for _, existingTransaction := range lbc.transactions {
		if transactionHash == existingTransaction.Hash() {
			return fmt.Errorf("transaction already exists")
		}
	}

	lbc.transactions = append(lbc.transactions, transaction)

	return nil
}

func (lbc *localBitcoinChain) GetLatestBlockHeight() (uint, error) {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	// Return the highest block header's height.
	blockchainTip := uint(0)
	for blockHeaderHeight := range lbc.blockHeaders {
		if blockHeaderHeight > blockchainTip {
			blockchainTip = blockHeaderHeight
		}
	}

	if blockchainTip == 0 {
		return 0, fmt.Errorf("block headers not found")
	}

	return blockchainTip, nil
}

func (lbc *localBitcoinChain) GetBlockHeader(blockHeight uint) (
	*bitcoin.BlockHeader,
	error,
) {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	if blockHeader, exists := lbc.blockHeaders[blockHeight]; exists {
		return blockHeader, nil
	}

	return nil, fmt.Errorf("block header does not exist")
}

func (lbc *localBitcoinChain) GetTransactionMerkleProof(
	transactionHash bitcoin.Hash,
	blockHeight uint,
) (*bitcoin.TransactionMerkleProof, error) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) GetTransactionsForPublicKeyHash(
	publicKeyHash [20]byte,
	limit int,
) ([]*bitcoin.Transaction, error) {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	p2pkh, err := bitcoin.PayToPublicKeyHash(publicKeyHash)
	if err != nil {
		return nil, err
	}

	p2wpkh, err := bitcoin.PayToWitnessPublicKeyHash(publicKeyHash)
	if err != nil {
		return nil, err
	}

	matchingTransactions := make([]*bitcoin.Transaction, 0)

	for _, transaction := range lbc.transactions {
		for _, output := range transaction.Outputs {
			script := output.PublicKeyScript
			if bytes.Equal(script, p2pkh) || bytes.Equal(script, p2wpkh) {
				matchingTransactions = append(matchingTransactions, transaction)
				break
			}
		}
	}

	if len(matchingTransactions) > limit {
		return matchingTransactions[len(matchingTransactions)-limit:], nil
	}

	return matchingTransactions, nil
}

func (lbc *localBitcoinChain) GetTxHashesForPublicKeyHash(
	publicKeyHash [20]byte,
) ([]bitcoin.Hash, error) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) GetMempoolForPublicKeyHash(publicKeyHash [20]byte) (
	[]*bitcoin.Transaction,
	error,
) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) GetUtxosForPublicKeyHash(
	publicKeyHash [20]byte,
) ([]*bitcoin.UnspentTransactionOutput, error) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) GetMempoolUtxosForPublicKeyHash(
	publicKeyHash [20]byte,
) ([]*bitcoin.UnspentTransactionOutput, error) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) EstimateSatPerVByteFee(blocks uint32) (
	int64,
	error,
) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) GetCoinbaseTxHash(blockHeight uint) (
	bitcoin.Hash,
	error,
) {
	panic("unsupported")
}

func (lbc *localBitcoinChain) addBlockHeader(
	blockNumber uint,
	blockHeader *bitcoin.BlockHeader,
) error {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	if _, exists := lbc.blockHeaders[blockNumber]; exists {
		return fmt.Errorf("block header already exists")
	}

	lbc.blockHeaders[blockNumber] = blockHeader

	return nil
}

func (lbc *localBitcoinChain) addTransactionConfirmations(
	transactionHash bitcoin.Hash,
	transactionConfirmations uint,
) error {
	lbc.mutex.Lock()
	defer lbc.mutex.Unlock()

	if _, exists := lbc.transactionConfirmations[transactionHash]; exists {
		return fmt.Errorf("transaction confirmations already set")
	}

	lbc.transactionConfirmations[transactionHash] = transactionConfirmations

	return nil
}

// countingHeaderGetter wraps a header getter (typically
// localBitcoinChain.GetBlockHeader) with a per-height call counter and optional
// per-height failure injection. Tests use it to assert how many times the
// backend is hit and that the header cache does not cache failures.
type countingHeaderGetter struct {
	inner        func(uint) (*bitcoin.BlockHeader, error)
	mutex        sync.Mutex
	calls        map[uint]int
	failuresLeft map[uint]int
}

func newCountingHeaderGetter(
	inner func(uint) (*bitcoin.BlockHeader, error),
) *countingHeaderGetter {
	return &countingHeaderGetter{
		inner:        inner,
		calls:        make(map[uint]int),
		failuresLeft: make(map[uint]int),
	}
}

// get records the call and either injects a pending failure for the height or
// delegates to the wrapped getter.
func (c *countingHeaderGetter) get(blockHeight uint) (
	*bitcoin.BlockHeader,
	error,
) {
	c.mutex.Lock()
	c.calls[blockHeight]++
	if c.failuresLeft[blockHeight] > 0 {
		c.failuresLeft[blockHeight]--
		c.mutex.Unlock()
		return nil, fmt.Errorf(
			"injected header failure at height [%d]",
			blockHeight,
		)
	}
	c.mutex.Unlock()

	return c.inner(blockHeight)
}

// failNext makes the next `times` calls for the given height return an error
// before the wrapped getter is consulted.
func (c *countingHeaderGetter) failNext(blockHeight uint, times int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.failuresLeft[blockHeight] = times
}

// callsAt returns the number of get calls recorded for the given height.
func (c *countingHeaderGetter) callsAt(blockHeight uint) int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.calls[blockHeight]
}

// totalCalls returns the total number of get calls across all heights.
func (c *countingHeaderGetter) totalCalls() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	total := 0
	for _, n := range c.calls {
		total += n
	}
	return total
}
