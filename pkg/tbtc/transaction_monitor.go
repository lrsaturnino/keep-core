package tbtc

import (
	"context"
	"sync"
	"time"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

const (
	// defaultStuckTransactionThresholdBlocks is the number of Bitcoin blocks a
	// broadcast wallet transaction may remain unconfirmed before it is
	// considered stuck and an alert is raised. Roughly 6 hours at ~10 min per
	// block.
	defaultStuckTransactionThresholdBlocks = uint(36)

	// transactionMonitorCheckInterval is how often the monitor polls the
	// confirmation status of the tracked transactions.
	transactionMonitorCheckInterval = 5 * time.Minute

	// transactionMonitorMinConfirmations is the number of confirmations at
	// which a tracked transaction is considered mined and stops being tracked.
	transactionMonitorMinConfirmations = uint(1)

	// transactionMonitorMaxTracked bounds the number of tracked transactions to
	// prevent unbounded memory growth.
	transactionMonitorMaxTracked = 1000
)

// trackedTransaction holds the monitoring state of a single broadcast wallet
// transaction.
type trackedTransaction struct {
	walletPublicKeyHash [20]byte
	broadcastBlock      uint
	alerted             bool
}

// transactionMonitor watches broadcast wallet transactions (deposit sweeps,
// redemptions, moving funds) and raises an alert if one stays unconfirmed for
// longer than a configurable number of Bitcoin blocks. A stuck wallet
// transaction locks the wallet's main UTXO and blocks all subsequent wallet
// transactions until it confirms, so surfacing it lets operators intervene
// (e.g. mempool acceleration or CPFP) promptly.
//
// The monitor only emits a metric and a warn-level log identifying the wallet
// and transaction; automated recovery (fee-bumping / RBF) is intentionally out
// of scope (see threshold-network/keep-core#4171).
type transactionMonitor struct {
	btcChain bitcoin.Chain

	mu      sync.Mutex
	tracked map[bitcoin.Hash]*trackedTransaction

	thresholdBlocks uint

	metricsRecorder clientinfo.PerformanceMetricsRecorder
}

func newTransactionMonitor(btcChain bitcoin.Chain) *transactionMonitor {
	return &transactionMonitor{
		btcChain:        btcChain,
		tracked:         make(map[bitcoin.Hash]*trackedTransaction),
		thresholdBlocks: defaultStuckTransactionThresholdBlocks,
	}
}

// setMetricsRecorder wires the performance metrics recorder used to expose the
// stuck-transaction metric. It is safe to call after construction.
func (tm *transactionMonitor) setMetricsRecorder(
	recorder clientinfo.PerformanceMetricsRecorder,
) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.metricsRecorder = recorder
}

// track registers a freshly broadcast wallet transaction for confirmation
// monitoring. It is a no-op if the transaction is already tracked or the
// tracking table is full.
func (tm *transactionMonitor) track(
	txHash bitcoin.Hash,
	walletPublicKeyHash [20]byte,
) {
	broadcastBlock, err := tm.btcChain.GetLatestBlockHeight()
	if err != nil {
		logger.Warnf(
			"transaction monitor cannot read latest block height while "+
				"tracking transaction [%s]: [%v]",
			txHash.Hex(bitcoin.ReversedByteOrder),
			err,
		)
		return
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, ok := tm.tracked[txHash]; ok {
		return
	}

	if len(tm.tracked) >= transactionMonitorMaxTracked {
		logger.Warnf(
			"transaction monitor tracking table is full ([%d]); not tracking "+
				"transaction [%s]",
			transactionMonitorMaxTracked,
			txHash.Hex(bitcoin.ReversedByteOrder),
		)
		return
	}

	tm.tracked[txHash] = &trackedTransaction{
		walletPublicKeyHash: walletPublicKeyHash,
		broadcastBlock:      broadcastBlock,
	}
}

// run starts the monitor's polling loop. It blocks until the context is done.
func (tm *transactionMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(transactionMonitorCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tm.check()
		}
	}
}

// check polls the confirmation status of every tracked transaction once. It
// drops confirmed transactions and alerts (once) on those that have remained
// unconfirmed for longer than the stuck threshold.
func (tm *transactionMonitor) check() {
	latestBlock, err := tm.btcChain.GetLatestBlockHeight()
	if err != nil {
		logger.Warnf(
			"transaction monitor cannot read latest block height: [%v]",
			err,
		)
		return
	}

	// Snapshot the tracked set so chain calls are not made under the lock.
	tm.mu.Lock()
	snapshot := make(map[bitcoin.Hash]trackedTransaction, len(tm.tracked))
	for hash, t := range tm.tracked {
		snapshot[hash] = *t
	}
	tm.mu.Unlock()

	for txHash, t := range snapshot {
		confirmations, err := tm.btcChain.GetTransactionConfirmations(txHash)
		if err == nil && confirmations >= transactionMonitorMinConfirmations {
			// The transaction is mined; stop tracking it.
			tm.mu.Lock()
			delete(tm.tracked, txHash)
			tm.mu.Unlock()
			continue
		}

		// Still unconfirmed (in the mempool) or not yet found. A lookup error is
		// treated the same as unconfirmed: it does not indicate the transaction
		// confirmed, and it may be transient.
		var blocksOutstanding uint
		if latestBlock >= t.broadcastBlock {
			blocksOutstanding = latestBlock - t.broadcastBlock
		}

		if blocksOutstanding <= tm.thresholdBlocks || t.alerted {
			continue
		}

		logger.Warnf(
			"wallet transaction [%s] for wallet [0x%x] has been unconfirmed "+
				"for [%d] blocks (threshold [%d]); it may be stuck in the "+
				"mempool and blocking subsequent wallet transactions - consider "+
				"fee-bumping or accelerating it",
			txHash.Hex(bitcoin.ReversedByteOrder),
			t.walletPublicKeyHash,
			blocksOutstanding,
			tm.thresholdBlocks,
		)

		tm.mu.Lock()
		if tracked, ok := tm.tracked[txHash]; ok {
			tracked.alerted = true
		}
		if tm.metricsRecorder != nil {
			tm.metricsRecorder.IncrementCounter(
				clientinfo.MetricStuckWalletTransactionsTotal, 1,
			)
		}
		tm.mu.Unlock()
	}
}
