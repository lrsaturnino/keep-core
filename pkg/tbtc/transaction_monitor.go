package tbtc

import (
	"context"
	"sync"
	"time"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

const (
	// defaultStuckTransactionThreshold is how long a broadcast wallet
	// transaction may remain unconfirmed before it is considered stuck and an
	// alert is raised (~6 hours).
	defaultStuckTransactionThreshold = 6 * time.Hour

	// transactionMonitorCheckInterval is how often the monitor polls the
	// confirmation status of the tracked transactions.
	transactionMonitorCheckInterval = 5 * time.Minute

	// transactionMonitorMinConfirmations is the number of confirmations at
	// which a tracked transaction is considered mined and stops being tracked.
	transactionMonitorMinConfirmations = uint(1)

	// transactionMonitorMaxTracked bounds the number of tracked transactions to
	// prevent unbounded memory growth.
	transactionMonitorMaxTracked = 1000

	// transactionMonitorMaxTrackingAge is how long a still-unconfirmed
	// transaction is tracked before the monitor gives up on it - e.g. it was
	// dropped from the mempool and will never confirm. Bounding the tracking
	// duration prevents never-confirming transactions from filling up the
	// tracking table and starving monitoring of new transactions (~24 hours).
	transactionMonitorMaxTrackingAge = 24 * time.Hour

	// transactionMonitorCheckBudget bounds the wall-clock time of a single check
	// pass so that a slow chain call cannot stall monitoring of every remaining
	// transaction; transactions not reached within the budget are handled on the
	// next pass.
	transactionMonitorCheckBudget = 2 * time.Minute
)

// trackedTransaction holds the monitoring state of a single broadcast wallet
// transaction.
type trackedTransaction struct {
	walletPublicKeyHash [20]byte
	broadcastAt         time.Time
	alerted             bool
}

// transactionMonitor watches broadcast wallet transactions (deposit sweeps,
// redemptions, moving funds) and raises an alert if one stays unconfirmed for
// longer than a configurable duration. A stuck wallet transaction locks the
// wallet's main UTXO and blocks all subsequent wallet transactions until it
// confirms, so surfacing it lets operators intervene (e.g. mempool acceleration
// or CPFP) promptly.
//
// The monitor only emits a metric and a warn-level log identifying the wallet
// and transaction; automated recovery (fee-bumping / RBF) is intentionally out
// of scope (see threshold-network/keep-core#4171). Alerting is left to the
// operator's monitoring stack. Every wallet operator that broadcasts a given
// transaction tracks it independently, so the metric and log are emitted per
// operator and should be de-duplicated by transaction hash downstream.
//
// The tracked set is in-memory only. A transaction that is already stuck when
// the node restarts is not re-tracked (it was broadcast by the previous
// process), so cross-restart stuck transactions are not detected here; they
// remain covered by the coarser wallet-level liveness metrics.
type transactionMonitor struct {
	btcChain bitcoin.Chain

	mu      sync.Mutex
	tracked map[bitcoin.Hash]*trackedTransaction

	threshold time.Duration

	metricsRecorder clientinfo.PerformanceMetricsRecorder
}

func newTransactionMonitor(btcChain bitcoin.Chain) *transactionMonitor {
	return &transactionMonitor{
		btcChain:  btcChain,
		tracked:   make(map[bitcoin.Hash]*trackedTransaction),
		threshold: defaultStuckTransactionThreshold,
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
// tracking table is full. It performs no network calls, so it never blocks the
// broadcast path or silently drops a transaction due to a chain lookup failure.
func (tm *transactionMonitor) track(
	txHash bitcoin.Hash,
	walletPublicKeyHash [20]byte,
) {
	tm.mu.Lock()

	if _, ok := tm.tracked[txHash]; ok {
		tm.mu.Unlock()
		return
	}

	if len(tm.tracked) >= transactionMonitorMaxTracked {
		// A full table means a real broadcast transaction goes unmonitored;
		// surface it as a metric (emitted outside the lock) as well as a log.
		recorder := tm.metricsRecorder
		tm.mu.Unlock()

		logger.Warnf(
			"transaction monitor tracking table is full ([%d]); transaction "+
				"[%s] will not be monitored",
			transactionMonitorMaxTracked,
			txHash.Hex(bitcoin.ReversedByteOrder),
		)
		if recorder != nil {
			recorder.IncrementCounter(
				clientinfo.MetricUnmonitoredWalletTransactionsTotal, 1,
			)
		}
		return
	}

	tm.tracked[txHash] = &trackedTransaction{
		walletPublicKeyHash: walletPublicKeyHash,
		broadcastAt:         time.Now(),
	}
	tm.mu.Unlock()
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
// drops confirmed transactions, gives up on ones that have been unconfirmed for
// too long, and alerts (once) on those that have remained unconfirmed for longer
// than the stuck threshold.
//
// check is only ever called from the single run loop goroutine. track may run
// concurrently but only inserts new entries, so the per-entry alerted flag is
// only ever mutated here, under the mutex.
func (tm *transactionMonitor) check() {
	now := time.Now()
	deadline := now.Add(transactionMonitorCheckBudget)

	// Snapshot the tracked set so chain calls are not made under the lock.
	tm.mu.Lock()
	snapshot := make(map[bitcoin.Hash]trackedTransaction, len(tm.tracked))
	for hash, t := range tm.tracked {
		snapshot[hash] = *t
	}
	tm.mu.Unlock()

	for txHash, t := range snapshot {
		// Bound the wall-clock time of a single pass so a run of slow chain calls
		// cannot stall monitoring of every transaction behind them; the remaining
		// transactions are picked up on the next pass. The deadline is checked
		// between calls; each individual GetTransactionConfirmations call is
		// separately bounded by the Electrum client's own operation timeouts, so a
		// single call cannot block the pass indefinitely.
		if time.Now().After(deadline) {
			logger.Warnf(
				"transaction monitor check pass exceeded its time budget [%s]; "+
					"deferring the remaining transactions to the next pass",
				transactionMonitorCheckBudget,
			)
			break
		}

		confirmations, err := tm.btcChain.GetTransactionConfirmations(txHash)
		if err == nil && confirmations >= transactionMonitorMinConfirmations {
			// The transaction is mined; stop tracking it.
			tm.remove(txHash)
			continue
		}

		// Still unconfirmed (in the mempool) or not found. A lookup error is
		// treated the same as unconfirmed: it does not indicate the transaction
		// confirmed and may be transient.
		outstanding := now.Sub(t.broadcastAt)

		// Alert (once) if the transaction has been unconfirmed past the stuck
		// threshold. This runs before the give-up eviction below so that a
		// transaction first observed after the maximum tracking age still fires
		// exactly one alert instead of being silently evicted.
		if outstanding > tm.threshold && !t.alerted {
			logger.Warnf(
				"wallet transaction [%s] for wallet [0x%x] has been unconfirmed "+
					"for [%s] (threshold [%s]); it may be stuck in the mempool "+
					"and blocking subsequent wallet transactions - consider "+
					"fee-bumping or accelerating it",
				txHash.Hex(bitcoin.ReversedByteOrder),
				t.walletPublicKeyHash,
				outstanding.Round(time.Minute),
				tm.threshold,
			)

			// Mark as alerted under the lock, but emit the metric outside the
			// lock to avoid holding it during an external call.
			tm.mu.Lock()
			if tracked, ok := tm.tracked[txHash]; ok {
				tracked.alerted = true
			}
			recorder := tm.metricsRecorder
			tm.mu.Unlock()

			if recorder != nil {
				recorder.IncrementCounter(
					clientinfo.MetricStuckWalletTransactionsTotal, 1,
				)
			}
		}

		// Give up on transactions that have been unconfirmed for too long (e.g.
		// dropped from the mempool) so they cannot fill the tracking table.
		if outstanding > transactionMonitorMaxTrackingAge {
			logger.Warnf(
				"giving up monitoring wallet transaction [%s] for wallet "+
					"[0x%x]; it has been unconfirmed for [%s]",
				txHash.Hex(bitcoin.ReversedByteOrder),
				t.walletPublicKeyHash,
				outstanding.Round(time.Minute),
			)
			tm.remove(txHash)
		}
	}
}

// remove stops tracking the transaction with the given hash.
func (tm *transactionMonitor) remove(txHash bitcoin.Hash) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.tracked, txHash)
}
