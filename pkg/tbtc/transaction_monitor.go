package tbtc

import (
	"context"
	"sort"
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

	// transactionMonitorCheckBudget is the wall-clock budget requested for a
	// single check pass so that a slow chain call cannot stall monitoring of
	// every remaining transaction; transactions not reached within the budget
	// are handled on the next pass.
	//
	// It is a requested bound, not a guaranteed one. The monitor threads it into
	// the chain call as a context deadline, which is all a bitcoin.Chain
	// implementation is asked to honor. The production Electrum adapter has two
	// paths that can outlive it: GetTransactionConfirmations resolves the chain
	// tip through GetLatestBlockHeight, which takes no caller context, and
	// requests serialize on a plain mutex whose acquisition no context can
	// cancel. Bounding those needs its own review of Electrum request
	// serialization, so release evidence must say the budget is requested rather
	// than that every production lookup is strictly bounded by it.
	transactionMonitorCheckBudget = 2 * time.Minute
)

// trackedTransaction holds the monitoring state of a single broadcast wallet
// transaction.
type trackedTransaction struct {
	walletPublicKeyHash [20]byte
	broadcastAt         time.Time
	alerted             bool
}

// trackedTransactionSnapshot pairs a copy of a tracked transaction with its hash
// so the check loop can iterate an ordered snapshot outside the lock.
type trackedTransactionSnapshot struct {
	hash bitcoin.Hash
	trackedTransaction
}

// snapshotByAge returns a copy of the tracked transactions ordered by broadcast
// time, oldest first. Checking oldest first ensures the transactions closest to
// the stuck threshold are never starved when a check pass hits its time budget:
// Go map iteration order is randomized, so without an explicit ordering an
// unlucky old transaction could be skipped pass after pass and miss its
// threshold; with it, only the newest transactions - furthest from alerting -
// are ever deferred. The copy is taken under the lock; the sort is not.
func (tm *transactionMonitor) snapshotByAge() []trackedTransactionSnapshot {
	tm.mu.Lock()
	ordered := make([]trackedTransactionSnapshot, 0, len(tm.tracked))
	for hash, t := range tm.tracked {
		ordered = append(ordered, trackedTransactionSnapshot{hash, *t})
	}
	tm.mu.Unlock()

	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].broadcastAt.Before(ordered[j].broadcastAt)
	})

	return ordered
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

	// checkInterval is how often run polls the tracked transactions. It is
	// always the production transactionMonitorCheckInterval outside of package
	// tests, which shorten it so the run loop can be exercised without waiting
	// out a production tick. It is deliberately not configurable: the interval
	// is monitoring policy, not an operator knob, and shortening it in
	// production would multiply the confirmation-query load on the Bitcoin
	// backend.
	checkInterval time.Duration

	// checkFn is the check pass the run loop invokes on each tick; nil - the
	// production case - means check. Package tests substitute a recording
	// wrapper to observe whether the loop opened a pass at all.
	//
	// Nothing else can observe it. A pass entered on a cancelled context
	// returns at its own entry guard without a lookup, a metric, or any other
	// external effect, so with only the pass's guard in place, deleting the
	// loop's post-tick guard would change nothing any test could see. The two
	// guards defend different things - the loop's keeps a shutting-down node
	// from opening a pass, the pass's keeps one from issuing a request - and
	// this seam is what keeps the first independently provable.
	checkFn func(ctx context.Context)

	// publishMu serializes tracked-count gauge publication. It orders the read
	// of the tracked-set size against the recorder call that publishes it, so
	// concurrent inserts and removals cannot leave the gauge holding a stale
	// value once they settle. It is never held while acquiring mu in the
	// reverse order.
	publishMu sync.Mutex

	// stopped is closed once run has returned. The node starts run in its own
	// goroutine and keeps no handle on it, so this is the only way to observe
	// that the loop has actually finished rather than merely published its
	// final telemetry - the running gauge drops to zero while the goroutine is
	// still unwinding. sync.Once keeps a second run call from closing it twice;
	// a monitor is only ever run once (see the sole launch site in
	// runCoordinationLayer), but a panic is a poor way to report that.
	stopped     chan struct{}
	stoppedOnce sync.Once

	metricsRecorder clientinfo.PerformanceMetricsRecorder
}

func newTransactionMonitor(btcChain bitcoin.Chain) *transactionMonitor {
	return &transactionMonitor{
		btcChain:      btcChain,
		tracked:       make(map[bitcoin.Hash]*trackedTransaction),
		threshold:     defaultStuckTransactionThreshold,
		checkInterval: transactionMonitorCheckInterval,
		stopped:       make(chan struct{}),
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

	tm.publishTrackedCount()
}

// publishTrackedCount republishes the size of the tracked set. The recorder and
// the size are snapshotted under mu and the recorder is called after releasing
// it, so no external call is ever made under the monitor's own lock; publishMu
// keeps concurrent publishers ordered so the value that settles is the value of
// the last mutation.
func (tm *transactionMonitor) publishTrackedCount() {
	tm.publishMu.Lock()
	defer tm.publishMu.Unlock()

	tm.mu.Lock()
	recorder := tm.metricsRecorder
	count := len(tm.tracked)
	tm.mu.Unlock()

	if recorder != nil {
		recorder.SetGauge(
			clientinfo.MetricTransactionMonitorTrackedTransactions,
			float64(count),
		)
	}
}

// recorder returns the currently wired metrics recorder, or nil when metrics
// are disabled. Callers must not hold mu.
func (tm *transactionMonitor) recorder() clientinfo.PerformanceMetricsRecorder {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.metricsRecorder
}

// run starts the monitor's polling loop. It blocks until the context is done.
// The context is the node's run context, so the loop lives for as long as the
// node does and stops once the node cancels it after its shutdown drain.
func (tm *transactionMonitor) run(ctx context.Context) {
	// Registered first so it runs last: every other exit path - including the
	// refusal below - has finished by the time the loop reports itself stopped.
	defer tm.stoppedOnce.Do(func() { close(tm.stopped) })

	tm.mu.Lock()
	checkInterval := tm.checkInterval
	checkPass := tm.checkFn
	tm.mu.Unlock()

	if checkPass == nil {
		checkPass = tm.check
	}

	if checkInterval <= 0 {
		// Unreachable through the constructor, which always installs the
		// production interval. Refusing here keeps a future wiring mistake from
		// turning into a time.NewTicker panic that takes down the node.
		logger.Errorf(
			"transaction monitor check interval [%s] is not positive; "+
				"the monitor will not run",
			checkInterval,
		)
		return
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// The stuck- and unmonitored-transaction counters read zero whether or not
	// this loop is alive, so publish an explicit liveness signal an operator can
	// gate on. The paired log lines are supplemental operational evidence.
	if recorder := tm.recorder(); recorder != nil {
		recorder.SetGauge(clientinfo.MetricTransactionMonitorRunning, 1)
	}
	logger.Info("transaction monitor started")

	defer func() {
		if recorder := tm.recorder(); recorder != nil {
			recorder.SetGauge(clientinfo.MetricTransactionMonitorRunning, 0)
		}
		logger.Info("transaction monitor stopped")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A tick and a cancellation can become ready at the same moment,
			// and select chooses between two ready cases at random. Re-checking
			// here makes cancellation win that race every time, so a node on
			// its way out never opens a fresh pass at all.
			if ctx.Err() != nil {
				return
			}

			checkPass(ctx)

			// Count the pass only if it ran to its own conclusion - empty,
			// complete, or budget-exhausted. A pass cut short by node
			// cancellation is not forward progress and must not read as such.
			if ctx.Err() != nil {
				return
			}
			if recorder := tm.recorder(); recorder != nil {
				recorder.IncrementCounter(
					clientinfo.MetricTransactionMonitorCheckCyclesTotal, 1,
				)
			}
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
func (tm *transactionMonitor) check(ctx context.Context) {
	tm.checkWithBudget(ctx, transactionMonitorCheckBudget)
}

func (tm *transactionMonitor) checkWithBudget(
	ctx context.Context,
	checkBudget time.Duration,
) {
	// Observed before the pass does anything at all: no budget context, no
	// telemetry defer, no snapshot. "Start no new work once cancellation is
	// observed" covers the pass's own bookkeeping too - reconciling the
	// tracked-count gauge on the way out of a pass that never ran is a metric
	// write a stopping monitor has no business making.
	if ctx.Err() != nil {
		return
	}

	checkCtx, cancelCheck := context.WithTimeout(
		ctx,
		checkBudget,
	)
	defer cancelCheck()

	// Reconcile the tracked-count gauge once the pass settles, whichever exit it
	// takes. Individual mutations publish as they happen; this bounds any skew
	// between the gauge and the tracked set to a single check interval.
	defer tm.publishTrackedCount()

	now := time.Now()

	// Iterate the tracked set oldest-first (see snapshotByAge) so a pass that
	// hits its time budget never starves the transactions closest to the stuck
	// threshold; only the newest, furthest-from-alerting ones are deferred to the
	// next pass. Chain calls are made on the copy, outside the lock.
	for _, t := range tm.snapshotByAge() {
		txHash := t.hash

		// Cancellation is checked on both sides of the lookup. Before it, so
		// that a shutdown arriving mid-pass stops the next request rather than
		// only being noticed after it returns; after it, to abandon the rest of
		// a pass the node cut short.
		if ctx.Err() != nil {
			return
		}

		// The chain call carries checkCtx, so a backend that honors the deadline
		// releases this run loop when the budget expires instead of keeping it
		// blocked. See transactionMonitorCheckBudget for the Electrum paths that
		// can still outlive it.
		confirmations, err :=
			tm.btcChain.GetTransactionConfirmations(checkCtx, txHash)

		// Stop immediately if the monitor itself is shutting down.
		if ctx.Err() != nil {
			return
		}

		// The budget may have expired during the lookup above. The age-based
		// alert and eviction below need no network data, so still run them for
		// the current transaction - whose lookup was attempted and cancelled -
		// before deferring the rest. Otherwise a backend that hangs on the oldest
		// tracked transaction every pass would keep it (the one closest to the
		// stuck threshold) from ever alerting or being evicted. The remaining
		// transactions are deferred, not alerted: alerting on a transaction we
		// never looked up this pass could raise a false alert for one that has
		// in fact confirmed.
		budgetExpired := checkCtx.Err() != nil

		if !budgetExpired && err == nil &&
			confirmations >= transactionMonitorMinConfirmations {
			// The transaction is mined; stop tracking it.
			tm.remove(txHash)
			continue
		}

		// Still unconfirmed (in the mempool), not found, or the lookup returned a
		// transient error. A lookup error is treated the same as unconfirmed: it
		// does not indicate the transaction confirmed and may be transient.
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

		if budgetExpired {
			// The check budget expired during this transaction's lookup; its
			// age-based alert/eviction ran above, and the remaining transactions
			// are deferred to the next pass. The monitor is not shutting down here
			// (that returned earlier), so the warning is unconditional.
			logger.Warnf(
				"transaction monitor check pass exceeded its time budget [%s]; "+
					"deferring the remaining transactions to the next pass",
				checkBudget,
			)
			return
		}
	}
}

// remove stops tracking the transaction with the given hash.
func (tm *transactionMonitor) remove(txHash bitcoin.Hash) {
	tm.mu.Lock()
	delete(tm.tracked, txHash)
	tm.mu.Unlock()

	tm.publishTrackedCount()
}
