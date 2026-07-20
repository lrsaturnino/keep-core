package tbtc

import (
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// countingMetricsRecorder is a PerformanceMetricsRecorder that counts counter
// increments so tests can assert the stuck-transaction metric fired.
type countingMetricsRecorder struct {
	counters map[string]float64
}

func newCountingMetricsRecorder() *countingMetricsRecorder {
	return &countingMetricsRecorder{counters: make(map[string]float64)}
}

func (c *countingMetricsRecorder) IncrementCounter(name string, value float64) {
	c.counters[name] += value
}
func (c *countingMetricsRecorder) RecordDuration(string, time.Duration) {}
func (c *countingMetricsRecorder) SetGauge(string, float64)             {}
func (c *countingMetricsRecorder) GetCounterValue(name string) float64 {
	return c.counters[name]
}
func (c *countingMetricsRecorder) GetGaugeValue(string) float64 { return 0 }

// ageTransaction backdates the broadcast time of a tracked transaction to
// simulate the passage of time.
func ageTransaction(
	tm *transactionMonitor,
	txHash bitcoin.Hash,
	by time.Duration,
) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if t, ok := tm.tracked[txHash]; ok {
		t.broadcastAt = t.broadcastAt.Add(-by)
	}
}

func isTracked(tm *transactionMonitor, txHash bitcoin.Hash) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	_, ok := tm.tracked[txHash]
	return ok
}

func trackedCount(tm *transactionMonitor) int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.tracked)
}

func TestTransactionMonitor(t *testing.T) {
	chain := newLocalBitcoinChain()
	recorder := newCountingMetricsRecorder()

	monitor := newTransactionMonitor(chain)
	monitor.setMetricsRecorder(recorder)

	tx := &bitcoin.Transaction{}
	txHash := tx.Hash()
	monitor.track(txHash, [20]byte{1, 2, 3})

	stuckCount := func() float64 {
		return recorder.GetCounterValue(clientinfo.MetricStuckWalletTransactionsTotal)
	}

	// Fresh: not yet stuck.
	monitor.check()
	if got := stuckCount(); got != 0 {
		t.Fatalf("expected no alert for a fresh transaction; got counter [%v]", got)
	}

	// Just below the threshold: still not stuck. The alert condition is strictly
	// greater than the threshold. Testing exactly at the threshold is omitted
	// deliberately: with a real clock the check-time drift always nudges the
	// elapsed time a hair past any exact backdated value, so it cannot be pinned
	// deterministically without an injectable clock.
	ageTransaction(monitor, txHash, defaultStuckTransactionThreshold-time.Minute)
	monitor.check()
	if got := stuckCount(); got != 0 {
		t.Fatalf("expected no alert at the threshold boundary; got counter [%v]", got)
	}

	// Past the threshold: flagged as stuck exactly once across repeated checks.
	ageTransaction(monitor, txHash, 2*time.Minute) // now threshold + 1 minute total
	monitor.check()
	monitor.check()
	if got := stuckCount(); got != 1 {
		t.Fatalf("expected exactly one alert; got counter [%v]", got)
	}

	// Once the transaction confirms, it stops being tracked.
	if err := chain.BroadcastTransaction(tx); err != nil {
		t.Fatalf("unexpected error confirming transaction: [%v]", err)
	}
	monitor.check()
	if isTracked(monitor, txHash) {
		t.Fatal("expected confirmed transaction to be untracked")
	}
}

// TestTransactionMonitor_GivesUpOnNeverConfirming verifies that a transaction
// that never confirms is eventually evicted so it cannot fill the tracking
// table.
func TestTransactionMonitor_GivesUpOnNeverConfirming(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)

	tx := &bitcoin.Transaction{}
	txHash := tx.Hash()
	monitor.track(txHash, [20]byte{})

	// Age it beyond the maximum tracking age; on its first check it is past both
	// the stuck threshold and the give-up age. It must still fire exactly one
	// stuck alert (the alert runs before eviction) and then be evicted rather
	// than tracked forever.
	ageTransaction(monitor, txHash, transactionMonitorMaxTrackingAge+time.Minute)
	monitor.check()

	if got := recorder.GetCounterValue(
		clientinfo.MetricStuckWalletTransactionsTotal,
	); got != 1 {
		t.Fatalf("expected one stuck alert before eviction; got counter [%v]", got)
	}
	if isTracked(monitor, txHash) {
		t.Fatal("expected a never-confirming transaction to be evicted")
	}
}

// TestTransactionMonitor_CapacityBound verifies the tracking table does not grow
// past its bound.
func TestTransactionMonitor_CapacityBound(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)

	const excess = 10
	for i := 0; i < transactionMonitorMaxTracked+excess; i++ {
		var h bitcoin.Hash
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		monitor.track(h, [20]byte{})
	}

	if got := trackedCount(monitor); got != transactionMonitorMaxTracked {
		t.Fatalf(
			"expected tracking table bounded to [%d]; got [%d]",
			transactionMonitorMaxTracked,
			got,
		)
	}

	// The transactions that could not be tracked once the table filled must be
	// surfaced via the unmonitored-transactions metric.
	if got := recorder.GetCounterValue(
		clientinfo.MetricUnmonitoredWalletTransactionsTotal,
	); got != excess {
		t.Fatalf(
			"expected [%d] unmonitored-transaction increments; got [%v]",
			excess,
			got,
		)
	}
}

// TestTransactionMonitor_SnapshotByAge verifies the check pass iterates tracked
// transactions oldest-first, so an old transaction near the stuck threshold is
// never starved when a pass hits its time budget (Go map order is randomized).
func TestTransactionMonitor_SnapshotByAge(t *testing.T) {
	monitor := newTransactionMonitor(newLocalBitcoinChain())

	var h1, h2, h3 bitcoin.Hash
	h1[0], h2[0], h3[0] = 1, 2, 3
	monitor.track(h1, [20]byte{})
	monitor.track(h2, [20]byte{})
	monitor.track(h3, [20]byte{})

	// Backdate broadcast times so the age order is h2 (oldest), h3, h1 (newest).
	// The hour-scale gaps dwarf the sub-second differences in track() times.
	ageTransaction(monitor, h1, 1*time.Hour)
	ageTransaction(monitor, h2, 3*time.Hour)
	ageTransaction(monitor, h3, 2*time.Hour)

	ordered := monitor.snapshotByAge()

	want := []bitcoin.Hash{h2, h3, h1}
	if len(ordered) != len(want) {
		t.Fatalf("expected [%d] entries; got [%d]", len(want), len(ordered))
	}
	for i, w := range want {
		if ordered[i].hash != w {
			t.Fatalf(
				"snapshotByAge not oldest-first at index [%d]\nexpected: %v\ngot:      %v",
				i, want, []bitcoin.Hash{ordered[0].hash, ordered[1].hash, ordered[2].hash},
			)
		}
	}
	// Broadcast times must be non-decreasing across the ordered snapshot.
	for i := 1; i < len(ordered); i++ {
		if ordered[i].broadcastAt.Before(ordered[i-1].broadcastAt) {
			t.Fatalf("entry [%d] is older than entry [%d]; not sorted oldest-first", i, i-1)
		}
	}
}
