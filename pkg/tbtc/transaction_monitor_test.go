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

	// Past the threshold: flagged as stuck exactly once across repeated checks.
	ageTransaction(monitor, txHash, defaultStuckTransactionThreshold+time.Minute)
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
	monitor := newTransactionMonitor(newLocalBitcoinChain())

	tx := &bitcoin.Transaction{}
	txHash := tx.Hash()
	monitor.track(txHash, [20]byte{})

	// Age it beyond the maximum tracking age; it never confirmed, so it is
	// dropped rather than tracked forever.
	ageTransaction(monitor, txHash, transactionMonitorMaxTrackingAge+time.Minute)
	monitor.check()

	if isTracked(monitor, txHash) {
		t.Fatal("expected a never-confirming transaction to be evicted")
	}
}

// TestTransactionMonitor_CapacityBound verifies the tracking table does not grow
// past its bound.
func TestTransactionMonitor_CapacityBound(t *testing.T) {
	monitor := newTransactionMonitor(newLocalBitcoinChain())

	for i := 0; i < transactionMonitorMaxTracked+10; i++ {
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
}
