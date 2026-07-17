package tbtc

import (
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// monitorTestChain embeds the local Bitcoin chain mock and adds a settable
// latest block height, which the base mock does not implement.
type monitorTestChain struct {
	*localBitcoinChain
	latestBlockHeight uint
}

func (m *monitorTestChain) GetLatestBlockHeight() (uint, error) {
	return m.latestBlockHeight, nil
}

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

func TestTransactionMonitor(t *testing.T) {
	chain := &monitorTestChain{
		localBitcoinChain: newLocalBitcoinChain(),
		latestBlockHeight: 100,
	}
	recorder := newCountingMetricsRecorder()

	monitor := newTransactionMonitor(chain)
	monitor.setMetricsRecorder(recorder)

	tx := &bitcoin.Transaction{}
	txHash := tx.Hash()
	walletPublicKeyHash := [20]byte{1, 2, 3}

	monitor.track(txHash, walletPublicKeyHash)

	stuckCount := func() float64 {
		return recorder.GetCounterValue(clientinfo.MetricStuckWalletTransactionsTotal)
	}

	// At exactly the threshold the transaction is not yet considered stuck.
	chain.latestBlockHeight = 100 + defaultStuckTransactionThresholdBlocks
	monitor.check()
	if got := stuckCount(); got != 0 {
		t.Fatalf("expected no alert at threshold; got counter [%v]", got)
	}

	// One block past the threshold it is flagged as stuck, exactly once even
	// across repeated checks.
	chain.latestBlockHeight = 100 + defaultStuckTransactionThresholdBlocks + 1
	monitor.check()
	monitor.check()
	if got := stuckCount(); got != 1 {
		t.Fatalf("expected exactly one alert; got counter [%v]", got)
	}

	// Once the transaction confirms it stops being tracked.
	if err := chain.BroadcastTransaction(tx); err != nil {
		t.Fatalf("unexpected error confirming transaction: [%v]", err)
	}
	monitor.check()

	monitor.mu.Lock()
	_, stillTracked := monitor.tracked[txHash]
	monitor.mu.Unlock()
	if stillTracked {
		t.Fatal("expected confirmed transaction to be untracked")
	}
}
