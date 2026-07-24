package tbtc

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// cutoverFakeBlockCounter is a minimal chain.BlockCounter returning a fixed
// height.
type cutoverFakeBlockCounter struct {
	block uint64
}

func (f *cutoverFakeBlockCounter) CurrentBlock() (uint64, error)   { return f.block, nil }
func (f *cutoverFakeBlockCounter) WaitForBlockHeight(uint64) error { return nil }
func (f *cutoverFakeBlockCounter) BlockHeightWaiter(uint64) (<-chan uint64, error) {
	c := make(chan uint64, 1)
	close(c)
	return c, nil
}
func (f *cutoverFakeBlockCounter) WatchBlocks(ctx context.Context) <-chan uint64 {
	c := make(chan uint64)
	go func() {
		<-ctx.Done()
		close(c)
	}()
	return c
}

// cutoverFakeMetrics records counter/gauge writes. It satisfies both the
// announcer mismatch metrics sink and the roster metrics recorder.
type cutoverFakeMetrics struct {
	mu       sync.Mutex
	counters map[string]float64
	gauges   map[string]float64
}

func newCutoverFakeMetrics() *cutoverFakeMetrics {
	return &cutoverFakeMetrics{
		counters: make(map[string]float64),
		gauges:   make(map[string]float64),
	}
}

func (m *cutoverFakeMetrics) IncrementCounter(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] += value
}

func (m *cutoverFakeMetrics) SetGauge(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = value
}

func (m *cutoverFakeMetrics) counter(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

// captureLogger records formatted log lines.
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) Infof(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *captureLogger) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.lines))
	copy(out, l.lines)
	return out
}

// operatorAddrs is a set of three valid, distinct operator addresses.
var operatorAddrs = chain.Addresses{
	chain.Address("0x1111111111111111111111111111111111111111"),
	chain.Address("0x2222222222222222222222222222222222222222"),
	chain.Address("0x3333333333333333333333333333333333333333"),
}

func newTestRoster(
	t *testing.T,
	metrics participation.CutoverRosterMetricsRecorder,
	block uint64,
) *participation.CutoverPeerRoster {
	t.Helper()
	roster, err := participation.NewCutoverPeerRoster(
		context.Background(),
		&cutoverFakeBlockCounter{block: block},
		1500,
		metrics,
	)
	if err != nil {
		t.Fatalf("cannot build roster: %v", err)
	}
	t.Cleanup(roster.Close)
	return roster
}

// TestHandleAnnouncerSessionMismatch_LegacyStragglerRecorded proves that a
// legacy peer observed by a security-v2 permit increments both the mismatch and
// cross-format counters, is attributed to the correct operator address in the
// node-local roster, and is logged without any raw session identifier.
func TestHandleAnnouncerSessionMismatch_LegacyStragglerRecorded(t *testing.T) {
	metrics := newCutoverFakeMetrics()
	roster := newTestRoster(t, metrics, 5000)
	logger := &captureLogger{}

	// sender 2 -> operatorAddrs[1] (0x2222...). A nil limiter always logs.
	handleAnnouncerSessionMismatch(
		logger,
		nil,
		metrics,
		roster,
		participation.ModeSecurityV2,
		operatorAddrs,
		"tbtc-dkg",
		group.MemberIndex(2),
		announcer.SessionIDFormatHardenedDKG,
		announcer.SessionIDFormatLegacy,
	)

	if got := metrics.counter(clientinfo.MetricAnnouncerSessionIDMismatchTotal); got != 1 {
		t.Errorf("mismatch counter = %v, want 1", got)
	}
	if got := metrics.counter(clientinfo.MetricAnnouncerCrossFormatPeerTotal); got != 1 {
		t.Errorf("cross-format counter = %v, want 1", got)
	}

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected 1 peer in roster, got %d", len(snapshot.Peers))
	}
	if snapshot.Peers[0].OperatorAddress != "0x2222222222222222222222222222222222222222" {
		t.Errorf(
			"expected operator 0x2222..., got %s",
			snapshot.Peers[0].OperatorAddress,
		)
	}

	lines := logger.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 log line, got %d: %v", len(lines), lines)
	}
	line := lines[0]
	if !strings.Contains(line, "session ID mismatch") ||
		!strings.Contains(line, "legacy") ||
		!strings.Contains(line, "hardened_dkg") ||
		!strings.Contains(line, "security_v2") {
		t.Errorf("log line missing expected safe fields: %q", line)
	}
	// The observer only ever receives classified formats, never raw IDs; the
	// operator address is the only identifier and no session-ID hex appears.
	for _, forbidden := range []string{"dkg-", "signing-", "seed", "0xdeadbeef"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("log line leaked raw material %q: %q", forbidden, line)
		}
	}
}

// TestHandleAnnouncerSessionMismatch_HardenedVsHardened proves that a mismatch
// between two hardened formats is counted as a mismatch but not as a
// cross-format peer, and is not recorded in the roster (the observed peer is not
// legacy).
func TestHandleAnnouncerSessionMismatch_HardenedVsHardened(t *testing.T) {
	metrics := newCutoverFakeMetrics()
	roster := newTestRoster(t, metrics, 5000)

	handleAnnouncerSessionMismatch(
		&captureLogger{},
		nil,
		metrics,
		roster,
		participation.ModeSecurityV2,
		operatorAddrs,
		"tbtc-signing",
		group.MemberIndex(1),
		announcer.SessionIDFormatHardenedSigning,
		announcer.SessionIDFormatHardenedDKG,
	)

	if got := metrics.counter(clientinfo.MetricAnnouncerSessionIDMismatchTotal); got != 1 {
		t.Errorf("mismatch counter = %v, want 1", got)
	}
	if got := metrics.counter(clientinfo.MetricAnnouncerCrossFormatPeerTotal); got != 0 {
		t.Errorf("cross-format counter = %v, want 0", got)
	}
	if got := len(roster.Snapshot().Peers); got != 0 {
		t.Errorf("expected empty roster, got %d peers", got)
	}
}

// TestHandleAnnouncerSessionMismatch_OutOfRangeSender proves the explicit bounds
// check: an out-of-range member index does not panic and is not attributed to
// any operator, though the mismatch is still counted.
func TestHandleAnnouncerSessionMismatch_OutOfRangeSender(t *testing.T) {
	metrics := newCutoverFakeMetrics()
	roster := newTestRoster(t, metrics, 5000)

	// Only three operators exist; index 99 is out of range.
	handleAnnouncerSessionMismatch(
		&captureLogger{},
		nil,
		metrics,
		roster,
		participation.ModeSecurityV2,
		operatorAddrs,
		"tbtc-dkg",
		group.MemberIndex(99),
		announcer.SessionIDFormatHardenedDKG,
		announcer.SessionIDFormatLegacy,
	)

	if got := metrics.counter(clientinfo.MetricAnnouncerSessionIDMismatchTotal); got != 1 {
		t.Errorf("mismatch counter = %v, want 1", got)
	}
	if got := len(roster.Snapshot().Peers); got != 0 {
		t.Errorf("out-of-range sender must not be rostered, got %d peers", got)
	}
}

// TestHandleAnnouncerSessionMismatch_PortZeroNilMetrics proves the handler is
// safe when client-info is disabled (nil metrics sink) and that the roster —
// constructed with a no-op recorder in that mode — still records the sighting.
func TestHandleAnnouncerSessionMismatch_PortZeroNilMetrics(t *testing.T) {
	// Port-zero uses the no-op recorder for the roster and passes a nil metrics
	// sink to the handler.
	roster := newTestRoster(t, &clientinfo.NoOpPerformanceMetrics{}, 5000)
	logger := &captureLogger{}

	handleAnnouncerSessionMismatch(
		logger,
		nil,
		nil, // no metrics sink (client-info disabled)
		roster,
		participation.ModeSecurityV2,
		operatorAddrs,
		"tbtc-dkg",
		group.MemberIndex(3),
		announcer.SessionIDFormatHardenedDKG,
		announcer.SessionIDFormatLegacy,
	)

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected 1 peer despite disabled metrics, got %d", len(snapshot.Peers))
	}
	if snapshot.Peers[0].OperatorAddress != "0x3333333333333333333333333333333333333333" {
		t.Errorf("expected operator 0x3333..., got %s", snapshot.Peers[0].OperatorAddress)
	}
	if len(logger.all()) != 1 {
		t.Errorf("expected the mismatch to still be logged when metrics are disabled")
	}
}
