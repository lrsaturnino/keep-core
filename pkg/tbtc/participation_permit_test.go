package tbtc

import (
	"context"
	"sync"
	"testing"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// testGateMetrics is a no-op metrics sink for test participation gates.
type testGateMetrics struct{}

func (testGateMetrics) IncrementCounter(string, float64) {}
func (testGateMetrics) SetGauge(string, float64)         {}

type testAuthoritativeClock struct{ chain.BlockCounter }

func (c testAuthoritativeClock) CurrentHeight(
	context.Context,
) (uint64, error) {
	return c.CurrentBlock()
}

// newTestGate constructs a real participation gate over the given block
// counter with an already-crossed cutover block, so every permit with a
// nonzero anchor pins the security-v2 mode — the only mode the tECDSA stack
// can run.
func newTestGate(
	t *testing.T,
	blockCounter chain.BlockCounter,
) participation.Gate {
	t.Helper()

	return newTestGateWithCutover(t, blockCounter, 1)
}

// newTestGateWithCutover constructs a real participation gate over the given
// block counter with the given cutover block, letting boundary tests choose
// the protocol mode a permit anchor resolves to.
func newTestGateWithCutover(
	t *testing.T,
	blockCounter chain.BlockCounter,
	cutoverBlock uint64,
) participation.Gate {
	t.Helper()

	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: cutoverBlock},
		blockCounter,
		testAuthoritativeClock{blockCounter},
		testGateMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	return gate
}

// testPermit is a minimal participation.Permit for exercising wallet actions
// and executors without a running gate: it pins the security-v2 mode, keeps
// an always-open (or preset failing) commit fence, and records commit
// operations and closure for assertions.
type testPermit struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	mode     participation.ProtocolMode
	ceremony participation.Ceremony
	anchor   uint64

	// commitErr, when set, is returned by every CheckCommit call, modeling a
	// refused fence.
	commitErr error

	mu               sync.Mutex
	commits          []string
	terminalOutcomes []testTerminalOutcome
	closed           bool
}

type testTerminalOutcome struct {
	outcome  participation.TerminalOutcome
	evidence participation.TerminalEvidence
}

func newTestPermit(ceremony participation.Ceremony) *testPermit {
	ctx, cancel := context.WithCancelCause(context.Background())

	return &testPermit{
		ctx:      ctx,
		cancel:   cancel,
		mode:     participation.ModeSecurityV2,
		ceremony: ceremony,
		anchor:   1,
	}
}

func (tp *testPermit) Context() context.Context { return tp.ctx }

func (tp *testPermit) Ceremony() participation.Ceremony { return tp.ceremony }

func (tp *testPermit) CanonicalStartBlock() uint64 { return tp.anchor }

func (tp *testPermit) Mode() participation.ProtocolMode { return tp.mode }

func (tp *testPermit) WorkID() string { return "test-work" }

func (tp *testPermit) PermitID() string { return "test-permit" }

func (tp *testPermit) RecordTerminalOutcome(
	outcome participation.TerminalOutcome,
	evidence participation.TerminalEvidence,
) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.terminalOutcomes = append(
		tp.terminalOutcomes,
		testTerminalOutcome{outcome: outcome, evidence: evidence},
	)

	return nil
}

func (tp *testPermit) CheckCommit(
	operation string,
	class participation.CommitClass,
) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.commits = append(tp.commits, operation)

	return tp.commitErr
}

func (tp *testPermit) Close() {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if !tp.closed {
		tp.closed = true
		tp.cancel(participation.ErrPermitClosed)
	}
}

func (tp *testPermit) recordedTerminalOutcomes() []testTerminalOutcome {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	return append([]testTerminalOutcome(nil), tp.terminalOutcomes...)
}

func (tp *testPermit) isClosed() bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	return tp.closed
}

func (tp *testPermit) commitOperations() []string {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	operations := make([]string, len(tp.commits))
	copy(operations, tp.commits)

	return operations
}
