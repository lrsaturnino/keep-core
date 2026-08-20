package participation

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// gateBlockCounter is a controllable chain.BlockCounter with real height
// waiter semantics: a waiter channel emits the reached height and closes, or
// can be force-closed without a value to simulate a waiter failure. A one-shot
// read hold lets tests model a slow RPC response, computed from an older chain
// view, arriving after newer reads have completed.
type gateBlockCounter struct {
	mu          sync.Mutex
	block       uint64
	err         error
	waiterErr   error
	waiters     map[uint64][]chan uint64
	reads       uint64
	holdStarted chan struct{}
	holdRelease chan struct{}
}

func TestGate_CeremonySpecificPermitIdentityValidation(t *testing.T) {
	const cutover = uint64(1_000)
	recorder := &recordingQuiescenceSnapshotRecorder{}
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
		WithArtifactIdentity("v2.1.0", "revision-test"),
		WithQuiescenceSnapshotRecorder(recorder),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	tests := map[string]struct {
		ceremony Ceremony
		identity PermitIdentity
	}{
		"uppercase DKG seed hash": {
			ceremony: TBTCDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("A", 64),
				PermitID:        "1",
				OperatedMembers: MemberIndexes{1},
			},
		},
		"truncated DKG seed hash": {
			ceremony: BeaconDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("a", 63),
				PermitID:        "1",
				OperatedMembers: MemberIndexes{1},
			},
		},
		"prefixed member index": {
			ceremony: TBTCDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("a", 64),
				PermitID:        "01",
				OperatedMembers: MemberIndexes{1},
			},
		},
		"zero member index": {
			ceremony: BeaconDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("a", 64),
				PermitID:        "0",
				OperatedMembers: MemberIndexes{1},
			},
		},
		// The seats a per-seat ceremony announces cannot say anything other
		// than what its permit ID already says.
		"DKG permit operating no seat": {
			ceremony: TBTCDKG,
			identity: PermitIdentity{
				WorkID:   strings.Repeat("a", 64),
				PermitID: "7",
			},
		},
		"DKG permit operating a different seat": {
			ceremony: BeaconDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("a", 64),
				PermitID:        "7",
				OperatedMembers: MemberIndexes{8},
			},
		},
		"DKG permit operating more than its own seat": {
			ceremony: TBTCDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("a", 64),
				PermitID:        "7",
				OperatedMembers: MemberIndexes{7, 8},
			},
		},
		"relay signing permit operating a different seat": {
			ceremony: BeaconRelaySigning,
			identity: PermitIdentity{
				WorkID:          BeaconRelayWorkID(1_000),
				PermitID:        "3",
				OperatedMembers: MemberIndexes{4},
			},
		},
		// And the ceremonies that operate no seat may not claim one: a
		// forwarder relays other members' shares and a timeout report is a
		// penalty filing, so a seat here would enter the fleet's ownership map
		// with no membership behind it.
		"forwarder claiming a seat": {
			ceremony: BeaconRelayForwarding,
			identity: PermitIdentity{
				WorkID:          BeaconRelayWorkID(1_000),
				PermitID:        "forwarder",
				OperatedMembers: MemberIndexes{1},
			},
		},
		"timeout monitor claiming a seat": {
			ceremony: BeaconTimeoutReport,
			identity: PermitIdentity{
				WorkID:          BeaconRelayWorkID(1_000),
				PermitID:        "timeout-monitor",
				OperatedMembers: MemberIndexes{1},
			},
		},
		// The generic set rules hold for every ceremony: one set has exactly
		// one encoding, so a reader cannot be shown the same seat twice.
		"unordered operated seats": {
			ceremony: TBTCSigning,
			identity: PermitIdentity{
				WorkID:          "wallet-action-unordered",
				PermitID:        "wallet",
				OperatedMembers: MemberIndexes{4, 2},
			},
		},
		"repeated operated seat": {
			ceremony: TBTCSigning,
			identity: PermitIdentity{
				WorkID:          "wallet-action-repeated",
				PermitID:        "wallet",
				OperatedMembers: MemberIndexes{2, 2},
			},
		},
		"invalid operated seat": {
			ceremony: TBTCSigning,
			identity: PermitIdentity{
				WorkID:          "wallet-action-zero-seat",
				PermitID:        "wallet",
				OperatedMembers: MemberIndexes{0},
			},
		},
		"nonmember relay identity": {
			ceremony: BeaconRelaySigning,
			identity: PermitIdentity{
				WorkID:   "relay-request-1000",
				PermitID: "member-1",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := gate.Begin(
				test.ceremony,
				cutover,
				test.identity,
			); !errors.Is(err, ErrInvalidPermitIdentity) {
				t.Fatalf(
					"expected ceremony-specific identity rejection, got [%v]",
					err,
				)
			}
		})
	}

	permit, err := gate.Begin(
		TBTCDKG,
		cutover,
		PermitIdentity{
			WorkID:          strings.Repeat("a", 64),
			PermitID:        "255",
			OperatedMembers: MemberIndexes{255},
		},
	)
	if err != nil {
		t.Fatalf("canonical DKG identity rejected: [%v]", err)
	}
	permit.Close()
}

func TestGate_NodeAuthoredTerminalOutcomes(t *testing.T) {
	const cutover = uint64(1_000)
	capturedAt := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	recorder := &recordingQuiescenceSnapshotRecorder{}
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
		WithArtifactIdentity("v2.1.0", "revision-test"),
		WithQuiescenceSnapshotRecorder(recorder),
		withGateTimeSource(func() time.Time { return capturedAt }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	completed, err := gate.Begin(
		TBTCSigning,
		cutover,
		PermitIdentity{
			WorkID:          "wallet-action-completed",
			PermitID:        "wallet-completed",
			OperatedMembers: MemberIndexes{1},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	unresolved, err := gate.Begin(
		BeaconRelayForwarding,
		cutover,
		PermitIdentity{
			WorkID:   "relay-request-unresolved",
			PermitID: "forwarder",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	gate.Quiesce(fmt.Errorf("rollback drill"))
	if err := completed.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		TerminalEvidence{
			Kind:         TerminalEvidenceBitcoinTransaction,
			Reference:    "signed-transaction-hash",
			Contribution: testTranscriptContribution(TBTCSigning, 1),
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := completed.RecordTerminalOutcome(
		TerminalOutcomeExhausted,
		TerminalEvidence{Kind: TerminalEvidenceNoThreshold},
	); !errors.Is(err, ErrTerminalOutcomeAlreadyRecorded) {
		t.Fatalf("expected immutable terminal outcome, got [%v]", err)
	}

	completed.Close()
	unresolved.Close()

	outcomes := recorder.recordedOutcomes()
	if len(outcomes) != 2 {
		t.Fatalf("expected two terminal outcomes, got [%d]", len(outcomes))
	}
	recorded := make(map[string]TerminalOutcome)
	for _, outcome := range outcomes {
		recorded[outcome.Permit.WorkID] = outcome.Outcome
	}
	if recorded["wallet-action-completed"] != TerminalOutcomeCompleted {
		t.Errorf("completed permit outcome not persisted: %+v", outcomes)
	}
	if recorded["relay-request-unresolved"] != terminalOutcomeUnresolved {
		t.Errorf("missing owner outcome did not fail closed: %+v", outcomes)
	}
}

// TestGate_RetainsTerminalOutcomesOfClosedPermits asserts the gate keeps its
// own account of what became of the permits it closed, and that the account is
// available without a quiescence transition.
//
// The journal exists only from the first quiescence onward. Before one, a
// permit that finishes simply disappears from the live state: an observer
// watching work cross the cutover sees it held and then sees nothing, and has
// to take some other party's report for how it ended. A report about a
// ceremony is not evidence about a ceremony, and the difference is the whole
// point of the record — so what the ceremony's own owner recorded has to
// outlive the permit while the node is still running.
func TestGate_RetainsTerminalOutcomesOfClosedPermits(t *testing.T) {
	const cutover = uint64(1_000)
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	// No quiescence transition anywhere in this test: the account has to be
	// there for a node that is simply running.
	completed, err := gate.Begin(
		TBTCSigning,
		cutover,
		PermitIdentity{
			WorkID:          "wallet-action",
			PermitID:        "wallet",
			OperatedMembers: MemberIndexes{1},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	silent, err := gate.Begin(
		BeaconRelayForwarding,
		cutover,
		PermitIdentity{WorkID: "relay-request", PermitID: "forwarder"},
	)
	if err != nil {
		t.Fatal(err)
	}

	if held := gate.State().RecentTerminalOutcomes; len(held) != 0 {
		t.Fatalf("a live permit was accounted for as closed: %+v", held)
	}

	if err := completed.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		TerminalEvidence{
			Kind:         TerminalEvidenceBitcoinTransaction,
			Reference:    "signed-transaction-hash",
			Contribution: testTranscriptContribution(TBTCSigning, 1),
		},
	); err != nil {
		t.Fatal(err)
	}
	completed.Close()
	silent.Close()

	outcomes := gate.State().RecentTerminalOutcomes
	if len(outcomes) != 2 {
		t.Fatalf("expected two closed permits accounted for: %+v", outcomes)
	}

	// The order is the order they closed in, which is what says which of two
	// dispositions came first.
	if outcomes[0].Permit.WorkID != "wallet-action" ||
		outcomes[1].Permit.WorkID != "relay-request" {
		t.Errorf("closed permits are not in the order they closed: %+v", outcomes)
	}
	if outcomes[0].Outcome != TerminalOutcomeCompleted {
		t.Errorf(
			"the owner's recorded outcome was not retained: %+v",
			outcomes[0],
		)
	}
	if outcomes[0].Evidence.Reference != "signed-transaction-hash" {
		t.Errorf(
			"the owner's recorded evidence was not retained: %+v",
			outcomes[0].Evidence,
		)
	}
	// The permit identity is what a reader joins the record to a live reading
	// on; without it the account names dispositions belonging to nobody.
	if outcomes[0].Permit.PermitID != "wallet" ||
		outcomes[0].Permit.Ceremony != TBTCSigning ||
		outcomes[0].Permit.Mode != ModeSecurityV2.String() {
		t.Errorf("the closed permit's identity was not retained: %+v", outcomes[0])
	}
	// A permit whose owner recorded nothing is not silently absent. Its
	// ceremony came to something the node cannot vouch for, and that is a
	// disposition a reader has to be able to see.
	if outcomes[1].Outcome != terminalOutcomeUnresolved {
		t.Errorf(
			"a permit closed without an owner outcome was not accounted "+
				"for as unresolved: %+v",
			outcomes[1],
		)
	}

	// Closing again must not double-count: an idempotent release that added a
	// second record would make one ceremony look like two.
	completed.Close()
	if again := gate.State().RecentTerminalOutcomes; len(again) != 2 {
		t.Errorf("a repeated release was accounted for twice: %+v", again)
	}
}

// TestGate_TerminalOutcomeAccountIsBounded asserts the gate's account of closed
// permits forgets rather than growing without limit, and that it forgets the
// oldest.
//
// A node runs for as long as the release does, so an account that kept every
// permit would be a slow leak in the one component every ceremony passes
// through.
func TestGate_TerminalOutcomeAccountIsBounded(t *testing.T) {
	const cutover = uint64(1_000)
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	const surplus = 3
	for i := 0; i < retainedTerminalOutcomes+surplus; i++ {
		permit, err := gate.Begin(
			TBTCSigning,
			cutover,
			PermitIdentity{
				WorkID:          fmt.Sprintf("wallet-action-%d", i),
				PermitID:        fmt.Sprintf("wallet-%d", i),
				OperatedMembers: MemberIndexes{1},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		permit.Close()
	}

	outcomes := gate.State().RecentTerminalOutcomes
	if len(outcomes) != retainedTerminalOutcomes {
		t.Fatalf(
			"unexpected account size\nexpected: [%d]\nactual:   [%d]",
			retainedTerminalOutcomes,
			len(outcomes),
		)
	}
	if first := outcomes[0].Permit.WorkID; first !=
		fmt.Sprintf("wallet-action-%d", surplus) {
		t.Errorf("the account did not forget the oldest permits: [%s]", first)
	}
	if last := outcomes[len(outcomes)-1].Permit.WorkID; last !=
		fmt.Sprintf("wallet-action-%d", retainedTerminalOutcomes+surplus-1) {
		t.Errorf("the account did not keep the newest permit: [%s]", last)
	}
	// And it says how many it forgot. Without that a reader joining a permit it
	// saw held to the ending its holder recorded cannot tell an account that
	// never held the record from one that dropped it, and those are opposite
	// answers about whether this node did the work.
	if forgotten := gate.State().ForgottenTerminalOutcomes; forgotten !=
		surplus {
		t.Errorf(
			"unexpected forgotten count\nexpected: [%d]\nactual:   [%d]",
			surplus,
			forgotten,
		)
	}
}

// TestGate_PublishesAProcessInstanceIdentity asserts each gate names itself, and
// that two gates do not share a name.
//
// The gate's account of closed permits lives in memory. A reader following work
// through a node has no way to tell an account that never held a record from one
// that held it and lost it to a restart, and reading the second as the first
// attributes that node's work to whoever else was on the network. The instance is
// what separates the two: two readings that disagree about it came from different
// processes, and every record the earlier one held is gone.
func TestGate_PublishesAProcessInstanceIdentity(t *testing.T) {
	const cutover = uint64(1_000)

	instances := make(map[string]struct{})
	for run := 0; run < 2; run++ {
		gate, err := newGate(
			context.Background(),
			Schedule{CutoverBlock: cutover},
			newGateBlockCounter(cutover),
			newGateBlockCounter(cutover),
			newFakeMetrics(),
			inertPollInterval,
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(gate.Close)

		instance := gate.State().GateInstance
		if instance == "" {
			t.Fatal("a gate published no instance identity")
		}
		// It has to be the same answer every time it is asked, or a single
		// process would read as a restarting one and every reading of its
		// account would be unusable.
		if again := gate.State().GateInstance; again != instance {
			t.Errorf(
				"one gate named itself twice over: [%s] then [%s]",
				instance,
				again,
			)
		}
		instances[instance] = struct{}{}
	}

	if len(instances) != 2 {
		t.Error("two gates published one instance identity between them")
	}
}

// TestGate_TerminalOutcomeAccountIsNotAliased asserts a reader cannot reach
// into the gate's own account through the snapshot it is handed.
//
// The evidence carries the chain settlement by pointer, so a shallow copy
// would hand every scrape a live reference to the record the gate keeps.
func TestGate_TerminalOutcomeAccountIsNotAliased(t *testing.T) {
	const cutover = uint64(1_000)
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	// The heartbeat is the one ceremony that dispatches a chain settlement of
	// its own, so it is the only permit whose evidence carries the pointer
	// this test is about.
	permit, err := gate.Begin(
		TBTCHeartbeat,
		cutover,
		PermitIdentity{
			WorkID:          "heartbeat-work",
			PermitID:        "heartbeat",
			OperatedMembers: MemberIndexes{1},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		TerminalEvidence{
			Kind:      TerminalEvidenceProtocolResult,
			Reference: "heartbeat-result-identity",
			ChainSettlement: &ChainSettlementRecord{
				Kind: ChainSettlementInactivityClaim,
			},
			Contribution: testTranscriptContribution(TBTCHeartbeat, 1),
		},
	); err != nil {
		t.Fatal(err)
	}
	permit.Close()

	handed := gate.State().RecentTerminalOutcomes
	if len(handed) != 1 || handed[0].Evidence.ChainSettlement == nil {
		t.Fatalf("the settled outcome was not retained: %+v", handed)
	}
	handed[0].Evidence.ChainSettlement.Reference = "some-other-claim"

	reread := gate.State().RecentTerminalOutcomes
	if reread[0].Evidence.ChainSettlement.Reference != "" {
		t.Errorf(
			"a reader rewrote the gate's own record: [%s]",
			reread[0].Evidence.ChainSettlement.Reference,
		)
	}
}

func TestGate_NodeAuthoredTerminalOutcomeRetriesPersistence(t *testing.T) {
	const cutover = uint64(1_000)
	capturedAt := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	recorder := &recordingQuiescenceSnapshotRecorder{
		terminalFailures: 1,
		terminalErr:      errors.New("transient journal failure"),
	}
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
		WithArtifactIdentity("v2.1.0", "revision-test"),
		WithQuiescenceSnapshotRecorder(recorder),
		withGateTimeSource(func() time.Time { return capturedAt }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	permit, err := gate.Begin(
		TBTCSigning,
		cutover,
		PermitIdentity{
			WorkID:          "wallet-action-retry",
			PermitID:        "wallet-retry",
			OperatedMembers: MemberIndexes{1},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	gate.Quiesce(fmt.Errorf("rollback drill"))

	outcome := TerminalOutcomeCompleted
	evidence := TerminalEvidence{
		Kind:         TerminalEvidenceBitcoinTransaction,
		Reference:    "signed-transaction-hash",
		Contribution: testTranscriptContribution(TBTCSigning, 1),
	}
	if err := permit.RecordTerminalOutcome(
		outcome,
		evidence,
	); !errors.Is(err, ErrTerminalOutcomePersistence) {
		t.Fatalf("expected first persistence attempt to fail, got [%v]", err)
	}
	if err := permit.RecordTerminalOutcome(outcome, evidence); err != nil {
		t.Fatalf("expected identical outcome retry to succeed, got [%v]", err)
	}
	permit.Close()

	outcomes := recorder.recordedOutcomes()
	if len(outcomes) != 1 {
		t.Fatalf("expected one terminal outcome, got [%d]", len(outcomes))
	}
	if outcomes[0].Outcome != outcome ||
		!outcomes[0].Evidence.Equal(evidence) {
		t.Errorf("unexpected terminal outcome after retry: %+v", outcomes[0])
	}
}

type recordingQuiescenceSnapshotRecorder struct {
	mu               sync.Mutex
	snapshots        []QuiescenceSnapshot
	outcomes         []TerminalOutcomeRecord
	err              error
	terminalFailures int
	terminalErr      error
}

func (r *recordingQuiescenceSnapshotRecorder) Record(
	snapshot QuiescenceSnapshot,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.snapshots = append(r.snapshots, cloneQuiescenceSnapshot(snapshot))
	return r.err
}

func (r *recordingQuiescenceSnapshotRecorder) RecordTerminalOutcome(
	outcome TerminalOutcomeRecord,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.terminalFailures > 0 {
		r.terminalFailures--
		return r.terminalErr
	}

	for _, existing := range r.outcomes {
		if existing.Permit.Equal(outcome.Permit) {
			if existing.Equal(outcome) {
				return r.err
			}
			return fmt.Errorf("contradictory terminal outcome")
		}
	}
	r.outcomes = append(r.outcomes, outcome)
	return r.err
}

func (r *recordingQuiescenceSnapshotRecorder) recorded() []QuiescenceSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]QuiescenceSnapshot, len(r.snapshots))
	for i, snapshot := range r.snapshots {
		result[i] = cloneQuiescenceSnapshot(snapshot)
	}
	return result
}

func (r *recordingQuiescenceSnapshotRecorder) recordedOutcomes() []TerminalOutcomeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]TerminalOutcomeRecord(nil), r.outcomes...)
}

func newGateBlockCounter(block uint64) *gateBlockCounter {
	return &gateBlockCounter{
		block:   block,
		waiters: make(map[uint64][]chan uint64),
	}
}

func (f *gateBlockCounter) set(block uint64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.block = block
	f.err = err

	if err != nil {
		return
	}
	for height, channels := range f.waiters {
		if block >= height {
			for _, ch := range channels {
				ch <- block
				close(ch)
			}
			delete(f.waiters, height)
		}
	}
}

// failWaiters closes all armed waiters without emitting a value, which the
// gate must treat as a clock failure.
func (f *gateBlockCounter) failWaiters() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for height, channels := range f.waiters {
		for _, ch := range channels {
			close(ch)
		}
		delete(f.waiters, height)
	}
}

// deliverWaiters fires every waiter armed at or below the given height without
// changing the current block or error, so a test can make the cutover waiter
// report its target while the synchronous read path stays independently
// controlled.
func (f *gateBlockCounter) deliverWaiters(height uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for target, channels := range f.waiters {
		if height >= target {
			for _, ch := range channels {
				ch <- height
				close(ch)
			}
			delete(f.waiters, target)
		}
	}
}

// holdNextRead arms a one-shot hold: the next CurrentBlock call snapshots its
// result immediately but does not return until release is called. The started
// channel closes once the held read has taken its snapshot; release is
// idempotent.
func (f *gateBlockCounter) holdNextRead() (<-chan struct{}, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()

	started := make(chan struct{})
	releaseCh := make(chan struct{})
	f.holdStarted = started
	f.holdRelease = releaseCh

	var once sync.Once
	return started, func() { once.Do(func() { close(releaseCh) }) }
}

// readCount returns how many CurrentBlock reads have been served, letting a
// test wait deterministically for a background read to have happened.
func (f *gateBlockCounter) readCount() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func (f *gateBlockCounter) CurrentBlock() (uint64, error) {
	f.mu.Lock()
	f.reads++
	block, err := f.block, f.err
	started, releaseCh := f.holdStarted, f.holdRelease
	f.holdStarted, f.holdRelease = nil, nil
	f.mu.Unlock()

	if started != nil {
		close(started)
		<-releaseCh
	}
	return block, err
}

func (f *gateBlockCounter) CurrentHeight(context.Context) (uint64, error) {
	return f.CurrentBlock()
}

func (f *gateBlockCounter) WaitForBlockHeight(uint64) error { return nil }

func (f *gateBlockCounter) BlockHeightWaiter(
	height uint64,
) (<-chan uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.waiterErr != nil {
		return nil, f.waiterErr
	}

	ch := make(chan uint64, 1)
	if f.block >= height {
		ch <- f.block
		close(ch)
		return ch, nil
	}
	f.waiters[height] = append(f.waiters[height], ch)
	return ch, nil
}

func (f *gateBlockCounter) WatchBlocks(ctx context.Context) <-chan uint64 {
	ch := make(chan uint64)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

// inertPollInterval keeps the supervisor loop out of a test's way; state is
// then driven exclusively by the waiter and the per-operation reads.
const inertPollInterval = time.Hour

func newTestGate(
	t *testing.T,
	schedule Schedule,
	initialBlock uint64,
	pollInterval time.Duration,
) (*chainGate, *gateBlockCounter, *fakeMetrics) {
	t.Helper()

	blockCounter := newGateBlockCounter(initialBlock)
	metrics := newFakeMetrics()

	gate, err := newGate(
		context.Background(),
		schedule,
		blockCounter,
		blockCounter,
		metrics,
		pollInterval,
	)
	if err != nil {
		t.Fatalf("failed to construct gate: [%v]", err)
	}
	t.Cleanup(gate.Close)

	return gate, blockCounter, metrics
}

// eventually polls the condition until it holds or the timeout elapses.
func eventually(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not reached before timeout")
}

func TestNewGate_Validation(t *testing.T) {
	metrics := newFakeMetrics()
	blockCounter := newGateBlockCounter(100)

	if _, err := newGate(
		context.Background(), Schedule{}, nil, blockCounter, metrics, time.Second,
	); err == nil {
		t.Error("expected a nil block counter rejection")
	}

	if _, err := newGate(
		context.Background(), Schedule{}, blockCounter, nil, metrics, time.Second,
	); err == nil {
		t.Error("expected a nil authoritative clock rejection")
	}

	if _, err := newGate(
		context.Background(),
		Schedule{},
		blockCounter,
		blockCounter,
		nil,
		time.Second,
	); err == nil {
		t.Error("expected a nil metrics recorder rejection")
	}

	if _, err := newGate(
		context.Background(), Schedule{}, blockCounter, blockCounter, metrics, 0,
	); err == nil {
		t.Error("expected a non-positive poll interval rejection")
	}

	if _, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: maxSafeMetricInteger + 1},
		blockCounter,
		blockCounter,
		metrics,
		time.Second,
	); err == nil {
		t.Error("expected an unprojectable cutover block rejection")
	}

	failing := newGateBlockCounter(100)
	failing.set(100, fmt.Errorf("clock down"))
	if _, err := newGate(
		context.Background(), Schedule{}, failing, failing, metrics, time.Second,
	); err == nil {
		t.Error("expected a chain-clock error at startup to be rejected")
	}

	unprojectable := newGateBlockCounter(maxSafeMetricInteger + 1)
	if _, err := newGate(
		context.Background(),
		Schedule{},
		unprojectable,
		unprojectable,
		metrics,
		time.Second,
	); err == nil {
		t.Error("expected an unprojectable chain height rejection")
	}

	noWaiter := newGateBlockCounter(100)
	noWaiter.waiterErr = fmt.Errorf("waiter down")
	if _, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: 1000},
		noWaiter,
		noWaiter,
		metrics,
		time.Second,
	); err == nil {
		t.Error("expected a waiter arming error at startup to be rejected")
	}
}

func TestNewGate_RegistersFixedMetrics(t *testing.T) {
	_, _, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 500, inertPollInterval,
	)

	gauges := []string{
		clientinfo.MetricParticipationGateState,
		clientinfo.MetricParticipationCurrentBlock,
		clientinfo.MetricParticipationCutoverBlock,
		clientinfo.MetricParticipationAllowed,
		clientinfo.MetricParticipationActiveCeremonies,
		clientinfo.MetricParticipationActiveLegacyCeremonies,
		clientinfo.MetricParticipationActiveSecurityV2Ceremonies,
	}
	for _, name := range gauges {
		if !metrics.hasGauge(name) {
			t.Errorf("gauge [%s] not registered", name)
		}
	}

	counters := []string{
		clientinfo.MetricParticipationModeLegacyTotal,
		clientinfo.MetricParticipationModeSecurityV2Total,
		clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal,
		clientinfo.MetricParticipationRefusalsTotal,
		clientinfo.MetricParticipationCommitRefusalsTotal,
		clientinfo.MetricParticipationClockErrorsTotal,
		clientinfo.MetricParticipationClockAbortsTotal,
		clientinfo.MetricParticipationQuiesceTotal,
		clientinfo.MetricParticipationQuiesceForcedAbortsTotal,
		clientinfo.MetricHeartbeatPenaltySuppressedTotal,
	}
	for _, ceremony := range AllCeremonies() {
		counters = append(
			counters,
			clientinfo.ParticipationRefusalMetricName(string(ceremony)),
		)
	}
	for _, name := range counters {
		if !metrics.hasCounter(name) {
			t.Errorf("counter [%s] not registered", name)
		}
	}

	if got := metrics.gauge(
		clientinfo.MetricParticipationCutoverBlock,
	); got != 1000 {
		t.Errorf("expected cutover block gauge [1000], got [%f]", got)
	}
	if got := metrics.gauge(
		clientinfo.MetricParticipationCurrentBlock,
	); got != 500 {
		t.Errorf("expected current block gauge [500], got [%f]", got)
	}
	if got := metrics.gauge(clientinfo.MetricParticipationAllowed); got != 1 {
		t.Errorf("expected allowed gauge [1], got [%f]", got)
	}
	if got := metrics.gauge(
		clientinfo.MetricParticipationGateState,
	); got != float64(StateOpenLegacy) {
		t.Errorf("expected state gauge [%d], got [%f]", StateOpenLegacy, got)
	}
}

func TestGate_CeremonyListMatchesClientInfo(t *testing.T) {
	fromClientInfo := clientinfo.GetAllParticipationCeremonies()
	fromGate := AllCeremonies()

	if len(fromClientInfo) != len(fromGate) {
		t.Fatalf(
			"ceremony list length drift: clientinfo [%d], participation [%d]",
			len(fromClientInfo),
			len(fromGate),
		)
	}
	for i, ceremony := range fromGate {
		if fromClientInfo[i] != string(ceremony) {
			t.Errorf(
				"ceremony list drift at [%d]: clientinfo [%s], "+
					"participation [%s]",
				i,
				fromClientInfo[i],
				ceremony,
			)
		}
	}
}

func TestGate_StateTransitionsAtCutoverViaWaiter(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	if state := gate.State().State; state != StateOpenLegacy {
		t.Fatalf("expected initial state open_legacy, got [%s]", state)
	}

	// The armed cutover waiter must flip the state eagerly, without waiting
	// for the (inert) supervisor poll.
	blockCounter.set(1000, nil)
	eventually(t, func() bool {
		return gate.State().State == StateOpenSecurityV2
	})
}

func TestGate_BeginModeFromCanonicalAnchor(t *testing.T) {
	gate, _, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 1500, inertPollInterval,
	)

	// A pre-cutover chain event confirmed after the cutover block classifies
	// by the event's canonical block, not the callback's local arrival height.
	legacy, err := gate.Begin(TBTCDKG, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if legacy.Mode() != ModeLegacy {
		t.Errorf("expected legacy mode, got [%s]", legacy.Mode())
	}
	if legacy.CanonicalStartBlock() != 999 {
		t.Errorf(
			"expected canonical start block [999], got [%d]",
			legacy.CanonicalStartBlock(),
		)
	}
	if legacy.Ceremony() != TBTCDKG {
		t.Errorf("expected ceremony [tbtc_dkg], got [%s]", legacy.Ceremony())
	}

	atCutover, err := gate.Begin(TBTCSigning, 1000)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if atCutover.Mode() != ModeSecurityV2 {
		t.Errorf("expected security_v2 mode, got [%s]", atCutover.Mode())
	}

	after, err := gate.Begin(BeaconDKG, 1500)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if after.Mode() != ModeSecurityV2 {
		t.Errorf("expected security_v2 mode, got [%s]", after.Mode())
	}

	snapshot := gate.State()
	if snapshot.ActiveCeremonies != 3 ||
		snapshot.ActiveLegacyCeremonies != 1 ||
		snapshot.ActiveSecurityV2Ceremonies != 2 {
		t.Errorf(
			"expected active counts 3/1/2, got %d/%d/%d",
			snapshot.ActiveCeremonies,
			snapshot.ActiveLegacyCeremonies,
			snapshot.ActiveSecurityV2Ceremonies,
		)
	}

	if got := metrics.counter(
		clientinfo.MetricParticipationModeLegacyTotal,
	); got != 1 {
		t.Errorf("expected legacy mode counter [1], got [%f]", got)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationModeSecurityV2Total,
	); got != 2 {
		t.Errorf("expected security_v2 mode counter [2], got [%f]", got)
	}

	legacy.Close()
	atCutover.Close()
	after.Close()

	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Errorf("expected zero active ceremonies, got [%d]", active)
	}

	// Close is idempotent: a second close must not unbalance the counts.
	legacy.Close()
	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Errorf(
			"expected zero active ceremonies after double close, got [%d]",
			active,
		)
	}
}

func TestGate_BeginRejectsInvalidAnchors(t *testing.T) {
	gate, _, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 500, inertPollInterval,
	)

	if _, err := gate.Begin(TBTCDKG, 501); !errors.Is(err, ErrInvalidAnchor) {
		t.Errorf("expected a future anchor rejection, got: [%v]", err)
	}

	if _, err := gate.Begin(TBTCDKG, 0); !errors.Is(err, ErrInvalidAnchor) {
		t.Errorf("expected a zero anchor rejection, got: [%v]", err)
	}

	// An anchor equal to the current height is valid: the event is in the
	// current block.
	permit, err := gate.Begin(TBTCDKG, 500)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	permit.Close()

	if got := metrics.counter(
		clientinfo.MetricParticipationRefusalsTotal,
	); got != 2 {
		t.Errorf("expected refusals counter [2], got [%f]", got)
	}
	if got := metrics.counter(
		clientinfo.ParticipationRefusalMetricName(string(TBTCDKG)),
	); got != 2 {
		t.Errorf("expected tbtc_dkg refusals counter [2], got [%f]", got)
	}
}

func TestGate_UnknownCeremonyRejected(t *testing.T) {
	gate, _, _ := newTestGate(t, Schedule{CutoverBlock: 1000}, 500, inertPollInterval)

	if _, err := gate.Begin(Ceremony("bogus"), 100); err == nil {
		t.Error("expected an unknown ceremony rejection")
	}
}

func TestGate_DisabledScheduleAlwaysLegacy(t *testing.T) {
	gate, _, _ := newTestGate(t, Schedule{}, 50, inertPollInterval)

	if state := gate.State().State; state != StateDisabled {
		t.Fatalf("expected disabled state, got [%s]", state)
	}

	// The developer-only disabled schedule accepts a genesis anchor and
	// always selects legacy.
	for _, anchor := range []uint64{0, 50} {
		permit, err := gate.Begin(TBTCSigning, anchor)
		if err != nil {
			t.Fatalf("unexpected error for anchor [%d]: [%v]", anchor, err)
		}
		if permit.Mode() != ModeLegacy {
			t.Errorf(
				"anchor [%d]: expected legacy mode, got [%s]",
				anchor,
				permit.Mode(),
			)
		}

		// The disabled schedule never suppresses penalties by height.
		if err := permit.CheckCommit(
			"test_penalty", PenaltyCommit,
		); err != nil {
			t.Errorf("unexpected penalty fence error: [%v]", err)
		}

		permit.Close()
	}

	if _, err := gate.Begin(TBTCSigning, 51); !errors.Is(err, ErrInvalidAnchor) {
		t.Errorf("expected a future anchor rejection, got: [%v]", err)
	}
}

func TestGate_PermitSurvivesCrossingCutover(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if permit.Mode() != ModeLegacy {
		t.Fatalf("expected legacy mode, got [%s]", permit.Mode())
	}

	// Crossing the cutover block must not cancel the permit or mutate its
	// mode.
	blockCounter.set(1005, nil)

	select {
	case <-permit.Context().Done():
		t.Fatal("crossing the cutover block must not cancel a permit")
	default:
	}

	if permit.Mode() != ModeLegacy {
		t.Errorf("permit mode mutated to [%s]", permit.Mode())
	}

	// A legacy completion commit after the cutover block is allowed and
	// counted.
	if err := permit.CheckCommit(
		"result_submission", CompletionCommit,
	); err != nil {
		t.Errorf("unexpected completion fence error: [%v]", err)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal,
	); got != 1 {
		t.Errorf("expected legacy completions counter [1], got [%f]", got)
	}

	if state := gate.State().State; state != StateOpenSecurityV2 {
		t.Errorf("expected open_security_v2 state, got [%s]", state)
	}
	if active := gate.State().ActiveLegacyCeremonies; active != 1 {
		t.Errorf("expected one active legacy ceremony, got [%d]", active)
	}

	permit.Close()
}

func TestGate_LegacyCompletionBeforeCutoverNotCounted(t *testing.T) {
	gate, _, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 500, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 500)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	if err := permit.CheckCommit("broadcast", CompletionCommit); err != nil {
		t.Errorf("unexpected completion fence error: [%v]", err)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal,
	); got != 0 {
		t.Errorf("expected legacy completions counter [0], got [%f]", got)
	}
}

func TestGate_LegacyPenaltyFence(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	heartbeat, err := gate.Begin(TBTCHeartbeat, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer heartbeat.Close()

	timeoutReport, err := gate.Begin(BeaconTimeoutReport, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer timeoutReport.Close()

	// Below the cutover block, a legacy penalty commit is normal work.
	if err := heartbeat.CheckCommit(
		"inactivity_claim", PenaltyCommit,
	); err != nil {
		t.Fatalf("unexpected penalty fence error below cutover: [%v]", err)
	}

	// At and after the cutover block, a legacy penalty commit is suppressed.
	blockCounter.set(1000, nil)
	err = heartbeat.CheckCommit("inactivity_claim", PenaltyCommit)
	if !errors.Is(err, ErrPenaltySuppressed) {
		t.Errorf("expected a suppressed penalty, got: [%v]", err)
	}
	if got := metrics.counter(
		clientinfo.MetricHeartbeatPenaltySuppressedTotal,
	); got != 1 {
		t.Errorf("expected heartbeat suppression counter [1], got [%f]", got)
	}

	// A non-heartbeat penalty suppression counts as a commit refusal but not
	// as a heartbeat suppression.
	err = timeoutReport.CheckCommit("timeout_report", PenaltyCommit)
	if !errors.Is(err, ErrPenaltySuppressed) {
		t.Errorf("expected a suppressed penalty, got: [%v]", err)
	}
	if got := metrics.counter(
		clientinfo.MetricHeartbeatPenaltySuppressedTotal,
	); got != 1 {
		t.Errorf(
			"expected heartbeat suppression counter to stay [1], got [%f]",
			got,
		)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationCommitRefusalsTotal,
	); got != 2 {
		t.Errorf("expected commit refusals counter [2], got [%f]", got)
	}

	// A completion commit for the same legacy permit remains allowed.
	if err := heartbeat.CheckCommit(
		"heartbeat_signature", CompletionCommit,
	); err != nil {
		t.Errorf("unexpected completion fence error: [%v]", err)
	}
}

func TestGate_SecurityV2CommitFences(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 1200, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 1100)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()
	if permit.Mode() != ModeSecurityV2 {
		t.Fatalf("expected security_v2 mode, got [%s]", permit.Mode())
	}

	if err := permit.CheckCommit("broadcast", CompletionCommit); err != nil {
		t.Fatalf("unexpected completion fence error: [%v]", err)
	}
	if err := permit.CheckCommit("penalty", PenaltyCommit); err != nil {
		t.Fatalf("unexpected penalty fence error: [%v]", err)
	}

	// After a deep reorg below the cutover block, a security-v2 commit must
	// be refused; the permit itself remains alive.
	blockCounter.set(999, nil)
	err = permit.CheckCommit("broadcast", CompletionCommit)
	if !errors.Is(err, ErrCommitBeforeCutover) {
		t.Errorf("expected a below-cutover refusal, got: [%v]", err)
	}
	select {
	case <-permit.Context().Done():
		t.Fatal("a refused commit must not cancel the permit")
	default:
	}

	// Once the chain recovers, the same permit commits normally again.
	blockCounter.set(1200, nil)
	if err := permit.CheckCommit("broadcast", CompletionCommit); err != nil {
		t.Errorf("unexpected completion fence error after recovery: [%v]", err)
	}
}

func TestGate_UnknownCommitClassFailsClosed(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCHeartbeat, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	// An unknown class must not become an implicit completion or penalty.
	// Exercise it after C, where treating it as neither would bypass the
	// legacy penalty fence.
	blockCounter.set(1000, nil)
	err = permit.CheckCommit("unknown", CommitClass(0))
	if !errors.Is(err, ErrInvalidCommitClass) {
		t.Errorf("expected an invalid commit class refusal, got: [%v]", err)
	}
	if !IsGateRefusal(err) {
		t.Errorf("expected the invalid commit class to be a gate refusal: [%v]", err)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationCommitRefusalsTotal,
	); got != 1 {
		t.Errorf("expected commit refusals counter [1], got [%f]", got)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal,
	); got != 0 {
		t.Errorf("expected legacy completions counter [0], got [%f]", got)
	}
	if got := metrics.counter(
		clientinfo.MetricHeartbeatPenaltySuppressedTotal,
	); got != 0 {
		t.Errorf("expected heartbeat suppressions counter [0], got [%f]", got)
	}
}

func TestGate_ResumeOnlyForBeaconRelaySigning(t *testing.T) {
	gate, _, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 1500, inertPollInterval,
	)

	for _, ceremony := range []Ceremony{
		TBTCDKG,
		TBTCSigning,
		TBTCHeartbeat,
		BeaconDKG,
		BeaconRelayForwarding,
		BeaconTimeoutReport,
	} {
		if _, err := gate.Resume(
			ceremony, 900,
		); !errors.Is(err, ErrResumeUnsupported) {
			t.Errorf(
				"expected resume rejection for [%s], got: [%v]",
				ceremony,
				err,
			)
		}
	}

	// The beacon relay restart path resumes with the mode pinned from the
	// on-chain request start block.
	legacy, err := gate.Resume(BeaconRelaySigning, 900)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if legacy.Mode() != ModeLegacy {
		t.Errorf("expected legacy mode, got [%s]", legacy.Mode())
	}
	legacy.Close()

	hardened, err := gate.Resume(BeaconRelaySigning, 1100)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if hardened.Mode() != ModeSecurityV2 {
		t.Errorf("expected security_v2 mode, got [%s]", hardened.Mode())
	}
	hardened.Close()

	if _, err := gate.Resume(
		BeaconRelaySigning, 2000,
	); !errors.Is(err, ErrInvalidAnchor) {
		t.Errorf("expected a future anchor rejection, got: [%v]", err)
	}
}

func TestGate_ClockFailureCancelsPermits(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	legacy, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	blockCounter.set(1100, nil)
	hardened, err := gate.Begin(TBTCDKG, 1100)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	// A failed synchronous read anywhere atomically fails the whole gate.
	blockCounter.set(1100, fmt.Errorf("rpc down"))
	if _, err := gate.Begin(
		TBTCSigning, 1100,
	); !errors.Is(err, ErrClockUnavailable) {
		t.Fatalf("expected a clock-unavailable refusal, got: [%v]", err)
	}

	if state := gate.State().State; state != StateClockUnavailable {
		t.Errorf("expected clock_unavailable state, got [%s]", state)
	}
	if gate.State().Allowed {
		t.Error("expected the gate to refuse new permits")
	}

	for _, p := range []Permit{legacy, hardened} {
		select {
		case <-p.Context().Done():
		default:
			t.Fatal("expected the permit to be canceled by clock failure")
		}
		if cause := context.Cause(
			p.Context(),
		); !errors.Is(cause, ErrClockUnavailable) {
			t.Errorf(
				"expected cancellation cause clock-unavailable, got: [%v]",
				cause,
			)
		}
		if err := p.CheckCommit(
			"anything", CompletionCommit,
		); !errors.Is(err, ErrClockUnavailable) {
			t.Errorf(
				"expected a canceled-permit commit refusal, got: [%v]",
				err,
			)
		}
	}

	if got := metrics.counter(
		clientinfo.MetricParticipationClockAbortsTotal,
	); got != 2 {
		t.Errorf("expected clock aborts counter [2], got [%f]", got)
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationClockErrorsTotal,
	); got == 0 {
		t.Error("expected a nonzero clock errors counter")
	}

	// The next successful read recomputes the state, but canceled permits do
	// not revive.
	blockCounter.set(1100, nil)
	fresh, err := gate.Begin(TBTCSigning, 1100)
	if err != nil {
		t.Fatalf("unexpected error after clock recovery: [%v]", err)
	}
	if state := gate.State().State; state != StateOpenSecurityV2 {
		t.Errorf("expected open_security_v2 state, got [%s]", state)
	}
	if cause := context.Cause(
		legacy.Context(),
	); !errors.Is(cause, ErrClockUnavailable) {
		t.Error("expected the canceled permit to stay canceled")
	}

	fresh.Close()
	legacy.Close()
	hardened.Close()
}

func TestGate_SupervisorUsesAuthoritativeClockNotCache(t *testing.T) {
	t.Parallel()

	cache := newGateBlockCounter(1000)
	auth := &staticAuthClock{height: 1000}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gate, err := newGate(
		ctx,
		Schedule{CutoverBlock: 1000},
		cache,
		auth,
		newFakeMetrics(),
		time.Millisecond*20,
	)
	if err != nil {
		t.Fatalf("newGate: %v", err)
	}
	defer gate.Close()

	auth.set(0, errors.New("rpc unavailable"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gate.State().State == StateClockUnavailable {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf(
		"expected clock_unavailable while cache still returns height; got %s",
		gate.State().State,
	)
}

type staticAuthClock struct {
	mu     sync.Mutex
	height uint64
	err    error
}

func (s *staticAuthClock) CurrentHeight(context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.height, s.err
}

func (s *staticAuthClock) set(height uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.height = height
	s.err = err
}

func TestGate_ClockFailureViaSupervisorPoll(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, 5*time.Millisecond,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	blockCounter.set(999, fmt.Errorf("rpc down"))
	eventually(t, func() bool {
		return gate.State().State == StateClockUnavailable
	})
	select {
	case <-permit.Context().Done():
	default:
		t.Fatal("expected the supervisor to cancel the permit")
	}

	// Recovery restores the open state without reviving the permit.
	blockCounter.set(999, nil)
	eventually(t, func() bool {
		return gate.State().State == StateOpenLegacy
	})
	if cause := context.Cause(
		permit.Context(),
	); !errors.Is(cause, ErrClockUnavailable) {
		t.Error("expected the canceled permit to stay canceled")
	}
}

func TestGate_WaiterCloseWithoutValueIsClockFailure(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	blockCounter.failWaiters()
	eventually(t, func() bool {
		return gate.State().State == StateClockUnavailable
	})
	select {
	case <-permit.Context().Done():
	default:
		t.Fatal("expected a waiter failure to cancel the permit")
	}
}

func TestGate_QuiesceLifecycle(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	legacy, err := gate.Begin(TBTCHeartbeat, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	blockCounter.set(1100, nil)
	hardened, err := gate.Begin(TBTCSigning, 1100)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	done := gate.Quiesce(fmt.Errorf("shutdown signal"))

	if state := gate.State().State; state != StateQuiescing {
		t.Errorf("expected quiescing state, got [%s]", state)
	}
	if _, err := gate.Begin(
		TBTCSigning, 1100,
	); !errors.Is(err, ErrQuiescing) {
		t.Errorf("expected a quiescing refusal, got: [%v]", err)
	}

	// Quiescence keeps existing permits alive to natural completion.
	select {
	case <-legacy.Context().Done():
		t.Fatal("quiescence must not cancel existing permits")
	default:
	}

	// Penalty commits are refused for every permit from the transition
	// onward; completion commits remain allowed.
	if err := legacy.CheckCommit(
		"inactivity_claim", PenaltyCommit,
	); !errors.Is(err, ErrPenaltySuppressed) {
		t.Errorf("expected a suppressed legacy penalty, got: [%v]", err)
	}
	if err := hardened.CheckCommit(
		"timeout_report", PenaltyCommit,
	); !errors.Is(err, ErrPenaltySuppressed) {
		t.Errorf("expected a suppressed security-v2 penalty, got: [%v]", err)
	}
	if err := legacy.CheckCommit(
		"heartbeat_signature", CompletionCommit,
	); err != nil {
		t.Errorf("unexpected completion fence error: [%v]", err)
	}
	if err := hardened.CheckCommit("broadcast", CompletionCommit); err != nil {
		t.Errorf("unexpected completion fence error: [%v]", err)
	}

	// The quiesce channel closes exactly when the active count reaches zero.
	select {
	case <-done:
		t.Fatal("quiesce channel closed with active permits")
	default:
	}

	// Quiesce is idempotent and returns the same channel.
	if again := gate.Quiesce(fmt.Errorf("second signal")); again != done {
		t.Error("expected the same quiesce channel")
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationQuiesceTotal,
	); got != 1 {
		t.Errorf("expected quiesce counter [1], got [%f]", got)
	}

	legacy.Close()
	select {
	case <-done:
		t.Fatal("quiesce channel closed with one active permit")
	default:
	}

	hardened.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("quiesce channel did not close at zero active permits")
	}
}

func TestGate_QuiescenceCapturesRealPermitInventoryAtomically(t *testing.T) {
	const cutover = uint64(1000)
	capturedAt := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	blockCounter := newGateBlockCounter(cutover - 1)
	recorder := &recordingQuiescenceSnapshotRecorder{}

	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		blockCounter,
		blockCounter,
		newFakeMetrics(),
		inertPollInterval,
		WithArtifactIdentity("v2.1.0", "revision-test"),
		WithQuiescenceSnapshotRecorder(recorder),
		withGateTimeSource(func() time.Time { return capturedAt }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	if _, err := gate.Begin(
		TBTCSigning,
		cutover-1,
	); !errors.Is(err, ErrInvalidPermitIdentity) {
		t.Fatalf(
			"expected production issuance without identity to fail, got [%v]",
			err,
		)
	}

	legacy, err := gate.Begin(
		TBTCSigning,
		cutover-1,
		PermitIdentity{
			WorkID:   "wallet-action-legacy",
			PermitID: "wallet-legacy",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Begin(
		TBTCSigning,
		cutover-1,
		PermitIdentity{
			WorkID:   "wallet-action-legacy",
			PermitID: "wallet-legacy",
		},
	); !errors.Is(err, ErrInvalidPermitIdentity) {
		t.Fatalf("expected duplicate permit identity rejection, got [%v]", err)
	}
	blockCounter.set(cutover, nil)
	securityV2, err := gate.Begin(
		BeaconRelaySigning,
		cutover,
		PermitIdentity{
			WorkID:          "relay-request-security-v2",
			PermitID:        "2",
			OperatedMembers: MemberIndexes{2},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	before := gate.State()
	if len(before.ActivePermits) != 2 {
		t.Fatalf(
			"expected the live gate snapshot to inventory two permits, got [%d]",
			len(before.ActivePermits),
		)
	}

	gate.Quiesce(fmt.Errorf("rollback drill"))
	legacy.Close()
	securityV2.Close()

	snapshot, ok := gate.QuiescenceSnapshot()
	if !ok {
		t.Fatal("expected a quiescence snapshot")
	}
	if snapshot.CapturedAt != capturedAt {
		t.Errorf(
			"expected capture time [%s], got [%s]",
			capturedAt,
			snapshot.CapturedAt,
		)
	}
	if snapshot.ReleaseVersion != "v2.1.0" ||
		snapshot.ReleaseRevision != "revision-test" ||
		snapshot.ReleaseEpoch != CompiledEpoch.String() {
		t.Errorf("unexpected artifact identity: %+v", snapshot)
	}
	if snapshot.CutoverBlock != cutover ||
		snapshot.State != StateQuiescing.String() ||
		snapshot.QuiesceCause != "rollback drill" {
		t.Errorf("unexpected quiescence binding: %+v", snapshot)
	}
	if snapshot.ActiveCeremonies != 2 ||
		snapshot.ActiveLegacyCeremonies != 1 ||
		snapshot.ActiveSecurityV2Ceremonies != 1 ||
		len(snapshot.ActivePermits) != 2 {
		t.Errorf("unexpected captured inventory: %+v", snapshot)
	}
	for _, permit := range snapshot.ActivePermits {
		if !permit.IdentityBound {
			t.Errorf("expected a bound permit identity: %+v", permit)
		}
	}

	recorded := recorder.recorded()
	if len(recorded) != 1 {
		t.Fatalf("expected exactly one persisted snapshot, got [%d]", len(recorded))
	}
	if fmt.Sprint(recorded[0]) != fmt.Sprint(snapshot) {
		t.Errorf(
			"persisted snapshot differs from the gate capture\npersisted: %+v\n"+
				"captured: %+v",
			recorded[0],
			snapshot,
		)
	}

	// Closing permits after the transition cannot rewrite history.
	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Fatalf("expected the live gate to drain, got [%d] permits", active)
	}
	again, ok := gate.QuiescenceSnapshot()
	if !ok || again.ActiveCeremonies != 2 || len(again.ActivePermits) != 2 {
		t.Errorf("quiescence inventory mutated after drain: %+v", again)
	}

	// Returned slices are defensive copies.
	again.ActivePermits[0].WorkID = "mutated"
	final, _ := gate.QuiescenceSnapshot()
	if final.ActivePermits[0].WorkID == "mutated" {
		t.Error("the caller mutated the gate's retained quiescence inventory")
	}
}

func TestGate_QuiesceOnIdleGateClosesImmediately(t *testing.T) {
	gate, _, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	done := gate.Quiesce(fmt.Errorf("shutdown signal"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("quiesce channel did not close on an idle gate")
	}
}

func TestGate_CloseForcesQuiesceDeadline(t *testing.T) {
	gate, _, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	first, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	second, err := gate.Begin(TBTCHeartbeat, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	done := gate.Quiesce(fmt.Errorf("shutdown signal"))
	gate.Close()

	for _, p := range []Permit{first, second} {
		select {
		case <-p.Context().Done():
		default:
			t.Fatal("expected the permit to be force-canceled at close")
		}
		if cause := context.Cause(
			p.Context(),
		); !errors.Is(cause, ErrQuiesceDeadline) {
			t.Errorf(
				"expected cancellation cause quiesce-deadline, got: [%v]",
				cause,
			)
		}
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("quiesce channel did not close at gate close")
	}

	if got := metrics.counter(
		clientinfo.MetricParticipationQuiesceForcedAbortsTotal,
	); got != 2 {
		t.Errorf("expected forced aborts counter [2], got [%f]", got)
	}

	if _, err := gate.Begin(TBTCSigning, 999); !errors.Is(err, ErrQuiescing) {
		t.Errorf("expected a refusal after close, got: [%v]", err)
	}
	if err := first.CheckCommit(
		"anything", CompletionCommit,
	); !errors.Is(err, ErrQuiesceDeadline) {
		t.Errorf("expected a forced-abort commit refusal, got: [%v]", err)
	}

	// Close is idempotent: no double counting.
	gate.Close()
	if got := metrics.counter(
		clientinfo.MetricParticipationQuiesceForcedAbortsTotal,
	); got != 2 {
		t.Errorf(
			"expected forced aborts counter to stay [2], got [%f]",
			got,
		)
	}

	first.Close()
	second.Close()
}

// TestGate_DrainedJoinsForcedPermitRelease pins the two-phase forced
// cancellation: Close closes the quiesce channel immediately, but the drained
// channel stays open until the owner of every force-canceled permit releases
// it — the window in which the cancellation cleanup, quarantine writes
// included, is still running.
func TestGate_DrainedJoinsForcedPermitRelease(t *testing.T) {
	gate, _, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	drained := gate.Drained()

	done := gate.Quiesce(fmt.Errorf("shutdown signal"))
	gate.Close()

	select {
	case <-done:
	default:
		t.Fatal("quiesce channel must close at gate close")
	}
	select {
	case <-drained:
		t.Fatal("drained channel closed while a force-canceled permit was held")
	default:
	}

	permit.Close()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("drained channel did not close at the last permit release")
	}
}

// TestGate_DrainedClosesWithNaturalQuiesceCompletion proves the drained
// channel needs no Close on the natural path: once quiescence begins, the
// release of the last permit both completes the quiesce drain and drains the
// gate.
func TestGate_DrainedClosesWithNaturalQuiesceCompletion(t *testing.T) {
	gate, _, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	drained := gate.Drained()

	gate.Quiesce(fmt.Errorf("shutdown signal"))
	select {
	case <-drained:
		t.Fatal("drained channel closed with an active permit")
	default:
	}

	permit.Close()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("drained channel did not close at natural completion")
	}
}

// TestGate_DrainedStaysOpenWhileGateIssuesPermits pins the boundary of the
// drained condition: neither an active count reaching zero during normal
// operation nor a clock-failure cancellation drains the gate, because both
// leave it able to issue permits again. Only quiescence or close does.
func TestGate_DrainedStaysOpenWhileGateIssuesPermits(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)
	drained := gate.Drained()

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	permit.Close()
	select {
	case <-drained:
		t.Fatal("drained channel closed while the gate still issues permits")
	default:
	}

	held, err := gate.Begin(TBTCDKG, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	blockCounter.set(999, fmt.Errorf("rpc down"))
	if _, err := gate.Begin(
		TBTCHeartbeat, 999,
	); !errors.Is(err, ErrClockUnavailable) {
		t.Fatalf("expected a clock-unavailable refusal, got: [%v]", err)
	}
	if cause := context.Cause(
		held.Context(),
	); !errors.Is(cause, ErrClockUnavailable) {
		t.Fatalf("expected a clock-failure cancellation, got: [%v]", cause)
	}
	held.Close()
	select {
	case <-drained:
		t.Fatal("drained channel closed on a clock-failure cancellation")
	default:
	}

	gate.Close()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("drained channel did not close at the close of an idle gate")
	}
}

func TestGate_ClosedPermitCommitRefused(t *testing.T) {
	gate, _, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	permit.Close()

	if err := permit.CheckCommit(
		"anything", CompletionCommit,
	); !errors.Is(err, ErrPermitClosed) {
		t.Errorf("expected a closed-permit commit refusal, got: [%v]", err)
	}
}

// TestGate_StaleClockSuccessCannotReopenGate pins the clock-sample ordering
// for permit issuance: a successful read initiated before a newer failing read
// but applied after it must be discarded. The issuing operation fails closed
// and the gate stays clock-unavailable instead of silently reopening.
func TestGate_StaleClockSuccessCannotReopenGate(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	existing, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer existing.Close()

	started, release := blockCounter.holdNextRead()

	// This Begin's read snapshots a healthy chain view, then stalls in flight.
	staleResult := make(chan error, 1)
	go func() {
		_, err := gate.Begin(TBTCDKG, 999)
		staleResult <- err
	}()
	<-started

	// A read initiated after the held one fails and must win permanently.
	blockCounter.set(999, fmt.Errorf("rpc down"))
	if _, err := gate.Begin(
		TBTCHeartbeat, 999,
	); !errors.Is(err, ErrClockUnavailable) {
		t.Fatalf("expected a clock-unavailable refusal, got: [%v]", err)
	}
	if state := gate.State().State; state != StateClockUnavailable {
		t.Fatalf("expected clock_unavailable state, got [%s]", state)
	}

	// The stale success lands last: it must not reopen the gate, must not
	// issue a permit, and must not revive the canceled permit.
	release()
	if err := <-staleResult; !errors.Is(err, ErrClockUnavailable) {
		t.Errorf("expected the stale Begin to fail closed, got: [%v]", err)
	}
	snapshot := gate.State()
	if snapshot.State != StateClockUnavailable {
		t.Errorf(
			"expected the gate to stay clock_unavailable, got [%s]",
			snapshot.State,
		)
	}
	if snapshot.ClockAvailable {
		t.Error("expected the clock to stay unavailable")
	}
	if snapshot.Allowed {
		t.Error("expected the gate to keep refusing new permits")
	}
	if cause := context.Cause(
		existing.Context(),
	); !errors.Is(cause, ErrClockUnavailable) {
		t.Errorf("expected the canceled permit to stay canceled, got: [%v]", cause)
	}
}

// TestGate_StaleClockSuccessCannotReopenGateViaFence pins the same ordering
// for the commit fence path: a stalled successful fence read applied after a
// newer failure is discarded, the fence refuses, and the gate stays failed.
func TestGate_StaleClockSuccessCannotReopenGateViaFence(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()
	other, err := gate.Begin(TBTCHeartbeat, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer other.Close()

	started, release := blockCounter.holdNextRead()

	staleResult := make(chan error, 1)
	go func() {
		staleResult <- permit.CheckCommit(
			"result_submission", CompletionCommit,
		)
	}()
	<-started

	blockCounter.set(999, fmt.Errorf("rpc down"))
	if err := other.CheckCommit(
		"heartbeat_signature", CompletionCommit,
	); !errors.Is(err, ErrClockUnavailable) {
		t.Fatalf("expected a clock-unavailable fence refusal, got: [%v]", err)
	}
	if state := gate.State().State; state != StateClockUnavailable {
		t.Fatalf("expected clock_unavailable state, got [%s]", state)
	}

	release()
	if err := <-staleResult; !errors.Is(err, ErrClockUnavailable) {
		t.Errorf("expected the stale fence to fail closed, got: [%v]", err)
	}
	snapshot := gate.State()
	if snapshot.State != StateClockUnavailable {
		t.Errorf(
			"expected the gate to stay clock_unavailable, got [%s]",
			snapshot.State,
		)
	}
	if snapshot.ClockAvailable {
		t.Error("expected the clock to stay unavailable")
	}
}

// TestGate_StaleClockFailureCannotCancelAfterNewerSuccess pins the symmetric
// ordering guarantee: a failing read initiated before a newer successful read
// but applied after it refuses only its own operation. It must not transition
// the gate to clock-unavailable or cancel permits on stale information.
func TestGate_StaleClockFailureCannotCancelAfterNewerSuccess(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	// The held read snapshots a transient failure, then stalls in flight.
	blockCounter.set(999, fmt.Errorf("transient rpc error"))
	started, release := blockCounter.holdNextRead()

	staleResult := make(chan error, 1)
	go func() {
		_, err := gate.Begin(TBTCDKG, 999)
		staleResult <- err
	}()
	<-started

	// The chain recovers and a newer read succeeds before the stale failure
	// lands.
	blockCounter.set(1000, nil)
	fresh, err := gate.Begin(BeaconDKG, 1000)
	if err != nil {
		t.Fatalf("unexpected error after recovery: [%v]", err)
	}
	defer fresh.Close()

	release()
	// The operation whose own read failed still fails closed.
	if err := <-staleResult; !errors.Is(err, ErrClockUnavailable) {
		t.Errorf("expected the stale Begin to fail closed, got: [%v]", err)
	}
	// But the stale failure must not have transitioned the gate or canceled
	// anything.
	snapshot := gate.State()
	if snapshot.State != StateOpenSecurityV2 {
		t.Errorf("expected open_security_v2 state, got [%s]", snapshot.State)
	}
	if !snapshot.ClockAvailable {
		t.Error("expected the clock to stay available")
	}
	select {
	case <-permit.Context().Done():
		t.Error("a stale clock failure must not cancel permits")
	default:
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationClockAbortsTotal,
	); got != 0 {
		t.Errorf("expected zero clock aborts, got [%f]", got)
	}
}

// TestGate_WaiterFireWithFailingReadIsClockFailure pins that the cutover
// waiter is telemetry-only: recovery and state advancement require a
// successful synchronous read. A waiter that reports its target while the
// synchronous clock fails must produce clock-unavailable, not a transition,
// and must not project the waiter's height.
func TestGate_WaiterFireWithFailingReadIsClockFailure(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	// Reads fail from here on; the armed cutover waiter stays deliverable.
	blockCounter.set(999, fmt.Errorf("rpc down"))
	blockCounter.deliverWaiters(1000)

	eventually(t, func() bool {
		return gate.State().State == StateClockUnavailable
	})
	snapshot := gate.State()
	if snapshot.CurrentBlock != 999 {
		t.Errorf(
			"expected the waiter height to be discarded and the current "+
				"block to stay [999], got [%d]",
			snapshot.CurrentBlock,
		)
	}
	if cause := context.Cause(
		permit.Context(),
	); !errors.Is(cause, ErrClockUnavailable) {
		t.Errorf("expected a clock-unavailable cancellation, got: [%v]", cause)
	}
}

// TestGate_WaiterFireWithLaggingReadStaysAuthoritative pins that a waiter
// firing at the cutover target cannot advance the state past what the
// authoritative synchronous read reports: a healthy read still below the
// cutover block keeps the gate open in legacy state.
func TestGate_WaiterFireWithLaggingReadStaysAuthoritative(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	reads := blockCounter.readCount()
	blockCounter.deliverWaiters(1000)

	// Wait for the waiter-triggered authoritative poll to have read the
	// (still lagging) clock.
	eventually(t, func() bool {
		return blockCounter.readCount() > reads
	})

	snapshot := gate.State()
	if snapshot.State != StateOpenLegacy {
		t.Errorf(
			"expected the lagging read to keep open_legacy, got [%s]",
			snapshot.State,
		)
	}
	if snapshot.CurrentBlock != 999 {
		t.Errorf(
			"expected current block [999] from the authoritative read, "+
				"got [%d]",
			snapshot.CurrentBlock,
		)
	}

	// Once the synchronous clock itself reports the cutover height, new work
	// selects security-v2: the gate stayed live throughout.
	blockCounter.set(1000, nil)
	permit, err := gate.Begin(TBTCDKG, 1000)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if permit.Mode() != ModeSecurityV2 {
		t.Errorf("expected security_v2 mode, got [%s]", permit.Mode())
	}
	permit.Close()
}

// TestGate_UnprojectableHeightIsClockFailure pins that a chain height the
// float64 metrics projection cannot represent exactly is handled as a clock
// failure at runtime instead of being exported imprecisely.
func TestGate_UnprojectableHeightIsClockFailure(t *testing.T) {
	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 999, inertPollInterval,
	)

	permit, err := gate.Begin(TBTCSigning, 999)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()

	blockCounter.set(maxSafeMetricInteger+1, nil)
	if _, err := gate.Begin(
		TBTCDKG, 999,
	); !errors.Is(err, ErrClockUnavailable) {
		t.Fatalf("expected a clock-unavailable refusal, got: [%v]", err)
	}
	if state := gate.State().State; state != StateClockUnavailable {
		t.Errorf("expected clock_unavailable state, got [%s]", state)
	}
	if cause := context.Cause(
		permit.Context(),
	); !errors.Is(cause, ErrClockUnavailable) {
		t.Errorf("expected a clock-unavailable cancellation, got: [%v]", cause)
	}
	if current := gate.State().CurrentBlock; current != 999 {
		t.Errorf(
			"expected the unprojectable height to be discarded and the "+
				"current block to stay [999], got [%d]",
			current,
		)
	}
}

// TestGate_StaleUnprojectableHeightStillFailsItsOperation pins that an
// unprojectable height belongs to its own read's result: a Begin whose read
// snapshots a height above the metric projection limit fails closed even when
// a newer valid sample applies first, discards the stale sample, and keeps the
// gate available. The discarded sample must not fail the gate or cancel
// permits, exactly like a superseded RPC error.
func TestGate_StaleUnprojectableHeightStillFailsItsOperation(t *testing.T) {
	// Constructing at the cutover height fires the construction-armed cutover
	// waiter immediately, so its one-shot telemetry poll is the only background
	// read; wait it out so nothing races the held-read choreography below.
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 1000, inertPollInterval,
	)
	eventually(t, func() bool { return blockCounter.readCount() >= 2 })

	existing, err := gate.Begin(TBTCSigning, 1000)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer existing.Close()

	// The held read snapshots an unprojectable height, then stalls in flight.
	blockCounter.set(maxSafeMetricInteger+1, nil)
	started, release := blockCounter.holdNextRead()

	staleResult := make(chan error, 1)
	go func() {
		p, err := gate.Begin(TBTCDKG, 1000)
		if err == nil {
			p.Close()
		}
		staleResult <- err
	}()
	<-started

	// The chain recovers and a newer read succeeds before the stale
	// unprojectable sample lands.
	blockCounter.set(1005, nil)
	fresh, err := gate.Begin(BeaconDKG, 1005)
	if err != nil {
		t.Fatalf("unexpected error after recovery: [%v]", err)
	}
	defer fresh.Close()

	release()
	// The operation whose own read was unprojectable still fails closed.
	if err := <-staleResult; !errors.Is(err, ErrClockUnavailable) {
		t.Errorf("expected the stale Begin to fail closed, got: [%v]", err)
	}
	// But the discarded stale sample must not have transitioned the gate or
	// canceled anything.
	snapshot := gate.State()
	if snapshot.State != StateOpenSecurityV2 {
		t.Errorf("expected open_security_v2 state, got [%s]", snapshot.State)
	}
	if !snapshot.ClockAvailable {
		t.Error("expected the clock to stay available")
	}
	if snapshot.CurrentBlock != 1005 {
		t.Errorf(
			"expected the newer valid height [1005] to remain, got [%d]",
			snapshot.CurrentBlock,
		)
	}
	select {
	case <-existing.Context().Done():
		t.Error("a stale unprojectable sample must not cancel permits")
	default:
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationClockAbortsTotal,
	); got != 0 {
		t.Errorf("expected zero clock aborts, got [%f]", got)
	}
}

// TestGate_StaleUnprojectableHeightStillFailsItsFence pins the same guarantee
// for the commit fence path: a fence whose own read snapshots an unprojectable
// height refuses even when a newer valid sample applied first and kept the
// gate available for everyone else.
func TestGate_StaleUnprojectableHeightStillFailsItsFence(t *testing.T) {
	gate, blockCounter, metrics := newTestGate(
		t, Schedule{CutoverBlock: 1000}, 1000, inertPollInterval,
	)
	eventually(t, func() bool { return blockCounter.readCount() >= 2 })

	permit, err := gate.Begin(TBTCSigning, 1000)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer permit.Close()
	other, err := gate.Begin(TBTCHeartbeat, 1000)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	defer other.Close()

	blockCounter.set(maxSafeMetricInteger+1, nil)
	started, release := blockCounter.holdNextRead()

	staleResult := make(chan error, 1)
	go func() {
		staleResult <- permit.CheckCommit(
			"result_submission", CompletionCommit,
		)
	}()
	<-started

	blockCounter.set(1005, nil)
	if err := other.CheckCommit(
		"heartbeat_signature", CompletionCommit,
	); err != nil {
		t.Fatalf("unexpected fence error after recovery: [%v]", err)
	}

	release()
	// The fence whose own read was unprojectable still fails closed.
	if err := <-staleResult; !errors.Is(err, ErrClockUnavailable) {
		t.Errorf("expected the stale fence to fail closed, got: [%v]", err)
	}
	// The discarded stale sample left the gate available on the newer height.
	snapshot := gate.State()
	if snapshot.State != StateOpenSecurityV2 {
		t.Errorf("expected open_security_v2 state, got [%s]", snapshot.State)
	}
	if !snapshot.ClockAvailable {
		t.Error("expected the clock to stay available")
	}
	for _, p := range []Permit{permit, other} {
		select {
		case <-p.Context().Done():
			t.Error("a stale unprojectable sample must not cancel permits")
		default:
		}
	}
	if got := metrics.counter(
		clientinfo.MetricParticipationClockAbortsTotal,
	); got != 0 {
		t.Errorf("expected zero clock aborts, got [%f]", got)
	}
}

// TestGate_ConcurrentBeginAcrossCutover races permit issuance, commit fences,
// state reads, and permit closes against the chain crossing the cutover block,
// a mid-flight Quiesce, and the terminal gate Close, all genuinely
// overlapping. The invariants: a permit is pinned legacy for an anchor below C
// and security-v2 at/above C regardless of which goroutine observed C first;
// every fence outcome is one of the exactly allowed sentinels for its commit
// class (the clock never fails here, so a clock sentinel is a bug); and the
// active-permit accounting balances to zero once every owner closed.
func TestGate_ConcurrentBeginAcrossCutover(t *testing.T) {
	const cutover = uint64(1000)

	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: cutover}, cutover-10, 3*time.Millisecond,
	)

	var wg sync.WaitGroup
	lifecycleDone := make(chan struct{})

	// Advance the chain across the cutover block while workers race, and keep
	// stepping until the lifecycle goroutine has closed the gate so crossing,
	// quiescence, and close all overlap live traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		height := cutover - 10
		for {
			blockCounter.set(height, nil)
			height++
			select {
			case <-lifecycleDone:
				return
			case <-time.After(500 * time.Microsecond):
			}
		}
	}()

	// Quiesce once the gate has observably crossed the cutover block, then
	// close shortly after, while workers still hammer the gate.
	var quiesceDone <-chan struct{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lifecycleDone)
		for gate.State().CurrentBlock < cutover+2 {
			time.Sleep(200 * time.Microsecond)
		}
		quiesceDone = gate.Quiesce(fmt.Errorf("test quiesce"))
		time.Sleep(2 * time.Millisecond)
		gate.Close()
	}()

	// The exact allowed fence outcomes. Completion commits stay allowed
	// through crossing and quiescence and refuse only after the forced
	// close; penalty commits are additionally suppressed for legacy permits
	// at/after C and for every permit once quiescence begins.
	completionAllowed := func(err error) bool {
		return err == nil || errors.Is(err, ErrQuiesceDeadline)
	}
	penaltyAllowed := func(err error) bool {
		return err == nil ||
			errors.Is(err, ErrPenaltySuppressed) ||
			errors.Is(err, ErrQuiesceDeadline)
	}

	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var held []Permit
			defer func() {
				for _, p := range held {
					p.Close()
				}
			}()

			// Run until the lifecycle finished, then a few bonus iterations
			// so the closed-gate paths are exercised too.
			bonus := 0
			for bonus <= 10 {
				select {
				case <-lifecycleDone:
					bonus++
				default:
				}

				anchor, err := blockCounter.CurrentBlock()
				if err != nil {
					continue
				}

				permit, err := gate.Begin(TBTCHeartbeat, anchor)
				if err != nil {
					// The gate may have quiesced or closed, and an anchor can
					// race one step ahead of a concurrent reader's applied
					// height. Nothing else is acceptable.
					if !errors.Is(err, ErrQuiescing) &&
						!errors.Is(err, ErrInvalidAnchor) {
						t.Errorf("unexpected Begin error: [%v]", err)
					}
				} else {
					expected := ModeLegacy
					if anchor >= cutover {
						expected = ModeSecurityV2
					}
					if permit.Mode() != expected {
						t.Errorf(
							"anchor [%d]: expected mode [%s], got [%s]",
							anchor,
							expected,
							permit.Mode(),
						)
					}
					held = append(held, permit)
				}

				// Fence every held permit and assert every outcome; permits
				// held across the crossing, the quiescence, and the close are
				// exactly the ones the fences must keep classifying.
				for _, p := range held {
					if err := p.CheckCommit(
						"race_completion", CompletionCommit,
					); !completionAllowed(err) {
						t.Errorf(
							"unexpected completion fence outcome for "+
								"mode [%s]: [%v]",
							p.Mode(),
							err,
						)
					}
					if err := p.CheckCommit(
						"race_penalty", PenaltyCommit,
					); !penaltyAllowed(err) {
						t.Errorf(
							"unexpected penalty fence outcome for "+
								"mode [%s]: [%v]",
							p.Mode(),
							err,
						)
					}
				}
				_ = gate.State()

				// Close the oldest permit so ownership churns while newer
				// permits keep spanning the lifecycle transitions.
				if len(held) > 3 {
					held[0].Close()
					held = held[1:]
				}
			}
		}()
	}

	wg.Wait()

	if quiesceDone == nil {
		t.Fatal("the lifecycle goroutine did not quiesce the gate")
	}
	select {
	case <-quiesceDone:
	default:
		t.Error("expected the quiesce channel to be closed after gate close")
	}

	// Every worker closed all its permits, including force-canceled ones, so
	// the accounting must balance exactly.
	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Errorf("expected zero active ceremonies, got [%d]", active)
	}
	if _, err := gate.Begin(
		TBTCSigning, cutover,
	); !errors.Is(err, ErrQuiescing) {
		t.Errorf("expected a quiescing refusal after close, got: [%v]", err)
	}
}

// TestGate_TerminalOutcomeRetryComparesSettlementByValue pins the retry path
// for an outcome carrying a chain settlement. The retry is expected to be an
// identical call, but a ceremony owner rebuilds its evidence each time, so the
// two settlements are equal values at different addresses. Comparing them by
// address would reject the retry as a contradictory second outcome and lose the
// disposition the ceremony actually reached.
func TestGate_TerminalOutcomeRetryComparesSettlementByValue(t *testing.T) {
	const cutover = uint64(1_000)
	capturedAt := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	recorder := &recordingQuiescenceSnapshotRecorder{
		terminalFailures: 1,
		terminalErr:      errors.New("transient journal failure"),
	}
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
		WithArtifactIdentity("v2.1.0", "revision-test"),
		WithQuiescenceSnapshotRecorder(recorder),
		withGateTimeSource(func() time.Time { return capturedAt }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	permit, err := gate.Begin(
		TBTCHeartbeat,
		cutover,
		PermitIdentity{
			WorkID:          "heartbeat-retry",
			PermitID:        "heartbeat-retry",
			OperatedMembers: MemberIndexes{1},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	gate.Quiesce(fmt.Errorf("rollback drill"))

	walletID := make([]byte, inactivityClaimWalletIDLength)
	walletID[0] = 0x5c
	reference, err := InactivityClaimSettlementReference(
		walletID,
		big.NewInt(4),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Each attempt builds its own settlement record, exactly as the ceremony
	// owner does.
	newEvidence := func() TerminalEvidence {
		return TerminalEvidence{
			Kind:      TerminalEvidenceProtocolResult,
			Reference: "heartbeat-result-identity",
			ChainSettlement: &ChainSettlementRecord{
				Kind:      ChainSettlementInactivityClaim,
				Reference: reference,
			},
			Contribution: testTranscriptContribution(TBTCHeartbeat, 1),
		}
	}

	if err := permit.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		newEvidence(),
	); !errors.Is(err, ErrTerminalOutcomePersistence) {
		t.Fatalf("expected first persistence attempt to fail, got [%v]", err)
	}
	if err := permit.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		newEvidence(),
	); err != nil {
		t.Fatalf("expected identical outcome retry to succeed, got [%v]", err)
	}
	permit.Close()

	outcomes := recorder.recordedOutcomes()
	if len(outcomes) != 1 {
		t.Fatalf("expected one terminal outcome, got [%d]", len(outcomes))
	}
	if !outcomes[0].Evidence.Equal(newEvidence()) {
		t.Errorf(
			"unexpected terminal outcome after retry: %+v",
			outcomes[0].Evidence,
		)
	}

	// A retry that names a different settlement is a contradiction, not a
	// retry, and must still be refused.
	contradicting := newEvidence()
	contradicting.ChainSettlement = &ChainSettlementRecord{
		Kind: ChainSettlementInactivityClaim,
	}
	if !TerminalEvidence.Equal(newEvidence(), newEvidence()) {
		t.Error("two equal evidence values compared unequal")
	}
	if newEvidence().Equal(contradicting) {
		t.Error("an unobserved settlement compared equal to an observed one")
	}
}
