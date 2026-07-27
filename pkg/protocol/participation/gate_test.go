package participation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// gateBlockCounter is a controllable chain.BlockCounter with real height
// waiter semantics: a waiter channel emits the reached height and closes, or
// can be force-closed without a value to simulate a waiter failure.
type gateBlockCounter struct {
	mu        sync.Mutex
	block     uint64
	err       error
	waiterErr error
	waiters   map[uint64][]chan uint64
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

func (f *gateBlockCounter) CurrentBlock() (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.block, f.err
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
		context.Background(), Schedule{}, nil, metrics, time.Second,
	); err == nil {
		t.Error("expected a nil block counter rejection")
	}

	if _, err := newGate(
		context.Background(), Schedule{}, blockCounter, nil, time.Second,
	); err == nil {
		t.Error("expected a nil metrics recorder rejection")
	}

	if _, err := newGate(
		context.Background(), Schedule{}, blockCounter, metrics, 0,
	); err == nil {
		t.Error("expected a non-positive poll interval rejection")
	}

	if _, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: maxSafeMetricInteger + 1},
		blockCounter,
		metrics,
		time.Second,
	); err == nil {
		t.Error("expected an unprojectable cutover block rejection")
	}

	failing := newGateBlockCounter(100)
	failing.set(100, fmt.Errorf("clock down"))
	if _, err := newGate(
		context.Background(), Schedule{}, failing, metrics, time.Second,
	); err == nil {
		t.Error("expected a chain-clock error at startup to be rejected")
	}

	noWaiter := newGateBlockCounter(100)
	noWaiter.waiterErr = fmt.Errorf("waiter down")
	if _, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: 1000},
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

// TestGate_ConcurrentBeginAcrossCutover races permit issuance, commit fences,
// state reads, and permit closes against the chain crossing the cutover block.
// The only valid outcomes for any permit are: anchored below C and permanently
// legacy, or anchored at/above C and permanently security-v2.
func TestGate_ConcurrentBeginAcrossCutover(t *testing.T) {
	const cutover = uint64(1000)

	gate, blockCounter, _ := newTestGate(
		t, Schedule{CutoverBlock: cutover}, cutover-10, 3*time.Millisecond,
	)

	var wg sync.WaitGroup

	// Advance the chain across the cutover block while workers race.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for height := cutover - 10; height <= cutover+10; height++ {
			blockCounter.set(height, nil)
			time.Sleep(time.Millisecond)
		}
	}()

	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				anchor, err := blockCounter.CurrentBlock()
				if err != nil || anchor == 0 {
					continue
				}

				permit, err := gate.Begin(TBTCSigning, anchor)
				if err != nil {
					// The chain may have been read one step behind another
					// goroutine's Begin; the only acceptable refusals here
					// are anchor/ordering ones.
					if !errors.Is(err, ErrInvalidAnchor) {
						t.Errorf("unexpected Begin error: [%v]", err)
					}
					continue
				}

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

				_ = permit.CheckCommit("race_commit", CompletionCommit)
				_ = gate.State()
				permit.Close()
			}
		}()
	}

	wg.Wait()

	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Errorf("expected zero active ceremonies, got [%d]", active)
	}

	done := gate.Quiesce(fmt.Errorf("test quiesce"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("quiesce channel did not close")
	}
	gate.Close()
}
