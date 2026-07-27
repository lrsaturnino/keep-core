package cmd

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

func TestAwaitQuiesce_NaturalCompletion(t *testing.T) {
	quiesceDone := make(chan struct{})
	close(quiesceDone)

	reason := awaitQuiesce(quiesceDone, make(chan os.Signal), time.Hour)
	if reason != "completed" {
		t.Errorf("expected reason [completed], got [%s]", reason)
	}
}

func TestAwaitQuiesce_SecondSignalForces(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM

	reason := awaitQuiesce(make(chan struct{}), signals, time.Hour)
	if reason != "forced_by_signal" {
		t.Errorf("expected reason [forced_by_signal], got [%s]", reason)
	}
}

func TestAwaitQuiesce_BackstopDeadline(t *testing.T) {
	reason := awaitQuiesce(
		make(chan struct{}),
		make(chan os.Signal),
		time.Millisecond,
	)
	if reason != "backstop_deadline" {
		t.Errorf("expected reason [backstop_deadline], got [%s]", reason)
	}
}

// TestSignalLifecycleController_FirstSignalPreventsNewPermits proves the
// controller acts on the first termination signal the moment it arrives —
// the model of a signal received while startup is still initializing
// components: the gate refuses every subsequent Begin, the in-flight permit
// keeps draining, and only after it completes does the controller report
// shutdown and cancel the run context.
func TestSignalLifecycleController_FirstSignalPreventsNewPermits(t *testing.T) {
	localChain := local_v1.Connect(10, 5)
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: 1_000_000},
		blockCounter,
		&clientinfo.NoOpPerformanceMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()

	// The in-flight ceremony that must survive the first signal and keep the
	// drain open until it completes.
	permit, err := gate.Begin(participation.BeaconDKG, 1)
	if err != nil {
		t.Fatalf("cannot begin the in-flight ceremony: [%v]", err)
	}

	runCtx, cancelRunCtx := context.WithCancel(context.Background())
	defer cancelRunCtx()

	signals := make(chan os.Signal, 2)
	shutdownChan := startSignalLifecycleController(
		runCtx,
		cancelRunCtx,
		gate,
		signals,
		time.Hour,
		time.Hour,
	)

	signals <- syscall.SIGTERM

	// The controller quiesces asynchronously; a Begin that still succeeds
	// lost the race with the quiesce transition and its permit is returned
	// before retrying. Once the refusal appears it must be the quiesce
	// sentinel.
	deadline := time.Now().Add(10 * time.Second)
	for {
		extraPermit, err := gate.Begin(participation.BeaconDKG, 1)
		if err != nil {
			if !errors.Is(err, participation.ErrQuiescing) {
				t.Fatalf("expected the quiesce refusal, got [%v]", err)
			}
			break
		}
		extraPermit.Close()

		if time.Now().After(deadline) {
			t.Fatal("the gate never started refusing new permits")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The drain must wait for the in-flight permit: no shutdown report and no
	// run-context cancellation may occur while it is open.
	select {
	case err := <-shutdownChan:
		t.Fatalf("shutdown reported while a permit was active: [%v]", err)
	case <-runCtx.Done():
		t.Fatal("run context canceled while a permit was active")
	default:
	}

	permit.Close()

	select {
	case err := <-shutdownChan:
		if err == nil || !strings.Contains(err.Error(), "signal") {
			t.Errorf("expected a signal shutdown report, got [%v]", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown report after the drain completed")
	}

	select {
	case <-runCtx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the run context was not canceled after the shutdown report")
	}
}

func TestAwaitForcedCancellationCleanup_Drained(t *testing.T) {
	drained := make(chan struct{})
	close(drained)

	reason := awaitForcedCancellationCleanup(drained, time.Hour)
	if reason != cleanupReasonDrained {
		t.Errorf(
			"expected reason [%s], got [%s]",
			cleanupReasonDrained,
			reason,
		)
	}
}

func TestAwaitForcedCancellationCleanup_AllowanceExceeded(t *testing.T) {
	reason := awaitForcedCancellationCleanup(
		make(chan struct{}),
		time.Millisecond,
	)
	if reason != cleanupReasonAllowanceExceeded {
		t.Errorf(
			"expected reason [%s], got [%s]",
			cleanupReasonAllowanceExceeded,
			reason,
		)
	}
}

// TestForcedCancellationAllowance_BoundToManifestAllowance pins the runtime
// phase-two wait to the reviewed allowance the release manifest adds on top
// of the in-process backstop: the wall-clock room the controller actually
// grants the cancellation cleanup must be exactly the room the service
// manager's termination grace reserves for it before SIGKILL.
func TestForcedCancellationAllowance_BoundToManifestAllowance(t *testing.T) {
	grace, err := deriveTerminationGrace(
		defaultForcedCancellationAllowanceSeconds,
	)
	if err != nil {
		t.Fatalf("unexpected derivation error: [%v]", err)
	}

	expected := time.Duration(grace.ForcedCancellationAllowanceSeconds) *
		time.Second
	if got := forcedCancellationAllowance(); got != expected {
		t.Errorf(
			"expected the runtime allowance [%s] to match the manifest "+
				"allowance, got [%s]",
			expected,
			got,
		)
	}

	graceHeadroom := grace.TerminationGracePeriodSeconds -
		grace.InProcessBackstopSeconds
	if graceHeadroom != uint64(forcedCancellationAllowance()/time.Second) {
		t.Errorf(
			"the termination grace reserves [%d]s after the backstop, but "+
				"the runtime waits [%s]",
			graceHeadroom,
			forcedCancellationAllowance(),
		)
	}
}

// TestSignalLifecycleController_JoinsForcedCancellationCleanup proves the
// forced path is two-phase: after the second signal ends the drain, the
// controller must not report shutdown or cancel the run context until the
// owner of the force-canceled permit has finished its delayed cleanup — the
// model of a quarantine persistence write racing process exit — and released
// the permit.
func TestSignalLifecycleController_JoinsForcedCancellationCleanup(t *testing.T) {
	localChain := local_v1.Connect(10, 5)
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: 1_000_000},
		blockCounter,
		&clientinfo.NoOpPerformanceMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()

	permit, err := gate.Begin(participation.BeaconDKG, 1)
	if err != nil {
		t.Fatalf("cannot begin the in-flight ceremony: [%v]", err)
	}

	runCtx, cancelRunCtx := context.WithCancel(context.Background())
	defer cancelRunCtx()

	signals := make(chan os.Signal, 2)
	shutdownChan := startSignalLifecycleController(
		runCtx,
		cancelRunCtx,
		gate,
		signals,
		time.Hour,
		time.Hour,
	)

	// The permit owner: it starts its cleanup only when the gate cancels the
	// permit, holds the permit across a deliberately slow persistence write,
	// and releases it only afterwards — exactly the shape of the quarantine
	// paths in the beacon and tBTC nodes.
	quarantineFinished := make(chan struct{})
	var runCtxEndedDuringCleanup atomic.Bool
	go func() {
		<-permit.Context().Done()
		time.Sleep(200 * time.Millisecond)
		if runCtx.Err() != nil {
			runCtxEndedDuringCleanup.Store(true)
		}
		close(quarantineFinished)
		permit.Close()
	}()

	// The first signal quiesces; the second forces the drain to end while the
	// permit is still held.
	signals <- syscall.SIGTERM
	signals <- syscall.SIGTERM

	select {
	case err := <-shutdownChan:
		select {
		case <-quarantineFinished:
		default:
			t.Fatal(
				"shutdown reported before the delayed cleanup finished",
			)
		}
		if err == nil || !strings.Contains(err.Error(), "signal") {
			t.Errorf("expected a signal shutdown report, got [%v]", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown report after the cleanup finished")
	}

	if runCtxEndedDuringCleanup.Load() {
		t.Fatal("run context canceled while the cleanup was still running")
	}

	select {
	case <-runCtx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the run context was not canceled after the shutdown report")
	}
}

// TestSignalLifecycleController_CancellationAllowanceBoundsTheWait proves the
// cleanup join cannot wedge the shutdown: a permit owner that never releases
// its canceled permit delays the shutdown report by exactly the reviewed
// allowance, not forever.
func TestSignalLifecycleController_CancellationAllowanceBoundsTheWait(
	t *testing.T,
) {
	localChain := local_v1.Connect(10, 5)
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: 1_000_000},
		blockCounter,
		&clientinfo.NoOpPerformanceMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()

	// Deliberately never released before the shutdown report: the owner is
	// modeled as wedged.
	permit, err := gate.Begin(participation.BeaconDKG, 1)
	if err != nil {
		t.Fatalf("cannot begin the in-flight ceremony: [%v]", err)
	}
	defer permit.Close()

	runCtx, cancelRunCtx := context.WithCancel(context.Background())
	defer cancelRunCtx()

	allowance := 150 * time.Millisecond
	signals := make(chan os.Signal, 2)
	shutdownChan := startSignalLifecycleController(
		runCtx,
		cancelRunCtx,
		gate,
		signals,
		time.Hour,
		allowance,
	)

	waitStart := time.Now()
	signals <- syscall.SIGTERM
	signals <- syscall.SIGTERM

	select {
	case err := <-shutdownChan:
		if elapsed := time.Since(waitStart); elapsed < allowance {
			t.Errorf(
				"shutdown reported after [%s], before the [%s] allowance "+
					"was consumed",
				elapsed,
				allowance,
			)
		}
		if err == nil || !strings.Contains(err.Error(), "signal") {
			t.Errorf("expected a signal shutdown report, got [%v]", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the allowance did not bound the cleanup wait")
	}
}

// TestQuiesceBackstopDeadline_DominatesCompletionBound pins the wall-clock
// backstop to the block-derived completion bound plus the reviewed block
// margin: the drain must always be given at least the conservative wall-clock
// equivalent of the longest legitimately in-flight work, plus the margins.
func TestQuiesceBackstopDeadline_DominatesCompletionBound(t *testing.T) {
	bound := uint64(1200)
	expected := time.Duration(bound+quiesceReviewedMarginBlocks)*
		quiesceUpperBlockIntervalSeconds*time.Second +
		quiesceBackstopMargin

	got, err := quiesceBackstopDeadline(bound)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if got != expected {
		t.Errorf(
			"expected backstop [%s] for bound [%d], got [%s]",
			expected,
			bound,
			got,
		)
	}
	if got <= quiesceBackstopMargin {
		t.Error("the backstop must exceed the margin for a nonzero bound")
	}
}

// TestQuiesceBackstopDeadline_RejectsOverflow proves every step of the
// deadline calculation is overflow-checked: a bound that cannot be converted
// to a wall-clock deadline is a startup error, never a silently truncated
// grace period.
func TestQuiesceBackstopDeadline_RejectsOverflow(t *testing.T) {
	overflowingBounds := map[string]uint64{
		"block margin addition overflows": math.MaxUint64 - 1,
		"seconds multiplication overflows": math.MaxUint64/
			quiesceUpperBlockIntervalSeconds - 1,
		"duration conversion overflows": math.MaxInt64/
			uint64(time.Second) + 1,
	}

	for name, bound := range overflowingBounds {
		t.Run(name, func(t *testing.T) {
			if _, err := quiesceBackstopDeadline(bound); err == nil {
				t.Errorf(
					"expected an overflow error for bound [%d]",
					bound,
				)
			}
		})
	}
}
