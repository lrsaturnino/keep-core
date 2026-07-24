package spv

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunMaintainSpvRecoversPanic asserts that a panic inside a maintainer
// iteration is recovered and surfaced as an error instead of escaping the
// goroutine.
func TestRunMaintainSpvRecoversPanic(t *testing.T) {
	sm := &spvMaintainer{}

	err := sm.runMaintainSpv(
		context.Background(),
		func(context.Context) error {
			panic("sentinel panic")
		},
	)

	if err == nil {
		t.Fatal("expected a non-nil error from a recovered panic")
	}
	if !strings.Contains(err.Error(), "sentinel panic") {
		t.Fatalf("expected the error to mention the panic value, got [%v]", err)
	}
}

// TestRunMaintainSpvPassesThroughError asserts that an ordinary error returned
// by the iteration is preserved unchanged by the recovery wrapper.
func TestRunMaintainSpvPassesThroughError(t *testing.T) {
	sentinel := errors.New("ordinary maintainer error")

	sm := &spvMaintainer{}

	err := sm.runMaintainSpv(
		context.Background(),
		func(context.Context) error {
			return sentinel
		},
	)

	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the sentinel error to pass through, got [%v]", err)
	}
}

// TestRunControlLoopRestartsAfterRecoveredPanic asserts that the control loop
// recovers a panicking iteration, waits the restart backoff, and invokes the
// iteration again, then exits promptly on context cancellation. Synchronization
// uses channels rather than sleeps to stay deterministic.
func TestRunControlLoopRestartsAfterRecoveredPanic(t *testing.T) {
	sm := &spvMaintainer{
		config: Config{RestartBackoffTime: time.Millisecond},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Buffered generously so a late iteration after cancellation can never block
	// the loop goroutine on send.
	invocations := make(chan int, 8)
	var count int32

	iteration := func(context.Context) error {
		n := atomic.AddInt32(&count, 1)
		invocations <- int(n)
		if n == 1 {
			panic("first-iteration panic")
		}
		// Later invocations block until the context is cancelled, mimicking the
		// real maintainSpv steady state.
		<-ctx.Done()
		return ctx.Err()
	}

	done := make(chan struct{})
	go func() {
		sm.runControlLoop(ctx, iteration)
		close(done)
	}()

	// First invocation panics and is recovered.
	select {
	case n := <-invocations:
		if n != 1 {
			t.Fatalf("expected first invocation, got [%d]", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first invocation")
	}

	// After the restart backoff, the loop invokes the iteration again.
	select {
	case n := <-invocations:
		if n != 2 {
			t.Fatalf("expected a second invocation after restart, got [%d]", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the restart invocation")
	}

	// Cancellation exits the loop promptly and does not spin into a restart.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the control loop to exit")
	}
}
