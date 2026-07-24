package tbtc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// countingCloser is a race-safe rosterLifecycleCloser test double that records
// how many times Close was called.
type countingCloser struct {
	mu     sync.Mutex
	closes int
}

func (c *countingCloser) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
}

func (c *countingCloser) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// TestCloseRosterOnShutdownOrInitError_StopReleasesOnInitError reproduces the
// initialization-error path: Initialize fails after the roster is constructed
// but the caller keeps the parent context alive. The stop channel must release
// the lifecycle goroutine (so it does not leak on ctx.Done() forever) and close
// the roster.
func TestCloseRosterOnShutdownOrInitError_StopReleasesOnInitError(t *testing.T) {
	// The parent context deliberately stays alive for the whole test, mirroring
	// a caller that keeps ctx open after Initialize returns an error.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	roster := &countingCloser{}
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		closeRosterOnShutdownOrInitError(ctx, stop, roster)
		close(done)
	}()

	// The error path releases the goroutine through stop, not ctx.
	close(stop)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(
			"lifecycle goroutine did not return after stop; it would leak on " +
				"the initialization-error path while the parent context stays alive",
		)
	}

	if got := roster.count(); got != 1 {
		t.Fatalf("expected roster closed exactly once, got %d", got)
	}
}

// TestCloseRosterOnShutdownOrInitError_ContextCancelClosesRoster covers the
// success path: the roster is handed off to the process lifecycle and closed
// when the parent context is cancelled at shutdown.
func TestCloseRosterOnShutdownOrInitError_ContextCancelClosesRoster(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	roster := &countingCloser{}
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		closeRosterOnShutdownOrInitError(ctx, stop, roster)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle goroutine did not return after context cancellation")
	}

	if got := roster.count(); got != 1 {
		t.Fatalf("expected roster closed exactly once, got %d", got)
	}
}

// TestCloseRosterOnShutdownOrInitError_StopAndCancelCloseOnce covers the select
// itself: both wake-up signals (stop closed and context cancelled) are delivered
// and the goroutine acts on whichever it observes first, calling Close exactly
// once from its single code path and returning. It does not model the deferred
// cleanup's own direct Close — that double-invocation overlap is covered by
// TestCloseRosterOnShutdownOrInitError_ErrorPathDoubleCloseIsIdempotent.
func TestCloseRosterOnShutdownOrInitError_StopAndCancelCloseOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	roster := &countingCloser{}
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		closeRosterOnShutdownOrInitError(ctx, stop, roster)
		close(done)
	}()

	// Both triggers fire; the goroutine acts on whichever it observes first and
	// must call Close exactly once and return.
	close(stop)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle goroutine did not return")
	}

	if got := roster.count(); got != 1 {
		t.Fatalf("expected roster closed exactly once, got %d", got)
	}
}

// TestCloseRosterOnShutdownOrInitError_ErrorPathDoubleCloseIsIdempotent
// reproduces the exact initialization-error cleanup in Initialize against a REAL
// *participation.CutoverPeerRoster with a live background sweep loop — not a fake
// that supplies its own sync.Once. The deferred cleanup releases the lifecycle
// goroutine by closing the stop channel and then closes the roster directly
// (tbtc.go: close(rosterStop); cutoverRoster.Close()), while the goroutine
// independently closes the same roster after observing stop. Close is therefore
// invoked twice and races on the real roster.
//
// The real roster's Close cancels the loop context and joins the sweep goroutine
// under sync.Once, so both concurrent callers must return without panicking,
// double-closing the join channel, or blocking forever on the join. If the real
// roster lost its Close idempotency (for example by joining or signalling more
// than once), one of the closers would panic or hang and this test — which is
// part of the targeted `-race` subset — would fail. The parent context stays
// alive for the whole test, matching a caller that keeps ctx open after
// Initialize returns an error, so the roster is released only through Close.
func TestCloseRosterOnShutdownOrInitError_ErrorPathDoubleCloseIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A real roster, constructed exactly as Initialize does: same parent context,
	// a live sweep loop, and the no-op recorder used on the port-zero path.
	roster, err := participation.NewCutoverPeerRoster(
		ctx,
		&cutoverFakeBlockCounter{block: 5000},
		1500,
		&clientinfo.NoOpPerformanceMetrics{},
	)
	if err != nil {
		t.Fatalf("cannot build cutover peer roster: %v", err)
	}

	stop := make(chan struct{})

	// The lifecycle goroutine, exactly as started by Initialize.
	goroutineDone := make(chan struct{})
	go func() {
		closeRosterOnShutdownOrInitError(ctx, stop, roster)
		close(goroutineDone)
	}()

	// The deferred error-path cleanup, in Initialize's order: release the goroutine
	// through stop, then close the roster directly. The direct close and the
	// goroutine's close now race on the same real roster and its single sweep loop.
	close(stop)
	directDone := make(chan struct{})
	go func() {
		roster.Close()
		close(directDone)
	}()

	// Both concurrent closers must return. Each real Close waits on the sweep
	// loop's join channel, so if the double invocation were unsafe — a panic on a
	// second join-channel close, or a caller stuck on the join — one of these would
	// never complete and the test would time out.
	for _, w := range []struct {
		name string
		done <-chan struct{}
	}{
		{"lifecycle goroutine close", goroutineDone},
		{"direct error-path close", directDone},
	} {
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
			t.Fatalf(
				"%s did not return; the real roster Close did not safely join the "+
					"sweep loop under the double-close overlap",
				w.name,
			)
		}
	}

	// Both closers returning proves the single sweep loop was joined (each Close
	// blocks until the loop goroutine has exited). A further Close after shutdown
	// must remain a safe no-op, confirming idempotency across repeated signals.
	thirdDone := make(chan struct{})
	go func() {
		roster.Close()
		close(thirdDone)
	}()
	select {
	case <-thirdDone:
	case <-time.After(5 * time.Second):
		t.Fatal("a third Close on the real roster blocked; Close is not idempotent")
	}
}
