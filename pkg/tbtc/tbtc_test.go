package tbtc

import (
	"context"
	"sync"
	"testing"
	"time"
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

// idempotentCountingCloser mirrors the real *participation.CutoverPeerRoster.Close
// contract used on the initialization-error path: Close may be invoked more than
// once (the deferred cleanup in Initialize closes the roster directly while the
// lifecycle goroutine closes it again after observing the stop signal), and the
// underlying stop-and-join effect MUST run exactly once through sync.Once. It
// records both raw invocations and effective (once-guarded) closes so a test can
// prove the double invocation is safe.
type idempotentCountingCloser struct {
	mu        sync.Mutex
	once      sync.Once
	rawCalls  int
	effective int
}

func (c *idempotentCountingCloser) Close() {
	c.mu.Lock()
	c.rawCalls++
	c.mu.Unlock()
	c.once.Do(func() {
		c.mu.Lock()
		c.effective++
		c.mu.Unlock()
	})
}

func (c *idempotentCountingCloser) rawCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rawCalls
}

func (c *idempotentCountingCloser) effectiveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.effective
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
// reproduces the exact initialization-error cleanup in Initialize: the deferred
// cleanup releases the lifecycle goroutine by closing the stop channel and then
// closes the roster directly, while the goroutine independently closes the roster
// after observing stop. Close is therefore invoked twice and races on the same
// roster; because the real roster guards its stop-and-join with sync.Once, that
// underlying effect must run exactly once. The parent context stays alive for the
// whole test, matching a caller that keeps ctx open after Initialize returns an
// error.
func TestCloseRosterOnShutdownOrInitError_ErrorPathDoubleCloseIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	roster := &idempotentCountingCloser{}
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		closeRosterOnShutdownOrInitError(ctx, stop, roster)
		close(done)
	}()

	// The deferred error-path cleanup, in Initialize's order (tbtc.go): release the
	// goroutine through stop, then close the roster directly. This direct close and
	// the goroutine's close race on the same roster.
	close(stop)
	roster.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(
			"lifecycle goroutine did not return on the initialization-error path",
		)
	}

	// Waiting on done guarantees the goroutine's Close has completed, and the
	// direct close above has too, so both counts are settled and race-free.
	if got := roster.rawCount(); got != 2 {
		t.Fatalf(
			"expected the error path to invoke Close twice (deferred cleanup plus "+
				"lifecycle goroutine), got %d",
			got,
		)
	}
	if got := roster.effectiveCount(); got != 1 {
		t.Fatalf(
			"expected the idempotent Close to run its stop-and-join effect exactly "+
				"once despite the double invocation, got %d",
			got,
		)
	}
}
