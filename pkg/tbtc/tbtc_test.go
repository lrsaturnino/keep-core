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

// TestCloseRosterOnShutdownOrInitError_StopAndCancelCloseOnce guards the
// overlap the error path relies on: the deferred close in Initialize closes the
// roster synchronously while also closing stop to release this goroutine, which
// then calls Close again. The roster's Close is idempotent, so exactly one close
// must be observed here per call, and the goroutine must still return.
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
