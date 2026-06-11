package retransmission

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnTick(t *testing.T) {
	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tickCount uint64
	ticker.onTick(ctx, func() { atomic.AddUint64(&tickCount, 1) })

	ticks <- 1
	ticks <- 2
	waitForCounter(t, &tickCount, 2)

	if got := atomic.LoadUint64(&tickCount); got != 2 {
		t.Errorf("expected [2] executions of handler, had [%v]", got)
	}
}

func TestOnTickSameContext(t *testing.T) {
	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tickCount1 uint64
	var tickCount2 uint64
	ticker.onTick(ctx, func() { atomic.AddUint64(&tickCount1, 1) })
	ticker.onTick(ctx, func() { atomic.AddUint64(&tickCount2, 1) })

	ticks <- 1
	ticks <- 2
	waitForCounter(t, &tickCount1, 2)
	waitForCounter(t, &tickCount2, 2)

	if got := atomic.LoadUint64(&tickCount1); got != 2 {
		t.Errorf("expected [2] executions of handler, had [%v]", got)
	}
	if got := atomic.LoadUint64(&tickCount2); got != 2 {
		t.Errorf("expected [2] executions of handler, had [%v]", got)
	}
}

func TestOnTickTimeTicker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 105*time.Millisecond)
	defer cancel()

	ticker := NewTimeTicker(ctx, 10*time.Millisecond)

	var tickCount uint64
	ticker.onTick(ctx, func() { atomic.AddUint64(&tickCount, 1) })

	<-ctx.Done()

	waitForCounter(t, &tickCount, 10)

	if got := atomic.LoadUint64(&tickCount); got != 10 {
		t.Errorf("expected [10] executions of handler, had [%v]", got)
	}
}

func TestUnregisterHandler(t *testing.T) {
	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel1()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()

	var tickCount1 uint64
	ticker.onTick(ctx1, func() { atomic.AddUint64(&tickCount1, 1) })

	var tickCount2 uint64
	ticker.onTick(ctx2, func() { atomic.AddUint64(&tickCount2, 1) })

	ticks <- 1
	ticks <- 2
	<-ctx1.Done()
	ticks <- 3
	<-ctx2.Done()
	ticks <- 4
	waitForCounter(t, &tickCount2, 3)

	if got := atomic.LoadUint64(&tickCount1); got != 2 {
		t.Errorf("expected [2] executions of the first handler, had [%v]", got)
	}
	if got := atomic.LoadUint64(&tickCount2); got != 3 {
		t.Errorf("expected [3] executions of the second handler, had [%v]", got)
	}
}

func TestUnregisterHandlerSameContext(t *testing.T) {
	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var tickCount1 uint64
	ticker.onTick(ctx, func() { atomic.AddUint64(&tickCount1, 1) })

	var tickCount2 uint64
	ticker.onTick(ctx, func() { atomic.AddUint64(&tickCount2, 1) })

	ticks <- 1
	ticks <- 2
	waitForCounter(t, &tickCount1, 2)
	waitForCounter(t, &tickCount2, 2)
	<-ctx.Done()

	if got := atomic.LoadUint64(&tickCount1); got != 2 {
		t.Errorf("expected [2] executions of the first handler, had [%v]", got)
	}
	if got := atomic.LoadUint64(&tickCount2); got != 2 {
		t.Errorf("expected [2] executions of the second handler, had [%v]", got)
	}
}

func TestCloseTicker(t *testing.T) {
	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ticker.onTick(ctx, func() {})

	close(ticks)

	waitForHandlersUnregistered(t, ticker)
}

func TestCloseTimeTicker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 105*time.Millisecond)
	defer cancel()

	ticker := NewTimeTicker(ctx, 10*time.Millisecond)

	ticker.onTick(ctx, func() {})

	<-ctx.Done()

	waitForHandlersUnregistered(t, ticker)
}

// waitForCounter blocks until the atomic counter reaches at least the expected
// value, failing the test on timeout. Handlers run in the ticker's goroutine,
// so the test must await the counter rather than sleep and read it without
// synchronization.
func waitForCounter(t *testing.T, counter *uint64, expected uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(counter) >= expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf(
		"timed out waiting for counter to reach [%v], has [%v]",
		expected,
		atomic.LoadUint64(counter),
	)
}

// waitForHandlersUnregistered blocks until the ticker has no onTick handlers
// registered. The shutdown cleanup in the ticker's start goroutine runs
// asynchronously after the ticks channel closes, so the postcondition must be
// awaited rather than asserted after a fixed sleep.
func waitForHandlersUnregistered(t *testing.T, ticker *Ticker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ticker.handlersMutex.Lock()
		remaining := len(ticker.handlers)
		ticker.handlersMutex.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for handlers to be unregistered")
}
