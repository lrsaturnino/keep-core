package generator

import (
	"context"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
)

var one = big.NewInt(1)

// safeCounter is a goroutine-safe counter used by the scheduler tests. The
// scheduler runs worker functions in their own goroutines while the test's main
// goroutine reads the accumulated results, so both the increment and the
// snapshot read must be synchronized to avoid a data race.
type safeCounter struct {
	mu    sync.Mutex
	value *big.Int
}

func newSafeCounter() *safeCounter {
	return &safeCounter{value: big.NewInt(0)}
}

func (c *safeCounter) increment() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value.Add(c.value, one)
}

// snapshot returns an independent copy of the current value that the caller can
// compare without holding the lock.
func (c *safeCounter) snapshot() *big.Int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return new(big.Int).Set(c.value)
}

// TestComputeStop tests the situation when two new worker functions are added
// to a scheduler in a working state. The test ensures the worker functions
// starts doing their work. Then, the scheduler is stopped and the test ensures
// the worker functions are stopped.
func TestComputeStop(t *testing.T) {
	scheduler := new(Scheduler)

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	// give some time to perform computations
	time.Sleep(10 * time.Millisecond)

	// ensure computations started
	testutils.AssertBigIntNonZero(t, "computation result", number1.snapshot())
	testutils.AssertBigIntNonZero(t, "computation result", number2.snapshot())

	// send the stop signal and give some time to stop computations
	scheduler.stop()
	time.Sleep(100 * time.Millisecond)

	// at this point, all computations should be stopped, capture the current
	// result
	result1 := number1.snapshot()
	result2 := number2.snapshot()

	// wait some time and ensure computations stopped
	time.Sleep(20 * time.Millisecond)
	testutils.AssertBigIntsEqual(
		t,
		"computation result after stop signal",
		result1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsEqual(
		t,
		"computation result after stop signal",
		result2,
		number2.snapshot(),
	)
}

// TestComputeStopContext covers the same situation as TestComputeStop except
// that it ensures if the context passed to the function is cancelled when the
// work is stopped.
func TestComputeStopContext(t *testing.T) {
	scheduler := new(Scheduler)

	// cancelled1/cancelled2 are written by the worker goroutines and read by the
	// main goroutine, so they are accessed atomically.
	var cancelled1 atomic.Bool
	var cancelled2 atomic.Bool

	scheduler.compute(func(ctx context.Context) {
		// this simulates a long-running task
		<-ctx.Done()
		cancelled1.Store(true)
	})
	scheduler.compute(func(ctx context.Context) {
		// this simulates a long-running task
		<-ctx.Done()
		cancelled2.Store(true)
	})

	// give some time to perform computations
	time.Sleep(10 * time.Millisecond)

	// send the stop signal and give some time to stop computations
	scheduler.stop()
	time.Sleep(100 * time.Millisecond)

	// ensure context got cancelled
	if !cancelled1.Load() {
		t.Errorf("expected context to be cancelled")
	}
	if !cancelled2.Load() {
		t.Errorf("expected context to be cancelled")
	}
}

// TestComputeStopResume tests the situation when two new worker functions are
// added to a scheduler in a working state. Then, the scheduler is stopped and
// after some time its work is resumed. The test ensures the worker functions
// resume their work.
func TestComputeStopResume(t *testing.T) {
	scheduler := new(Scheduler)
	defer scheduler.stop()

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	// send the stop signal and give some time to stop computations
	scheduler.stop()
	time.Sleep(100 * time.Millisecond)

	// at this point, all computations should be stopped, capture the current
	// result
	intermediateResult1 := number1.snapshot()
	intermediateResult2 := number2.snapshot()

	// send the resume signal and give some time to resume computations
	scheduler.resume()
	time.Sleep(100 * time.Millisecond)

	// ensure computations have been resumed
	testutils.AssertBigIntsNotEqual(
		t,
		"computation results after resume signal",
		intermediateResult1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation results after resume signal",
		intermediateResult2,
		number2.snapshot(),
	)
}

// TestComputeStopResumeStop tests the situation when two new worker functions
// are added to a scheduler in a working state. Then, the scheduler is stopped,
// resumed, and stopped again. The test ensures the worker functions are stopped
// at the end of the cycle.
func TestComputeStopResumeStop(t *testing.T) {
	scheduler := new(Scheduler)

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	scheduler.stop()
	scheduler.resume()
	scheduler.stop()

	// at this point, all computations should be stopped, capture the current
	// result
	result1 := number1.snapshot()
	result2 := number2.snapshot()

	// wait some time and ensure computations stopped
	time.Sleep(20 * time.Millisecond)
	testutils.AssertBigIntsEqual(
		t,
		"computation result after stop signal",
		result1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsEqual(
		t,
		"computation result after stop signal",
		result2,
		number2.snapshot(),
	)
}

// TestStopComputeResume tests the situation when two new worker functions are
// added to a stopped scheduler. Then, the scheduler work is resumed. The test
// ensures the worker functions are not working before the resume and that they
// are working after the resume.
func TestStopComputeResume(t *testing.T) {
	scheduler := new(Scheduler)
	defer scheduler.stop()

	scheduler.stop()

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	// assert computations have not started - the scheduler is stopped
	testutils.AssertBigIntsEqual(t, "computation result", big.NewInt(0), number1.snapshot())
	testutils.AssertBigIntsEqual(t, "computation result", big.NewInt(0), number2.snapshot())

	scheduler.resume()
	// give some time to perform computations;
	// given the goroutines are started after Resume call, we are giving this
	// test a bit more time than others
	time.Sleep(250 * time.Millisecond)

	// ensure computations started
	testutils.AssertBigIntNonZero(t, "computation result", number1.snapshot())
	testutils.AssertBigIntNonZero(t, "computation result", number2.snapshot())
}

// TestCheckProtocols_NoProtocols ensures the execution of checkProtocols
// does not stop the scheduler if there are no protocols registered.
func TestCheckProtocols_NoProtocols(t *testing.T) {
	scheduler := new(Scheduler)
	defer scheduler.stop()

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	// give some time to perform computations
	time.Sleep(10 * time.Millisecond)

	scheduler.checkProtocols()

	// give some time to potentially stop computations (shouldn't happen)
	time.Sleep(100 * time.Millisecond)

	// there are no protocols executed, nothing can stop the scheduler;
	// ensure the computations are performed
	intermediateResult1 := number1.snapshot()
	intermediateResult2 := number2.snapshot()

	time.Sleep(20 * time.Millisecond)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation result after stop signal",
		intermediateResult1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation result after stop signal",
		intermediateResult2,
		number2.snapshot(),
	)
}

// TestCheckProtocols_ProtocolNotExecuting ensures the execution of checkProtocols
// does not stop the scheduler if there are protocols registered but they are
// not executing.
func TestCheckProtocols_ProtocolNotExecuting(t *testing.T) {
	scheduler := new(Scheduler)
	defer scheduler.stop()

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	protocol1 := &mockProtocol{}
	protocol2 := &mockProtocol{}
	scheduler.RegisterProtocol(protocol1)
	scheduler.RegisterProtocol(protocol2)

	// give some time to perform computations
	time.Sleep(10 * time.Millisecond)

	scheduler.checkProtocols()

	// give some time to potentially stop computations (shouldn't happen)
	time.Sleep(100 * time.Millisecond)

	// there are two protocols but they are not executing;
	// ensure the computations are performed
	intermediateResult1 := number1.snapshot()
	intermediateResult2 := number2.snapshot()

	time.Sleep(20 * time.Millisecond)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation result after stop signal",
		intermediateResult1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation result after stop signal",
		intermediateResult2,
		number2.snapshot(),
	)
}

// TestCheckProtocols_ProtocolExecuting ensures the execution of checkProtocols
// does stop the scheduler if at least of the registered protocols is executing.
func TestCheckProtocols_ProtocolExecuting(t *testing.T) {
	scheduler := new(Scheduler)
	defer scheduler.stop()

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	protocol1 := &mockProtocol{}
	protocol2 := &mockProtocol{}
	scheduler.RegisterProtocol(protocol1)
	scheduler.RegisterProtocol(protocol2)

	// give some time to perform computations
	time.Sleep(10 * time.Millisecond)

	protocol2.isExecuting = true
	scheduler.checkProtocols()

	// give some time to stop computations
	time.Sleep(100 * time.Millisecond)

	// there are two protocols and the second one is executing
	// ensure the computations are stopped
	intermediateResult1 := number1.snapshot()
	intermediateResult2 := number2.snapshot()

	time.Sleep(20 * time.Millisecond)
	testutils.AssertBigIntsEqual(
		t,
		"computation result after stop signal",
		intermediateResult1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsEqual(
		t,
		"computation result after stop signal",
		intermediateResult2,
		number2.snapshot(),
	)
}

// TestCheckProtocols_ProtocolFinishedExecution ensures the execution of
// checkProtocols resumes the work of the scheduler if the protocol that was
// previously executing finished the work.
func TestCheckProtocols_ProtocolFinishedExecution(t *testing.T) {
	scheduler := new(Scheduler)
	defer scheduler.stop()

	number1 := newSafeCounter()
	number2 := newSafeCounter()

	scheduler.compute(func(context.Context) {
		number1.increment()
	})
	scheduler.compute(func(context.Context) {
		number2.increment()
	})

	protocol1 := &mockProtocol{}
	protocol2 := &mockProtocol{}
	scheduler.RegisterProtocol(protocol1)
	scheduler.RegisterProtocol(protocol2)

	// give some time to perform computations
	time.Sleep(10 * time.Millisecond)

	protocol2.isExecuting = true
	scheduler.checkProtocols()

	// give some time to stop computations
	time.Sleep(100 * time.Millisecond)

	protocol2.isExecuting = false
	scheduler.checkProtocols()

	// give some time to resume computations
	time.Sleep(100 * time.Millisecond)

	// there are two protocols, the second one was executing, but it has
	// finished; ensure the computations are resumed
	intermediateResult1 := number1.snapshot()
	intermediateResult2 := number2.snapshot()

	time.Sleep(20 * time.Millisecond)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation result after stop signal",
		intermediateResult1,
		number1.snapshot(),
	)
	testutils.AssertBigIntsNotEqual(
		t,
		"computation result after stop signal",
		intermediateResult2,
		number2.snapshot(),
	)
}

type mockProtocol struct {
	isExecuting bool
}

func (mp *mockProtocol) IsExecuting() bool {
	return mp.isExecuting
}
