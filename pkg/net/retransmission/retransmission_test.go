package retransmission

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"

	"github.com/keep-network/keep-core/pkg/net"
)

func TestRetransmitExpectedNumberOfTimes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 510*time.Millisecond)
	defer cancel()

	var retransmissionsCount uint64
	ScheduleRetransmissions(
		ctx,
		&testutils.MockLogger{},
		NewTimeTicker(ctx, 50*time.Millisecond),
		func() error {
			atomic.AddUint64(&retransmissionsCount, 1)
			return nil
		},
		WithStandardStrategy(),
	)

	<-ctx.Done()

	if atomic.LoadUint64(&retransmissionsCount) != 10 {
		t.Errorf("expected [10] retransmissions, has [%v]", retransmissionsCount)
	}
}

func TestHandlerReceiveUniqueMessages(t *testing.T) {
	var received []net.Message

	handler := WithRetransmissionSupport(func(message net.Message) {
		received = append(received, message)
	})

	handler(&mockNetworkMessage{senderID: "a", seqno: 1})
	handler(&mockNetworkMessage{senderID: "a", seqno: 2})
	handler(&mockNetworkMessage{senderID: "a", seqno: 4})
	handler(&mockNetworkMessage{senderID: "b", seqno: 1})
	handler(&mockNetworkMessage{senderID: "b", seqno: 2})

	if len(received) != 5 {
		t.Fatalf(
			"unexpected number of accepted messages\nactual:   [%v]\nexpected: [5]",
			len(received),
		)
	}
}

func TestHandlerReceiveRetransmissions(t *testing.T) {
	var received []net.Message

	handler := WithRetransmissionSupport(func(message net.Message) {
		received = append(received, message)
	})

	handler(&mockNetworkMessage{senderID: "a", seqno: 1})
	handler(&mockNetworkMessage{senderID: "a", seqno: 2})
	handler(&mockNetworkMessage{senderID: "a", seqno: 2})
	handler(&mockNetworkMessage{senderID: "a", seqno: 1})
	handler(&mockNetworkMessage{senderID: "b", seqno: 2})
	handler(&mockNetworkMessage{senderID: "b", seqno: 1})
	handler(&mockNetworkMessage{senderID: "b", seqno: 1})

	if len(received) != 4 {
		t.Fatalf(
			"unexpected number of accepted messages\nactual:   [%v]\nexpected: [4]",
			len(received),
		)
	}
}

type mockNetworkMessage struct {
	senderID string
	seqno    uint64
}

func (mnm *mockNetworkMessage) TransportSenderID() net.TransportIdentifier {
	return &mockTransportIdentifier{mnm.senderID}
}

func (mnm *mockNetworkMessage) Payload() interface{} {
	panic("not implemented")
}

func (mnm *mockNetworkMessage) Type() string {
	panic("not implemented")
}

func (mnm *mockNetworkMessage) SenderPublicKey() []byte {
	panic("not implemented")
}

func (mnm *mockNetworkMessage) Seqno() uint64 {
	return mnm.seqno
}

// TestScheduleRetransmissions_WithBackoffStrategy verifies that the integrated
// path of ScheduleRetransmissions + BackoffStrategy fires at the correct
// exponential-backoff ticks (1, 3, 6, 11, 20 out of the first 20 ticks).
func TestScheduleRetransmissions_WithBackoffStrategy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	var retransmissions uint64

	ScheduleRetransmissions(
		ctx,
		&testutils.MockLogger{},
		ticker,
		func() error {
			atomic.AddUint64(&retransmissions, 1)
			return nil
		},
		WithBackoffStrategy(),
	)

	// ScheduleRetransmissions registers its onTick handler in a goroutine;
	// yield briefly so that goroutine runs before we start sending ticks.
	time.Sleep(10 * time.Millisecond)

	// BackoffStrategy fires at ticks 1, 3, 6, 11, 20 -- 5 fires in 20 ticks.
	for i := uint64(1); i <= 20; i++ {
		ticks <- i
	}
	time.Sleep(50 * time.Millisecond)

	got := atomic.LoadUint64(&retransmissions)
	if got != 5 {
		t.Errorf(
			"expected 5 retransmissions with BackoffStrategy in 20 ticks, got %d",
			got,
		)
	}
}

// TestScheduleRetransmissions_LogsRetransmitError verifies that when the
// retransmit function returns an error the error is passed to the logger.
func TestScheduleRetransmissions_LogsRetransmitError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ticks := make(chan uint64)
	ticker := NewTicker(ticks)

	logger := &capturingLogger{}

	ScheduleRetransmissions(
		ctx,
		logger,
		ticker,
		func() error { return fmt.Errorf("network unavailable") },
		WithStandardStrategy(),
	)

	// Allow the registration goroutine inside ScheduleRetransmissions to call
	// onTick before we send the first tick.
	time.Sleep(10 * time.Millisecond)

	ticks <- 1
	time.Sleep(50 * time.Millisecond)

	logger.mu.Lock()
	errs := logger.errors
	logger.mu.Unlock()

	if len(errs) == 0 {
		t.Fatal("expected error to be logged, got none")
	}
	if !strings.Contains(errs[0], "network unavailable") {
		t.Errorf("unexpected logged error: %q", errs[0])
	}
}

// TestWithRetransmissionSupport_ConcurrentCallsAreSafe verifies that when
// many goroutines concurrently deliver the same message only one call reaches
// the delegate -- and there are no data races on the deduplication cache.
func TestWithRetransmissionSupport_ConcurrentCallsAreSafe(t *testing.T) {
	var delegateCount uint64

	handler := WithRetransmissionSupport(func(_ net.Message) {
		atomic.AddUint64(&delegateCount, 1)
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler(&mockNetworkMessage{senderID: "peer-a", seqno: 42})
		}()
	}
	wg.Wait()

	got := atomic.LoadUint64(&delegateCount)
	if got != 1 {
		t.Errorf("expected delegate called exactly once for duplicate messages, got %d", got)
	}
}

type mockTransportIdentifier struct {
	senderID string
}

func (mti *mockTransportIdentifier) String() string {
	return mti.senderID
}

// capturingLogger wraps MockLogger and records Errorf calls for assertions.
type capturingLogger struct {
	testutils.MockLogger
	mu     sync.Mutex
	errors []string
}

func (cl *capturingLogger) Errorf(format string, args ...interface{}) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.errors = append(cl.errors, fmt.Sprintf(format, args...))
}
