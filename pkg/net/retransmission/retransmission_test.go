package retransmission

import (
	"context"
	"fmt"
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

	if retransmissionsCount != 10 {
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

func TestHandlerEvictsOldRetransmissions(t *testing.T) {
	var received []net.Message

	handler := withRetransmissionSupport(func(message net.Message) {
		received = append(received, message)
	}, 2)

	firstMessage := &mockNetworkMessage{senderID: "a", seqno: 1}

	handler(firstMessage)
	handler(&mockNetworkMessage{senderID: "a", seqno: 2})
	handler(&mockNetworkMessage{senderID: "a", seqno: 3})
	handler(firstMessage)

	if len(received) != 4 {
		t.Fatalf(
			"unexpected number of accepted messages\nactual:   [%v]\nexpected: [4]",
			len(received),
		)
	}
}

func TestHandlerEvictsAcrossMultipleCycles(t *testing.T) {
	// cacheSize=3. Two full eviction cycles: seqno 1-6 all accepted (6 total).
	// After seqno 6, cache holds [4,5,6] and seqno 1-3 have been evicted.
	// Retransmitting 4, 5, 6 must be filtered (still cached).
	// Re-sending 1, 2, 3 must be accepted (evicted from cache).
	var received []net.Message

	handler := withRetransmissionSupport(func(message net.Message) {
		received = append(received, message)
	}, 3)

	for i := uint64(1); i <= 6; i++ {
		handler(&mockNetworkMessage{senderID: "a", seqno: i})
	}

	// Still in cache -- must be filtered.
	handler(&mockNetworkMessage{senderID: "a", seqno: 4})
	handler(&mockNetworkMessage{senderID: "a", seqno: 5})
	handler(&mockNetworkMessage{senderID: "a", seqno: 6})

	// Evicted -- must be re-accepted.
	handler(&mockNetworkMessage{senderID: "a", seqno: 1})
	handler(&mockNetworkMessage{senderID: "a", seqno: 2})
	handler(&mockNetworkMessage{senderID: "a", seqno: 3})

	if len(received) != 9 {
		t.Fatalf(
			"unexpected number of accepted messages\nactual:   [%v]\nexpected: [9]",
			len(received),
		)
	}
}

func TestHandlerConcurrentAccess(t *testing.T) {
	var mu sync.Mutex
	var received []net.Message

	handler := withRetransmissionSupport(func(message net.Message) {
		mu.Lock()
		received = append(received, message)
		mu.Unlock()
	}, 10)

	const goroutines = 20
	const msgsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < msgsPerGoroutine; i++ {
				handler(&mockNetworkMessage{
					senderID: fmt.Sprintf("peer-%d", g),
					seqno:    uint64(i),
				})
			}
		}(g)
	}
	wg.Wait()

	if len(received) == 0 {
		t.Fatal("expected at least one message to be received")
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

type mockTransportIdentifier struct {
	senderID string
}

func (mti *mockTransportIdentifier) String() string {
	return mti.senderID
}
