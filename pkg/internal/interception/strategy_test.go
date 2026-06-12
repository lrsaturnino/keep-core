package interception

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/net"
	netLocal "github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// senderTestMessage is a TaggedMarshaler that also exposes a protocol-level
// SenderID, mimicking the GJKR message types the interceptor attributes.
type senderTestMessage struct {
	payload string
	sender  group.MemberIndex
}

func (m *senderTestMessage) Type() string             { return "sender_test_message" }
func (m *senderTestMessage) Marshal() ([]byte, error) { return []byte(m.payload), nil }
func (m *senderTestMessage) Unmarshal(b []byte) error { m.payload = string(b); return nil }
func (m *senderTestMessage) SenderID() group.MemberIndex {
	return m.sender
}

// TestStrategyInvokedExactlyOncePerSend is the regression guard for the
// double-invocation bug in the previous wrapper (it called rules(m) twice per
// Send). A stateful Byzantine strategy must see each Send exactly once.
func TestStrategyInvokedExactlyOncePerSend(t *testing.T) {
	var calls int32
	strategy := func(out Outbound) []net.TaggedMarshaler {
		atomic.AddInt32(&calls, 1)
		return []net.TaggedMarshaler{out.Message}
	}

	channel := newStrategyTestChannel(t, strategy)
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler { return &testMessage{} })
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := channel.Send(ctx, &testMessage{"hello"}); err != nil {
		t.Fatal(err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("strategy invoked %d times per Send; want exactly 1", got)
	}
}

// TestStrategyExtractsSender confirms the interceptor attributes an outbound
// message to its protocol-level sender, and reports 0 for non-attributable
// messages.
func TestStrategyExtractsSender(t *testing.T) {
	var seen group.MemberIndex
	strategy := func(out Outbound) []net.TaggedMarshaler {
		seen = out.Sender
		return []net.TaggedMarshaler{out.Message}
	}

	channel := newStrategyTestChannel(t, strategy)
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler { return &senderTestMessage{} })
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler { return &testMessage{} })
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := channel.Send(ctx, &senderTestMessage{"from-7", group.MemberIndex(7)}); err != nil {
		t.Fatal(err)
	}
	if seen != group.MemberIndex(7) {
		t.Errorf("extracted sender = %d; want 7", seen)
	}

	if err := channel.Send(ctx, &testMessage{"no-sender"}); err != nil {
		t.Fatal(err)
	}
	if seen != group.MemberIndex(0) {
		t.Errorf("sender for a non-attributable message = %d; want 0", seen)
	}
}

// TestStrategyDuplicateDelivers confirms a strategy returning N copies results
// in N distinct messages at the receiver (distinct seqnos, not deduped away),
// and that an empty result drops the message entirely.
func TestStrategyDuplicateDelivers(t *testing.T) {
	tests := map[string]struct {
		strategy  Strategy
		wantCount int
	}{
		"pass-through": {
			strategy:  PassThrough,
			wantCount: 1,
		},
		"drop": {
			strategy:  func(Outbound) []net.TaggedMarshaler { return nil },
			wantCount: 0,
		},
		"triplicate (flood)": {
			strategy: func(out Outbound) []net.TaggedMarshaler {
				return []net.TaggedMarshaler{out.Message, out.Message, out.Message}
			},
			wantCount: 3,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			channel := newStrategyTestChannel(t, test.strategy)

			ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
			defer cancel()

			channel.SetUnmarshaler(func() net.TaggedUnmarshaler { return &testMessage{} })

			var received int32
			channel.Recv(ctx, func(net.Message) { atomic.AddInt32(&received, 1) })

			if err := channel.Send(ctx, &testMessage{"flood-me"}); err != nil {
				t.Fatal(err)
			}

			<-ctx.Done() // let retransmissions settle; dedup keeps the count stable
			if got := int(atomic.LoadInt32(&received)); got != test.wantCount {
				t.Errorf("received %d distinct messages; want %d", got, test.wantCount)
			}
		})
	}
}

// TestStrategyConcurrentStatefulNoRace drives many concurrent Sends through a
// stateful strategy (as the shared-channel group does) to confirm the
// interceptor's lock lets a Strategy carry state without a data race. Run with
// -race for the assertion to have teeth.
func TestStrategyConcurrentStatefulNoRace(t *testing.T) {
	const sends = 100

	// A deliberately non-atomic counter: correctness here depends entirely on
	// the interceptor serializing strategy invocations.
	count := 0
	strategy := func(out Outbound) []net.TaggedMarshaler {
		count++
		return []net.TaggedMarshaler{out.Message}
	}

	channel := newStrategyTestChannel(t, strategy)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(sends)
	for i := 0; i < sends; i++ {
		go func() {
			defer wg.Done()
			_ = channel.Send(ctx, &testMessage{"concurrent"})
		}()
	}
	wg.Wait()

	if count != sends {
		t.Errorf("stateful strategy counted %d invocations; want %d", count, sends)
	}
}

func newStrategyTestChannel(t *testing.T, strategy Strategy) net.BroadcastChannel {
	t.Helper()
	// t.Name() is unique per (sub)test, isolating this channel from others in
	// the process-global local broadcast registry (keyed by name).
	channel, err := NewNetworkWithStrategy(netLocal.Connect(), strategy).
		BroadcastChannelFor(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	return channel
}
