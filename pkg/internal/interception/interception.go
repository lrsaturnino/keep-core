package interception

import (
	"context"
	"sync"

	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// Rules defines the legacy modify-or-drop interception contract. A message can
// be returned unmodified, modified on the fly, or dropped by returning nil.
//
// Rules cannot attribute a message to a sender, duplicate it, or inject new
// messages. New Byzantine scenarios should use Strategy; Rules is retained so
// existing callers keep working and is adapted onto Strategy via FromRules.
type Rules = func(msg net.TaggedMarshaler) net.TaggedMarshaler

// Outbound is an intercepted outbound message together with its protocol-level
// sender index, extracted from the message payload. Sender is 0 (an invalid
// group.MemberIndex) when the message does not expose a SenderID - i.e. it is
// not a per-member protocol message and cannot be attributed to a group member
// (e.g. a chain-result submission). Strategies that target a specific sender
// should treat Sender == 0 as "not attributable" and leave such messages alone.
type Outbound struct {
	Sender  group.MemberIndex
	Message net.TaggedMarshaler
}

// Strategy is the Byzantine fault model applied to every outbound message of a
// simulated run. It decides what a single Send becomes on the wire, returning
// the set of messages actually delivered:
//
//   - nil / empty slice     -> the message is dropped. Models sender inactivity
//     or selective withholding. The delegate is never called, so no
//     retransmission is scheduled for the dropped message.
//   - exactly one message   -> pass-through (return out.Message unchanged) or a
//     content mutation (return a modified / corrupted message).
//   - more than one message -> duplication or injection. Models flooding and
//     extra-message attacks. Each message is sent independently and receives
//     its own sequence number, so receivers do not deduplicate the copies away.
//
// Invocation contract: Strategy is called EXACTLY ONCE per Send, under a lock
// held by the interceptor. Because all members of a simulated group share a
// single channel and Send concurrently, that lock serializes strategy
// invocations - so a single Strategy value may carry mutable state across calls
// (e.g. "go inactive after phase 2", "flood the next N messages") without
// additional synchronization. The lock does not impose a deterministic message
// ORDER (goroutine scheduling still varies which Send arrives first); it only
// guarantees the strategy never runs concurrently with itself. This matches the
// strategy-level (not byte-level) reproducibility established in Tier-2
// work-package 0.
//
// Boundary - what a Strategy CANNOT do, by construction: it observes a message
// after the sender has serialized and encrypted it. For GJKR peer shares it can
// corrupt or drop the encrypted per-receiver ciphertext (provoking a decryption
// failure -> accusation -> disqualification / recovery, which exercises the
// contested F-008 reconstructed-share path), and it can withhold a message
// entirely. It CANNOT forge a chosen inconsistent-but-individually-valid share,
// because the pairwise i-j symmetric key never appears on the wire. Modeling a
// member that emits internally inconsistent but individually valid values
// requires a malicious gjkr.Member implementation, not channel interception.
type Strategy = func(out Outbound) []net.TaggedMarshaler

// PassThrough is the identity Strategy: every message is delivered unmodified.
// It is the honest baseline a Byzantine sweep perturbs.
func PassThrough(out Outbound) []net.TaggedMarshaler {
	return []net.TaggedMarshaler{out.Message}
}

// FromRules adapts a legacy modify-or-drop Rules function to a Strategy. A nil
// Rules result becomes an empty (drop) action set; any other result becomes a
// single pass-through / mutated message.
func FromRules(rules Rules) Strategy {
	return func(out Outbound) []net.TaggedMarshaler {
		altered := rules(out.Message)
		if altered == nil {
			return nil
		}
		return []net.TaggedMarshaler{altered}
	}
}

// senderAware is implemented by every per-member protocol message (all GJKR
// message types expose SenderID). The interceptor uses it to attribute an
// outbound message to the group member that produced it, without depending on
// the protocol packages.
type senderAware interface {
	SenderID() group.MemberIndex
}

// Network is the local test network implementation capable of intercepting
// network messages and modifying, dropping, duplicating, or injecting them
// based on a Strategy.
type Network interface {
	BroadcastChannelFor(name string) (net.BroadcastChannel, error)
}

// NewNetwork creates a Network applying the legacy modify-or-drop Rules to every
// outbound message. Retained for existing callers; new Byzantine scenarios
// should use NewNetworkWithStrategy.
func NewNetwork(
	provider net.Provider,
	rules Rules,
) Network {
	return NewNetworkWithStrategy(provider, FromRules(rules))
}

// NewNetworkWithStrategy creates a Network applying the given Byzantine Strategy
// to every outbound message.
func NewNetworkWithStrategy(
	provider net.Provider,
	strategy Strategy,
) Network {
	return &network{
		provider: provider,
		strategy: strategy,
	}
}

type network struct {
	provider net.Provider
	strategy Strategy
}

func (n *network) BroadcastChannelFor(name string) (net.BroadcastChannel, error) {
	delegate, err := n.provider.BroadcastChannelFor(name)
	if err != nil {
		return nil, err
	}

	return &channel{
		delegate: delegate,
		strategy: n.strategy,
	}, nil
}

type channel struct {
	delegate net.BroadcastChannel
	strategy Strategy

	// strategyMutex serializes Strategy invocations. All members of a simulated
	// group share one channel and Send concurrently; serializing the strategy
	// decision lets a stateful Strategy run without data races. It is held only
	// across the strategy call, not across delivery.
	strategyMutex sync.Mutex
}

func (c *channel) Name() string {
	return c.delegate.Name()
}

func (c *channel) Send(
	ctx context.Context,
	m net.TaggedMarshaler,
	retransmissionStrategy ...net.RetransmissionStrategy,
) error {
	out := Outbound{Message: m}
	if sa, ok := m.(senderAware); ok {
		out.Sender = sa.SenderID()
	}

	c.strategyMutex.Lock()
	messages := c.strategy(out) // invoked exactly once per Send
	c.strategyMutex.Unlock()

	// An empty result drops the message: the delegate is never called, so no
	// retransmission is scheduled for it.
	for _, message := range messages {
		if message == nil {
			continue
		}
		// Each delegate.Send assigns a fresh sequence number, so duplicated or
		// injected copies are delivered as distinct messages instead of being
		// deduplicated by receivers. The caller's retransmission strategy is
		// forwarded (the previous wrapper silently dropped it).
		if err := c.delegate.Send(ctx, message, retransmissionStrategy...); err != nil {
			return err
		}
	}

	return nil
}

func (c *channel) Recv(ctx context.Context, handler func(m net.Message)) {
	c.delegate.Recv(ctx, handler)
}

func (c *channel) SetUnmarshaler(unmarshaler func() net.TaggedUnmarshaler) {
	c.delegate.SetUnmarshaler(unmarshaler)
}

func (c *channel) SetFilter(filter net.BroadcastChannelFilter) error {
	return nil // no-op
}
