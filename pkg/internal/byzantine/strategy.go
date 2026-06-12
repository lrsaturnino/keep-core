// Package byzantine provides a small library of named, composable
// interception.Strategy constructors for simulating malicious-operator
// behavior in deterministic protocol tests (Tier-2 Byzantine simulation).
//
// Each constructor targets a single group member by its protocol-level
// MemberIndex and passes every other member's traffic through untouched, so a
// scenario reads as "member N does X". The strategies are protocol-agnostic:
// they act on net.TaggedMarshaler and a caller-supplied match predicate, so the
// same library serves DKG today and threshold signing once those harnesses
// exist.
//
// Scope and boundary are inherited from interception.Strategy: these act on the
// wire, after a sender serialized and encrypted its message. They can withhold,
// duplicate, and corrupt/replace a message, but cannot forge a chosen
// inconsistent-but-individually-valid share (that needs a malicious member, not
// channel interception). See docs tier2-interceptor-action-api.md.
package byzantine

import (
	"github.com/keep-network/keep-core/pkg/internal/interception"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// MatchAll is the nil predicate: it matches every message. Pass it (or nil)
// where a constructor accepts a match predicate to act on all of a member's
// messages regardless of type.
var MatchAll func(net.TaggedMarshaler) bool = nil

// matches reports whether the predicate selects the message. A nil predicate
// matches everything.
func matches(match func(net.TaggedMarshaler) bool, m net.TaggedMarshaler) bool {
	return match == nil || match(m)
}

// targeted builds a Strategy that applies action to messages from member that
// satisfy match, and passes every other message (other senders, or
// non-matching types from this member) through unchanged. action receives the
// outbound message and returns the set actually delivered.
func targeted(
	member group.MemberIndex,
	match func(net.TaggedMarshaler) bool,
	action func(out interception.Outbound) []net.TaggedMarshaler,
) interception.Strategy {
	return func(out interception.Outbound) []net.TaggedMarshaler {
		if out.Sender == member && matches(match, out.Message) {
			return action(out)
		}
		return interception.PassThrough(out)
	}
}

// Inactive drops every message from member, modelling a member that is silent
// for the whole protocol. Equivalent to Withhold(member, MatchAll).
func Inactive(member group.MemberIndex) interception.Strategy {
	return Withhold(member, MatchAll)
}

// Withhold drops messages from member that satisfy match (e.g. a single phase's
// message type), passing all others through. Models selective withholding at a
// specific protocol step. A nil match withholds every message from the member.
func Withhold(
	member group.MemberIndex,
	match func(net.TaggedMarshaler) bool,
) interception.Strategy {
	return targeted(member, match, func(interception.Outbound) []net.TaggedMarshaler {
		return nil // empty set -> dropped
	})
}

// Flood delivers `copies` instances of every message from member that satisfies
// match. Each copy is sent independently and receives its own transport
// sequence number, so receivers do not treat them as retransmissions: the
// protocol's own per-sender deduplication is what must absorb the flood.
// copies <= 1 is a no-op pass-through (one delivery).
//
// The copies share the same underlying message pointer. That is safe for
// duplication, but do NOT combine Flood with an in-place mutation - mutating
// one copy mutates them all. To duplicate-then-corrupt, return distinct cloned
// messages from a custom Strategy instead.
func Flood(
	member group.MemberIndex,
	copies int,
	match func(net.TaggedMarshaler) bool,
) interception.Strategy {
	return targeted(member, match, func(out interception.Outbound) []net.TaggedMarshaler {
		if copies < 1 {
			return []net.TaggedMarshaler{out.Message}
		}
		flooded := make([]net.TaggedMarshaler, copies)
		for i := range flooded {
			flooded[i] = out.Message
		}
		return flooded
	})
}

// Corrupt replaces messages from member that satisfy match with
// transform(message), modelling a malformed-but-typed message. If transform
// returns nil the message is dropped. transform may mutate and return the
// message in place (e.g. PeerSharesMessage.RemoveShares): the local transport
// marshals each outbound message synchronously at Send, so the mutation is
// captured for this delivery and other members' independently-marshaled sends
// are unaffected. This matches the existing GJKR disqualification tests.
func Corrupt(
	member group.MemberIndex,
	match func(net.TaggedMarshaler) bool,
	transform func(net.TaggedMarshaler) net.TaggedMarshaler,
) interception.Strategy {
	return targeted(member, match, func(out interception.Outbound) []net.TaggedMarshaler {
		replaced := transform(out.Message)
		if replaced == nil {
			return nil
		}
		return []net.TaggedMarshaler{replaced}
	})
}
