package byzantine_test

import (
	"testing"

	"github.com/keep-network/keep-core/pkg/internal/byzantine"
	"github.com/keep-network/keep-core/pkg/internal/interception"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// msg is a minimal sender-attributed TaggedMarshaler for exercising the
// strategy constructors without running a protocol.
type msg struct {
	kind   string
	sender group.MemberIndex
}

func (m *msg) Type() string                { return m.kind }
func (m *msg) Marshal() ([]byte, error)    { return []byte(m.kind), nil }
func (m *msg) Unmarshal(b []byte) error    { m.kind = string(b); return nil }
func (m *msg) SenderID() group.MemberIndex { return m.sender }

// apply runs a strategy against a message attributed to sender and returns the
// delivered set, mirroring what interception's channel extracts.
func apply(s interception.Strategy, sender group.MemberIndex, m net.TaggedMarshaler) []net.TaggedMarshaler {
	return s(interception.Outbound{Sender: sender, Message: m})
}

func TestInactiveDropsOnlyTargetMember(t *testing.T) {
	s := byzantine.Inactive(group.MemberIndex(3))

	if got := apply(s, 3, &msg{"any", 3}); len(got) != 0 {
		t.Errorf("member 3 message: delivered %d; want 0 (dropped)", len(got))
	}
	if got := apply(s, 2, &msg{"any", 2}); len(got) != 1 {
		t.Errorf("member 2 message: delivered %d; want 1 (passed through)", len(got))
	}
}

func TestWithholdMatchesTypeAndMember(t *testing.T) {
	isPhase1 := func(m net.TaggedMarshaler) bool { return m.Type() == "phase1" }
	s := byzantine.Withhold(group.MemberIndex(3), isPhase1)

	// Targeted member, matching type -> dropped.
	if got := apply(s, 3, &msg{"phase1", 3}); len(got) != 0 {
		t.Errorf("member 3 phase1: delivered %d; want 0", len(got))
	}
	// Targeted member, non-matching type -> passes.
	if got := apply(s, 3, &msg{"phase2", 3}); len(got) != 1 {
		t.Errorf("member 3 phase2: delivered %d; want 1", len(got))
	}
	// Other member, matching type -> passes.
	if got := apply(s, 5, &msg{"phase1", 5}); len(got) != 1 {
		t.Errorf("member 5 phase1: delivered %d; want 1", len(got))
	}
}

func TestFloodDuplicatesTargetMember(t *testing.T) {
	s := byzantine.Flood(group.MemberIndex(3), 4, byzantine.MatchAll)

	if got := apply(s, 3, &msg{"any", 3}); len(got) != 4 {
		t.Errorf("member 3 flood: delivered %d; want 4", len(got))
	}
	if got := apply(s, 2, &msg{"any", 2}); len(got) != 1 {
		t.Errorf("member 2 (untargeted): delivered %d; want 1", len(got))
	}

	// copies < 1 is a single pass-through, never a drop.
	noop := byzantine.Flood(group.MemberIndex(3), 0, byzantine.MatchAll)
	if got := apply(noop, 3, &msg{"any", 3}); len(got) != 1 {
		t.Errorf("flood copies=0: delivered %d; want 1", len(got))
	}
}

func TestCorruptReplacesAndCanDrop(t *testing.T) {
	corrupted := &msg{"corrupted", 3}
	replace := byzantine.Corrupt(
		group.MemberIndex(3),
		byzantine.MatchAll,
		func(net.TaggedMarshaler) net.TaggedMarshaler { return corrupted },
	)
	got := apply(replace, 3, &msg{"original", 3})
	if len(got) != 1 || got[0] != corrupted {
		t.Errorf("corrupt: got %v; want the corrupted replacement", got)
	}
	// Untargeted member is untouched.
	if got := apply(replace, 1, &msg{"original", 1}); len(got) != 1 || got[0].Type() != "original" {
		t.Errorf("corrupt leaked onto member 1: %v", got)
	}

	// transform returning nil drops the message.
	drop := byzantine.Corrupt(
		group.MemberIndex(3),
		byzantine.MatchAll,
		func(net.TaggedMarshaler) net.TaggedMarshaler { return nil },
	)
	if got := apply(drop, 3, &msg{"original", 3}); len(got) != 0 {
		t.Errorf("corrupt->nil: delivered %d; want 0 (dropped)", len(got))
	}
}
