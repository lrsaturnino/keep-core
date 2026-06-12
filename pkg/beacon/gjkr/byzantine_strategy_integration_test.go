package gjkr_test

import (
	"testing"

	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
	"github.com/keep-network/keep-core/pkg/internal/byzantine"
	"github.com/keep-network/keep-core/pkg/internal/dkgtest"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// These tests exercise the Tier-2 Byzantine strategy library
// (pkg/internal/byzantine) end to end through a full DKG roundtrip, via
// dkgtest.RunTestWithStrategy. They are the first scenarios built on the
// upgraded interceptor action API.

// isEphemeralPublicKey matches the GJKR phase-1 message. Withholding it from a
// member models that member being inactive from phase 1 onward.
func isEphemeralPublicKey(m net.TaggedMarshaler) bool {
	_, ok := m.(*gjkr.EphemeralPublicKeyMessage)
	return ok
}

// isPeerShares matches the GJKR phase-3 peer-shares message.
func isPeerShares(m net.TaggedMarshaler) bool {
	_, ok := m.(*gjkr.PeerSharesMessage)
	return ok
}

// TestByzantine_Withhold_member1_phase1 reproduces the hand-written
// TestExecute_IA_member1_phase1 scenario using byzantine.Withhold, proving the
// typed strategy library yields the same protocol outcome as the bespoke
// interceptor it replaces: member 1 is marked inactive, the remaining four
// members complete DKG and agree on the group key.
func TestByzantine_Withhold_member1_phase1(t *testing.T) {
	t.Parallel()

	groupSize := 5
	honestThreshold := 3
	seed := dkgtest.RandomSeed(t)

	strategy := byzantine.Withhold(group.MemberIndex(1), isEphemeralPublicKey)

	result, err := dkgtest.RunTestWithStrategy(groupSize, honestThreshold, seed, strategy)
	if err != nil {
		t.Fatal(err)
	}

	dkgtest.AssertDkgResultPublished(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, groupSize-1)
	dkgtest.AssertSuccessfulSigners(t, result, []group.MemberIndex{2, 3, 4, 5}...)
	dkgtest.AssertMemberFailuresCount(t, result, 1)
	dkgtest.AssertSamePublicKey(t, result)
	dkgtest.AssertMisbehavingMembers(t, result, group.MemberIndex(1))
	dkgtest.AssertValidGroupPublicKey(t, result)
	dkgtest.AssertResultSupportingMembers(t, result, []group.MemberIndex{2, 3, 4, 5}...)
}

// TestByzantine_Flood_member1 exercises a capability the legacy modify-or-drop
// interceptor could not express: a member duplicating every message it sends.
// The safety/liveness invariant under test is that the protocol's own
// per-sender deduplication absorbs the flood - with a single over-active member
// and groupSize-1 >= honestThreshold, DKG must still publish a valid,
// agreed-upon group key. The resulting misbehavior classification is observed
// (logged), not asserted, since it is the behavior this scenario is here to
// characterize.
// NOTE: deliberately NOT t.Parallel(). This scenario multiplies one member's
// message volume 5x; running it concurrently with the parallel DKG suite raises
// contention and risks the async result handler missing its 5s window - a
// timeout-miss that would surface as a spurious AssertDkgResultPublished
// failure. Per the Tier-2 work-package-0 determinism finding, high-volume
// scenarios run serially.
func TestByzantine_Flood_member1(t *testing.T) {
	groupSize := 5
	honestThreshold := 3
	seed := dkgtest.RandomSeed(t)

	strategy := byzantine.Flood(group.MemberIndex(1), 5, byzantine.MatchAll)

	result, err := dkgtest.RunTestWithStrategy(groupSize, honestThreshold, seed, strategy)
	if err != nil {
		t.Fatal(err)
	}

	// What this pins: a member duplicating all of its traffic neither breaks
	// the protocol nor gets itself disqualified - every member (the flooder
	// included) completes and agrees on the group key. It does not, by itself,
	// isolate the absorbing mechanism (per-sender dedup); it shows the protocol
	// shrugs the flood off.
	dkgtest.AssertDkgResultPublished(t, result)
	dkgtest.AssertValidGroupPublicKey(t, result)
	dkgtest.AssertSamePublicKey(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, groupSize)
	dkgtest.AssertNoMisbehavingMembers(t, result)
}

// TestByzantine_Corrupt_member4_invalidShares reproduces the hand-written
// TestExecute_DQ_member4_invalidSharesMessage_phase4 scenario using
// byzantine.Corrupt: member 4 broadcasts a peer-shares message missing the
// share for member 1. Receivers detect the malformed message and disqualify
// the sender. This exercises the accusation/disqualification path - the
// stateful-protocol logic Tier 2 exists to reach, and where the contested
// F-008 reconstructed-share finding lives.
func TestByzantine_Corrupt_member4_invalidShares(t *testing.T) {
	t.Parallel()

	groupSize := 5
	honestThreshold := 3
	seed := dkgtest.RandomSeed(t)

	strategy := byzantine.Corrupt(
		group.MemberIndex(4),
		isPeerShares,
		func(m net.TaggedMarshaler) net.TaggedMarshaler {
			m.(*gjkr.PeerSharesMessage).RemoveShares(group.MemberIndex(1))
			return m
		},
	)

	result, err := dkgtest.RunTestWithStrategy(groupSize, honestThreshold, seed, strategy)
	if err != nil {
		t.Fatal(err)
	}

	dkgtest.AssertDkgResultPublished(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, groupSize-1)
	dkgtest.AssertSuccessfulSigners(t, result, []group.MemberIndex{1, 2, 3, 5}...)
	dkgtest.AssertMemberFailuresCount(t, result, 1)
	dkgtest.AssertSamePublicKey(t, result)
	dkgtest.AssertMisbehavingMembers(t, result, group.MemberIndex(4))
	dkgtest.AssertValidGroupPublicKey(t, result)
	dkgtest.AssertResultSupportingMembers(t, result, []group.MemberIndex{1, 2, 3, 5}...)
}
