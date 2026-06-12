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

// isPublicKeySharePoints matches the GJKR phase-7 public-key-share-points
// message. Withholding it from a member that already provided valid phase-3
// shares makes that member inactive AFTER it qualified into the QUAL set, which
// is what forces the share-reconstruction path (phases 11-12) to run for it.
func isPublicKeySharePoints(m net.TaggedMarshaler) bool {
	_, ok := m.(*gjkr.MemberPublicKeySharePointsMessage)
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

// TestByzantine_F008_ReconstructionPathExecutes is the execution-verified
// corroboration for the F-008 reachability analysis
// (docs/audits/keep-core/f008-reachability-analysis.md, verdict: false
// positive). It drives a QUAL member into the share-reconstruction path and
// confirms phase 12 completes without the contested nil-deref.
//
// F-008 claims an unguarded ScalarBaseMult(nil) in
// CombiningMember.ComputeGroupPublicKeyShares (gjkr/protocol.go phase 12),
// reachable only via its reconstruction ELSE-branch - which iterates a
// reconstructed member's peerSharesS for every operating member. No existing
// test reaches that branch: the other Byzantine demos disqualify a member in
// phase 4/5 (BEFORE the QUAL set is fixed), so the member is never
// reconstructed and the else-branch never runs.
//
// This scenario withholds member 3's PHASE-7 public-key-share-points message
// AFTER member 3 has already broadcast valid phase-3 shares. Member 3 therefore
// qualifies into QUAL, is then marked inactive in phase 8 for the missing
// points, and so satisfies needsReconstruction (in QUAL, no valid points). The
// honest members reveal their ephemeral keys for it (phase 10-11), reconstruct
// its individual key (phase 11), and at phase 12 take the else-branch for it,
// reading peerSharesS for every operating member - the exact F-008 crash site.
//
// A passing run is the evidence: ComputeGroupPublicKeyShares runs in an
// unrecovered goroutine, so a ScalarBaseMult(nil) panic would crash the test
// binary. Completion with a valid, agreed group key demonstrates that
// peerSharesS was fully populated (no gap) when the else-branch executed -
// exactly what the invariant chain (L1 inactivity gate + L2 completeness check
// + L3 recovery-failure disqualification) guarantees.
func TestByzantine_F008_ReconstructionPathExecutes(t *testing.T) {
	t.Parallel()

	groupSize := 5
	honestThreshold := 3
	seed := dkgtest.RandomSeed(t)

	// Member 3 stays silent in phase 7 only; its phase-3 shares pass, so it
	// enters QUAL and is reconstructed rather than excluded early.
	strategy := byzantine.Withhold(group.MemberIndex(3), isPublicKeySharePoints)

	result, err := dkgtest.RunTestWithStrategy(groupSize, honestThreshold, seed, strategy)
	if err != nil {
		t.Fatal(err)
	}

	// The four honest members complete and agree; member 3 is reconstructed
	// (its key recovered from peers) but does not itself complete.
	dkgtest.AssertDkgResultPublished(t, result)
	dkgtest.AssertValidGroupPublicKey(t, result)
	dkgtest.AssertSamePublicKey(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, groupSize-1)
	dkgtest.AssertSuccessfulSigners(t, result, []group.MemberIndex{1, 2, 4, 5}...)
	dkgtest.AssertMemberFailuresCount(t, result, 1)
	dkgtest.AssertMisbehavingMembers(t, result, group.MemberIndex(3))
	dkgtest.AssertResultSupportingMembers(t, result, []group.MemberIndex{1, 2, 4, 5}...)

	// The teeth of the corroboration: the reconstructed-share branch executed
	// for member 3 (it is in QUAL, lacks valid phase-7 points), and found
	// peerSharesS fully populated - the F-008 guard never fired. Without this
	// the PASS would be ambiguous, since the PR #27 guard prevents a crash even
	// if the gap occurred.
	dkgtest.AssertNoReconstructionGap(t, result)
}
