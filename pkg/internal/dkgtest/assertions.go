package dkgtest

import (
	"strings"
	"testing"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// AssertDkgResultPublished checks if DKG result has been published to the
// chain. It does not inspect the result.
func AssertDkgResultPublished(t *testing.T, testResult *Result) {
	if testResult.dkgResult == nil {
		t.Fatal("dkg result is nil")
	}
}

// AssertNoDkgResultPublished checks that no DKG result reached the chain: the
// fail-closed outcome of a ceremony that must not complete.
func AssertNoDkgResultPublished(t *testing.T, testResult *Result) {
	if testResult.dkgResult != nil {
		t.Fatal("expected no dkg result to be published")
	}
}

// reconstructionGuardMarker is a stable substring of the F-008 defensive guard's
// Error message (gjkr/protocol.go ComputeGroupPublicKeyShares). Its appearance
// means the reconstructed-share branch found peerSharesS missing an entry for an
// operating member - i.e. the gap F-008 posits actually occurred at runtime and
// was absorbed by the guard (upstream, without the guard, this is the crash).
const reconstructionGuardMarker = "missing revealed share"

// reconstructionGapErrors returns the captured Errorf messages that match the
// F-008 guard marker. Pure (no *testing.T) so the detection logic is unit
// testable independently of a full DKG run.
func reconstructionGapErrors(testResult *Result) []string {
	var hits []string
	for _, msg := range testResult.loggedErrors {
		if strings.Contains(msg, reconstructionGuardMarker) {
			hits = append(hits, msg)
		}
	}
	return hits
}

// AssertNoReconstructionGap fails if the F-008 reconstruction guard fired during
// the run. A passing assertion is the execution-verified evidence that the
// reconstructed-share branch found peerSharesS fully populated - corroborating
// the reachability analysis that the gap does not occur under real execution.
// This is distinct from the unit-level guard regression
// (gjkr.TestComputeGroupPublicKeyShares_MissingRevealedShare), which forces the
// gap artificially to check the guard; here we check the gap never forms.
func AssertNoReconstructionGap(t *testing.T, testResult *Result) {
	for _, msg := range reconstructionGapErrors(testResult) {
		t.Errorf(
			"F-008 reconstruction guard fired - a peerSharesS gap occurred "+
				"at runtime (would crash upstream): %q",
			msg,
		)
	}
}

// AssertSuccessfulSignersCount checks the number of successful signers. It does
// not check which particular signers were successful.
func AssertSuccessfulSignersCount(
	t *testing.T,
	testResult *Result,
	expectedCount int,
) {
	if len(testResult.signers) != expectedCount {
		t.Errorf(
			"unexpected number of successful signers\nexpected: [%v]\nactual:   [%v]",
			expectedCount,
			len(testResult.signers),
		)
	}
}

// AssertSuccessfulSigners checks which particular signers were successful.
func AssertSuccessfulSigners(
	t *testing.T,
	testResult *Result,
	expectedSuccessfulMembers ...group.MemberIndex,
) {
	actualSuccessfulMembers := make([]group.MemberIndex, len(testResult.signers))
	for _, signer := range testResult.signers {
		memberIndex := signer.MemberID()
		actualSuccessfulMembers = append(actualSuccessfulMembers, memberIndex)

		isSuccessfulExpected := containsMemberIndex(
			memberIndex,
			expectedSuccessfulMembers,
		)

		if !isSuccessfulExpected {
			t.Errorf(
				"member [%v] should not be a successful signer",
				memberIndex,
			)
		}
	}

	for _, memberIndex := range expectedSuccessfulMembers {
		isSuccessful := containsMemberIndex(
			memberIndex,
			actualSuccessfulMembers,
		)

		if !isSuccessful {
			t.Errorf(
				"member [%v] should be a successful signer",
				memberIndex,
			)
		}
	}
}

// AssertMemberFailuresCount checks the number of members who failed the
// protocol execution. It does not check which particular members failed.
func AssertMemberFailuresCount(
	t *testing.T,
	testResult *Result,
	expectedCount int,
) {
	if len(testResult.memberFailures) != expectedCount {
		t.Errorf(
			"unexpected number of member failures\nexpected: [%v]\nactual:   [%v]",
			expectedCount,
			len(testResult.memberFailures),
		)
	}
}

func containsMemberIndex(
	index group.MemberIndex,
	indexes []group.MemberIndex,
) bool {
	for _, i := range indexes {
		if i == index {
			return true
		}
	}

	return false
}

// AssertNoMisbehavingMembers checks there were no misbehaving - inactive or
// disqualified members - during protocol execution.
func AssertNoMisbehavingMembers(t *testing.T, testResult *Result) {
	AssertMisbehavingMembers(t, testResult)
}

// AssertMisbehavingMembers checks which members were misbehaving - either
// inactive or disqualified - during the protocol execution and compares them
// against expected ones.
func AssertMisbehavingMembers(
	t *testing.T,
	testResult *Result,
	expectedMisbehavingMembers ...group.MemberIndex,
) {
	actualMisbehavingMembers := make(
		[]group.MemberIndex,
		len(testResult.dkgResult.Misbehaved),
	)

	for _, misbehaved := range testResult.dkgResult.Misbehaved {
		memberIndex := group.MemberIndex(uint8(misbehaved))
		actualMisbehavingMembers = append(actualMisbehavingMembers, memberIndex)

		misbehaviourExpected := containsMemberIndex(
			memberIndex,
			expectedMisbehavingMembers,
		)

		if !misbehaviourExpected {
			t.Errorf(
				"member [%v] should not be marked as misbehaving",
				memberIndex,
			)
		}
	}

	for _, memberIndex := range expectedMisbehavingMembers {
		isMisbehaving := containsMemberIndex(
			memberIndex,
			actualMisbehavingMembers,
		)

		if !isMisbehaving {
			t.Errorf(
				"member [%v] should be marked as misbehaving",
				memberIndex,
			)
		}
	}
}

// AssertSamePublicKey checks if all members of the group generated the same
// group public key during DKG.
func AssertSamePublicKey(t *testing.T, testResult *Result) {
	for _, signer := range testResult.signers {
		testutils.AssertBytesEqual(
			t,
			testResult.dkgResult.GroupPublicKey,
			signer.GroupPublicKeyBytes(),
		)
	}
}

// AssertValidGroupPublicKey checks if the generated group public key is valid.
func AssertValidGroupPublicKey(t *testing.T, testResult *Result) {
	_, err := altbn128.DecompressToG2(testResult.dkgResult.GroupPublicKey)
	if err != nil {
		t.Errorf("invalid group public key: [%v]", err)
	}
}

// AssertResultSupportingMembers checks which particular members
// actually support the final result with their signature.
func AssertResultSupportingMembers(
	t *testing.T,
	testResult *Result,
	expectedSupportingMembers ...group.MemberIndex,
) {
	actualSupportingMembers := make(
		[]group.MemberIndex,
		len(testResult.dkgResultSignatures),
	)
	for memberIndex := range testResult.dkgResultSignatures {
		actualSupportingMembers = append(actualSupportingMembers, memberIndex)

		isSupportingExpected := containsMemberIndex(
			memberIndex,
			expectedSupportingMembers,
		)

		if !isSupportingExpected {
			t.Errorf(
				"member [%v] should not support the result",
				memberIndex,
			)
		}
	}

	for _, memberIndex := range expectedSupportingMembers {
		isSupporting := containsMemberIndex(
			memberIndex,
			actualSupportingMembers,
		)

		if !isSupporting {
			t.Errorf(
				"member [%v] should support the result",
				memberIndex,
			)
		}
	}
}
