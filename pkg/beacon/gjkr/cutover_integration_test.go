package gjkr_test

import (
	"testing"

	"github.com/keep-network/keep-core/pkg/internal/dkgtest"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// TestExecute_HomogeneousLegacy proves the full DKG roundtrip succeeds when
// every member runs the legacy compatibility bundle: the pre-cutover wire
// behavior (legacy ECDH derivation and legacy hash-to-point) is a complete,
// working protocol on the production execution path, not only a set of
// primitive fixtures.
func TestExecute_HomogeneousLegacy(t *testing.T) {
	t.Parallel()

	groupSize := 5
	honestThreshold := 3
	seed := dkgtest.RandomSeed(t)

	interceptor := func(msg net.TaggedMarshaler) net.TaggedMarshaler {
		return msg
	}

	result, err := dkgtest.RunTestWithModes(
		groupSize,
		honestThreshold,
		seed,
		interceptor,
		func(group.MemberIndex) compatibility.Strategies {
			return compatibility.Legacy()
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	dkgtest.AssertDkgResultPublished(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, groupSize)
	dkgtest.AssertMemberFailuresCount(t, result, 0)
	dkgtest.AssertSamePublicKey(t, result)
	dkgtest.AssertNoMisbehavingMembers(t, result)
	dkgtest.AssertValidGroupPublicKey(t, result)
}

// TestExecute_HomogeneousSecurityV2Explicit proves the same roundtrip with an
// explicitly selected security-v2 bundle for every member. The default
// harness already pins security-v2, so this pins that the explicit selector
// path is equivalent to it.
func TestExecute_HomogeneousSecurityV2Explicit(t *testing.T) {
	t.Parallel()

	groupSize := 5
	honestThreshold := 3
	seed := dkgtest.RandomSeed(t)

	interceptor := func(msg net.TaggedMarshaler) net.TaggedMarshaler {
		return msg
	}

	result, err := dkgtest.RunTestWithModes(
		groupSize,
		honestThreshold,
		seed,
		interceptor,
		func(group.MemberIndex) compatibility.Strategies {
			return compatibility.SecurityV2()
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	dkgtest.AssertDkgResultPublished(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, groupSize)
	dkgtest.AssertMemberFailuresCount(t, result, 0)
	dkgtest.AssertSamePublicKey(t, result)
	dkgtest.AssertNoMisbehavingMembers(t, result)
	dkgtest.AssertValidGroupPublicKey(t, result)
}

// TestExecute_MixedModeFailsClosed proves a partially incompatible ceremony
// fails closed: with three legacy members and two security-v2 members under a
// four-member honest threshold, neither same-mode cohort can reach the
// threshold, so no member may produce a threshold signer and no result may
// reach the chain. Cross-mode members cannot decrypt each other's shares and
// derive different commitment generators, so both cohorts see the other as
// misbehaving.
func TestExecute_MixedModeFailsClosed(t *testing.T) {
	t.Parallel()

	groupSize := 5
	honestThreshold := 4
	seed := dkgtest.RandomSeed(t)

	interceptor := func(msg net.TaggedMarshaler) net.TaggedMarshaler {
		return msg
	}

	result, err := dkgtest.RunTestWithModes(
		groupSize,
		honestThreshold,
		seed,
		interceptor,
		func(memberIndex group.MemberIndex) compatibility.Strategies {
			if memberIndex <= 3 {
				return compatibility.Legacy()
			}
			return compatibility.SecurityV2()
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	dkgtest.AssertNoDkgResultPublished(t, result)
	dkgtest.AssertSuccessfulSignersCount(t, result, 0)
	dkgtest.AssertMemberFailuresCount(t, result, groupSize)
}
