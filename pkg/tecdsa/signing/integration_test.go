// Package signing_test contains whole-protocol integration tests for tECDSA
// signing, driving signing.Execute end to end over a local broadcast channel
// via the signingtest harness. This complements the per-phase unit tests in
// protocol_test.go (whose TODO asks for exactly these integration tests) and
// is the entry point for Byzantine signing scenarios (Tier 2).
package signing_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/internal/byzantine"
	"github.com/keep-network/keep-core/pkg/internal/interception"
	"github.com/keep-network/keep-core/pkg/internal/signingtest"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

func TestSigningExecute_HappyPath(t *testing.T) {
	groupSize := 5
	dishonestThreshold := 0
	message := big.NewInt(0xDEADBEEF)

	result, err := signingtest.RunTest(
		message,
		groupSize,
		dishonestThreshold,
		interception.PassThrough,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Every member completes, all agree on one signature, and it verifies
	// against the group public key for the signed message.
	signingtest.AssertSignatureGenerated(t, result, groupSize)
	signingtest.AssertMemberFailuresCount(t, result, 0)
	signingtest.AssertSameSignature(t, result)

	keyShare, err := signingtest.GroupPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signingtest.AssertValidSignature(t, result, keyShare.PublicKey(), message)
}

// TestSigningExecute_Byzantine_Withhold_member2 demonstrates the harness
// carrying a Byzantine strategy through full signing. tECDSA signing is
// all-or-nothing for the chosen signing set: if a participant withholds, the
// session cannot complete. The safety invariant under test is that this causes
// a denial of service (no completion) but NEVER splits the group onto divergent
// signatures. A short execution bound keeps the (expected) DoS quick to observe.
func TestSigningExecute_Byzantine_Withhold_member2(t *testing.T) {
	groupSize := 5
	dishonestThreshold := 0
	message := big.NewInt(0xDEADBEEF)

	strategy := byzantine.Inactive(group.MemberIndex(2))

	result, err := signingtest.RunTestWithTimeout(
		message,
		groupSize,
		dishonestThreshold,
		15*time.Second,
		strategy,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Liveness: tECDSA signing is all-or-nothing for the active signing set.
	// With dishonestThreshold=0 the honest threshold is the whole group, so a
	// single withholding participant prevents EVERY member from completing - the
	// session is a total denial of service. These are the falsifiable contract:
	// a regression that let any member complete, or that changed how many members
	// fail, trips them. (The previous version asserted only no-divergence, which
	// loops over an empty slice when zero members complete and so passed
	// unconditionally.)
	signingtest.AssertSignatureGenerated(t, result, 0)
	signingtest.AssertMemberFailuresCount(t, result, groupSize)

	// Safety: no member may output a signature that disagrees with another, and
	// any signature that is produced must verify against the group key. These are
	// vacuous while zero members complete (asserted above) - all-or-nothing
	// signing over the shared broadcast channel cannot yield a partial, divergent
	// result, and the committed fixtures are a threshold-(groupSize-1) key that
	// only the full set can sign, so a non-vacuous fork cannot be induced here.
	// They are kept as a guard: if a future change ever lets members complete
	// under this scenario, a fork or an invalid signature fails loudly instead of
	// passing silently.
	signingtest.AssertNoDivergentSignatures(t, result)
	keyShare, err := signingtest.GroupPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signingtest.AssertValidSignature(t, result, keyShare.PublicKey(), message)

	t.Logf(
		"withhold(member2): %d signatures produced, %d member failures (total DoS, as required)",
		len(result.GetSignatures()), len(result.GetMemberFailures()),
	)
}
