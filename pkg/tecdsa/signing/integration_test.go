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

	// Safety holds regardless of how many members completed: no two members may
	// ever output different signatures. (Liveness is intentionally sacrificed -
	// a withholding participant denies service, which is the observed outcome.)
	signingtest.AssertNoDivergentSignatures(t, result)

	t.Logf(
		"withhold(member2): %d signatures produced, %d member failures (DoS expected; safety = no divergence)",
		len(result.GetSignatures()), len(result.GetMemberFailures()),
	)
}
