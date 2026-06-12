package signingtest

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
)

// AssertSignatureGenerated checks how many members produced a signature.
func AssertSignatureGenerated(t *testing.T, result *Result, expectedCount int) {
	if len(result.signatures) != expectedCount {
		t.Errorf(
			"unexpected number of produced signatures\nexpected: [%v]\nactual:   [%v]",
			expectedCount,
			len(result.signatures),
		)
	}
}

// AssertMemberFailuresCount checks how many members failed to complete.
func AssertMemberFailuresCount(t *testing.T, result *Result, expectedCount int) {
	if len(result.memberFailures) != expectedCount {
		t.Errorf(
			"unexpected number of member failures\nexpected: [%v]\nactual:   [%v]\nerrors:   %v",
			expectedCount,
			len(result.memberFailures),
			result.memberFailures,
		)
	}
}

// AssertSameSignature checks that every member that completed produced the
// identical signature - the core agreement invariant of threshold signing.
func AssertSameSignature(t *testing.T, result *Result) {
	if len(result.signatures) < 2 {
		return
	}
	first := result.signatures[0]
	for i, sig := range result.signatures[1:] {
		if !first.Equals(sig) {
			t.Errorf(
				"signatures disagree: member-result[0] != member-result[%d]\n[0]: %s\n[%d]: %s",
				i+1, first, i+1, sig,
			)
		}
	}
}

// AssertNoDivergentSignatures is the safety invariant for Byzantine scenarios:
// regardless of how many members complete (a disrupted signing session may
// produce zero), no two members may ever output DIFFERENT signatures. A
// Byzantine participant may cause a denial of service, but must never split the
// group onto conflicting signatures.
func AssertNoDivergentSignatures(t *testing.T, result *Result) {
	for i := 1; i < len(result.signatures); i++ {
		if !result.signatures[0].Equals(result.signatures[i]) {
			t.Errorf(
				"SAFETY VIOLATION: divergent signatures produced\n[0]: %s\n[%d]: %s",
				result.signatures[0], i, result.signatures[i],
			)
		}
	}
}

// AssertValidSignature checks that every produced signature verifies against
// the group public key for the signed message. publicKey is the ECDSA group key
// the fixture shares correspond to (see GroupPublicKey).
func AssertValidSignature(
	t *testing.T,
	result *Result,
	publicKey *ecdsa.PublicKey,
	message *big.Int,
) {
	for i, sig := range result.signatures {
		if !ecdsa.Verify(publicKey, message.Bytes(), sig.R, sig.S) {
			t.Errorf(
				"signature %d does not verify against the group public key: %s",
				i, sig,
			)
		}
	}
}
