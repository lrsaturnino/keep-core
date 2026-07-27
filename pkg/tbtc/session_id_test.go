package tbtc

import (
	"math/big"
	"testing"

	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// TestDkgAttemptSessionID_ExactForms pins both compatibility forms of the DKG
// attempt session ID byte-for-byte: the legacy form is exactly what the
// pre-hardening production releases announce, and the security-v2 form is the
// hardened protocol-named, fixed-width form. The announcer's wire-format
// classifier must agree with the producer on both.
func TestDkgAttemptSessionID_ExactForms(t *testing.T) {
	seed := new(big.Int).SetBytes([]byte{0xAB, 0xCD, 0xEF})

	legacy := dkgAttemptSessionID(participation.ModeLegacy, seed, 7)
	if legacy != "abcdef-7" {
		t.Errorf("expected legacy session ID [abcdef-7], got [%s]", legacy)
	}
	if format := announcer.ClassifySessionIDFormat(
		legacy,
	); format != announcer.SessionIDFormatLegacy {
		t.Errorf(
			"expected the legacy session ID to classify as legacy, got [%s]",
			format,
		)
	}

	hardened := dkgAttemptSessionID(participation.ModeSecurityV2, seed, 7)
	if hardened != "dkg-abcdef-0000000000000007" {
		t.Errorf(
			"expected hardened session ID [dkg-abcdef-0000000000000007], "+
				"got [%s]",
			hardened,
		)
	}
	if format := announcer.ClassifySessionIDFormat(
		hardened,
	); format != announcer.SessionIDFormatHardenedDKG {
		t.Errorf(
			"expected the hardened session ID to classify as hardened DKG, "+
				"got [%s]",
			format,
		)
	}
}

// TestSigningAttemptSessionID_ExactForms pins both compatibility forms of the
// signing attempt session ID byte-for-byte. The legacy form carries no attempt
// start block — exactly as the pre-hardening production releases announce —
// while the security-v2 form carries the protocol name and fixed-width start
// block and attempt.
func TestSigningAttemptSessionID_ExactForms(t *testing.T) {
	message := new(big.Int).SetBytes([]byte{0x01, 0x23, 0x45})

	legacy := signingAttemptSessionID(participation.ModeLegacy, message, 206, 12)
	if legacy != "12345-12" {
		t.Errorf("expected legacy session ID [12345-12], got [%s]", legacy)
	}
	if format := announcer.ClassifySessionIDFormat(
		legacy,
	); format != announcer.SessionIDFormatLegacy {
		t.Errorf(
			"expected the legacy session ID to classify as legacy, got [%s]",
			format,
		)
	}

	hardened := signingAttemptSessionID(
		participation.ModeSecurityV2,
		message,
		206,
		12,
	)
	if hardened != "signing-12345-00000000000000ce-000000000000000c" {
		t.Errorf(
			"expected hardened session ID "+
				"[signing-12345-00000000000000ce-000000000000000c], got [%s]",
			hardened,
		)
	}
	if format := announcer.ClassifySessionIDFormat(
		hardened,
	); format != announcer.SessionIDFormatHardenedSigning {
		t.Errorf(
			"expected the hardened session ID to classify as hardened "+
				"signing, got [%s]",
			format,
		)
	}
}

// TestAttemptSessionID_UnsetModePanics proves there is no implicit protocol
// mode: an unset mode is a programming error that must fail loudly rather
// than silently produce either wire format.
func TestAttemptSessionID_UnsetModePanics(t *testing.T) {
	assertPanics := func(name string, fn func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected a panic for an unset protocol mode", name)
			}
		}()
		fn()
	}

	assertPanics("dkg", func() {
		dkgAttemptSessionID(participation.ProtocolMode(0), big.NewInt(1), 1)
	})
	assertPanics("signing", func() {
		signingAttemptSessionID(
			participation.ProtocolMode(0),
			big.NewInt(1),
			1,
			1,
		)
	})
}
