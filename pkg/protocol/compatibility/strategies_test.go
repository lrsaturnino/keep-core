package compatibility

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/crypto/ephemeral"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

func TestStrategiesFor(t *testing.T) {
	legacy, err := StrategiesFor(participation.ModeLegacy)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if legacy.Mode() != participation.ModeLegacy {
		t.Errorf("expected legacy mode, got [%s]", legacy.Mode())
	}

	securityV2, err := StrategiesFor(participation.ModeSecurityV2)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if securityV2.Mode() != participation.ModeSecurityV2 {
		t.Errorf("expected security_v2 mode, got [%s]", securityV2.Mode())
	}

	// There is no default bundle: an unset or unknown mode must fail loudly
	// instead of silently selecting one side of the cutover.
	for _, mode := range []participation.ProtocolMode{0, 3, 255} {
		if _, err := StrategiesFor(mode); err == nil {
			t.Errorf("expected an error for mode [%d]", mode)
		}
	}
}

// TestDKGSessionIDFixtures pins the exact DKG announcement session-ID bytes
// of both modes. The legacy form must remain byte-for-byte the pre-hardening
// production form; the security-v2 form must remain the hardened form. A
// drifted value breaks announcement matching with the corresponding release.
func TestDKGSessionIDFixtures(t *testing.T) {
	seed, ok := new(big.Int).SetString("64757a1f", 16)
	if !ok {
		t.Fatal("could not parse the seed fixture")
	}

	legacy, _ := StrategiesFor(participation.ModeLegacy)
	securityV2, _ := StrategiesFor(participation.ModeSecurityV2)

	if got := legacy.DKGSessionID(seed, 1); got != "64757a1f-1" {
		t.Errorf("legacy DKG session ID drifted: [%s]", got)
	}
	if got := legacy.DKGSessionID(seed, 12); got != "64757a1f-12" {
		t.Errorf("legacy DKG session ID drifted: [%s]", got)
	}

	if got := securityV2.DKGSessionID(
		seed, 1,
	); got != "dkg-64757a1f-0000000000000001" {
		t.Errorf("security-v2 DKG session ID drifted: [%s]", got)
	}
	if got := securityV2.DKGSessionID(
		seed, 12,
	); got != "dkg-64757a1f-000000000000000c" {
		t.Errorf("security-v2 DKG session ID drifted: [%s]", got)
	}
}

// TestSigningSessionIDFixtures pins the exact signing announcement session-ID
// bytes of both modes. The legacy form carries no attempt start block — the
// start block must not leak into it — while the security-v2 form binds both
// the start block and the attempt with fixed width.
func TestSigningSessionIDFixtures(t *testing.T) {
	message, ok := new(big.Int).SetString("9f1c8e2d", 16)
	if !ok {
		t.Fatal("could not parse the message fixture")
	}

	legacy, _ := StrategiesFor(participation.ModeLegacy)
	securityV2, _ := StrategiesFor(participation.ModeSecurityV2)

	if got := legacy.SigningSessionID(message, 12345, 3); got != "9f1c8e2d-3" {
		t.Errorf("legacy signing session ID drifted: [%s]", got)
	}
	// Different start blocks must produce the identical legacy session ID.
	if got := legacy.SigningSessionID(message, 99999, 3); got != "9f1c8e2d-3" {
		t.Errorf(
			"legacy signing session ID depends on the start block: [%s]",
			got,
		)
	}

	if got := securityV2.SigningSessionID(
		message, 12345, 3,
	); got != "signing-9f1c8e2d-0000000000003039-0000000000000003" {
		t.Errorf("security-v2 signing session ID drifted: [%s]", got)
	}
}

// TestECDHSelection proves the bundle selects the exact derivation of its
// mode — the key agrees with the mode's direct derivation — and that the two
// modes' keys cannot decrypt each other's ciphertexts: they fail with an
// error, not a panic or a wrong plaintext.
func TestECDHSelection(t *testing.T) {
	keyPair1, err := ephemeral.GenerateKeyPair()
	if err != nil {
		t.Fatalf("could not generate a key pair: [%v]", err)
	}
	keyPair2, err := ephemeral.GenerateKeyPair()
	if err != nil {
		t.Fatalf("could not generate a key pair: [%v]", err)
	}

	legacy, _ := StrategiesFor(participation.ModeLegacy)
	securityV2, _ := StrategiesFor(participation.ModeSecurityV2)

	info := []byte("protocol-label|peer-pair")
	plaintext := []byte("compatibility bundle plaintext")

	// The legacy bundle key must agree with the direct legacy derivation on
	// the other side of the exchange.
	legacyKey := legacy.ECDH(keyPair1.PrivateKey, keyPair2.PublicKey, info)
	directLegacy := keyPair2.PrivateKey.EcdhLegacy(keyPair1.PublicKey)
	ciphertext, err := legacyKey.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("could not encrypt: [%v]", err)
	}
	decrypted, err := directLegacy.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("legacy bundle key disagrees with EcdhLegacy: [%v]", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("legacy round trip corrupted the plaintext")
	}

	// The security-v2 bundle key must agree with the direct hardened
	// derivation for the same info label.
	securityV2Key := securityV2.ECDH(
		keyPair1.PrivateKey, keyPair2.PublicKey, info,
	)
	directSecurityV2 := keyPair2.PrivateKey.Ecdh(keyPair1.PublicKey, info)
	ciphertext, err = securityV2Key.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("could not encrypt: [%v]", err)
	}
	decrypted, err = directSecurityV2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("security-v2 bundle key disagrees with Ecdh: [%v]", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("security-v2 round trip corrupted the plaintext")
	}

	// Cross-mode decryption must fail closed in both directions.
	securityV2Ciphertext, err := securityV2Key.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("could not encrypt: [%v]", err)
	}
	if _, err := legacyKey.Decrypt(securityV2Ciphertext); err == nil {
		t.Error("the legacy key decrypted a security-v2 ciphertext")
	}
	legacyCiphertext, err := legacyKey.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("could not encrypt: [%v]", err)
	}
	if _, err := securityV2Key.Decrypt(legacyCiphertext); err == nil {
		t.Error("the security-v2 key decrypted a legacy ciphertext")
	}
}

// TestG1HashToPointSelection proves the bundle selects the exact
// hash-to-point mapping of its mode and that the two mappings diverge for the
// same input, so a mode mix-up cannot go unnoticed on the wire.
func TestG1HashToPointSelection(t *testing.T) {
	legacy, _ := StrategiesFor(participation.ModeLegacy)
	securityV2, _ := StrategiesFor(participation.ModeSecurityV2)

	for _, message := range [][]byte{
		[]byte(""),
		[]byte("beacon group seed"),
		make([]byte, 32),
	} {
		legacyPoint := legacy.G1HashToPoint(message).Marshal()
		if !bytes.Equal(
			legacyPoint,
			altbn128.G1HashToPointLegacy(message).Marshal(),
		) {
			t.Errorf(
				"legacy bundle mapping disagrees with G1HashToPointLegacy "+
					"for input %q",
				message,
			)
		}

		securityV2Point := securityV2.G1HashToPoint(message).Marshal()
		if !bytes.Equal(
			securityV2Point,
			altbn128.G1HashToPoint(message).Marshal(),
		) {
			t.Errorf(
				"security-v2 bundle mapping disagrees with G1HashToPoint "+
					"for input %q",
				message,
			)
		}

		if bytes.Equal(legacyPoint, securityV2Point) {
			t.Errorf(
				"legacy and security-v2 mappings coincided for input %q",
				message,
			)
		}
	}
}
