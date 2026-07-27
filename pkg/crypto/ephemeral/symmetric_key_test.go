package ephemeral

import (
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/keep-network/keep-common/pkg/encryption"
	"golang.org/x/crypto/hkdf"
)

func TestEncryptDecrypt(t *testing.T) {
	msg := "I’m just a little black rain cloud, hovering under the honey tree."

	symmetricKey, err := newEcdhSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := symmetricKey.Encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := symmetricKey.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	decryptedString := string(decrypted)
	if decryptedString != msg {
		t.Fatalf(
			"unexpected message\nexpected: %v\nactual: %v",
			msg,
			decryptedString,
		)
	}
}

func TestCiphertextRandomized(t *testing.T) {
	msg := `You can't stay in your corner of the forest waiting 
			 for others to come to you. You have to go to them sometimes.`

	symmetricKey, err := newEcdhSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypted1, err := symmetricKey.Encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	encrypted2, err := symmetricKey.Encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	if len(encrypted1) != len(encrypted2) {
		t.Fatalf(
			"expected the same length of ciphertexts (%v vs %v)",
			len(encrypted1),
			len(encrypted2),
		)
	}

	if reflect.DeepEqual(encrypted1, encrypted2) {
		t.Fatalf("expected two different ciphertexts")
	}
}

func TestGracefullyHandleBrokenCipher(t *testing.T) {
	symmetricKey, err := newEcdhSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	brokenCipher := []byte{0x01, 0x02, 0x03}

	_, err = symmetricKey.Decrypt(brokenCipher)

	expectedError := fmt.Errorf("symmetric key decryption failed")
	if !reflect.DeepEqual(expectedError, err) {
		t.Fatalf(
			"unexpected error\nexpected: %v\nactual:   %v",
			expectedError,
			err,
		)
	}
}

// TestEcdhInfoDomainSeparation verifies that different info values produce
// different keys even for the same ECDH shared secret.
func TestEcdhInfoDomainSeparation(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	keyA := keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, []byte("protocol-a"))
	keyB := keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, []byte("protocol-b"))

	msgA, err := keyA.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// keyB must not decrypt a message encrypted with keyA.
	if _, err := keyB.Decrypt(msgA); err == nil {
		t.Fatal("different info values produced the same key")
	}
}

// TestEcdhSymmetry verifies that both sides of ECDH with the same info derive
// the same key (ECDH is commutative and HKDF is deterministic).
func TestEcdhSymmetry(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	info := []byte("symmetry-test")
	key1 := keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, info)
	key2 := keyPair2.PrivateKey.Ecdh(keyPair1.PublicKey, info)

	msg := []byte("message")
	encrypted, err := key1.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := key2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("symmetric ECDH keys do not match: %v", err)
	}
	if string(decrypted) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, decrypted)
	}
}

func newEcdhSymmetricKey() (*SymmetricEcdhKey, error) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	keyPair2, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, []byte("test")), nil
}

// TestEcdhNilInfoDiffersFromLabeled documents that passing nil info produces a
// key that is cryptographically distinct from any labeled derivation. This
// prevents a regression where nil and a real label converge to the same key.
func TestEcdhNilInfoDiffersFromLabeled(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	keyNil := keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, nil)
	keyLabeled := keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, []byte("some-protocol"))

	msg := []byte("probe")
	encrypted, err := keyNil.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyLabeled.Decrypt(encrypted); err == nil {
		t.Fatal("nil info and labeled info produced the same HKDF key")
	}
}

// TestEcdhLegacyMatchesPreHardeningDerivation proves EcdhLegacy derives the
// exact pre-hardening key: a box keyed with the direct SHA-256 of the ECDH
// shared secret, computed here independently, must interoperate with the
// EcdhLegacy box in both directions.
func TestEcdhLegacyMatchesPreHardeningDerivation(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	legacyKey := keyPair1.PrivateKey.EcdhLegacy(keyPair2.PublicKey)

	shared := btcec.GenerateSharedSecret(
		(*btcec.PrivateKey)(keyPair2.PrivateKey),
		(*btcec.PublicKey)(keyPair1.PublicKey),
	)
	referenceKey := &SymmetricEcdhKey{
		box: encryption.NewBox(sha256.Sum256(shared)),
	}

	msg := []byte("legacy reference interop")
	encrypted, err := legacyKey.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := referenceKey.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("reference sha256(shared) key cannot decrypt: [%v]", err)
	}
	if string(decrypted) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, decrypted)
	}

	encrypted, err = referenceKey.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = legacyKey.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("EcdhLegacy cannot decrypt the reference key: [%v]", err)
	}
	if string(decrypted) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, decrypted)
	}
}

// TestEcdhMatchesHKDFDerivation proves the hardened Ecdh derives the exact
// HKDF-SHA256 key for a protocol/peer info label, computed here independently.
func TestEcdhMatchesHKDFDerivation(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	info := []byte("protocol-label-peer-1-2")
	hardenedKey := keyPair1.PrivateKey.Ecdh(keyPair2.PublicKey, info)

	shared := btcec.GenerateSharedSecret(
		(*btcec.PrivateKey)(keyPair2.PrivateKey),
		(*btcec.PublicKey)(keyPair1.PublicKey),
	)
	kdf := hkdf.New(sha256.New, shared, nil, info)
	var key [32]byte
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		t.Fatal(err)
	}
	referenceKey := &SymmetricEcdhKey{box: encryption.NewBox(key)}

	msg := []byte("hardened reference interop")
	encrypted, err := hardenedKey.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := referenceKey.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("reference HKDF key cannot decrypt: [%v]", err)
	}
	if string(decrypted) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, decrypted)
	}
}

// TestEcdhLegacySymmetry proves both sides of the legacy derivation reach the
// same key, exactly as prior-release peers do.
func TestEcdhLegacySymmetry(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	key1 := keyPair1.PrivateKey.EcdhLegacy(keyPair2.PublicKey)
	key2 := keyPair2.PrivateKey.EcdhLegacy(keyPair1.PublicKey)

	msg := []byte("legacy homogeneous message")
	encrypted, err := key1.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := key2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("legacy symmetric ECDH keys do not match: [%v]", err)
	}
	if string(decrypted) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, decrypted)
	}
}

// TestEcdhCrossModeDecryptionFails proves the two derivations are
// cryptographically disjoint: a legacy key must not decrypt a security-v2
// ciphertext and the reverse must fail with an error, without producing
// plaintext and without panicking.
func TestEcdhCrossModeDecryptionFails(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	legacyKey := keyPair1.PrivateKey.EcdhLegacy(keyPair2.PublicKey)
	hardenedKey := keyPair2.PrivateKey.Ecdh(
		keyPair1.PublicKey,
		[]byte("protocol-label"),
	)

	msg := []byte("cross-mode probe")

	hardenedCiphertext, err := hardenedKey.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := legacyKey.Decrypt(hardenedCiphertext); err == nil {
		t.Fatalf(
			"legacy key decrypted a security-v2 ciphertext: %q",
			plaintext,
		)
	}

	legacyCiphertext, err := legacyKey.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := hardenedKey.Decrypt(legacyCiphertext); err == nil {
		t.Fatalf(
			"security-v2 key decrypted a legacy ciphertext: %q",
			plaintext,
		)
	}
}
