package ephemeral

import (
	"fmt"
	"reflect"
	"testing"
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
