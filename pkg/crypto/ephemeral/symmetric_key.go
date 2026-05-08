package ephemeral

import (
	"crypto/sha256"
	"io"

	"github.com/btcsuite/btcd/btcec"
	"github.com/keep-network/keep-common/pkg/encryption"
	"golang.org/x/crypto/hkdf"
)

// SymmetricEcdhKey is an ephemeral Elliptic Curve key created with
// Diffie-Hellman key exchange and implementing `SymmetricKey` interface.
type SymmetricEcdhKey struct {
	box encryption.Box
}

// Ecdh performs Elliptic Curve Diffie-Hellman between the private key and
// publicKey, then derives a 32-byte symmetric key via HKDF-SHA256. The info
// parameter provides domain separation: callers should pass a label encoding
// the protocol name and the canonical (sorted) peer-pair IDs so that keys
// derived for different protocols or peer pairs are cryptographically
// independent.
func (pk *PrivateKey) Ecdh(publicKey *PublicKey, info []byte) *SymmetricEcdhKey {
	shared := btcec.GenerateSharedSecret(
		(*btcec.PrivateKey)(pk),
		(*btcec.PublicKey)(publicKey),
	)

	kdf := hkdf.New(sha256.New, shared, nil, info)
	var key [32]byte
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		// HKDF over a fixed-size output cannot fail in practice.
		panic("ephemeral.Ecdh: HKDF derivation failed: " + err.Error())
	}

	return &SymmetricEcdhKey{
		box: encryption.NewBox(key),
	}
}

// Encrypt plaintext.
func (sek *SymmetricEcdhKey) Encrypt(plaintext []byte) ([]byte, error) {
	return sek.box.Encrypt(plaintext)
}

// Decrypt ciphertext.
func (sek *SymmetricEcdhKey) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	return sek.box.Decrypt(ciphertext)
}
