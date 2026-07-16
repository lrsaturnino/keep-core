// Package secp256k1 provides helpers for encoding and decoding secp256k1
// public keys.
package secp256k1

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

const uncompressedPublicKeyPrefix = byte(0x04)

// Marshal converts a secp256k1 public key to the 65-byte uncompressed form
// specified in SEC 1, Version 2.0, Section 2.3.3.
func Marshal(publicKey *ecdsa.PublicKey) []byte {
	curve := btcec.S256()
	if publicKey == nil ||
		publicKey.Curve == nil ||
		publicKey.X == nil ||
		publicKey.Y == nil ||
		publicKey.Curve.Params().Name != curve.Params().Name ||
		!curve.IsOnCurve(publicKey.X, publicKey.Y) {
		panic("invalid secp256k1 public key")
	}

	return (*btcec.PublicKey)(publicKey).SerializeUncompressed()
}

// Unmarshal converts a 65-byte uncompressed SEC 1 encoding to a secp256k1
// public key.
func Unmarshal(bytes []byte) (*ecdsa.PublicKey, error) {
	if len(bytes) != btcec.PubKeyBytesLenUncompressed {
		return nil, fmt.Errorf(
			"invalid uncompressed public key length: [%v]",
			len(bytes),
		)
	}

	if bytes[0] != uncompressedPublicKeyPrefix {
		return nil, fmt.Errorf(
			"invalid uncompressed public key prefix: [0x%x]",
			bytes[0],
		)
	}

	publicKey, err := btcec.ParsePubKey(bytes, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 public key: [%w]", err)
	}

	return publicKey.ToECDSA(), nil
}
