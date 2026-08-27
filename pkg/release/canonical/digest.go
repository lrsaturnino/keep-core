package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Hash is a domain-separated 32-byte identity. It is never rendered with a 0x
// prefix: an artifact identity is exactly 64 lowercase hex characters, which
// keeps it textually distinct from the 0x-prefixed byte fields inside an
// artifact.
type Hash [sha256.Size]byte

// Hex renders the identity as 64 lowercase hex characters without a prefix.
func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

// ParseHash parses the one textual identity spelling: exactly 64 lowercase hex
// characters without a 0x prefix.
func ParseHash(value string) (Hash, error) {
	if !isCanonical256Hex(value) {
		return Hash{}, fmt.Errorf("canonical: identity is not 64 lowercase hex characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return Hash{}, fmt.Errorf("canonical: invalid identity: %w", err)
	}
	var result Hash
	copy(result[:], decoded)
	return result, nil
}

// isCanonical256Hex reports whether value is exactly one textual Hash:
// 64 lowercase hexadecimal characters without a prefix.
func isCanonical256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// domainSeparator is the single byte placed between the domain label and the
// payload so that no payload can forge another domain's identity by ending in
// the next domain's label.
const domainSeparator = 0x00

// Digest computes the domain-separated identity of already-canonical payload
// bytes:
//
//	SHA-256(domain || 0x00 || canonical_payload_bytes)
//
// The domain is a stable ASCII label owned by the schema registry, for example
// "pr4109/canonical-anchor/v1"; it may never be supplied by an untrusted
// payload. Callers that hold a Go value should use Identity, which canonicalizes
// first. A digest without a domain is not a valid identity in this pipeline.
func Digest(domain string, canonicalPayload []byte) (Hash, error) {
	if err := validateDomain(domain); err != nil {
		return Hash{}, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(domain))
	hasher.Write([]byte{domainSeparator})
	hasher.Write(canonicalPayload)

	var identity Hash
	copy(identity[:], hasher.Sum(nil))
	return identity, nil
}

// Identity canonicalizes value and returns its domain-separated identity. It is
// the composition callers reach for most: Digest(domain, Marshal(value)).
func Identity(domain string, value any) (Hash, error) {
	canonicalPayload, err := Marshal(value)
	if err != nil {
		return Hash{}, err
	}
	return Digest(domain, canonicalPayload)
}

// validateDomain enforces that a domain label is a non-empty run of visible
// ASCII characters (U+0021..U+007E). This excludes the NUL separator, spaces,
// and all control characters, so a label can never collide with the separator
// or carry invisible bytes.
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("canonical: empty identity domain")
	}
	for index := 0; index < len(domain); index++ {
		character := domain[index]
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf(
				"canonical: identity domain contains a non-visible-ASCII "+
					"byte 0x%02x at position %d",
				character,
				index,
			)
		}
	}
	return nil
}
