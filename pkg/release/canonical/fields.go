package canonical

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

// timestampLayout is RFC 3339 with a fixed nine-digit nanosecond fraction and a
// literal Z. Fixing the precision keeps two timestamps that denote the same
// instant from producing two different identities.
const timestampLayout = "2006-01-02T15:04:05.000000000Z"

// Hex renders bytes as a lowercase, 0x-prefixed string. This is the one
// spelling every byte-string field uses unless its schema explicitly declares
// unpadded base64url instead.
func Hex(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

// DecodeHex decodes an exact-size, lowercase, 0x-prefixed hex value. Requiring a
// single spelling keeps event identities, result hashes, and addresses from
// acquiring case or prefix aliases that would hash differently.
func DecodeHex(value string, size int) ([]byte, error) {
	if size < 0 || !strings.HasPrefix(value, "0x") ||
		len(value[2:])%2 != 0 || len(value[2:])/2 != size {
		return nil, fmt.Errorf(
			"canonical: expected a 0x-prefixed lowercase hex value of %d bytes",
			size,
		)
	}
	if err := requireLowerHex(value[2:]); err != nil {
		return nil, err
	}
	return hex.DecodeString(value[2:])
}

// DecodeHexDynamic decodes a variable-length, lowercase, 0x-prefixed hex value.
func DecodeHexDynamic(value string) ([]byte, error) {
	if len(value) < 2 || len(value)%2 != 0 || !strings.HasPrefix(value, "0x") {
		return nil, fmt.Errorf(
			"canonical: expected an even-length 0x-prefixed lowercase hex value",
		)
	}
	if err := requireLowerHex(value[2:]); err != nil {
		return nil, err
	}
	return hex.DecodeString(value[2:])
}

func requireLowerHex(digits string) error {
	for _, character := range digits {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return fmt.Errorf(
				"canonical: expected lowercase hex, found %q",
				character,
			)
		}
	}
	return nil
}

// CanonicalAddress normalizes an Ethereum address to its identity form: exactly
// 20 bytes as lowercase 0x-prefixed hex. Input casing is accepted and folded to
// lowercase, because the identity is the 20 bytes and never the display casing.
func CanonicalAddress(value string) (string, error) {
	if len(value) != 42 || !strings.HasPrefix(value, "0x") {
		return "", fmt.Errorf(
			"canonical: expected a 0x-prefixed 20-byte address",
		)
	}
	lowered := strings.ToLower(value)
	if err := requireLowerHex(lowered[2:]); err != nil {
		return "", err
	}
	return lowered, nil
}

// ChecksumAddress derives the EIP-55 mixed-case display spelling of an address.
// The checksum casing is derived from the identity bytes and is never hashed;
// callers store and sign the lowercase identity form and render this only for
// human display.
func ChecksumAddress(value string) (string, error) {
	canonical, err := CanonicalAddress(value)
	if err != nil {
		return "", err
	}
	digits := canonical[2:]

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(digits))
	hash := hex.EncodeToString(hasher.Sum(nil))

	out := []byte("0x")
	for index := 0; index < len(digits); index++ {
		character := digits[index]
		if character >= 'a' && character <= 'f' && hash[index] >= '8' {
			out = append(out, character-('a'-'A'))
		} else {
			out = append(out, character)
		}
	}
	return string(out), nil
}

// Uint64String renders an unsigned integer as a canonical base-10 string. Any
// count that can exceed the interoperable JSON range is carried this way rather
// than as a bare number.
func Uint64String(value uint64) string {
	return strconv.FormatUint(value, 10)
}

// ParseUint64String parses a canonical base-10 unsigned integer string,
// rejecting leading zeros, signs, and other non-canonical spellings.
func ParseUint64String(value string) (uint64, error) {
	if err := requireCanonicalDigits(value, false); err != nil {
		return 0, err
	}
	return strconv.ParseUint(value, 10, 64)
}

// BigIntString renders an arbitrary-precision integer as a canonical base-10
// string. This is the representation for any signed or unsigned integer that
// does not fit the interoperable JSON range. A nil integer is rejected.
func BigIntString(value *big.Int) (string, error) {
	if value == nil {
		return "", fmt.Errorf("canonical: cannot format a nil big integer")
	}
	return value.String(), nil
}

// ParseBigIntString parses a canonical base-10 integer string of arbitrary
// magnitude, rejecting leading zeros and a leading plus.
func ParseBigIntString(value string) (*big.Int, error) {
	if err := requireCanonicalDigits(value, true); err != nil {
		return nil, err
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("canonical: invalid integer %q", value)
	}
	return parsed, nil
}

// requireCanonicalDigits enforces the one spelling of a base-10 integer string:
// an optional single leading minus (only when signed is allowed and only for a
// non-zero magnitude), no leading plus, and no redundant leading zeros.
func requireCanonicalDigits(value string, signed bool) error {
	if value == "" {
		return fmt.Errorf("canonical: empty integer string")
	}

	digits := value
	if strings.HasPrefix(digits, "-") {
		if !signed {
			return fmt.Errorf("canonical: unsigned integer must not be negative")
		}
		digits = digits[1:]
	}

	if digits == "" {
		return fmt.Errorf("canonical: integer string has no digits")
	}
	for _, character := range digits {
		if character < '0' || character > '9' {
			return fmt.Errorf(
				"canonical: non-decimal character %q in integer string",
				character,
			)
		}
	}
	if len(digits) > 1 && digits[0] == '0' {
		return fmt.Errorf("canonical: integer string has a leading zero: %q", value)
	}
	if signed && digits == "0" && strings.HasPrefix(value, "-") {
		return fmt.Errorf("canonical: negative zero is not canonical")
	}
	return nil
}

// Timestamp renders an instant as an RFC 3339 UTC string with fixed nanosecond
// precision and a trailing Z. RFC 3339's four-digit year range is enforced so
// every produced value is accepted by ParseTimestamp.
func Timestamp(value time.Time) (string, error) {
	utc := value.UTC()
	if utc.Year() < 0 || utc.Year() > 9999 {
		return "", fmt.Errorf(
			"canonical: timestamp year %d is outside the RFC 3339 range",
			utc.Year(),
		)
	}
	return utc.Format(timestampLayout), nil
}

// ParseTimestamp parses a canonical timestamp and rejects any spelling that is
// not exactly the one Timestamp produces (non-UTC offset, missing or ragged
// nanoseconds, lowercase z, and so on).
func ParseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("canonical: invalid timestamp: %w", err)
	}
	canonical, err := Timestamp(parsed)
	if err != nil {
		return time.Time{}, err
	}
	if canonical != value {
		return time.Time{}, fmt.Errorf(
			"canonical: timestamp %q is not in canonical form",
			value,
		)
	}
	return parsed.UTC(), nil
}

// DurationNanos renders a duration or deadline as a base-10 nanosecond string.
func DurationNanos(value time.Duration) string {
	return strconv.FormatInt(value.Nanoseconds(), 10)
}

// ParseDurationNanos parses a base-10 nanosecond string into a duration.
func ParseDurationNanos(value string) (time.Duration, error) {
	if err := requireCanonicalDigits(value, true); err != nil {
		return 0, err
	}
	nanos, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("canonical: invalid duration: %w", err)
	}
	return time.Duration(nanos), nil
}

// Base64URL renders bytes as unpadded base64url, the only non-hex byte-string
// spelling a schema may declare.
func Base64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// DecodeBase64URL decodes an unpadded base64url string, rejecting padded or
// standard-alphabet input.
func DecodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, err
	}
	// Strict rejects non-zero trailing padding bits; the round-trip check also
	// makes the accepted spelling explicit and protects this boundary if the
	// standard-library decoder's permissiveness ever changes.
	if Base64URL(decoded) != value {
		return nil, fmt.Errorf("canonical: base64url value is not in canonical form")
	}
	return decoded, nil
}

// ParseAddress accepts only the 20-byte lowercase identity spelling of an
// Ethereum address. CanonicalAddress is the producer-side normalization helper
// for user/display input; schema decoders and verifiers use ParseAddress so
// mixed-case display aliases can never enter hashed payloads.
func ParseAddress(value string) ([20]byte, error) {
	decoded, err := DecodeHex(value, 20)
	if err != nil {
		return [20]byte{}, err
	}
	var address [20]byte
	copy(address[:], decoded)
	return address, nil
}
