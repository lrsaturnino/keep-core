package canonical

import (
	"math/big"
	"testing"
	"time"
)

func TestHexRoundTrip(t *testing.T) {
	value := []byte{0x00, 0x0a, 0xff, 0x10}
	encoded := Hex(value)
	if encoded != "0x000aff10" {
		t.Fatalf("Hex = %q, want 0x000aff10", encoded)
	}
	decoded, err := DecodeHex(encoded, len(value))
	if err != nil {
		t.Fatalf("DecodeHex: %v", err)
	}
	if string(decoded) != string(value) {
		t.Errorf("DecodeHex round trip mismatch")
	}
}

func TestDecodeHexRejects(t *testing.T) {
	tests := []struct {
		name  string
		value string
		size  int
	}{
		{"no prefix", "000aff10", 4},
		{"uppercase", "0x000AFF10", 4},
		{"wrong length", "0x000aff", 4},
		{"non-hex", "0x000aff1z", 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeHex(test.value, test.size); err == nil {
				t.Errorf("DecodeHex(%q) unexpectedly succeeded", test.value)
			}
		})
	}
}

func TestCanonicalAddress(t *testing.T) {
	mixed := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	got, err := CanonicalAddress(mixed)
	if err != nil {
		t.Fatalf("CanonicalAddress: %v", err)
	}
	want := "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
	if got != want {
		t.Errorf("CanonicalAddress = %q, want %q", got, want)
	}

	if _, err := CanonicalAddress("0x1234"); err == nil {
		t.Error("CanonicalAddress of a short value unexpectedly succeeded")
	}
	if _, err := CanonicalAddress("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"); err == nil {
		t.Error("CanonicalAddress without 0x prefix unexpectedly succeeded")
	}
}

// TestChecksumAddress pins the EIP-55 mixed-case display spelling against the
// canonical vectors published in the EIP itself.
func TestChecksumAddress(t *testing.T) {
	vectors := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, want := range vectors {
		lower, err := CanonicalAddress(want)
		if err != nil {
			t.Fatalf("CanonicalAddress(%q): %v", want, err)
		}
		got, err := ChecksumAddress(lower)
		if err != nil {
			t.Fatalf("ChecksumAddress(%q): %v", lower, err)
		}
		if got != want {
			t.Errorf("ChecksumAddress(%q) = %q, want %q", lower, got, want)
		}
	}
}

func TestUint64String(t *testing.T) {
	if got := Uint64String(0); got != "0" {
		t.Errorf("Uint64String(0) = %q", got)
	}
	if got := Uint64String(18446744073709551615); got != "18446744073709551615" {
		t.Errorf("Uint64String(max) = %q", got)
	}

	parsed, err := ParseUint64String("18446744073709551615")
	if err != nil {
		t.Fatalf("ParseUint64String: %v", err)
	}
	if parsed != 18446744073709551615 {
		t.Errorf("ParseUint64String round trip mismatch: %d", parsed)
	}

	for _, bad := range []string{"", "-1", "+1", "01", "0x1", "1 "} {
		if _, err := ParseUint64String(bad); err == nil {
			t.Errorf("ParseUint64String(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestBigIntString(t *testing.T) {
	huge, _ := new(big.Int).SetString("340282366920938463463374607431768211456", 10)
	encoded, err := BigIntString(huge)
	if err != nil {
		t.Fatalf("BigIntString: %v", err)
	}
	if encoded != "340282366920938463463374607431768211456" {
		t.Fatalf("BigIntString = %q", encoded)
	}
	parsed, err := ParseBigIntString(encoded)
	if err != nil {
		t.Fatalf("ParseBigIntString: %v", err)
	}
	if parsed.Cmp(huge) != 0 {
		t.Errorf("ParseBigIntString round trip mismatch")
	}

	negative, err := ParseBigIntString("-42")
	if err != nil {
		t.Fatalf("ParseBigIntString(-42): %v", err)
	}
	if negative.Int64() != -42 {
		t.Errorf("ParseBigIntString(-42) = %v", negative)
	}

	for _, bad := range []string{"", "007", "+7", "-0", "1.0", "abc"} {
		if _, err := ParseBigIntString(bad); err == nil {
			t.Errorf("ParseBigIntString(%q) unexpectedly succeeded", bad)
		}
	}

	if _, err := BigIntString(nil); err == nil {
		t.Error("BigIntString(nil) unexpectedly succeeded")
	}
}

func TestDecodeHexRejectsInvalidSize(t *testing.T) {
	if _, err := DecodeHex("0x", -1); err == nil {
		t.Error("DecodeHex with a negative size unexpectedly succeeded")
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	instant := time.Date(2026, 8, 20, 13, 45, 6, 123456789, time.UTC)
	encoded, err := Timestamp(instant)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if encoded != "2026-08-20T13:45:06.123456789Z" {
		t.Fatalf("Timestamp = %q", encoded)
	}
	parsed, err := ParseTimestamp(encoded)
	if err != nil {
		t.Fatalf("ParseTimestamp: %v", err)
	}
	if !parsed.Equal(instant) {
		t.Errorf("ParseTimestamp round trip mismatch: %v", parsed)
	}
}

func TestTimestampForcesUTCAndFixedPrecision(t *testing.T) {
	// A non-UTC instant is rendered in UTC with a Z.
	loc := time.FixedZone("plus2", 2*3600)
	instant := time.Date(2026, 8, 20, 15, 45, 6, 0, loc)
	got, err := Timestamp(instant)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if got != "2026-08-20T13:45:06.000000000Z" {
		t.Errorf("Timestamp of a non-UTC instant = %q", got)
	}
}

func TestTimestampRejectsOutOfRangeYear(t *testing.T) {
	for _, year := range []int{-1, 10000} {
		instant := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		if _, err := Timestamp(instant); err == nil {
			t.Errorf("Timestamp accepted out-of-range year %d", year)
		}
	}
}

func TestParseTimestampRejectsNonCanonical(t *testing.T) {
	for _, bad := range []string{
		"2026-08-20T13:45:06Z",                // missing nanoseconds
		"2026-08-20T13:45:06.123Z",            // ragged fraction
		"2026-08-20T15:45:06.000000000+02:00", // non-UTC offset
		"2026-08-20t13:45:06.000000000z",      // lowercase
	} {
		if _, err := ParseTimestamp(bad); err == nil {
			t.Errorf("ParseTimestamp(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestDurationNanos(t *testing.T) {
	encoded := DurationNanos(90 * time.Minute)
	if encoded != "5400000000000" {
		t.Fatalf("DurationNanos = %q", encoded)
	}
	parsed, err := ParseDurationNanos(encoded)
	if err != nil {
		t.Fatalf("ParseDurationNanos: %v", err)
	}
	if parsed != 90*time.Minute {
		t.Errorf("ParseDurationNanos round trip mismatch: %v", parsed)
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	value := []byte{0xfb, 0xff, 0x00, 0x3e, 0x3f}
	encoded := Base64URL(value)
	// Unpadded base64url uses - and _ and no trailing =.
	if encoded != "-_8APj8" {
		t.Fatalf("Base64URL = %q", encoded)
	}
	decoded, err := DecodeBase64URL(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64URL: %v", err)
	}
	if string(decoded) != string(value) {
		t.Errorf("DecodeBase64URL round trip mismatch")
	}

	// Padded input is rejected.
	if _, err := DecodeBase64URL("-_8APj8="); err == nil {
		t.Error("DecodeBase64URL of padded input unexpectedly succeeded")
	}
}
