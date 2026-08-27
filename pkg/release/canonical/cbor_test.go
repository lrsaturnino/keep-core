package canonical

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
)

func TestMarshalCBORGolden(t *testing.T) {
	tests := []struct {
		name  string
		value any
		hex   string
	}{
		{"zero", uint64(0), "00"},
		{"largest inline uint", uint64(23), "17"},
		{"first one-byte uint", uint64(24), "1818"},
		{"largest one-byte uint", uint64(255), "18ff"},
		{"first two-byte uint", uint64(256), "190100"},
		{"max uint64", uint64(math.MaxUint64), "1bffffffffffffffff"},
		{"negative one", int64(-1), "20"},
		{"negative twenty-four", int64(-24), "37"},
		{"negative twenty-five", int64(-25), "3818"},
		{"minimum CBOR integer", CBORNegative(math.MaxUint64), "3bffffffffffffffff"},
		{"empty bytes", []byte{}, "40"},
		{"bytes", []byte{0x00, 0xff}, "4200ff"},
		{"text", "€", "63e282ac"},
		{"array", CBORArray{uint64(1), true, nil}, "8301f5f6"},
		{
			"core deterministic map order",
			CBORMap{
				{Key: "z", Value: "d"},
				{Key: int64(-1), Value: "c"},
				{Key: uint64(100), Value: "b"},
				{Key: uint64(10), Value: "a"},
			},
			"a40a616118646162206163617a6164",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := MarshalCBOR(test.value)
			if err != nil {
				t.Fatalf("MarshalCBOR: %v", err)
			}
			if hex.EncodeToString(got) != test.hex {
				t.Fatalf("encoded %x, want %s", got, test.hex)
			}

			decoded, err := DecodeCBOR(got)
			if err != nil {
				t.Fatalf("DecodeCBOR: %v", err)
			}
			reencoded, err := MarshalCBOR(decoded)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(reencoded, got) {
				t.Fatalf("decode/re-encode changed %x to %x", got, reencoded)
			}
		})
	}
}

func TestDecodeCBORRejectsNoncanonicalAndForbidden(t *testing.T) {
	tests := map[string]string{
		"non-shortest uint8":       "1800",
		"non-shortest uint16":      "190018",
		"non-shortest uint32":      "1a00000100",
		"non-shortest uint64":      "1b00000000ffffffff",
		"indefinite array":         "9f01ff",
		"indefinite bytes":         "5f4100ff",
		"unsorted map":             "a202000100",
		"duplicate map key":        "a201000101",
		"tag":                      "c100",
		"half float":               "f90000",
		"single float":             "fa00000000",
		"double float":             "fb0000000000000000",
		"undefined":                "f7",
		"other simple value":       "e0",
		"simple value with byte":   "f818",
		"invalid utf8":             "61ff",
		"trailing second value":    "0001",
		"truncated byte string":    "4200",
		"reserved additional info": "1c",
	}

	for name, encodedHex := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := hex.DecodeString(encodedHex)
			if err != nil {
				t.Fatalf("decode test hex: %v", err)
			}
			if _, err := DecodeCBOR(encoded); err == nil {
				t.Fatalf("DecodeCBOR accepted %s (%s)", name, encodedHex)
			}
		})
	}
}

func TestMarshalCBORRejectsAmbiguousOrForbiddenValues(t *testing.T) {
	var nilBytes []byte
	var nilArray []string
	var nilMap map[string]any
	var pointerCycle any
	pointerCycle = &pointerCycle
	mapCycle := map[string]any{}
	mapCycle["self"] = mapCycle
	sliceCycle := make([]any, 1)
	sliceCycle[0] = sliceCycle

	tests := map[string]any{
		"float":         1.5,
		"nil bytes":     nilBytes,
		"nil array":     nilArray,
		"nil map":       nilMap,
		"pointer cycle": pointerCycle,
		"map cycle":     mapCycle,
		"slice cycle":   sliceCycle,
		"duplicate semantic map keys": CBORMap{
			{Key: int8(1), Value: "a"},
			{Key: uint64(1), Value: "b"},
		},
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := MarshalCBOR(value); err == nil {
				t.Fatalf("MarshalCBOR accepted %s", name)
			}
		})
	}
}

func TestCBORDepthLimit(t *testing.T) {
	withinLimit := append(bytes.Repeat([]byte{0x81}, MaxCBORDepth), 0x00)
	if _, err := DecodeCBOR(withinLimit); err != nil {
		t.Fatalf("DecodeCBOR at depth limit: %v", err)
	}

	overLimit := append([]byte{0x81}, withinLimit...)
	if _, err := DecodeCBOR(overLimit); err == nil {
		t.Fatal("DecodeCBOR above depth limit unexpectedly succeeded")
	}

	pointerTo := func(value any) any { return &value }
	var withinPointerLimit any = uint64(0)
	for range MaxCBORDepth {
		withinPointerLimit = pointerTo(withinPointerLimit)
	}
	if _, err := MarshalCBOR(withinPointerLimit); err != nil {
		t.Fatalf("MarshalCBOR pointer chain at depth limit: %v", err)
	}

	overPointerLimit := pointerTo(withinPointerLimit)
	if _, err := MarshalCBOR(overPointerLimit); err == nil {
		t.Fatal("MarshalCBOR pointer chain above depth limit unexpectedly succeeded")
	}
}

func TestCanonicalCBORSeedsReencodeIdentically(t *testing.T) {
	for _, seed := range []string{
		"00", "20", "40", "4200ff", "8301f5f6", "a2016161026162",
		"1800", "9f01ff", "a202000100", "f90000",
	} {
		input, _ := hex.DecodeString(seed)
		value, err := DecodeCBOR(input)
		if err != nil {
			continue
		}
		reencoded, err := MarshalCBOR(value)
		if err != nil {
			t.Fatalf("accepted value cannot be encoded: %v", err)
		}
		if !bytes.Equal(reencoded, input) {
			t.Fatalf("accepted CBOR changed on re-encode: %x != %x", input, reencoded)
		}
	}
}
