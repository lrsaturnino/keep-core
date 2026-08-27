package canonical

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type invalidTextMarshaler struct {
	output byte
}

func (m invalidTextMarshaler) MarshalText() ([]byte, error) {
	return []byte{m.output}, nil
}

func TestCanonicalizeValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "object keys sorted",
			input: `{"b":1,"a":2,"c":3}`,
			want:  `{"a":2,"b":1,"c":3}`,
		},
		{
			name:  "whitespace removed and nested objects sorted",
			input: "{ \"z\": [ 3, 2, 1 ], \"a\": { \"y\": true, \"x\": null } }",
			want:  `{"a":{"x":null,"y":true},"z":[3,2,1]}`,
		},
		{
			name:  "negative zero normalized",
			input: `{"n":-0}`,
			want:  `{"n":0}`,
		},
		{
			name:  "largest safe integers preserved",
			input: `[9007199254740991,-9007199254740991]`,
			want:  `[9007199254740991,-9007199254740991]`,
		},
		{
			name:  "booleans and null",
			input: `[true,false,null]`,
			want:  `[true,false,null]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(test.input))
			if err != nil {
				t.Fatalf("Canonicalize(%s) returned error: %v", test.input, err)
			}
			if string(got) != test.want {
				t.Errorf("Canonicalize(%s)\n got: %s\nwant: %s", test.input, got, test.want)
			}
		})
	}
}

func TestCanonicalizeDepthLimit(t *testing.T) {
	withinLimit := strings.Repeat("[", MaxJSONDepth) + "0" +
		strings.Repeat("]", MaxJSONDepth)
	if _, err := Canonicalize([]byte(withinLimit)); err != nil {
		t.Fatalf("Canonicalize at depth limit: %v", err)
	}

	overLimit := "[" + withinLimit + "]"
	if _, err := Canonicalize([]byte(overLimit)); err == nil {
		t.Fatal("Canonicalize above depth limit unexpectedly succeeded")
	}
}

// TestCanonicalizeStringEscaping exercises the RFC 8785 string escaping rules
// for the two mandatory escapes, the short control-character escapes, and
// literal (unescaped) emission of non-ASCII. The decoded string is built
// explicitly so there is no ambiguity in what bytes are being canonicalized.
// The \u00xx lowercase-hex path for the remaining C0 controls is covered by the
// on-disk golden vectors, which avoid source-level escaping hazards.
//
// This case is not tautological: encoding/json emits the long six-digit
// escapes for backspace and form feed, while the canonical form normalizes
// them to the short backslash-b and backslash-f escapes.
func TestCanonicalizeStringEscaping(t *testing.T) {
	decoded := "A\"B\\C\nD\tE\bF\fG\rH€"

	input, err := json.Marshal(map[string]string{"s": decoded})
	if err != nil {
		t.Fatalf("building input: %v", err)
	}

	want := "{\"s\":\"A\\\"B\\\\C\\nD\\tE\\bF\\fG\\rH€\"}"

	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize returned error: %v", err)
	}
	if string(got) != want {
		t.Errorf("Canonicalize\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalizeUTF16KeyOrder proves the object-member sort is by UTF-16 code
// units and not by UTF-8 bytes. U+1F600 (a surrogate pair 0xD83D,0xDE00) sorts
// before U+FFFF in UTF-16 because 0xD83D < 0xFFFF, but its UTF-8 bytes (0xF0...)
// sort after U+FFFF's (0xEF...). A UTF-8 sort would order these the other way.
func TestCanonicalizeUTF16KeyOrder(t *testing.T) {
	input := "{\"￿\":1,\"\U0001f600\":2}"
	want := "{\"\U0001f600\":2,\"￿\":1}"

	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatalf("Canonicalize returned error: %v", err)
	}
	if string(got) != want {
		t.Errorf("Canonicalize\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalizeIdempotent(t *testing.T) {
	inputs := []string{
		`{"b":1,"a":2}`,
		`[1,2,3]`,
		`{"nested":{"deep":[{"z":1,"a":2}]}}`,
	}
	for _, input := range inputs {
		once, err := Canonicalize([]byte(input))
		if err != nil {
			t.Fatalf("first Canonicalize(%s): %v", input, err)
		}
		twice, err := Canonicalize(once)
		if err != nil {
			t.Fatalf("second Canonicalize(%s): %v", once, err)
		}
		if string(once) != string(twice) {
			t.Errorf("Canonicalize not idempotent for %s: %s vs %s", input, once, twice)
		}
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
		frag  string
	}{
		{"duplicate key", `{"a":1,"a":2}`, "duplicate object key"},
		{"float", `{"a":1.5}`, "floating-point"},
		{"exponent", `{"a":1e3}`, "floating-point"},
		{"integer above safe range", `9007199254740992`, "interoperable range"},
		{"integer below safe range", `-9007199254740992`, "interoperable range"},
		{"empty input", ``, "empty JSON input"},
		{"trailing value", `{} {}`, "more than one JSON value"},
		{"trailing garbage", `1 x`, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Canonicalize([]byte(test.input))
			if err == nil {
				t.Fatalf("Canonicalize(%s) unexpectedly succeeded", test.input)
			}
			if test.frag != "" && !strings.Contains(err.Error(), test.frag) {
				t.Errorf("Canonicalize(%s) error = %q, want fragment %q", test.input, err, test.frag)
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	type inner struct {
		Y bool `json:"y"`
		X int  `json:"x"`
	}
	type outer struct {
		Z []int `json:"z"`
		A inner `json:"a"`
	}

	got, err := Marshal(outer{Z: []int{3, 2, 1}, A: inner{Y: true, X: 5}})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	want := `{"a":{"x":5,"y":true},"z":[3,2,1]}`
	if string(got) != want {
		t.Errorf("Marshal\n got: %s\nwant: %s", got, want)
	}
}

func TestMarshalRejectsFloat(t *testing.T) {
	if _, err := Marshal(map[string]any{"x": 1.5}); err == nil {
		t.Fatal("Marshal of a float unexpectedly succeeded")
	}
}

func TestMarshalRejectsUnsafeInteger(t *testing.T) {
	// A uint64 beyond the interoperable range must be modeled as a string, so
	// marshaling it as a bare number is rejected rather than silently emitting
	// bytes other languages would round differently.
	if _, err := Marshal(map[string]uint64{"x": 1 << 53}); err == nil {
		t.Fatal("Marshal of an out-of-range integer unexpectedly succeeded")
	}
}

func TestCanonicalizeRejectsMalformedUnicode(t *testing.T) {
	for _, input := range [][]byte{
		{'"', 0xff, '"'},
		[]byte(`"\ud800"`),
		[]byte(`"\udc00"`),
		[]byte(`"\ud800\u0041"`),
	} {
		if _, err := Canonicalize(input); err == nil {
			t.Fatalf("Canonicalize accepted malformed Unicode %q", input)
		}
	}
	got, err := Canonicalize([]byte(`{"emoji":"\ud83d\ude00"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair: %v", err)
	}
	if string(got) != `{"emoji":"😀"}` {
		t.Fatalf("surrogate pair canonicalized to %q", got)
	}
}

func TestMarshalRejectsInvalidGoString(t *testing.T) {
	if _, err := Marshal(string([]byte{0xff})); err == nil {
		t.Fatal("Marshal replaced invalid UTF-8 instead of rejecting it")
	}
}

func TestMarshalRejectsTextMarshalerRepair(t *testing.T) {
	first, err := json.Marshal(invalidTextMarshaler{output: 0xff})
	if err != nil {
		t.Fatalf("encoding/json first malformed text value: %v", err)
	}
	second, err := json.Marshal(invalidTextMarshaler{output: 0xfe})
	if err != nil {
		t.Fatalf("encoding/json second malformed text value: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("test setup did not reproduce TextMarshaler repair: %q != %q", first, second)
	}

	if _, err := Marshal(invalidTextMarshaler{output: 0xff}); err == nil {
		t.Fatal("Marshal accepted an encoding.TextMarshaler value")
	}
}

func TestMarshalGoValueDepthLimit(t *testing.T) {
	pointerTo := func(value any) any { return &value }
	var withinPointerLimit any = 0
	for range MaxJSONDepth {
		withinPointerLimit = pointerTo(withinPointerLimit)
	}
	if _, err := Marshal(withinPointerLimit); err != nil {
		t.Fatalf("Marshal pointer chain at traversal limit: %v", err)
	}
	if _, err := Marshal(pointerTo(withinPointerLimit)); err == nil {
		t.Fatal("Marshal pointer chain above traversal limit unexpectedly succeeded")
	}

	var withinContainerLimit any = 0
	for range MaxJSONDepth {
		withinContainerLimit = []any{withinContainerLimit}
	}
	if _, err := Marshal(withinContainerLimit); err != nil {
		t.Fatalf("Marshal nested containers at traversal limit: %v", err)
	}
	if _, err := Marshal([]any{withinContainerLimit}); err == nil {
		t.Fatal("Marshal nested containers above traversal limit unexpectedly succeeded")
	}
}

func TestMarshalChecksAliasedSliceViewsForInvalidUTF8(t *testing.T) {
	values := []string{"valid", string([]byte{0xff})}
	aliased := struct {
		Prefix []string `json:"prefix"`
		All    []string `json:"all"`
	}{
		Prefix: values[:1],
		All:    values,
	}
	if _, err := Marshal(aliased); err == nil {
		t.Fatal("Marshal silently repaired invalid UTF-8 hidden behind an aliased slice view")
	}
}

func TestCanonicalizeSeedsReencodeIdentically(t *testing.T) {
	for _, seed := range [][]byte{
		[]byte(`null`),
		[]byte(`{"b":2,"a":[true,"é",null]}`),
		[]byte(`{"\ud83d\ude00":"astral"}`),
		[]byte(`{"duplicate":1,"duplicate":2}`),
		{0xff},
	} {
		canonical, err := Canonicalize(seed)
		if err != nil {
			continue
		}
		reencoded, err := Canonicalize(canonical)
		if err != nil {
			t.Fatalf("accepted canonical bytes were rejected on reparse: %v", err)
		}
		if !bytes.Equal(canonical, reencoded) {
			t.Fatalf("accepted JSON did not re-encode identically: %q != %q", canonical, reencoded)
		}
	}
}
