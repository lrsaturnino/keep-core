package strictjson

import (
	"strings"
	"testing"
)

type testDocument struct {
	Name   string       `json:"name"`
	Nested testNested   `json:"nested"`
	Items  []testNested `json:"items"`
}

type testNested struct {
	Enabled bool `json:"enabled"`
}

func TestDecodeRejectsAmbiguousJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "duplicate root name",
			input: `{"name":"first","name":"last","nested":{"enabled":true},"items":[]}`,
			want:  `duplicate JSON object name "name" at $`,
		},
		{
			name:  "duplicate nested name",
			input: `{"name":"one","nested":{"enabled":true,"enabled":false},"items":[]}`,
			want:  `duplicate JSON object name "enabled" at $.nested`,
		},
		{
			name:  "duplicate name in array object",
			input: `{"name":"one","nested":{"enabled":true},"items":[{"enabled":true,"enabled":false}]}`,
			want:  `duplicate JSON object name "enabled" at $.items[0]`,
		},
		{
			name:  "unknown field",
			input: `{"name":"one","nested":{"enabled":true},"items":[],"extra":true}`,
			want:  `unknown field "extra"`,
		},
		{
			name:  "case folded root alias",
			input: `{"name":"one","NAME":"two","nested":{"enabled":true},"items":[]}`,
			want:  `object name "NAME" at $ must use exact field name "name"`,
		},
		{
			name:  "case folded nested alias",
			input: `{"name":"one","nested":{"enabled":true,"ENABLED":false},"items":[]}`,
			want:  `object name "ENABLED" at $.nested must use exact field name "enabled"`,
		},
		{
			name:  "multiple values",
			input: `{"name":"one","nested":{"enabled":true},"items":[]} {}`,
			want:  "multiple JSON values",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document testDocument
			err := Decode([]byte(test.input), &document)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Decode error is %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	input := append(
		[]byte(`{"name":"`),
		[]byte{0xff, 0xfe}...,
	)
	input = append(input, []byte(`","nested":{"enabled":true},"items":[]}`)...)

	var document testDocument
	err := Decode(input, &document)
	if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("Decode error is %v, want invalid UTF-8 rejection", err)
	}
}

func TestDecodeRejectsUnpairedUTF16Surrogates(t *testing.T) {
	for _, input := range []string{
		`{"name":"\ud800","nested":{"enabled":true},"items":[]}`,
		`{"name":"\udfff","nested":{"enabled":true},"items":[]}`,
		`{"name":"\ud800x","nested":{"enabled":true},"items":[]}`,
	} {
		var document testDocument
		err := Decode([]byte(input), &document)
		if err == nil || !strings.Contains(err.Error(), "unpaired") {
			t.Fatalf("Decode error is %v, want unpaired-surrogate rejection", err)
		}
	}
}

func TestDecodeAcceptsPairedUTF16Surrogates(t *testing.T) {
	input := []byte(`{"name":"\ud83d\ude00","nested":{"enabled":true},"items":[]}`)
	var document testDocument
	if err := Decode(input, &document); err != nil {
		t.Fatalf("Decode rejected a valid surrogate pair: %v", err)
	}
	if document.Name != "😀" {
		t.Fatalf("Decode returned name %q, want grinning face", document.Name)
	}
}

func TestDecodeAcceptsOneUnambiguousDocument(t *testing.T) {
	input := []byte(`{"name":"one","nested":{"enabled":true},"items":[{"enabled":false}]}`)
	var document testDocument
	if err := Decode(input, &document); err != nil {
		t.Fatalf("Decode rejected valid document: %v", err)
	}
	if document.Name != "one" || !document.Nested.Enabled || document.Items[0].Enabled {
		t.Fatalf("Decode returned unexpected document: %+v", document)
	}
}
