package canonical

import "testing"

// TestDigestKnownVectors pins the domain-separated identity against values
// computed independently with an external SHA-256 tool over the exact byte
// sequence domain || 0x00 || payload.
func TestDigestKnownVectors(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		payload string
		want    string
	}{
		{
			name:    "object payload",
			domain:  "pr4109/test/v1",
			payload: `{"a":1}`,
			want:    "c0f823a4773559116d2b87c695da57aa822686fd03442b9a7b56c7939bf82e79",
		},
		{
			name:    "empty object under the anchor domain",
			domain:  "pr4109/canonical-anchor/v1",
			payload: `{}`,
			want:    "c30d5a6026263a869138e471692f8ee7f6f6cc56e0cff070f3ecc477e403fc3c",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Digest(test.domain, []byte(test.payload))
			if err != nil {
				t.Fatalf("Digest returned error: %v", err)
			}
			if got.Hex() != test.want {
				t.Errorf("Digest(%q, %q) = %s, want %s", test.domain, test.payload, got.Hex(), test.want)
			}
		})
	}
}

func TestDigestHexIsSixtyFourLowerHexNoPrefix(t *testing.T) {
	got, err := Digest("pr4109/test/v1", []byte("payload"))
	if err != nil {
		t.Fatalf("Digest returned error: %v", err)
	}
	hex := got.Hex()
	if len(hex) != 64 {
		t.Errorf("digest hex length = %d, want 64", len(hex))
	}
	if !isCanonical256Hex(hex) {
		t.Errorf("digest hex %q is not 64 lowercase hex characters", hex)
	}
}

// TestDigestDomainSeparation confirms the 0x00 separator prevents a payload
// from forging another domain's identity by absorbing the domain suffix. The
// pair (domain="ab", payload="\x00cd...") and (domain="abcd...", payload="")
// would collide without the separator; with it they differ.
func TestDigestDomainSeparation(t *testing.T) {
	a, err := Digest("prefix", []byte("suffix"))
	if err != nil {
		t.Fatalf("Digest a: %v", err)
	}
	b, err := Digest("prefixsuffix", []byte(""))
	if err != nil {
		t.Fatalf("Digest b: %v", err)
	}
	if a.Hex() == b.Hex() {
		t.Error("domain separation failed: different (domain,payload) split produced the same identity")
	}
}

func TestDigestRejectsBadDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"empty", ""},
		{"space", "pr4109 anchor"},
		{"control character", "pr4109\x01anchor"},
		{"nul", "pr4109\x00anchor"},
		{"non-ascii", "pr4109/ançor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Digest(test.domain, []byte("x")); err == nil {
				t.Errorf("Digest with domain %q unexpectedly succeeded", test.domain)
			}
		})
	}
}

func TestIdentityCanonicalizesFirst(t *testing.T) {
	// Two spellings of the same object must yield the same identity, because
	// Identity canonicalizes before digesting.
	unsorted := map[string]int{"b": 2, "a": 1}

	got, err := Identity("pr4109/test/v1", unsorted)
	if err != nil {
		t.Fatalf("Identity returned error: %v", err)
	}

	// {"a":1,"b":2} is the canonical form.
	want, err := Digest("pr4109/test/v1", []byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatalf("Digest returned error: %v", err)
	}
	if got.Hex() != want.Hex() {
		t.Errorf("Identity = %s, want %s", got.Hex(), want.Hex())
	}
}
