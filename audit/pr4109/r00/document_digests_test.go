package r00

import (
	"regexp"
	"testing"
)

func TestDocumentDigestsBindEmbeddedR00V1Bytes(t *testing.T) {
	digests := DocumentDigests()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "frozen inputs",
			got:  digests.FrozenInputsSHA256,
			want: "03cecccccb2dc1eb24e0fda9bb05f5403a6e7d962d46d836179b4db09cad5e8b",
		},
		{
			name: "reproduction catalog",
			got:  digests.ReproductionCatalogSHA256,
			want: "79dd86ea28b595de2da49033c5ce9ad0c0b95eaa2152b944d6045db8dba69f6e",
		},
	}

	lowercaseSHA256 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("digest is %q, want %q", test.got, test.want)
			}
			if !lowercaseSHA256.MatchString(test.got) {
				t.Fatalf("digest is not lowercase SHA-256 hexadecimal: %q", test.got)
			}
		})
	}
}
