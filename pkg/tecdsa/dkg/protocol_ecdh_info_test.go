package dkg

import (
	"bytes"
	"testing"

	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// TestDkgEcdhInfoSortSymmetry verifies that the info label is independent of
// argument order. Both peers must derive the same session key regardless of
// who initiates.
func TestDkgEcdhInfoSortSymmetry(t *testing.T) {
	for a := group.MemberIndex(1); a < group.MaxMemberIndex; a++ {
		for b := group.MemberIndex(1); b < group.MaxMemberIndex; b++ {
			if !bytes.Equal(dkgEcdhInfo(a, b), dkgEcdhInfo(b, a)) {
				t.Fatalf("info label not symmetric for (%d, %d)", a, b)
			}
		}
	}
}

// TestDkgEcdhInfoDistinctPerPair verifies that every distinct sorted member
// pair produces a distinct info label. This is the F-03 invariant that would
// silently break if MemberIndex is ever widened past uint8 without updating
// the encoder.
func TestDkgEcdhInfoDistinctPerPair(t *testing.T) {
	seen := make(map[string][2]group.MemberIndex)
	for a := group.MemberIndex(1); a < group.MaxMemberIndex; a++ {
		for b := a; b < group.MaxMemberIndex; b++ {
			label := string(dkgEcdhInfo(a, b))
			if prev, ok := seen[label]; ok {
				t.Fatalf(
					"info label collision: (%d, %d) and (%d, %d) both produce %x",
					prev[0], prev[1], a, b, label,
				)
			}
			seen[label] = [2]group.MemberIndex{a, b}
		}
	}
}

// TestDkgEcdhInfoEncoding pins the wire format. Any change here is a
// protocol-breaking change and requires a coordinated network upgrade.
func TestDkgEcdhInfoEncoding(t *testing.T) {
	got := dkgEcdhInfo(7, 3)
	want := []byte{'t', 'e', 'c', 'd', 's', 'a', '-', 'd', 'k', 'g', 3, 7}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding drift: got %v, want %v", got, want)
	}
}
