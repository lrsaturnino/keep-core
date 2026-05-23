package group

import (
	"testing"
	"unsafe"
)

// TestMemberIndexFitsInOneByte is a belt-and-braces runtime check on top of the
// compile-time assertion in group.go. The F-03 HKDF info encoders in gjkr,
// tecdsa-dkg, and tecdsa-signing serialize each MemberIndex as a single byte
// via `byte(id)`. If MemberIndex is ever widened, the compile-time assertion
// in this package fires first; this test exists so a reader grepping for
// "MemberIndex" finds an explicit, named justification for that invariant.
func TestMemberIndexFitsInOneByte(t *testing.T) {
	if got := unsafe.Sizeof(MemberIndex(0)); got != 1 {
		t.Fatalf(
			"MemberIndex must be one byte for F-03 EcdhInfo encoders to be "+
				"injective; got sizeof %d. Either revert the type change or "+
				"switch all *EcdhInfo encoders to a width-independent "+
				"encoding (e.g. binary.BigEndian.PutUint16) in a coordinated "+
				"network upgrade.",
			got,
		)
	}
	if MaxMemberIndex != 255 {
		t.Fatalf("MaxMemberIndex must be 255, got %d", MaxMemberIndex)
	}
}
