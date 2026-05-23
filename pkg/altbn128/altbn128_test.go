package altbn128

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/internal/testutils"
)

func TestCompressG1(t *testing.T) {
	for i := 0; i < 100; i++ {
		_, p, err := bn256.RandomG1(rand.Reader)

		if err != nil {
			t.Errorf("Error generating random point on G1")
		}

		buffer := G1Point{p}.Compress()
		assertEqual(t, len(buffer), 32, "Compressed G1 should be 32 bytes")
	}
}

func TestDecompressG1(t *testing.T) {
	errorSeen := false
	for i := 0; i < 100; i++ {
		buffer := make([]byte, 32)
		_, err := rand.Read(buffer)
		if err == nil {
			_, err2 := DecompressToG1(buffer)

			if err2 == nil {
				errorSeen = true
			}
		}
	}
	if !errorSeen {
		t.Errorf("No errors seen decompressing random points on G1. Highly unlikely")
	}
}

func TestCompressDecompressGivesSameG1Point(t *testing.T) {
	for i := 0; i < 100; i++ {
		_, p1, err1 := bn256.RandomG1(rand.Reader)

		if err1 != nil {
			continue
		}

		buffer := G1Point{p1}.Compress()

		t.Logf("Compressed G1 to [%v]", buffer)

		p2, _ := DecompressToG1(buffer)

		testutils.AssertBytesEqual(t, p1.Marshal(), p2.Marshal())
	}
}

func TestCompressDecompressGivesSameG2Point(t *testing.T) {
	for i := 0; i < 100; i++ {
		_, p1, err1 := bn256.RandomG2(rand.Reader)

		if err1 != nil {
			continue
		}

		buffer := G2Point{p1}.Compress()

		t.Logf("Compressed G2 to [%v]", buffer)

		p2, _ := DecompressToG2(buffer)

		testutils.AssertBytesEqual(t, p1.Marshal(), p2.Marshal())
	}
}

func TestG1HashToPointDeterministic(t *testing.T) {
	msg := []byte("test message for hash-to-point")
	p1 := G1HashToPoint(msg)
	p2 := G1HashToPoint(msg)
	testutils.AssertBytesEqual(t, p1.Marshal(), p2.Marshal())
}

func TestG1HashToPointDistinct(t *testing.T) {
	p1 := G1HashToPoint([]byte("message one"))
	p2 := G1HashToPoint([]byte("message two"))
	if string(p1.Marshal()) == string(p2.Marshal()) {
		t.Error("distinct inputs produced the same G1 point")
	}
}

func TestG1HashToPointValidPoint(t *testing.T) {
	// A valid G1 point can be marshalled and unmarshalled without error.
	for _, msg := range [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hello world"),
		make([]byte, 32),
	} {
		p := G1HashToPoint(msg)
		if p == nil {
			t.Fatalf("G1HashToPoint returned nil for input %q", msg)
		}
		// Round-trip through Marshal/Unmarshal to confirm the point is on-curve.
		recovered := new(bn256.G1)
		if _, err := recovered.Unmarshal(p.Marshal()); err != nil {
			t.Errorf("G1HashToPoint produced an invalid G1 point for input %q: %v", msg, err)
		}
	}
}

// TestG1HashToPointWireFormat pins the marshalled G1 output for a small set of
// known inputs. G1HashToPoint participates in BLS relay-entry signing and in
// the GJKR DKG Pedersen generator derivation, so any change in its output for
// the same input is a wire-breaking change requiring a coordinated network
// upgrade (see SECURITY-BREAKING-CHANGES.md and F-02.md). If this test fails,
// do NOT update the expected values without scheduling a network cutover.
func TestG1HashToPointWireFormat(t *testing.T) {
	vectors := []struct {
		input       []byte
		expectedHex string
	}{
		{
			input:       []byte(""),
			expectedHex: "0d6b6eb73d503a452c04b979b8755971498d481ce253a35c0cd08ad866b5a58f25bba4e5ae5ce667d11a0abbe09bd0d8a5dd3cb96d9b1aa6a712522a3864aeb1",
		},
		{
			input:       []byte("keep-core G1 pin"),
			expectedHex: "0a20e79a20646662a57a1eada632447c6c966842b7ae285eaaf5ab9d3e51536512d4cb82462b309207a8aa92b8e5aa0e3eb64c1ee1bbafa84f2c1069e4358be7",
		},
		{
			input:       []byte("relay entry v2"),
			expectedHex: "0d362375b0d764011cc14db6819cb6ac72dff0c49a9ff88236c4d8ede0120817284575f93cd1444d37faa967de5eeea0fdd696321dabc9e292eb6b075a25196e",
		},
	}

	for _, v := range vectors {
		got := hex.EncodeToString(G1HashToPoint(v.input).Marshal())
		if got != v.expectedHex {
			t.Errorf(
				"G1HashToPoint(%q) output drifted -- this is a wire-breaking "+
					"change requiring a coordinated network upgrade.\n"+
					"  expected: %s\n"+
					"  got:      %s\n"+
					"See SECURITY-BREAKING-CHANGES.md and security/findings/F-02.md.",
				v.input, v.expectedHex, got,
			)
		}
	}
}

// TestSqrtGfP2Exponent asserts the hardcoded exponent in sqrtGfP2 equals (p^2+15)/32.
func TestSqrtGfP2Exponent(t *testing.T) {
	p2 := new(big.Int).Mul(bn256.P, bn256.P)
	expected := new(big.Int).Div(new(big.Int).Add(p2, big.NewInt(15)), big.NewInt(32))

	hardcoded, ok := new(big.Int).SetString(
		"14971724250519463826312126413021210649976634891596900701138993820439690427699319920245032869357433499099632259837909383182382988566862092145199781964622",
		10,
	)
	if !ok {
		t.Fatal("failed to parse hardcoded exponent")
	}
	if expected.Cmp(hardcoded) != 0 {
		t.Errorf("sqrtGfP2 exponent mismatch:\n  expected (p^2+15)/32 = %v\n  hardcoded            = %v", expected, hardcoded)
	}
}

func assertEqual(t *testing.T, n int, n2 int, msg string) {
	if n != n2 {
		t.Errorf("%v: [%v] != [%v]", msg, n, n2)
	}
}
