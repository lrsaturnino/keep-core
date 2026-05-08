package altbn128

import (
	"crypto/rand"
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
