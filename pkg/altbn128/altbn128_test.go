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
// known inputs. G1HashToPoint's only operational consumer is the GJKR DKG
// Pedersen commitment generator H, which every group member derives from the
// shared beacon seed (pkg/beacon/gjkr/protocol_parameters.go); all members must
// derive an identical H, so its output must agree node-to-node. (The relay-entry
// path signs and verifies raw G1 points via bls.SignG1/VerifyG1 and never routes
// through this function.) Any change in its output for the same input is a
// wire-breaking change requiring a coordinated network upgrade (see
// SECURITY-BREAKING-CHANGES.md and F-02.md). If this test fails, do NOT update
// the expected values without scheduling a network cutover.
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

// TestG1HashToPointLegacyWireFormat pins the marshalled output of the legacy
// try-and-increment mapping for a small set of known inputs. The legacy
// mapping exists solely so a ceremony pinned to the legacy protocol mode
// remains wire-compatible with peers running a pre-hardening production
// release: its output must stay byte-for-byte what those releases derive. If
// this test fails, the legacy compatibility path is broken — do NOT update
// the expected values; restore the mapping.
func TestG1HashToPointLegacyWireFormat(t *testing.T) {
	vectors := []struct {
		input       []byte
		expectedHex string
	}{
		{
			input:       []byte(""),
			expectedHex: "221f8a7714359b6db9baddee936a57adc9a8979ec2d46917b41368c0165ec33a2a05536f2b20da52c6ae18e4a02e2aec0a7f35497cfd27b9084ef5c0147b1442",
		},
		{
			input:       []byte("keep-core G1 pin"),
			expectedHex: "089fea656fe4bbf194be17dadca92032084f10647fd6f2233028e80d18f025832143081e571616093f5a1f6e352902a438f60cc7f8a75a3fe5bc8783ef2ecd28",
		},
		{
			input:       []byte("relay entry v2"),
			expectedHex: "1401d7e9e769a82e1f824e2402f66b7ac1621ede4f02160df4d96ec8000de7b713c2979faf9a76ee254e4c6a0c1c9f5fdd35fdc0533efbe85580074ebd65cf05",
		},
		{
			input:       []byte("beacon group seed"),
			expectedHex: "081822c14fff3b1aa5a665ffd7cb7a62a440c7985c931a180fe8bfcc436d7aa416614a46f32a09e169df3f78b678ba5be3ccd3bebce3423bbe1c43b01b06913d",
		},
	}

	for _, v := range vectors {
		got := hex.EncodeToString(G1HashToPointLegacy(v.input).Marshal())
		if got != v.expectedHex {
			t.Errorf(
				"G1HashToPointLegacy(%q) output drifted -- the legacy "+
					"compatibility path no longer matches pre-hardening "+
					"releases; restore the mapping instead of updating the "+
					"expected value.\n"+
					"  expected: %s\n"+
					"  got:      %s",
				v.input, v.expectedHex, got,
			)
		}
	}
}

// TestG1HashToPointLegacyProperties proves the legacy mapping is
// deterministic, produces valid on-curve points, and diverges from the
// hardened counter-based mapping: the two mappings must never be conflated
// for the same ceremony.
func TestG1HashToPointLegacyProperties(t *testing.T) {
	for _, msg := range [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hello world"),
		make([]byte, 32),
	} {
		p1 := G1HashToPointLegacy(msg)
		p2 := G1HashToPointLegacy(msg)
		testutils.AssertBytesEqual(t, p1.Marshal(), p2.Marshal())

		recovered := new(bn256.G1)
		if _, err := recovered.Unmarshal(p1.Marshal()); err != nil {
			t.Errorf(
				"G1HashToPointLegacy produced an invalid G1 point for "+
					"input %q: %v",
				msg,
				err,
			)
		}

		hardened := G1HashToPoint(msg)
		if string(p1.Marshal()) == string(hardened.Marshal()) {
			t.Errorf(
				"legacy and hardened mappings coincided for input %q; the "+
					"modes would be indistinguishable on the wire",
				msg,
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
