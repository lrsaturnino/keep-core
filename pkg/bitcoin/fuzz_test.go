package bitcoin

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Native coverage-guided fuzz targets for the pure deserializers that run on
// untrusted data fetched from external sources (an Electrum server). The
// invariant for every one of them is the same: arbitrary bytes must never
// cause a panic. Malformed input must be rejected with an error, not crash the
// process. Seeds include the valid examples used by the table-driven tests plus
// a few known malformed shapes; the fuzzer mutates from there.
//
// Seeds are decoded with the file-local fhex helper rather than the package's
// test-only decodeString: the OSS-Fuzz / ClusterFuzzLite native-fuzzing shim
// compiles each target from a generated non-test file, so a target may only
// reference symbols defined in this file or in non-test package code.
//
// Run locally with, e.g.:
//
//	go test ./pkg/bitcoin/ -run=^$ -fuzz=FuzzNewScriptFromVarLenData -fuzztime=60s
//
// Crashers are persisted under testdata/fuzz/<FuzzName>/ and become permanent
// regression cases on the next normal `go test` run.

// fhex decodes a hex string seed. It is intentionally defined in this file (not
// shared with other _test.go files) so the fuzz targets remain compilable by
// the native-fuzzing shim. Seeds are compile-time constants, so a decode error
// is a programming mistake and yields a nil seed.
func fhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// FuzzNewScriptFromVarLenData fuzzes the variable-length script parser. Beyond
// "never panics", it asserts a round-trip property: any byte slice that parses
// successfully must serialize back to exactly the input via ToVarLenData (the
// CompactSizeUint length prefix is canonical, so this must hold).
func FuzzNewScriptFromVarLenData(f *testing.F) {
	f.Add(fhex("1600148db50eb52063ea9d98b3eac91489a90f738986f6"))       // valid
	f.Add(fhex("16"))                                                   // missing script body
	f.Add(fhex("00148db50eb52063ea9d98b3eac91489a90f738986f6"))         // missing length prefix
	f.Add([]byte(nil))                                                  // empty
	f.Add([]byte{0xfd})                                                 // truncated multi-byte CompactSizeUint
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // huge declared length

	f.Fuzz(func(t *testing.T, data []byte) {
		script, err := NewScriptFromVarLenData(data)
		if err != nil {
			// Malformed input rejected cleanly: the expected outcome.
			return
		}

		// On success the parsed script must round-trip back to the input.
		roundTripped, err := script.ToVarLenData()
		if err != nil {
			t.Fatalf("ToVarLenData failed on a successfully parsed script: %v", err)
		}
		if !bytes.Equal(roundTripped, data) {
			t.Fatalf(
				"round-trip mismatch\n input: %x\n got:   %x",
				data,
				roundTripped,
			)
		}
	})
}

// FuzzTransactionDeserialize fuzzes the transaction deserializer, the entry
// point for untrusted transaction bytes returned by an Electrum server. It must
// never panic on arbitrary input; an error return is the correct rejection.
func FuzzTransactionDeserialize(f *testing.F) {
	// A complete, valid standard (non-witness) serialized transaction.
	f.Add(fhex(
		"01000000036896f9abcac13ce6bd2b80d125bedf997ff6330e999f2f60" +
			"5ea15ea542f2eaf80000000000ffffffffed0ae94da996c6f3b89dfe967675d" +
			"4808251db93e81022ae9e038d06f92efed400000000c948304502210092327d" +
			"dff69a2b8c7ae787c5d590a2f14586089e6339e942d56e82aa42052cd902204" +
			"c0d1700ba1ac617da27fee032a57937c9607f0187199ed3c46954df845643d7" +
			"012103989d253b17a6a0f41838b84ff0d20e8898f9d7b1a98f2564da4cc29dc" +
			"f8581d94c5c14934b98637ca318a4d6e7ca6ffd1690b8e77df6377508f9f0c9" +
			"0d000395237576a9148db50eb52063ea9d98b3eac91489a90f738986f68763a" +
			"c6776a914e257eccafbc07c381642ce6e7e55120fb077fbed8804e0250162b1" +
			"75ac68ffffffffe37f552fc23fa0032bfd00c8eef5f5c22bf85fe4c6e735857" +
			"719ff8a4ff66eb80000000000ffffffff0180ed0000000000001600148db50e" +
			"b52063ea9d98b3eac91489a90f738986f600000000",
	))
	f.Add([]byte(nil))                          // empty
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})       // version only, truncated
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0xff}) // version + oversized input count

	f.Fuzz(func(t *testing.T, data []byte) {
		var tx Transaction
		// Must not panic on arbitrary input; an error return is acceptable.
		_ = tx.Deserialize(data)
	})
}
