package dkg

// Native coverage-guided fuzz targets for the network-message protobuf
// unmarshalers in this package. Each target asserts that Unmarshal never
// panics on arbitrary bytes; a non-nil error on malformed input is fine.
// PreParams is intentionally excluded: it is local key material loaded from
// the operator's own disk, not untrusted network input.

import "testing"

func FuzzEphemeralPublicKeyMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&ephemeralPublicKeyMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundOneMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundOneMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundTwoMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundTwoMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundThreeMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundThreeMessage{}).Unmarshal(data)
	})
}

func FuzzTssFinalizationMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssFinalizationMessage{}).Unmarshal(data)
	})
}

func FuzzResultSignatureMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&resultSignatureMessage{}).Unmarshal(data)
	})
}
