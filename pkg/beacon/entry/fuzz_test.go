package entry

// Fuzz target for the network-message protobuf unmarshaler in this package.
// Asserts that Unmarshal never panics on arbitrary bytes: malformed input must
// return an error, not crash.

import "testing"

func FuzzSignatureShareMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&SignatureShareMessage{}).Unmarshal(data)
	})
}
