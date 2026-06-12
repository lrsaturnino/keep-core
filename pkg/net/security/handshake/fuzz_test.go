package handshake

// These fuzz targets exercise the handshake message unmarshalers, which parse
// bytes received from untrusted peers during the connection handshake. The
// invariant under test is that Unmarshal never panics on arbitrary input:
// malformed bytes must return an error, not crash the process.

import "testing"

func FuzzAct1MessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic on arbitrary input; an error return is correct.
		_ = (&Act1Message{}).Unmarshal(data)
	})
}

func FuzzAct2MessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic on arbitrary input; an error return is correct.
		_ = (&Act2Message{}).Unmarshal(data)
	})
}

func FuzzAct3MessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic on arbitrary input; an error return is correct.
		_ = (&Act3Message{}).Unmarshal(data)
	})
}
