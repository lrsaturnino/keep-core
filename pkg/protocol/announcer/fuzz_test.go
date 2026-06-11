package announcer

// This fuzz target exercises the announcer announcementMessage unmarshaler,
// which parses bytes received from untrusted peers over the broadcast channel.
// The invariant under test is that Unmarshal never panics on arbitrary input:
// malformed bytes must return an error, not crash the process.

import "testing"

func FuzzAnnouncementMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic on arbitrary input; an error return is correct.
		_ = (&announcementMessage{}).Unmarshal(data)
	})
}
