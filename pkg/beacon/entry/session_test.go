package entry

import "testing"

// TestShareSessionID holds the session a signature share is filtered by to the
// encoding a mixed-release group agrees on.
//
// The session ID leaves the node. A peer running the prior release derives it
// from the same previous entry with the same encoding and drops a share carrying
// anything else, so this is a wire contract rather than an internal naming
// choice: changing what goes into it — salting it with the relay request anchor
// to bind a share to one request, or rendering the bytes another way —
// partitions a mixed group into two sessions whose shares never combine. The
// expected value here is written out rather than derived, so that such a change
// fails this test instead of following it.
func TestShareSessionID(t *testing.T) {
	previousEntry := []byte{0x0a, 0xff, 0x10, 0x00}
	expected := "0aff1000"

	if sessionID := shareSessionID(previousEntry); sessionID != expected {
		t.Errorf(
			"unexpected session ID\nexpected: [%v]\nactual:   [%v]",
			expected,
			sessionID,
		)
	}

	// Two requests are one session exactly when the value being signed is the
	// same. That is what lets a share of one request combine into another over
	// the same previous entry — the reason a recovered entry's population
	// attributes seats to the entry rather than to the request — and what keeps
	// a share from crossing between requests over different previous entries.
	otherEntry := []byte{0x0a, 0xff, 0x10, 0x01}

	if shareSessionID(previousEntry) == shareSessionID(otherEntry) {
		t.Errorf(
			"distinct previous entries share the session [%v]",
			shareSessionID(previousEntry),
		)
	}
}
