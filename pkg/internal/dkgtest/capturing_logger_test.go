package dkgtest

import "testing"

// TestCapturingLoggerAndGapDetection proves the F-008 corroboration machinery
// has teeth: the capturing logger records Errorf (and discards other levels),
// and reconstructionGapErrors matches the real guard-message format while
// rejecting unrelated errors. Without this, AssertNoReconstructionGap could be
// vacuously green if the plumbing silently dropped messages.
func TestCapturingLoggerAndGapDetection(t *testing.T) {
	l := newCapturingLogger()

	// Non-Errorf levels are discarded (inherited MockLogger no-ops).
	l.Infof("info %d", 1)
	l.Warnf("warn %d", 2)
	if got := len(l.snapshot()); got != 0 {
		t.Fatalf("non-error levels should be discarded; captured %d", got)
	}

	// Errorf is captured, formatted. This mirrors the guard message emitted by
	// gjkr.ComputeGroupPublicKeyShares (protocol.go); keep the marker in sync if
	// that log is reworded.
	l.Errorf(
		"[member:%v] missing revealed share for operating member [%v] from "+
			"misbehaved member [%v]; skipping term (unexpected per DKG invariants)",
		1, 2, 3,
	)
	captured := l.snapshot()
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured Errorf, got %d: %v", len(captured), captured)
	}

	// Positive: the guard message is detected as a reconstruction gap.
	withGap := &Result{loggedErrors: captured}
	if hits := reconstructionGapErrors(withGap); len(hits) != 1 {
		t.Errorf("expected the guard message to be detected; got %d hits", len(hits))
	}

	// Negative: an unrelated error is not a false positive.
	noGap := &Result{loggedErrors: []string{"[member:1] some unrelated error"}}
	if hits := reconstructionGapErrors(noGap); len(hits) != 0 {
		t.Errorf("unrelated error must not be flagged as a gap; got %v", hits)
	}
}
