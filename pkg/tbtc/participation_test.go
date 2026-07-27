package tbtc

import "testing"

// TestMaximumLegacyCompletionBlocks pins the derived in-flight completion
// bound. The dominant constituent is the deposit sweep proposal validity.
func TestMaximumLegacyCompletionBlocks(t *testing.T) {
	if maximum := MaximumLegacyCompletionBlocks(); maximum != 1200 {
		t.Errorf(
			"expected maximum legacy completion bound [1200], got [%d]",
			maximum,
		)
	}
}

// TestCutoverPeerRosterRetentionBlocks pins the derived roster retention: the
// maximum legacy completion bound plus the reviewed margin. A different value
// means the retention review must be redone deliberately, not that this test
// should be updated casually.
func TestCutoverPeerRosterRetentionBlocks(t *testing.T) {
	retention, err := CutoverPeerRosterRetentionBlocks()
	if err != nil {
		t.Fatalf("unexpected retention derivation error: [%v]", err)
	}
	if retention != 1500 {
		t.Errorf("expected roster retention [1500], got [%d]", retention)
	}
	if cutoverPeerRosterRetentionMarginBlocks != 300 {
		t.Errorf(
			"reviewed retention margin changed: expected [300], got [%d]; "+
				"re-review the roster retention derivation",
			cutoverPeerRosterRetentionMarginBlocks,
		)
	}
}

// TestMaximumLegacyCompletionBlocksConstituents is a drift test: it fails when
// any constituent protocol constant changes without the completion bound —
// and everything derived from it, such as roster retention and rollback
// quiescence deadlines — being deliberately re-reviewed.
func TestMaximumLegacyCompletionBlocksConstituents(t *testing.T) {
	constituents := map[string]struct {
		actual   uint64
		expected uint64
	}{
		"dkg retry loop": {
			uint64(dkgAttemptsLimit) * uint64(dkgAttemptMaximumBlocks()),
			216,
		},
		"signing retry loop": {
			uint64(signingAttemptsLimit) * uint64(signingAttemptMaximumBlocks()),
			205,
		},
		"coordination window": {coordinationDurationBlocks, 100},
		"heartbeat proposal validity": {
			heartbeatTotalProposalValidityBlocks,
			600,
		},
		"deposit sweep proposal validity": {
			depositSweepProposalValidityBlocks,
			1200,
		},
		"redemption proposal validity": {redemptionProposalValidityBlocks, 600},
		"moving funds proposal validity": {
			movingFundsProposalValidityBlocks,
			650,
		},
		"moved funds sweep proposal validity": {
			movedFundsSweepProposalValidityBlocks,
			600,
		},
	}

	for name, constituent := range constituents {
		if constituent.actual != constituent.expected {
			t.Errorf(
				"%s changed: expected [%d] blocks, got [%d]; re-review the "+
					"maximum legacy completion bound and its derived values",
				name,
				constituent.expected,
				constituent.actual,
			)
		}
	}
}
