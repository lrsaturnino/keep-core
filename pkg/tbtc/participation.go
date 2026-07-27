package tbtc

import (
	"fmt"
	"math"
)

// MaximumLegacyCompletionBlocks returns the maximum number of Ethereum blocks
// that any already-started tBTC protocol work may legitimately need to reach
// its natural completion: the largest of the DKG and signing retry-loop
// bounds, the coordination window, and every wallet-action proposal validity.
//
// The bound sizes cutover-rehearsal timing, local straggler-roster retention,
// graceful rollback quiescence, and alerts about unexpectedly long legacy
// overlap after the protocol cutover block. It is deliberately not an
// activation height and must never gate new work; each protocol's existing
// validity context remains the hard end of any in-flight grace behavior.
func MaximumLegacyCompletionBlocks() uint64 {
	bounds := []uint64{
		uint64(dkgAttemptsLimit) * uint64(dkgAttemptMaximumBlocks()),
		uint64(signingAttemptsLimit) * uint64(signingAttemptMaximumBlocks()),
		coordinationDurationBlocks,
		heartbeatTotalProposalValidityBlocks,
		depositSweepProposalValidityBlocks,
		redemptionProposalValidityBlocks,
		movingFundsProposalValidityBlocks,
		movedFundsSweepProposalValidityBlocks,
	}

	maximum := uint64(0)
	for _, bound := range bounds {
		if bound > maximum {
			maximum = bound
		}
	}
	return maximum
}

// cutoverPeerRosterRetentionMarginBlocks is the reviewed margin added to the
// maximum legacy completion bound when deriving the cutover peer roster
// retention: it covers RPC and processing skew beyond the longest in-flight
// work bound.
const cutoverPeerRosterRetentionMarginBlocks = uint64(300)

// cutoverPeerRosterRetentionBlocks derives how long a legacy peer sighting is
// retained without a fresh observation before it is evicted as "not recently
// observed": the maximum number of blocks any already-started tBTC work may
// legitimately still be running, plus the reviewed margin. Deriving from the
// completion bound keeps retention in lockstep with the protocol validity
// windows; the addition is overflow-checked because the retention feeds the
// roster's gauge projection and eviction arithmetic.
func cutoverPeerRosterRetentionBlocks() (uint64, error) {
	bound := MaximumLegacyCompletionBlocks()
	if bound > math.MaxUint64-cutoverPeerRosterRetentionMarginBlocks {
		return 0, fmt.Errorf(
			"cutover peer roster retention overflows: completion bound [%d] "+
				"plus margin [%d]",
			bound,
			cutoverPeerRosterRetentionMarginBlocks,
		)
	}
	return bound + cutoverPeerRosterRetentionMarginBlocks, nil
}
