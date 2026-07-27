package tbtc

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
