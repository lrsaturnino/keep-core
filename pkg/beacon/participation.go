package beacon

import (
	"fmt"
	"math"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	dkgResult "github.com/keep-network/keep-core/pkg/beacon/dkg/result"
	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
)

// MaximumLegacyCompletionBlocks returns the maximum number of Ethereum blocks
// that any already-started random beacon protocol work may legitimately need
// to reach its natural completion: the larger of the full DKG duration — GJKR
// protocol states, pre-publication result signing, and the worst-case
// publication loop over all group members — and the on-chain relay entry
// timeout.
//
// The bound sizes cutover-rehearsal timing, local straggler-roster retention,
// graceful rollback quiescence, and alerts about unexpectedly long legacy
// overlap after the protocol cutover block. It is deliberately not an
// activation height and must never gate new work; each protocol's existing
// validity context remains the hard end of any in-flight grace behavior.
//
// The configuration is chain-supplied at runtime, so a nil config, a
// non-positive group size, and arithmetic overflow are rejected instead of
// silently producing a wrapped-around retention or quiescence deadline.
func MaximumLegacyCompletionBlocks(config *beaconchain.Config) (uint64, error) {
	if config == nil {
		return 0, fmt.Errorf(
			"cannot derive the completion bound: beacon chain config is nil",
		)
	}
	if config.GroupSize <= 0 {
		return 0, fmt.Errorf(
			"cannot derive the completion bound: beacon group size [%d] "+
				"must be positive",
			config.GroupSize,
		)
	}

	groupSize := uint64(config.GroupSize)
	if config.ResultPublicationBlockStep != 0 &&
		groupSize > math.MaxUint64/config.ResultPublicationBlockStep {
		return 0, fmt.Errorf(
			"cannot derive the completion bound: publication loop of group "+
				"size [%d] times publication block step [%d] overflows",
			config.GroupSize,
			config.ResultPublicationBlockStep,
		)
	}
	publicationBlocks := groupSize * config.ResultPublicationBlockStep

	fixedBlocks := gjkr.ProtocolBlocks() + dkgResult.PrePublicationBlocks()
	if publicationBlocks > math.MaxUint64-fixedBlocks {
		return 0, fmt.Errorf(
			"cannot derive the completion bound: fixed DKG duration [%d] "+
				"plus publication loop [%d] blocks overflows",
			fixedBlocks,
			publicationBlocks,
		)
	}
	dkgBlocks := fixedBlocks + publicationBlocks

	if config.RelayEntryTimeout > dkgBlocks {
		return config.RelayEntryTimeout, nil
	}
	return dkgBlocks, nil
}
