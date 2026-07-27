package beacon

import (
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
func MaximumLegacyCompletionBlocks(config *beaconchain.Config) uint64 {
	dkgBlocks := gjkr.ProtocolBlocks() +
		dkgResult.PrePublicationBlocks() +
		uint64(config.GroupSize)*config.ResultPublicationBlockStep

	if config.RelayEntryTimeout > dkgBlocks {
		return config.RelayEntryTimeout
	}
	return dkgBlocks
}
