package beacon

import (
	"testing"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	dkgResult "github.com/keep-network/keep-core/pkg/beacon/dkg/result"
	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
)

// TestMaximumLegacyCompletionBlocks pins the derived in-flight completion
// bound for the current Ethereum beacon configuration (group size 64,
// publication step 1, relay entry timeout 64): the full DKG duration
// dominates the relay entry timeout.
func TestMaximumLegacyCompletionBlocks(t *testing.T) {
	config := &beaconchain.Config{
		GroupSize:                  64,
		ResultPublicationBlockStep: 1,
		RelayEntryTimeout:          64,
	}

	if maximum := MaximumLegacyCompletionBlocks(config); maximum != 136 {
		t.Errorf(
			"expected maximum legacy completion bound [136], got [%d]",
			maximum,
		)
	}

	// A configuration with a dominant relay entry timeout must return it.
	timeoutDominant := &beaconchain.Config{
		GroupSize:                  64,
		ResultPublicationBlockStep: 1,
		RelayEntryTimeout:          500,
	}
	if maximum := MaximumLegacyCompletionBlocks(timeoutDominant); maximum != 500 {
		t.Errorf(
			"expected the relay entry timeout [500] to dominate, got [%d]",
			maximum,
		)
	}
}

// TestMaximumLegacyCompletionBlocksConstituents is a drift test: it fails when
// a GJKR or result-publication protocol constant changes without the
// completion bound — and everything derived from it, such as roster retention
// and rollback quiescence deadlines — being deliberately re-reviewed.
func TestMaximumLegacyCompletionBlocksConstituents(t *testing.T) {
	if blocks := gjkr.ProtocolBlocks(); blocks != 66 {
		t.Errorf(
			"GJKR protocol duration changed: expected [66] blocks, got [%d]; "+
				"re-review the maximum legacy completion bound",
			blocks,
		)
	}
	if blocks := dkgResult.PrePublicationBlocks(); blocks != 6 {
		t.Errorf(
			"result pre-publication duration changed: expected [6] blocks, "+
				"got [%d]; re-review the maximum legacy completion bound",
			blocks,
		)
	}
}
