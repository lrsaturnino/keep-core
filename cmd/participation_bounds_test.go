package cmd

import (
	"testing"

	"github.com/keep-network/keep-core/pkg/beacon"
	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/tbtc"
)

// TestMaximumLegacyCompletionBlocksAcrossProtocols is the cross-package drift
// assertion for the combined in-flight completion bound: the starting input
// for quiesce deadlines, roster retention, and the release-manifest grace
// derivation. It fails when either protocol's bound moves without those
// derived values being deliberately re-reviewed.
func TestMaximumLegacyCompletionBlocksAcrossProtocols(t *testing.T) {
	tbtcBound := tbtc.MaximumLegacyCompletionBlocks()
	beaconBound := beacon.MaximumLegacyCompletionBlocks(&beaconchain.Config{
		GroupSize:                  64,
		ResultPublicationBlockStep: 1,
		RelayEntryTimeout:          64,
	})

	combined := tbtcBound
	if beaconBound > combined {
		combined = beaconBound
	}

	if tbtcBound != 1200 {
		t.Errorf("tBTC completion bound changed: expected [1200], got [%d]", tbtcBound)
	}
	if beaconBound != 136 {
		t.Errorf("beacon completion bound changed: expected [136], got [%d]", beaconBound)
	}
	if combined != 1200 {
		t.Errorf("combined completion bound changed: expected [1200], got [%d]", combined)
	}
}
