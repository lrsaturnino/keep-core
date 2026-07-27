package beacon

import (
	"math"
	"testing"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	dkgResult "github.com/keep-network/keep-core/pkg/beacon/dkg/result"
	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
	"github.com/keep-network/keep-core/pkg/chain/ethereum"
)

// TestMaximumLegacyCompletionBlocks pins the derived in-flight completion
// bound against the configuration the production Ethereum beacon adapter
// actually supplies, so adapter drift fails this test, not only a changed
// literal. GetConfig reads no receiver state today; if that ever changes,
// this test fails loudly and the bound must be re-anchored deliberately.
func TestMaximumLegacyCompletionBlocks(t *testing.T) {
	config := (&ethereum.BeaconChain{}).GetConfig()

	maximum, err := MaximumLegacyCompletionBlocks(config)
	if err != nil {
		t.Fatalf("unexpected completion bound error: [%v]", err)
	}
	if maximum != 136 {
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
	maximum, err = MaximumLegacyCompletionBlocks(timeoutDominant)
	if err != nil {
		t.Fatalf("unexpected completion bound error: [%v]", err)
	}
	if maximum != 500 {
		t.Errorf(
			"expected the relay entry timeout [500] to dominate, got [%d]",
			maximum,
		)
	}
}

// TestMaximumLegacyCompletionBlocks_Validation proves the bound rejects a nil
// config, a non-positive group size, and arithmetic overflow instead of
// deriving a wrapped-around retention or quiescence deadline from them.
func TestMaximumLegacyCompletionBlocks_Validation(t *testing.T) {
	if _, err := MaximumLegacyCompletionBlocks(nil); err == nil {
		t.Error("expected a nil config rejection")
	}

	invalid := map[string]*beaconchain.Config{
		"zero group size": {
			GroupSize:                  0,
			ResultPublicationBlockStep: 1,
			RelayEntryTimeout:          64,
		},
		"negative group size": {
			GroupSize:                  -1,
			ResultPublicationBlockStep: 1,
			RelayEntryTimeout:          64,
		},
		"publication loop multiplication overflow": {
			GroupSize:                  2,
			ResultPublicationBlockStep: math.MaxUint64/2 + 1,
			RelayEntryTimeout:          64,
		},
		"completion bound addition overflow": {
			GroupSize:                  1,
			ResultPublicationBlockStep: math.MaxUint64 - 10,
			RelayEntryTimeout:          64,
		},
	}
	for name, config := range invalid {
		if _, err := MaximumLegacyCompletionBlocks(config); err == nil {
			t.Errorf("expected a rejection for %s", name)
		}
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

	// The production adapter inputs themselves are constituents: a changed
	// adapter configuration must re-trip the bound review even if the formula
	// is untouched.
	config := (&ethereum.BeaconChain{}).GetConfig()
	if config.GroupSize != 64 ||
		config.ResultPublicationBlockStep != 1 ||
		config.RelayEntryTimeout != 64 {
		t.Errorf(
			"Ethereum beacon adapter configuration changed: got group size "+
				"[%d], publication step [%d], relay entry timeout [%d]; "+
				"re-review the maximum legacy completion bound",
			config.GroupSize,
			config.ResultPublicationBlockStep,
			config.RelayEntryTimeout,
		)
	}
}
