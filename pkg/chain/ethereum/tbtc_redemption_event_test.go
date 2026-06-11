package ethereum

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"

	tbtcabi "github.com/keep-network/keep-core/pkg/chain/ethereum/tbtc/gen/abi"
)

// TestConvertRedemptionRequestedEvent is regression coverage for the
// security-audit finding F-014: the RedemptionRequested event conversion
// mapped TxMaxFee from event.TreasuryFee (a copy-paste defect). TreasuryFee
// and TxMaxFee are distinct fee bounds and must each map from their own
// source field.
//
// The test uses deliberately distinct TreasuryFee and TxMaxFee values so the
// previous (buggy) mapping returns the wrong TxMaxFee and the test fails
// against the unpatched code.
func TestConvertRedemptionRequestedEvent(t *testing.T) {
	event := &tbtcabi.BridgeRedemptionRequested{
		WalletPubKeyHash:     [20]byte{0x01, 0x02, 0x03},
		RedeemerOutputScript: []byte{0x01, 0xaa}, // var-len: 1-byte script
		Redeemer:             common.HexToAddress("0x1111111111111111111111111111111111111111"),
		RequestedAmount:      1000,
		TreasuryFee:          100,
		TxMaxFee:             7, // intentionally distinct from TreasuryFee
	}

	converted, err := convertRedemptionRequestedEvent(event)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}

	if converted.TreasuryFee != event.TreasuryFee {
		t.Errorf(
			"wrong TreasuryFee\nexpected: %v\nactual:   %v",
			event.TreasuryFee,
			converted.TreasuryFee,
		)
	}

	if converted.TxMaxFee != event.TxMaxFee {
		t.Errorf(
			"wrong TxMaxFee (must map from event.TxMaxFee, not event.TreasuryFee)"+
				"\nexpected: %v\nactual:   %v",
			event.TxMaxFee,
			converted.TxMaxFee,
		)
	}

	if converted.RequestedAmount != event.RequestedAmount {
		t.Errorf(
			"wrong RequestedAmount\nexpected: %v\nactual:   %v",
			event.RequestedAmount,
			converted.RequestedAmount,
		)
	}
}
