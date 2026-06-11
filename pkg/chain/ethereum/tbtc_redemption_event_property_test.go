package ethereum

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"pgregory.net/rapid"

	tbtcabi "github.com/keep-network/keep-core/pkg/chain/ethereum/tbtc/gen/abi"
)

// Property-based (adapter) coverage for security-audit finding F-014: the
// RedemptionRequested event conversion must map each scalar field from its own
// source field. The original defect mapped TxMaxFee from event.TreasuryFee.
//
// TestConvertRedemptionRequestedEvent (the table test) pins one distinct-fee
// case; this property generalizes it: for arbitrary field values the converted
// event must reproduce every source field exactly. rapid will readily generate
// inputs where TreasuryFee != TxMaxFee, so any reintroduced cross-wiring of the
// two (or of any other scalar) is caught.
func TestRapidConvertRedemptionRequestedEventFieldMapping(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requestedAmount := rapid.Uint64().Draw(t, "requestedAmount")
		treasuryFee := rapid.Uint64().Draw(t, "treasuryFee")
		txMaxFee := rapid.Uint64().Draw(t, "txMaxFee")
		blockNumber := rapid.Uint64().Draw(t, "blockNumber")

		event := &tbtcabi.BridgeRedemptionRequested{
			WalletPubKeyHash: [20]byte{0x01, 0x02, 0x03},
			// Constant, valid variable-length script (1-byte CompactSizeUint
			// prefix + 1 script byte); script parsing is covered elsewhere.
			RedeemerOutputScript: []byte{0x01, 0xaa},
			Redeemer:             common.HexToAddress("0x1111111111111111111111111111111111111111"),
			RequestedAmount:      requestedAmount,
			TreasuryFee:          treasuryFee,
			TxMaxFee:             txMaxFee,
		}
		event.Raw.BlockNumber = blockNumber

		got, err := convertRedemptionRequestedEvent(event)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got.RequestedAmount != requestedAmount {
			t.Fatalf("RequestedAmount: got %d, want %d", got.RequestedAmount, requestedAmount)
		}
		if got.TreasuryFee != treasuryFee {
			t.Fatalf("TreasuryFee: got %d, want %d", got.TreasuryFee, treasuryFee)
		}
		// The F-014 invariant: TxMaxFee must come from event.TxMaxFee, never
		// from event.TreasuryFee.
		if got.TxMaxFee != txMaxFee {
			t.Fatalf(
				"TxMaxFee: got %d, want %d (must map from event.TxMaxFee, not TreasuryFee=%d)",
				got.TxMaxFee, txMaxFee, treasuryFee,
			)
		}
		if got.BlockNumber != blockNumber {
			t.Fatalf("BlockNumber: got %d, want %d", got.BlockNumber, blockNumber)
		}
		if got.WalletPublicKeyHash != event.WalletPubKeyHash {
			t.Fatalf("WalletPublicKeyHash mismatch")
		}
	})
}
