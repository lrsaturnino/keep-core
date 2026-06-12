package ethereum

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"pgregory.net/rapid"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
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
		redeemerBytes := rapid.SliceOfN(rapid.Byte(), 20, 20).Draw(t, "redeemer")

		// Draw raw script bytes and wrap them in the var-len encoding the
		// converter parses, so the script round-trips through
		// NewScriptFromVarLenData rather than failing on malformed input.
		scriptBytes := rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, "script")
		varLenScript, err := bitcoin.Script(scriptBytes).ToVarLenData()
		if err != nil {
			t.Fatalf("cannot var-len encode generated script: %v", err)
		}

		event := &tbtcabi.BridgeRedemptionRequested{
			WalletPubKeyHash:     [20]byte{0x01, 0x02, 0x03},
			RedeemerOutputScript: varLenScript,
			Redeemer:             common.BytesToAddress(redeemerBytes),
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
		if got.Redeemer != chain.Address(event.Redeemer.Hex()) {
			t.Fatalf(
				"Redeemer: got %s, want %s",
				got.Redeemer, event.Redeemer.Hex(),
			)
		}
		// The converted script must be the decoded payload of the var-len
		// data, i.e. exactly the raw bytes that were wrapped above.
		if !bytes.Equal(got.RedeemerOutputScript, scriptBytes) {
			t.Fatalf(
				"RedeemerOutputScript: got %x, want %x",
				got.RedeemerOutputScript, scriptBytes,
			)
		}
	})
}
