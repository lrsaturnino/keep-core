package tbtc

import (
	"encoding/hex"
	"testing"

	"github.com/keep-network/keep-core/pkg/bitcoin"
)

// TestDecodeSignerAuditRecord proves the audit decode accepts exactly what
// the registry loader accepts and reports the identity the loader would use
// for its wallet cache, including a wallet ID byte-identical to the chain's
// own derivation.
func TestDecodeSignerAuditRecord(t *testing.T) {
	signer := createMockSigner(t)

	signerBytes, err := signer.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	record, err := DecodeSignerAuditRecord(signerBytes)
	if err != nil {
		t.Fatalf("unexpected decode error: [%v]", err)
	}

	expectedKey := getWalletStorageKey(signer.wallet.publicKey)
	if record.WalletStorageKey != expectedKey {
		t.Errorf(
			"expected wallet storage key [%s], got [%s]",
			expectedKey,
			record.WalletStorageKey,
		)
	}

	chainWalletID, err := Connect().CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if expected := hex.EncodeToString(
		chainWalletID[:],
	); record.WalletID != expected {
		t.Errorf(
			"expected wallet ID [%s], got [%s]",
			expected,
			record.WalletID,
		)
	}

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	if expected := hex.EncodeToString(
		walletPublicKeyHash[:],
	); record.WalletPublicKeyHash != expected {
		t.Errorf(
			"expected wallet public key hash [%s], got [%s]",
			expected,
			record.WalletPublicKeyHash,
		)
	}
	if record.MemberIndex != signer.signingGroupMemberIndex {
		t.Errorf(
			"expected member index [%d], got [%d]",
			signer.signingGroupMemberIndex,
			record.MemberIndex,
		)
	}
	if record.SigningGroupSize != len(signer.wallet.signingGroupOperators) {
		t.Errorf(
			"expected signing group size [%d], got [%d]",
			len(signer.wallet.signingGroupOperators),
			record.SigningGroupSize,
		)
	}
}

// TestDecodeSignerAuditRecord_RejectsUndecodableRecord proves a record the
// registry loader would reject is reported as an error, not misclassified.
func TestDecodeSignerAuditRecord_RejectsUndecodableRecord(t *testing.T) {
	if _, err := DecodeSignerAuditRecord([]byte("not a signer record")); err == nil {
		t.Error("expected a decode error for an undecodable record")
	}
}
