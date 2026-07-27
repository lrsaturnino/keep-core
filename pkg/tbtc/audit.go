package tbtc

import (
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// SignerAuditRecord is the non-secret identity of one persisted wallet signer
// record, decoded for the offline participation state audit.
type SignerAuditRecord struct {
	// WalletStorageKey identifies the wallet the signer belongs to. It is the
	// directory name the wallet registry stores the record under, derived
	// from the wallet public key.
	WalletStorageKey string
	// MemberIndex is the signer's index within the wallet signing group.
	MemberIndex group.MemberIndex
	// SigningGroupSize is the size of the wallet signing group the record
	// carries.
	SigningGroupSize int
}

// DecodeSignerAuditRecord decodes a persisted wallet signer record exactly
// the way the registry's own loader does — the decode any release's active
// scan must survive — and returns only its non-secret identity fields. The
// private key share is decoded to prove the record parses in full but never
// leaves this function.
func DecodeSignerAuditRecord(recordBytes []byte) (*SignerAuditRecord, error) {
	signer := &signer{}
	if err := signer.Unmarshal(recordBytes); err != nil {
		return nil, err
	}

	return &SignerAuditRecord{
		WalletStorageKey: getWalletStorageKey(signer.wallet.publicKey),
		MemberIndex:      signer.signingGroupMemberIndex,
		SigningGroupSize: len(signer.wallet.signingGroupOperators),
	}, nil
}
