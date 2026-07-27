package tbtc

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/internal/byteutils"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// SignerAuditRecord is the non-secret identity of one persisted wallet signer
// record, decoded for the offline participation state audit.
type SignerAuditRecord struct {
	// WalletStorageKey identifies the wallet the signer belongs to. It is the
	// directory name the wallet registry stores the record under, derived
	// from the wallet public key.
	WalletStorageKey string
	// WalletID is the hex-encoded 32-byte ECDSA wallet ID derived from the
	// record's wallet public key, computed the same way the on-chain wallet
	// registry derives it. It lets the offline audit match a decoded record
	// against chain reconciliation evidence without any chain access.
	WalletID string
	// WalletPublicKeyHash is the hex-encoded 20-byte Bitcoin public key hash
	// of the record's wallet public key.
	WalletPublicKeyHash string
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

	walletPublicKey := signer.wallet.publicKey

	// The offline audit runs without a chain connection, so the wallet ID is
	// derived locally: the keccak256 of the 64-byte chain-format public key,
	// exactly the derivation the chain's CalculateWalletID performs.
	x, err := byteutils.LeftPadTo32Bytes(walletPublicKey.X.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cannot derive the wallet ID: [%v]", err)
	}
	y, err := byteutils.LeftPadTo32Bytes(walletPublicKey.Y.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cannot derive the wallet ID: [%v]", err)
	}
	walletID := crypto.Keccak256Hash(append(x, y...))

	walletPublicKeyHash := bitcoin.PublicKeyHash(walletPublicKey)

	return &SignerAuditRecord{
		WalletStorageKey:    getWalletStorageKey(walletPublicKey),
		WalletID:            hex.EncodeToString(walletID[:]),
		WalletPublicKeyHash: hex.EncodeToString(walletPublicKeyHash[:]),
		MemberIndex:         signer.signingGroupMemberIndex,
		SigningGroupSize:    len(signer.wallet.signingGroupOperators),
	}, nil
}
