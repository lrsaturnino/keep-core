package tbtc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/pkg/bitcoin"
)

// QuarantineSchemaVersion versions the quarantined-signer metadata document
// for the offline state-audit tooling.
const QuarantineSchemaVersion uint32 = 1

// QuarantinedSignerMetadata describes one quarantined tBTC signer output for
// the offline state audit, without any private material: the key share itself
// stays only inside the encrypted membership record it accompanies. The seed
// is recorded as a hash, never raw.
type QuarantinedSignerMetadata struct {
	SchemaVersion       uint32    `json:"schema_version"`
	ReleaseEpoch        string    `json:"release_epoch"`
	ProtocolMode        string    `json:"protocol_mode"`
	CutoverBlock        uint64    `json:"cutover_block"`
	CanonicalStartBlock uint64    `json:"canonical_start_block"`
	Ceremony            string    `json:"ceremony"`
	SeedHash            string    `json:"seed_hash"`
	MemberIndex         uint8     `json:"member_index"`
	WalletID            string    `json:"wallet_id"`
	WalletPublicKeyHash string    `json:"wallet_public_key_hash"`
	FailedOperation     string    `json:"failed_operation"`
	LastObservedBlock   uint64    `json:"last_observed_block"`
	PreservedAt         time.Time `json:"preserved_at"`
}

// signerQuarantine preserves tBTC signer outputs whose activation the
// participation gate refused — clock failure, forced quiescence, or a refused
// commit fence — before the wallet's on-chain registration was proven. The
// handle MUST be rooted in a dedicated protected namespace that no release's
// active-wallet scan reads: quarantined records use the same membership
// encoding as active ones, so placing them beside active membership files
// would make a prior binary load them as active signers, which is not
// rollback-safe. Quarantined material is recovery evidence for the offline
// state audit; it is never activated by the running process.
type signerQuarantine struct {
	logger log.StandardLogger
	handle persistence.ProtectedHandle
}

// newSignerQuarantine creates a quarantine store over the given protected
// handle.
func newSignerQuarantine(
	logger log.StandardLogger,
	handle persistence.ProtectedHandle,
) *signerQuarantine {
	return &signerQuarantine{
		logger: logger,
		handle: handle,
	}
}

// preserve durably saves the signer membership and its audit metadata under
// the quarantine namespace, mirroring the active storage layout so the same
// decoding path can interpret both. Preservation failure is surfaced to the
// caller: losing generated key material is a protocol violation, so the
// caller must log it unsuppressed.
func (q *signerQuarantine) preserve(
	signer *signer,
	metadata QuarantinedSignerMetadata,
) error {
	signerBytes, err := signer.Marshal()
	if err != nil {
		return fmt.Errorf(
			"could not marshal the quarantined signer: [%v]",
			err,
		)
	}

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)

	metadata.SchemaVersion = QuarantineSchemaVersion
	metadata.MemberIndex = uint8(signer.signingGroupMemberIndex)
	metadata.WalletPublicKeyHash = hex.EncodeToString(walletPublicKeyHash[:])
	metadata.PreservedAt = time.Now().UTC()

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf(
			"could not marshal the quarantine metadata: [%v]",
			err,
		)
	}

	directory := getWalletStorageKey(signer.wallet.publicKey)
	memberSuffix := fmt.Sprint(signer.signingGroupMemberIndex)

	if err := q.handle.Save(
		signerBytes,
		directory,
		"/membership_"+memberSuffix,
	); err != nil {
		return fmt.Errorf(
			"could not persist the quarantined signer: [%v]",
			err,
		)
	}

	if err := q.handle.Save(
		metadataBytes,
		directory,
		"/metadata_"+memberSuffix,
	); err != nil {
		return fmt.Errorf(
			"could not persist the quarantine metadata: [%v]",
			err,
		)
	}

	q.logger.Warnf(
		"quarantined a tbtc signer output [walletPKH=0x%s] [member=%v] "+
			"[mode=%s] [canonicalStartBlock=%d] [failedOperation=%s] "+
			"[lastObservedBlock=%d]",
		metadata.WalletPublicKeyHash,
		signer.signingGroupMemberIndex,
		metadata.ProtocolMode,
		metadata.CanonicalStartBlock,
		metadata.FailedOperation,
		metadata.LastObservedBlock,
	)

	return nil
}
