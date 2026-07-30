package tbtc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/protocol/group"
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

// quarantinedSigner names one preserved signer output by the wallet it belongs
// to and the seat it was generated for — the pair an active signer is also
// identified by, so the two namespaces can be compared without decoding either
// side's key material.
type quarantinedSigner struct {
	walletStorageKey string
	memberIndex      group.MemberIndex
}

// preservedOutputs lists the signer outputs currently held in the quarantine
// namespace.
//
// Only the membership records are counted. Each preserved output writes a
// membership beside its audit metadata, and counting both would report every
// output twice; the membership is the output itself, so it is the one that
// decides. Nothing here reads a record's content: the pair identifying an
// output is carried by the wallet directory and the membership name, and the
// share inside stays encrypted and unread.
//
// A namespace that cannot be enumerated returns an error rather than a short
// list. The count exists to say how much preserved material a rollback still
// has to account for, and a truncated one reads as an all-clear — the single
// answer this must never invent.
func (q *signerQuarantine) preservedOutputs() ([]quarantinedSigner, error) {
	descriptorsChan, errorsChan := q.handle.ReadAll()

	// The descriptor and error channels are unbuffered and written to in an
	// order this side cannot predict, so both are drained concurrently. This
	// mirrors the active wallet storage scan.
	var wg sync.WaitGroup
	wg.Add(2)

	var outputs []quarantinedSigner
	go func() {
		defer wg.Done()
		for descriptor := range descriptorsChan {
			memberIndex, ok := quarantinedMemberIndex(descriptor.Name())
			if !ok {
				continue
			}
			outputs = append(outputs, quarantinedSigner{
				walletStorageKey: descriptor.Directory(),
				memberIndex:      memberIndex,
			})
		}
	}()

	var readErrs []error
	go func() {
		defer wg.Done()
		for err := range errorsChan {
			readErrs = append(readErrs, err)
		}
	}()

	wg.Wait()

	if len(readErrs) > 0 {
		return nil, fmt.Errorf(
			"could not enumerate the signer quarantine namespace: %w",
			errors.Join(readErrs...),
		)
	}

	return outputs, nil
}

// quarantinedMemberIndex reads the seat a preserved membership record was
// written for out of its name, reporting whether the name is one at all.
//
// The name is this package's own: preserve writes "membership_<seat>" beside
// "metadata_<seat>". Anything else in the namespace — the metadata documents, a
// name a later schema adds, an operator's stray file — is not a signer output
// and is not counted as one.
//
// A leading separator is tolerated because the name is written with one and not
// every handle hands it back the same way: the disk implementation joins it into
// a path and enumerates the bare file name, while a handle that keeps what it
// was given returns the name as this package wrote it. Both spell the same
// record, so neither is allowed to decide whether it counts.
func quarantinedMemberIndex(name string) (group.MemberIndex, bool) {
	const prefix = "membership_"

	suffix, found := strings.CutPrefix(strings.TrimPrefix(name, "/"), prefix)
	if !found {
		return 0, false
	}

	seat, err := strconv.ParseUint(suffix, 10, 8)
	if err != nil || seat == 0 {
		return 0, false
	}

	return group.MemberIndex(seat), true
}
