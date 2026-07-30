package registry

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ipfs/go-log"

	"github.com/keep-network/keep-common/pkg/persistence"
)

// QuarantineSchemaVersion versions the quarantined-signer metadata document
// for the offline state-audit tooling.
const QuarantineSchemaVersion uint32 = 1

// QuarantinedSignerMetadata describes one quarantined signer output for the
// offline state audit, without any private material: the key share itself
// stays only inside the encrypted membership record it accompanies.
type QuarantinedSignerMetadata struct {
	SchemaVersion       uint32    `json:"schema_version"`
	ReleaseEpoch        string    `json:"release_epoch"`
	ProtocolMode        string    `json:"protocol_mode"`
	CutoverBlock        uint64    `json:"cutover_block"`
	CanonicalStartBlock uint64    `json:"canonical_start_block"`
	Ceremony            string    `json:"ceremony"`
	SeedHash            string    `json:"seed_hash"`
	MemberIndex         uint8     `json:"member_index"`
	GroupPublicKey      string    `json:"group_public_key"`
	FailedOperation     string    `json:"failed_operation"`
	LastObservedBlock   uint64    `json:"last_observed_block"`
	PreservedAt         time.Time `json:"preserved_at"`
}

// Quarantine preserves signer outputs whose completion the participation gate
// interrupted — clock failure, forced quiescence, or a refused commit fence —
// before an accepted on-chain publication was observed. The handle MUST be
// rooted in a dedicated protected namespace that no release's active-group
// scan reads: quarantined records use the same membership encoding as active
// ones, so placing them beside active membership files would make a prior
// binary load them as active signers, which is not rollback-safe. Quarantined
// material is recovery evidence for the offline state audit; it is never
// activated by the running process.
type Quarantine struct {
	logger log.StandardLogger
	handle persistence.ProtectedHandle
}

// NewQuarantine creates a quarantine store over the given protected handle.
func NewQuarantine(
	logger log.StandardLogger,
	handle persistence.ProtectedHandle,
) *Quarantine {
	return &Quarantine{
		logger: logger,
		handle: handle,
	}
}

// QuarantineState reports which halves of a preserved output reached the
// namespace. A caller cannot infer this from the error alone, and the two
// halves mean different things: the membership is the key material a rollback
// has to account for, while the metadata is the audit record explaining it.
// Reporting the wrong one is how an operator log, a published count, and the
// offline audit come to disagree about the same directory.
type QuarantineState struct {
	// MembershipPersisted reports whether the key material reached the
	// namespace.
	MembershipPersisted bool
	// MetadataPersisted reports whether the audit record reached the
	// namespace.
	MetadataPersisted bool
}

// Preserve durably saves the membership and its audit metadata under the
// quarantine namespace. Preservation failure is surfaced to the caller: losing
// generated key material is a protocol violation, so the caller must log it
// unsuppressed.
//
// Both records are attempted even when the first fails, and what actually
// landed is returned beside the error. A half that could have been written is
// evidence the offline audit would otherwise not have, and the audit already
// reads either orphan as a finding — a membership without metadata is
// unexplained key material, metadata without a membership is a share that was
// lost. What must not happen is the node reporting a state the namespace
// contradicts, so the caller is told which of the two it is.
//
// The membership is attempted first so that a process killed between the two
// writes leaves the key material behind rather than only the note describing
// it: an unexplained share is recoverable, a lost one is not.
func (q *Quarantine) Preserve(
	membership *Membership,
	metadata QuarantinedSignerMetadata,
) (QuarantineState, error) {
	var state QuarantineState

	membershipBytes, err := membership.Marshal()
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantined membership: [%v]",
			err,
		)
	}

	metadata.SchemaVersion = QuarantineSchemaVersion
	metadata.GroupPublicKey = hex.EncodeToString(
		membership.Signer.GroupPublicKeyBytesCompressed(),
	)
	metadata.MemberIndex = uint8(membership.Signer.MemberID())
	metadata.PreservedAt = time.Now().UTC()

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantine metadata: [%v]",
			err,
		)
	}

	directory := metadata.GroupPublicKey
	memberSuffix := fmt.Sprint(membership.Signer.MemberID())

	var writeErrs []error

	if err := q.handle.Save(
		membershipBytes,
		directory,
		"/membership_"+memberSuffix,
	); err != nil {
		writeErrs = append(writeErrs, fmt.Errorf(
			"could not persist the quarantined membership: [%v]",
			err,
		))
	} else {
		state.MembershipPersisted = true
	}

	if err := q.handle.Save(
		metadataBytes,
		directory,
		"/metadata_"+memberSuffix,
	); err != nil {
		writeErrs = append(writeErrs, fmt.Errorf(
			"could not persist the quarantine metadata: [%v]",
			err,
		))
	} else {
		state.MetadataPersisted = true
	}

	// One line names the output and what the namespace now holds of it, so the
	// operator record and the namespace cannot drift apart. An incomplete pair
	// is a finding the offline audit will raise, so it is logged as an error
	// here rather than left to read like an ordinary quarantine.
	logQuarantine := q.logger.Warnf
	if len(writeErrs) > 0 {
		logQuarantine = q.logger.Errorf
	}
	logQuarantine(
		"quarantined a beacon signer output [group=0x%v] [member=%v] "+
			"[mode=%s] [canonicalStartBlock=%d] [failedOperation=%s] "+
			"[lastObservedBlock=%d] [keyMaterialPreserved=%v] "+
			"[auditMetadataPreserved=%v]",
		metadata.GroupPublicKey,
		membership.Signer.MemberID(),
		metadata.ProtocolMode,
		metadata.CanonicalStartBlock,
		metadata.FailedOperation,
		metadata.LastObservedBlock,
		state.MembershipPersisted,
		state.MetadataPersisted,
	)

	if len(writeErrs) > 0 {
		return state, errors.Join(writeErrs...)
	}

	return state, nil
}
