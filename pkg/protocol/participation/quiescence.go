package participation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keep-network/keep-core/pkg/protocol/group"
)

const (
	// QuiescenceSnapshotSchemaVersion is the schema of the node-authored gate
	// snapshot persisted at the quiescence transition.
	QuiescenceSnapshotSchemaVersion = uint32(1)

	// QuiescenceSnapshotStorageDirectory and
	// QuiescenceSnapshotStorageFile identify the record inside the encrypted
	// work/participation persistence namespace. The rollback audit reads this
	// exact record from the stopped node's storage snapshot.
	QuiescenceSnapshotStorageDirectory = "quiescence"
	QuiescenceSnapshotStorageFile      = "gate-snapshot.json"

	// TerminalOutcomeJournalSchemaVersion is the schema of the node-authored
	// terminal-outcome journal. The journal is bound to the gate snapshot's
	// capture time and covers that snapshot's permit inventory one-to-one.
	TerminalOutcomeJournalSchemaVersion = uint32(2)

	// TerminalOutcomeJournalStorageFile identifies the terminal-outcome
	// journal beside the immutable gate snapshot. Both records are encrypted
	// by the participation work persistence handle.
	TerminalOutcomeJournalStorageFile = "terminal-outcomes.json"
)

// PermitIdentity binds one local permit to the chain-native work it performs
// and to the stable local membership or action identity that owns it. Neither
// component may contain raw seeds, messages, session IDs, keys, hostnames, or
// network addresses.
type PermitIdentity struct {
	WorkID   string `json:"work_id"`
	PermitID string `json:"permit_id"`
}

const maxPermitIdentityComponentLength = 256

func validatePermitIdentity(identity PermitIdentity) error {
	for _, component := range []struct {
		name  string
		value string
	}{
		{name: "work ID", value: identity.WorkID},
		{name: "permit ID", value: identity.PermitID},
	} {
		name := component.name
		value := component.value
		if value == "" {
			return fmt.Errorf("%s is empty", name)
		}
		if len(value) > maxPermitIdentityComponentLength {
			return fmt.Errorf(
				"%s exceeds [%d] bytes",
				name,
				maxPermitIdentityComponentLength,
			)
		}
		for i, character := range []byte(value) {
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				(i > 0 && (character == '_' ||
					character == '.' ||
					character == ':' ||
					character == '-')) {
				continue
			}
			return fmt.Errorf(
				"%s contains an unsupported character at byte [%d]",
				name,
				i,
			)
		}
	}

	return nil
}

// validatePermitIdentityForCeremony applies the identity shape that is
// intrinsic to a ceremony in addition to the generic nonsecret token rules.
// DKG work is always keyed by the lowercase SHA-256 hash of its seed, and
// member-owned DKG/relay permits always use the canonical decimal member
// index. Enforcing these shapes at issuance prevents an unauditable identity
// from entering the authoritative quiescence inventory.
func validatePermitIdentityForCeremony(
	ceremony Ceremony,
	identity PermitIdentity,
) error {
	if err := validatePermitIdentity(identity); err != nil {
		return err
	}

	switch ceremony {
	case TBTCDKG, BeaconDKG:
		if len(identity.WorkID) != 64 ||
			identity.WorkID != strings.ToLower(identity.WorkID) {
			return fmt.Errorf(
				"work ID must be a lowercase SHA-256 hash of 64 hexadecimal characters",
			)
		}
		if _, err := hex.DecodeString(identity.WorkID); err != nil {
			return fmt.Errorf(
				"work ID must be a lowercase SHA-256 hash of 64 hexadecimal characters",
			)
		}
	}

	switch ceremony {
	case TBTCDKG, BeaconDKG, BeaconRelaySigning:
		memberIndex, err := strconv.ParseUint(identity.PermitID, 10, 8)
		if err != nil ||
			memberIndex == 0 ||
			memberIndex > uint64(group.MaxMemberIndex) ||
			strconv.FormatUint(memberIndex, 10) != identity.PermitID {
			return fmt.Errorf(
				"permit ID must be a canonical member index from 1 through %d",
				group.MaxMemberIndex,
			)
		}
	}

	return nil
}

// PermitSnapshot is the immutable, nonsecret identity and cutover
// classification of one live permit.
type PermitSnapshot struct {
	Ceremony            Ceremony `json:"ceremony"`
	Mode                string   `json:"mode"`
	CanonicalStartBlock uint64   `json:"canonical_start_block"`
	WorkID              string   `json:"work_id"`
	PermitID            string   `json:"permit_id"`
	// IdentityBound is true only when the ceremony owner supplied the
	// chain-work and local-permit identity at issuance. The source-compatible
	// unbound path exists only for test gates without a persistence recorder;
	// production issuance and the rollback audit both refuse it.
	IdentityBound bool `json:"identity_bound"`
}

// QuiescenceSnapshot is the node-authored, immutable record captured under
// the gate lock at the instant the first Quiesce call makes the transition.
// It binds the real active-permit registry to the exact artifact and one-value
// cutover schedule that were running. The node-authored terminal-outcome
// journal must cover this inventory one-to-one; external reconciliation can
// only corroborate it.
type QuiescenceSnapshot struct {
	SchemaVersion uint32    `json:"schema_version"`
	CapturedAt    time.Time `json:"captured_at"`

	ReleaseVersion  string `json:"release_version"`
	ReleaseRevision string `json:"release_revision"`
	ReleaseEpoch    string `json:"release_epoch"`

	CutoverBlock   uint64 `json:"cutover_block"`
	CurrentBlock   uint64 `json:"current_block"`
	ClockAvailable bool   `json:"clock_available"`
	State          string `json:"state"`
	QuiesceCause   string `json:"quiesce_cause"`

	ActiveCeremonies           uint64           `json:"active_ceremonies"`
	ActiveLegacyCeremonies     uint64           `json:"active_legacy_ceremonies"`
	ActiveSecurityV2Ceremonies uint64           `json:"active_security_v2_ceremonies"`
	ActivePermits              []PermitSnapshot `json:"active_permits"`
}

// TerminalOutcome is the final disposition of a permit that was active at the
// quiescence transition.
type TerminalOutcome string

const (
	// TerminalOutcomeCompleted means the ceremony owner reached a durable
	// successful result and recorded evidence identifying that result.
	TerminalOutcomeCompleted TerminalOutcome = "completed"
	// TerminalOutcomeQuarantined means generated key material was durably
	// preserved in the protected quarantine namespace.
	TerminalOutcomeQuarantined TerminalOutcome = "quarantined"
	// TerminalOutcomeExhausted means the ceremony ended without producing a
	// threshold result or durable state transition.
	TerminalOutcomeExhausted TerminalOutcome = "exhausted"
	// terminalOutcomeUnresolved is written by permit Close when its ceremony
	// owner did not record any terminal disposition. It is intentionally not
	// accepted by RecordTerminalOutcome and always blocks the offline barrier.
	terminalOutcomeUnresolved TerminalOutcome = "unresolved"
)

// TerminalEvidenceKind identifies the durable state or explicit terminal
// condition behind an outcome. References contain only stable public
// identities or digests; private material and raw protocol inputs are
// forbidden.
type TerminalEvidenceKind string

const (
	TerminalEvidencePersistedTBTCSinger     TerminalEvidenceKind = "persisted_tbtc_signer"
	TerminalEvidencePersistedBeaconSigner   TerminalEvidenceKind = "persisted_beacon_signer"
	TerminalEvidenceQuarantinedTBTCSinger   TerminalEvidenceKind = "quarantined_tbtc_signer"
	TerminalEvidenceQuarantinedBeaconSigner TerminalEvidenceKind = "quarantined_beacon_signer"
	TerminalEvidenceBitcoinTransaction      TerminalEvidenceKind = "bitcoin_transaction"
	TerminalEvidenceEthereumTransaction     TerminalEvidenceKind = "ethereum_transaction"
	TerminalEvidenceProtocolResult          TerminalEvidenceKind = "protocol_result"
	TerminalEvidenceNoThreshold             TerminalEvidenceKind = "no_threshold"
	TerminalEvidenceForwarderClosed         TerminalEvidenceKind = "forwarder_closed"
)

// TerminalEvidence binds a terminal outcome to the state it left behind.
// Reference is required for persisted signers, transactions, and protocol
// result digests. Explicit no-threshold and forwarder-close outcomes carry no
// reference.
type TerminalEvidence struct {
	Kind      TerminalEvidenceKind `json:"kind"`
	Reference string               `json:"reference,omitempty"`
	// MembershipIndex identifies the exact persisted membership produced by
	// a completed DKG permit. For tBTC this is the final wallet signing-group
	// index, which may differ from the original DKG permit index after
	// inactive or disqualified members are removed. For beacon it is the
	// persisted threshold signer's member index.
	MembershipIndex group.MemberIndex `json:"membership_index,omitempty"`
}

// TerminalOutcomeRecord is written by the permit owner after real completion
// or quarantine handling. The embedded permit identity is copied from the gate
// and cannot be supplied or changed by an external report generator.
type TerminalOutcomeRecord struct {
	RecordedAt time.Time        `json:"recorded_at"`
	Permit     PermitSnapshot   `json:"permit"`
	Outcome    TerminalOutcome  `json:"outcome"`
	Evidence   TerminalEvidence `json:"evidence"`
}

// TerminalOutcomeJournal is the node-authored terminal record for the exact
// permit population captured at one quiescence transition.
type TerminalOutcomeJournal struct {
	SchemaVersion      uint32                  `json:"schema_version"`
	SnapshotCapturedAt time.Time               `json:"snapshot_captured_at"`
	Outcomes           []TerminalOutcomeRecord `json:"outcomes"`
}

// ValidateTerminalOutcome checks that an outcome and its evidence have a
// supported shape for the owning ceremony. The live gate and the offline
// state audit use this same validator so corrupted journal data cannot exploit
// schema drift between issuance and reconciliation.
func ValidateTerminalOutcome(
	ceremony Ceremony,
	outcome TerminalOutcome,
	evidence TerminalEvidence,
) error {
	if outcome != TerminalOutcomeCompleted &&
		outcome != TerminalOutcomeQuarantined &&
		outcome != TerminalOutcomeExhausted {
		return fmt.Errorf("unsupported terminal outcome [%s]", outcome)
	}

	referenceRequired := false
	switch evidence.Kind {
	case TerminalEvidencePersistedTBTCSinger,
		TerminalEvidencePersistedBeaconSigner,
		TerminalEvidenceBitcoinTransaction,
		TerminalEvidenceEthereumTransaction,
		TerminalEvidenceProtocolResult:
		referenceRequired = true
	case TerminalEvidenceQuarantinedTBTCSinger,
		TerminalEvidenceQuarantinedBeaconSigner,
		TerminalEvidenceNoThreshold,
		TerminalEvidenceForwarderClosed:
	default:
		return fmt.Errorf(
			"unsupported terminal evidence kind [%s]",
			evidence.Kind,
		)
	}

	if referenceRequired {
		if err := validatePermitIdentity(PermitIdentity{
			WorkID:   evidence.Reference,
			PermitID: "evidence",
		}); err != nil {
			return fmt.Errorf("invalid terminal evidence reference: [%w]", err)
		}
	} else if evidence.Reference != "" {
		return fmt.Errorf(
			"terminal evidence kind [%s] must not carry a reference",
			evidence.Kind,
		)
	}

	dkgSignerEvidence :=
		evidence.Kind == TerminalEvidencePersistedTBTCSinger ||
			evidence.Kind == TerminalEvidencePersistedBeaconSigner
	if dkgSignerEvidence {
		if evidence.MembershipIndex == 0 ||
			evidence.MembershipIndex > group.MaxMemberIndex {
			return fmt.Errorf(
				"persisted DKG signer evidence requires a membership index "+
					"from 1 through %d",
				group.MaxMemberIndex,
			)
		}
	} else if evidence.MembershipIndex != 0 {
		return fmt.Errorf(
			"terminal evidence kind [%s] must not carry a membership index",
			evidence.Kind,
		)
	}

	switch outcome {
	case TerminalOutcomeCompleted:
		if evidence.Kind == TerminalEvidenceQuarantinedTBTCSinger ||
			evidence.Kind == TerminalEvidenceQuarantinedBeaconSigner ||
			evidence.Kind == TerminalEvidenceNoThreshold {
			return fmt.Errorf(
				"completed outcome cannot use evidence kind [%s]",
				evidence.Kind,
			)
		}
	case TerminalOutcomeQuarantined:
		expected := TerminalEvidenceQuarantinedTBTCSinger
		if ceremony == BeaconDKG {
			expected = TerminalEvidenceQuarantinedBeaconSigner
		}
		if (ceremony != TBTCDKG && ceremony != BeaconDKG) ||
			evidence.Kind != expected {
			return fmt.Errorf(
				"quarantined outcome for ceremony [%s] requires evidence kind [%s]",
				ceremony,
				expected,
			)
		}
	case TerminalOutcomeExhausted:
		if evidence.Kind != TerminalEvidenceNoThreshold {
			return fmt.Errorf(
				"exhausted outcome requires evidence kind [%s]",
				TerminalEvidenceNoThreshold,
			)
		}
	}

	switch ceremony {
	case TBTCDKG:
		if outcome == TerminalOutcomeExhausted {
			return fmt.Errorf(
				"exhausted tbtc DKG has no chain-derived proof that another " +
					"member did not publish an accepted result",
			)
		}
		if outcome == TerminalOutcomeCompleted &&
			evidence.Kind != TerminalEvidencePersistedTBTCSinger {
			return fmt.Errorf(
				"completed tbtc DKG requires evidence kind [%s]",
				TerminalEvidencePersistedTBTCSinger,
			)
		}
	case BeaconDKG:
		if outcome == TerminalOutcomeExhausted {
			return fmt.Errorf(
				"exhausted beacon DKG has no chain-derived proof that another " +
					"member did not publish an accepted result",
			)
		}
		if outcome == TerminalOutcomeCompleted &&
			evidence.Kind != TerminalEvidencePersistedBeaconSigner {
			return fmt.Errorf(
				"completed beacon DKG requires evidence kind [%s]",
				TerminalEvidencePersistedBeaconSigner,
			)
		}
	}

	return nil
}

func terminalOutcomeRecordLess(
	left TerminalOutcomeRecord,
	right TerminalOutcomeRecord,
) bool {
	if left.Permit.Ceremony != right.Permit.Ceremony {
		return left.Permit.Ceremony < right.Permit.Ceremony
	}
	if left.Permit.CanonicalStartBlock != right.Permit.CanonicalStartBlock {
		return left.Permit.CanonicalStartBlock <
			right.Permit.CanonicalStartBlock
	}
	if left.Permit.WorkID != right.Permit.WorkID {
		return left.Permit.WorkID < right.Permit.WorkID
	}
	return left.Permit.PermitID < right.Permit.PermitID
}

// QuiescenceSnapshotRecorder persists the node-authored snapshot and the
// ceremony-owner-authored terminal outcomes. Implementations must serialize
// concurrent terminal writes and make contradictory duplicate outcomes fail.
type QuiescenceSnapshotRecorder interface {
	Record(snapshot QuiescenceSnapshot) error
	RecordTerminalOutcome(outcome TerminalOutcomeRecord) error
}

// quiescencePersistence is the narrow persistence handle used by the
// recorder. persistence.BasicHandle satisfies it without coupling the gate to
// the rest of the storage API.
type quiescencePersistence interface {
	Save(data []byte, directory string, name string) error
	Delete(directory string, name string) error
}

type persistenceQuiescenceSnapshotRecorder struct {
	persistence quiescencePersistence

	mutex   sync.Mutex
	journal TerminalOutcomeJournal
}

// NewPersistenceQuiescenceSnapshotRecorder constructs the production
// recorder for the encrypted work/participation namespace.
func NewPersistenceQuiescenceSnapshotRecorder(
	persistence quiescencePersistence,
) (QuiescenceSnapshotRecorder, error) {
	if persistence == nil {
		return nil, fmt.Errorf("quiescence snapshot persistence is required")
	}

	// A snapshot authorizes only the process run that produced it. Clear any
	// prior run's record before the gate becomes available; if the node exits
	// or a later write fails, the offline audit then sees a missing or malformed
	// record instead of accepting stale inventory.
	if err := persistence.Delete(
		QuiescenceSnapshotStorageDirectory,
		QuiescenceSnapshotStorageFile,
	); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf(
			"cannot invalidate the prior quiescence snapshot: [%w]",
			err,
		)
	}
	if err := persistence.Delete(
		QuiescenceSnapshotStorageDirectory,
		TerminalOutcomeJournalStorageFile,
	); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf(
			"cannot invalidate the prior terminal-outcome journal: [%w]",
			err,
		)
	}

	return &persistenceQuiescenceSnapshotRecorder{
		persistence: persistence,
	}, nil
}

func (r *persistenceQuiescenceSnapshotRecorder) Record(
	snapshot QuiescenceSnapshot,
) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the quiescence snapshot: [%w]", err)
	}

	if err := r.persistence.Save(
		content,
		QuiescenceSnapshotStorageDirectory,
		QuiescenceSnapshotStorageFile,
	); err != nil {
		return fmt.Errorf("cannot persist the quiescence snapshot: [%w]", err)
	}

	r.journal = TerminalOutcomeJournal{
		SchemaVersion:      TerminalOutcomeJournalSchemaVersion,
		SnapshotCapturedAt: snapshot.CapturedAt,
	}
	if err := r.persistJournalLocked(); err != nil {
		return err
	}

	return nil
}

func (r *persistenceQuiescenceSnapshotRecorder) RecordTerminalOutcome(
	outcome TerminalOutcomeRecord,
) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.journal.SnapshotCapturedAt.IsZero() {
		return fmt.Errorf(
			"cannot persist a terminal outcome before the quiescence snapshot",
		)
	}

	for _, existing := range r.journal.Outcomes {
		if existing.Permit == outcome.Permit {
			if existing == outcome {
				return nil
			}
			return fmt.Errorf(
				"terminal outcome already recorded for ceremony [%s] "+
					"[workID=%s] [permitID=%s]",
				outcome.Permit.Ceremony,
				outcome.Permit.WorkID,
				outcome.Permit.PermitID,
			)
		}
	}

	previous := append(
		[]TerminalOutcomeRecord(nil),
		r.journal.Outcomes...,
	)
	r.journal.Outcomes = append(r.journal.Outcomes, outcome)
	sort.Slice(r.journal.Outcomes, func(i, j int) bool {
		return terminalOutcomeRecordLess(
			r.journal.Outcomes[i],
			r.journal.Outcomes[j],
		)
	})

	if err := r.persistJournalLocked(); err != nil {
		r.journal.Outcomes = previous
		return err
	}

	return nil
}

func (r *persistenceQuiescenceSnapshotRecorder) persistJournalLocked() error {
	content, err := json.MarshalIndent(r.journal, "", "  ")
	if err != nil {
		return fmt.Errorf(
			"cannot encode the terminal-outcome journal: [%w]",
			err,
		)
	}

	if err := r.persistence.Save(
		content,
		QuiescenceSnapshotStorageDirectory,
		TerminalOutcomeJournalStorageFile,
	); err != nil {
		return fmt.Errorf(
			"cannot persist the terminal-outcome journal: [%w]",
			err,
		)
	}

	return nil
}
