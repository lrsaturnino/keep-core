package participation

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
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
	//
	// Version 3 added the chain-settlement record. An earlier journal cannot
	// carry one, so it cannot distinguish a heartbeat that filed an inactivity
	// claim from one that did not, and the audit must reject it outright
	// rather than reconcile it under a rule it had no way to satisfy.
	TerminalOutcomeJournalSchemaVersion = uint32(3)

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

const (
	maxPermitIdentityComponentLength = 256
	// maxTerminalEvidenceReferenceLength bounds a terminal evidence reference.
	// It is wider than a permit identity component because one evidence class
	// is verifiable rather than merely nameable: a beacon relay entry carries
	// the group public key, the previous entry and the entry as public curve
	// points precisely so the offline audit can check the signature instead of
	// taking the node's word for the result. Three 64-byte components in hex
	// with their separators is the widest reference any ceremony produces.
	maxTerminalEvidenceReferenceLength = 3*2*beaconRelayEntryComponentLength + 2
)

// validateNonsecretToken applies the shared shape of every identity and
// reference the journal carries: nonempty, bounded, and drawn from an alphabet
// that cannot smuggle raw seeds, keys, hostnames, or network addresses past a
// reader.
func validateNonsecretToken(name string, value string, maxLength int) error {
	if value == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if len(value) > maxLength {
		return fmt.Errorf("%s exceeds [%d] bytes", name, maxLength)
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

	return nil
}

func validatePermitIdentity(identity PermitIdentity) error {
	for _, component := range []struct {
		name  string
		value string
	}{
		{name: "work ID", value: identity.WorkID},
		{name: "permit ID", value: identity.PermitID},
	} {
		if err := validateNonsecretToken(
			component.name,
			component.value,
			maxPermitIdentityComponentLength,
		); err != nil {
			return err
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
	// ChainSettlement reports a chain side effect the ceremony dispatched
	// beyond its own protocol result. It is nil when the ceremony dispatched
	// none.
	ChainSettlement *ChainSettlementRecord `json:"chain_settlement,omitempty"`
}

// Equal reports whether two evidence records describe the same durable result.
// It exists because TerminalEvidence carries a pointer: Go's == would compare
// the settlement by address, so two records built separately from the same
// observation — a retried write, a record reloaded from the journal — would
// read as different results. Callers must use this instead of ==.
func (e TerminalEvidence) Equal(other TerminalEvidence) bool {
	if e.Kind != other.Kind ||
		e.Reference != other.Reference ||
		e.MembershipIndex != other.MembershipIndex {
		return false
	}
	if e.ChainSettlement == nil || other.ChainSettlement == nil {
		return e.ChainSettlement == other.ChainSettlement
	}

	return *e.ChainSettlement == *other.ChainSettlement
}

// ChainSettlementKind identifies a chain side effect a ceremony dispatches
// outside its own protocol result.
type ChainSettlementKind string

const (
	// ChainSettlementInactivityClaim is the operator inactivity claim a
	// low-activity tBTC heartbeat files against the WalletRegistry.
	ChainSettlementInactivityClaim ChainSettlementKind = "tbtc_inactivity_claim"
)

// ChainSettlementRecord reports a chain side effect the ceremony handed to a
// chain and the canonical chain state it was resolved to settle into.
//
// Submitting is not settling. The submitting call returns as soon as the
// transaction reaches the provider and the transaction is mined afterwards, it
// can lose the race to another member's submission, and it can be canceled
// mid-flight; in none of those cases does the node know from the call alone
// whether the side effect reached the chain. A submission whose settlement the
// ceremony could not resolve is therefore recorded with an empty Reference: the
// attempt is on the record, its outcome is unknown, and the offline barrier
// must treat it as unreconciled instead of letting a node-authored digest close
// the journal over a penalty that may or may not exist on chain.
//
// The record is absent entirely when the ceremony never reached the submitting
// call. A suppressed, refused, or aborted dispatch left no transaction
// anywhere, and reporting it as an unresolved submission would block a rollback
// over chain state that provably cannot exist.
type ChainSettlementRecord struct {
	Kind ChainSettlementKind `json:"kind"`
	// Reference is the canonical chain identity of the resolved settlement.
	// It is empty when the submission's settlement could not be resolved.
	Reference string `json:"reference,omitempty"`
}

// inactivityClaimWalletIDLength is the byte length of the WalletRegistry
// wallet identifier an inactivity claim names.
const inactivityClaimWalletIDLength = 32

// InactivityClaimSettlementReference renders the canonical identity of an
// on-chain tBTC inactivity claim: the wallet it was filed against and the
// claim nonce it settled at. The pair identifies exactly one claim for all
// time, because the WalletRegistry accepts a claim only at the wallet's
// current nonce and increments that nonce in the same call. The offline audit
// can therefore join the reference to exactly one authenticated
// InactivityClaimed log, which is what keeps the node from naming a settlement
// that never happened.
func InactivityClaimSettlementReference(
	walletID []byte,
	nonce *big.Int,
) (string, error) {
	if len(walletID) != inactivityClaimWalletIDLength {
		return "", fmt.Errorf(
			"inactivity claim wallet identifier must be %d bytes, got [%d]",
			inactivityClaimWalletIDLength,
			len(walletID),
		)
	}
	if nonce == nil {
		return "", fmt.Errorf("inactivity claim nonce is missing")
	}
	if nonce.Sign() < 0 {
		return "", fmt.Errorf(
			"inactivity claim nonce [%s] is negative",
			nonce,
		)
	}

	return hex.EncodeToString(walletID) + ":" + nonce.String(), nil
}

// ParseInactivityClaimSettlementReference recovers the wallet identifier and
// claim nonce from a reference produced by
// InactivityClaimSettlementReference. Only the exact rendering that function
// produces is accepted: an uppercase, prefixed, or zero-padded alias would
// name the same claim while failing every string comparison the audit makes
// against it, which is indistinguishable from naming no claim at all.
func ParseInactivityClaimSettlementReference(
	reference string,
) ([]byte, *big.Int, error) {
	walletIDText, nonceText, separated := strings.Cut(reference, ":")
	if !separated {
		return nil, nil, fmt.Errorf(
			"inactivity claim reference [%s] is not a wallet identifier and "+
				"nonce pair",
			reference,
		)
	}

	walletID, err := hex.DecodeString(walletIDText)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"inactivity claim reference wallet identifier [%s] is not hex: "+
				"[%v]",
			walletIDText,
			err,
		)
	}
	if len(walletID) != inactivityClaimWalletIDLength {
		return nil, nil, fmt.Errorf(
			"inactivity claim reference wallet identifier [%s] is not %d "+
				"bytes",
			walletIDText,
			inactivityClaimWalletIDLength,
		)
	}
	if hex.EncodeToString(walletID) != walletIDText {
		return nil, nil, fmt.Errorf(
			"inactivity claim reference wallet identifier [%s] is not "+
				"canonically encoded",
			walletIDText,
		)
	}

	nonce, valid := new(big.Int).SetString(nonceText, 10)
	if !valid || nonce.Sign() < 0 {
		return nil, nil, fmt.Errorf(
			"inactivity claim reference nonce [%s] is not a non-negative "+
				"decimal integer",
			nonceText,
		)
	}
	if nonce.String() != nonceText {
		return nil, nil, fmt.Errorf(
			"inactivity claim reference nonce [%s] is not canonically encoded",
			nonceText,
		)
	}

	return walletID, nonce, nil
}

// beaconRelayEntryComponentLength is the byte length of each component of a
// relay entry identity. A compressed bn256 group public key, a marshaled
// previous entry, and a marshaled recovered entry are all 64 bytes.
const beaconRelayEntryComponentLength = 64

// BeaconRelayEntryReference renders the canonical identity of a recovered
// relay entry: the group that signed it, the previous entry it signed over,
// and the entry itself.
//
// Unlike every other protocol result, this identity is not a digest. A relay
// entry is a threshold BLS signature by the group over the previous entry, and
// all three components are public beacon state that the chain publishes
// anyway. Carrying them in the clear is what lets the offline audit verify the
// pairing itself: an entry that verifies under a group public key the snapshot
// holds cannot have been authored by anything but that group's threshold key,
// so the node's word is not what makes the record true. A digest would prove
// only that the node was consistent with itself.
func BeaconRelayEntryReference(
	groupPublicKey []byte,
	previousEntry []byte,
	entry []byte,
) (string, error) {
	for _, component := range []struct {
		name  string
		value []byte
	}{
		{name: "group public key", value: groupPublicKey},
		{name: "previous entry", value: previousEntry},
		{name: "entry", value: entry},
	} {
		if len(component.value) != beaconRelayEntryComponentLength {
			return "", fmt.Errorf(
				"relay entry %s must be %d bytes, got [%d]",
				component.name,
				beaconRelayEntryComponentLength,
				len(component.value),
			)
		}
	}

	return hex.EncodeToString(groupPublicKey) + ":" +
		hex.EncodeToString(previousEntry) + ":" +
		hex.EncodeToString(entry), nil
}

// ParseBeaconRelayEntryReference recovers the group public key, previous entry
// and recovered entry from a reference produced by BeaconRelayEntryReference.
// Only that exact rendering is accepted: an uppercase or prefixed alias would
// name the same entry while failing every comparison the audit makes against
// the group identities it decoded, which is indistinguishable from naming no
// group at all.
func ParseBeaconRelayEntryReference(
	reference string,
) (groupPublicKey []byte, previousEntry []byte, entry []byte, err error) {
	parts := strings.Split(reference, ":")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf(
			"relay entry reference [%s] is not a group, previous entry and "+
				"entry triple",
			reference,
		)
	}

	decoded := make([][]byte, 0, len(parts))
	for i, name := range []string{
		"group public key",
		"previous entry",
		"entry",
	} {
		value, err := hex.DecodeString(parts[i])
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"relay entry reference %s [%s] is not hex: [%v]",
				name,
				parts[i],
				err,
			)
		}
		if len(value) != beaconRelayEntryComponentLength {
			return nil, nil, nil, fmt.Errorf(
				"relay entry reference %s [%s] is not %d bytes",
				name,
				parts[i],
				beaconRelayEntryComponentLength,
			)
		}
		if hex.EncodeToString(value) != parts[i] {
			return nil, nil, nil, fmt.Errorf(
				"relay entry reference %s [%s] is not canonically encoded",
				name,
				parts[i],
			)
		}
		decoded = append(decoded, value)
	}

	return decoded[0], decoded[1], decoded[2], nil
}

// TerminalResultReference derives the nonsecret, stable identity of a protocol
// result for a terminal evidence record. Components are length-prefixed under a
// domain label, so no two ceremonies can derive the same digest from different
// inputs and no component boundary can be shifted to forge a collision. Only
// the digest — never the underlying material — reaches the journal, which keeps
// raw protocol inputs out of a record the rollback audit reads outside the
// node's trust boundary.
func TerminalResultReference(domain string, components ...[]byte) string {
	digest := sha256.New()

	writeComponent := func(component []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(component)))
		digest.Write(length[:])
		digest.Write(component)
	}

	writeComponent([]byte(domain))
	for _, component := range components {
		writeComponent(component)
	}

	return hex.EncodeToString(digest.Sum(nil))
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

// Equal reports whether two records report the same disposition of the same
// permit. Like TerminalEvidence.Equal it exists because the embedded evidence
// carries a pointer, so == would separate a record from an identical one
// rebuilt or reloaded elsewhere. Callers must use this instead of ==.
func (r TerminalOutcomeRecord) Equal(other TerminalOutcomeRecord) bool {
	return r.RecordedAt.Equal(other.RecordedAt) &&
		r.Permit == other.Permit &&
		r.Outcome == other.Outcome &&
		r.Evidence.Equal(other.Evidence)
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
		if err := validateNonsecretToken(
			"terminal evidence reference",
			evidence.Reference,
			maxTerminalEvidenceReferenceLength,
		); err != nil {
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
	case BeaconDKG:
		if outcome == TerminalOutcomeExhausted {
			return fmt.Errorf(
				"exhausted beacon DKG has no chain-derived proof that another " +
					"member did not publish an accepted result",
			)
		}
	}

	if outcome == TerminalOutcomeCompleted {
		expected, known := completedEvidenceKinds[ceremony]
		if !known {
			return fmt.Errorf(
				"ceremony [%s] has no declared completed evidence kind",
				ceremony,
			)
		}
		if evidence.Kind != expected {
			return fmt.Errorf(
				"completed ceremony [%s] requires evidence kind [%s], got [%s]",
				ceremony,
				expected,
				evidence.Kind,
			)
		}
		// A relay entry is the one protocol result whose reference is
		// verifiable rather than merely well formed, so a malformed one is
		// rejected here instead of reaching an audit that could not check it.
		if ceremony == BeaconRelaySigning {
			if _, _, _, err := ParseBeaconRelayEntryReference(
				evidence.Reference,
			); err != nil {
				return fmt.Errorf("invalid relay entry reference: [%w]", err)
			}
		}
	}

	return validateChainSettlement(ceremony, outcome, evidence.ChainSettlement)
}

// chainSettlementKinds names the single chain side effect each ceremony may
// dispatch outside its own protocol result. A ceremony absent from the map
// dispatches none: it has no code path that submits to a chain, so a
// settlement recorded against it is a fabricated one, and accepting it would
// let any ceremony attach a penalty submission it could not have made.
var chainSettlementKinds = map[Ceremony]ChainSettlementKind{
	// A low-activity heartbeat files the inactivity claim under its own permit,
	// so the heartbeat's terminal record is the only place that submission is
	// ever reported.
	TBTCHeartbeat: ChainSettlementInactivityClaim,
}

func validateChainSettlement(
	ceremony Ceremony,
	outcome TerminalOutcome,
	settlement *ChainSettlementRecord,
) error {
	if settlement == nil {
		return nil
	}

	expected, dispatches := chainSettlementKinds[ceremony]
	if !dispatches {
		return fmt.Errorf(
			"ceremony [%s] dispatches no chain settlement",
			ceremony,
		)
	}
	if settlement.Kind != expected {
		return fmt.Errorf(
			"ceremony [%s] dispatches chain settlement kind [%s], got [%s]",
			ceremony,
			expected,
			settlement.Kind,
		)
	}
	// Every dispatch path runs downstream of the ceremony's own threshold
	// result, so a ceremony that reports no result cannot have reached one.
	if outcome != TerminalOutcomeCompleted {
		return fmt.Errorf(
			"[%s] outcome cannot carry a chain settlement",
			outcome,
		)
	}

	// An empty reference is the deliberate unresolved-submission record; only a
	// reference that claims a settlement has to name one canonically.
	if settlement.Reference == "" {
		return nil
	}

	switch settlement.Kind {
	case ChainSettlementInactivityClaim:
		if _, _, err := ParseInactivityClaimSettlementReference(
			settlement.Reference,
		); err != nil {
			return fmt.Errorf("invalid chain settlement reference: [%w]", err)
		}
	}

	return nil
}

// completedEvidenceKinds names the single evidence kind each ceremony may use
// to claim a durable result. The mapping is deliberately exhaustive and
// one-to-one: without it, a ceremony whose real result is an external
// transaction — a signed Bitcoin spend, an on-chain penalty submission — could
// settle its permit with TerminalEvidenceProtocolResult, a digest the node
// authors entirely by itself. That would let an ambiguous submission clear the
// rollback journal on the node's own say-so, with nothing for the offline audit
// to reconcile against canonical state. Each ceremony is therefore pinned to
// the evidence class its result actually lives in.
//
// A ceremony added to AllCeremonies without an entry here fails closed: its
// completed outcome is rejected, the permit closes unresolved, and the offline
// barrier blocks until the omission is fixed.
var completedEvidenceKinds = map[Ceremony]TerminalEvidenceKind{
	// The wallet's persisted signing-group membership.
	TBTCDKG: TerminalEvidencePersistedTBTCSinger,
	// The agreed proposal; it dispatches an action that settles separately.
	TBTCWalletCoordination: TerminalEvidenceProtocolResult,
	// The signed Bitcoin transaction the action may have broadcast.
	TBTCSigning: TerminalEvidenceBitcoinTransaction,
	// The threshold signature over the proposed heartbeat message.
	TBTCHeartbeat: TerminalEvidenceProtocolResult,
	// The claim submission, which is Ethereum state and never node-authored.
	TBTCInactivityClaim: TerminalEvidenceEthereumTransaction,
	// The persisted threshold signer.
	BeaconDKG: TerminalEvidencePersistedBeaconSigner,
	// The recovered relay entry, deterministic for a given previous entry.
	BeaconRelaySigning: TerminalEvidenceProtocolResult,
	// The forwarder relays other members' shares and produces no result of its
	// own; reaching its close is the whole of its durable disposition.
	BeaconRelayForwarding: TerminalEvidenceForwarderClosed,
	// The filed timeout report, identified by its request and report blocks.
	BeaconTimeoutReport: TerminalEvidenceProtocolResult,
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
			if existing.Equal(outcome) {
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
