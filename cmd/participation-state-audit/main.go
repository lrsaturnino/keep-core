// Command participation-state-audit classifies a stopped node's persisted
// protocol state for the rollback barrier, without exposing private material.
//
// It records the snapshot identity (an aggregate checksum over every at-rest
// file and the root access mode), inventories the keystore and work
// namespaces, flags any entry the expected storage layout does not contain,
// and — when the storage password is supplied — interprets the beacon active,
// beacon quarantine, and tBTC active namespaces with the same decode paths
// the client's own loaders use. Every inconsistency is a finding: records
// that fail to decrypt or decode, quarantine halves missing their partner,
// quarantine metadata that contradicts its schema, epoch, mode, anchor,
// directory, or decrypted membership, groups present in both the active and
// quarantine namespaces, and records stored under a directory their content
// does not match.
//
// The tool MUST run against a snapshot copy of the node's storage, never the
// live directory: opening the standard persistence handles creates their
// bookkeeping subdirectories and probes write permission, and a rollback
// audit must not mutate the original evidence.
//
// Namespace consistency alone is deliberately insufficient for the rollback
// barrier. Chain reconciliation (wallet/group registration and DKG
// settlement, for active and quarantined state alike), Bitcoin transaction
// reconciliation, the quiescence outcome report, and prior-reader
// compatibility evidence are produced outside this offline tool; until a
// reference to each is supplied and recorded, the manifest reports the
// missing pieces as rollback blockers and the process exits nonzero. Every
// evidence record must additionally bind to the operator-supplied expected
// operational identities — Ethereum chain ID, Bitcoin network, the exact
// prior and current release versions and revisions, both immutable image
// digests, the compiled release epoch, and the cutover block — and fall
// within the evidence freshness bound: schema-valid evidence for the wrong
// target, the wrong artifact, the wrong cutover schedule, or from long
// before the rollback decision blocks the barrier exactly like missing
// evidence. This tool's output never authorizes activating quarantined
// material by itself.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/storage"
	"github.com/keep-network/keep-core/pkg/tbtc"
)

// manifestSchemaVersion versions the audit manifest document.
const manifestSchemaVersion = uint32(5)

// The audited namespaces, relative to the storage root. The beacon quarantine
// namespace is a sibling of the active beacon keystore precisely so the
// active-group scan cannot read it; the audit re-verifies that separation.
const (
	beaconKeystoreNamespace    = "keystore/beacon"
	beaconQuarantineNamespace  = "keystore/beacon-quarantine"
	tbtcKeystoreNamespace      = "keystore/tbtc"
	tbtcQuarantineNamespace    = "keystore/tbtc-quarantine"
	tbtcWorkNamespace          = "work/tbtc"
	participationWorkNamespace = "work/participation"
)

// The expected storage layout at each level. Any other entry is a finding:
// state this audit cannot classify must block the rollback barrier, not pass
// silently, and a namespace added by a later release must extend this audit
// in the same change.
var (
	knownRootEntries     = []string{"keystore", "work"}
	knownKeystoreEntries = []string{
		"beacon",
		"beacon-quarantine",
		"tbtc",
		"tbtc-quarantine",
	}
	knownWorkEntries = []string{"participation", "tbtc"}
)

// tbtcWorkPreparamsMarker classifies tECDSA pre-parameter pool records inside
// the tBTC work namespace; the pool is regenerable material, not ceremony
// state.
const tbtcWorkPreparamsMarker = "/preparams/"

type fileRecord struct {
	// Path is relative to the storage root.
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	// SHA256 is the checksum of the at-rest bytes. Key-holding files are
	// encrypted at rest, so the checksum commits to the snapshot content
	// without exposing key material.
	SHA256 string `json:"sha256"`
}

type namespaceInventory struct {
	Name    string       `json:"name"`
	Present bool         `json:"present"`
	Files   []fileRecord `json:"files"`
}

// snapshotIdentity commits the manifest to one exact snapshot: the aggregate
// checksum binds every inventoried file, and the root mode records the access
// controls the snapshot was audited under.
type snapshotIdentity struct {
	Path            string `json:"path"`
	RootMode        string `json:"root_mode"`
	TotalFiles      int    `json:"total_files"`
	TotalBytes      int64  `json:"total_bytes"`
	AggregateSHA256 string `json:"aggregate_sha256"`
}

// evidenceRecord references one externally produced rollback-evidence input.
// The audit records the reference and its checksum, validates the record
// against its schema, and binds it to this exact snapshot; a record that
// fails validation stays a rollback blocker exactly like a missing one.
type evidenceRecord struct {
	Name     string `json:"name"`
	Supplied bool   `json:"supplied"`
	Valid    bool   `json:"valid"`
	Path     string `json:"path,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// evidenceSchemaVersion versions the external rollback-evidence record
// schemas this audit accepts.
const evidenceSchemaVersion uint32 = 4

// evidenceFutureSkewAllowance bounds how far in the future an evidence
// record's generation time may lie relative to this audit before it is a
// violation; it absorbs ordinary clock skew between the evidence generator
// and the audit host.
const evidenceFutureSkewAllowance = 5 * time.Minute

// evidenceEnvelope is the common header of every external rollback-evidence
// record. The snapshot binding makes a record usable for exactly one audited
// snapshot: evidence generated for different storage cannot authorize this
// rollback.
type evidenceEnvelope struct {
	SchemaVersion           uint32    `json:"schema_version"`
	EvidenceType            string    `json:"evidence_type"`
	GeneratedAt             time.Time `json:"generated_at"`
	SnapshotAggregateSHA256 string    `json:"snapshot_aggregate_sha256"`
}

// chainReconciliationEvidence records the on-chain wallet/group registration
// and DKG settlement state for every persisted group in the snapshot.
type chainReconciliationEvidence struct {
	evidenceEnvelope

	EthereumChainID string `json:"ethereum_chain_id"`
	Wallets         []struct {
		WalletStorageKey string `json:"wallet_storage_key"`
		WalletID         string `json:"wallet_id"`
		Registered       bool   `json:"registered"`
		// DKGSettlement is the wallet's DKG settlement state on chain:
		// "approved" is the only state that permits its persisted signers in
		// the prior binary's active scan.
		DKGSettlement string `json:"dkg_settlement"`
	} `json:"wallets"`
	BeaconGroups []struct {
		GroupPublicKey string `json:"group_public_key"`
		Registered     bool   `json:"registered"`
	} `json:"beacon_groups"`
}

// bitcoinReconciliationEvidence records every pending Bitcoin transaction of
// the audited wallets and its mempool/chain state.
type bitcoinReconciliationEvidence struct {
	evidenceEnvelope

	BitcoinNetwork string `json:"bitcoin_network"`
	// Complete attests the generator enumerated every pending transaction; an
	// explicitly incomplete reconciliation cannot authorize the barrier.
	Complete            bool `json:"complete"`
	PendingTransactions []struct {
		TransactionHash string `json:"transaction_hash"`
		State           string `json:"state"`
	} `json:"pending_transactions"`
}

// quiescenceReportEvidence records the permits active at process quiescence
// and each one's terminal outcome. The quiescing node also attests its own
// exact artifact identity — release version and revision — and the compiled
// epoch and armed cutover block it quiesced under, so the report cannot vouch
// for the state of a different candidate build or cutover schedule.
type quiescencePermitEvidence struct {
	Ceremony            string `json:"ceremony"`
	Mode                string `json:"mode"`
	CanonicalStartBlock uint64 `json:"canonical_start_block"`
	WorkID              string `json:"work_id"`
	PermitID            string `json:"permit_id"`
	Outcome             string `json:"outcome"`
}

type quiescenceReportEvidence struct {
	evidenceEnvelope

	ReleaseVersion            string                     `json:"release_version"`
	ReleaseRevision           string                     `json:"release_revision"`
	ReleaseEpoch              string                     `json:"release_epoch"`
	CutoverBlock              uint64                     `json:"cutover_block"`
	QuiesceCause              string                     `json:"quiesce_cause"`
	ActivePermitsAtQuiescence []quiescencePermitEvidence `json:"active_permits_at_quiescence"`
}

// priorReaderCompatibilityEvidence records the tested prior release and its
// result against every schema this release writes, including loading and
// signing with a wallet created after the cutover block. Both sides of the
// test are pinned exactly: the prior artifact that performed the reads and
// the current release artifact that wrote the tested schemas, each with its
// version, revision, and immutable image digest.
type priorReaderCompatibilityEvidence struct {
	evidenceEnvelope

	PriorVersion       string `json:"prior_version"`
	PriorRevision      string `json:"prior_revision"`
	PriorImageDigest   string `json:"prior_image_digest"`
	ReleaseVersion     string `json:"release_version"`
	ReleaseRevision    string `json:"release_revision"`
	ReleaseImageDigest string `json:"release_image_digest"`
	SchemaResults      []struct {
		Schema     string `json:"schema"`
		Compatible bool   `json:"compatible"`
	} `json:"schema_results"`
}

// The prior-reader compatibility evidence must cover every schema whose
// unreadability makes the prior-binary rollback an unacceptable mechanism.
var requiredPriorReaderSchemas = []string{
	"beacon_membership",
	"tbtc_membership",
	"post_cutover_wallet_load_and_sign",
}

// Valid DKG settlement states of a reconciled tBTC wallet. "approved" is the
// only state that permits persisted active signers; "none" — no DKG result
// on chain references the wallet — is the only state that permits a
// quarantined-only share, because a pending or challenged result may still
// settle into an on-chain wallet whose share the prior binary cannot load.
var validDKGSettlementStates = map[string]struct{}{
	"approved":   {},
	"pending":    {},
	"challenged": {},
	"none":       {},
}

// Valid terminal states of a reconciled pending Bitcoin transaction.
var validBitcoinTransactionStates = map[string]struct{}{
	"signed":    {},
	"broadcast": {},
	"mined":     {},
	"absent":    {},
}

// Valid terminal outcomes of a permit active at quiescence.
var validQuiescencePermitOutcomes = map[string]struct{}{
	"completed":   {},
	"quarantined": {},
	"exhausted":   {},
}

type beaconMembershipRecord struct {
	GroupPublicKey string `json:"group_public_key"`
	MemberIndex    uint8  `json:"member_index"`
	ChannelName    string `json:"channel_name"`
}

type beaconQuarantineRecord struct {
	registry.QuarantinedSignerMetadata

	// HasMembershipRecord reports whether the preserved membership bytes
	// accompany the metadata; metadata without the membership means the key
	// material was lost and the record is evidence only.
	HasMembershipRecord bool `json:"has_membership_record"`
}

// tbtcWalletRecord summarizes the decoded signer records of one wallet in the
// tBTC active namespace.
type tbtcWalletRecord struct {
	WalletStorageKey string `json:"wallet_storage_key"`
	// WalletID is the ECDSA wallet ID derived from the decoded wallet public
	// key — the identity chain reconciliation evidence must match exactly.
	WalletID         string  `json:"wallet_id"`
	MemberIndexes    []uint8 `json:"member_indexes"`
	SigningGroupSize int     `json:"signing_group_size"`
}

type tbtcQuarantineRecord struct {
	tbtc.QuarantinedSignerMetadata

	// WalletStorageKey is the quarantine directory the output was preserved
	// under — the same public-key-derived key the active namespace uses — so
	// chain reconciliation can match quarantined and active state of the
	// same wallet one-to-one.
	WalletStorageKey string `json:"wallet_storage_key"`
	// SignerWalletID is the ECDSA wallet ID derived from the preserved
	// signer's decoded public key. Unlike the metadata's wallet ID — recorded
	// best-effort at preservation time — it is derived from the key material
	// itself, so it stays the authoritative identity for chain
	// reconciliation when the metadata half is incomplete.
	SignerWalletID string `json:"signer_wallet_id,omitempty"`
	// HasMembershipRecord reports whether the preserved signer bytes
	// accompany the metadata; metadata without the signer means the key
	// material was lost and the record is evidence only.
	HasMembershipRecord bool `json:"has_membership_record"`
}

type manifest struct {
	SchemaVersion uint32           `json:"schema_version"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Snapshot      snapshotIdentity `json:"snapshot"`
	// Interpreted reports whether the storage password was supplied and the
	// beacon and tBTC namespaces were decoded; without it the manifest is a
	// raw inventory only.
	Interpreted bool                 `json:"interpreted"`
	Namespaces  []namespaceInventory `json:"namespaces"`

	BeaconActiveMemberships  []beaconMembershipRecord `json:"beacon_active_memberships,omitempty"`
	BeaconQuarantinedOutputs []beaconQuarantineRecord `json:"beacon_quarantined_outputs,omitempty"`
	TBTCActiveWallets        []tbtcWalletRecord       `json:"tbtc_active_wallets,omitempty"`
	TBTCQuarantinedOutputs   []tbtcQuarantineRecord   `json:"tbtc_quarantined_outputs,omitempty"`
	// TBTCWorkClassification counts the tBTC work-namespace files by class;
	// an unclassified work record is additionally a finding.
	TBTCWorkClassification map[string]int `json:"tbtc_work_classification,omitempty"`
	// QuiescenceSnapshot is decoded from the node-authored encrypted
	// work/participation artifact. External evidence cannot replace this
	// inventory; terminal outcomes reconcile against it.
	QuiescenceSnapshot *participation.QuiescenceSnapshot `json:"quiescence_snapshot,omitempty"`
	// ParticipationTerminalOutcomes is decoded from the node-authored terminal
	// journal beside the gate snapshot. External quiescence evidence must match
	// this record exactly; it cannot author a completed outcome.
	ParticipationTerminalOutcomes *participation.TerminalOutcomeJournal `json:"participation_terminal_outcomes,omitempty"`

	// Findings lists every inconsistency; an empty list with Interpreted true
	// means the namespaces are internally consistent.
	Findings []string `json:"findings"`
	// Consistent is true when interpretation ran and produced no findings.
	// It classifies namespace integrity only and never means rollback-ready
	// by itself.
	Consistent bool `json:"consistent"`

	// ExpectedIdentity records the operator-supplied operational identities
	// the external evidence was bound to; a missing input is a rollback
	// blocker, never a silently skipped check.
	ExpectedIdentity expectedIdentityRecord `json:"expected_identity"`

	// ExternalEvidence records the externally produced rollback inputs this
	// offline tool cannot derive; RollbackBlockers names every one still
	// missing, plus any finding that blocks the barrier.
	ExternalEvidence     []evidenceRecord `json:"external_evidence"`
	RollbackBlockers     []string         `json:"rollback_blockers"`
	RollbackBarrierReady bool             `json:"rollback_barrier_ready"`
}

// expectedIdentityRecord is the manifest's evidence trail of the expected
// operational identities the audit ran with.
type expectedIdentityRecord struct {
	EthereumChainID    string `json:"ethereum_chain_id,omitempty"`
	BitcoinNetwork     string `json:"bitcoin_network,omitempty"`
	PriorVersion       string `json:"prior_version,omitempty"`
	PriorRevision      string `json:"prior_revision,omitempty"`
	PriorImageDigest   string `json:"prior_image_digest,omitempty"`
	ReleaseVersion     string `json:"release_version,omitempty"`
	ReleaseRevision    string `json:"release_revision,omitempty"`
	ReleaseImageDigest string `json:"release_image_digest,omitempty"`
	ReleaseEpoch       string `json:"release_epoch,omitempty"`
	CutoverBlock       uint64 `json:"cutover_block,omitempty"`
	MaxEvidenceAge     string `json:"max_evidence_age,omitempty"`
}

// evidenceInputs carries the externally produced rollback-evidence references
// supplied on the command line.
type evidenceInputs struct {
	chainReconciliation      string
	bitcoinReconciliation    string
	quiescenceReport         string
	priorReaderCompatibility string
}

// expectedIdentityInputs carries the operator-supplied expected operational
// identities the audit binds the external evidence to. Every rollback-grade
// run must supply all of them: without an expected chain, network, exact
// prior and current artifact identities, immutable image digests, compiled
// epoch, cutover block, and freshness bound, schema-valid evidence generated
// against the wrong target — or long before the rollback decision — would
// pass. A missing input is a rollback blocker, not a skipped check.
type expectedIdentityInputs struct {
	ethereumChainID    string
	bitcoinNetwork     string
	priorVersion       string
	priorRevision      string
	priorImageDigest   string
	releaseVersion     string
	releaseRevision    string
	releaseImageDigest string
	releaseEpoch       string
	cutoverBlock       uint64
	maxEvidenceAge     time.Duration
}

func main() {
	var storageDir string
	var outputPath string
	var evidence evidenceInputs
	var expected expectedIdentityInputs

	flag.StringVar(
		&storageDir,
		"storage-snapshot",
		"",
		"path to a snapshot copy of the node's storage directory (required); "+
			"never point this at a live node's storage",
	)
	flag.StringVar(
		&outputPath,
		"output",
		"",
		"write the manifest to this file instead of stdout",
	)
	flag.StringVar(
		&evidence.chainReconciliation,
		"chain-reconciliation-evidence",
		"",
		"path to the Ethereum reconciliation record: wallet/group "+
			"registration and DKG settlement state for every persisted group",
	)
	flag.StringVar(
		&evidence.bitcoinReconciliation,
		"bitcoin-reconciliation-evidence",
		"",
		"path to the Bitcoin reconciliation record: every pending "+
			"transaction and whether it is signed, broadcast, mined, or absent",
	)
	flag.StringVar(
		&evidence.quiescenceReport,
		"quiescence-report",
		"",
		"path to the external quiescence reconciliation record: it must match "+
			"the node-authored gate inventory and terminal-outcome journal",
	)
	flag.StringVar(
		&evidence.priorReaderCompatibility,
		"prior-reader-compatibility-evidence",
		"",
		"path to the prior-release reader compatibility record: the tested "+
			"prior version and its result against every schema this release "+
			"writes",
	)
	flag.StringVar(
		&expected.ethereumChainID,
		"expected-ethereum-chain-id",
		"",
		"the Ethereum chain ID the rollback targets; the chain "+
			"reconciliation evidence must record exactly this chain",
	)
	flag.StringVar(
		&expected.bitcoinNetwork,
		"expected-bitcoin-network",
		"",
		"the Bitcoin network the rollback targets; the Bitcoin "+
			"reconciliation evidence must record exactly this network",
	)
	flag.StringVar(
		&expected.priorVersion,
		"expected-prior-version",
		"",
		"the exact prior release version the rollback restores; the "+
			"prior-reader compatibility evidence must record exactly this "+
			"version",
	)
	flag.StringVar(
		&expected.priorRevision,
		"expected-prior-revision",
		"",
		"the exact prior release revision the rollback restores; the "+
			"prior-reader compatibility evidence must record exactly this "+
			"revision",
	)
	flag.StringVar(
		&expected.priorImageDigest,
		"expected-prior-image-digest",
		"",
		"the immutable sha256 image digest of the prior release artifact the "+
			"rollback restores; the prior-reader compatibility evidence must "+
			"record exactly this digest",
	)
	flag.StringVar(
		&expected.releaseVersion,
		"expected-release-version",
		"",
		"the exact version of the release being rolled back; the quiescence "+
			"report and prior-reader compatibility evidence must record "+
			"exactly this version",
	)
	flag.StringVar(
		&expected.releaseRevision,
		"expected-release-revision",
		"",
		"the exact revision of the release being rolled back; the quiescence "+
			"report and prior-reader compatibility evidence must record "+
			"exactly this revision",
	)
	flag.StringVar(
		&expected.releaseImageDigest,
		"expected-release-image-digest",
		"",
		"the immutable sha256 image digest of the release artifact being "+
			"rolled back; the prior-reader compatibility evidence must record "+
			"exactly this digest",
	)
	flag.StringVar(
		&expected.releaseEpoch,
		"expected-release-epoch",
		"",
		"the release epoch the audited state was written under; it must "+
			"match this audit build's compiled epoch and the quiescence "+
			"report's recorded epoch",
	)
	flag.Uint64Var(
		&expected.cutoverBlock,
		"expected-cutover-block",
		0,
		"the cutover block the audited deployment was armed with; the "+
			"quiescence report and every quarantined output must record "+
			"exactly this block",
	)
	flag.DurationVar(
		&expected.maxEvidenceAge,
		"max-evidence-age",
		24*time.Hour,
		"the maximum age of every supplied evidence record; older evidence "+
			"reflects a state the rollback decision cannot rely on",
	)
	flag.Parse()

	if storageDir == "" {
		fmt.Fprintln(os.Stderr, "the --storage-snapshot flag is required")
		flag.Usage()
		os.Exit(2)
	}

	password := os.Getenv(config.EthereumPasswordEnvVariable)

	auditManifest, err := runAudit(storageDir, password, evidence, expected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit failed: [%v]\n", err)
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(auditManifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot encode the manifest: [%v]\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')

	if outputPath != "" {
		// #nosec G703 G304 (manifest destination provided as the operator's
		// explicit output flag)
		if err := os.WriteFile(outputPath, encoded, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write the manifest: [%v]\n", err)
			os.Exit(1)
		}
	} else {
		if _, err := os.Stdout.Write(encoded); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write the manifest: [%v]\n", err)
			os.Exit(1)
		}
	}

	if !auditManifest.Consistent || !auditManifest.RollbackBarrierReady {
		os.Exit(3)
	}
}

// auditRun serializes all finding collection: interpretation drains
// persistence error channels concurrently with the descriptor loops, so every
// mutation of the manifest findings goes through one mutex.
type auditRun struct {
	mu       sync.Mutex
	manifest *manifest
	expected expectedIdentityInputs
}

func (r *auditRun) finding(format string, args ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.manifest.Findings = append(
		r.manifest.Findings,
		fmt.Sprintf(format, args...),
	)
}

// runAudit produces the audit manifest for the given storage snapshot. An
// empty password skips interpretation and produces a raw inventory whose
// missing interpretation is itself a rollback blocker, exactly like a
// missing expected-identity input.
func runAudit(
	storageDir string,
	password string,
	evidence evidenceInputs,
	expected expectedIdentityInputs,
) (*manifest, error) {
	info, err := os.Stat(storageDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read the storage snapshot: [%w]", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf(
			"the storage snapshot [%s] is not a directory",
			storageDir,
		)
	}

	run := &auditRun{
		manifest: &manifest{
			SchemaVersion: manifestSchemaVersion,
			GeneratedAt:   time.Now().UTC(),
			Snapshot: snapshotIdentity{
				Path:     storageDir,
				RootMode: info.Mode().String(),
			},
			ExpectedIdentity: expectedIdentityRecord{
				EthereumChainID:    expected.ethereumChainID,
				BitcoinNetwork:     expected.bitcoinNetwork,
				PriorVersion:       expected.priorVersion,
				PriorRevision:      expected.priorRevision,
				PriorImageDigest:   expected.priorImageDigest,
				ReleaseVersion:     expected.releaseVersion,
				ReleaseRevision:    expected.releaseRevision,
				ReleaseImageDigest: expected.releaseImageDigest,
				ReleaseEpoch:       expected.releaseEpoch,
				CutoverBlock:       expected.cutoverBlock,
				MaxEvidenceAge:     expected.maxEvidenceAge.String(),
			},
		},
		expected: expected,
	}
	auditManifest := run.manifest

	if err := run.scanUnexpectedEntries(storageDir); err != nil {
		return nil, err
	}

	for _, namespace := range []string{
		beaconKeystoreNamespace,
		beaconQuarantineNamespace,
		tbtcKeystoreNamespace,
		tbtcQuarantineNamespace,
		tbtcWorkNamespace,
		participationWorkNamespace,
	} {
		inventory, err := inventoryNamespace(storageDir, namespace)
		if err != nil {
			return nil, err
		}
		auditManifest.Namespaces = append(auditManifest.Namespaces, inventory)
	}
	sealSnapshotIdentity(auditManifest)

	classifyTBTCWork(run)

	if password != "" {
		auditManifest.Interpreted = true
		if err := interpretKeyStoreNamespaces(
			storageDir,
			password,
			run,
		); err != nil {
			return nil, err
		}
	} else {
		run.finding(
			"interpretation skipped: the [%s] environment variable is "+
				"not set",
			config.EthereumPasswordEnvVariable,
		)
	}

	auditManifest.Consistent = auditManifest.Interpreted &&
		len(auditManifest.Findings) == 0

	recordMissingExpectedIdentity(run)
	if err := recordExternalEvidence(run, evidence); err != nil {
		return nil, err
	}
	if !auditManifest.Consistent {
		auditManifest.RollbackBlockers = append(
			auditManifest.RollbackBlockers,
			"the storage snapshot is not interpreted as consistent; every "+
				"finding must be resolved or the ambiguous state quarantined",
		)
	}
	auditManifest.RollbackBarrierReady =
		len(auditManifest.RollbackBlockers) == 0

	return auditManifest, nil
}

// scanUnexpectedEntries flags every directory entry the expected storage
// layout does not contain, at the snapshot root and inside the keystore and
// work roots. An absent root is not a finding — a node that never ran tBTC
// has no work directory — but an entry this audit cannot classify is.
func (r *auditRun) scanUnexpectedEntries(storageDir string) error {
	levels := []struct {
		relative string
		known    []string
	}{
		{".", knownRootEntries},
		{"keystore", knownKeystoreEntries},
		{"work", knownWorkEntries},
	}

	for _, level := range levels {
		entries, err := os.ReadDir(filepath.Join(storageDir, level.relative))
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return fmt.Errorf(
				"cannot scan the [%s] level of the snapshot: [%w]",
				level.relative,
				err,
			)
		}

		for _, entry := range entries {
			known := false
			for _, name := range level.known {
				if entry.Name() == name {
					known = true
					break
				}
			}
			if !known {
				r.finding(
					"unexpected entry [%s] under [%s]: this audit cannot "+
						"classify it and unclassifiable state blocks the "+
						"rollback barrier",
					entry.Name(),
					level.relative,
				)
			}
		}
	}

	return nil
}

// inventoryNamespace walks one namespace and records every regular file with
// the checksum of its at-rest bytes. A missing namespace is recorded as
// absent, not an error: a node that never quarantined anything has no
// quarantine directory.
func inventoryNamespace(
	storageDir string,
	namespace string,
) (namespaceInventory, error) {
	inventory := namespaceInventory{Name: namespace}

	root := filepath.Join(storageDir, filepath.FromSlash(namespace))
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return inventory, nil
	} else if err != nil {
		return inventory, fmt.Errorf(
			"cannot read namespace [%s]: [%w]",
			namespace,
			err,
		)
	}
	inventory.Present = true

	err := filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		err error,
	) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		// A symlink or other non-regular entry could point outside the
		// snapshot; such a snapshot cannot be certified.
		if !entry.Type().IsRegular() {
			return fmt.Errorf(
				"cannot inventory [%s]: non-regular entry in the storage "+
					"snapshot",
				path,
			)
		}

		// #nosec G304 G122 (path walked from the snapshot root and
		// non-regular entries rejected above; checksumming every snapshot
		// file is this audit's purpose)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read [%s]: [%w]", path, err)
		}
		checksum := sha256.Sum256(content)

		relative, err := filepath.Rel(storageDir, path)
		if err != nil {
			return err
		}

		inventory.Files = append(inventory.Files, fileRecord{
			Path:   filepath.ToSlash(relative),
			Bytes:  int64(len(content)),
			SHA256: hex.EncodeToString(checksum[:]),
		})
		return nil
	})
	if err != nil {
		return inventory, fmt.Errorf(
			"cannot inventory namespace [%s]: [%w]",
			namespace,
			err,
		)
	}

	sort.Slice(inventory.Files, func(i, j int) bool {
		return inventory.Files[i].Path < inventory.Files[j].Path
	})

	return inventory, nil
}

// sealSnapshotIdentity derives the aggregate snapshot checksum from the
// sorted per-file checksums, so two audits agree on the snapshot identity
// exactly when they saw byte-identical namespace content.
func sealSnapshotIdentity(auditManifest *manifest) {
	aggregate := sha256.New()
	for _, namespace := range auditManifest.Namespaces {
		for _, file := range namespace.Files {
			fmt.Fprintf(aggregate, "%s:%s\n", file.Path, file.SHA256)
			auditManifest.Snapshot.TotalFiles++
			auditManifest.Snapshot.TotalBytes += file.Bytes
		}
	}
	auditManifest.Snapshot.AggregateSHA256 =
		hex.EncodeToString(aggregate.Sum(nil))
}

// classifyTBTCWork classifies the tBTC work namespace from its inventory:
// tECDSA pre-parameter pool records are regenerable material, and anything
// else is unclassifiable work state and therefore a finding.
func classifyTBTCWork(r *auditRun) {
	for _, namespace := range r.manifest.Namespaces {
		if namespace.Name != tbtcWorkNamespace || !namespace.Present {
			continue
		}

		classification := make(map[string]int)
		for _, file := range namespace.Files {
			if strings.Contains(file.Path, tbtcWorkPreparamsMarker) {
				classification["tecdsa_preparams"]++
				continue
			}
			classification["unclassified"]++
			r.finding(
				"tbtc work record [%s] is not a recognized work class",
				file.Path,
			)
		}
		if len(classification) > 0 {
			r.manifest.TBTCWorkClassification = classification
		}
	}
}

// isImmutableImageDigest reports whether the reference is an immutable
// sha256 image digest — "sha256:" followed by 64 hex characters. Tags and
// other mutable references cannot pin a rollback artifact.
func isImmutableImageDigest(reference string) bool {
	digest, ok := strings.CutPrefix(reference, "sha256:")
	if !ok || len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// isCanonicalSHA256Hex reports whether value is the canonical textual form of
// a SHA-256 digest: exactly 64 lowercase hexadecimal characters. DKG work
// identities and quarantined seed hashes use this form so case aliases or
// truncated values cannot make unrelated work compare equal during rollback
// reconciliation.
func isCanonicalSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// isStableEvidenceID reports whether value can be used as a stable
// chain-work or local-permit identity without colliding with the separators
// used by the rehearsal and audit evidence. The driver accepts the same
// alphabet for non-membership identities.
func isStableEvidenceID(value string) bool {
	if value == "" || !isASCIIAlphaNumeric(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		character := value[i]
		if !isASCIIAlphaNumeric(character) &&
			character != '_' &&
			character != '.' &&
			character != ':' &&
			character != '-' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(character byte) bool {
	return (character >= '0' && character <= '9') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z')
}

// isCanonicalMemberIndex reports whether value is the canonical decimal
// representation of a real protocol member index. Group indexes start at one;
// leading zeroes and values beyond the one-byte MemberIndex range are aliases
// or invalid memberships and therefore cannot identify a local permit.
func isCanonicalMemberIndex(value string) bool {
	memberIndex, err := strconv.ParseUint(value, 10, 8)
	if err != nil || memberIndex == 0 || memberIndex > group.MaxMemberIndex {
		return false
	}
	return strconv.FormatUint(memberIndex, 10) == value
}

// recordMissingExpectedIdentity turns every unsupplied expected-identity
// input into a rollback blocker — evidence that is not bound to an explicit
// operational target can approve a rollback of the wrong chain, network,
// artifact, or cutover schedule — and every unusable one likewise: a mutable
// image reference cannot pin an artifact, and an expected epoch differing
// from this audit build's compiled epoch means the wrong audit tool is
// examining the state.
func recordMissingExpectedIdentity(r *auditRun) {
	blocked := []struct {
		when    bool
		blocker string
	}{
		{
			when: r.expected.ethereumChainID == "",
			blocker: "the expected Ethereum chain ID is not supplied: the " +
				"chain reconciliation evidence cannot be bound to the " +
				"rollback's operational target",
		},
		{
			when: r.expected.bitcoinNetwork == "",
			blocker: "the expected Bitcoin network is not supplied: the " +
				"Bitcoin reconciliation evidence cannot be bound to the " +
				"rollback's operational target",
		},
		{
			when: r.expected.priorVersion == "",
			blocker: "the expected prior version is not supplied: the " +
				"prior-reader compatibility evidence cannot be bound to the " +
				"exact restored artifact",
		},
		{
			when: r.expected.priorRevision == "",
			blocker: "the expected prior revision is not supplied: the " +
				"prior-reader compatibility evidence cannot be bound to the " +
				"exact restored artifact",
		},
		{
			when: r.expected.priorImageDigest == "",
			blocker: "the expected prior image digest is not supplied: the " +
				"prior-reader compatibility evidence cannot be bound to the " +
				"exact restored image",
		},
		{
			when: r.expected.priorImageDigest != "" &&
				!isImmutableImageDigest(r.expected.priorImageDigest),
			blocker: fmt.Sprintf(
				"the expected prior image digest [%s] is not an immutable "+
					"sha256 image digest: a mutable reference cannot pin the "+
					"restored artifact",
				r.expected.priorImageDigest,
			),
		},
		{
			when: r.expected.releaseVersion == "",
			blocker: "the expected release version is not supplied: the " +
				"evidence cannot be bound to the exact rolled-back artifact",
		},
		{
			when: r.expected.releaseRevision == "",
			blocker: "the expected release revision is not supplied: the " +
				"evidence cannot be bound to the exact rolled-back artifact",
		},
		{
			when: r.expected.releaseImageDigest == "",
			blocker: "the expected release image digest is not supplied: the " +
				"evidence cannot be bound to the exact rolled-back image",
		},
		{
			when: r.expected.releaseImageDigest != "" &&
				!isImmutableImageDigest(r.expected.releaseImageDigest),
			blocker: fmt.Sprintf(
				"the expected release image digest [%s] is not an immutable "+
					"sha256 image digest: a mutable reference cannot pin the "+
					"rolled-back artifact",
				r.expected.releaseImageDigest,
			),
		},
		{
			when: r.expected.releaseEpoch == "",
			blocker: "the expected release epoch is not supplied: the " +
				"audited state cannot be bound to the release that wrote it",
		},
		{
			when: r.expected.releaseEpoch != "" &&
				r.expected.releaseEpoch != participation.CompiledEpoch.String(),
			blocker: fmt.Sprintf(
				"the expected release epoch [%s] does not match this audit "+
					"build's compiled epoch [%s]: the audit must be built from "+
					"the audited release",
				r.expected.releaseEpoch,
				participation.CompiledEpoch,
			),
		},
		{
			when: r.expected.cutoverBlock == 0,
			blocker: "the expected cutover block is not supplied: the " +
				"audited state cannot be bound to the armed cutover schedule",
		},
		{
			when: r.expected.maxEvidenceAge <= 0,
			blocker: "no evidence freshness bound is supplied: arbitrarily " +
				"old evidence cannot support a rollback decision",
		},
	}

	for _, input := range blocked {
		if input.when {
			r.manifest.RollbackBlockers = append(
				r.manifest.RollbackBlockers,
				input.blocker,
			)
		}
	}
}

// recordExternalEvidence records every externally produced rollback input,
// validates each supplied record against its mandatory schema and this exact
// snapshot, and turns each missing or invalid one into a rollback blocker. A
// supplied reference that cannot be read is an input error: fail fast instead
// of recording evidence that does not exist.
func recordExternalEvidence(r *auditRun, evidence evidenceInputs) error {
	inputs := []struct {
		name     string
		path     string
		missing  string
		validate func([]byte) []string
	}{
		{
			name: "chain_reconciliation",
			path: evidence.chainReconciliation,
			missing: "chain reconciliation evidence not supplied: on-chain " +
				"wallet/group registration and DKG settlement state are " +
				"unverified",
			validate: r.validateChainReconciliationEvidence,
		},
		{
			name: "bitcoin_reconciliation",
			path: evidence.bitcoinReconciliation,
			missing: "bitcoin reconciliation evidence not supplied: pending " +
				"transaction state is unverified",
			validate: r.validateBitcoinReconciliationEvidence,
		},
		{
			name: "quiescence_report",
			path: evidence.quiescenceReport,
			missing: "quiescence report not supplied: the at-quiescence gate " +
				"inventory and terminal outcomes are unverified",
			validate: r.validateQuiescenceReportEvidence,
		},
		{
			name: "prior_reader_compatibility",
			path: evidence.priorReaderCompatibility,
			missing: "prior-reader compatibility evidence not supplied: the " +
				"prior release's ability to read every persisted schema is " +
				"unverified",
			validate: r.validatePriorReaderCompatibilityEvidence,
		},
	}

	for _, input := range inputs {
		record := evidenceRecord{Name: input.name}
		if input.path == "" {
			r.manifest.ExternalEvidence = append(
				r.manifest.ExternalEvidence,
				record,
			)
			r.manifest.RollbackBlockers = append(
				r.manifest.RollbackBlockers,
				input.missing,
			)
			continue
		}

		content, err := os.ReadFile(input.path)
		if err != nil {
			return fmt.Errorf(
				"cannot read the supplied [%s] evidence: [%w]",
				input.name,
				err,
			)
		}
		checksum := sha256.Sum256(content)

		record.Supplied = true
		record.Path = input.path
		record.SHA256 = hex.EncodeToString(checksum[:])

		violations := input.validate(content)
		record.Valid = len(violations) == 0
		for _, violation := range violations {
			r.manifest.RollbackBlockers = append(
				r.manifest.RollbackBlockers,
				fmt.Sprintf(
					"[%s] evidence fails validation: %s",
					input.name,
					violation,
				),
			)
		}

		r.manifest.ExternalEvidence = append(
			r.manifest.ExternalEvidence,
			record,
		)
	}

	return nil
}

// validateEnvelope checks the common header of one evidence record against
// the expected type and this audit's snapshot identity.
func (r *auditRun) validateEnvelope(
	envelope evidenceEnvelope,
	expectedType string,
) []string {
	var violations []string

	if envelope.SchemaVersion != evidenceSchemaVersion {
		violations = append(violations, fmt.Sprintf(
			"schema version [%d], expected [%d]",
			envelope.SchemaVersion,
			evidenceSchemaVersion,
		))
	}
	if envelope.EvidenceType != expectedType {
		violations = append(violations, fmt.Sprintf(
			"evidence type [%s], expected [%s]",
			envelope.EvidenceType,
			expectedType,
		))
	}
	if envelope.GeneratedAt.IsZero() {
		violations = append(violations, "the generation time is missing")
	} else if r.expected.maxEvidenceAge > 0 {
		// Freshness is measured against this audit's own generation time so
		// the manifest and its verdict stay reproducible from the recorded
		// inputs. Evidence from the future signals a clock problem in the
		// generator and cannot be trusted either.
		age := r.manifest.GeneratedAt.Sub(envelope.GeneratedAt)
		if age > r.expected.maxEvidenceAge {
			violations = append(violations, fmt.Sprintf(
				"generated [%s] before this audit, exceeding the [%s] "+
					"evidence freshness bound",
				age.Round(time.Second),
				r.expected.maxEvidenceAge,
			))
		}
		if age < -evidenceFutureSkewAllowance {
			violations = append(violations, fmt.Sprintf(
				"generated [%s] after this audit, beyond the [%s] clock "+
					"skew allowance",
				(-age).Round(time.Second),
				evidenceFutureSkewAllowance,
			))
		}
	}
	if envelope.SnapshotAggregateSHA256 !=
		r.manifest.Snapshot.AggregateSHA256 {
		violations = append(violations, fmt.Sprintf(
			"bound to snapshot [%s], not to this audited snapshot [%s]",
			envelope.SnapshotAggregateSHA256,
			r.manifest.Snapshot.AggregateSHA256,
		))
	}

	return violations
}

// exactIdentityViolations checks one identity field of an evidence record:
// it must be present, and it must be exactly the expected value when an
// expectation is supplied.
func exactIdentityViolations(
	description string,
	value string,
	expected string,
) []string {
	if value == "" {
		return []string{fmt.Sprintf("the %s is missing", description)}
	}
	if expected != "" && value != expected {
		return []string{fmt.Sprintf(
			"%s [%s], expected [%s]",
			description,
			value,
			expected,
		)}
	}
	return nil
}

// digestViolations checks one image-digest field of an evidence record: it
// must be present, immutable — a sha256 digest, never a tag — and exactly
// the expected digest when an expectation is supplied.
func digestViolations(
	description string,
	value string,
	expected string,
) []string {
	if value == "" {
		return []string{fmt.Sprintf("the %s is missing", description)}
	}
	var violations []string
	if !isImmutableImageDigest(value) {
		violations = append(violations, fmt.Sprintf(
			"the %s [%s] is not an immutable sha256 image digest",
			description,
			value,
		))
	}
	if expected != "" && value != expected {
		violations = append(violations, fmt.Sprintf(
			"%s [%s], expected [%s]",
			description,
			value,
			expected,
		))
	}
	return violations
}

// validateChainReconciliationEvidence checks the Ethereum reconciliation
// record: schema, snapshot binding, the expected chain identity, one-to-one
// coverage of every persisted tBTC wallet and beacon group — active and
// quarantined — with no duplicate entries and wallet IDs matching the
// decoded snapshot identities, a settled, registered on-chain state for each
// active wallet, and an explicit no-result settlement for each
// quarantined-only one. A quarantined output whose wallet or group is
// registered on chain is a blocker of its own: the prior binary would run
// that wallet without the preserved share.
func (r *auditRun) validateChainReconciliationEvidence(
	content []byte,
) []string {
	record := &chainReconciliationEvidence{}
	if err := strictUnmarshal(content, record); err != nil {
		return []string{fmt.Sprintf(
			"cannot be decoded as a chain reconciliation record: [%v]",
			err,
		)}
	}

	violations := r.validateEnvelope(
		record.evidenceEnvelope,
		"chain_reconciliation",
	)

	if record.EthereumChainID == "" {
		violations = append(violations, "the Ethereum chain ID is missing")
	} else if r.expected.ethereumChainID != "" &&
		record.EthereumChainID != r.expected.ethereumChainID {
		violations = append(violations, fmt.Sprintf(
			"reconciled against Ethereum chain [%s], expected [%s]",
			record.EthereumChainID,
			r.expected.ethereumChainID,
		))
	}

	wallets := make(map[string]int)
	walletIDs := make(map[string]string)
	for i, wallet := range record.Wallets {
		if wallet.WalletStorageKey == "" || wallet.WalletID == "" {
			violations = append(violations, fmt.Sprintf(
				"wallet entry [%d] is missing its identity",
				i,
			))
			continue
		}
		if _, duplicate := wallets[wallet.WalletStorageKey]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] is reconciled more than once; duplicate "+
					"entries cannot prove one-to-one coverage",
				wallet.WalletStorageKey,
			))
			continue
		}
		if previous, duplicate := walletIDs[wallet.WalletID]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"wallet ID [%s] is claimed by both tbtc wallet [%s] and "+
					"tbtc wallet [%s]",
				wallet.WalletID,
				previous,
				wallet.WalletStorageKey,
			))
			continue
		}
		if _, known := validDKGSettlementStates[wallet.DKGSettlement]; !known {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] has unknown DKG settlement state [%s]",
				wallet.WalletStorageKey,
				wallet.DKGSettlement,
			))
		}
		wallets[wallet.WalletStorageKey] = i
		walletIDs[wallet.WalletID] = wallet.WalletStorageKey
	}
	beaconGroups := make(map[string]int)
	for i, beaconGroup := range record.BeaconGroups {
		if beaconGroup.GroupPublicKey == "" {
			violations = append(violations, fmt.Sprintf(
				"beacon group entry [%d] is missing its group public key",
				i,
			))
			continue
		}
		if _, duplicate := beaconGroups[beaconGroup.GroupPublicKey]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"beacon group [%s] is reconciled more than once; duplicate "+
					"entries cannot prove one-to-one coverage",
				beaconGroup.GroupPublicKey,
			))
			continue
		}
		beaconGroups[beaconGroup.GroupPublicKey] = i
	}

	activeWalletKeys := make(map[string]struct{})
	for _, wallet := range r.manifest.TBTCActiveWallets {
		activeWalletKeys[wallet.WalletStorageKey] = struct{}{}

		i, covered := wallets[wallet.WalletStorageKey]
		if !covered {
			violations = append(violations, fmt.Sprintf(
				"persisted tbtc wallet [%s] is not reconciled",
				wallet.WalletStorageKey,
			))
			continue
		}
		if !record.Wallets[i].Registered {
			violations = append(violations, fmt.Sprintf(
				"persisted tbtc wallet [%s] is not registered on chain",
				wallet.WalletStorageKey,
			))
		}
		if record.Wallets[i].DKGSettlement != "approved" {
			violations = append(violations, fmt.Sprintf(
				"persisted tbtc wallet [%s] has DKG settlement [%s], "+
					"expected [approved]",
				wallet.WalletStorageKey,
				record.Wallets[i].DKGSettlement,
			))
		}
		if wallet.WalletID != "" &&
			record.Wallets[i].WalletID != wallet.WalletID {
			violations = append(violations, fmt.Sprintf(
				"persisted tbtc wallet [%s] is reconciled under wallet ID "+
					"[%s], but its decoded records carry wallet ID [%s]",
				wallet.WalletStorageKey,
				record.Wallets[i].WalletID,
				wallet.WalletID,
			))
		}
	}
	quarantinedWalletKeys := make(map[string]struct{})
	for _, quarantined := range r.manifest.TBTCQuarantinedOutputs {
		quarantinedWalletKeys[quarantined.WalletStorageKey] = struct{}{}

		i, covered := wallets[quarantined.WalletStorageKey]
		if !covered {
			violations = append(violations, fmt.Sprintf(
				"quarantined tbtc wallet [%s] is not reconciled",
				quarantined.WalletStorageKey,
			))
			continue
		}
		if _, active := activeWalletKeys[quarantined.WalletStorageKey]; active {
			// Both namespaces holding the same wallet is already an
			// interpretation finding; the registered state is judged there.
			continue
		}
		if record.Wallets[i].Registered {
			violations = append(violations, fmt.Sprintf(
				"quarantined tbtc wallet [%s] is registered on chain but "+
					"its share is preserved only in quarantine; the prior "+
					"binary would run it without the share",
				quarantined.WalletStorageKey,
			))
		}
		// A quarantined-only share tolerates no DKG result on chain at all:
		// a pending or challenged result may still settle into a wallet the
		// prior binary would run without the share, and an approved one
		// contradicts the quarantine itself.
		if record.Wallets[i].DKGSettlement != "none" {
			violations = append(violations, fmt.Sprintf(
				"quarantined tbtc wallet [%s] has DKG settlement [%s], "+
					"expected [none]",
				quarantined.WalletStorageKey,
				record.Wallets[i].DKGSettlement,
			))
		}
		expectedWalletID := quarantined.SignerWalletID
		if expectedWalletID == "" {
			expectedWalletID = quarantined.WalletID
		}
		if expectedWalletID != "" &&
			record.Wallets[i].WalletID != expectedWalletID {
			violations = append(violations, fmt.Sprintf(
				"quarantined tbtc wallet [%s] is reconciled under wallet ID "+
					"[%s], but its preserved output carries wallet ID [%s]",
				quarantined.WalletStorageKey,
				record.Wallets[i].WalletID,
				expectedWalletID,
			))
		}
	}

	activeBeaconGroups := make(map[string]struct{})
	for _, membership := range r.manifest.BeaconActiveMemberships {
		activeBeaconGroups[membership.GroupPublicKey] = struct{}{}

		i, covered := beaconGroups[membership.GroupPublicKey]
		if !covered {
			violations = append(violations, fmt.Sprintf(
				"persisted beacon group [%s] is not reconciled",
				membership.GroupPublicKey,
			))
			continue
		}
		if !record.BeaconGroups[i].Registered {
			violations = append(violations, fmt.Sprintf(
				"persisted beacon group [%s] is not registered on chain",
				membership.GroupPublicKey,
			))
		}
	}
	quarantinedBeaconGroups := make(map[string]struct{})
	for _, quarantined := range r.manifest.BeaconQuarantinedOutputs {
		quarantinedBeaconGroups[quarantined.GroupPublicKey] = struct{}{}

		i, covered := beaconGroups[quarantined.GroupPublicKey]
		if !covered {
			violations = append(violations, fmt.Sprintf(
				"quarantined beacon group [%s] is not reconciled",
				quarantined.GroupPublicKey,
			))
			continue
		}
		if _, active := activeBeaconGroups[quarantined.GroupPublicKey]; active {
			continue
		}
		if record.BeaconGroups[i].Registered {
			violations = append(violations, fmt.Sprintf(
				"quarantined beacon group [%s] is registered on chain but "+
					"its share is preserved only in quarantine; the prior "+
					"binary would run it without the share",
				quarantined.GroupPublicKey,
			))
		}
	}

	// One-to-one the other way: evidence reconciling state the snapshot does
	// not hold audits a different node — or fabricates coverage — and cannot
	// bind to this rollback.
	for _, wallet := range record.Wallets {
		if wallet.WalletStorageKey == "" {
			continue
		}
		_, active := activeWalletKeys[wallet.WalletStorageKey]
		_, quarantined := quarantinedWalletKeys[wallet.WalletStorageKey]
		if !active && !quarantined {
			violations = append(violations, fmt.Sprintf(
				"reconciles tbtc wallet [%s] that the snapshot does not hold",
				wallet.WalletStorageKey,
			))
		}
	}
	for _, beaconGroup := range record.BeaconGroups {
		if beaconGroup.GroupPublicKey == "" {
			continue
		}
		_, active := activeBeaconGroups[beaconGroup.GroupPublicKey]
		_, quarantined := quarantinedBeaconGroups[beaconGroup.GroupPublicKey]
		if !active && !quarantined {
			violations = append(violations, fmt.Sprintf(
				"reconciles beacon group [%s] that the snapshot does not hold",
				beaconGroup.GroupPublicKey,
			))
		}
	}

	return violations
}

// validateBitcoinReconciliationEvidence checks the Bitcoin reconciliation
// record: schema, snapshot binding, network identity, an attested-complete
// pending set, and a valid terminal state for every pending transaction.
func (r *auditRun) validateBitcoinReconciliationEvidence(
	content []byte,
) []string {
	record := &bitcoinReconciliationEvidence{}
	if err := strictUnmarshal(content, record); err != nil {
		return []string{fmt.Sprintf(
			"cannot be decoded as a bitcoin reconciliation record: [%v]",
			err,
		)}
	}

	violations := r.validateEnvelope(
		record.evidenceEnvelope,
		"bitcoin_reconciliation",
	)

	if record.BitcoinNetwork == "" {
		violations = append(violations, "the Bitcoin network is missing")
	} else if r.expected.bitcoinNetwork != "" &&
		record.BitcoinNetwork != r.expected.bitcoinNetwork {
		violations = append(violations, fmt.Sprintf(
			"reconciled against Bitcoin network [%s], expected [%s]",
			record.BitcoinNetwork,
			r.expected.bitcoinNetwork,
		))
	}
	if !record.Complete {
		violations = append(
			violations,
			"the pending transaction set is not attested complete",
		)
	}
	for i, transaction := range record.PendingTransactions {
		if transaction.TransactionHash == "" {
			violations = append(violations, fmt.Sprintf(
				"pending transaction entry [%d] is missing its hash",
				i,
			))
		}
		if _, ok := validBitcoinTransactionStates[transaction.State]; !ok {
			violations = append(violations, fmt.Sprintf(
				"pending transaction entry [%d] has unknown state [%s]",
				i,
				transaction.State,
			))
		}
	}

	return violations
}

// quarantineIdentity identifies one quarantined local permit. Several DKG
// events can share an anchor and one node can control several members in one
// event, so ceremony, mode, and block are only classifications. The seed hash
// identifies the chain work; the member index identifies the local permit.
type quarantineIdentity struct {
	ceremony            string
	mode                string
	canonicalStartBlock uint64
	workID              string
	permitID            string
}

// cutoverModeViolation applies the release gate's one-value schedule to
// persisted evidence. It is shared by quiescence records and both quarantine
// namespaces so completed and interrupted work are judged by the same
// boundary rule.
func cutoverModeViolation(
	subject string,
	mode string,
	canonicalStartBlock uint64,
	cutoverBlock uint64,
) string {
	legacy := participation.ModeLegacy.String()
	securityV2 := participation.ModeSecurityV2.String()

	if cutoverBlock > 0 && canonicalStartBlock == 0 {
		return fmt.Sprintf(
			"%s has zero canonical anchor under armed cutover block [%d]",
			subject,
			cutoverBlock,
		)
	}

	switch mode {
	case legacy:
		if cutoverBlock > 0 && canonicalStartBlock >= cutoverBlock {
			return fmt.Sprintf(
				"%s claims mode [%s] with canonical anchor [%d] at or "+
					"after cutover block [%d]",
				subject,
				legacy,
				canonicalStartBlock,
				cutoverBlock,
			)
		}
	case securityV2:
		if cutoverBlock == 0 {
			return fmt.Sprintf(
				"%s claims mode [%s] under a disabled all-zero schedule",
				subject,
				securityV2,
			)
		}
		if canonicalStartBlock < cutoverBlock {
			return fmt.Sprintf(
				"%s claims mode [%s] with canonical anchor [%d] before "+
					"cutover block [%d]",
				subject,
				securityV2,
				canonicalStartBlock,
				cutoverBlock,
			)
		}
	default:
		return fmt.Sprintf(
			"%s names unknown protocol mode [%s]",
			subject,
			mode,
		)
	}

	return ""
}

// validateQuiescencePermitIdentity checks the chain-work and local-permit
// portions of one quiescence entry. DKG work is identified by the SHA-256 hash
// of its seed and each DKG or relay-signing permit belongs to one group member;
// other ceremony classes use the stable chain-native/action identifiers
// accepted by the rehearsal driver.
func validateQuiescencePermitIdentity(
	index int,
	permit quiescencePermitEvidence,
) []string {
	violations := make([]string, 0)

	switch permit.Ceremony {
	case string(participation.TBTCDKG),
		string(participation.BeaconDKG):
		if !isCanonicalSHA256Hex(permit.WorkID) {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] chain work identity [%s] is not a "+
					"canonical SHA-256 seed hash of 64 lowercase "+
					"hexadecimal characters",
				index,
				permit.WorkID,
			))
		}
	default:
		if !isStableEvidenceID(permit.WorkID) {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] chain work identity [%s] is not a "+
					"stable evidence identifier",
				index,
				permit.WorkID,
			))
		}
	}

	switch permit.Ceremony {
	case string(participation.TBTCDKG),
		string(participation.BeaconDKG),
		string(participation.BeaconRelaySigning):
		if !isCanonicalMemberIndex(permit.PermitID) {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] local permit identity [%s] is not a "+
					"canonical protocol member index from 1 through %d",
				index,
				permit.PermitID,
				group.MaxMemberIndex,
			))
		}
	default:
		if !isStableEvidenceID(permit.PermitID) {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] local permit identity [%s] is not a "+
					"stable evidence identifier",
				index,
				permit.PermitID,
			))
		}
	}

	return violations
}

func inventoryIdentity(permit participation.PermitSnapshot) quarantineIdentity {
	return quarantineIdentity{
		ceremony:            string(permit.Ceremony),
		mode:                permit.Mode,
		canonicalStartBlock: permit.CanonicalStartBlock,
		workID:              permit.WorkID,
		permitID:            permit.PermitID,
	}
}

func outcomeIdentity(permit quiescencePermitEvidence) quarantineIdentity {
	return quarantineIdentity{
		ceremony:            permit.Ceremony,
		mode:                permit.Mode,
		canonicalStartBlock: permit.CanonicalStartBlock,
		workID:              permit.WorkID,
		permitID:            permit.PermitID,
	}
}

// validateQuiescenceReportEvidence checks the quiescence outcome record:
// schema, snapshot binding, the quiescing node's exact artifact identity and
// cutover schedule, a stated cause, and an independently captured gate
// inventory. The inventory and terminal outcomes must cover exactly the same
// unique permit identities and agree with the gate's total and per-mode
// counts. Every quarantined DKG outcome must also be matched by preserved
// quarantine state carrying the same ceremony, protocol mode, canonical
// anchor, chain-work ID, and local permit ID — one preserved output per
// claiming permit, so one real output cannot vouch for several claims.
func (r *auditRun) validateQuiescenceReportEvidence(content []byte) []string {
	record := &quiescenceReportEvidence{}
	if err := strictUnmarshal(content, record); err != nil {
		return []string{fmt.Sprintf(
			"cannot be decoded as a quiescence report: [%v]",
			err,
		)}
	}

	violations := r.validateEnvelope(
		record.evidenceEnvelope,
		"quiescence_report",
	)

	violations = append(violations, exactIdentityViolations(
		"quiescing release version",
		record.ReleaseVersion,
		r.expected.releaseVersion,
	)...)
	violations = append(violations, exactIdentityViolations(
		"quiescing release revision",
		record.ReleaseRevision,
		r.expected.releaseRevision,
	)...)
	violations = append(violations, exactIdentityViolations(
		"quiescing release epoch",
		record.ReleaseEpoch,
		r.expected.releaseEpoch,
	)...)
	if record.CutoverBlock == 0 {
		violations = append(
			violations,
			"the armed cutover block is missing",
		)
	} else if r.expected.cutoverBlock > 0 &&
		record.CutoverBlock != r.expected.cutoverBlock {
		violations = append(violations, fmt.Sprintf(
			"quiesced under cutover block [%d], expected [%d]",
			record.CutoverBlock,
			r.expected.cutoverBlock,
		))
	}

	if record.QuiesceCause == "" {
		violations = append(violations, "the quiescence cause is missing")
	}

	knownCeremonies := make(map[string]struct{})
	for _, ceremony := range participation.AllCeremonies() {
		knownCeremonies[string(ceremony)] = struct{}{}
	}

	snapshot := r.manifest.QuiescenceSnapshot
	if snapshot == nil {
		violations = append(
			violations,
			"the audited storage snapshot contains no node-authored "+
				"quiescence gate snapshot",
		)
		snapshot = &participation.QuiescenceSnapshot{}
	}

	violations = append(violations, exactIdentityViolations(
		"node-authored quiescing release version",
		snapshot.ReleaseVersion,
		record.ReleaseVersion,
	)...)
	violations = append(violations, exactIdentityViolations(
		"node-authored quiescing release revision",
		snapshot.ReleaseRevision,
		record.ReleaseRevision,
	)...)
	violations = append(violations, exactIdentityViolations(
		"node-authored quiescing release epoch",
		snapshot.ReleaseEpoch,
		record.ReleaseEpoch,
	)...)
	if snapshot.CutoverBlock != record.CutoverBlock {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence used cutover block [%d], but the "+
				"terminal report names [%d]",
			snapshot.CutoverBlock,
			record.CutoverBlock,
		))
	}
	if snapshot.QuiesceCause != record.QuiesceCause {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence cause [%s] does not match the "+
				"terminal report cause [%s]",
			snapshot.QuiesceCause,
			record.QuiesceCause,
		))
	}
	if !record.GeneratedAt.IsZero() &&
		snapshot.CapturedAt.After(record.GeneratedAt) {
		violations = append(
			violations,
			"the node-authored quiescence gate snapshot was captured after the "+
				"quiescence report was generated",
		)
	}

	inventoryPermits := make(map[quarantineIdentity]int)
	for i, permit := range snapshot.ActivePermits {
		identity := inventoryIdentity(permit)
		if firstIndex, duplicate := inventoryPermits[identity]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"gate inventory entry [%d] duplicates the full permit "+
					"identity first recorded by entry [%d]",
				i,
				firstIndex,
			))
		} else {
			inventoryPermits[identity] = i
		}
	}

	nodeOutcomes := make(
		map[quarantineIdentity]participation.TerminalOutcomeRecord,
	)
	if r.manifest.ParticipationTerminalOutcomes != nil {
		for _, outcome := range r.manifest.ParticipationTerminalOutcomes.Outcomes {
			nodeOutcomes[inventoryIdentity(outcome.Permit)] = outcome
		}
	}

	beaconQuarantined := make(map[quarantineIdentity]int)
	for _, quarantined := range r.manifest.BeaconQuarantinedOutputs {
		beaconQuarantined[quarantineIdentity{
			ceremony:            quarantined.Ceremony,
			mode:                quarantined.ProtocolMode,
			canonicalStartBlock: quarantined.CanonicalStartBlock,
			workID:              quarantined.SeedHash,
			permitID:            fmt.Sprint(quarantined.MemberIndex),
		}]++
	}
	tbtcQuarantined := make(map[quarantineIdentity]int)
	for _, quarantined := range r.manifest.TBTCQuarantinedOutputs {
		tbtcQuarantined[quarantineIdentity{
			ceremony:            quarantined.Ceremony,
			mode:                quarantined.ProtocolMode,
			canonicalStartBlock: quarantined.CanonicalStartBlock,
			workID:              quarantined.SeedHash,
			permitID:            fmt.Sprint(quarantined.MemberIndex),
		}]++
	}

	seenPermits := make(map[quarantineIdentity]int)
	var outcomeLegacy uint64
	var outcomeSecurityV2 uint64
	for i, permit := range record.ActivePermitsAtQuiescence {
		if _, ok := knownCeremonies[permit.Ceremony]; !ok {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] names unknown ceremony [%s]",
				i,
				permit.Ceremony,
			))
		}
		if permit.Mode != participation.ModeLegacy.String() &&
			permit.Mode != participation.ModeSecurityV2.String() {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] names unknown protocol mode [%s]",
				i,
				permit.Mode,
			))
		} else {
			if permit.Mode == participation.ModeLegacy.String() {
				outcomeLegacy++
			} else {
				outcomeSecurityV2++
			}
			if violation := cutoverModeViolation(
				fmt.Sprintf("permit entry [%d]", i),
				permit.Mode,
				permit.CanonicalStartBlock,
				record.CutoverBlock,
			); violation != "" {
				violations = append(violations, violation)
			}
		}
		if _, ok := validQuiescencePermitOutcomes[permit.Outcome]; !ok {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] has unknown terminal outcome [%s]",
				i,
				permit.Outcome,
			))
			continue
		}

		violations = append(
			violations,
			validateQuiescencePermitIdentity(i, permit)...,
		)

		identity := outcomeIdentity(permit)
		if firstIndex, duplicate := seenPermits[identity]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] duplicates the full permit identity "+
					"first recorded by entry [%d] [ceremony=%s] [mode=%s] "+
					"[canonicalStartBlock=%d] [workID=%s] [permitID=%s]",
				i,
				firstIndex,
				permit.Ceremony,
				permit.Mode,
				permit.CanonicalStartBlock,
				permit.WorkID,
				permit.PermitID,
			))
		} else {
			seenPermits[identity] = i
		}
		if _, inventoried := inventoryPermits[identity]; !inventoried {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] has no matching identity in the "+
					"at-quiescence gate inventory",
				i,
			))
		}
		nodeOutcome, nodeAuthored := nodeOutcomes[identity]
		if !nodeAuthored {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] has no matching node-authored terminal "+
					"outcome",
				i,
			))
		} else if string(nodeOutcome.Outcome) != permit.Outcome {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] claims terminal outcome [%s], but the "+
					"node-authored journal records [%s]",
				i,
				permit.Outcome,
				nodeOutcome.Outcome,
			))
		}

		if permit.Outcome != "quarantined" || !r.manifest.Interpreted {
			continue
		}
		switch permit.Ceremony {
		case string(participation.BeaconDKG):
			if beaconQuarantined[identity] == 0 {
				violations = append(violations, fmt.Sprintf(
					"permit entry [%d] claims a quarantined [%s] output "+
						"[mode=%s] [canonicalStartBlock=%d] [workID=%s] "+
						"[permitID=%s] but the beacon quarantine namespace "+
						"holds none matching that exact local permit",
					i,
					permit.Ceremony,
					permit.Mode,
					permit.CanonicalStartBlock,
					permit.WorkID,
					permit.PermitID,
				))
				continue
			}
			beaconQuarantined[identity]--
		case string(participation.TBTCDKG):
			if tbtcQuarantined[identity] == 0 {
				violations = append(violations, fmt.Sprintf(
					"permit entry [%d] claims a quarantined [%s] output "+
						"[mode=%s] [canonicalStartBlock=%d] [workID=%s] "+
						"[permitID=%s] but the tbtc quarantine namespace "+
						"holds none matching that exact local permit",
					i,
					permit.Ceremony,
					permit.Mode,
					permit.CanonicalStartBlock,
					permit.WorkID,
					permit.PermitID,
				))
				continue
			}
			tbtcQuarantined[identity]--
		}
	}

	if uint64(len(record.ActivePermitsAtQuiescence)) !=
		snapshot.ActiveCeremonies {
		violations = append(violations, fmt.Sprintf(
			"the terminal outcome list contains [%d] permits, but the "+
				"node-authored gate snapshot declares total [%d]",
			len(record.ActivePermitsAtQuiescence),
			snapshot.ActiveCeremonies,
		))
	}
	if outcomeLegacy != snapshot.ActiveLegacyCeremonies {
		violations = append(violations, fmt.Sprintf(
			"the terminal outcome list contains [%d] legacy permits, but "+
				"the node-authored gate snapshot declares [%d]",
			outcomeLegacy,
			snapshot.ActiveLegacyCeremonies,
		))
	}
	if outcomeSecurityV2 != snapshot.ActiveSecurityV2Ceremonies {
		violations = append(violations, fmt.Sprintf(
			"the terminal outcome list contains [%d] security-v2 permits, "+
				"but the node-authored gate snapshot declares [%d]",
			outcomeSecurityV2,
			snapshot.ActiveSecurityV2Ceremonies,
		))
	}
	for identity, inventoryIndex := range inventoryPermits {
		if _, reported := seenPermits[identity]; !reported {
			violations = append(violations, fmt.Sprintf(
				"node-authored gate inventory entry [%d] has no terminal outcome "+
					"[ceremony=%s] [mode=%s] "+
					"[canonicalStartBlock=%d] [workID=%s] [permitID=%s]",
				inventoryIndex,
				identity.ceremony,
				identity.mode,
				identity.canonicalStartBlock,
				identity.workID,
				identity.permitID,
			))
		}
	}

	return violations
}

// validatePriorReaderCompatibilityEvidence checks the prior-reader record:
// schema, snapshot binding, the exactly pinned prior and current release
// artifacts on both sides of the test, and an explicit compatible result for
// every schema this release writes — each schema at most once, so one result
// cannot be shadowed by a contradicting duplicate. Any missing or
// incompatible schema means the prior-binary rollback is not an accepted
// mechanism.
func (r *auditRun) validatePriorReaderCompatibilityEvidence(
	content []byte,
) []string {
	record := &priorReaderCompatibilityEvidence{}
	if err := strictUnmarshal(content, record); err != nil {
		return []string{fmt.Sprintf(
			"cannot be decoded as a prior-reader compatibility record: [%v]",
			err,
		)}
	}

	violations := r.validateEnvelope(
		record.evidenceEnvelope,
		"prior_reader_compatibility",
	)

	violations = append(violations, exactIdentityViolations(
		"tested prior version",
		record.PriorVersion,
		r.expected.priorVersion,
	)...)
	violations = append(violations, exactIdentityViolations(
		"tested prior revision",
		record.PriorRevision,
		r.expected.priorRevision,
	)...)
	violations = append(violations, digestViolations(
		"tested prior image digest",
		record.PriorImageDigest,
		r.expected.priorImageDigest,
	)...)
	violations = append(violations, exactIdentityViolations(
		"writing release version",
		record.ReleaseVersion,
		r.expected.releaseVersion,
	)...)
	violations = append(violations, exactIdentityViolations(
		"writing release revision",
		record.ReleaseRevision,
		r.expected.releaseRevision,
	)...)
	violations = append(violations, digestViolations(
		"writing release image digest",
		record.ReleaseImageDigest,
		r.expected.releaseImageDigest,
	)...)

	results := make(map[string]bool)
	for i, result := range record.SchemaResults {
		if result.Schema == "" {
			violations = append(violations, fmt.Sprintf(
				"schema result entry [%d] is missing its schema name",
				i,
			))
			continue
		}
		if _, duplicate := results[result.Schema]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"schema [%s] is covered more than once; duplicate results "+
					"cannot prove compatibility",
				result.Schema,
			))
			continue
		}
		results[result.Schema] = result.Compatible
	}
	for _, schema := range requiredPriorReaderSchemas {
		compatible, covered := results[schema]
		if !covered {
			violations = append(violations, fmt.Sprintf(
				"required schema [%s] is not covered",
				schema,
			))
			continue
		}
		if !compatible {
			violations = append(violations, fmt.Sprintf(
				"the prior release cannot read schema [%s]",
				schema,
			))
		}
	}

	return violations
}

// strictUnmarshal decodes JSON while rejecting unknown fields and trailing
// content, so a placeholder or mistyped record cannot pass as evidence.
func strictUnmarshal(content []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("trailing content after the record")
	}
	return nil
}

// interpretKeyStoreNamespaces decodes the beacon active, beacon quarantine,
// and tBTC active namespaces through the standard encrypted persistence
// handles, cross-validates every record against its storage location and its
// paired records, and reports every failure as a finding.
func interpretKeyStoreNamespaces(
	storageDir string,
	password string,
	run *auditRun,
) error {
	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		password,
	)
	if err != nil {
		return fmt.Errorf("cannot open the storage snapshot: [%w]", err)
	}

	activeGroups, err := interpretBeaconActiveNamespace(diskStorage, run)
	if err != nil {
		return err
	}
	if err := interpretBeaconQuarantineNamespace(
		diskStorage,
		run,
		activeGroups,
	); err != nil {
		return err
	}
	activeWallets, err := interpretTBTCActiveNamespace(diskStorage, run)
	if err != nil {
		return err
	}
	if err := interpretTBTCQuarantineNamespace(
		diskStorage,
		run,
		activeWallets,
	); err != nil {
		return err
	}
	if err := interpretParticipationQuiescenceSnapshot(
		diskStorage,
		run,
	); err != nil {
		return err
	}

	sortRecords(run.manifest)

	return nil
}

// interpretParticipationQuiescenceSnapshot reads the node-authored gate
// capture from encrypted work storage. This is the authoritative active-permit
// inventory. Its companion terminal-outcome journal supplies the authoritative
// dispositions; the external quiescence report can only corroborate them and
// cannot replace or shorten either record.
func interpretParticipationQuiescenceSnapshot(
	diskStorage storage.Storage,
	run *auditRun,
) error {
	handle, err := diskStorage.InitializeWorkPersistence("participation")
	if err != nil {
		return fmt.Errorf(
			"cannot open the participation work namespace: [%w]",
			err,
		)
	}

	descriptors, descriptorErrors := handle.ReadAll()
	errorsDone := make(chan struct{})
	go func() {
		defer close(errorsDone)
		for err := range descriptorErrors {
			run.finding(
				"participation work namespace read error: [%v]",
				err,
			)
		}
	}()

	snapshotCount := 0
	journalCount := 0
	for descriptor := range descriptors {
		if descriptor.Directory() !=
			participation.QuiescenceSnapshotStorageDirectory {
			run.finding(
				"participation work record [%s/%s] is not in the recognized "+
					"node-authored quiescence directory",
				descriptor.Directory(),
				descriptor.Name(),
			)
			continue
		}

		content, err := descriptor.Content()
		if err != nil {
			run.finding(
				"node-authored quiescence snapshot cannot be decrypted: [%v]",
				err,
			)
			continue
		}

		switch descriptor.Name() {
		case participation.QuiescenceSnapshotStorageFile:
			snapshotCount++
			snapshot := &participation.QuiescenceSnapshot{}
			if err := strictUnmarshal(content, snapshot); err != nil {
				run.finding(
					"node-authored quiescence snapshot cannot be decoded: [%v]",
					err,
				)
				continue
			}
			if run.manifest.QuiescenceSnapshot != nil {
				run.finding(
					"more than one node-authored quiescence snapshot is present",
				)
				continue
			}

			run.manifest.QuiescenceSnapshot = snapshot
			for _, violation := range validateNodeQuiescenceSnapshot(snapshot) {
				run.finding("%s", violation)
			}
			if snapshot.CapturedAt.After(run.manifest.GeneratedAt) {
				run.finding(
					"node-authored quiescence snapshot capture time is after " +
						"the offline audit time",
				)
			} else if run.expected.maxEvidenceAge > 0 &&
				run.manifest.GeneratedAt.Sub(snapshot.CapturedAt) >
					run.expected.maxEvidenceAge {
				run.finding(
					"node-authored quiescence snapshot is older than the "+
						"maximum evidence age [%s]",
					run.expected.maxEvidenceAge,
				)
			}
		case participation.TerminalOutcomeJournalStorageFile:
			journalCount++
			journal := &participation.TerminalOutcomeJournal{}
			if err := strictUnmarshal(content, journal); err != nil {
				run.finding(
					"node-authored terminal-outcome journal cannot be "+
						"decoded: [%v]",
					err,
				)
				continue
			}
			if run.manifest.ParticipationTerminalOutcomes != nil {
				run.finding(
					"more than one node-authored terminal-outcome journal " +
						"is present",
				)
				continue
			}
			run.manifest.ParticipationTerminalOutcomes = journal
		default:
			run.finding(
				"participation work record [%s/%s] is not a recognized "+
					"node-authored quiescence artifact",
				descriptor.Directory(),
				descriptor.Name(),
			)
		}
	}
	<-errorsDone

	if snapshotCount == 0 {
		run.finding(
			"the node-authored participation quiescence snapshot is missing",
		)
	}
	if journalCount == 0 {
		run.finding(
			"the node-authored participation terminal-outcome journal is missing",
		)
	}
	for _, violation := range validateNodeTerminalOutcomes(run.manifest) {
		run.finding("%s", violation)
	}

	return nil
}

func validateNodeQuiescenceSnapshot(
	snapshot *participation.QuiescenceSnapshot,
) []string {
	violations := make([]string, 0)

	if snapshot.SchemaVersion != participation.QuiescenceSnapshotSchemaVersion {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence snapshot schema [%d] is not [%d]",
			snapshot.SchemaVersion,
			participation.QuiescenceSnapshotSchemaVersion,
		))
	}
	if snapshot.CapturedAt.IsZero() {
		violations = append(
			violations,
			"node-authored quiescence snapshot capture time is missing",
		)
	}
	if snapshot.ReleaseVersion == "" {
		violations = append(
			violations,
			"node-authored quiescence snapshot release version is missing",
		)
	}
	if snapshot.ReleaseRevision == "" {
		violations = append(
			violations,
			"node-authored quiescence snapshot release revision is missing",
		)
	}
	if snapshot.ReleaseEpoch != participation.CompiledEpoch.String() {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence snapshot epoch [%s] is not the "+
				"compiled epoch [%s]",
			snapshot.ReleaseEpoch,
			participation.CompiledEpoch,
		))
	}
	if snapshot.CutoverBlock == 0 {
		violations = append(
			violations,
			"node-authored quiescence snapshot cutover block is zero",
		)
	}
	if snapshot.State != participation.StateQuiescing.String() {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence snapshot state [%s] is not [%s]",
			snapshot.State,
			participation.StateQuiescing,
		))
	}
	if snapshot.QuiesceCause == "" {
		violations = append(
			violations,
			"node-authored quiescence snapshot cause is missing",
		)
	}

	if snapshot.ActiveLegacyCeremonies >
		snapshot.ActiveCeremonies ||
		snapshot.ActiveSecurityV2Ceremonies >
			snapshot.ActiveCeremonies-
				snapshot.ActiveLegacyCeremonies ||
		snapshot.ActiveLegacyCeremonies+
			snapshot.ActiveSecurityV2Ceremonies !=
			snapshot.ActiveCeremonies {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence snapshot mode counts [%d legacy, "+
				"%d security-v2] do not sum to total [%d]",
			snapshot.ActiveLegacyCeremonies,
			snapshot.ActiveSecurityV2Ceremonies,
			snapshot.ActiveCeremonies,
		))
	}
	if snapshot.ActiveCeremonies != uint64(len(snapshot.ActivePermits)) {
		violations = append(violations, fmt.Sprintf(
			"node-authored quiescence snapshot inventories [%d] permits, "+
				"but declares total [%d]",
			len(snapshot.ActivePermits),
			snapshot.ActiveCeremonies,
		))
	}

	knownCeremonies := make(map[string]struct{})
	for _, ceremony := range participation.AllCeremonies() {
		knownCeremonies[string(ceremony)] = struct{}{}
	}

	identities := make(map[quarantineIdentity]int)
	var legacy uint64
	var securityV2 uint64
	for i, permit := range snapshot.ActivePermits {
		if _, ok := knownCeremonies[string(permit.Ceremony)]; !ok {
			violations = append(violations, fmt.Sprintf(
				"node-authored gate inventory entry [%d] names unknown "+
					"ceremony [%s]",
				i,
				permit.Ceremony,
			))
		}
		switch permit.Mode {
		case participation.ModeLegacy.String():
			legacy++
		case participation.ModeSecurityV2.String():
			securityV2++
		default:
			violations = append(violations, fmt.Sprintf(
				"node-authored gate inventory entry [%d] names unknown "+
					"protocol mode [%s]",
				i,
				permit.Mode,
			))
		}
		if !permit.IdentityBound {
			violations = append(violations, fmt.Sprintf(
				"node-authored gate inventory entry [%d] was issued "+
					"without a stable work and permit identity",
				i,
			))
		}
		if violation := cutoverModeViolation(
			fmt.Sprintf("node-authored gate inventory entry [%d]", i),
			permit.Mode,
			permit.CanonicalStartBlock,
			snapshot.CutoverBlock,
		); violation != "" {
			violations = append(violations, violation)
		}
		violations = append(
			violations,
			validateQuiescencePermitIdentity(
				i,
				quiescencePermitEvidence{
					Ceremony:            string(permit.Ceremony),
					Mode:                permit.Mode,
					CanonicalStartBlock: permit.CanonicalStartBlock,
					WorkID:              permit.WorkID,
					PermitID:            permit.PermitID,
				},
			)...,
		)

		identity := inventoryIdentity(permit)
		if firstIndex, duplicate := identities[identity]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"node-authored gate inventory entry [%d] duplicates the "+
					"full permit identity first recorded by entry [%d]",
				i,
				firstIndex,
			))
		} else {
			identities[identity] = i
		}

		if i > 0 {
			previous := snapshot.ActivePermits[i-1]
			if permitSnapshotLess(permit, previous) {
				violations = append(
					violations,
					"node-authored gate inventory is not deterministically sorted",
				)
			}
		}
	}

	if legacy != snapshot.ActiveLegacyCeremonies {
		violations = append(violations, fmt.Sprintf(
			"node-authored gate inventory contains [%d] legacy permits, "+
				"but declares [%d]",
			legacy,
			snapshot.ActiveLegacyCeremonies,
		))
	}
	if securityV2 != snapshot.ActiveSecurityV2Ceremonies {
		violations = append(violations, fmt.Sprintf(
			"node-authored gate inventory contains [%d] security-v2 "+
				"permits, but declares [%d]",
			securityV2,
			snapshot.ActiveSecurityV2Ceremonies,
		))
	}

	return violations
}

// validateNodeTerminalOutcomes reconciles the ceremony-owner-authored terminal
// journal with the immutable permit inventory captured by the gate. It also
// corroborates DKG completion against persisted signer state and quarantine
// against the protected signer namespaces. An external quiescence report is
// deliberately not consulted here.
func validateNodeTerminalOutcomes(
	auditManifest *manifest,
) []string {
	journal := auditManifest.ParticipationTerminalOutcomes
	if journal == nil {
		return nil
	}

	violations := make([]string, 0)
	if journal.SchemaVersion !=
		participation.TerminalOutcomeJournalSchemaVersion {
		violations = append(violations, fmt.Sprintf(
			"node-authored terminal-outcome journal schema [%d] is not [%d]",
			journal.SchemaVersion,
			participation.TerminalOutcomeJournalSchemaVersion,
		))
	}

	snapshot := auditManifest.QuiescenceSnapshot
	if snapshot == nil {
		violations = append(
			violations,
			"node-authored terminal-outcome journal has no gate snapshot to bind",
		)
		return violations
	}
	if !journal.SnapshotCapturedAt.Equal(snapshot.CapturedAt) {
		violations = append(violations, fmt.Sprintf(
			"node-authored terminal-outcome journal binds snapshot time [%s], "+
				"but the gate snapshot was captured at [%s]",
			journal.SnapshotCapturedAt,
			snapshot.CapturedAt,
		))
	}

	inventory := make(map[quarantineIdentity]int)
	for i, permit := range snapshot.ActivePermits {
		inventory[inventoryIdentity(permit)] = i
	}

	activeTBTCSigners := make(map[string]struct{})
	for _, wallet := range auditManifest.TBTCActiveWallets {
		activeTBTCSigners[wallet.WalletStorageKey] = struct{}{}
		activeTBTCSigners[wallet.WalletID] = struct{}{}
	}
	activeBeaconSigners := make(map[string]struct{})
	for _, membership := range auditManifest.BeaconActiveMemberships {
		activeBeaconSigners[membership.GroupPublicKey] = struct{}{}
	}
	tbtcQuarantined := make(map[quarantineIdentity]struct{})
	for _, quarantined := range auditManifest.TBTCQuarantinedOutputs {
		tbtcQuarantined[quarantineIdentity{
			ceremony:            quarantined.Ceremony,
			mode:                quarantined.ProtocolMode,
			canonicalStartBlock: quarantined.CanonicalStartBlock,
			workID:              quarantined.SeedHash,
			permitID:            fmt.Sprint(quarantined.MemberIndex),
		}] = struct{}{}
	}
	beaconQuarantined := make(map[quarantineIdentity]struct{})
	for _, quarantined := range auditManifest.BeaconQuarantinedOutputs {
		beaconQuarantined[quarantineIdentity{
			ceremony:            quarantined.Ceremony,
			mode:                quarantined.ProtocolMode,
			canonicalStartBlock: quarantined.CanonicalStartBlock,
			workID:              quarantined.SeedHash,
			permitID:            fmt.Sprint(quarantined.MemberIndex),
		}] = struct{}{}
	}

	seen := make(map[quarantineIdentity]int)
	for i, outcome := range journal.Outcomes {
		identity := inventoryIdentity(outcome.Permit)
		if firstIndex, duplicate := seen[identity]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"node-authored terminal outcome [%d] duplicates the full "+
					"permit identity first recorded by outcome [%d]",
				i,
				firstIndex,
			))
		} else {
			seen[identity] = i
		}
		if _, inventoried := inventory[identity]; !inventoried {
			violations = append(violations, fmt.Sprintf(
				"node-authored terminal outcome [%d] has no matching permit "+
					"in the at-quiescence gate inventory",
				i,
			))
		}
		if outcome.RecordedAt.IsZero() {
			violations = append(violations, fmt.Sprintf(
				"node-authored terminal outcome [%d] has no record time",
				i,
			))
		}
		if !outcome.Permit.IdentityBound {
			violations = append(violations, fmt.Sprintf(
				"node-authored terminal outcome [%d] belongs to an unbound "+
					"permit identity",
				i,
			))
		}
		violations = append(
			violations,
			validateQuiescencePermitIdentity(
				i,
				quiescencePermitEvidence{
					Ceremony:            string(outcome.Permit.Ceremony),
					Mode:                outcome.Permit.Mode,
					CanonicalStartBlock: outcome.Permit.CanonicalStartBlock,
					WorkID:              outcome.Permit.WorkID,
					PermitID:            outcome.Permit.PermitID,
				},
			)...,
		)
		if outcome.Outcome != "unresolved" {
			if err := participation.ValidateTerminalOutcome(
				outcome.Permit.Ceremony,
				outcome.Outcome,
				outcome.Evidence,
			); err != nil {
				violations = append(violations, fmt.Sprintf(
					"node-authored terminal outcome [%d] evidence is invalid: [%v]",
					i,
					err,
				))
			}
		}

		switch outcome.Outcome {
		case participation.TerminalOutcomeCompleted:
			switch outcome.Permit.Ceremony {
			case participation.TBTCDKG:
				if outcome.Evidence.Kind !=
					participation.TerminalEvidencePersistedTBTCSinger {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed tbtc DKG outcome [%d] does "+
							"not name persisted tbtc signer evidence",
						i,
					))
				} else if _, ok :=
					activeTBTCSigners[outcome.Evidence.Reference]; !ok {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed tbtc DKG outcome [%d] names "+
							"persisted signer [%s], but the active tbtc "+
							"namespace holds no matching signer",
						i,
						outcome.Evidence.Reference,
					))
				}
			case participation.BeaconDKG:
				if outcome.Evidence.Kind !=
					participation.TerminalEvidencePersistedBeaconSigner {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed beacon DKG outcome [%d] does "+
							"not name persisted beacon signer evidence",
						i,
					))
				} else if _, ok :=
					activeBeaconSigners[outcome.Evidence.Reference]; !ok {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed beacon DKG outcome [%d] names "+
							"persisted signer [%s], but the active beacon "+
							"namespace holds no matching signer",
						i,
						outcome.Evidence.Reference,
					))
				}
			default:
				if outcome.Evidence.Kind ==
					participation.TerminalEvidenceNoThreshold ||
					outcome.Evidence.Kind == "" {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed outcome [%d] has no durable "+
							"result evidence",
						i,
					))
				}
			}
			if outcome.Evidence.Reference != "" &&
				!isStableEvidenceID(outcome.Evidence.Reference) {
				violations = append(violations, fmt.Sprintf(
					"node-authored completed outcome [%d] evidence reference "+
						"[%s] is not a stable evidence identifier",
					i,
					outcome.Evidence.Reference,
				))
			}
		case participation.TerminalOutcomeQuarantined:
			switch outcome.Permit.Ceremony {
			case participation.TBTCDKG:
				if outcome.Evidence.Kind !=
					participation.TerminalEvidenceQuarantinedTBTCSinger {
					violations = append(violations, fmt.Sprintf(
						"node-authored quarantined tbtc DKG outcome [%d] has "+
							"the wrong evidence kind [%s]",
						i,
						outcome.Evidence.Kind,
					))
				}
				if _, ok := tbtcQuarantined[identity]; !ok {
					violations = append(violations, fmt.Sprintf(
						"node-authored quarantined tbtc DKG outcome [%d] has "+
							"no exact protected signer record",
						i,
					))
				}
			case participation.BeaconDKG:
				if outcome.Evidence.Kind !=
					participation.TerminalEvidenceQuarantinedBeaconSigner {
					violations = append(violations, fmt.Sprintf(
						"node-authored quarantined beacon DKG outcome [%d] has "+
							"the wrong evidence kind [%s]",
						i,
						outcome.Evidence.Kind,
					))
				}
				if _, ok := beaconQuarantined[identity]; !ok {
					violations = append(violations, fmt.Sprintf(
						"node-authored quarantined beacon DKG outcome [%d] has "+
							"no exact protected signer record",
						i,
					))
				}
			default:
				violations = append(violations, fmt.Sprintf(
					"node-authored terminal outcome [%d] claims quarantine "+
						"for ceremony [%s], which has no protected signer "+
						"namespace",
					i,
					outcome.Permit.Ceremony,
				))
			}
		case participation.TerminalOutcomeExhausted:
			if outcome.Evidence.Kind !=
				participation.TerminalEvidenceNoThreshold ||
				outcome.Evidence.Reference != "" {
				violations = append(violations, fmt.Sprintf(
					"node-authored exhausted outcome [%d] is not an explicit "+
						"no-threshold result",
					i,
				))
			}
		default:
			violations = append(violations, fmt.Sprintf(
				"node-authored terminal outcome [%d] is unresolved or unknown "+
					"[%s]",
				i,
				outcome.Outcome,
			))
		}

		if i > 0 &&
			permitSnapshotLess(
				outcome.Permit,
				journal.Outcomes[i-1].Permit,
			) {
			violations = append(
				violations,
				"node-authored terminal-outcome journal is not "+
					"deterministically sorted",
			)
		}
	}

	if len(journal.Outcomes) != len(snapshot.ActivePermits) {
		violations = append(violations, fmt.Sprintf(
			"node-authored terminal-outcome journal contains [%d] outcomes, "+
				"but the gate snapshot inventories [%d] permits",
			len(journal.Outcomes),
			len(snapshot.ActivePermits),
		))
	}
	for identity, inventoryIndex := range inventory {
		if _, recorded := seen[identity]; !recorded {
			violations = append(violations, fmt.Sprintf(
				"node-authored gate inventory entry [%d] has no node-authored "+
					"terminal outcome [ceremony=%s] [mode=%s] "+
					"[canonicalStartBlock=%d] [workID=%s] [permitID=%s]",
				inventoryIndex,
				identity.ceremony,
				identity.mode,
				identity.canonicalStartBlock,
				identity.workID,
				identity.permitID,
			))
		}
	}

	return violations
}

func permitSnapshotLess(
	left participation.PermitSnapshot,
	right participation.PermitSnapshot,
) bool {
	if left.Ceremony != right.Ceremony {
		return left.Ceremony < right.Ceremony
	}
	if left.CanonicalStartBlock != right.CanonicalStartBlock {
		return left.CanonicalStartBlock < right.CanonicalStartBlock
	}
	if left.WorkID != right.WorkID {
		return left.WorkID < right.WorkID
	}
	return left.PermitID < right.PermitID
}

// interpretBeaconActiveNamespace decodes every active-namespace record as a
// membership — exactly what the client's own active-group scan assumes on
// start — and cross-checks each record against the directory and file name it
// is stored under. It returns the set of active group public keys for the
// quarantine overlap check.
func interpretBeaconActiveNamespace(
	diskStorage storage.Storage,
	run *auditRun,
) (map[string]struct{}, error) {
	activeHandle, err := diskStorage.InitializeKeyStorePersistence("beacon")
	if err != nil {
		return nil, fmt.Errorf(
			"cannot open the beacon keystore namespace: [%w]",
			err,
		)
	}

	activeGroups := make(map[string]struct{})

	activeData, activeErrors := activeHandle.ReadAll()
	activeDone := make(chan struct{})
	go func() {
		defer close(activeDone)
		for err := range activeErrors {
			run.finding("beacon active namespace read error: [%v]", err)
		}
	}()
	for descriptor := range activeData {
		content, err := descriptor.Content()
		if err != nil {
			run.finding(
				"beacon active record [%s/%s] cannot be decrypted: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		membership := &registry.Membership{}
		if err := membership.Unmarshal(content); err != nil {
			run.finding(
				"beacon active record [%s/%s] cannot be decoded as a "+
					"membership: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		groupPublicKey := hex.EncodeToString(
			membership.Signer.GroupPublicKeyBytesCompressed(),
		)
		memberIndex := uint8(membership.Signer.MemberID())

		// The client's active scan trusts the storage location; a record
		// whose content disagrees with its directory or member file name
		// belongs to a different group or member than the layout claims.
		if descriptor.Directory() != groupPublicKey {
			run.finding(
				"beacon active record [%s/%s] contains group [%s], not the "+
					"group its directory claims",
				descriptor.Directory(),
				descriptor.Name(),
				groupPublicKey,
			)
		}
		if expected := fmt.Sprintf(
			"membership_%d",
			memberIndex,
		); descriptor.Name() != expected {
			run.finding(
				"beacon active record [%s/%s] contains member [%d], not the "+
					"member its file name claims",
				descriptor.Directory(),
				descriptor.Name(),
				memberIndex,
			)
		}

		activeGroups[groupPublicKey] = struct{}{}
		run.manifest.BeaconActiveMemberships = append(
			run.manifest.BeaconActiveMemberships,
			beaconMembershipRecord{
				GroupPublicKey: groupPublicKey,
				MemberIndex:    memberIndex,
				ChannelName:    membership.ChannelName,
			},
		)
	}
	<-activeDone

	return activeGroups, nil
}

// beaconQuarantineEntry pairs the two halves of one quarantined output while
// the namespace is scanned.
type beaconQuarantineEntry struct {
	directory    string
	memberSuffix string
	metadata     *registry.QuarantinedSignerMetadata
	membership   *registry.Membership
}

// interpretBeaconQuarantineNamespace decodes the quarantine namespace, pairs
// metadata and membership halves by directory and member suffix, and
// cross-validates the metadata against its schema, this release's identity,
// the cutover arithmetic, the storage location, the decrypted membership, and
// the active namespace.
func interpretBeaconQuarantineNamespace(
	diskStorage storage.Storage,
	run *auditRun,
	activeGroups map[string]struct{},
) error {
	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"beacon-quarantine",
	)
	if err != nil {
		return fmt.Errorf(
			"cannot open the beacon quarantine namespace: [%w]",
			err,
		)
	}

	quarantineEntries := make(map[string]*beaconQuarantineEntry)
	entryFor := func(directory, name, prefix string) *beaconQuarantineEntry {
		suffix := strings.TrimPrefix(name, prefix)
		key := directory + "/" + suffix
		if _, ok := quarantineEntries[key]; !ok {
			quarantineEntries[key] = &beaconQuarantineEntry{
				directory:    directory,
				memberSuffix: suffix,
			}
		}
		return quarantineEntries[key]
	}

	quarantineData, quarantineErrors := quarantineHandle.ReadAll()
	quarantineDone := make(chan struct{})
	go func() {
		defer close(quarantineDone)
		for err := range quarantineErrors {
			run.finding("beacon quarantine namespace read error: [%v]", err)
		}
	}()
	for descriptor := range quarantineData {
		content, err := descriptor.Content()
		if err != nil {
			run.finding(
				"beacon quarantine record [%s/%s] cannot be decrypted: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		switch {
		case strings.HasPrefix(descriptor.Name(), "metadata_"):
			metadata := &registry.QuarantinedSignerMetadata{}
			if err := json.Unmarshal(content, metadata); err != nil {
				run.finding(
					"beacon quarantine metadata [%s/%s] cannot be decoded: "+
						"[%v]",
					descriptor.Directory(),
					descriptor.Name(),
					err,
				)
				continue
			}
			entryFor(
				descriptor.Directory(),
				descriptor.Name(),
				"metadata_",
			).metadata = metadata
		case strings.HasPrefix(descriptor.Name(), "membership_"):
			membership := &registry.Membership{}
			if err := membership.Unmarshal(content); err != nil {
				run.finding(
					"beacon quarantine membership [%s/%s] cannot be decoded: "+
						"[%v]",
					descriptor.Directory(),
					descriptor.Name(),
					err,
				)
				continue
			}
			entryFor(
				descriptor.Directory(),
				descriptor.Name(),
				"membership_",
			).membership = membership
		default:
			run.finding(
				"beacon quarantine record [%s/%s] has an unknown name",
				descriptor.Directory(),
				descriptor.Name(),
			)
		}
	}
	<-quarantineDone

	keys := make([]string, 0, len(quarantineEntries))
	for key := range quarantineEntries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		entry := quarantineEntries[key]

		validateQuarantineEntry(run, entry, activeGroups)

		if entry.metadata == nil {
			continue
		}
		run.manifest.BeaconQuarantinedOutputs = append(
			run.manifest.BeaconQuarantinedOutputs,
			beaconQuarantineRecord{
				QuarantinedSignerMetadata: *entry.metadata,
				HasMembershipRecord:       entry.membership != nil,
			},
		)
	}

	return nil
}

// validateQuarantineEntry cross-validates one paired quarantine output. The
// metadata exists for the offline audit alone, so any half or field that
// contradicts the rest of the record makes the output untrustworthy evidence.
func validateQuarantineEntry(
	run *auditRun,
	entry *beaconQuarantineEntry,
	activeGroups map[string]struct{},
) {
	key := entry.directory + "/" + entry.memberSuffix

	// A quarantined group visible in the active namespace is exactly the
	// ambiguity the quarantine exists to prevent: the same key material would
	// be both activated and marked interrupted.
	if _, active := activeGroups[entry.directory]; active {
		run.finding(
			"beacon quarantine output [%s] belongs to group [%s] that is "+
				"also present in the active namespace",
			key,
			entry.directory,
		)
	}

	if entry.membership != nil {
		membershipGroup := hex.EncodeToString(
			entry.membership.Signer.GroupPublicKeyBytesCompressed(),
		)
		if membershipGroup != entry.directory {
			run.finding(
				"beacon quarantine membership [%s] contains group [%s], not "+
					"the group its directory claims",
				key,
				membershipGroup,
			)
		}
		if suffix := fmt.Sprint(
			entry.membership.Signer.MemberID(),
		); suffix != entry.memberSuffix {
			run.finding(
				"beacon quarantine membership [%s] contains member [%s], "+
					"not the member its file name claims",
				key,
				suffix,
			)
		}
	}

	if entry.metadata == nil {
		run.finding(
			"beacon quarantine output [%s] has a membership record "+
				"without audit metadata",
			key,
		)
		return
	}

	metadata := entry.metadata
	if entry.membership == nil {
		run.finding(
			"beacon quarantine output [%s] has audit metadata without "+
				"a membership record; the key material was not preserved",
			key,
		)
	}

	if metadata.SchemaVersion != registry.QuarantineSchemaVersion {
		run.finding(
			"beacon quarantine metadata [%s] has schema version [%d], "+
				"expected [%d]",
			key,
			metadata.SchemaVersion,
			registry.QuarantineSchemaVersion,
		)
	}
	if metadata.ReleaseEpoch != participation.CompiledEpoch.String() {
		run.finding(
			"beacon quarantine metadata [%s] was written by release epoch "+
				"[%s], not by this audit's epoch [%s]",
			key,
			metadata.ReleaseEpoch,
			participation.CompiledEpoch,
		)
	}
	if metadata.Ceremony != string(participation.BeaconDKG) {
		run.finding(
			"beacon quarantine metadata [%s] names ceremony [%s]; only "+
				"[%s] outputs are quarantined",
			key,
			metadata.Ceremony,
			participation.BeaconDKG,
		)
	}
	if !isCanonicalSHA256Hex(metadata.SeedHash) {
		run.finding(
			"beacon quarantine metadata [%s] seed hash [%s] is not a "+
				"canonical SHA-256 digest of 64 lowercase hexadecimal "+
				"characters",
			key,
			metadata.SeedHash,
		)
	}
	if metadata.MemberIndex == 0 {
		run.finding(
			"beacon quarantine metadata [%s] names invalid member index [0]",
			key,
		)
	}
	if metadata.GroupPublicKey != entry.directory {
		run.finding(
			"beacon quarantine metadata [%s] names group [%s], not the "+
				"group its directory claims",
			key,
			metadata.GroupPublicKey,
		)
	}
	if suffix := fmt.Sprint(metadata.MemberIndex); suffix != entry.memberSuffix {
		run.finding(
			"beacon quarantine metadata [%s] names member [%s], not the "+
				"member its file name claims",
			key,
			suffix,
		)
	}

	validateQuarantineMode(run, key, metadata)

	if entry.membership != nil {
		if member := uint8(
			entry.membership.Signer.MemberID(),
		); member != metadata.MemberIndex {
			run.finding(
				"beacon quarantine output [%s] pairs metadata for member "+
					"[%d] with a membership of member [%d]",
				key,
				metadata.MemberIndex,
				member,
			)
		}
		membershipGroup := hex.EncodeToString(
			entry.membership.Signer.GroupPublicKeyBytesCompressed(),
		)
		if membershipGroup != metadata.GroupPublicKey {
			run.finding(
				"beacon quarantine output [%s] pairs metadata for group "+
					"[%s] with a membership of group [%s]",
				key,
				metadata.GroupPublicKey,
				membershipGroup,
			)
		}
	}
}

// validateQuarantineMode checks the recorded protocol mode against the
// recorded cutover arithmetic — the mode is pinned from the canonical
// anchor, so a record that contradicts that rule was not produced by the
// release gate — and the recorded cutover block against the expected armed
// schedule: a record preserved under a different cutover block belongs to a
// different deployment than the one being rolled back.
func validateQuarantineMode(
	run *auditRun,
	key string,
	metadata *registry.QuarantinedSignerMetadata,
) {
	if run.expected.cutoverBlock > 0 &&
		metadata.CutoverBlock != run.expected.cutoverBlock {
		run.finding(
			"beacon quarantine metadata [%s] was preserved under cutover "+
				"block [%d], not the expected cutover block [%d]",
			key,
			metadata.CutoverBlock,
			run.expected.cutoverBlock,
		)
	}

	if violation := cutoverModeViolation(
		fmt.Sprintf("beacon quarantine metadata [%s]", key),
		metadata.ProtocolMode,
		metadata.CanonicalStartBlock,
		metadata.CutoverBlock,
	); violation != "" {
		run.finding("%s", violation)
	}
}

// interpretTBTCActiveNamespace decodes every tBTC keystore record with the
// same decode the wallet registry loader uses and cross-checks each record
// against the wallet directory and member file name it is stored under, the
// signing group bounds, and its sibling records. It returns the set of active
// wallet storage keys for the quarantine overlap check.
func interpretTBTCActiveNamespace(
	diskStorage storage.Storage,
	run *auditRun,
) (map[string]struct{}, error) {
	tbtcHandle, err := diskStorage.InitializeKeyStorePersistence("tbtc")
	if err != nil {
		return nil, fmt.Errorf(
			"cannot open the tbtc keystore namespace: [%w]",
			err,
		)
	}

	wallets := make(map[string]*tbtcWalletRecord)
	seenMembers := make(map[string]map[uint8]struct{})

	tbtcData, tbtcErrors := tbtcHandle.ReadAll()
	tbtcDone := make(chan struct{})
	go func() {
		defer close(tbtcDone)
		for err := range tbtcErrors {
			run.finding("tbtc keystore namespace read error: [%v]", err)
		}
	}()
	for descriptor := range tbtcData {
		content, err := descriptor.Content()
		if err != nil {
			run.finding(
				"tbtc active record [%s/%s] cannot be decrypted: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		record, err := tbtc.DecodeSignerAuditRecord(content)
		if err != nil {
			run.finding(
				"tbtc active record [%s/%s] cannot be decoded the way the "+
					"wallet registry loader decodes it: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		if record.WalletStorageKey != descriptor.Directory() {
			run.finding(
				"tbtc active record [%s/%s] contains wallet [%s], not the "+
					"wallet its directory claims",
				descriptor.Directory(),
				descriptor.Name(),
				record.WalletStorageKey,
			)
		}

		// The registry saves each signer under "membership_<index>"; a record
		// whose content disagrees with its file name belongs to a different
		// member than the layout claims.
		if expected := fmt.Sprintf(
			"membership_%d",
			record.MemberIndex,
		); descriptor.Name() != expected {
			run.finding(
				"tbtc active record [%s/%s] contains member [%d], not the "+
					"member its file name claims",
				descriptor.Directory(),
				descriptor.Name(),
				record.MemberIndex,
			)
		}

		if record.SigningGroupSize <= 0 ||
			int(record.MemberIndex) < 1 ||
			int(record.MemberIndex) > record.SigningGroupSize {
			run.finding(
				"tbtc active record [%s/%s] claims member index [%d] outside "+
					"the signing group bounds [1, %d]",
				descriptor.Directory(),
				descriptor.Name(),
				record.MemberIndex,
				record.SigningGroupSize,
			)
		}

		wallet, ok := wallets[record.WalletStorageKey]
		if !ok {
			wallet = &tbtcWalletRecord{
				WalletStorageKey: record.WalletStorageKey,
				WalletID:         record.WalletID,
				SigningGroupSize: record.SigningGroupSize,
			}
			wallets[record.WalletStorageKey] = wallet
			seenMembers[record.WalletStorageKey] = make(map[uint8]struct{})
		}
		if wallet.SigningGroupSize != record.SigningGroupSize {
			run.finding(
				"tbtc active record [%s/%s] claims signing group size [%d] "+
					"while another record of the same wallet claims [%d]",
				descriptor.Directory(),
				descriptor.Name(),
				record.SigningGroupSize,
				wallet.SigningGroupSize,
			)
		}
		if _, duplicate := seenMembers[record.WalletStorageKey][uint8(
			record.MemberIndex,
		)]; duplicate {
			run.finding(
				"tbtc active record [%s/%s] duplicates member index [%d] of "+
					"the same wallet",
				descriptor.Directory(),
				descriptor.Name(),
				record.MemberIndex,
			)
		}
		seenMembers[record.WalletStorageKey][uint8(
			record.MemberIndex,
		)] = struct{}{}
		wallet.MemberIndexes = append(
			wallet.MemberIndexes,
			uint8(record.MemberIndex),
		)
	}
	<-tbtcDone

	activeWallets := make(map[string]struct{})
	for _, wallet := range wallets {
		sort.Slice(wallet.MemberIndexes, func(i, j int) bool {
			return wallet.MemberIndexes[i] < wallet.MemberIndexes[j]
		})
		run.manifest.TBTCActiveWallets = append(
			run.manifest.TBTCActiveWallets,
			*wallet,
		)
		activeWallets[wallet.WalletStorageKey] = struct{}{}
	}

	return activeWallets, nil
}

// tbtcQuarantineEntry pairs the two halves of one quarantined tBTC signer
// output while the namespace is scanned.
type tbtcQuarantineEntry struct {
	directory    string
	memberSuffix string
	metadata     *tbtc.QuarantinedSignerMetadata
	signer       *tbtc.SignerAuditRecord
}

// interpretTBTCQuarantineNamespace decodes the tBTC quarantine namespace,
// pairs metadata and signer halves by wallet directory and member suffix, and
// cross-validates the metadata against its schema, this release's identity,
// the cutover arithmetic, the storage location, the decoded signer, and the
// active namespace.
func interpretTBTCQuarantineNamespace(
	diskStorage storage.Storage,
	run *auditRun,
	activeWallets map[string]struct{},
) error {
	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"tbtc-quarantine",
	)
	if err != nil {
		return fmt.Errorf(
			"cannot open the tbtc quarantine namespace: [%w]",
			err,
		)
	}

	quarantineEntries := make(map[string]*tbtcQuarantineEntry)
	entryFor := func(directory, name, prefix string) *tbtcQuarantineEntry {
		suffix := strings.TrimPrefix(name, prefix)
		key := directory + "/" + suffix
		if _, ok := quarantineEntries[key]; !ok {
			quarantineEntries[key] = &tbtcQuarantineEntry{
				directory:    directory,
				memberSuffix: suffix,
			}
		}
		return quarantineEntries[key]
	}

	quarantineData, quarantineErrors := quarantineHandle.ReadAll()
	quarantineDone := make(chan struct{})
	go func() {
		defer close(quarantineDone)
		for err := range quarantineErrors {
			run.finding("tbtc quarantine namespace read error: [%v]", err)
		}
	}()
	for descriptor := range quarantineData {
		content, err := descriptor.Content()
		if err != nil {
			run.finding(
				"tbtc quarantine record [%s/%s] cannot be decrypted: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		switch {
		case strings.HasPrefix(descriptor.Name(), "metadata_"):
			metadata := &tbtc.QuarantinedSignerMetadata{}
			if err := json.Unmarshal(content, metadata); err != nil {
				run.finding(
					"tbtc quarantine metadata [%s/%s] cannot be decoded: [%v]",
					descriptor.Directory(),
					descriptor.Name(),
					err,
				)
				continue
			}
			entryFor(
				descriptor.Directory(),
				descriptor.Name(),
				"metadata_",
			).metadata = metadata
		case strings.HasPrefix(descriptor.Name(), "membership_"):
			record, err := tbtc.DecodeSignerAuditRecord(content)
			if err != nil {
				run.finding(
					"tbtc quarantine membership [%s/%s] cannot be decoded the "+
						"way the wallet registry loader decodes it: [%v]",
					descriptor.Directory(),
					descriptor.Name(),
					err,
				)
				continue
			}
			entryFor(
				descriptor.Directory(),
				descriptor.Name(),
				"membership_",
			).signer = record
		default:
			run.finding(
				"tbtc quarantine record [%s/%s] has an unknown name",
				descriptor.Directory(),
				descriptor.Name(),
			)
		}
	}
	<-quarantineDone

	keys := make([]string, 0, len(quarantineEntries))
	for key := range quarantineEntries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		entry := quarantineEntries[key]

		validateTBTCQuarantineEntry(run, entry, activeWallets)

		if entry.metadata == nil {
			continue
		}
		signerWalletID := ""
		if entry.signer != nil {
			signerWalletID = entry.signer.WalletID
		}
		run.manifest.TBTCQuarantinedOutputs = append(
			run.manifest.TBTCQuarantinedOutputs,
			tbtcQuarantineRecord{
				QuarantinedSignerMetadata: *entry.metadata,
				WalletStorageKey:          entry.directory,
				SignerWalletID:            signerWalletID,
				HasMembershipRecord:       entry.signer != nil,
			},
		)
	}

	return nil
}

// validateTBTCQuarantineEntry cross-validates one paired tBTC quarantine
// output. The metadata exists for the offline audit alone, so any half or
// field that contradicts the rest of the record makes the output
// untrustworthy evidence.
func validateTBTCQuarantineEntry(
	run *auditRun,
	entry *tbtcQuarantineEntry,
	activeWallets map[string]struct{},
) {
	key := entry.directory + "/" + entry.memberSuffix

	// A quarantined wallet visible in the active namespace is exactly the
	// ambiguity the quarantine exists to prevent: the same wallet would be
	// both activated and marked interrupted.
	if _, active := activeWallets[entry.directory]; active {
		run.finding(
			"tbtc quarantine output [%s] belongs to wallet [%s] that is "+
				"also present in the active namespace",
			key,
			entry.directory,
		)
	}

	if entry.signer != nil {
		if entry.signer.WalletStorageKey != entry.directory {
			run.finding(
				"tbtc quarantine membership [%s] contains wallet [%s], not "+
					"the wallet its directory claims",
				key,
				entry.signer.WalletStorageKey,
			)
		}
		if suffix := fmt.Sprint(
			entry.signer.MemberIndex,
		); suffix != entry.memberSuffix {
			run.finding(
				"tbtc quarantine membership [%s] contains member [%s], not "+
					"the member its file name claims",
				key,
				suffix,
			)
		}
	}

	if entry.metadata == nil {
		run.finding(
			"tbtc quarantine output [%s] has a membership record without "+
				"audit metadata",
			key,
		)
		return
	}

	metadata := entry.metadata
	if entry.signer == nil {
		run.finding(
			"tbtc quarantine output [%s] has audit metadata without a "+
				"membership record; the key material was not preserved",
			key,
		)
	}

	if metadata.SchemaVersion != tbtc.QuarantineSchemaVersion {
		run.finding(
			"tbtc quarantine metadata [%s] has schema version [%d], "+
				"expected [%d]",
			key,
			metadata.SchemaVersion,
			tbtc.QuarantineSchemaVersion,
		)
	}
	if metadata.ReleaseEpoch != participation.CompiledEpoch.String() {
		run.finding(
			"tbtc quarantine metadata [%s] was written by release epoch "+
				"[%s], not by this audit's epoch [%s]",
			key,
			metadata.ReleaseEpoch,
			participation.CompiledEpoch,
		)
	}
	if metadata.Ceremony != string(participation.TBTCDKG) {
		run.finding(
			"tbtc quarantine metadata [%s] names ceremony [%s]; only [%s] "+
				"outputs are quarantined",
			key,
			metadata.Ceremony,
			participation.TBTCDKG,
		)
	}
	if suffix := fmt.Sprint(metadata.MemberIndex); suffix != entry.memberSuffix {
		run.finding(
			"tbtc quarantine metadata [%s] names member [%s], not the "+
				"member its file name claims",
			key,
			suffix,
		)
	}
	if !isCanonicalSHA256Hex(metadata.SeedHash) {
		run.finding(
			"tbtc quarantine metadata [%s] seed hash [%s] is not a "+
				"canonical SHA-256 digest of 64 lowercase hexadecimal "+
				"characters",
			key,
			metadata.SeedHash,
		)
	}
	if metadata.MemberIndex == 0 {
		run.finding(
			"tbtc quarantine metadata [%s] names invalid member index [0]",
			key,
		)
	}
	if metadata.WalletPublicKeyHash == "" {
		run.finding(
			"tbtc quarantine metadata [%s] is missing the wallet public "+
				"key hash",
			key,
		)
	}

	validateTBTCQuarantineMode(run, key, metadata)

	if entry.signer == nil {
		return
	}

	if uint8(entry.signer.MemberIndex) != metadata.MemberIndex {
		run.finding(
			"tbtc quarantine output [%s] pairs metadata for member [%d] "+
				"with a membership of member [%d]",
			key,
			metadata.MemberIndex,
			entry.signer.MemberIndex,
		)
	}
	if metadata.WalletID != "" &&
		metadata.WalletID != entry.signer.WalletID {
		run.finding(
			"tbtc quarantine metadata [%s] names wallet ID [%s], but its "+
				"membership decodes to wallet ID [%s]",
			key,
			metadata.WalletID,
			entry.signer.WalletID,
		)
	}
	if metadata.WalletPublicKeyHash != "" &&
		metadata.WalletPublicKeyHash != entry.signer.WalletPublicKeyHash {
		run.finding(
			"tbtc quarantine metadata [%s] names wallet public key hash "+
				"[%s], but its membership decodes to [%s]",
			key,
			metadata.WalletPublicKeyHash,
			entry.signer.WalletPublicKeyHash,
		)
	}
}

// validateTBTCQuarantineMode checks the recorded protocol mode against the
// recorded cutover arithmetic — the mode is pinned from the canonical
// anchor, so a record that contradicts that rule was not produced by the
// release gate — and the recorded cutover block against the expected armed
// schedule: a record preserved under a different cutover block belongs to a
// different deployment than the one being rolled back.
func validateTBTCQuarantineMode(
	run *auditRun,
	key string,
	metadata *tbtc.QuarantinedSignerMetadata,
) {
	if run.expected.cutoverBlock > 0 &&
		metadata.CutoverBlock != run.expected.cutoverBlock {
		run.finding(
			"tbtc quarantine metadata [%s] was preserved under cutover "+
				"block [%d], not the expected cutover block [%d]",
			key,
			metadata.CutoverBlock,
			run.expected.cutoverBlock,
		)
	}

	if violation := cutoverModeViolation(
		fmt.Sprintf("tbtc quarantine metadata [%s]", key),
		metadata.ProtocolMode,
		metadata.CanonicalStartBlock,
		metadata.CutoverBlock,
	); violation != "" {
		run.finding("%s", violation)
	}
}

// sortRecords orders the interpreted records deterministically so two audits
// of the same snapshot produce byte-identical manifests apart from the
// generation time.
func sortRecords(auditManifest *manifest) {
	sort.Slice(auditManifest.BeaconActiveMemberships, func(i, j int) bool {
		left := auditManifest.BeaconActiveMemberships[i]
		right := auditManifest.BeaconActiveMemberships[j]
		if left.GroupPublicKey != right.GroupPublicKey {
			return left.GroupPublicKey < right.GroupPublicKey
		}
		return left.MemberIndex < right.MemberIndex
	})
	sort.Slice(auditManifest.BeaconQuarantinedOutputs, func(i, j int) bool {
		left := auditManifest.BeaconQuarantinedOutputs[i]
		right := auditManifest.BeaconQuarantinedOutputs[j]
		if left.GroupPublicKey != right.GroupPublicKey {
			return left.GroupPublicKey < right.GroupPublicKey
		}
		return left.MemberIndex < right.MemberIndex
	})
	sort.Slice(auditManifest.TBTCActiveWallets, func(i, j int) bool {
		return auditManifest.TBTCActiveWallets[i].WalletStorageKey <
			auditManifest.TBTCActiveWallets[j].WalletStorageKey
	})
	sort.Slice(auditManifest.TBTCQuarantinedOutputs, func(i, j int) bool {
		left := auditManifest.TBTCQuarantinedOutputs[i]
		right := auditManifest.TBTCQuarantinedOutputs[j]
		if left.WalletPublicKeyHash != right.WalletPublicKeyHash {
			return left.WalletPublicKeyHash < right.WalletPublicKeyHash
		}
		return left.MemberIndex < right.MemberIndex
	})
}
