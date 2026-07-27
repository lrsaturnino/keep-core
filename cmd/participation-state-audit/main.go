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
// operational identities — Ethereum chain ID, Bitcoin network, exact prior
// version and revision — and fall within the evidence freshness bound:
// schema-valid evidence for the wrong target or from long before the
// rollback decision blocks the barrier exactly like missing evidence. This
// tool's output never authorizes activating quarantined material by itself.
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
	"strings"
	"sync"
	"time"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/storage"
	"github.com/keep-network/keep-core/pkg/tbtc"
)

// manifestSchemaVersion versions the audit manifest document.
const manifestSchemaVersion = uint32(3)

// The audited namespaces, relative to the storage root. The beacon quarantine
// namespace is a sibling of the active beacon keystore precisely so the
// active-group scan cannot read it; the audit re-verifies that separation.
const (
	beaconKeystoreNamespace   = "keystore/beacon"
	beaconQuarantineNamespace = "keystore/beacon-quarantine"
	tbtcKeystoreNamespace     = "keystore/tbtc"
	tbtcQuarantineNamespace   = "keystore/tbtc-quarantine"
	tbtcWorkNamespace         = "work/tbtc"
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
	knownWorkEntries = []string{"tbtc"}
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
const evidenceSchemaVersion uint32 = 1

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
// and each one's terminal outcome.
type quiescenceReportEvidence struct {
	evidenceEnvelope

	QuiesceCause              string `json:"quiesce_cause"`
	ActivePermitsAtQuiescence []struct {
		Ceremony            string `json:"ceremony"`
		Mode                string `json:"mode"`
		CanonicalStartBlock uint64 `json:"canonical_start_block"`
		Outcome             string `json:"outcome"`
	} `json:"active_permits_at_quiescence"`
}

// priorReaderCompatibilityEvidence records the tested prior release and its
// result against every schema this release writes, including loading and
// signing with a wallet created after the cutover block.
type priorReaderCompatibilityEvidence struct {
	evidenceEnvelope

	PriorVersion  string `json:"prior_version"`
	PriorRevision string `json:"prior_revision"`
	SchemaResults []struct {
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
	WalletStorageKey string  `json:"wallet_storage_key"`
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
	EthereumChainID string `json:"ethereum_chain_id,omitempty"`
	BitcoinNetwork  string `json:"bitcoin_network,omitempty"`
	PriorVersion    string `json:"prior_version,omitempty"`
	PriorRevision   string `json:"prior_revision,omitempty"`
	MaxEvidenceAge  string `json:"max_evidence_age,omitempty"`
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
// run must supply all of them: without an expected chain, network, prior
// artifact identity, and freshness bound, schema-valid evidence generated
// against the wrong target — or long before the rollback decision — would
// pass. A missing input is a rollback blocker, not a skipped check.
type expectedIdentityInputs struct {
	ethereumChainID string
	bitcoinNetwork  string
	priorVersion    string
	priorRevision   string
	maxEvidenceAge  time.Duration
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
		"path to the node's quiescence outcome record: the permits active at "+
			"quiescence and each one's terminal outcome",
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
		if err := os.WriteFile(outputPath, encoded, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write the manifest: [%v]\n", err)
			os.Exit(1)
		}
	} else {
		os.Stdout.Write(encoded)
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
				EthereumChainID: expected.ethereumChainID,
				BitcoinNetwork:  expected.bitcoinNetwork,
				PriorVersion:    expected.priorVersion,
				PriorRevision:   expected.priorRevision,
				MaxEvidenceAge:  expected.maxEvidenceAge.String(),
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

// recordExternalEvidence records every externally produced rollback input,
// validates each supplied record against its mandatory schema and this exact
// snapshot, and turns each missing or invalid one into a rollback blocker. A
// supplied reference that cannot be read is an input error: fail fast instead
// of recording evidence that does not exist.
// recordMissingExpectedIdentity turns every unsupplied expected-identity
// input into a rollback blocker: evidence that is not bound to an explicit
// operational target can approve a rollback of the wrong chain, network, or
// prior artifact.
func recordMissingExpectedIdentity(r *auditRun) {
	missing := []struct {
		absent  bool
		blocker string
	}{
		{
			absent: r.expected.ethereumChainID == "",
			blocker: "the expected Ethereum chain ID is not supplied: the " +
				"chain reconciliation evidence cannot be bound to the " +
				"rollback's operational target",
		},
		{
			absent: r.expected.bitcoinNetwork == "",
			blocker: "the expected Bitcoin network is not supplied: the " +
				"Bitcoin reconciliation evidence cannot be bound to the " +
				"rollback's operational target",
		},
		{
			absent: r.expected.priorVersion == "",
			blocker: "the expected prior version is not supplied: the " +
				"prior-reader compatibility evidence cannot be bound to the " +
				"exact restored artifact",
		},
		{
			absent: r.expected.priorRevision == "",
			blocker: "the expected prior revision is not supplied: the " +
				"prior-reader compatibility evidence cannot be bound to the " +
				"exact restored artifact",
		},
		{
			absent: r.expected.maxEvidenceAge <= 0,
			blocker: "no evidence freshness bound is supplied: arbitrarily " +
				"old evidence cannot support a rollback decision",
		},
	}

	for _, input := range missing {
		if input.absent {
			r.manifest.RollbackBlockers = append(
				r.manifest.RollbackBlockers,
				input.blocker,
			)
		}
	}
}

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
			missing: "quiescence report not supplied: the permits active at " +
				"quiescence and their terminal outcomes are unverified",
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

// validateChainReconciliationEvidence checks the Ethereum reconciliation
// record: schema, snapshot binding, the expected chain identity, one-to-one
// coverage of every persisted tBTC wallet and beacon group — active and
// quarantined — and a settled, registered on-chain state for each active
// one. A quarantined output whose wallet or group is registered on chain is
// a blocker of its own: the prior binary would run that wallet without the
// preserved share.
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
	for i, wallet := range record.Wallets {
		if wallet.WalletStorageKey == "" || wallet.WalletID == "" {
			violations = append(violations, fmt.Sprintf(
				"wallet entry [%d] is missing its identity",
				i,
			))
			continue
		}
		wallets[wallet.WalletStorageKey] = i
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

// quarantineTriple identifies quarantined state by the immutable permit
// identity it was preserved under: the ceremony, the pinned protocol mode,
// and the canonical chain anchor.
type quarantineTriple struct {
	ceremony            string
	mode                string
	canonicalStartBlock uint64
}

// validateQuiescenceReportEvidence checks the quiescence outcome record:
// schema, snapshot binding, a stated cause, and a known ceremony, mode, and
// terminal outcome for every permit active at quiescence. Every quarantined
// DKG outcome must be matched by preserved quarantine state carrying the
// same ceremony, protocol mode, and canonical anchor — one preserved output
// per claiming permit, so one real output cannot vouch for several claims.
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

	if record.QuiesceCause == "" {
		violations = append(violations, "the quiescence cause is missing")
	}

	knownCeremonies := make(map[string]struct{})
	for _, ceremony := range participation.AllCeremonies() {
		knownCeremonies[string(ceremony)] = struct{}{}
	}

	beaconQuarantined := make(map[quarantineTriple]int)
	for _, quarantined := range r.manifest.BeaconQuarantinedOutputs {
		beaconQuarantined[quarantineTriple{
			ceremony:            quarantined.Ceremony,
			mode:                quarantined.ProtocolMode,
			canonicalStartBlock: quarantined.CanonicalStartBlock,
		}]++
	}
	tbtcQuarantined := make(map[quarantineTriple]int)
	for _, quarantined := range r.manifest.TBTCQuarantinedOutputs {
		tbtcQuarantined[quarantineTriple{
			ceremony:            quarantined.Ceremony,
			mode:                quarantined.ProtocolMode,
			canonicalStartBlock: quarantined.CanonicalStartBlock,
		}]++
	}

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
		}
		if _, ok := validQuiescencePermitOutcomes[permit.Outcome]; !ok {
			violations = append(violations, fmt.Sprintf(
				"permit entry [%d] has unknown terminal outcome [%s]",
				i,
				permit.Outcome,
			))
			continue
		}

		if permit.Outcome != "quarantined" || !r.manifest.Interpreted {
			continue
		}
		triple := quarantineTriple{
			ceremony:            permit.Ceremony,
			mode:                permit.Mode,
			canonicalStartBlock: permit.CanonicalStartBlock,
		}
		switch permit.Ceremony {
		case string(participation.BeaconDKG):
			if beaconQuarantined[triple] == 0 {
				violations = append(violations, fmt.Sprintf(
					"permit entry [%d] claims a quarantined [%s] output "+
						"[mode=%s] [canonicalStartBlock=%d] but the beacon "+
						"quarantine namespace holds none matching that "+
						"ceremony, mode, and anchor",
					i,
					permit.Ceremony,
					permit.Mode,
					permit.CanonicalStartBlock,
				))
				continue
			}
			beaconQuarantined[triple]--
		case string(participation.TBTCDKG):
			if tbtcQuarantined[triple] == 0 {
				violations = append(violations, fmt.Sprintf(
					"permit entry [%d] claims a quarantined [%s] output "+
						"[mode=%s] [canonicalStartBlock=%d] but the tbtc "+
						"quarantine namespace holds none matching that "+
						"ceremony, mode, and anchor",
					i,
					permit.Ceremony,
					permit.Mode,
					permit.CanonicalStartBlock,
				))
				continue
			}
			tbtcQuarantined[triple]--
		}
	}

	return violations
}

// validatePriorReaderCompatibilityEvidence checks the prior-reader record:
// schema, snapshot binding, an identified prior release, and an explicit
// compatible result for every schema this release writes. Any missing or
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

	if record.PriorVersion == "" {
		violations = append(violations, "the tested prior version is missing")
	} else if r.expected.priorVersion != "" &&
		record.PriorVersion != r.expected.priorVersion {
		violations = append(violations, fmt.Sprintf(
			"tested prior version [%s], expected [%s]",
			record.PriorVersion,
			r.expected.priorVersion,
		))
	}
	if record.PriorRevision == "" {
		violations = append(violations, "the tested prior revision is missing")
	} else if r.expected.priorRevision != "" &&
		record.PriorRevision != r.expected.priorRevision {
		violations = append(violations, fmt.Sprintf(
			"tested prior revision [%s], expected [%s]",
			record.PriorRevision,
			r.expected.priorRevision,
		))
	}

	results := make(map[string]bool)
	for _, result := range record.SchemaResults {
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

	sortRecords(run.manifest)

	return nil
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
// recorded cutover arithmetic: the mode is pinned from the canonical anchor,
// so a record that contradicts that rule was not produced by the release
// gate.
func validateQuarantineMode(
	run *auditRun,
	key string,
	metadata *registry.QuarantinedSignerMetadata,
) {
	legacy := participation.ModeLegacy.String()
	securityV2 := participation.ModeSecurityV2.String()

	switch metadata.ProtocolMode {
	case legacy:
		if metadata.CutoverBlock > 0 &&
			metadata.CanonicalStartBlock >= metadata.CutoverBlock {
			run.finding(
				"beacon quarantine metadata [%s] claims mode [%s] with "+
					"canonical anchor [%d] at or after cutover block [%d]",
				key,
				legacy,
				metadata.CanonicalStartBlock,
				metadata.CutoverBlock,
			)
		}
	case securityV2:
		if metadata.CutoverBlock == 0 {
			run.finding(
				"beacon quarantine metadata [%s] claims mode [%s] under a "+
					"disabled all-zero schedule",
				key,
				securityV2,
			)
		} else if metadata.CanonicalStartBlock < metadata.CutoverBlock {
			run.finding(
				"beacon quarantine metadata [%s] claims mode [%s] with "+
					"canonical anchor [%d] before cutover block [%d]",
				key,
				securityV2,
				metadata.CanonicalStartBlock,
				metadata.CutoverBlock,
			)
		}
	default:
		run.finding(
			"beacon quarantine metadata [%s] names unknown protocol mode "+
				"[%s]",
			key,
			metadata.ProtocolMode,
		)
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
		run.manifest.TBTCQuarantinedOutputs = append(
			run.manifest.TBTCQuarantinedOutputs,
			tbtcQuarantineRecord{
				QuarantinedSignerMetadata: *entry.metadata,
				WalletStorageKey:          entry.directory,
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
	if metadata.SeedHash == "" {
		run.finding(
			"tbtc quarantine metadata [%s] is missing the seed hash",
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

	if entry.signer != nil &&
		uint8(entry.signer.MemberIndex) != metadata.MemberIndex {
		run.finding(
			"tbtc quarantine output [%s] pairs metadata for member [%d] "+
				"with a membership of member [%d]",
			key,
			metadata.MemberIndex,
			entry.signer.MemberIndex,
		)
	}
}

// validateTBTCQuarantineMode checks the recorded protocol mode against the
// recorded cutover arithmetic: the mode is pinned from the canonical anchor,
// so a record that contradicts that rule was not produced by the release
// gate.
func validateTBTCQuarantineMode(
	run *auditRun,
	key string,
	metadata *tbtc.QuarantinedSignerMetadata,
) {
	legacy := participation.ModeLegacy.String()
	securityV2 := participation.ModeSecurityV2.String()

	switch metadata.ProtocolMode {
	case legacy:
		if metadata.CutoverBlock > 0 &&
			metadata.CanonicalStartBlock >= metadata.CutoverBlock {
			run.finding(
				"tbtc quarantine metadata [%s] claims mode [%s] with "+
					"canonical anchor [%d] at or after cutover block [%d]",
				key,
				legacy,
				metadata.CanonicalStartBlock,
				metadata.CutoverBlock,
			)
		}
	case securityV2:
		if metadata.CutoverBlock == 0 {
			run.finding(
				"tbtc quarantine metadata [%s] claims mode [%s] under a "+
					"disabled all-zero schedule",
				key,
				securityV2,
			)
		} else if metadata.CanonicalStartBlock < metadata.CutoverBlock {
			run.finding(
				"tbtc quarantine metadata [%s] claims mode [%s] with "+
					"canonical anchor [%d] before cutover block [%d]",
				key,
				securityV2,
				metadata.CanonicalStartBlock,
				metadata.CutoverBlock,
			)
		}
	default:
		run.finding(
			"tbtc quarantine metadata [%s] names unknown protocol mode [%s]",
			key,
			metadata.ProtocolMode,
		)
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
