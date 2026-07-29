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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	ecdsaabi "github.com/keep-network/keep-core/pkg/chain/ethereum/ecdsa/gen/abi"
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
const evidenceSchemaVersion uint32 = 7

const chainReconciliationSignatureDomain = "keep-core/" +
	"participation-state-audit/chain-reconciliation/v7\x00"

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

// ethereumLogEvidence identifies one canonical Ethereum log. The external
// evidence generator obtains these values from a receipt on the expected
// chain; the audit requires every event in the DKG lineage to name its exact
// transaction, block, and log position instead of accepting a free-standing
// settlement label.
type ethereumLogEvidence struct {
	TransactionHash string `json:"transaction_hash"`
	BlockHash       string `json:"block_hash"`
	BlockNumber     uint64 `json:"block_number"`
	LogIndex        uint64 `json:"log_index"`
}

// ethereumRawLogEvidence is the exact log projection returned in an Ethereum
// transaction receipt. Event summaries below are accepted only when the
// corresponding authenticated receipt contains byte-identical topics/data
// emitted by the expected WalletRegistry address.
type ethereumRawLogEvidence struct {
	Address  string   `json:"address"`
	Topics   []string `json:"topics"`
	Data     string   `json:"data"`
	LogIndex uint64   `json:"log_index"`
}

// ethereumReceiptEvidence carries the receipt fields needed to authenticate
// an event observation. The collector signature authenticates these fields;
// the audit still independently requires successful status, canonical block
// membership, exact transaction/block identity, and an exact raw event log.
type ethereumReceiptEvidence struct {
	TransactionHash  string                   `json:"transaction_hash"`
	BlockHash        string                   `json:"block_hash"`
	BlockNumber      uint64                   `json:"block_number"`
	TransactionIndex uint64                   `json:"transaction_index"`
	Status           uint64                   `json:"status"`
	Logs             []ethereumRawLogEvidence `json:"logs"`
}

type ethereumCanonicalBlockEvidence struct {
	BlockNumber uint64 `json:"block_number"`
	BlockHash   string `json:"block_hash"`
}

// ethereumCollectorAttestation makes the chain record an authenticated
// collector artifact instead of a caller-authored decoded summary. Signature
// is Ed25519 over the domain-separated canonical JSON encoding of the entire
// chainReconciliationEvidence with this field empty. The trusted public key,
// expected finalized block, and expected WalletRegistry are independent audit
// inputs and therefore cannot be selected by the evidence generator.
type ethereumCollectorAttestation struct {
	FinalizedBlockNumber uint64                           `json:"finalized_block_number"`
	FinalizedBlockHash   string                           `json:"finalized_block_hash"`
	CanonicalBlocks      []ethereumCanonicalBlockEvidence `json:"canonical_blocks"`
	Signature            string                           `json:"signature"`
}

// tbtcDKGChainResultEvidence is the complete EcdsaDkg.Result tuple emitted by
// DkgResultSubmitted. The audit ABI-encodes this tuple exactly as the
// WalletRegistry contract does and recomputes keccak256(abi.encode(result)).
// Summary-only inputs are deliberately insufficient: group size,
// misbehaviour, members hash, and wallet identity are all derived from these
// event bytes.
type tbtcDKGChainResultEvidence struct {
	SubmitterMemberIndex    uint16     `json:"submitter_member_index"`
	GroupPublicKey          string     `json:"group_public_key"`
	MisbehavedMemberIndexes []uint8    `json:"misbehaved_member_indexes"`
	Signatures              string     `json:"signatures"`
	SigningMemberIndexes    []*big.Int `json:"signing_member_indexes"`
	Members                 []uint32   `json:"members"`
	MembersHash             string     `json:"members_hash"`
}

type tbtcDKGStartedEventEvidence struct {
	ethereumLogEvidence
	Seed string `json:"seed"`
}

type tbtcDKGResultSubmittedEventEvidence struct {
	ethereumLogEvidence
	ResultHash string                     `json:"result_hash"`
	Seed       string                     `json:"seed"`
	Result     tbtcDKGChainResultEvidence `json:"result"`
}

type tbtcDKGResultApprovedEventEvidence struct {
	ethereumLogEvidence
	ResultHash string `json:"result_hash"`
}

type tbtcWalletCreatedEventEvidence struct {
	ethereumLogEvidence
	WalletID      string `json:"wallet_id"`
	DKGResultHash string `json:"dkg_result_hash"`
}

// tbtcDKGResultEvidence is the complete accepted-event lineage for the result
// that created a persisted tBTC wallet. DkgStarted binds the canonical anchor
// and seed, DkgResultSubmitted carries the bytes hashed by the contract, and
// DkgResultApproved plus WalletCreated prove the same result reached the
// wallet-creation transition.
type tbtcDKGResultEvidence struct {
	Started       tbtcDKGStartedEventEvidence         `json:"started"`
	Submitted     tbtcDKGResultSubmittedEventEvidence `json:"submitted"`
	Approved      tbtcDKGResultApprovedEventEvidence  `json:"approved"`
	WalletCreated tbtcWalletCreatedEventEvidence      `json:"wallet_created"`
}

func (e *tbtcDKGResultEvidence) resultHash() string {
	return strings.TrimPrefix(e.Submitted.ResultHash, "0x")
}

func (e *tbtcDKGResultEvidence) seedHash() (string, error) {
	seedBytes, err := decodeCanonicalEthereumBytes(e.Started.Seed, 32)
	if err != nil {
		return "", err
	}

	seed := new(big.Int).SetBytes(seedBytes)
	hash := sha256.Sum256(seed.Bytes())
	return hex.EncodeToString(hash[:]), nil
}

func (e *tbtcDKGResultEvidence) startBlock() uint64 {
	return e.Started.BlockNumber
}

func (e *tbtcDKGResultEvidence) originalGroupSize() uint16 {
	return uint16(len(e.Submitted.Result.Members))
}

func (e *tbtcDKGResultEvidence) misbehavedMemberIndexes() []uint8 {
	return e.Submitted.Result.MisbehavedMemberIndexes
}

type tbtcWalletChainEvidence struct {
	WalletStorageKey string                 `json:"wallet_storage_key"`
	WalletID         string                 `json:"wallet_id"`
	Registered       bool                   `json:"registered"`
	DKGSettlement    string                 `json:"dkg_settlement"`
	DKGResult        *tbtcDKGResultEvidence `json:"dkg_result,omitempty"`
}

// chainReconciliationEvidence records the on-chain wallet/group registration
// and DKG settlement state for every persisted group in the snapshot. An
// accepted tBTC result is part of the wallet identity: a bare "approved"
// assertion cannot prove which ceremony and original member produced a
// persisted final membership.
type chainReconciliationEvidence struct {
	evidenceEnvelope

	EthereumChainID       string                       `json:"ethereum_chain_id"`
	WalletRegistryAddress string                       `json:"wallet_registry_address"`
	Receipts              []ethereumReceiptEvidence    `json:"receipts"`
	CollectorAttestation  ethereumCollectorAttestation `json:"collector_attestation"`
	Wallets               []tbtcWalletChainEvidence    `json:"wallets"`
	BeaconGroups          []struct {
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
	EthereumChainID              string `json:"ethereum_chain_id,omitempty"`
	WalletRegistryAddress        string `json:"wallet_registry_address,omitempty"`
	FinalizedEthereumBlockNumber uint64 `json:"finalized_ethereum_block_number,omitempty"`
	FinalizedEthereumBlockHash   string `json:"finalized_ethereum_block_hash,omitempty"`
	ChainEvidencePublicKeySHA256 string `json:"chain_evidence_public_key_sha256,omitempty"`
	BitcoinNetwork               string `json:"bitcoin_network,omitempty"`
	PriorVersion                 string `json:"prior_version,omitempty"`
	PriorRevision                string `json:"prior_revision,omitempty"`
	PriorImageDigest             string `json:"prior_image_digest,omitempty"`
	ReleaseVersion               string `json:"release_version,omitempty"`
	ReleaseRevision              string `json:"release_revision,omitempty"`
	ReleaseImageDigest           string `json:"release_image_digest,omitempty"`
	ReleaseEpoch                 string `json:"release_epoch,omitempty"`
	CutoverBlock                 uint64 `json:"cutover_block,omitempty"`
	MaxEvidenceAge               string `json:"max_evidence_age,omitempty"`
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
	ethereumChainID              string
	walletRegistryAddress        string
	finalizedEthereumBlockNumber uint64
	finalizedEthereumBlockHash   string
	chainEvidencePublicKey       string
	bitcoinNetwork               string
	priorVersion                 string
	priorRevision                string
	priorImageDigest             string
	releaseVersion               string
	releaseRevision              string
	releaseImageDigest           string
	releaseEpoch                 string
	cutoverBlock                 uint64
	maxEvidenceAge               time.Duration
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
			"registration and DKG settlement state for every persisted group, "+
			"including the complete accepted tBTC DKG event lineage",
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
		&expected.walletRegistryAddress,
		"expected-wallet-registry-address",
		"",
		"the exact WalletRegistry address whose authenticated receipt logs "+
			"may establish tBTC DKG settlement",
	)
	flag.Uint64Var(
		&expected.finalizedEthereumBlockNumber,
		"expected-finalized-ethereum-block-number",
		0,
		"the independently obtained finalized Ethereum block number anchoring "+
			"the chain collector attestation",
	)
	flag.StringVar(
		&expected.finalizedEthereumBlockHash,
		"expected-finalized-ethereum-block-hash",
		"",
		"the independently obtained finalized Ethereum block hash anchoring "+
			"the chain collector attestation",
	)
	flag.StringVar(
		&expected.chainEvidencePublicKey,
		"expected-chain-evidence-public-key",
		"",
		"the lowercase hexadecimal Ed25519 public key of the independently "+
			"trusted finalized-chain evidence collector",
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
				EthereumChainID:              expected.ethereumChainID,
				WalletRegistryAddress:        expected.walletRegistryAddress,
				FinalizedEthereumBlockNumber: expected.finalizedEthereumBlockNumber,
				FinalizedEthereumBlockHash:   expected.finalizedEthereumBlockHash,
				ChainEvidencePublicKeySHA256: chainEvidencePublicKeySHA256(
					expected.chainEvidencePublicKey,
				),
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

// decodeCanonicalEthereumBytes decodes an exact-size, lowercase, 0x-prefixed
// Ethereum byte value. Requiring one canonical spelling keeps event identity,
// result hashes, and wallet IDs from acquiring case or prefix aliases.
func decodeCanonicalEthereumBytes(value string, size int) ([]byte, error) {
	if len(value) != 2+(size*2) || !strings.HasPrefix(value, "0x") {
		return nil, fmt.Errorf(
			"expected a 0x-prefixed lowercase hexadecimal value of %d bytes",
			size,
		)
	}
	for _, character := range value[2:] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return nil, fmt.Errorf(
				"expected a 0x-prefixed lowercase hexadecimal value of %d bytes",
				size,
			)
		}
	}

	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, fmt.Errorf("cannot decode hexadecimal value: [%v]", err)
	}
	return decoded, nil
}

func decodeCanonicalEthereumDynamicBytes(value string) ([]byte, error) {
	if len(value) < 2 || len(value)%2 != 0 || !strings.HasPrefix(value, "0x") {
		return nil, fmt.Errorf(
			"expected an even-length 0x-prefixed lowercase hexadecimal value",
		)
	}
	for _, character := range value[2:] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return nil, fmt.Errorf(
				"expected an even-length 0x-prefixed lowercase hexadecimal value",
			)
		}
	}

	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, fmt.Errorf("cannot decode hexadecimal value: [%v]", err)
	}
	return decoded, nil
}

func chainEvidencePublicKeySHA256(value string) string {
	decoded, err := hex.DecodeString(value)
	if err != nil ||
		len(decoded) != ed25519.PublicKeySize ||
		hex.EncodeToString(decoded) != value {
		return ""
	}
	checksum := sha256.Sum256(decoded)
	return hex.EncodeToString(checksum[:])
}

func tbtcDKGResultABIValue(
	result tbtcDKGChainResultEvidence,
) (ecdsaabi.EcdsaDkgResult, error) {
	groupPublicKey, err := decodeCanonicalEthereumBytes(
		result.GroupPublicKey,
		64,
	)
	if err != nil {
		return ecdsaabi.EcdsaDkgResult{}, fmt.Errorf(
			"invalid group public key: [%v]",
			err,
		)
	}
	signatures, err := decodeCanonicalEthereumDynamicBytes(result.Signatures)
	if err != nil {
		return ecdsaabi.EcdsaDkgResult{}, fmt.Errorf(
			"invalid signatures: [%v]",
			err,
		)
	}
	membersHashBytes, err := decodeCanonicalEthereumBytes(
		result.MembersHash,
		32,
	)
	if err != nil {
		return ecdsaabi.EcdsaDkgResult{}, fmt.Errorf(
			"invalid members hash: [%v]",
			err,
		)
	}
	var membersHash [32]byte
	copy(membersHash[:], membersHashBytes)

	signingMemberIndexes := make(
		[]*big.Int,
		len(result.SigningMemberIndexes),
	)
	for i, memberIndex := range result.SigningMemberIndexes {
		if memberIndex == nil {
			return ecdsaabi.EcdsaDkgResult{}, fmt.Errorf(
				"signing member index [%d] is null",
				i,
			)
		}
		signingMemberIndexes[i] = new(big.Int).Set(memberIndex)
	}

	return ecdsaabi.EcdsaDkgResult{
		SubmitterMemberIndex: new(big.Int).SetUint64(
			uint64(result.SubmitterMemberIndex),
		),
		GroupPubKey:              groupPublicKey,
		MisbehavedMembersIndices: result.MisbehavedMemberIndexes,
		Signatures:               signatures,
		SigningMembersIndices:    signingMemberIndexes,
		Members:                  result.Members,
		MembersHash:              membersHash,
	}, nil
}

func computeTBTCDKGResultHash(
	result tbtcDKGChainResultEvidence,
) (string, error) {
	abiValue, err := tbtcDKGResultABIValue(result)
	if err != nil {
		return "", err
	}

	resultType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "submitterMemberIndex", Type: "uint256"},
		{Name: "groupPubKey", Type: "bytes"},
		{Name: "misbehavedMembersIndices", Type: "uint8[]"},
		{Name: "signatures", Type: "bytes"},
		{Name: "signingMembersIndices", Type: "uint256[]"},
		{Name: "members", Type: "uint32[]"},
		{Name: "membersHash", Type: "bytes32"},
	})
	if err != nil {
		return "", fmt.Errorf("cannot construct DKG result ABI type: [%v]", err)
	}

	encoded, err := (abi.Arguments{{Type: resultType}}).Pack(abiValue)
	if err != nil {
		return "", fmt.Errorf("cannot ABI-encode DKG result: [%v]", err)
	}

	return "0x" + hex.EncodeToString(ethereumCrypto.Keccak256(encoded)), nil
}

func computeTBTCDKGMembersHash(
	result tbtcDKGChainResultEvidence,
) (string, error) {
	misbehaved := make(
		map[uint8]struct{},
		len(result.MisbehavedMemberIndexes),
	)
	for _, memberIndex := range result.MisbehavedMemberIndexes {
		misbehaved[memberIndex] = struct{}{}
	}

	operatingMembers := make([]uint32, 0, len(result.Members))
	for i, member := range result.Members {
		if _, excluded := misbehaved[uint8(i+1)]; excluded {
			continue
		}
		operatingMembers = append(operatingMembers, member)
	}

	uint32SliceType, err := abi.NewType("uint32[]", "uint32[]", nil)
	if err != nil {
		return "", fmt.Errorf("cannot construct members ABI type: [%v]", err)
	}
	encoded, err := (abi.Arguments{{Type: uint32SliceType}}).Pack(
		operatingMembers,
	)
	if err != nil {
		return "", fmt.Errorf("cannot ABI-encode operating members: [%v]", err)
	}

	return "0x" + hex.EncodeToString(ethereumCrypto.Keccak256(encoded)), nil
}

func computeTBTCWalletID(groupPublicKey string) (string, error) {
	publicKeyBytes, err := decodeCanonicalEthereumBytes(groupPublicKey, 64)
	if err != nil {
		return "", err
	}
	uncompressed := append([]byte{0x04}, publicKeyBytes...)
	if _, err := ethereumCrypto.UnmarshalPubkey(uncompressed); err != nil {
		return "", fmt.Errorf("invalid secp256k1 group public key: [%v]", err)
	}
	return "0x" + hex.EncodeToString(
		ethereumCrypto.Keccak256(publicKeyBytes),
	), nil
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
			when: r.expected.walletRegistryAddress == "",
			blocker: "the expected WalletRegistry address is not supplied: " +
				"authenticated logs cannot be bound to the rollback's " +
				"settlement contract",
		},
		{
			when: r.expected.walletRegistryAddress != "" &&
				func() bool {
					_, err := decodeCanonicalEthereumBytes(
						r.expected.walletRegistryAddress,
						20,
					)
					return err != nil
				}(),
			blocker: fmt.Sprintf(
				"the expected WalletRegistry address [%s] is not a "+
					"canonical Ethereum address",
				r.expected.walletRegistryAddress,
			),
		},
		{
			when: r.expected.finalizedEthereumBlockNumber == 0,
			blocker: "the expected finalized Ethereum block number is not " +
				"supplied: the chain evidence has no independent finality " +
				"anchor",
		},
		{
			when: r.expected.finalizedEthereumBlockHash == "",
			blocker: "the expected finalized Ethereum block hash is not " +
				"supplied: the chain evidence has no independent canonical " +
				"anchor",
		},
		{
			when: r.expected.finalizedEthereumBlockHash != "" &&
				func() bool {
					_, err := decodeCanonicalEthereumBytes(
						r.expected.finalizedEthereumBlockHash,
						32,
					)
					return err != nil
				}(),
			blocker: fmt.Sprintf(
				"the expected finalized Ethereum block hash [%s] is not "+
					"canonical",
				r.expected.finalizedEthereumBlockHash,
			),
		},
		{
			when: r.expected.chainEvidencePublicKey == "",
			blocker: "the expected chain-evidence public key is not supplied: " +
				"caller-authored Ethereum summaries cannot authorize rollback",
		},
		{
			when: r.expected.chainEvidencePublicKey != "" &&
				chainEvidencePublicKeySHA256(
					r.expected.chainEvidencePublicKey,
				) == "",
			blocker: "the expected chain-evidence public key is not a " +
				"lowercase hexadecimal Ed25519 public key",
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

func chainReconciliationSignaturePayload(
	record *chainReconciliationEvidence,
) ([]byte, error) {
	unsigned := *record
	unsigned.CollectorAttestation.Signature = ""

	encoded, err := json.Marshal(&unsigned)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot encode the canonical chain record: [%v]",
			err,
		)
	}

	payload := make(
		[]byte,
		0,
		len(chainReconciliationSignatureDomain)+len(encoded),
	)
	payload = append(payload, chainReconciliationSignatureDomain...)
	payload = append(payload, encoded...)
	return payload, nil
}

func (r *auditRun) validateAuthenticatedEthereumEvidence(
	record *chainReconciliationEvidence,
) []string {
	var violations []string

	if _, err := decodeCanonicalEthereumBytes(
		record.WalletRegistryAddress,
		20,
	); err != nil {
		violations = append(violations, fmt.Sprintf(
			"the WalletRegistry address [%s] is invalid: [%v]",
			record.WalletRegistryAddress,
			err,
		))
	} else if r.expected.walletRegistryAddress != "" &&
		record.WalletRegistryAddress != r.expected.walletRegistryAddress {
		violations = append(violations, fmt.Sprintf(
			"the WalletRegistry address [%s], expected [%s]",
			record.WalletRegistryAddress,
			r.expected.walletRegistryAddress,
		))
	}

	attestation := record.CollectorAttestation
	if attestation.FinalizedBlockNumber == 0 {
		violations = append(
			violations,
			"the collector attestation has no finalized block number",
		)
	} else if r.expected.finalizedEthereumBlockNumber != 0 &&
		attestation.FinalizedBlockNumber !=
			r.expected.finalizedEthereumBlockNumber {
		violations = append(violations, fmt.Sprintf(
			"the collector finalized block number [%d], expected [%d]",
			attestation.FinalizedBlockNumber,
			r.expected.finalizedEthereumBlockNumber,
		))
	}
	if _, err := decodeCanonicalEthereumBytes(
		attestation.FinalizedBlockHash,
		32,
	); err != nil {
		violations = append(violations, fmt.Sprintf(
			"the collector finalized block hash [%s] is invalid: [%v]",
			attestation.FinalizedBlockHash,
			err,
		))
	} else if r.expected.finalizedEthereumBlockHash != "" &&
		attestation.FinalizedBlockHash !=
			r.expected.finalizedEthereumBlockHash {
		violations = append(violations, fmt.Sprintf(
			"the collector finalized block hash [%s], expected [%s]",
			attestation.FinalizedBlockHash,
			r.expected.finalizedEthereumBlockHash,
		))
	}

	canonicalBlocks := make(map[uint64]string)
	var previousBlock uint64
	for i, block := range attestation.CanonicalBlocks {
		if block.BlockNumber == 0 {
			violations = append(violations, fmt.Sprintf(
				"canonical block entry [%d] has zero block number",
				i,
			))
		}
		if _, err := decodeCanonicalEthereumBytes(
			block.BlockHash,
			32,
		); err != nil {
			violations = append(violations, fmt.Sprintf(
				"canonical block [%d] has invalid hash [%s]: [%v]",
				block.BlockNumber,
				block.BlockHash,
				err,
			))
		}
		if _, duplicate := canonicalBlocks[block.BlockNumber]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"canonical block [%d] is attested more than once",
				block.BlockNumber,
			))
		}
		if i > 0 && block.BlockNumber <= previousBlock {
			violations = append(violations, fmt.Sprintf(
				"canonical block entries are not strictly increasing at [%d]",
				block.BlockNumber,
			))
		}
		canonicalBlocks[block.BlockNumber] = block.BlockHash
		previousBlock = block.BlockNumber
	}
	if hash, ok := canonicalBlocks[attestation.FinalizedBlockNumber]; !ok {
		violations = append(violations, fmt.Sprintf(
			"the finalized block [%d] is absent from the authenticated "+
				"canonical block set",
			attestation.FinalizedBlockNumber,
		))
	} else if hash != attestation.FinalizedBlockHash {
		violations = append(violations, fmt.Sprintf(
			"canonical block [%d] has hash [%s], not the attested finalized "+
				"hash [%s]",
			attestation.FinalizedBlockNumber,
			hash,
			attestation.FinalizedBlockHash,
		))
	}

	publicKey, publicKeyErr := hex.DecodeString(
		r.expected.chainEvidencePublicKey,
	)
	signature, signatureErr := hex.DecodeString(attestation.Signature)
	switch {
	case publicKeyErr != nil ||
		len(publicKey) != ed25519.PublicKeySize ||
		hex.EncodeToString(publicKey) != r.expected.chainEvidencePublicKey:
		violations = append(
			violations,
			"the independently supplied chain-evidence public key is invalid",
		)
	case signatureErr != nil ||
		len(signature) != ed25519.SignatureSize ||
		hex.EncodeToString(signature) != attestation.Signature:
		violations = append(
			violations,
			"the collector attestation signature is not canonical Ed25519",
		)
	default:
		payload, err := chainReconciliationSignaturePayload(record)
		if err != nil {
			violations = append(violations, err.Error())
		} else if !ed25519.Verify(publicKey, payload, signature) {
			violations = append(
				violations,
				"the chain reconciliation record is not signed by the "+
					"independently trusted finalized-chain collector",
			)
		}
	}

	receipts := make(map[string]struct{})
	for i, receipt := range record.Receipts {
		if _, err := decodeCanonicalEthereumBytes(
			receipt.TransactionHash,
			32,
		); err != nil {
			violations = append(violations, fmt.Sprintf(
				"receipt [%d] has invalid transaction hash [%s]: [%v]",
				i,
				receipt.TransactionHash,
				err,
			))
		}
		if _, duplicate := receipts[receipt.TransactionHash]; duplicate {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] is supplied more than once",
				receipt.TransactionHash,
			))
		}
		receipts[receipt.TransactionHash] = struct{}{}

		if receipt.BlockNumber == 0 {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] has zero block number",
				receipt.TransactionHash,
			))
		}
		if receipt.BlockNumber > attestation.FinalizedBlockNumber {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] at block [%d] is newer than the "+
					"attested finalized block [%d]",
				receipt.TransactionHash,
				receipt.BlockNumber,
				attestation.FinalizedBlockNumber,
			))
		}
		if _, err := decodeCanonicalEthereumBytes(
			receipt.BlockHash,
			32,
		); err != nil {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] has invalid block hash [%s]: [%v]",
				receipt.TransactionHash,
				receipt.BlockHash,
				err,
			))
		}
		if canonicalHash, ok := canonicalBlocks[receipt.BlockNumber]; !ok {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] block [%d] is absent from the "+
					"authenticated canonical block set",
				receipt.TransactionHash,
				receipt.BlockNumber,
			))
		} else if canonicalHash != receipt.BlockHash {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] names non-canonical block hash "+
					"[%s] at height [%d]; the collector attests [%s]",
				receipt.TransactionHash,
				receipt.BlockHash,
				receipt.BlockNumber,
				canonicalHash,
			))
		}
		if receipt.Status != 1 {
			violations = append(violations, fmt.Sprintf(
				"transaction receipt [%s] has failed status [%d]",
				receipt.TransactionHash,
				receipt.Status,
			))
		}

		logIndexes := make(map[uint64]struct{})
		for j, rawLog := range receipt.Logs {
			if _, duplicate := logIndexes[rawLog.LogIndex]; duplicate {
				violations = append(violations, fmt.Sprintf(
					"transaction receipt [%s] repeats log index [%d]",
					receipt.TransactionHash,
					rawLog.LogIndex,
				))
			}
			logIndexes[rawLog.LogIndex] = struct{}{}
			if _, err := decodeCanonicalEthereumBytes(
				rawLog.Address,
				20,
			); err != nil {
				violations = append(violations, fmt.Sprintf(
					"transaction receipt [%s] log [%d] has invalid address "+
						"[%s]: [%v]",
					receipt.TransactionHash,
					j,
					rawLog.Address,
					err,
				))
			}
			for k, topic := range rawLog.Topics {
				if _, err := decodeCanonicalEthereumBytes(topic, 32); err != nil {
					violations = append(violations, fmt.Sprintf(
						"transaction receipt [%s] log [%d] topic [%d] is "+
							"invalid [%s]: [%v]",
						receipt.TransactionHash,
						j,
						k,
						topic,
						err,
					))
				}
			}
			if _, err := decodeCanonicalEthereumDynamicBytes(
				rawLog.Data,
			); err != nil {
				violations = append(violations, fmt.Sprintf(
					"transaction receipt [%s] log [%d] has invalid data: [%v]",
					receipt.TransactionHash,
					j,
					err,
				))
			}
		}
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
	violations = append(
		violations,
		r.validateAuthenticatedEthereumEvidence(record)...,
	)

	wallets := make(map[string]int)
	walletIDs := make(map[string]string)
	dkgResultHashes := make(map[string]string)
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
		if wallet.DKGSettlement == "none" {
			if wallet.DKGResult != nil {
				violations = append(violations, fmt.Sprintf(
					"tbtc wallet [%s] claims no DKG settlement but also "+
						"names result [%s]",
					wallet.WalletStorageKey,
					wallet.DKGResult.resultHash(),
				))
			}
		} else if wallet.DKGResult == nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] has DKG settlement [%s] without the "+
					"canonical DKG result that produced it",
				wallet.WalletStorageKey,
				wallet.DKGSettlement,
			))
		} else {
			violations = append(
				violations,
				validateTBTCDKGResultEvidence(
					wallet.WalletStorageKey,
					wallet.WalletID,
					wallet.DKGResult,
					record,
				)...,
			)
			resultHash := wallet.DKGResult.resultHash()
			if previous, duplicate := dkgResultHashes[resultHash]; duplicate {
				violations = append(violations, fmt.Sprintf(
					"DKG result [%s] is claimed by both tbtc wallet [%s] "+
						"and tbtc wallet [%s]",
					resultHash,
					previous,
					wallet.WalletStorageKey,
				))
			} else {
				dkgResultHashes[resultHash] = wallet.WalletStorageKey
			}
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
		if result := record.Wallets[i].DKGResult; result != nil {
			originalGroupSize := result.originalGroupSize()
			misbehavedMemberIndexes := result.misbehavedMemberIndexes()
			finalGroupSize :=
				int(originalGroupSize) - len(misbehavedMemberIndexes)
			if finalGroupSize != wallet.SigningGroupSize {
				violations = append(violations, fmt.Sprintf(
					"persisted tbtc wallet [%s] has signing group size "+
						"[%d], but canonical DKG result [%s] derives [%d] "+
						"members from original group size [%d] and [%d] "+
						"misbehaved seats",
					wallet.WalletStorageKey,
					wallet.SigningGroupSize,
					result.resultHash(),
					finalGroupSize,
					originalGroupSize,
					len(misbehavedMemberIndexes),
				))
			}
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
	violations = append(
		violations,
		validateTBTCDKGTerminalLineage(r.manifest, record, wallets)...,
	)

	return violations
}

func expectedTBTCDKGRawLog(
	eventName string,
	result *tbtcDKGResultEvidence,
) ([]string, string, error) {
	parsed, err := ecdsaabi.WalletRegistryMetaData.GetAbi()
	if err != nil {
		return nil, "", fmt.Errorf(
			"cannot load the generated WalletRegistry ABI: [%v]",
			err,
		)
	}
	event, ok := parsed.Events[eventName]
	if !ok {
		return nil, "", fmt.Errorf(
			"generated WalletRegistry ABI has no [%s] event",
			eventName,
		)
	}

	topics := []string{event.ID.Hex()}
	var values []interface{}
	switch eventName {
	case "DkgStarted":
		topics = append(topics, result.Started.Seed)
	case "DkgResultSubmitted":
		topics = append(
			topics,
			result.Submitted.ResultHash,
			result.Submitted.Seed,
		)
		abiValue, err := tbtcDKGResultABIValue(result.Submitted.Result)
		if err != nil {
			return nil, "", err
		}
		values = append(values, abiValue)
	case "DkgResultApproved":
		// The approver is not part of wallet identity, but its indexed address
		// must still be present and canonically encoded in the raw log. An
		// empty expected topic below is that one explicit wildcard.
		topics = append(topics, result.Approved.ResultHash, "")
	case "WalletCreated":
		topics = append(
			topics,
			result.WalletCreated.WalletID,
			result.WalletCreated.DKGResultHash,
		)
	default:
		return nil, "", fmt.Errorf(
			"unsupported WalletRegistry event [%s]",
			eventName,
		)
	}

	data, err := event.Inputs.NonIndexed().Pack(values...)
	if err != nil {
		return nil, "", fmt.Errorf(
			"cannot ABI-encode expected [%s] event data: [%v]",
			eventName,
			err,
		)
	}
	return topics, "0x" + hex.EncodeToString(data), nil
}

func validateTBTCDKGAuthenticatedLineage(
	walletStorageKey string,
	result *tbtcDKGResultEvidence,
	record *chainReconciliationEvidence,
) []string {
	var violations []string

	receipts := make(map[string]ethereumReceiptEvidence)
	for _, receipt := range record.Receipts {
		if _, duplicate := receipts[receipt.TransactionHash]; !duplicate {
			receipts[receipt.TransactionHash] = receipt
		}
	}

	for _, observed := range []struct {
		name string
		log  ethereumLogEvidence
	}{
		{"DkgStarted", result.Started.ethereumLogEvidence},
		{"DkgResultSubmitted", result.Submitted.ethereumLogEvidence},
		{"DkgResultApproved", result.Approved.ethereumLogEvidence},
		{"WalletCreated", result.WalletCreated.ethereumLogEvidence},
	} {
		receipt, ok := receipts[observed.log.TransactionHash]
		if !ok {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event transaction [%s] has no "+
					"authenticated receipt",
				walletStorageKey,
				observed.name,
				observed.log.TransactionHash,
			))
			continue
		}
		if receipt.BlockHash != observed.log.BlockHash ||
			receipt.BlockNumber != observed.log.BlockNumber {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event block identity does not match "+
					"its authenticated receipt",
				walletStorageKey,
				observed.name,
			))
		}
		if receipt.Status != 1 {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event belongs to failed receipt [%s]",
				walletStorageKey,
				observed.name,
				observed.log.TransactionHash,
			))
		}

		var rawLog *ethereumRawLogEvidence
		for i := range receipt.Logs {
			if receipt.Logs[i].LogIndex == observed.log.LogIndex {
				rawLog = &receipt.Logs[i]
				break
			}
		}
		if rawLog == nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event log index [%d] is absent from "+
					"authenticated receipt [%s]",
				walletStorageKey,
				observed.name,
				observed.log.LogIndex,
				observed.log.TransactionHash,
			))
			continue
		}
		if rawLog.Address != record.WalletRegistryAddress {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event was emitted by unrelated "+
					"contract [%s], expected WalletRegistry [%s]",
				walletStorageKey,
				observed.name,
				rawLog.Address,
				record.WalletRegistryAddress,
			))
		}

		expectedTopics, expectedData, err := expectedTBTCDKGRawLog(
			observed.name,
			result,
		)
		if err != nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] cannot derive expected %s event bytes: [%v]",
				walletStorageKey,
				observed.name,
				err,
			))
			continue
		}
		if len(rawLog.Topics) != len(expectedTopics) {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s raw log has [%d] topics, expected [%d]",
				walletStorageKey,
				observed.name,
				len(rawLog.Topics),
				len(expectedTopics),
			))
		} else {
			for i, expectedTopic := range expectedTopics {
				if expectedTopic == "" {
					decoded, err := decodeCanonicalEthereumBytes(
						rawLog.Topics[i],
						32,
					)
					if err == nil {
						for _, prefix := range decoded[:12] {
							if prefix != 0 {
								err = fmt.Errorf(
									"address topic is not left-padded with zeroes",
								)
								break
							}
						}
					}
					if err != nil {
						violations = append(violations, fmt.Sprintf(
							"tbtc wallet [%s] %s raw approver topic is "+
								"invalid: [%v]",
							walletStorageKey,
							observed.name,
							err,
						))
					}
					continue
				}
				if rawLog.Topics[i] != expectedTopic {
					violations = append(violations, fmt.Sprintf(
						"tbtc wallet [%s] %s raw topic [%d] [%s] does not "+
							"match decoded event value [%s]",
						walletStorageKey,
						observed.name,
						i,
						rawLog.Topics[i],
						expectedTopic,
					))
				}
			}
		}
		if rawLog.Data != expectedData {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s raw data does not match the decoded "+
					"event value",
				walletStorageKey,
				observed.name,
			))
		}
	}

	return violations
}

func validateTBTCDKGResultEvidence(
	walletStorageKey string,
	walletID string,
	result *tbtcDKGResultEvidence,
	record *chainReconciliationEvidence,
) []string {
	violations := make([]string, 0)
	resultHash := result.resultHash()
	violations = append(
		violations,
		validateTBTCDKGAuthenticatedLineage(
			walletStorageKey,
			result,
			record,
		)...,
	)

	for _, event := range []struct {
		name string
		log  ethereumLogEvidence
	}{
		{"DkgStarted", result.Started.ethereumLogEvidence},
		{"DkgResultSubmitted", result.Submitted.ethereumLogEvidence},
		{"DkgResultApproved", result.Approved.ethereumLogEvidence},
		{"WalletCreated", result.WalletCreated.ethereumLogEvidence},
	} {
		if _, err := decodeCanonicalEthereumBytes(
			event.log.TransactionHash,
			32,
		); err != nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event has invalid transaction hash "+
					"[%s]: [%v]",
				walletStorageKey,
				event.name,
				event.log.TransactionHash,
				err,
			))
		}
		if _, err := decodeCanonicalEthereumBytes(
			event.log.BlockHash,
			32,
		); err != nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event has invalid block hash [%s]: [%v]",
				walletStorageKey,
				event.name,
				event.log.BlockHash,
				err,
			))
		}
		if event.log.BlockNumber == 0 {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s event has zero block number",
				walletStorageKey,
				event.name,
			))
		}
	}

	if _, err := decodeCanonicalEthereumBytes(result.Started.Seed, 32); err != nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgStarted event has invalid seed [%s]: [%v]",
			walletStorageKey,
			result.Started.Seed,
			err,
		))
	}
	if _, err := decodeCanonicalEthereumBytes(result.Submitted.Seed, 32); err != nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgResultSubmitted event has invalid seed "+
				"[%s]: [%v]",
			walletStorageKey,
			result.Submitted.Seed,
			err,
		))
	}
	if result.Started.Seed != result.Submitted.Seed {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgStarted seed [%s] does not match "+
				"DkgResultSubmitted seed [%s]",
			walletStorageKey,
			result.Started.Seed,
			result.Submitted.Seed,
		))
	}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"DkgResultSubmitted result hash", result.Submitted.ResultHash},
		{"DkgResultApproved result hash", result.Approved.ResultHash},
		{"WalletCreated DKG result hash", result.WalletCreated.DKGResultHash},
		{"WalletCreated wallet ID", result.WalletCreated.WalletID},
	} {
		if _, err := decodeCanonicalEthereumBytes(field.value, 32); err != nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] %s [%s] is invalid: [%v]",
				walletStorageKey,
				field.name,
				field.value,
				err,
			))
		}
	}

	if result.Approved.ResultHash != result.Submitted.ResultHash {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgResultApproved hash [%s] does not match "+
				"DkgResultSubmitted hash [%s]",
			walletStorageKey,
			result.Approved.ResultHash,
			result.Submitted.ResultHash,
		))
	}
	if result.WalletCreated.DKGResultHash != result.Submitted.ResultHash {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] WalletCreated DKG result hash [%s] does not "+
				"match DkgResultSubmitted hash [%s]",
			walletStorageKey,
			result.WalletCreated.DKGResultHash,
			result.Submitted.ResultHash,
		))
	}

	if result.Started.BlockNumber > result.Submitted.BlockNumber {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgStarted block [%d] is after "+
				"DkgResultSubmitted block [%d]",
			walletStorageKey,
			result.Started.BlockNumber,
			result.Submitted.BlockNumber,
		))
	}
	if result.Submitted.BlockNumber > result.Approved.BlockNumber {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgResultSubmitted block [%d] is after "+
				"DkgResultApproved block [%d]",
			walletStorageKey,
			result.Submitted.BlockNumber,
			result.Approved.BlockNumber,
		))
	}
	if result.Approved.TransactionHash != result.WalletCreated.TransactionHash ||
		result.Approved.BlockHash != result.WalletCreated.BlockHash ||
		result.Approved.BlockNumber != result.WalletCreated.BlockNumber {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgResultApproved and WalletCreated events "+
				"do not belong to the same approval receipt",
			walletStorageKey,
		))
	} else if result.WalletCreated.LogIndex <= result.Approved.LogIndex {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] WalletCreated log index [%d] does not follow "+
				"DkgResultApproved log index [%d] in the approval receipt",
			walletStorageKey,
			result.WalletCreated.LogIndex,
			result.Approved.LogIndex,
		))
	}

	chainResult := result.Submitted.Result
	originalGroupSize := result.originalGroupSize()
	if originalGroupSize == 0 ||
		originalGroupSize > uint16(group.MaxMemberIndex) {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] has invalid original group "+
				"size [%d]",
			walletStorageKey,
			resultHash,
			originalGroupSize,
		))
	}
	if chainResult.SubmitterMemberIndex == 0 ||
		chainResult.SubmitterMemberIndex > originalGroupSize {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] has submitter member [%d] "+
				"outside original group size [%d]",
			walletStorageKey,
			resultHash,
			chainResult.SubmitterMemberIndex,
			originalGroupSize,
		))
	}
	if len(chainResult.Members) > int(group.MaxMemberIndex) {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] carries [%d] original "+
				"members, exceeding [%d]",
			walletStorageKey,
			resultHash,
			len(chainResult.Members),
			group.MaxMemberIndex,
		))
	}
	for i, member := range chainResult.Members {
		if member == 0 {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] DKG result [%s] has zero operator ID at "+
					"original member [%d]",
				walletStorageKey,
				resultHash,
				i+1,
			))
		}
	}
	if chainResult.MisbehavedMemberIndexes == nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] omits the complete "+
				"misbehaved-member set",
			walletStorageKey,
			resultHash,
		))
	}
	var previous uint8
	for i, memberIndex := range chainResult.MisbehavedMemberIndexes {
		if memberIndex == 0 ||
			uint16(memberIndex) > originalGroupSize {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] DKG result [%s] has misbehaved member "+
					"[%d] outside original group size [%d]",
				walletStorageKey,
				resultHash,
				memberIndex,
				originalGroupSize,
			))
		}
		if i > 0 && memberIndex <= previous {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] DKG result [%s] misbehaved members are "+
					"not strictly increasing at [%d]",
				walletStorageKey,
				resultHash,
				memberIndex,
			))
		}
		previous = memberIndex
	}
	if len(chainResult.MisbehavedMemberIndexes) >= int(originalGroupSize) {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] leaves no final signing-group "+
				"member",
			walletStorageKey,
			resultHash,
		))
	}

	if chainResult.SigningMemberIndexes == nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] omits signing-member indexes",
			walletStorageKey,
			resultHash,
		))
	} else if len(chainResult.SigningMemberIndexes) == 0 {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] has no signing member",
			walletStorageKey,
			resultHash,
		))
	}
	misbehaved := make(map[uint8]struct{}, len(chainResult.MisbehavedMemberIndexes))
	for _, memberIndex := range chainResult.MisbehavedMemberIndexes {
		misbehaved[memberIndex] = struct{}{}
	}
	if _, excluded := misbehaved[uint8(chainResult.SubmitterMemberIndex)]; excluded {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] names misbehaved member [%d] "+
				"as its submitter",
			walletStorageKey,
			resultHash,
			chainResult.SubmitterMemberIndex,
		))
	}
	var previousSigning *big.Int
	for i, memberIndex := range chainResult.SigningMemberIndexes {
		if memberIndex == nil {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] DKG result [%s] has null signing member "+
					"at position [%d]",
				walletStorageKey,
				resultHash,
				i,
			))
			continue
		}
		if memberIndex.Sign() <= 0 ||
			!memberIndex.IsUint64() ||
			memberIndex.Uint64() > uint64(originalGroupSize) {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] DKG result [%s] has signing member [%s] "+
					"outside original group size [%d]",
				walletStorageKey,
				resultHash,
				memberIndex.String(),
				originalGroupSize,
			))
		}
		if memberIndex.IsUint64() {
			if _, excluded := misbehaved[uint8(memberIndex.Uint64())]; excluded {
				violations = append(violations, fmt.Sprintf(
					"tbtc wallet [%s] DKG result [%s] names misbehaved "+
						"member [%s] as a signer",
					walletStorageKey,
					resultHash,
					memberIndex.String(),
				))
			}
		}
		if previousSigning != nil && memberIndex.Cmp(previousSigning) <= 0 {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] DKG result [%s] signing members are not "+
					"strictly increasing at [%s]",
				walletStorageKey,
				resultHash,
				memberIndex.String(),
			))
		}
		previousSigning = memberIndex
	}
	if signatures, err := decodeCanonicalEthereumDynamicBytes(
		chainResult.Signatures,
	); err != nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] has invalid signatures: [%v]",
			walletStorageKey,
			resultHash,
			err,
		))
	} else if len(signatures) != 65*len(chainResult.SigningMemberIndexes) {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] carries [%d] signature bytes "+
				"for [%d] signing members",
			walletStorageKey,
			resultHash,
			len(signatures),
			len(chainResult.SigningMemberIndexes),
		))
	}

	if calculatedMembersHash, err := computeTBTCDKGMembersHash(
		chainResult,
	); err != nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] cannot derive DKG members hash: [%v]",
			walletStorageKey,
			err,
		))
	} else if calculatedMembersHash != chainResult.MembersHash {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DKG result [%s] members hash [%s] does not "+
				"match the derived operating-members hash [%s]",
			walletStorageKey,
			resultHash,
			chainResult.MembersHash,
			calculatedMembersHash,
		))
	}

	if calculatedResultHash, err := computeTBTCDKGResultHash(
		chainResult,
	); err != nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] cannot derive DKG result hash from the "+
				"submitted event: [%v]",
			walletStorageKey,
			err,
		))
	} else if calculatedResultHash != result.Submitted.ResultHash {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] DkgResultSubmitted hash [%s] does not match "+
				"keccak256(abi.encode(result)) [%s]",
			walletStorageKey,
			result.Submitted.ResultHash,
			calculatedResultHash,
		))
	}

	if calculatedWalletID, err := computeTBTCWalletID(
		chainResult.GroupPublicKey,
	); err != nil {
		violations = append(violations, fmt.Sprintf(
			"tbtc wallet [%s] cannot derive wallet ID from the submitted "+
				"group public key: [%v]",
			walletStorageKey,
			err,
		))
	} else {
		if calculatedWalletID != result.WalletCreated.WalletID {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] WalletCreated ID [%s] does not match "+
					"keccak256(group public key) [%s]",
				walletStorageKey,
				result.WalletCreated.WalletID,
				calculatedWalletID,
			))
		}
		if strings.TrimPrefix(calculatedWalletID, "0x") != walletID {
			violations = append(violations, fmt.Sprintf(
				"tbtc wallet [%s] accepted event lineage derives wallet ID "+
					"[%s], but chain reconciliation names [%s]",
				walletStorageKey,
				strings.TrimPrefix(calculatedWalletID, "0x"),
				walletID,
			))
		}
	}

	return violations
}

// validateTBTCDKGTerminalLineage binds a completed node-owned DKG permit to
// the canonical accepted result for the persisted wallet it names. tBTC
// permits use the original selected-group index while persisted memberships
// use the compacted final signing-group index; the result's misbehaved seats
// are the only authoritative mapping between those identities.
func validateTBTCDKGTerminalLineage(
	auditManifest *manifest,
	record *chainReconciliationEvidence,
	wallets map[string]int,
) []string {
	journal := auditManifest.ParticipationTerminalOutcomes
	if journal == nil {
		return nil
	}

	violations := make([]string, 0)
	for i, outcome := range journal.Outcomes {
		if outcome.Outcome != participation.TerminalOutcomeCompleted ||
			outcome.Permit.Ceremony != participation.TBTCDKG ||
			outcome.Evidence.Kind !=
				participation.TerminalEvidencePersistedTBTCSinger {
			continue
		}

		walletIndex, ok := wallets[outcome.Evidence.Reference]
		if !ok {
			continue
		}
		wallet := record.Wallets[walletIndex]
		if wallet.DKGSettlement != "approved" || wallet.DKGResult == nil {
			continue
		}
		result := wallet.DKGResult
		resultSeedHash, _ := result.seedHash()
		resultHash := result.resultHash()
		resultStartBlock := result.startBlock()
		originalGroupSize := result.originalGroupSize()
		misbehavedMemberIndexes := result.misbehavedMemberIndexes()

		if outcome.Permit.WorkID != resultSeedHash {
			violations = append(violations, fmt.Sprintf(
				"node-authored completed tbtc DKG outcome [%d] belongs to "+
					"seed [%s], but persisted wallet [%s] was created by "+
					"canonical result [%s] for seed [%s]",
				i,
				outcome.Permit.WorkID,
				wallet.WalletStorageKey,
				resultHash,
				resultSeedHash,
			))
		}
		if outcome.Permit.CanonicalStartBlock != resultStartBlock {
			violations = append(violations, fmt.Sprintf(
				"node-authored completed tbtc DKG outcome [%d] has "+
					"canonical start block [%d], but persisted wallet [%s] "+
					"was created by result [%s] anchored at [%d]",
				i,
				outcome.Permit.CanonicalStartBlock,
				wallet.WalletStorageKey,
				resultHash,
				resultStartBlock,
			))
		}

		originalMemberIndex, err := strconv.ParseUint(
			outcome.Permit.PermitID,
			10,
			8,
		)
		if err != nil {
			continue
		}
		finalMemberIndex, included := finalTBTCDKGMembership(
			group.MemberIndex(originalMemberIndex),
			originalGroupSize,
			misbehavedMemberIndexes,
		)
		if !included {
			violations = append(violations, fmt.Sprintf(
				"node-authored completed tbtc DKG outcome [%d] belongs to "+
					"original member [%s], but canonical result [%s] does "+
					"not include that member in its final signing group",
				i,
				outcome.Permit.PermitID,
				resultHash,
			))
		} else if outcome.Evidence.MembershipIndex != finalMemberIndex {
			violations = append(violations, fmt.Sprintf(
				"node-authored completed tbtc DKG outcome [%d] belongs to "+
					"original member [%s], which canonical result [%s] maps "+
					"to final membership [%d], but names persisted "+
					"membership [%d]",
				i,
				outcome.Permit.PermitID,
				resultHash,
				finalMemberIndex,
				outcome.Evidence.MembershipIndex,
			))
		}
	}

	return violations
}

func finalTBTCDKGMembership(
	originalMemberIndex group.MemberIndex,
	originalGroupSize uint16,
	misbehavedMemberIndexes []uint8,
) (group.MemberIndex, bool) {
	if originalMemberIndex == 0 ||
		uint16(originalMemberIndex) > originalGroupSize {
		return 0, false
	}

	misbehavedBefore := uint16(0)
	seen := make(map[uint8]struct{}, len(misbehavedMemberIndexes))
	for _, rawMisbehaved := range misbehavedMemberIndexes {
		if rawMisbehaved == 0 ||
			uint16(rawMisbehaved) > originalGroupSize {
			continue
		}
		if _, duplicate := seen[rawMisbehaved]; duplicate {
			continue
		}
		seen[rawMisbehaved] = struct{}{}

		misbehaved := group.MemberIndex(rawMisbehaved)
		if misbehaved == originalMemberIndex {
			return 0, false
		}
		if misbehaved < originalMemberIndex {
			misbehavedBefore++
		}
	}

	return group.MemberIndex(
		uint16(originalMemberIndex) - misbehavedBefore,
	), true
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
	reconciled := make(map[string]string, len(record.PendingTransactions))
	for i, transaction := range record.PendingTransactions {
		if transaction.TransactionHash == "" {
			violations = append(violations, fmt.Sprintf(
				"pending transaction entry [%d] is missing its hash",
				i,
			))
		} else if !isCanonicalBitcoinTransactionHash(
			transaction.TransactionHash,
		) {
			// A hash in any other rendering cannot be matched against the
			// node's own record, so an entry could satisfy the coverage check
			// below by naming the same transaction in a shape that never
			// compares equal.
			violations = append(violations, fmt.Sprintf(
				"pending transaction entry [%d] hash [%s] is not a canonical "+
					"lowercase transaction hash",
				i,
				transaction.TransactionHash,
			))
		} else {
			reconciled[transaction.TransactionHash] = transaction.State
		}
		if _, ok := validBitcoinTransactionStates[transaction.State]; !ok {
			violations = append(violations, fmt.Sprintf(
				"pending transaction entry [%d] has unknown state [%s]",
				i,
				transaction.State,
			))
		}
	}

	violations = append(
		violations,
		r.reconcileSignedTransactionCoverage(reconciled)...,
	)

	return violations
}

// reconcileSignedTransactionCoverage joins every wallet action the node
// recorded as completed to the reconciled pending-transaction set. The node
// authors that record itself: it pins the transaction hash the moment the
// threshold signature is applied, before any broadcast, precisely because a
// permit canceled mid-broadcast may still have put the transaction on the
// network. So a signed transaction the reconciliation never enumerated is the
// ambiguous case the barrier exists to catch — the set attests it is complete,
// and it is missing a transaction the node knows it signed. Without this join
// the node's own token clears the journal and nothing checks it against
// Bitcoin.
func (r *auditRun) reconcileSignedTransactionCoverage(
	reconciled map[string]string,
) []string {
	if r.manifest.ParticipationTerminalOutcomes == nil {
		return nil
	}

	var violations []string
	for i, outcome := range r.manifest.ParticipationTerminalOutcomes.Outcomes {
		if outcome.Outcome != participation.TerminalOutcomeCompleted ||
			outcome.Permit.Ceremony != participation.TBTCSigning {
			continue
		}
		if outcome.Evidence.Kind !=
			participation.TerminalEvidenceBitcoinTransaction {
			// The evidence-kind rule already blocks this; skipping here keeps
			// one defect from being reported twice.
			continue
		}
		if !isCanonicalBitcoinTransactionHash(outcome.Evidence.Reference) {
			violations = append(violations, fmt.Sprintf(
				"node-authored completed wallet action [%d] names transaction "+
					"[%s], which is not a canonical transaction hash the "+
					"Bitcoin reconciliation could enumerate",
				i,
				outcome.Evidence.Reference,
			))
			continue
		}
		if _, covered := reconciled[outcome.Evidence.Reference]; !covered {
			violations = append(violations, fmt.Sprintf(
				"node-authored completed wallet action [%d] signed transaction "+
					"[%s], which the attested-complete pending transaction set "+
					"does not enumerate",
				i,
				outcome.Evidence.Reference,
			))
		}
	}

	return violations
}

// isCanonicalBitcoinTransactionHash reports whether value is the unprefixed
// lowercase hex rendering a Bitcoin transaction hash serializes to. Any other
// shape — mixed case, a 0x prefix, a truncated digest — is an alias that would
// silently fail every set comparison it takes part in.
func isCanonicalBitcoinTransactionHash(value string) bool {
	if len(value) != 2*bitcoin.HashByteLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
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

// persistedSignerIdentity identifies one exact active membership record. A
// wallet or beacon group can contain several locally controlled memberships,
// so the group reference alone cannot corroborate several completed DKG
// permits independently.
type persistedSignerIdentity struct {
	reference       string
	membershipIndex group.MemberIndex
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

	activeTBTCSigners := make(map[persistedSignerIdentity]struct{})
	for _, wallet := range auditManifest.TBTCActiveWallets {
		for _, memberIndex := range wallet.MemberIndexes {
			activeTBTCSigners[persistedSignerIdentity{
				reference:       wallet.WalletStorageKey,
				membershipIndex: group.MemberIndex(memberIndex),
			}] = struct{}{}
		}
	}
	activeBeaconSigners := make(map[persistedSignerIdentity]struct{})
	for _, membership := range auditManifest.BeaconActiveMemberships {
		activeBeaconSigners[persistedSignerIdentity{
			reference:       membership.GroupPublicKey,
			membershipIndex: group.MemberIndex(membership.MemberIndex),
		}] = struct{}{}
	}
	claimedTBTCSigners := make(map[persistedSignerIdentity]int)
	claimedBeaconSigners := make(map[persistedSignerIdentity]int)
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
				signerIdentity := persistedSignerIdentity{
					reference:       outcome.Evidence.Reference,
					membershipIndex: outcome.Evidence.MembershipIndex,
				}
				if outcome.Evidence.Kind !=
					participation.TerminalEvidencePersistedTBTCSinger {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed tbtc DKG outcome [%d] does "+
							"not name persisted tbtc signer evidence",
						i,
					))
				} else if _, ok := activeTBTCSigners[signerIdentity]; !ok {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed tbtc DKG outcome [%d] names "+
							"persisted signer [%s] membership [%d], but the "+
							"active tbtc namespace holds no matching signer",
						i,
						outcome.Evidence.Reference,
						outcome.Evidence.MembershipIndex,
					))
				} else if firstOutcome, duplicate :=
					claimedTBTCSigners[signerIdentity]; duplicate {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed tbtc DKG outcomes [%d] and "+
							"[%d] claim the same persisted signer [%s] "+
							"membership [%d]",
						firstOutcome,
						i,
						outcome.Evidence.Reference,
						outcome.Evidence.MembershipIndex,
					))
				} else {
					claimedTBTCSigners[signerIdentity] = i
				}
			case participation.BeaconDKG:
				signerIdentity := persistedSignerIdentity{
					reference:       outcome.Evidence.Reference,
					membershipIndex: outcome.Evidence.MembershipIndex,
				}
				if outcome.Evidence.Kind !=
					participation.TerminalEvidencePersistedBeaconSigner {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed beacon DKG outcome [%d] does "+
							"not name persisted beacon signer evidence",
						i,
					))
				} else if _, ok := activeBeaconSigners[signerIdentity]; !ok {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed beacon DKG outcome [%d] names "+
							"persisted signer [%s] membership [%d], but the "+
							"active beacon namespace holds no matching signer",
						i,
						outcome.Evidence.Reference,
						outcome.Evidence.MembershipIndex,
					))
				} else if firstOutcome, duplicate :=
					claimedBeaconSigners[signerIdentity]; duplicate {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed beacon DKG outcomes [%d] and "+
							"[%d] claim the same persisted signer [%s] "+
							"membership [%d]",
						firstOutcome,
						i,
						outcome.Evidence.Reference,
						outcome.Evidence.MembershipIndex,
					))
				} else {
					claimedBeaconSigners[signerIdentity] = i
				}
				permitMemberIndex, err := strconv.ParseUint(
					outcome.Permit.PermitID,
					10,
					8,
				)
				if err == nil &&
					outcome.Evidence.MembershipIndex !=
						group.MemberIndex(permitMemberIndex) {
					violations = append(violations, fmt.Sprintf(
						"node-authored completed beacon DKG outcome [%d] "+
							"belongs to permit member [%s], but names "+
							"persisted membership [%d]",
						i,
						outcome.Permit.PermitID,
						outcome.Evidence.MembershipIndex,
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
