// Package cutoverroster implements the authoritative fleet aggregation view for
// a coordinated protocol cutover. It joins node-local post-cutover legacy
// sightings and per-instance revision/epoch/digest attestations to an
// authoritative ceremony-eligible inventory, and answers "which eligible
// instance has not reported the exact cutover release?" — the primary go/no-go
// question.
//
// This package is decoupled from the cutover gate itself: the expected release
// identity (revision, epoch, image digest) and the cutover block are plain
// operator-supplied configuration. They become meaningful once the real cutover
// release ships.
package cutoverroster

import "time"

// FleetSnapshotSchemaVersion is the schema version of the persisted and
// API-exposed fleet snapshot.
const FleetSnapshotSchemaVersion uint32 = 1

// ExpectedEpochSecurityV2Cutover is the release epoch string the cutover
// artifact reports.
const ExpectedEpochSecurityV2Cutover = "security_v2_cutover"

// FleetStatus is the reconciled per-operator cutover status.
type FleetStatus string

const (
	// FleetObservedLegacy means a valid post-cutover node-local legacy sighting
	// exists for the operator; it outranks every other blocking status.
	FleetObservedLegacy FleetStatus = "observed_legacy"
	// FleetNonCutoverRevision means an eligible, nonquarantined instance is
	// reporting a revision, epoch, or image digest that differs from the
	// expected cutover release.
	FleetNonCutoverRevision FleetStatus = "noncutover_revision"
	// FleetOfflineUnknown means the operator cannot be confirmed current:
	// missing collections, no trusted report path, identity mismatch, or not
	// yet confirmed by enough consecutive exact reports. Offline is never ready.
	FleetOfflineUnknown FleetStatus = "offline_unknown"
	// FleetQuarantined means every otherwise-blocking instance has independently
	// verified network/eligibility quarantine or removal evidence.
	FleetQuarantined FleetStatus = "quarantined"
	// FleetResolvedCurrent means every authoritative eligible instance reported
	// the exact cutover revision/epoch/digest in enough consecutive accepted
	// collections, all newer than the last legacy observation.
	FleetResolvedCurrent FleetStatus = "resolved_current"
)

// IsBlocking reports whether the status blocks cutover readiness.
func (s FleetStatus) IsBlocking() bool {
	switch s {
	case FleetObservedLegacy, FleetNonCutoverRevision, FleetOfflineUnknown:
		return true
	default:
		return false
	}
}

// InventoryInstance is one authoritative ceremony-eligible instance record. It
// is operator-supplied inventory, not a discovered scrape target.
type InventoryInstance struct {
	InstanceID            string `json:"instance_id"`
	OperatorAddress       string `json:"operator_address"`
	StakingProvider       string `json:"staking_provider"`
	CeremonyEligible      bool   `json:"ceremony_eligible"`
	ExpectedRevision      string `json:"expected_revision"`
	ExpectedEpoch         string `json:"expected_epoch"`
	ExpectedImageDigest   string `json:"expected_image_digest"`
	TrustedReportTarget   string `json:"-"`
	QuarantineEvidenceRef string `json:"quarantine_evidence_ref,omitempty"`
}

// InventoryInstanceInput is the on-disk inventory input form. Unlike
// InventoryInstance — whose TrustedReportTarget is `json:"-"` so it is never
// serialized back out — this input form carries the trusted report target under
// an explicit JSON key so operator inventory can supply it. The collector copies
// it into the in-memory InventoryInstance, which never serializes the target.
type InventoryInstanceInput struct {
	InstanceID            string `json:"instance_id"`
	OperatorAddress       string `json:"operator_address"`
	StakingProvider       string `json:"staking_provider"`
	CeremonyEligible      bool   `json:"ceremony_eligible"`
	ExpectedRevision      string `json:"expected_revision"`
	ExpectedEpoch         string `json:"expected_epoch"`
	ExpectedImageDigest   string `json:"expected_image_digest"`
	TrustedReportTarget   string `json:"trusted_report_target"`
	QuarantineEvidenceRef string `json:"quarantine_evidence_ref,omitempty"`
}

// ToInventoryInstance converts the on-disk input form to the in-memory
// InventoryInstance, carrying the trusted report target across. The two structs
// share identical fields (differing only in JSON tags), so the conversion is a
// direct struct conversion; adding a field to one but not the other becomes a
// compile error, keeping the input and in-memory forms in lockstep.
func (i InventoryInstanceInput) ToInventoryInstance() InventoryInstance {
	return InventoryInstance(i)
}

// InstanceReport is one attested report obtained from an instance's trusted
// report target during a collection cycle.
type InstanceReport struct {
	InstanceID       string    `json:"instance_id"`
	OperatorAddress  string    `json:"operator_address"`
	Revision         string    `json:"revision"`
	Epoch            string    `json:"epoch"`
	ImageDigest      string    `json:"image_digest"`
	AttestedAt       time.Time `json:"attested_at"`
	ReporterRevision uint64    `json:"reporter_revision"`
}

// LegacySighting is a post-cutover node-local legacy sighting for an operator,
// aggregated from the node-local cutover peer rosters.
type LegacySighting struct {
	OperatorAddress string    `json:"operator_address"`
	Block           uint64    `json:"block"`
	ObservedAt      time.Time `json:"observed_at"`
}

// FleetOperatorEntry is the reconciled per-operator entry exposed in a snapshot.
type FleetOperatorEntry struct {
	OperatorAddress string           `json:"operator_address"`
	StakingProvider string           `json:"staking_provider"`
	Status          FleetStatus      `json:"status"`
	Instances       []InstanceReport `json:"instances"`
	FirstSeenBlock  uint64           `json:"first_seen_block"`
	LastSeenBlock   uint64           `json:"last_seen_block"`
	Reason          string           `json:"reason"`
}

// FleetSnapshot is the deterministic authoritative fleet view.
type FleetSnapshot struct {
	SchemaVersion    uint32               `json:"schema_version"`
	GeneratedAt      time.Time            `json:"generated_at"`
	CurrentBlock     uint64               `json:"current_block"`
	CutoverBlock     uint64               `json:"cutover_block"`
	Complete         bool                 `json:"complete"`
	ExpectedRevision string               `json:"expected_revision"`
	ExpectedEpoch    string               `json:"expected_epoch"`
	ExpectedDigest   string               `json:"expected_image_digest"`
	Blocking         []FleetOperatorEntry `json:"blocking"`
	Quarantined      []FleetOperatorEntry `json:"quarantined"`
	RecentlyResolved []FleetOperatorEntry `json:"recently_resolved"`
}

// CollectorConfig configures the fleet collector. ExpectedRevision,
// ExpectedEpoch, ExpectedImageDigest, and CutoverBlock are plain
// operator-supplied values; they become meaningful once the real cutover
// release ships.
type CollectorConfig struct {
	ExpectedRevision    string
	ExpectedEpoch       string
	ExpectedImageDigest string
	CutoverBlock        uint64
	ChainID             string
	CollectionInterval  time.Duration
	MissedThreshold     uint
	SuccessThreshold    uint
}

// Metric names for the authoritative fleet aggregation.
const (
	MetricFleetBlockingOperators = "performance_cutover_fleet_blocking_operators"
	MetricFleetObservedLegacy    = "performance_cutover_fleet_observed_legacy"
	MetricReportersStale         = "performance_cutover_reporters_stale"
	MetricInventoryUnreconciled  = "performance_cutover_inventory_unreconciled"
	MetricOperatorInfo           = "performance_cutover_operator_info"
	MetricOperatorFirstSeenBlock = "performance_cutover_operator_first_seen_block"
	MetricOperatorLastSeenBlock  = "performance_cutover_operator_last_seen_block"
)

// ResolvedRetention is how long resolved operator records are retained before
// purge. Unresolved (blocking/quarantined) history is retained indefinitely.
const ResolvedRetention = 30 * 24 * time.Hour
