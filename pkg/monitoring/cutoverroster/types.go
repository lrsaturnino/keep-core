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
	InstanceID      string `json:"instance_id"`
	OperatorAddress string `json:"operator_address"`
	StakingProvider string `json:"staking_provider"`
	// NetworkID is the instance's libp2p network identity (the node's own
	// network_id, exposed by /diagnostics client_info). It is the per-instance
	// join key against production service discovery and the responding node's
	// self-attested identity, so multiple instances of one operator resolve to
	// distinct discovered targets rather than collapsing onto one.
	NetworkID             string `json:"network_id"`
	CeremonyEligible      bool   `json:"ceremony_eligible"`
	ExpectedRevision      string `json:"expected_revision"`
	ExpectedEpoch         string `json:"expected_epoch"`
	ExpectedImageDigest   string `json:"expected_image_digest"`
	TrustedReportTarget   string `json:"-"`
	QuarantineEvidenceRef string `json:"quarantine_evidence_ref,omitempty"`

	// DisappearedFromDiscovery is set by the command layer when the instance's
	// operator is present in the authoritative inventory but absent from the
	// production service-discovery target set for this cycle. It is in-memory only
	// (never serialized) and drives reconciliation rule 2: disappearance from
	// service discovery is offline_unknown and never resolves central state.
	DisappearedFromDiscovery bool `json:"-"`
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
	NetworkID             string `json:"network_id"`
	CeremonyEligible      bool   `json:"ceremony_eligible"`
	ExpectedRevision      string `json:"expected_revision"`
	ExpectedEpoch         string `json:"expected_epoch"`
	ExpectedImageDigest   string `json:"expected_image_digest"`
	TrustedReportTarget   string `json:"trusted_report_target"`
	QuarantineEvidenceRef string `json:"quarantine_evidence_ref,omitempty"`
}

// ToInventoryInstance converts the on-disk input form to the in-memory
// InventoryInstance, carrying the trusted report target across. The in-memory
// form additionally carries DisappearedFromDiscovery, which is never sourced from
// operator input — it is computed by the command layer from the production
// service-discovery target set — so the conversion maps the shared fields
// explicitly and leaves that field at its zero value.
func (i InventoryInstanceInput) ToInventoryInstance() InventoryInstance {
	return InventoryInstance{
		InstanceID:            i.InstanceID,
		OperatorAddress:       i.OperatorAddress,
		StakingProvider:       i.StakingProvider,
		NetworkID:             i.NetworkID,
		CeremonyEligible:      i.CeremonyEligible,
		ExpectedRevision:      i.ExpectedRevision,
		ExpectedEpoch:         i.ExpectedEpoch,
		ExpectedImageDigest:   i.ExpectedImageDigest,
		TrustedReportTarget:   i.TrustedReportTarget,
		QuarantineEvidenceRef: i.QuarantineEvidenceRef,
	}
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

// FleetInstanceStatus is the per-instance reconciliation detail exposed in a
// snapshot for the dashboard's instance-level reasons and the audit trail. It
// pairs each authoritative instance's observed identity with the expected
// release identity, its reconciliation class/reason, and any independently
// verified quarantine evidence, so a reader can see exactly why an operator is
// blocking without joining separate inputs.
type FleetInstanceStatus struct {
	InstanceID      string `json:"instance_id"`
	OperatorAddress string `json:"operator_address"`
	Class           string `json:"class"`
	Reason          string `json:"reason"`
	// Reported means the instance has ever produced an accepted report.
	Reported bool `json:"reported"`
	// ReportedThisCycle means an accepted report was obtained in the current
	// collection cycle. It is deliberately distinct from Reported so an auditor
	// can tell a currently-reporting instance from a historical one.
	ReportedThisCycle bool `json:"reported_this_cycle"`
	// Per-instance authoritative inventory expectations, exposed so the dashboard
	// and audit trail can show exactly what the instance was expected to report.
	CeremonyEligible    bool   `json:"ceremony_eligible"`
	StakingProvider     string `json:"staking_provider,omitempty"`
	ExpectedRevision    string `json:"expected_revision,omitempty"`
	ExpectedEpoch       string `json:"expected_epoch,omitempty"`
	ExpectedImageDigest string `json:"expected_image_digest,omitempty"`
	ObservedRevision    string `json:"observed_revision,omitempty"`
	ObservedEpoch       string `json:"observed_epoch,omitempty"`
	ObservedDigest      string `json:"observed_image_digest,omitempty"`
	// ReporterRevision is the reporter-revision of the latest accepted report,
	// exposed for auditability alongside the observed artifact identity.
	ReporterRevision  uint64    `json:"reporter_revision,omitempty"`
	AttestedAt        time.Time `json:"attested_at,omitempty"`
	ConsecutiveExact  uint      `json:"consecutive_exact"`
	ConsecutiveMissed uint      `json:"consecutive_missed"`
	Quarantined       bool      `json:"quarantined"`
	QuarantineRef     string    `json:"quarantine_ref,omitempty"`
}

// FleetOperatorEntry is the reconciled per-operator entry exposed in a snapshot.
// Instances carries the raw attested reports (as specified); InstanceStatuses
// adds the per-instance reconciliation detail (class, reason, expected-vs-
// observed identity, and quarantine evidence) required for the dashboard's
// instance-level reasons and the audit record.
type FleetOperatorEntry struct {
	OperatorAddress  string                `json:"operator_address"`
	StakingProvider  string                `json:"staking_provider"`
	Status           FleetStatus           `json:"status"`
	Instances        []InstanceReport      `json:"instances"`
	InstanceStatuses []FleetInstanceStatus `json:"instance_statuses"`
	FirstSeenBlock   uint64                `json:"first_seen_block"`
	LastSeenBlock    uint64                `json:"last_seen_block"`
	Reason           string                `json:"reason"`
}

// FleetInventoryCounts summarizes the authoritative inventory reconciled this
// cycle: how many instances were supplied in total, how many were ceremony
// eligible, how many eligible instances lacked a fresh accepted report, and how
// many identity/target/inventory reconciliation faults were seen.
type FleetInventoryCounts struct {
	TotalInstances    int `json:"total_instances"`
	EligibleInstances int `json:"eligible_instances"`
	ReportersStale    int `json:"reporters_stale"`
	Unreconciled      int `json:"unreconciled"`
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
	Inventory        FleetInventoryCounts `json:"inventory"`
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

	// RequireServiceDiscovery makes reconciliation against the production
	// service-discovery target set mandatory for completeness. When true, a
	// collector that was not told service discovery is configured can never
	// certify readiness — a missing discovery feed blocks readiness rather than
	// silently degrading to trusting the inventory alone.
	RequireServiceDiscovery bool
	// RequireIdentityVerification makes an installed on-chain
	// operator→staking-provider identity verifier mandatory for completeness.
	// When true and no verifier is installed, readiness can never be complete —
	// a missing WalletRegistry verification blocks readiness rather than
	// certifying trusted-file identity assertions on their own.
	RequireIdentityVerification bool
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
