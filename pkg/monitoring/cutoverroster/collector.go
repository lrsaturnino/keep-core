package cutoverroster

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-log/v2"
)

var logger = log.Logger("keep-cutover-roster")

// QuarantineVerifier independently verifies that a quarantine/removal evidence
// reference is real before the collector accepts it. A note, unreachable
// endpoint, or self-report must not verify. When no verifier is configured, the
// collector fails closed and accepts no quarantine evidence.
type QuarantineVerifier interface {
	// Verify reports whether evidenceRef is independently verified network or
	// eligibility quarantine/removal evidence for the given instance.
	Verify(instanceID, operatorAddress, evidenceRef string) bool
}

// MetricsSink is the metrics interface the collector needs. The fleet-level
// gauges are label-less; the operator-level gauges carry
// {operator_address, staking_provider, status} labels.
type MetricsSink interface {
	// SetGauge sets a label-less fleet gauge.
	SetGauge(name string, value float64)
	// SetOperatorGauge sets a per-operator labeled gauge.
	SetOperatorGauge(name, operatorAddress, stakingProvider, status string, value float64)
	// ResetOperatorGauges clears all per-operator labeled gauge series before a
	// cycle re-emits them, so stale label sets do not linger.
	ResetOperatorGauges()
}

// instanceClass is the per-instance reconciliation classification.
type instanceClass uint8

const (
	classExactConfirmed instanceClass = iota
	classOfflineUnknown
	classNonCutoverRevision
)

// Collector reconciles the authoritative eligible inventory, per-instance
// attestations, and node-local legacy sightings into a per-operator fleet
// status. It persists central state transactionally and refreshes metrics.
type Collector struct {
	config   CollectorConfig
	store    *Store
	metrics  MetricsSink
	clock    func() time.Time
	verifier QuarantineVerifier

	// mu guards the mutable central state (operators/instances) and
	// lastSnapshot against concurrent Collect and HTTP Snapshot access.
	mu           sync.RWMutex
	operators    map[string]*operatorRecord
	instances    map[string]*instanceRecord
	lastSnapshot FleetSnapshot
}

// SetQuarantineVerifier installs the independent quarantine-evidence verifier.
// Until one is set, the collector accepts no quarantine evidence (fail closed).
func (c *Collector) SetQuarantineVerifier(verifier QuarantineVerifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifier = verifier
}

// NewCollector constructs a collector, loading any persisted central state from
// the store so it survives process restarts.
func NewCollector(
	config CollectorConfig,
	store *Store,
	metrics MetricsSink,
) (*Collector, error) {
	return newCollectorWithClock(config, store, metrics, time.Now)
}

func newCollectorWithClock(
	config CollectorConfig,
	store *Store,
	metrics MetricsSink,
	clock func() time.Time,
) (*Collector, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if metrics == nil {
		return nil, fmt.Errorf("metrics sink is required")
	}
	if config.MissedThreshold == 0 {
		return nil, fmt.Errorf("missed threshold must be non-zero")
	}
	if config.SuccessThreshold == 0 {
		return nil, fmt.Errorf("success threshold must be non-zero")
	}
	// A nonpositive collection interval would panic time.NewTicker in the
	// command's collection loop; reject it at construction so the invariant is
	// enforced regardless of the consumer.
	if config.CollectionInterval <= 0 {
		return nil, fmt.Errorf("collection interval must be positive")
	}

	operators, err := store.LoadOperators()
	if err != nil {
		return nil, fmt.Errorf("cannot load operators: %w", err)
	}
	instances, err := store.LoadInstances()
	if err != nil {
		return nil, fmt.Errorf("cannot load instances: %w", err)
	}

	return &Collector{
		config:    config,
		store:     store,
		metrics:   metrics,
		clock:     clock,
		operators: operators,
		instances: instances,
	}, nil
}

// Collect runs one collection cycle. reports maps instance ID to the report
// obtained this cycle; a missing key means the instance was not reachable.
// sightings are post-cutover node-local legacy sightings aggregated this cycle.
// It updates and persists central state, refreshes metrics, emits logs, and
// returns the resulting snapshot.
func (c *Collector) Collect(
	inventory []InventoryInstance,
	reports map[string]InstanceReport,
	sightings []LegacySighting,
	currentBlock uint64,
) (FleetSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()

	eligibleByOperator := map[string][]InventoryInstance{}
	stakingProviderByOperator := map[string]string{}
	// seenInstanceIDs records which instances were present and eligible in the
	// current inventory, so the reconciliation step can detect instances that
	// have disappeared from service discovery since an earlier cycle.
	seenInstanceIDs := map[string]bool{}
	totalInstances := len(inventory)
	unreconciled := 0
	stale := 0
	reconciledEligible := 0

	for _, rawInv := range inventory {
		inv := rawInv
		inv.OperatorAddress = normalizeAddress(inv.OperatorAddress)

		if !inv.CeremonyEligible {
			continue
		}

		// Reject a malformed, duplicated, or internally-contradictory
		// authoritative inventory entry as an inventory-reconciliation fault
		// before it can contribute to a resolved status. A missing instance or
		// operator identity cannot be joined or tracked; a duplicate instance ID
		// within one cycle would let one entry silently overwrite another; a
		// per-instance expected identity that contradicts the collector's
		// configured expected release means the inventory disagrees with itself
		// about what "current" is for that instance. Any of these forces readiness
		// closed (unreconciled > 0) rather than silently contributing to success.
		if inv.InstanceID == "" || inv.OperatorAddress == "" {
			unreconciled++
			continue
		}
		if seenInstanceIDs[inv.InstanceID] {
			unreconciled++
			continue
		}
		if c.inventoryExpectationContradicts(inv) {
			unreconciled++
			continue
		}

		reconciledEligible++
		seenInstanceIDs[inv.InstanceID] = true
		eligibleByOperator[inv.OperatorAddress] = append(
			eligibleByOperator[inv.OperatorAddress], inv,
		)
		if inv.StakingProvider != "" {
			stakingProviderByOperator[inv.OperatorAddress] = inv.StakingProvider
		}

		record := c.instanceForInventory(inv)

		// Quarantine evidence is accepted only when independently verified; a
		// bare reference, absent a verifier, never quarantines (fail closed). A
		// verified-quarantined instance is intentionally removed, so it is
		// excluded from the stale and unreconciled counts below.
		record.QuarantineRef = inv.QuarantineEvidenceRef
		record.HasQuarantine = inv.QuarantineEvidenceRef != "" &&
			c.verifier != nil &&
			c.verifier.Verify(
				inv.InstanceID, inv.OperatorAddress, inv.QuarantineEvidenceRef,
			)

		report, reported := reports[inv.InstanceID]

		// A missing trusted report target is an inventory-reconciliation failure
		// (unless the instance is quarantined and thus not expected to report).
		if inv.TrustedReportTarget == "" {
			reported = false
			if !record.HasQuarantine {
				unreconciled++
			}
		}

		// Reject an attestation whose identity, freshness, or reporter revision
		// cannot be validated, rather than silently accepting it. A report must
		// self-identify with the same instance ID and operator address as the
		// authoritative inventory entry it answers for: a missing or a mismatched
		// identity is an inventory-reconciliation failure, so a report that does
		// not name itself cannot stand in for the trusted instance (the reporter
		// deliberately does not fabricate these fields from inventory). A
		// stale/replayed attestation is merely a missed collection.
		unreconciledFault := false
		if reported {
			normalizedReportOperator := normalizeAddress(report.OperatorAddress)
			switch {
			case report.InstanceID != inv.InstanceID:
				reported, unreconciledFault = false, true
			case normalizedReportOperator != inv.OperatorAddress:
				reported, unreconciledFault = false, true
			case report.AttestedAt.IsZero():
				// Missing attestation time cannot prove freshness.
				reported, unreconciledFault = false, true
			case report.AttestedAt.After(now):
				// A future attestation time is invalid evidence; accepting it
				// would also poison the monotonic freshness guard below.
				reported, unreconciledFault = false, true
			case report.ReporterRevision == 0:
				// Missing reporter revision.
				reported, unreconciledFault = false, true
			case record.LatestReport != nil &&
				!report.AttestedAt.After(record.LatestReport.AttestedAt):
				// Stale or replayed attestation (not newer than the last one).
				reported = false
			case report.ReporterRevision < record.LastReporterRevision:
				// Reporter-revision downgrade.
				reported = false
			}
		}
		if unreconciledFault {
			unreconciled++
		}

		if reported {
			r := report
			r.OperatorAddress = inv.OperatorAddress
			record.LatestReport = &r
			record.LastReporterRevision = report.ReporterRevision
			record.ConsecutiveMissed = 0
			if c.reportIsExact(report) {
				record.ConsecutiveExact++
			} else {
				record.ConsecutiveExact = 0
			}
		} else {
			if !record.HasQuarantine {
				stale++
			}
			record.ConsecutiveMissed++
			record.ConsecutiveExact = 0
		}
	}

	// Fold in this cycle's post-cutover legacy sightings. A sighting before the
	// cutover block, or after the current block, is not valid post-cutover
	// straggler evidence and is ignored.
	freshLegacy := map[string]bool{}
	for _, sighting := range sightings {
		operator := normalizeAddress(sighting.OperatorAddress)
		if operator == "" {
			continue
		}
		if sighting.Block < c.config.CutoverBlock {
			continue
		}
		if currentBlock > 0 && sighting.Block > currentBlock {
			continue
		}
		op := c.operatorForAddress(operator, stakingProviderByOperator)
		freshLegacy[operator] = true
		if sighting.Block > op.LastLegacyBlock {
			op.LastLegacyBlock = sighting.Block
		}
		// Advance the last-legacy timestamp only from a non-zero, non-future
		// observation. The block bound above is the primary validity gate; a
		// zero or future ObservedAt must not push LastLegacyAt (which would make
		// resolution impossible) but does not invalidate the block evidence.
		if !sighting.ObservedAt.IsZero() &&
			!sighting.ObservedAt.After(now) &&
			sighting.ObservedAt.After(op.LastLegacyAt) {
			op.LastLegacyAt = sighting.ObservedAt
		}
	}

	// Reconcile each operator that has eligible instances this cycle, plus any
	// operator with a fresh legacy sighting.
	toReconcile := map[string]bool{}
	for op := range eligibleByOperator {
		toReconcile[op] = true
	}
	for op := range freshLegacy {
		toReconcile[op] = true
	}

	// Group every known instance record by operator so instances that were
	// present in an earlier cycle but have since disappeared from the current
	// inventory are still reconciled rather than silently dropped.
	instancesByOperator := map[string][]*instanceRecord{}
	for _, inst := range c.instances {
		instancesByOperator[inst.OperatorAddress] = append(
			instancesByOperator[inst.OperatorAddress], inst,
		)
	}

	for operatorAddress := range toReconcile {
		op := c.operatorForAddress(operatorAddress, stakingProviderByOperator)
		if provider, ok := stakingProviderByOperator[operatorAddress]; ok {
			op.StakingProvider = provider
		}

		instanceRecords := c.reconcileDisappearedInstances(
			instancesByOperator[operatorAddress],
			seenInstanceIDs,
		)

		previousStatus := op.Status
		status, reason := c.reconcileOperatorStatus(
			instanceRecords,
			freshLegacy[operatorAddress],
			op.LastLegacyAt,
		)

		if op.FirstSeenBlock == 0 {
			op.FirstSeenBlock = currentBlock
		}
		op.LastSeenBlock = currentBlock
		op.Status = status
		op.Reason = reason

		if status == FleetResolvedCurrent {
			// Refresh the resolution timestamp every cycle it stays resolved, so
			// the 30-day retention counts from when the operator was last
			// confirmed resolved. Only a resolved operator that drops out of the
			// authoritative inventory (and is therefore no longer reconciled)
			// ages out and is purged; an actively-resolved operator never does.
			op.ResolvedAt = now
			if previousStatus != FleetResolvedCurrent {
				logger.Infof(
					"cutover operator resolved [operator=%s] "+
						"[stakingProvider=%s] [resolution=%s] [currentBlock=%d]",
					op.OperatorAddress,
					op.StakingProvider,
					status,
					currentBlock,
				)
			}
		} else {
			// Reopened or still blocking: it is no longer resolved.
			op.ResolvedAt = time.Time{}
		}
	}

	c.purgeResolved(now)

	if err := c.store.Save(c.operators, c.instances); err != nil {
		return FleetSnapshot{}, fmt.Errorf("cannot persist central state: %w", err)
	}

	snapshot := c.buildSnapshot(now, currentBlock)
	snapshot.Complete = c.isComplete(
		snapshot, reconciledEligible, stale, unreconciled, currentBlock,
	)

	// Guarantee that an incomplete readiness determination always surfaces as a
	// nonzero blocking/stale/unreconciled signal, so the CutoverRosterIncomplete
	// alert fires even when readiness cannot be established at all — an empty
	// inventory, unset expected identity, a zero cutover block, or a stale chain
	// clock would otherwise leave every watched gauge at zero and hide the fault.
	if !snapshot.Complete &&
		len(snapshot.Blocking) == 0 && stale == 0 && unreconciled == 0 {
		unreconciled = 1
	}

	snapshot.Inventory = FleetInventoryCounts{
		TotalInstances:    totalInstances,
		EligibleInstances: reconciledEligible,
		ReportersStale:    stale,
		Unreconciled:      unreconciled,
	}
	c.lastSnapshot = snapshot

	c.updateMetrics(snapshot, stale, unreconciled)
	c.logCycle(snapshot)

	return snapshot, nil
}

// RecordInputUnavailable records a collection cycle in which an authoritative
// input — the ceremony-eligible inventory or the legacy-sightings evidence —
// could not be read. It fails readiness closed for the cycle: the published
// snapshot is forced incomplete with a nonzero inventory-unreconciled signal, and
// the fleet metrics are refreshed so the CutoverRosterIncomplete alert fires. A
// stale "complete=true" snapshot from an earlier cycle must never keep certifying
// readiness while the authoritative denominator is missing.
//
// Persisted operator/instance history is deliberately left untouched: a transient
// input blip is not evidence that any operator converged, disappeared, or missed
// a collection, so it must not advance a missed counter, purge a resolved record,
// or otherwise mutate central state.
func (c *Collector) RecordInputUnavailable(currentBlock uint64) FleetSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()

	snapshot := c.buildSnapshot(now, currentBlock)
	snapshot.Complete = false

	// The input failure is itself an inventory-reconciliation fault. Any persisted
	// blocking operators stay visible via buildSnapshot; forcing unreconciled to at
	// least one guarantees a nonzero watched gauge even when nothing was blocking.
	const stale = 0
	const unreconciled = 1
	snapshot.Inventory = FleetInventoryCounts{
		TotalInstances:    len(c.instances),
		EligibleInstances: 0,
		ReportersStale:    stale,
		Unreconciled:      unreconciled,
	}

	c.lastSnapshot = snapshot
	c.updateMetrics(snapshot, stale, unreconciled)
	c.logCycle(snapshot)

	return snapshot
}

// isComplete fails closed: readiness is "complete" only with a nonempty
// reconciled authoritative inventory, a fresh current block, fully specified
// expected artifact identity and chain ID, and zero blocking/stale/unreconciled.
// An empty or missing inventory, an unavailable chain clock, or an unset
// expected identity can never produce complete=true.
func (c *Collector) isComplete(
	snapshot FleetSnapshot,
	reconciledEligible, stale, unreconciled int,
	currentBlock uint64,
) bool {
	if reconciledEligible == 0 {
		return false
	}
	if currentBlock == 0 {
		return false
	}
	// A zero cutover block is placeholder metadata: readiness cannot be
	// certified for a go/no-go until a real cutover block C is supplied.
	if c.config.CutoverBlock == 0 {
		return false
	}
	if c.config.ExpectedRevision == "" ||
		c.config.ExpectedEpoch == "" ||
		c.config.ExpectedImageDigest == "" ||
		c.config.ChainID == "" {
		return false
	}
	return len(snapshot.Blocking) == 0 && stale == 0 && unreconciled == 0
}

// normalizeAddress normalizes an operator/staking address for identity joins:
// trimmed and lowercased. It is lenient — a value that is not a 0x-prefixed hex
// address is returned lowercased rather than dropped — so inventory, reports,
// and sightings that refer to one operator with different casing deduplicate to
// a single record.
func normalizeAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// inventoryExpectationContradicts reports whether an authoritative inventory
// entry's own expected release identity contradicts the collector's configured
// expected release. A per-instance expected revision, epoch, or image digest
// that is set but differs from the configured value means the inventory is
// internally inconsistent about what the cutover release is for that instance;
// the entry is treated as an inventory-reconciliation fault so it cannot
// contribute to a resolved status.
func (c *Collector) inventoryExpectationContradicts(inv InventoryInstance) bool {
	if inv.ExpectedRevision != "" &&
		inv.ExpectedRevision != c.config.ExpectedRevision {
		return true
	}
	if inv.ExpectedEpoch != "" &&
		inv.ExpectedEpoch != c.config.ExpectedEpoch {
		return true
	}
	if inv.ExpectedImageDigest != "" &&
		inv.ExpectedImageDigest != c.config.ExpectedImageDigest {
		return true
	}
	return false
}

// reconcileOperatorStatus applies the six reconciliation rules to one operator's
// eligible instance records and returns its status and a human-readable reason.
func (c *Collector) reconcileOperatorStatus(
	instances []*instanceRecord,
	freshLegacyThisCycle bool,
	lastLegacyAt time.Time,
) (FleetStatus, string) {
	// Rule 3: a valid post-cutover legacy sighting outranks other blocking
	// statuses and reopens/refreshes the operator.
	if freshLegacyThisCycle {
		return FleetObservedLegacy, "post-cutover legacy wire sighting"
	}

	if len(instances) == 0 {
		return FleetOfflineUnknown, "no eligible instances reporting"
	}

	nonQuarantinedBlocking := 0
	anyNonCutover := false
	anyQuarantined := false
	allExactConfirmed := true

	for _, inst := range instances {
		class := c.classifyInstance(inst)
		if class != classExactConfirmed {
			allExactConfirmed = false
		}
		if inst.HasQuarantine {
			anyQuarantined = true
			continue
		}
		switch class {
		case classExactConfirmed:
			// current
		case classNonCutoverRevision:
			nonQuarantinedBlocking++
			anyNonCutover = true
		default:
			nonQuarantinedBlocking++
		}
	}

	if nonQuarantinedBlocking == 0 {
		if allExactConfirmed {
			// Rule 4: resolved only if every report is newer than the last
			// legacy observation.
			if c.allReportsNewerThan(instances, lastLegacyAt) {
				return FleetResolvedCurrent, "all instances report exact cutover release"
			}
			return FleetOfflineUnknown,
				"exact reports not yet newer than last legacy observation"
		}
		// Rule 5: every otherwise-blocking instance is quarantined.
		if anyQuarantined {
			return FleetQuarantined, "all blocking instances independently quarantined"
		}
		return FleetOfflineUnknown, "awaiting confirmation"
	}

	// Rule 1/2: blocking. noncutover_revision is reported ahead of a bare
	// offline/unknown because it is a confirmed stale binary.
	if anyNonCutover {
		return FleetNonCutoverRevision, "instance reporting a non-cutover revision/epoch/digest"
	}
	return FleetOfflineUnknown, "instance offline or unconfirmed"
}

func (c *Collector) classifyInstance(inst *instanceRecord) instanceClass {
	if inst.ConsecutiveMissed >= c.config.MissedThreshold {
		return classOfflineUnknown
	}
	if inst.LatestReport == nil {
		return classOfflineUnknown
	}
	if !c.reportIsExact(*inst.LatestReport) {
		return classNonCutoverRevision
	}
	if inst.ConsecutiveExact >= c.config.SuccessThreshold {
		return classExactConfirmed
	}
	return classOfflineUnknown
}

func (c *Collector) allReportsNewerThan(
	instances []*instanceRecord,
	reference time.Time,
) bool {
	if reference.IsZero() {
		return true
	}
	for _, inst := range instances {
		if inst.LatestReport == nil {
			return false
		}
		if !inst.LatestReport.AttestedAt.After(reference) {
			return false
		}
	}
	return true
}

func (c *Collector) reportIsExact(report InstanceReport) bool {
	return report.Revision == c.config.ExpectedRevision &&
		report.Epoch == c.config.ExpectedEpoch &&
		report.ImageDigest == c.config.ExpectedImageDigest
}

func (c *Collector) instanceForInventory(inv InventoryInstance) *instanceRecord {
	record, ok := c.instances[inv.InstanceID]
	if !ok {
		record = &instanceRecord{
			InstanceID:      inv.InstanceID,
			OperatorAddress: inv.OperatorAddress,
		}
		c.instances[inv.InstanceID] = record
	}
	record.OperatorAddress = inv.OperatorAddress
	return record
}

func (c *Collector) operatorForAddress(
	address string,
	stakingProviders map[string]string,
) *operatorRecord {
	record, ok := c.operators[address]
	if !ok {
		record = &operatorRecord{
			OperatorAddress: address,
			StakingProvider: stakingProviders[address],
			Status:          FleetOfflineUnknown,
		}
		c.operators[address] = record
	}
	return record
}

// reconcileDisappearedInstances returns every known instance record for an
// operator, applying a missed-collection update to any instance absent from the
// current inventory (disappeared from service discovery). A disappeared instance
// loses its exact-confirmation streak and is re-checked for verified quarantine
// using its last-known evidence reference, so removal never silently resolves
// central state: the operator stays blocking until the instance either reappears
// with fresh exact reports or is independently quarantined.
func (c *Collector) reconcileDisappearedInstances(
	records []*instanceRecord,
	seenInstanceIDs map[string]bool,
) []*instanceRecord {
	for _, inst := range records {
		if seenInstanceIDs[inst.InstanceID] {
			continue
		}
		inst.ConsecutiveMissed++
		inst.ConsecutiveExact = 0
		inst.HasQuarantine = inst.QuarantineRef != "" &&
			c.verifier != nil &&
			c.verifier.Verify(inst.InstanceID, inst.OperatorAddress, inst.QuarantineRef)
	}
	return records
}

// purgeResolved removes resolved operator records older than the retention
// window. Unresolved (blocking/quarantined) history is never purged.
func (c *Collector) purgeResolved(now time.Time) {
	for address, op := range c.operators {
		if op.Status != FleetResolvedCurrent {
			continue
		}
		if op.ResolvedAt.IsZero() {
			continue
		}
		if now.Sub(op.ResolvedAt) > ResolvedRetention {
			delete(c.operators, address)
			// Drop the resolved operator's instance records too.
			for instanceID, inst := range c.instances {
				if inst.OperatorAddress == address {
					delete(c.instances, instanceID)
				}
			}
		}
	}
}

func (c *Collector) buildSnapshot(now time.Time, currentBlock uint64) FleetSnapshot {
	var blocking, quarantined, resolved []FleetOperatorEntry

	for _, op := range c.operators {
		entry := c.operatorEntry(op)
		switch {
		case op.Status == FleetQuarantined:
			quarantined = append(quarantined, entry)
		case op.Status == FleetResolvedCurrent:
			resolved = append(resolved, entry)
		case op.Status.IsBlocking():
			blocking = append(blocking, entry)
		}
	}

	sortEntries(blocking)
	sortEntries(quarantined)
	sortEntries(resolved)

	// Complete is decided by the caller's fail-closed isComplete; never derive
	// it from an empty blocking list alone, which would pass an empty inventory.
	return FleetSnapshot{
		SchemaVersion:    FleetSnapshotSchemaVersion,
		GeneratedAt:      now,
		CurrentBlock:     currentBlock,
		CutoverBlock:     c.config.CutoverBlock,
		Complete:         false,
		ExpectedRevision: c.config.ExpectedRevision,
		ExpectedEpoch:    c.config.ExpectedEpoch,
		ExpectedDigest:   c.config.ExpectedImageDigest,
		Blocking:         blocking,
		Quarantined:      quarantined,
		RecentlyResolved: resolved,
	}
}

func (c *Collector) operatorEntry(op *operatorRecord) FleetOperatorEntry {
	var records []*instanceRecord
	for _, inst := range c.instances {
		if inst.OperatorAddress == op.OperatorAddress {
			records = append(records, inst)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].InstanceID < records[j].InstanceID
	})

	instances := make([]InstanceReport, 0, len(records))
	statuses := make([]FleetInstanceStatus, 0, len(records))
	for _, inst := range records {
		if inst.LatestReport != nil {
			instances = append(instances, *inst.LatestReport)
		} else {
			// Offline / never-reported authoritative instance: surface its
			// identity so the audit trail lists every instance the operator
			// owns, not only those that produced a report this window.
			instances = append(instances, InstanceReport{
				InstanceID:      inst.InstanceID,
				OperatorAddress: inst.OperatorAddress,
			})
		}
		statuses = append(statuses, c.instanceStatus(inst))
	}

	return FleetOperatorEntry{
		OperatorAddress:  op.OperatorAddress,
		StakingProvider:  op.StakingProvider,
		Status:           op.Status,
		Instances:        instances,
		InstanceStatuses: statuses,
		FirstSeenBlock:   op.FirstSeenBlock,
		LastSeenBlock:    op.LastSeenBlock,
		Reason:           op.Reason,
	}
}

// instanceStatus builds the per-instance reconciliation detail for the snapshot,
// pairing the instance's observed identity with its reconciliation class and a
// short human-readable reason.
func (c *Collector) instanceStatus(inst *instanceRecord) FleetInstanceStatus {
	class := c.classifyInstance(inst)
	status := FleetInstanceStatus{
		InstanceID:        inst.InstanceID,
		OperatorAddress:   inst.OperatorAddress,
		Class:             instanceClassString(class),
		Reason:            c.instanceReason(inst, class),
		Reported:          inst.LatestReport != nil,
		ConsecutiveExact:  inst.ConsecutiveExact,
		ConsecutiveMissed: inst.ConsecutiveMissed,
		Quarantined:       inst.HasQuarantine,
		QuarantineRef:     inst.QuarantineRef,
	}
	if inst.LatestReport != nil {
		status.ObservedRevision = inst.LatestReport.Revision
		status.ObservedEpoch = inst.LatestReport.Epoch
		status.ObservedDigest = inst.LatestReport.ImageDigest
		status.AttestedAt = inst.LatestReport.AttestedAt
	}
	return status
}

func instanceClassString(class instanceClass) string {
	switch class {
	case classExactConfirmed:
		return "exact_confirmed"
	case classNonCutoverRevision:
		return "noncutover_revision"
	default:
		return "offline_unknown"
	}
}

func (c *Collector) instanceReason(inst *instanceRecord, class instanceClass) string {
	if inst.HasQuarantine {
		return "independently verified quarantine/removal"
	}
	switch class {
	case classExactConfirmed:
		return "exact cutover release confirmed"
	case classNonCutoverRevision:
		return "reporting a non-cutover revision/epoch/digest"
	default:
		if inst.LatestReport == nil {
			return "no accepted report"
		}
		if inst.ConsecutiveMissed >= c.config.MissedThreshold {
			return "missed consecutive collections"
		}
		return "awaiting consecutive exact confirmations"
	}
}

func sortEntries(entries []FleetOperatorEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].OperatorAddress < entries[j].OperatorAddress
	})
}

func (c *Collector) updateMetrics(snapshot FleetSnapshot, stale, unreconciled int) {
	blockingOperators := len(snapshot.Blocking)
	observedLegacy := 0
	for _, op := range snapshot.Blocking {
		if op.Status == FleetObservedLegacy {
			observedLegacy++
		}
	}

	c.metrics.SetGauge(MetricFleetBlockingOperators, float64(blockingOperators))
	c.metrics.SetGauge(MetricFleetObservedLegacy, float64(observedLegacy))
	c.metrics.SetGauge(MetricReportersStale, float64(stale))
	c.metrics.SetGauge(MetricInventoryUnreconciled, float64(unreconciled))

	c.metrics.ResetOperatorGauges()
	emit := func(entry FleetOperatorEntry) {
		status := string(entry.Status)
		c.metrics.SetOperatorGauge(
			MetricOperatorInfo, entry.OperatorAddress, entry.StakingProvider, status, 1,
		)
		c.metrics.SetOperatorGauge(
			MetricOperatorFirstSeenBlock, entry.OperatorAddress, entry.StakingProvider, status,
			float64(entry.FirstSeenBlock),
		)
		c.metrics.SetOperatorGauge(
			MetricOperatorLastSeenBlock, entry.OperatorAddress, entry.StakingProvider, status,
			float64(entry.LastSeenBlock),
		)
	}
	for _, entry := range snapshot.Blocking {
		emit(entry)
	}
	for _, entry := range snapshot.Quarantined {
		emit(entry)
	}
	for _, entry := range snapshot.RecentlyResolved {
		emit(entry)
	}
}

func (c *Collector) logCycle(snapshot FleetSnapshot) {
	noncutover, observedLegacy, offlineUnknown := 0, 0, 0
	for _, op := range snapshot.Blocking {
		switch op.Status {
		case FleetNonCutoverRevision:
			noncutover++
		case FleetObservedLegacy:
			observedLegacy++
		case FleetOfflineUnknown:
			offlineUnknown++
		}
	}

	logger.Infof(
		"cutover readiness fleet snapshot [currentBlock=%d] [cutoverBlock=%d] "+
			"[complete=%t] [blockingOperators=%d] [noncutoverRevision=%d] "+
			"[observedLegacy=%d] [offlineUnknown=%d] [quarantined=%d]",
		snapshot.CurrentBlock,
		snapshot.CutoverBlock,
		snapshot.Complete,
		len(snapshot.Blocking),
		noncutover,
		observedLegacy,
		offlineUnknown,
		len(snapshot.Quarantined),
	)

	for _, op := range snapshot.Blocking {
		// reporters is the number of instances that produced an accepted report,
		// which is distinct from the total instance count (the latter includes
		// offline/never-reported and disappeared authoritative instances).
		reporters := 0
		for _, st := range op.InstanceStatuses {
			if st.Reported {
				reporters++
			}
		}
		logger.Infof(
			"cutover operator unresolved [operator=%s] [stakingProvider=%s] "+
				"[status=%s] [firstSeenBlock=%d] [lastSeenBlock=%d] "+
				"[reporters=%d] [instances=%d]",
			op.OperatorAddress,
			op.StakingProvider,
			op.Status,
			op.FirstSeenBlock,
			op.LastSeenBlock,
			reporters,
			len(op.Instances),
		)
	}
}

// Snapshot returns the most recently computed fleet snapshot. It is safe to call
// concurrently with Collect.
func (c *Collector) Snapshot() FleetSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSnapshot
}
