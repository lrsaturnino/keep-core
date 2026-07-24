package cutoverroster

import (
	"fmt"
	"sort"
	"time"

	"github.com/ipfs/go-log/v2"
)

var logger = log.Logger("keep-cutover-roster")

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
	config  CollectorConfig
	store   *Store
	metrics MetricsSink
	clock   func() time.Time

	operators map[string]*operatorRecord
	instances map[string]*instanceRecord

	lastSnapshot FleetSnapshot
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
	now := c.clock()

	eligibleByOperator := map[string][]InventoryInstance{}
	stakingProviderByOperator := map[string]string{}
	unreconciled := 0
	stale := 0

	for _, inv := range inventory {
		if !inv.CeremonyEligible {
			continue
		}
		eligibleByOperator[inv.OperatorAddress] = append(
			eligibleByOperator[inv.OperatorAddress], inv,
		)
		if inv.StakingProvider != "" {
			stakingProviderByOperator[inv.OperatorAddress] = inv.StakingProvider
		}

		record := c.instanceForInventory(inv)

		// Identity/target reconciliation failures.
		if inv.TrustedReportTarget == "" {
			unreconciled++
		}

		report, reported := reports[inv.InstanceID]
		if inv.TrustedReportTarget == "" {
			reported = false
		}
		if reported && report.OperatorAddress != "" &&
			report.OperatorAddress != inv.OperatorAddress {
			// Identity mismatch: the reported operator does not match inventory.
			unreconciled++
			reported = false
		}

		if reported {
			r := report
			record.LatestReport = &r
			record.ConsecutiveMissed = 0
			if c.reportIsExact(report) {
				record.ConsecutiveExact++
			} else {
				record.ConsecutiveExact = 0
			}
		} else {
			stale++
			record.ConsecutiveMissed++
			record.ConsecutiveExact = 0
		}

		record.HasQuarantine = inv.QuarantineEvidenceRef != ""
		record.QuarantineRef = inv.QuarantineEvidenceRef
	}

	// Fold in this cycle's legacy sightings.
	freshLegacy := map[string]bool{}
	for _, sighting := range sightings {
		op := c.operatorForAddress(sighting.OperatorAddress, stakingProviderByOperator)
		freshLegacy[sighting.OperatorAddress] = true
		if sighting.Block > op.LastLegacyBlock {
			op.LastLegacyBlock = sighting.Block
		}
		if sighting.ObservedAt.After(op.LastLegacyAt) {
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

	for operatorAddress := range toReconcile {
		op := c.operatorForAddress(operatorAddress, stakingProviderByOperator)
		if provider, ok := stakingProviderByOperator[operatorAddress]; ok {
			op.StakingProvider = provider
		}

		instanceRecords := c.eligibleInstanceRecords(eligibleByOperator[operatorAddress])

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
	c.lastSnapshot = snapshot

	c.updateMetrics(snapshot, stale, unreconciled)
	c.logCycle(snapshot)

	return snapshot, nil
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

func (c *Collector) eligibleInstanceRecords(
	inventory []InventoryInstance,
) []*instanceRecord {
	records := make([]*instanceRecord, 0, len(inventory))
	for _, inv := range inventory {
		if record, ok := c.instances[inv.InstanceID]; ok {
			records = append(records, record)
		}
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

	complete := len(blocking) == 0

	return FleetSnapshot{
		SchemaVersion:    FleetSnapshotSchemaVersion,
		GeneratedAt:      now,
		CurrentBlock:     currentBlock,
		CutoverBlock:     c.config.CutoverBlock,
		Complete:         complete,
		ExpectedRevision: c.config.ExpectedRevision,
		ExpectedEpoch:    c.config.ExpectedEpoch,
		ExpectedDigest:   c.config.ExpectedImageDigest,
		Blocking:         blocking,
		Quarantined:      quarantined,
		RecentlyResolved: resolved,
	}
}

func (c *Collector) operatorEntry(op *operatorRecord) FleetOperatorEntry {
	var instances []InstanceReport
	for _, inst := range c.instances {
		if inst.OperatorAddress != op.OperatorAddress {
			continue
		}
		if inst.LatestReport != nil {
			instances = append(instances, *inst.LatestReport)
		}
	}
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].InstanceID < instances[j].InstanceID
	})

	return FleetOperatorEntry{
		OperatorAddress: op.OperatorAddress,
		StakingProvider: op.StakingProvider,
		Status:          op.Status,
		Instances:       instances,
		FirstSeenBlock:  op.FirstSeenBlock,
		LastSeenBlock:   op.LastSeenBlock,
		Reason:          op.Reason,
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
		logger.Infof(
			"cutover operator unresolved [operator=%s] [stakingProvider=%s] "+
				"[status=%s] [firstSeenBlock=%d] [lastSeenBlock=%d] "+
				"[reporters=%d] [instances=%d]",
			op.OperatorAddress,
			op.StakingProvider,
			op.Status,
			op.FirstSeenBlock,
			op.LastSeenBlock,
			len(op.Instances),
			len(op.Instances),
		)
	}
}

// Snapshot returns the most recently computed fleet snapshot.
func (c *Collector) Snapshot() FleetSnapshot {
	return c.lastSnapshot
}
