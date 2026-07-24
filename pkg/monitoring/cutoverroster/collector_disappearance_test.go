package cutoverroster

import (
	"path/filepath"
	"testing"
	"time"
)

// TestCollector_DisappearedInstanceKeepsOperatorBlocking proves reconciliation
// rule 6: removal of an instance from the authoritative inventory never resolves
// central state. An operator that is blocking because of one instance must stay
// blocking when that instance simply disappears, even if its other instances are
// exact-confirmed.
func TestCollector_DisappearedInstanceKeepsOperatorBlocking(t *testing.T) {
	tc := newTestCollector(t)

	both := []InventoryInstance{
		eligibleInstance("i1", "op1"),
		eligibleInstance("i2", "op1"),
	}

	// Cycles 1-3: both instances eligible; only i1 reports exact. i2 never
	// reports and is offline_unknown, so op1 is blocking throughout while i1
	// accrues its exact-confirmation streak.
	block := uint64(1001)
	for cycle := 1; cycle <= 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		snap, err := tc.collector.Collect(both, reports, nil, block)
		if err != nil {
			t.Fatal(err)
		}
		if status, _ := operatorStatus(snap, "op1"); status == FleetResolvedCurrent {
			t.Fatalf("operator resolved while i2 was offline at cycle %d", cycle)
		}
		tc.now = tc.now.Add(time.Minute)
		block++
	}

	// Cycle 4: i2 disappears from the inventory. i1 reports exact and is now
	// exact-confirmed; without disappearance handling the operator would falsely
	// resolve. i2's unverified removal must keep op1 blocking.
	onlyI1 := []InventoryInstance{eligibleInstance("i1", "op1")}
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(onlyI1, reports, nil, block)
	if err != nil {
		t.Fatal(err)
	}
	status, ok := operatorStatus(snap, "op1")
	if !ok {
		t.Fatal("op1 missing from snapshot")
	}
	if status == FleetResolvedCurrent {
		t.Fatalf("disappeared instance i2 must keep op1 blocking, got %s", status)
	}
	if !status.IsBlocking() {
		t.Fatalf("expected op1 blocking after i2 disappeared, got %s", status)
	}
	if snap.Complete {
		t.Error("snapshot must not be complete while op1 is blocking")
	}
}

// TestCollector_WholeOperatorDisappearanceStaysBlocking proves the fail-closed
// safety property for a whole-operator disappearance alongside a still-resolved
// operator: an operator that is blocking when every one of its instances vanishes
// from the authoritative inventory remains blocking (its removal is not treated
// as convergence), while a separate operator that keeps reporting exact resolves
// independently. The readiness determination must not become complete while the
// vanished operator is still blocking.
func TestCollector_WholeOperatorDisappearanceStaysBlocking(t *testing.T) {
	tc := newTestCollector(t)

	both := []InventoryInstance{
		eligibleInstance("i1", "opBlocking"),
		eligibleInstance("i2", "opResolving"),
	}

	// Cycles 1-3: opBlocking never reports (offline_unknown, blocking) while
	// opResolving reports exact and accrues its confirmation streak.
	block := uint64(1001)
	for cycle := 1; cycle <= 3; cycle++ {
		reports := map[string]InstanceReport{
			"i2": exactReport("i2", "opResolving", tc.now),
		}
		if _, err := tc.collector.Collect(both, reports, nil, block); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
		block++
	}

	// Cycle 4: opBlocking's only instance disappears from the inventory entirely.
	// opResolving remains and reports exact, so it resolves; opBlocking must not
	// silently drop out of the blocking set just because it vanished.
	onlyResolving := []InventoryInstance{eligibleInstance("i2", "opResolving")}
	reports := map[string]InstanceReport{
		"i2": exactReport("i2", "opResolving", tc.now),
	}
	snap, err := tc.collector.Collect(onlyResolving, reports, nil, block)
	if err != nil {
		t.Fatal(err)
	}

	blockingStatus, ok := operatorStatus(snap, "opBlocking")
	if !ok {
		t.Fatal("vanished blocking operator must be retained in the snapshot")
	}
	if !blockingStatus.IsBlocking() {
		t.Fatalf(
			"vanished operator must stay blocking, got %s", blockingStatus,
		)
	}
	if resolvingStatus, _ := operatorStatus(snap, "opResolving"); resolvingStatus != FleetResolvedCurrent {
		t.Fatalf(
			"still-present exact operator must resolve independently, got %s",
			resolvingStatus,
		)
	}
	if snap.Complete {
		t.Error("readiness must not be complete while the vanished operator blocks")
	}
}

// TestNewCollector_RejectsNonPositiveCollectionInterval proves the collection
// interval is validated at construction, so a zero or negative interval cannot
// reach time.NewTicker and panic the collection loop.
func TestNewCollector_RejectsNonPositiveCollectionInterval(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "roster.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	for _, interval := range []time.Duration{0, -time.Second} {
		cfg := testConfig()
		cfg.CollectionInterval = interval
		if _, err := NewCollector(cfg, store, newFakeSink()); err == nil {
			t.Fatalf("expected error for collection interval %s", interval)
		}
	}
}

// TestCollector_ZeroCutoverBlockNotComplete proves readiness cannot be certified
// while the cutover block C is the placeholder zero, even when every instance is
// exact-confirmed.
func TestCollector_ZeroCutoverBlockNotComplete(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "roster.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	cfg := testConfig()
	cfg.CutoverBlock = 0
	now := fleetBaseTime
	collector, err := newCollectorWithClock(
		cfg, store, newFakeSink(), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}
	block := uint64(10)
	var snap FleetSnapshot
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", now)}
		snap, err = collector.Collect(inventory, reports, nil, block)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		block++
	}
	if snap.Complete {
		t.Fatal("snapshot must not be complete with a zero cutover block")
	}
}

// TestCollector_FutureAttestationRejected proves a report timestamped in the
// future is treated as an invalid attestation: it is an unreconciled fault and
// does not count toward resolution.
func TestCollector_FutureAttestationRejected(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	future := tc.now.Add(time.Hour)
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", future)}
	snap, err := tc.collector.Collect(inventory, reports, nil, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := operatorStatus(snap, "op1"); status == FleetResolvedCurrent {
		t.Fatal("future-dated attestation must not count toward resolution")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Error("future attestation should raise the unreconciled gauge")
	}
}

// TestCollector_IncompleteRaisesWatchedGauge proves that any incomplete readiness
// determination raises at least one of the blocking/stale/unreconciled gauges, so
// the CutoverRosterIncomplete alert fires instead of the fault staying silent.
func TestCollector_IncompleteRaisesWatchedGauge(t *testing.T) {
	tc := newTestCollector(t)

	// Empty inventory: readiness cannot be established at all.
	snap, err := tc.collector.Collect(nil, nil, nil, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete {
		t.Fatal("empty inventory must not be complete")
	}
	if tc.sink.gauge(MetricFleetBlockingOperators) == 0 &&
		tc.sink.gauge(MetricReportersStale) == 0 &&
		tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Error("incomplete readiness must raise at least one watched gauge")
	}
	if snap.Inventory.Unreconciled == 0 {
		t.Error("snapshot inventory should record the readiness fault")
	}
}

// TestCollector_SnapshotInventoryCountsAndInstanceStatuses proves the snapshot
// exposes inventory totals and per-instance reconciliation detail, and that the
// reporter count is distinct from the total instance count.
func TestCollector_SnapshotInventoryCountsAndInstanceStatuses(t *testing.T) {
	tc := newTestCollector(t)

	inventory := []InventoryInstance{
		eligibleInstance("i1", "op1"),
		eligibleInstance("i2", "op1"),
		{InstanceID: "i3", OperatorAddress: "op2", CeremonyEligible: false},
	}
	// i1 reports exact; i2 never reports, so op1 is blocking (i2 offline).
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inventory, reports, nil, 1001)
	if err != nil {
		t.Fatal(err)
	}

	if snap.Inventory.TotalInstances != 3 {
		t.Errorf("total instances = %d, want 3", snap.Inventory.TotalInstances)
	}
	if snap.Inventory.EligibleInstances != 2 {
		t.Errorf("eligible instances = %d, want 2", snap.Inventory.EligibleInstances)
	}

	var op1 *FleetOperatorEntry
	for i := range snap.Blocking {
		if snap.Blocking[i].OperatorAddress == "op1" {
			op1 = &snap.Blocking[i]
		}
	}
	if op1 == nil {
		t.Fatal("op1 not blocking")
	}
	if len(op1.InstanceStatuses) != 2 {
		t.Fatalf("expected 2 instance statuses, got %d", len(op1.InstanceStatuses))
	}
	reported := 0
	for _, st := range op1.InstanceStatuses {
		if st.Reported {
			reported++
		}
	}
	if reported != 1 {
		t.Errorf(
			"expected exactly 1 reporting instance of %d, got %d",
			len(op1.InstanceStatuses), reported,
		)
	}
}
