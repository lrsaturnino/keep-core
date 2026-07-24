package cutoverroster

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestCollectorConfig(t *testing.T, cfg CollectorConfig) *testCollector {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "roster.db"))
	if err != nil {
		t.Fatalf("cannot open store: %v", err)
	}
	tc := &testCollector{store: store, sink: newFakeSink(), now: fleetBaseTime}
	collector, err := newCollectorWithClock(
		cfg, store, tc.sink, func() time.Time { return tc.now },
	)
	if err != nil {
		t.Fatalf("cannot construct collector: %v", err)
	}
	collector.SetQuarantineVerifier(testQuarantineVerifier())
	// Match newTestCollectorAtPath: satisfy the mandatory trust-chain completeness
	// requirements so configuration-specific tests still exercise completeness.
	collector.SetIdentityVerifier(derivedIdentityVerifier{})
	collector.SetServiceDiscoveryConfigured(true)
	tc.collector = collector
	t.Cleanup(func() { _ = store.Close() })
	return tc
}

func resolveOperator(t *testing.T, tc *testCollector, inv []InventoryInstance, instanceID, operatorAddr string, block uint64) FleetSnapshot {
	t.Helper()
	var snap FleetSnapshot
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{
			instanceID: exactReport(instanceID, operatorAddr, tc.now),
		}
		var err error
		snap, err = tc.collector.Collect(inv, reports, nil, block)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	return snap
}

// TestInventoryInput_TargetIngestedButNeverSerialized proves the report target
// is accepted on input (via the explicit JSON key) yet never serialized back out
// of an InventoryInstance.
func TestInventoryInput_TargetIngestedButNeverSerialized(t *testing.T) {
	raw := `[{
		"instance_id": "i1",
		"operator_address": "0xabc",
		"ceremony_eligible": true,
		"trusted_report_target": "https://reports.example/i1"
	}]`

	var inputs []InventoryInstanceInput
	if err := json.Unmarshal([]byte(raw), &inputs); err != nil {
		t.Fatalf("cannot decode inventory input: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}

	inv := inputs[0].ToInventoryInstance()
	if inv.TrustedReportTarget != "https://reports.example/i1" {
		t.Errorf("target not ingested: %q", inv.TrustedReportTarget)
	}

	// The in-memory InventoryInstance must never serialize the target.
	out, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("cannot marshal inventory instance: %v", err)
	}
	if strings.Contains(string(out), "reports.example") ||
		strings.Contains(string(out), "trusted_report_target") {
		t.Errorf("InventoryInstance leaked the trusted report target: %s", out)
	}
}

// TestCollector_EmptyInventoryNotComplete proves the fail-closed default: an
// empty/missing authoritative inventory can never be complete.
func TestCollector_EmptyInventoryNotComplete(t *testing.T) {
	tc := newTestCollector(t)
	snap, err := tc.collector.Collect(nil, nil, nil, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete {
		t.Errorf("empty inventory must never be complete")
	}
}

// TestCollector_FreshBlockRequiredForComplete proves that a resolved fleet is
// still not complete without a fresh (nonzero) current block.
func TestCollector_FreshBlockRequiredForComplete(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Resolve at a fresh block: complete.
	snap := resolveOperator(t, tc, inv, "i1", "op1", 1000)
	if !snap.Complete {
		t.Fatalf("expected complete with a fresh block, got not complete")
	}

	// One more cycle with currentBlock 0 (chain clock unavailable): not complete.
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inv, reports, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete {
		t.Errorf("must not be complete when the current block is zero")
	}
}

// TestCollector_ExpectedIdentityRequiredForComplete proves that an unset
// expected artifact identity or chain ID can never produce complete=true.
func TestCollector_ExpectedIdentityRequiredForComplete(t *testing.T) {
	cfg := testConfig()
	cfg.ExpectedImageDigest = "" // missing expected artifact identity
	tc := newTestCollectorConfig(t, cfg)

	inv := []InventoryInstance{eligibleInstance("i1", "op1")}
	// The instance reports the expected revision/epoch but the collector's own
	// expected digest is unset, so readiness must fail closed.
	snap := resolveOperator(t, tc, inv, "i1", "op1", 1000)
	if snap.Complete {
		t.Errorf("must not be complete with an unset expected image digest")
	}
}

// TestCollector_PreCutoverSightingIgnored proves a legacy sighting before the
// cutover block is not valid post-cutover straggler evidence.
func TestCollector_PreCutoverSightingIgnored(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}
	resolveOperator(t, tc, inv, "i1", "op1", 1000)

	// CutoverBlock is 1000; a sighting at block 900 is pre-cutover.
	sightings := []LegacySighting{
		{OperatorAddress: opAddr("op1"), Block: 900, ObservedAt: tc.now},
	}
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inv, reports, sightings, 1100)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := operatorStatus(snap, "op1"); status == FleetObservedLegacy {
		t.Errorf("pre-cutover sighting must not produce observed_legacy")
	}
	if tc.sink.gauge(MetricFleetObservedLegacy) != 0 {
		t.Errorf("pre-cutover sighting must not increment observed-legacy gauge")
	}
}

// TestCollector_FutureSightingIgnored proves a sighting past the current block is
// ignored.
func TestCollector_FutureSightingIgnored(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}
	resolveOperator(t, tc, inv, "i1", "op1", 1000)

	sightings := []LegacySighting{
		{OperatorAddress: opAddr("op1"), Block: 5000, ObservedAt: tc.now},
	}
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inv, reports, sightings, 1100)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := operatorStatus(snap, "op1"); status == FleetObservedLegacy {
		t.Errorf("future sighting must not produce observed_legacy")
	}
}

// TestCollector_AddressNormalization proves inventory and sightings that refer to
// one operator with different casing deduplicate to a single operator record.
func TestCollector_AddressNormalization(t *testing.T) {
	tc := newTestCollector(t)

	inv := []InventoryInstance{eligibleInstance("i1", "0xABCdef0000000000000000000000000000000001")}
	// The node-local sighting is already lowercase; it must map to the same
	// operator, not a second one.
	sightings := []LegacySighting{
		{OperatorAddress: "0xabcdef0000000000000000000000000000000001", Block: 1100, ObservedAt: tc.now},
	}
	snap, err := tc.collector.Collect(inv, map[string]InstanceReport{}, sightings, 1100)
	if err != nil {
		t.Fatal(err)
	}

	total := len(snap.Blocking) + len(snap.Quarantined) + len(snap.RecentlyResolved)
	if total != 1 {
		t.Fatalf("expected exactly 1 deduplicated operator, got %d: %+v", total, snap)
	}
	if status, _ := operatorStatus(snap, "0xABCDEF0000000000000000000000000000000001"); status != FleetObservedLegacy {
		t.Errorf("expected the case-different sighting to attach to the same operator")
	}
}

// TestCollector_ReplayedReportRejected proves an attestation that is not newer
// than the last accepted one is treated as a missed collection, not accepted.
func TestCollector_ReplayedReportRejected(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

	report := exactReport("i1", "op1", tc.now)
	// First cycle accepts.
	if _, err := tc.collector.Collect(inv, map[string]InstanceReport{"i1": report}, nil, 1000); err != nil {
		t.Fatal(err)
	}
	// Replay the identical attestation (same AttestedAt, same ReporterRevision)
	// twice more. It must not advance ConsecutiveExact; the instance instead
	// accrues missed collections and becomes offline.
	var snap FleetSnapshot
	for cycle := 0; cycle < 2; cycle++ {
		var err error
		snap, err = tc.collector.Collect(inv, map[string]InstanceReport{"i1": report}, nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
	}
	if status, _ := operatorStatus(snap, "op1"); status != FleetOfflineUnknown {
		t.Errorf("replayed reports must not resolve; got %s", status)
	}
}

// TestCollector_MissingAttestationTimeRejected proves a report without an
// attestation time is rejected and counted as an inventory-reconciliation
// failure, not accepted.
func TestCollector_MissingAttestationTimeRejected(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

	report := exactReport("i1", "op1", tc.now)
	report.AttestedAt = time.Time{} // missing

	snap, err := tc.collector.Collect(inv, map[string]InstanceReport{"i1": report}, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete {
		t.Errorf("a report missing its attestation time must not yield completeness")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Errorf("a missing attestation time must count as unreconciled")
	}
}

// TestCollector_ConcurrentCollectAndSnapshot exercises the collector's mutex:
// concurrent Collect writes and HTTP-style Snapshot reads must be race-free.
func TestCollector_ConcurrentCollectAndSnapshot(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = tc.collector.Snapshot()
			}
		}
	}()

	for i := 0; i < 50; i++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		if _, err := tc.collector.Collect(inv, reports, nil, uint64(1000+i)); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	close(stop)
	wg.Wait()
}

// TestCollector_MalformedIdentityRejected proves an eligible inventory entry with
// a missing instance or operator identity is rejected as an inventory-
// reconciliation fault: it cannot be reconciled or counted as an eligible
// instance, and it forces readiness closed.
func TestCollector_MalformedIdentityRejected(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{
		eligibleInstance("", "op1"), // missing instance ID
		eligibleInstance("i2", ""),  // missing operator address
	}
	snap, err := tc.collector.Collect(inv, nil, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete {
		t.Errorf("a malformed inventory identity must not yield completeness")
	}
	if snap.Inventory.EligibleInstances != 0 {
		t.Errorf(
			"malformed entries must not count as reconciled eligible; got %d",
			snap.Inventory.EligibleInstances,
		)
	}
	if snap.Inventory.Unreconciled < 2 {
		t.Errorf(
			"both malformed entries must count as unreconciled; got %d",
			snap.Inventory.Unreconciled,
		)
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Errorf("a malformed identity must raise the unreconciled gauge")
	}
}

// TestCollector_MissingReportIdentityRejected proves a report that does not
// self-identify — an empty instance ID or operator address — is rejected as an
// unreconciled fault and cannot resolve the operator, matching the reporter's
// documented contract that missing identity is rejected rather than fabricated
// from inventory.
func TestCollector_MissingReportIdentityRejected(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*InstanceReport)
	}{
		{"empty instance id", func(r *InstanceReport) { r.InstanceID = "" }},
		{"empty operator address", func(r *InstanceReport) { r.OperatorAddress = "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestCollector(t)
			inv := []InventoryInstance{eligibleInstance("i1", "op1")}

			var snap FleetSnapshot
			for cycle := 0; cycle < 3; cycle++ {
				report := exactReport("i1", "op1", tc.now)
				tt.mutate(&report)
				var err error
				snap, err = tc.collector.Collect(
					inv, map[string]InstanceReport{"i1": report}, nil, 1001,
				)
				if err != nil {
					t.Fatal(err)
				}
				tc.now = tc.now.Add(time.Minute)
			}

			if status, _ := operatorStatus(snap, "op1"); status == FleetResolvedCurrent {
				t.Errorf("a report without a self-identity must not resolve the operator")
			}
			if snap.Inventory.Unreconciled == 0 {
				t.Errorf("a report without a self-identity must count as unreconciled")
			}
			if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
				t.Errorf("a missing report identity must raise the unreconciled gauge")
			}
		})
	}
}

// TestCollector_DuplicateInstanceIDRejected proves a duplicate instance ID within
// one inventory cycle is flagged: the first entry is reconciled, the duplicate
// cannot silently overwrite it or create a second operator record, and readiness
// fails closed.
func TestCollector_DuplicateInstanceIDRejected(t *testing.T) {
	tc := newTestCollector(t)
	inv := []InventoryInstance{
		eligibleInstance("i1", "op1"),
		eligibleInstance("i1", "op2"), // duplicate instance ID, different operator
	}
	snap, err := tc.collector.Collect(
		inv,
		map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)},
		nil,
		1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete {
		t.Errorf("a duplicate instance ID must not yield completeness")
	}
	// Exactly one entry is reconciled eligible (the first i1); the duplicate is a
	// fault, not a second eligible instance.
	if snap.Inventory.EligibleInstances != 1 {
		t.Errorf(
			"expected 1 reconciled eligible instance, got %d",
			snap.Inventory.EligibleInstances,
		)
	}
	if snap.Inventory.Unreconciled == 0 {
		t.Errorf("the duplicate instance ID must count as unreconciled")
	}
	if _, ok := operatorStatus(snap, "op2"); ok {
		t.Errorf("the duplicate entry must not create a second operator record")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Errorf("the duplicate instance ID must raise the unreconciled gauge")
	}
}

// TestCollector_ContradictoryInstanceExpectationRejected proves an eligible
// inventory entry whose own expected release identity contradicts the collector's
// configured expected release is rejected as an inventory-reconciliation fault
// and cannot resolve the operator even with otherwise-exact reports.
func TestCollector_ContradictoryInstanceExpectationRejected(t *testing.T) {
	tc := newTestCollector(t)
	contradictory := eligibleInstance("i1", "op1")
	contradictory.ExpectedRevision = "some-other-revision" // contradicts config
	inv := []InventoryInstance{contradictory}

	// Even three exact reports (matching the collector config) must not resolve
	// the operator, because the inventory disagrees with the config about what the
	// cutover release is for this instance.
	var snap FleetSnapshot
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		var err error
		snap, err = tc.collector.Collect(inv, reports, nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if snap.Complete {
		t.Errorf("a contradictory per-instance expectation must not yield completeness")
	}
	if snap.Inventory.Unreconciled == 0 {
		t.Errorf("a contradictory per-instance expectation must count as unreconciled")
	}
	if status, _ := operatorStatus(snap, "op1"); status == FleetResolvedCurrent {
		t.Errorf("a contradictory per-instance expectation must not resolve the operator")
	}
}

// TestCollector_RecordInputUnavailableFailsClosed proves that once an
// authoritative input becomes unreadable, a previously-certified "complete=true"
// readiness snapshot is superseded by an incomplete one carrying a nonzero
// inventory-unreconciled signal, and that persisted operator history is left
// intact so a transient input blip neither resolves nor ages any operator.
func TestCollector_RecordInputUnavailableFailsClosed(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Drive the operator to resolved_current across three exact collections so the
	// last published snapshot is genuinely complete with zero watched gauges.
	var snap FleetSnapshot
	for cycle := 1; cycle <= 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		var err error
		snap, err = tc.collector.Collect(inventory, reports, nil, uint64(1000+cycle))
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if !snap.Complete {
		t.Fatalf("precondition failed: expected a complete snapshot after three exact reports")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) != 0 {
		t.Fatalf("precondition failed: expected zero unreconciled before the input failure")
	}

	// The next cycle cannot read its authoritative input.
	failed := tc.collector.RecordInputUnavailable(1004)

	if failed.Complete {
		t.Errorf("an unavailable authoritative input must not certify readiness")
	}
	if failed.Inventory.Unreconciled == 0 {
		t.Errorf("an unavailable authoritative input must surface as unreconciled")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Errorf("expected a nonzero unreconciled gauge after the input failure")
	}
	if failed.CurrentBlock != 1004 {
		t.Errorf("expected the failed snapshot to be stamped with the read block, got %d", failed.CurrentBlock)
	}

	// The most recently served snapshot must be the incomplete one, not the stale
	// complete snapshot from the prior cycle.
	served := tc.collector.Snapshot()
	if served.Complete {
		t.Errorf("the served snapshot must be incomplete while the input is unavailable")
	}

	// Persisted history is untouched: op1 is still recorded as resolved_current, it
	// was neither aged out nor reopened by the transient input failure.
	if status, ok := operatorStatus(served, "op1"); !ok || status != FleetResolvedCurrent {
		t.Errorf("expected op1 to remain resolved_current after the input failure, got %s (present=%t)", status, ok)
	}
}

// TestCollector_PersistenceFailureFailsClosed proves that a collection cycle whose
// central-state write fails also fails readiness closed: even though the inputs
// were fully readable and the reconciliation succeeded, a persistence error must
// supersede a previously-certified "complete=true" snapshot with an incomplete one
// carrying a nonzero inventory-unreconciled signal, rather than leaving the stale
// complete snapshot and its zero gauges served. This covers the Collect error path,
// complementing the unreadable-input path above.
func TestCollector_PersistenceFailureFailsClosed(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Drive the operator to resolved_current across three exact collections so the
	// last published snapshot is genuinely complete with zero watched gauges.
	var snap FleetSnapshot
	for cycle := 1; cycle <= 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		var err error
		snap, err = tc.collector.Collect(inventory, reports, nil, uint64(1000+cycle))
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if !snap.Complete {
		t.Fatalf("precondition failed: expected a complete snapshot after three exact reports")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) != 0 {
		t.Fatalf("precondition failed: expected zero unreconciled before the persistence failure")
	}

	// Force the next cycle's central-state write to fail by closing the bbolt store
	// out from under the collector. The inputs are still perfectly readable.
	if err := tc.store.Close(); err != nil {
		t.Fatalf("cannot close store to induce a persistence failure: %v", err)
	}

	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	_, err := tc.collector.Collect(inventory, reports, nil, 1004)
	if err == nil {
		t.Fatalf("expected Collect to return an error when persistence fails")
	}

	// The most recently served snapshot must be the incomplete one, not the stale
	// complete snapshot from the prior cycle.
	served := tc.collector.Snapshot()
	if served.Complete {
		t.Errorf("the served snapshot must be incomplete after a persistence failure")
	}
	if served.Inventory.Unreconciled == 0 {
		t.Errorf("a persistence failure must surface as unreconciled")
	}
	if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
		t.Errorf("expected a nonzero unreconciled gauge after the persistence failure")
	}

	// Persisted history is untouched: op1 remains resolved_current in the served
	// snapshot; the failed write neither aged it out nor reopened it.
	if status, ok := operatorStatus(served, "op1"); !ok || status != FleetResolvedCurrent {
		t.Errorf("expected op1 to remain resolved_current after the persistence failure, got %s (present=%t)", status, ok)
	}
}
