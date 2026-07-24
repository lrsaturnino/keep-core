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
		{OperatorAddress: "op1", Block: 900, ObservedAt: tc.now},
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
		{OperatorAddress: "op1", Block: 5000, ObservedAt: tc.now},
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
