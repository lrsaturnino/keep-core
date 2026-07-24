package cutoverroster

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	testRevision = "abc123def456"
	testDigest   = "sha256:deadbeefcafe"
)

var fleetBaseTime = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

// fakeSink is a recording MetricsSink.
type fakeSink struct {
	mu             sync.Mutex
	gauges         map[string]float64
	operatorGauges map[string]float64
}

func newFakeSink() *fakeSink {
	return &fakeSink{
		gauges:         map[string]float64{},
		operatorGauges: map[string]float64{},
	}
}

func (s *fakeSink) SetGauge(name string, value float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gauges[name] = value
}

func (s *fakeSink) SetOperatorGauge(name, addr, provider, status string, value float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operatorGauges[name+"|"+addr+"|"+provider+"|"+status] = value
}

func (s *fakeSink) ResetOperatorGauges() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operatorGauges = map[string]float64{}
}

func (s *fakeSink) gauge(name string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gauges[name]
}

func testConfig() CollectorConfig {
	return CollectorConfig{
		ExpectedRevision:    testRevision,
		ExpectedEpoch:       ExpectedEpochSecurityV2Cutover,
		ExpectedImageDigest: testDigest,
		CutoverBlock:        1000,
		ChainID:             "1",
		CollectionInterval:  time.Minute,
		MissedThreshold:     2,
		SuccessThreshold:    3,
	}
}

func eligibleInstance(instanceID, operatorAddr string) InventoryInstance {
	return InventoryInstance{
		InstanceID:          instanceID,
		OperatorAddress:     operatorAddr,
		StakingProvider:     "sp-" + operatorAddr,
		CeremonyEligible:    true,
		ExpectedRevision:    testRevision,
		ExpectedEpoch:       ExpectedEpochSecurityV2Cutover,
		ExpectedImageDigest: testDigest,
		TrustedReportTarget: "https://reports.example/" + instanceID,
	}
}

func exactReport(instanceID, operatorAddr string, at time.Time) InstanceReport {
	return InstanceReport{
		InstanceID:      instanceID,
		OperatorAddress: operatorAddr,
		Revision:        testRevision,
		Epoch:           ExpectedEpochSecurityV2Cutover,
		ImageDigest:     testDigest,
		AttestedAt:      at,
	}
}

func staleReport(instanceID, operatorAddr string, at time.Time) InstanceReport {
	return InstanceReport{
		InstanceID:      instanceID,
		OperatorAddress: operatorAddr,
		Revision:        "old-revision",
		Epoch:           ExpectedEpochSecurityV2Cutover,
		ImageDigest:     testDigest,
		AttestedAt:      at,
	}
}

type testCollector struct {
	collector *Collector
	store     *Store
	sink      *fakeSink
	now       time.Time
}

func newTestCollector(t *testing.T) *testCollector {
	t.Helper()
	return newTestCollectorAtPath(t, filepath.Join(t.TempDir(), "roster.db"))
}

func newTestCollectorAtPath(t *testing.T, path string) *testCollector {
	t.Helper()
	store, err := OpenStore(path)
	if err != nil {
		t.Fatalf("cannot open store: %v", err)
	}
	tc := &testCollector{store: store, sink: newFakeSink(), now: fleetBaseTime}
	collector, err := newCollectorWithClock(
		testConfig(),
		store,
		tc.sink,
		func() time.Time { return tc.now },
	)
	if err != nil {
		t.Fatalf("cannot construct collector: %v", err)
	}
	tc.collector = collector
	t.Cleanup(func() { _ = store.Close() })
	return tc
}

func operatorStatus(snapshot FleetSnapshot, addr string) (FleetStatus, bool) {
	for _, group := range [][]FleetOperatorEntry{
		snapshot.Blocking, snapshot.Quarantined, snapshot.RecentlyResolved,
	} {
		for _, e := range group {
			if e.OperatorAddress == addr {
				return e.Status, true
			}
		}
	}
	return "", false
}

func TestCollector_ThreeExactReportsResolve(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	for cycle := 1; cycle <= 2; cycle++ {
		reports := map[string]InstanceReport{
			"i1": exactReport("i1", "op1", tc.now),
		}
		snap, err := tc.collector.Collect(inventory, reports, nil, uint64(1000+cycle))
		if err != nil {
			t.Fatal(err)
		}
		status, _ := operatorStatus(snap, "op1")
		if status == FleetResolvedCurrent {
			t.Fatalf("operator resolved too early at cycle %d", cycle)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inventory, reports, nil, 1003)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := operatorStatus(snap, "op1")
	if status != FleetResolvedCurrent {
		t.Fatalf("expected resolved_current after three exact reports, got %s", status)
	}
	if !snap.Complete {
		t.Errorf("expected snapshot to be complete")
	}
	if tc.sink.gauge(MetricFleetBlockingOperators) != 0 {
		t.Errorf("expected zero blocking operators")
	}
}

func TestCollector_PreCutoverExactWithoutMismatch(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	var snap FleetSnapshot
	// currentBlock 500 is before the cutover block 1000; exact reports still
	// resolve, and no mismatch/legacy status is fabricated.
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		var err error
		snap, err = tc.collector.Collect(inventory, reports, nil, 500)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	status, _ := operatorStatus(snap, "op1")
	if status != FleetResolvedCurrent {
		t.Fatalf("expected resolved_current pre-cutover, got %s", status)
	}
	if tc.sink.gauge(MetricFleetObservedLegacy) != 0 {
		t.Errorf("expected no observed-legacy operators pre-cutover")
	}
}

func TestCollector_TwoMissedReportsOffline(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Establish resolution first.
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		if _, err := tc.collector.Collect(inventory, reports, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	// Two consecutive missed collections -> offline_unknown and blocking.
	var snap FleetSnapshot
	for cycle := 0; cycle < 2; cycle++ {
		var err error
		snap, err = tc.collector.Collect(inventory, map[string]InstanceReport{}, nil, 1010)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	status, _ := operatorStatus(snap, "op1")
	if status != FleetOfflineUnknown {
		t.Fatalf("expected offline_unknown after two missed reports, got %s", status)
	}
	if snap.Complete {
		t.Errorf("snapshot must not be complete when an operator is offline")
	}
}

func TestCollector_NonCutoverRevisionBlocks(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	// An instance reporting a stale revision is noncutover_revision, before or
	// after the cutover block.
	reports := map[string]InstanceReport{"i1": staleReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inventory, reports, nil, 1100)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := operatorStatus(snap, "op1")
	if status != FleetNonCutoverRevision {
		t.Fatalf("expected noncutover_revision, got %s", status)
	}
	if snap.Complete {
		t.Errorf("snapshot must not be complete with a noncutover instance")
	}
}

func TestCollector_PostCutoverLegacyReopens(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		if _, err := tc.collector.Collect(inventory, reports, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	// A fresh post-cutover legacy sighting reopens the operator.
	sightings := []LegacySighting{
		{OperatorAddress: "op1", Block: 1100, ObservedAt: tc.now},
	}
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inventory, reports, sightings, 1100)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := operatorStatus(snap, "op1")
	if status != FleetObservedLegacy {
		t.Fatalf("expected observed_legacy after a post-cutover sighting, got %s", status)
	}
	if tc.sink.gauge(MetricFleetObservedLegacy) != 1 {
		t.Errorf("expected observed-legacy gauge to be 1")
	}
}

func TestCollector_SameOperatorMultiInstanceBlocking(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{
		eligibleInstance("i1", "op1"),
		eligibleInstance("i2", "op1"),
	}

	// i1 reports exact three times; i2 never reports (offline).
	var snap FleetSnapshot
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		var err error
		snap, err = tc.collector.Collect(inventory, reports, nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	status, _ := operatorStatus(snap, "op1")
	if status != FleetOfflineUnknown {
		t.Fatalf("expected the operator to remain blocking while one instance is offline, got %s", status)
	}
}

func TestCollector_VerifiedQuarantineOnly(t *testing.T) {
	tc := newTestCollector(t)

	// A single blocking (never-reporting) instance without quarantine evidence
	// keeps the operator blocking.
	blocking := eligibleInstance("i1", "op1")
	var snap FleetSnapshot
	for cycle := 0; cycle < 2; cycle++ {
		var err error
		snap, err = tc.collector.Collect(
			[]InventoryInstance{blocking}, map[string]InstanceReport{}, nil, 1000,
		)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if status, _ := operatorStatus(snap, "op1"); status != FleetOfflineUnknown {
		t.Fatalf("expected offline_unknown without quarantine evidence, got %s", status)
	}

	// Adding independently verified quarantine evidence flips it to quarantined.
	quarantined := blocking
	quarantined.QuarantineEvidenceRef = "evidence://verified/op1"
	snap, err := tc.collector.Collect(
		[]InventoryInstance{quarantined}, map[string]InstanceReport{}, nil, 1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := operatorStatus(snap, "op1"); status != FleetQuarantined {
		t.Fatalf("expected quarantined with verified evidence, got %s", status)
	}
	if !snap.Complete {
		t.Errorf("a fully quarantined fleet has no blocking operators and is complete")
	}
}

func TestCollector_DistinctStatesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.db")
	tc := newTestCollectorAtPath(t, path)

	inventory := []InventoryInstance{
		eligibleInstance("i-res", "opResolved"),
		eligibleInstance("i-off", "opOffline"),
		func() InventoryInstance {
			inv := eligibleInstance("i-quar", "opQuarantined")
			inv.QuarantineEvidenceRef = "evidence://verified/opQuarantined"
			return inv
		}(),
	}

	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{
			"i-res": exactReport("i-res", "opResolved", tc.now),
			// i-off and i-quar never report.
		}
		if _, err := tc.collector.Collect(inventory, reports, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	assertStates := func(t *testing.T, snap FleetSnapshot) {
		t.Helper()
		checks := map[string]FleetStatus{
			"opResolved":    FleetResolvedCurrent,
			"opOffline":     FleetOfflineUnknown,
			"opQuarantined": FleetQuarantined,
		}
		for addr, want := range checks {
			got, ok := operatorStatus(snap, addr)
			if !ok {
				t.Errorf("operator %s missing from snapshot", addr)
				continue
			}
			if got != want {
				t.Errorf("operator %s: got %s, want %s", addr, got, want)
			}
		}
	}
	assertStates(t, tc.collector.Snapshot())

	// Restart the collector against the same bbolt file.
	if err := tc.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := newTestCollectorAtPath(t, path)
	reopened.now = tc.now

	// One more cycle with the same inputs must preserve the distinct states.
	reports := map[string]InstanceReport{
		"i-res": exactReport("i-res", "opResolved", reopened.now),
	}
	snap, err := reopened.collector.Collect(inventory, reports, nil, 1001)
	if err != nil {
		t.Fatal(err)
	}
	assertStates(t, snap)
}

func TestCollector_ResolvedPurgedAfter30Days(t *testing.T) {
	tc := newTestCollector(t)
	resolvedInv := []InventoryInstance{eligibleInstance("ir", "opR")}

	// Resolve opR.
	for cycle := 0; cycle < 3; cycle++ {
		r := map[string]InstanceReport{"ir": exactReport("ir", "opR", tc.now)}
		if _, err := tc.collector.Collect(resolvedInv, r, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if _, ok := operatorStatus(tc.collector.Snapshot(), "opR"); !ok {
		t.Fatal("operator opR should be present (resolved) before purge")
	}

	// opR leaves the authoritative inventory (cutover complete) and the clock
	// advances past the retention window. Its resolved record ages out.
	tc.now = tc.now.Add(ResolvedRetention + time.Hour)
	snap, err := tc.collector.Collect(nil, nil, nil, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := operatorStatus(snap, "opR"); ok {
		t.Errorf("expected resolved operator to be purged after the retention window")
	}
}

func TestCollector_BlockingNeverPurged(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Never reports -> offline_unknown (blocking).
	for cycle := 0; cycle < 2; cycle++ {
		if _, err := tc.collector.Collect(inventory, map[string]InstanceReport{}, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	// Advance far past the retention window; blocking history is never purged.
	tc.now = tc.now.Add(ResolvedRetention * 3)
	snap, err := tc.collector.Collect(inventory, map[string]InstanceReport{}, nil, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if status, ok := operatorStatus(snap, "op1"); !ok || status != FleetOfflineUnknown {
		t.Fatalf("blocking operator must be retained indefinitely; got ok=%v status=%s", ok, status)
	}
}

func TestCollector_ReadinessAPIDeterministicAndDenies(t *testing.T) {
	tc := newTestCollector(t)
	inventory := []InventoryInstance{
		eligibleInstance("i2", "opB"),
		eligibleInstance("i1", "opA"),
	}
	if _, err := tc.collector.Collect(inventory, map[string]InstanceReport{}, nil, 1000); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(tc.collector, nil)

	// GET returns JSON with sorted, deterministic content and no TrustedReportTarget.
	req := httptest.NewRequest(http.MethodGet, readinessPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var snap FleetSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("cannot decode readiness response: %v", err)
	}
	if len(snap.Blocking) != 2 {
		t.Fatalf("expected 2 blocking operators, got %d", len(snap.Blocking))
	}
	if snap.Blocking[0].OperatorAddress != "opA" || snap.Blocking[1].OperatorAddress != "opB" {
		t.Errorf("blocking operators are not sorted deterministically: %+v", snap.Blocking)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("reports.example")) {
		t.Errorf("TrustedReportTarget must never be exposed in the API")
	}

	// Non-GET is denied.
	postReq := httptest.NewRequest(http.MethodPost, readinessPath, nil)
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", postRec.Code)
	}

	// Unknown paths are denied.
	unknownReq := httptest.NewRequest(http.MethodGet, "/secret", nil)
	unknownRec := httptest.NewRecorder()
	handler.ServeHTTP(unknownRec, unknownReq)
	if unknownRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", unknownRec.Code)
	}
}

func TestServer_BindsToConfiguredAddress(t *testing.T) {
	tc := newTestCollector(t)
	if _, err := tc.collector.Collect(nil, nil, nil, 1000); err != nil {
		t.Fatal(err)
	}

	server, err := NewServer("127.0.0.1:0", tc.collector, nil)
	if err != nil {
		t.Fatalf("cannot start server: %v", err)
	}
	go func() { _ = server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Close(ctx)
	})

	if got := server.Addr(); got == "" {
		t.Fatal("expected a bound address")
	}

	resp, err := http.Get("http://" + server.Addr() + readinessPath)
	if err != nil {
		t.Fatalf("cannot reach readiness endpoint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from bound server, got %d", resp.StatusCode)
	}
}
