package cutoverroster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// opAddr maps a symbolic test operator name to a canonical (lowercase 0x + 40
// hex) address so tests can keep using readable names while the collector
// enforces canonical addresses. An empty name maps to the empty string (so the
// malformed-identity tests still exercise a missing address), and a value that
// already looks like a 0x address is passed through lowercased.
func opAddr(name string) string {
	if name == "" {
		return ""
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(lower, "0x") && len(lower) == 42 {
		return lower
	}
	sum := sha256.Sum256([]byte(name))
	return "0x" + hex.EncodeToString(sum[:20])
}

const (
	testRevision = "abc123def456"
	// testDigest is a full, immutable content digest (sha256:<64 hex>). The
	// collector now rejects an abbreviated digest, so the fixture uses a complete
	// one (this happens to be the sha256 of the empty string).
	testDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// spForOperator derives a canonical (lowercase 0x + 40 hex) staking-provider
// address deterministically from an operator address, so test inventory carries
// a canonical staking provider (the collector now rejects a non-address one) and
// the default identity verifier can independently reproduce the expected mapping.
func spForOperator(operatorAddress string) string {
	sum := sha256.Sum256([]byte("sp:" + normalizeAddress(operatorAddress)))
	return "0x" + hex.EncodeToString(sum[:20])
}

// derivedIdentityVerifier is the default test identity verifier. It returns the
// same canonical staking provider spForOperator derives, so an operator whose
// inventory claim matches verifies successfully while a mismatched or non-derived
// claim fails — a real verification, not an echo of the inventory claim.
type derivedIdentityVerifier struct{}

func (derivedIdentityVerifier) OperatorStakingProviderAtBlock(
	_ context.Context, operatorAddress string, _ uint64,
) (string, error) {
	op := normalizeAddress(operatorAddress)
	if !isCanonicalAddress(op) {
		return "", errNoIdentity
	}
	return spForOperator(op), nil
}

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
		// Production readiness requires the full trust chain. The test collector
		// (newTestCollectorAtPath) installs the default identity verifier and marks
		// discovery configured, so completeness is reachable while these stay on.
		RequireServiceDiscovery:     true,
		RequireIdentityVerification: true,
	}
}

func eligibleInstance(instanceID, operatorName string) InventoryInstance {
	op := opAddr(operatorName)
	return InventoryInstance{
		InstanceID:      instanceID,
		OperatorAddress: op,
		StakingProvider: spForOperator(op),
		// A unique per-instance network ID: the collector now requires one (and
		// requires it to be distinct) whenever the trust chain is enforced, so two
		// instances cannot collapse onto one responding node. Derived from the
		// instance ID so every fixture instance is automatically distinct.
		NetworkID:           "net-" + instanceID,
		CeremonyEligible:    true,
		ExpectedRevision:    testRevision,
		ExpectedEpoch:       ExpectedEpochSecurityV2Cutover,
		ExpectedImageDigest: testDigest,
		TrustedReportTarget: "https://reports.example/" + instanceID,
	}
}

// reporterRevisionFor derives a nonzero, monotonically non-decreasing reporter
// revision from the attestation time so the collector's replay/downgrade guard
// accepts a genuinely advancing report while rejecting a stale replay.
func reporterRevisionFor(at time.Time) uint64 {
	return uint64(at.Unix())
}

func exactReport(instanceID, operatorName string, at time.Time) InstanceReport {
	return InstanceReport{
		InstanceID:       instanceID,
		OperatorAddress:  opAddr(operatorName),
		NetworkID:        "net-" + instanceID,
		Revision:         testRevision,
		Epoch:            ExpectedEpochSecurityV2Cutover,
		ImageDigest:      testDigest,
		AttestedAt:       at,
		ReporterRevision: reporterRevisionFor(at),
	}
}

func staleReport(instanceID, operatorName string, at time.Time) InstanceReport {
	return InstanceReport{
		InstanceID:       instanceID,
		OperatorAddress:  opAddr(operatorName),
		NetworkID:        "net-" + instanceID,
		Revision:         "old-revision",
		Epoch:            ExpectedEpochSecurityV2Cutover,
		ImageDigest:      testDigest,
		AttestedAt:       at,
		ReporterRevision: reporterRevisionFor(at),
	}
}

// testQuarantineVerifier verifies the specific evidence references used by the
// tests. It is installed on every test collector so verified quarantine survives
// a restart; any reference not listed here fails verification (fail closed).
func testQuarantineVerifier() QuarantineVerifier {
	return NewAllowlistQuarantineVerifier([]VerifiedQuarantineEntry{
		{InstanceID: "i1", OperatorAddress: opAddr("op1"), EvidenceRef: "evidence://verified/op1"},
		{InstanceID: "i-quar", OperatorAddress: opAddr("opQuarantined"), EvidenceRef: "evidence://verified/opQuarantined"},
	})
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
	collector.SetQuarantineVerifier(testQuarantineVerifier())
	// Install the default identity verifier and mark discovery configured so the
	// mandatory-trust-chain completeness requirements are satisfied. Tests that
	// exercise identity mismatch install their own verifier over this default.
	collector.SetIdentityVerifier(derivedIdentityVerifier{})
	collector.SetServiceDiscoveryConfigured(true)
	tc.collector = collector
	t.Cleanup(func() { _ = store.Close() })
	return tc
}

func operatorStatus(snapshot FleetSnapshot, addr string) (FleetStatus, bool) {
	// Operator addresses are canonicalized on ingestion, so map the query (a
	// symbolic test name or a raw address) through the same mapping.
	want := opAddr(addr)
	for _, group := range [][]FleetOperatorEntry{
		snapshot.Blocking, snapshot.Quarantined, snapshot.RecentlyResolved,
	} {
		for _, e := range group {
			if e.OperatorAddress == want {
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
		{OperatorAddress: opAddr("op1"), Block: 1100, ObservedAt: tc.now},
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

// TestCollector_UnverifiedQuarantineStaysBlocking is the negative quarantine
// case: an evidence reference that is not independently verified (absent from
// the verifier allowlist) does not quarantine the operator; it stays blocking.
func TestCollector_UnverifiedQuarantineStaysBlocking(t *testing.T) {
	tc := newTestCollector(t)

	unverified := eligibleInstance("i1", "op1")
	// A plausible-looking but not independently-verified reference.
	unverified.QuarantineEvidenceRef = "evidence://unverified/op1"

	var snap FleetSnapshot
	for cycle := 0; cycle < 2; cycle++ {
		var err error
		snap, err = tc.collector.Collect(
			[]InventoryInstance{unverified}, map[string]InstanceReport{}, nil, 1000,
		)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	if status, _ := operatorStatus(snap, "op1"); status != FleetOfflineUnknown {
		t.Fatalf("unverified quarantine evidence must not quarantine; got %s", status)
	}
	if snap.Complete {
		t.Errorf("snapshot must not be complete with an unverified, blocking operator")
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

// TestCollector_ResolvedWhollyVanishedReopensOfflineNotPurged is the fail-closed
// regression test for reconciliation rule 6: a resolved_current operator whose
// every instance disappears entirely from the authoritative inventory (and whose
// sightings are also absent) must REOPEN as offline_unknown, not silently stay
// resolved and later be purged. Removal from inventory never resolves central
// state, so its unresolved history is then retained indefinitely.
func TestCollector_ResolvedWhollyVanishedReopensOfflineNotPurged(t *testing.T) {
	tc := newTestCollector(t)
	resolvedInv := []InventoryInstance{eligibleInstance("ir", "opR")}

	// Resolve opR across three exact collections while it is present.
	for cycle := 0; cycle < 3; cycle++ {
		r := map[string]InstanceReport{"ir": exactReport("ir", "opR", tc.now)}
		if _, err := tc.collector.Collect(resolvedInv, r, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if status, ok := operatorStatus(tc.collector.Snapshot(), "opR"); !ok || status != FleetResolvedCurrent {
		t.Fatalf("precondition: opR must be resolved before it vanishes, got %s (present=%t)", status, ok)
	}

	// opR wholly vanishes from the authoritative inventory and current sightings.
	tc.now = tc.now.Add(time.Minute)
	snap, err := tc.collector.Collect(nil, nil, nil, 1005)
	if err != nil {
		t.Fatal(err)
	}
	status, ok := operatorStatus(snap, "opR")
	if !ok {
		t.Fatal("a wholly-vanished resolved operator must be retained, not dropped")
	}
	if status == FleetResolvedCurrent {
		t.Fatalf("a wholly-vanished resolved operator must reopen, not stay resolved_current")
	}
	if status != FleetOfflineUnknown {
		t.Fatalf("expected the vanished operator to reopen as offline_unknown, got %s", status)
	}
	if snap.Complete {
		t.Error("readiness must not be complete while a reopened operator blocks")
	}

	// Advance far past the resolved-retention window and reconcile again with the
	// operator still absent: it must NOT be purged, because it is now blocking
	// (unresolved) and unresolved history is retained indefinitely.
	tc.now = tc.now.Add(ResolvedRetention + time.Hour)
	snap, err = tc.collector.Collect(nil, nil, nil, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if status, ok := operatorStatus(snap, "opR"); !ok || status != FleetOfflineUnknown {
		t.Errorf(
			"a reopened (blocking) operator must be retained indefinitely, not purged; got %s (present=%t)",
			status, ok,
		)
	}
}

// TestCollector_ReportsAcceptedImmediatelyAfterRestart is the regression for the
// restart-durable reporter revision (net-new finding 1). The collector persists
// the highest accepted reporter revision as a high-water mark and rejects
// anything below it. If the reporter revision were a process-local counter that
// reset on restart, every post-restart report would sit below the persisted
// high-water mark and be rejected for as many cycles as the previous process had
// run, silently reopening a resolved operator. Because the reporter revision is
// derived from the (monotonic wall-clock) attestation timestamp, a report taken
// after a restart still exceeds the persisted high-water mark and is accepted
// immediately, keeping the operator resolved.
func TestCollector_ReportsAcceptedImmediatelyAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.db")
	tc := newTestCollectorAtPath(t, path)
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Run many pre-restart cycles so the persisted reporter-revision high-water
	// mark is large (mirroring a long-running previous process).
	for cycle := 0; cycle < 20; cycle++ {
		reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
		if _, err := tc.collector.Collect(inv, reports, nil, 1000); err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if status, _ := operatorStatus(tc.collector.Snapshot(), "op1"); status != FleetResolvedCurrent {
		t.Fatalf("precondition: op1 must be resolved before restart, got %s", status)
	}

	// Restart the collector against the same bbolt file (a fresh process resets
	// any in-memory reporter-revision counter).
	if err := tc.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := newTestCollectorAtPath(t, path)
	reopened.now = tc.now.Add(time.Minute)

	// A single exact report immediately after restart must be ACCEPTED (its
	// timestamp-derived reporter revision exceeds the persisted high-water mark),
	// keeping the operator resolved. A rejected report would drop the operator's
	// exact-confirmation streak and reopen it as offline_unknown.
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", reopened.now)}
	snap, err := reopened.collector.Collect(inv, reports, nil, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := operatorStatus(snap, "op1"); status != FleetResolvedCurrent {
		t.Fatalf(
			"a report taken after restart must be accepted immediately, keeping op1 "+
				"resolved; got %s (a reset reporter revision would reject it)", status,
		)
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
	// Blocking operators are sorted deterministically by canonical operator
	// address, and both expected operators are present.
	if snap.Blocking[0].OperatorAddress >= snap.Blocking[1].OperatorAddress {
		t.Errorf("blocking operators are not sorted deterministically: %+v", snap.Blocking)
	}
	present := map[string]bool{
		snap.Blocking[0].OperatorAddress: true,
		snap.Blocking[1].OperatorAddress: true,
	}
	if !present[opAddr("opA")] || !present[opAddr("opB")] {
		t.Errorf("expected both opA and opB in the blocking set, got %+v", snap.Blocking)
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

	server, err := NewServer("127.0.0.1:0", tc.collector, nil, nil)
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
