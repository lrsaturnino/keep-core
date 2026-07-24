package cutoverroster

import (
	"path/filepath"
	"testing"
	"time"
)

// newBareCollector builds a collector with no identity verifier installed and no
// service-discovery feed marked, so a test can exercise exactly which parts of
// the mandatory trust chain gate completeness.
func newBareCollector(t *testing.T, cfg CollectorConfig) *testCollector {
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

// TestCollector_IdentityVerifierRequiredForComplete proves an installed on-chain
// identity verifier is mandatory for completeness: without it, an otherwise fully
// resolved fleet is not complete (a missing WalletRegistry verification blocks
// readiness rather than certifying inventory identity assertions on their own).
func TestCollector_IdentityVerifierRequiredForComplete(t *testing.T) {
	cfg := testConfig() // RequireIdentityVerification + RequireServiceDiscovery on
	tc := newBareCollector(t, cfg)
	tc.collector.SetServiceDiscoveryConfigured(true) // isolate the identity requirement
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

	// Three exact reports with NO identity verifier installed: the operator
	// resolves but readiness must not be complete.
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
		t.Fatal("readiness must not be complete without an installed identity verifier")
	}

	// Installing the verifier (which confirms the derived staking provider) makes
	// the same fleet complete.
	tc.collector.SetIdentityVerifier(derivedIdentityVerifier{})
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inv, reports, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Complete {
		t.Fatal("readiness must be complete once identity verification is configured")
	}
}

// TestCollector_ServiceDiscoveryRequiredForComplete proves a wired
// service-discovery feed is mandatory for completeness: without it, an otherwise
// fully resolved fleet is not complete (a missing discovery feed blocks readiness
// rather than degrading to an inventory-only view).
func TestCollector_ServiceDiscoveryRequiredForComplete(t *testing.T) {
	cfg := testConfig()
	tc := newBareCollector(t, cfg)
	tc.collector.SetIdentityVerifier(derivedIdentityVerifier{}) // isolate the discovery requirement
	inv := []InventoryInstance{eligibleInstance("i1", "op1")}

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
		t.Fatal("readiness must not be complete without a wired service-discovery feed")
	}

	tc.collector.SetServiceDiscoveryConfigured(true)
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	snap, err := tc.collector.Collect(inv, reports, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Complete {
		t.Fatal("readiness must be complete once service discovery is configured")
	}
}

// TestCollector_NonCanonicalOrZeroStakingProviderRejected proves the staking
// provider must be a canonical, non-zero address: a symbolic or zero-address
// staking provider is an inventory-reconciliation fault that blocks readiness.
func TestCollector_NonCanonicalOrZeroStakingProviderRejected(t *testing.T) {
	for _, bad := range []string{
		"sp-op1", // symbolic, not an address
		"0x1234", // too short
		zeroAddress,
	} {
		t.Run(bad, func(t *testing.T) {
			tc := newTestCollector(t)
			inv := eligibleInstance("i1", "op1")
			inv.StakingProvider = bad
			snap, err := tc.collector.Collect([]InventoryInstance{inv}, nil, nil, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Inventory.EligibleInstances != 0 {
				t.Errorf("staking provider %q must not count as reconciled eligible", bad)
			}
			if snap.Inventory.Unreconciled == 0 {
				t.Errorf("staking provider %q must count as unreconciled", bad)
			}
			if snap.Complete {
				t.Errorf("staking provider %q must not yield completeness", bad)
			}
		})
	}
}

// TestCollector_MalformedImageDigestRejected proves the expected image digest must
// be a full sha256:<64 hex> content digest: an abbreviated digest cannot pin the
// exact runtime image and is an inventory-reconciliation fault.
func TestCollector_MalformedImageDigestRejected(t *testing.T) {
	for _, bad := range []string{
		"sha256:deadbeefcafe",          // abbreviated
		"latest",                       // mutable tag
		"sha256:" + shortHex(63),       // one hex short
		"sha256:" + shortHex(64) + "0", // one hex too long
		"md5:" + shortHex(64),          // wrong algorithm
	} {
		t.Run(bad, func(t *testing.T) {
			tc := newTestCollector(t)
			inv := eligibleInstance("i1", "op1")
			inv.ExpectedImageDigest = bad
			snap, err := tc.collector.Collect([]InventoryInstance{inv}, nil, nil, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Inventory.EligibleInstances != 0 {
				t.Errorf("digest %q must not count as reconciled eligible", bad)
			}
			if snap.Inventory.Unreconciled == 0 {
				t.Errorf("digest %q must count as unreconciled", bad)
			}
		})
	}
}

func shortHex(n int) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexDigits[i%len(hexDigits)]
	}
	return string(b)
}

// TestCollector_ContradictoryStakingProvidersAcrossInstances proves that when two
// eligible instances of one operator assert different (canonical) staking
// providers, the contradiction is a fail-closed inventory fault: the last claim
// does not silently win, the operator cannot resolve, and readiness fails closed.
func TestCollector_ContradictoryStakingProvidersAcrossInstances(t *testing.T) {
	tc := newTestCollector(t)

	i1 := eligibleInstance("i1", "op1")
	i2 := eligibleInstance("i2", "op1")
	// Two distinct, individually-canonical staking providers for the same operator.
	i1.StakingProvider = "0x1111111111111111111111111111111111111111"
	i2.StakingProvider = "0x2222222222222222222222222222222222222222"
	inv := []InventoryInstance{i1, i2}

	var snap FleetSnapshot
	for cycle := 0; cycle < 3; cycle++ {
		reports := map[string]InstanceReport{
			"i1": exactReport("i1", "op1", tc.now),
			"i2": exactReport("i2", "op1", tc.now),
		}
		var err error
		snap, err = tc.collector.Collect(inv, reports, nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}

	if status, _ := operatorStatus(snap, "op1"); status == FleetResolvedCurrent {
		t.Fatalf("a cross-instance staking-provider contradiction must not resolve, got %s", status)
	}
	if snap.Inventory.Unreconciled == 0 {
		t.Error("a cross-instance staking-provider contradiction must count as unreconciled")
	}
	if snap.Complete {
		t.Error("a cross-instance staking-provider contradiction must not yield completeness")
	}
}

// TestCollector_PurgeResolvedAfter30Days restores independent coverage of the
// 30-day resolved-purge mechanism (collector.go purgeResolved). It is a
// white-box test of the mechanism rather than an end-to-end reconciliation
// scenario, because the two semantics genuinely conflict: the fail-closed
// reopening of a vanished resolved operator (reconciliation rule 6, covered by
// TestCollector_ResolvedWhollyVanishedReopensOfflineNotPurged) deliberately keeps
// a departed operator retained-and-blocking rather than resolved, so under normal
// reconciliation an actively resolved operator is continuously re-confirmed and a
// departed one reopens — neither ages out. purgeResolved therefore remains a
// bounded-store backstop for a resolved record that is no longer being
// re-confirmed, and this test pins that backstop: a resolved record older than
// the retention window is purged (with its instances), while a fresh resolved
// record and any blocking record are retained.
func TestCollector_PurgeResolvedAfter30Days(t *testing.T) {
	tc := newTestCollector(t)
	c := tc.collector
	now := fleetBaseTime

	const (
		staleResolved = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		freshResolved = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		staleBlocking = "0xcccccccccccccccccccccccccccccccccccccccc"
	)

	c.mu.Lock()
	c.operators[staleResolved] = &operatorRecord{
		OperatorAddress: staleResolved,
		Status:          FleetResolvedCurrent,
		ResolvedAt:      now.Add(-(ResolvedRetention + time.Hour)),
	}
	c.instances["i-stale"] = &instanceRecord{
		InstanceID: "i-stale", OperatorAddress: staleResolved,
	}
	c.operators[freshResolved] = &operatorRecord{
		OperatorAddress: freshResolved,
		Status:          FleetResolvedCurrent,
		ResolvedAt:      now,
	}
	// A blocking record with an ancient timestamp must never be purged: unresolved
	// history is retained indefinitely.
	c.operators[staleBlocking] = &operatorRecord{
		OperatorAddress: staleBlocking,
		Status:          FleetOfflineUnknown,
		ResolvedAt:      now.Add(-(ResolvedRetention * 3)),
	}

	c.purgeResolved(now)

	if _, ok := c.operators[staleResolved]; ok {
		t.Error("a resolved record older than the retention window must be purged")
	}
	if _, ok := c.instances["i-stale"]; ok {
		t.Error("a purged operator's instance records must be dropped too")
	}
	if _, ok := c.operators[freshResolved]; !ok {
		t.Error("a freshly resolved record must be retained")
	}
	if _, ok := c.operators[staleBlocking]; !ok {
		t.Error("a blocking record must be retained indefinitely, never purged")
	}
	c.mu.Unlock()
}
