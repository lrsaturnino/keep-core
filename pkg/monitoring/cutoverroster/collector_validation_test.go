package cutoverroster

import (
	"context"
	"testing"
	"time"
)

// TestCollector_NonCanonicalOperatorAddressRejected proves an eligible inventory
// entry whose operator address is not a canonical 0x + 40 hex address is rejected
// as an inventory-reconciliation fault: it is not counted as reconciled eligible
// and forces readiness closed.
func TestCollector_NonCanonicalOperatorAddressRejected(t *testing.T) {
	tc := newTestCollector(t)

	for _, bad := range []string{
		"op1",      // symbolic, not an address
		"0x1234",   // too short
		"deadbeef", // missing 0x
		"0xZZZZef0000000000000000000000000000000001", // non-hex
	} {
		inv := eligibleInstance("i1", "unused")
		inv.OperatorAddress = bad
		snap, err := tc.collector.Collect([]InventoryInstance{inv}, nil, nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if snap.Inventory.EligibleInstances != 0 {
			t.Errorf("address %q must not count as reconciled eligible", bad)
		}
		if snap.Inventory.Unreconciled == 0 {
			t.Errorf("address %q must count as unreconciled", bad)
		}
		if snap.Complete {
			t.Errorf("a non-canonical operator address must not yield completeness (%q)", bad)
		}
	}
}

// TestCollector_BlankRequiredInventoryFieldsRejected proves a blank required
// inventory field (staking provider, expected revision/epoch/digest) is an
// inventory-reconciliation fault: the entry cannot prove what "current" is for the
// instance, so readiness fails closed.
func TestCollector_BlankRequiredInventoryFieldsRejected(t *testing.T) {
	tc := newTestCollector(t)

	for _, mut := range []struct {
		name   string
		mutate func(*InventoryInstance)
	}{
		{"blank staking provider", func(i *InventoryInstance) { i.StakingProvider = "" }},
		{"blank expected revision", func(i *InventoryInstance) { i.ExpectedRevision = "" }},
		{"blank expected epoch", func(i *InventoryInstance) { i.ExpectedEpoch = "" }},
		{"blank expected digest", func(i *InventoryInstance) { i.ExpectedImageDigest = "" }},
	} {
		t.Run(mut.name, func(t *testing.T) {
			inv := eligibleInstance("i1", "op1")
			mut.mutate(&inv)
			snap, err := tc.collector.Collect([]InventoryInstance{inv}, nil, nil, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Inventory.EligibleInstances != 0 {
				t.Errorf("%s must not count as reconciled eligible", mut.name)
			}
			if snap.Inventory.Unreconciled == 0 {
				t.Errorf("%s must count as unreconciled", mut.name)
			}
		})
	}
}

// TestCollector_ZeroAndFutureSightingTimestampRejected proves a post-cutover
// sighting whose observation timestamp is zero or in the future is rejected
// outright — it does not create observed_legacy evidence — rather than being
// admitted while leaving LastLegacyAt unset (which would weaken the post-sighting
// resolution proof).
func TestCollector_ZeroAndFutureSightingTimestampRejected(t *testing.T) {
	for _, tt := range []struct {
		name       string
		observedAt time.Time
	}{
		{"zero timestamp", time.Time{}},
		{"future timestamp", fleetBaseTime.Add(time.Hour)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestCollector(t)
			inv := []InventoryInstance{eligibleInstance("i1", "op1")}

			// A valid post-cutover block (>= cutover 1000, <= current 1100) but an
			// invalid timestamp.
			sightings := []LegacySighting{
				{OperatorAddress: opAddr("op1"), Block: 1050, ObservedAt: tt.observedAt},
			}
			snap, err := tc.collector.Collect(inv, nil, sightings, 1100)
			if err != nil {
				t.Fatal(err)
			}
			if status, _ := operatorStatus(snap, "op1"); status == FleetObservedLegacy {
				t.Errorf("%s sighting must not create observed_legacy", tt.name)
			}
			if tc.sink.gauge(MetricFleetObservedLegacy) != 0 {
				t.Errorf("%s sighting must not increment the observed-legacy gauge", tt.name)
			}
		})
	}
}

// fakeIdentityVerifier maps operator addresses to their (test-asserted) on-chain
// staking provider. A missing operator returns an error.
type fakeIdentityVerifier struct {
	providers map[string]string
}

func (f *fakeIdentityVerifier) OperatorStakingProviderAtBlock(
	_ context.Context, operatorAddress string, _ uint64,
) (string, error) {
	if p, ok := f.providers[normalizeAddress(operatorAddress)]; ok {
		return p, nil
	}
	return "", errNoIdentity
}

var errNoIdentity = &identityError{}

type identityError struct{}

func (*identityError) Error() string { return "no on-chain identity for operator" }

// TestCollector_IdentityVerificationGatesResolution proves that with an on-chain
// identity verifier configured, an operator whose inventory staking-provider claim
// matches the WalletRegistry mapping can resolve, while a mismatch (or a lookup
// failure) blocks resolution and raises the unreconciled signal (fail closed).
func TestCollector_IdentityVerificationGatesResolution(t *testing.T) {
	provider := "0x1111111111111111111111111111111111111111"
	otherProvider := "0x2222222222222222222222222222222222222222"

	newInv := func(claim string) []InventoryInstance {
		inv := eligibleInstance("i1", "op1")
		inv.StakingProvider = claim
		return []InventoryInstance{inv}
	}

	t.Run("matching identity resolves", func(t *testing.T) {
		tc := newTestCollector(t)
		tc.collector.SetIdentityVerifier(&fakeIdentityVerifier{
			providers: map[string]string{opAddr("op1"): provider},
		})
		inv := newInv(provider)
		var snap FleetSnapshot
		for cycle := 0; cycle < 3; cycle++ {
			r := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
			var err error
			snap, err = tc.collector.Collect(inv, r, nil, 1000)
			if err != nil {
				t.Fatal(err)
			}
			tc.now = tc.now.Add(time.Minute)
		}
		if status, _ := operatorStatus(snap, "op1"); status != FleetResolvedCurrent {
			t.Fatalf("matching on-chain identity must allow resolution, got %s", status)
		}
	})

	t.Run("mismatching identity blocks resolution", func(t *testing.T) {
		tc := newTestCollector(t)
		tc.collector.SetIdentityVerifier(&fakeIdentityVerifier{
			providers: map[string]string{opAddr("op1"): otherProvider},
		})
		inv := newInv(provider) // inventory claims `provider`, chain says `otherProvider`
		var snap FleetSnapshot
		for cycle := 0; cycle < 3; cycle++ {
			r := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
			var err error
			snap, err = tc.collector.Collect(inv, r, nil, 1000)
			if err != nil {
				t.Fatal(err)
			}
			tc.now = tc.now.Add(time.Minute)
		}
		if status, _ := operatorStatus(snap, "op1"); status == FleetResolvedCurrent {
			t.Fatalf("an on-chain identity mismatch must block resolution, got %s", status)
		}
		if tc.sink.gauge(MetricInventoryUnreconciled) == 0 {
			t.Errorf("an identity mismatch must raise the unreconciled gauge")
		}
	})
}

// TestCollector_DisappearedFromDiscoveryOffline proves that an eligible instance
// flagged as absent from the production service-discovery target set is
// offline_unknown for the cycle even if it produced an otherwise-exact report:
// disappearance from discovery is never ready.
func TestCollector_DisappearedFromDiscoveryOffline(t *testing.T) {
	tc := newTestCollector(t)

	inv := eligibleInstance("i1", "op1")
	inv.DisappearedFromDiscovery = true

	// The instance still supplies an exact report, but it has vanished from
	// discovery, so it must be treated as offline.
	reports := map[string]InstanceReport{"i1": exactReport("i1", "op1", tc.now)}
	var snap FleetSnapshot
	for cycle := 0; cycle < 3; cycle++ {
		var err error
		snap, err = tc.collector.Collect([]InventoryInstance{inv}, reports, nil, 1100)
		if err != nil {
			t.Fatal(err)
		}
		tc.now = tc.now.Add(time.Minute)
	}
	if status, _ := operatorStatus(snap, "op1"); status != FleetOfflineUnknown {
		t.Fatalf("an instance absent from service discovery must be offline_unknown, got %s", status)
	}
	if snap.Complete {
		t.Error("readiness must not be complete while an instance has disappeared from discovery")
	}
}
