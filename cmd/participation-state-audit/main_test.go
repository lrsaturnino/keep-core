package main

import (
	"math/big"
	"strings"
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/storage"
)

const testPassword = "audit-test-password"

func newTestSigner(t *testing.T, memberIndex group.MemberIndex) *dkg.ThresholdSigner {
	t.Helper()

	groupPublicKey := new(bn256.G2).ScalarBaseMult(big.NewInt(42))

	return dkg.NewThresholdSigner(
		memberIndex,
		groupPublicKey,
		big.NewInt(7),
		map[group.MemberIndex]*bn256.G2{
			memberIndex: new(bn256.G2).ScalarBaseMult(big.NewInt(7)),
		},
		[]chain.Address{"0x0000000000000000000000000000000000000001"},
	)
}

// newTestStorage builds a storage snapshot with one active beacon membership
// and one quarantined output, written through the production persistence
// paths, and returns its root directory.
func newTestStorage(t *testing.T) string {
	t.Helper()

	storageDir := t.TempDir()

	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		testPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	activeHandle, err := diskStorage.InitializeKeyStorePersistence("beacon")
	if err != nil {
		t.Fatal(err)
	}
	activeSigner := newTestSigner(t, group.MemberIndex(1))
	activeMembership := &registry.Membership{
		Signer:      activeSigner,
		ChannelName: "test-channel",
	}
	activeBytes, err := activeMembership.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := activeHandle.Save(
		activeBytes,
		"active-group-directory",
		"/membership_1",
	); err != nil {
		t.Fatal(err)
	}

	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"beacon-quarantine",
	)
	if err != nil {
		t.Fatal(err)
	}
	quarantine := registry.NewQuarantine(
		&testutils.MockLogger{},
		quarantineHandle,
	)
	if err := quarantine.Preserve(
		&registry.Membership{
			Signer:      newTestSigner(t, group.MemberIndex(2)),
			ChannelName: "test-channel",
		},
		registry.QuarantinedSignerMetadata{
			ReleaseEpoch:        "security_v2_cutover",
			ProtocolMode:        "legacy",
			CutoverBlock:        1_000,
			CanonicalStartBlock: 900,
			Ceremony:            "beacon_dkg",
			FailedOperation:     "beacon_dkg_result_publication",
			LastObservedBlock:   950,
		},
	); err != nil {
		t.Fatal(err)
	}

	return storageDir
}

func TestRunAudit_ConsistentSnapshot(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(storageDir, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	if !auditManifest.Interpreted {
		t.Error("expected the manifest to be interpreted")
	}
	if !auditManifest.Consistent {
		t.Errorf(
			"expected a consistent manifest, findings: %v",
			auditManifest.Findings,
		)
	}

	if got := len(auditManifest.BeaconActiveMemberships); got != 1 {
		t.Fatalf("expected [1] active membership, got [%d]", got)
	}
	active := auditManifest.BeaconActiveMemberships[0]
	if active.MemberIndex != 1 {
		t.Errorf("expected active member index [1], got [%d]", active.MemberIndex)
	}
	if active.ChannelName != "test-channel" {
		t.Errorf("unexpected channel name [%s]", active.ChannelName)
	}

	if got := len(auditManifest.BeaconQuarantinedOutputs); got != 1 {
		t.Fatalf("expected [1] quarantined output, got [%d]", got)
	}
	quarantined := auditManifest.BeaconQuarantinedOutputs[0]
	if !quarantined.HasMembershipRecord {
		t.Error("expected the quarantined output to have its membership record")
	}
	if quarantined.MemberIndex != 2 {
		t.Errorf(
			"expected quarantined member index [2], got [%d]",
			quarantined.MemberIndex,
		)
	}
	if quarantined.ProtocolMode != "legacy" {
		t.Errorf(
			"expected the quarantined mode [legacy], got [%s]",
			quarantined.ProtocolMode,
		)
	}
	if quarantined.CanonicalStartBlock != 900 {
		t.Errorf(
			"expected the canonical start block [900], got [%d]",
			quarantined.CanonicalStartBlock,
		)
	}

	// The active membership must never surface from the quarantine namespace
	// and vice versa: the two interpreted sets are namespace-disjoint.
	for _, namespace := range auditManifest.Namespaces {
		if namespace.Name == "keystore/beacon-quarantine" && !namespace.Present {
			t.Error("expected the quarantine namespace to be present")
		}
		for _, file := range namespace.Files {
			if namespace.Name == "keystore/beacon" &&
				strings.Contains(file.Path, "beacon-quarantine") {
				t.Errorf(
					"quarantine file inventoried under the active "+
						"namespace: [%s]",
					file.Path,
				)
			}
		}
	}
}

func TestRunAudit_MetadataWithoutMembershipIsAFinding(t *testing.T) {
	storageDir := newTestStorage(t)

	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		testPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"beacon-quarantine",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := quarantineHandle.Save(
		[]byte(`{"schema_version":1,"member_index":3}`),
		"orphaned-group-directory",
		"/metadata_3",
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	found := false
	for _, finding := range auditManifest.Findings {
		if strings.Contains(finding, "audit metadata without a membership") {
			found = true
		}
	}
	if !found {
		t.Errorf(
			"expected an orphaned-metadata finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestRunAudit_WithoutPasswordInventoriesOnly(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(storageDir, "")
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Interpreted {
		t.Error("expected an uninterpreted manifest without the password")
	}
	if auditManifest.Consistent {
		t.Error("an uninterpreted manifest must not classify as consistent")
	}
	if len(auditManifest.BeaconActiveMemberships) != 0 {
		t.Error("expected no interpreted memberships without the password")
	}

	var beaconFiles, quarantineFiles int
	for _, namespace := range auditManifest.Namespaces {
		switch namespace.Name {
		case "keystore/beacon":
			beaconFiles = len(namespace.Files)
		case "keystore/beacon-quarantine":
			quarantineFiles = len(namespace.Files)
		}
	}
	if beaconFiles == 0 {
		t.Error("expected the active namespace inventory to list files")
	}
	if quarantineFiles == 0 {
		t.Error("expected the quarantine namespace inventory to list files")
	}
}
