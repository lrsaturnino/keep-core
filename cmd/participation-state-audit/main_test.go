package main

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
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

func newTestSigner(
	t *testing.T,
	memberIndex group.MemberIndex,
	groupSecret int64,
) *dkg.ThresholdSigner {
	t.Helper()

	groupPublicKey := new(bn256.G2).ScalarBaseMult(big.NewInt(groupSecret))

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

func groupPublicKeyHex(membership *registry.Membership) string {
	return hex.EncodeToString(
		membership.Signer.GroupPublicKeyBytesCompressed(),
	)
}

// newTestStorage builds a storage snapshot with one active beacon membership
// and one quarantined output of a different group, written through the
// production persistence paths and layout, and returns its root directory.
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
	activeMembership := &registry.Membership{
		Signer:      newTestSigner(t, group.MemberIndex(1), 42),
		ChannelName: "test-channel",
	}
	activeBytes, err := activeMembership.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := activeHandle.Save(
		activeBytes,
		groupPublicKeyHex(activeMembership),
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
			Signer:      newTestSigner(t, group.MemberIndex(2), 43),
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

// newTestEvidence writes one placeholder evidence file per external rollback
// input and returns the populated inputs.
func newTestEvidence(t *testing.T) evidenceInputs {
	t.Helper()

	evidenceDir := t.TempDir()
	write := func(name string) string {
		path := filepath.Join(evidenceDir, name)
		if err := os.WriteFile(path, []byte(name+" evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	return evidenceInputs{
		chainReconciliation:      write("chain-reconciliation"),
		bitcoinReconciliation:    write("bitcoin-reconciliation"),
		quiescenceReport:         write("quiescence-report"),
		priorReaderCompatibility: write("prior-reader-compatibility"),
	}
}

func hasFinding(auditManifest *manifest, fragment string) bool {
	for _, finding := range auditManifest.Findings {
		if strings.Contains(finding, fragment) {
			return true
		}
	}
	return false
}

func TestRunAudit_ConsistentSnapshot(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
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

	if auditManifest.Snapshot.AggregateSHA256 == "" {
		t.Error("expected the snapshot aggregate checksum to be recorded")
	}
	if auditManifest.Snapshot.TotalFiles == 0 {
		t.Error("expected the snapshot to count its inventoried files")
	}

	// A consistent snapshot alone must never read as rollback-ready: every
	// external evidence input is missing and each missing one is a blocker.
	if auditManifest.RollbackBarrierReady {
		t.Error("a consistent snapshot without evidence must not be barrier-ready")
	}
	if got := len(auditManifest.RollbackBlockers); got != 4 {
		t.Errorf(
			"expected [4] rollback blockers without evidence, got [%d]: %v",
			got,
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_SuppliedEvidenceSatisfiesBarrier(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newTestEvidence(t),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !auditManifest.Consistent {
		t.Fatalf(
			"expected a consistent manifest, findings: %v",
			auditManifest.Findings,
		)
	}
	if !auditManifest.RollbackBarrierReady {
		t.Errorf(
			"expected the barrier to be ready with all evidence supplied, "+
				"blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
	for _, record := range auditManifest.ExternalEvidence {
		if !record.Supplied || record.SHA256 == "" {
			t.Errorf(
				"expected evidence [%s] to be recorded with its checksum",
				record.Name,
			)
		}
	}
}

func TestRunAudit_UnreadableEvidenceIsAnError(t *testing.T) {
	storageDir := newTestStorage(t)

	_, err := runAudit(storageDir, testPassword, evidenceInputs{
		chainReconciliation: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err == nil {
		t.Error("expected an error for an unreadable evidence reference")
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	if !hasFinding(auditManifest, "audit metadata without a membership") {
		t.Errorf(
			"expected an orphaned-metadata finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestRunAudit_QuarantineMetadataCrossChecks(t *testing.T) {
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
	quarantine := registry.NewQuarantine(
		&testutils.MockLogger{},
		quarantineHandle,
	)

	// Written through the production quarantine path, so directory, group,
	// and member all pair up — but the metadata's own fields contradict the
	// release identity and the cutover arithmetic.
	if err := quarantine.Preserve(
		&registry.Membership{
			Signer:      newTestSigner(t, group.MemberIndex(4), 44),
			ChannelName: "test-channel",
		},
		registry.QuarantinedSignerMetadata{
			ReleaseEpoch:        "some_other_epoch",
			ProtocolMode:        "security_v2",
			CutoverBlock:        1_000,
			CanonicalStartBlock: 900,
			Ceremony:            "not_a_ceremony",
			FailedOperation:     "beacon_dkg_result_publication",
			LastObservedBlock:   950,
		},
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	for _, fragment := range []string{
		"was written by release epoch [some_other_epoch]",
		"names ceremony [not_a_ceremony]",
		"claims mode [security_v2] with canonical anchor [900] before " +
			"cutover block [1000]",
	} {
		if !hasFinding(auditManifest, fragment) {
			t.Errorf(
				"expected a finding containing [%s], findings: %v",
				fragment,
				auditManifest.Findings,
			)
		}
	}
}

func TestRunAudit_QuarantinedGroupAlsoActiveIsAFinding(t *testing.T) {
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
	quarantine := registry.NewQuarantine(
		&testutils.MockLogger{},
		quarantineHandle,
	)

	// Group secret 42 is the group the fixture also activates.
	if err := quarantine.Preserve(
		&registry.Membership{
			Signer:      newTestSigner(t, group.MemberIndex(5), 42),
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	if !hasFinding(auditManifest, "also present in the active namespace") {
		t.Errorf(
			"expected an active-overlap finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestRunAudit_MisplacedActiveMembershipIsAFinding(t *testing.T) {
	storageDir := newTestStorage(t)

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

	misplaced := &registry.Membership{
		Signer:      newTestSigner(t, group.MemberIndex(6), 45),
		ChannelName: "test-channel",
	}
	misplacedBytes, err := misplaced.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := activeHandle.Save(
		misplacedBytes,
		"not-the-group-directory",
		"/membership_7",
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	if !hasFinding(auditManifest, "not the group its directory claims") {
		t.Errorf(
			"expected a directory-mismatch finding, findings: %v",
			auditManifest.Findings,
		)
	}
	if !hasFinding(auditManifest, "not the member its file name claims") {
		t.Errorf(
			"expected a member-name finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestRunAudit_UndecodableTBTCRecordIsAFinding(t *testing.T) {
	storageDir := newTestStorage(t)

	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		testPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	tbtcHandle, err := diskStorage.InitializeKeyStorePersistence("tbtc")
	if err != nil {
		t.Fatal(err)
	}
	if err := tbtcHandle.Save(
		[]byte("not a signer record"),
		"some-wallet-directory",
		"/membership_1",
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	if !hasFinding(auditManifest, "wallet registry loader") {
		t.Errorf(
			"expected a tbtc decode finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestRunAudit_UnexpectedNamespaceIsAFinding(t *testing.T) {
	storageDir := newTestStorage(t)

	if err := os.MkdirAll(
		filepath.Join(storageDir, "keystore", "rogue-namespace"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Consistent {
		t.Error("expected an inconsistent manifest")
	}
	if !hasFinding(auditManifest, "unexpected entry [rogue-namespace]") {
		t.Errorf(
			"expected an unexpected-entry finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestRunAudit_WithoutPasswordInventoriesOnly(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(storageDir, "", evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.Interpreted {
		t.Error("expected an uninterpreted manifest without the password")
	}
	if auditManifest.Consistent {
		t.Error("an uninterpreted manifest must not classify as consistent")
	}
	if auditManifest.RollbackBarrierReady {
		t.Error("an uninterpreted manifest must not be barrier-ready")
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
