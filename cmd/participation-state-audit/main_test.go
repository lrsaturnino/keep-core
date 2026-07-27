package main

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// newPlaceholderEvidence writes one placeholder text file per external
// rollback input and returns the populated inputs. Placeholder bytes satisfy
// no evidence schema and must stay blocking.
func newPlaceholderEvidence(t *testing.T) evidenceInputs {
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

// newValidEvidence writes one schema-valid evidence record per external
// rollback input, bound to the given already-audited manifest: every
// persisted wallet and group the manifest interprets is reconciled as
// registered and settled, and the prior reader covers every required schema.
func newValidEvidence(t *testing.T, auditManifest *manifest) evidenceInputs {
	t.Helper()

	evidenceDir := t.TempDir()
	write := func(name string, record interface{}) string {
		path := filepath.Join(evidenceDir, name)
		content, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	envelope := func(evidenceType string) evidenceEnvelope {
		return evidenceEnvelope{
			SchemaVersion:           evidenceSchemaVersion,
			EvidenceType:            evidenceType,
			GeneratedAt:             time.Now().UTC(),
			SnapshotAggregateSHA256: auditManifest.Snapshot.AggregateSHA256,
		}
	}

	chainRecord := &chainReconciliationEvidence{
		evidenceEnvelope: envelope("chain_reconciliation"),
		EthereumChainID:  "1",
	}
	for _, wallet := range auditManifest.TBTCActiveWallets {
		chainRecord.Wallets = append(chainRecord.Wallets, struct {
			WalletStorageKey string `json:"wallet_storage_key"`
			WalletID         string `json:"wallet_id"`
			Registered       bool   `json:"registered"`
			DKGSettlement    string `json:"dkg_settlement"`
		}{
			WalletStorageKey: wallet.WalletStorageKey,
			WalletID:         "0x" + strings.Repeat("11", 32),
			Registered:       true,
			DKGSettlement:    "approved",
		})
	}
	for _, membership := range auditManifest.BeaconActiveMemberships {
		chainRecord.BeaconGroups = append(chainRecord.BeaconGroups, struct {
			GroupPublicKey string `json:"group_public_key"`
			Registered     bool   `json:"registered"`
		}{
			GroupPublicKey: membership.GroupPublicKey,
			Registered:     true,
		})
	}

	bitcoinRecord := &bitcoinReconciliationEvidence{
		evidenceEnvelope: envelope("bitcoin_reconciliation"),
		BitcoinNetwork:   "mainnet",
		Complete:         true,
	}

	quiescenceRecord := &quiescenceReportEvidence{
		evidenceEnvelope: envelope("quiescence_report"),
		QuiesceCause:     "rollback drill",
	}

	priorReaderRecord := &priorReaderCompatibilityEvidence{
		evidenceEnvelope: envelope("prior_reader_compatibility"),
		PriorVersion:     "v2.0.0",
		PriorRevision:    strings.Repeat("ab", 20),
	}
	for _, schema := range requiredPriorReaderSchemas {
		priorReaderRecord.SchemaResults = append(
			priorReaderRecord.SchemaResults,
			struct {
				Schema     string `json:"schema"`
				Compatible bool   `json:"compatible"`
			}{Schema: schema, Compatible: true},
		)
	}

	return evidenceInputs{
		chainReconciliation:   write("chain-reconciliation", chainRecord),
		bitcoinReconciliation: write("bitcoin-reconciliation", bitcoinRecord),
		quiescenceReport:      write("quiescence-report", quiescenceRecord),
		priorReaderCompatibility: write(
			"prior-reader-compatibility",
			priorReaderRecord,
		),
	}
}

func hasBlocker(auditManifest *manifest, fragment string) bool {
	for _, blocker := range auditManifest.RollbackBlockers {
		if strings.Contains(blocker, fragment) {
			return true
		}
	}
	return false
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

func TestRunAudit_ValidEvidenceSatisfiesBarrier(t *testing.T) {
	storageDir := newTestStorage(t)

	// The two-phase workflow: the first audit produces the snapshot identity
	// and interpreted inventory the external evidence must bind to and cover;
	// the second audit validates the produced evidence.
	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, firstPass),
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
			"expected the barrier to be ready with valid evidence supplied, "+
				"blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
	for _, record := range auditManifest.ExternalEvidence {
		if !record.Supplied || !record.Valid || record.SHA256 == "" {
			t.Errorf(
				"expected evidence [%s] to be recorded as supplied and valid "+
					"with its checksum",
				record.Name,
			)
		}
	}
}

func TestRunAudit_PlaceholderEvidenceIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newPlaceholderEvidence(t),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("placeholder evidence must never authorize the barrier")
	}
	for _, record := range auditManifest.ExternalEvidence {
		if !record.Supplied {
			t.Errorf("expected evidence [%s] to be recorded as supplied", record.Name)
		}
		if record.Valid {
			t.Errorf("expected placeholder evidence [%s] to be invalid", record.Name)
		}
	}
	if !hasBlocker(auditManifest, "cannot be decoded") {
		t.Errorf(
			"expected undecodable-evidence blockers, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_EvidenceBoundToDifferentSnapshotIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	// Rebind the otherwise valid evidence to a different snapshot identity.
	foreign := *firstPass
	foreign.Snapshot.AggregateSHA256 = strings.Repeat("00", 32)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, &foreign),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("evidence bound to another snapshot must not authorize the barrier")
	}
	if !hasBlocker(auditManifest, "not to this audited snapshot") {
		t.Errorf(
			"expected a snapshot-binding blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_UncoveredPersistedGroupIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	// Drop the persisted beacon group from the reconciliation coverage.
	uncovered := *firstPass
	uncovered.BeaconActiveMemberships = nil

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, &uncovered),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("an unreconciled persisted group must not authorize the barrier")
	}
	if !hasBlocker(auditManifest, "is not reconciled") {
		t.Errorf(
			"expected a coverage blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_IncompatiblePriorReaderIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)

	// Rewrite the prior-reader record with one incompatible required schema.
	record := &priorReaderCompatibilityEvidence{
		evidenceEnvelope: evidenceEnvelope{
			SchemaVersion:           evidenceSchemaVersion,
			EvidenceType:            "prior_reader_compatibility",
			GeneratedAt:             time.Now().UTC(),
			SnapshotAggregateSHA256: firstPass.Snapshot.AggregateSHA256,
		},
		PriorVersion:  "v2.0.0",
		PriorRevision: strings.Repeat("ab", 20),
	}
	for i, schema := range requiredPriorReaderSchemas {
		record.SchemaResults = append(record.SchemaResults, struct {
			Schema     string `json:"schema"`
			Compatible bool   `json:"compatible"`
		}{Schema: schema, Compatible: i != 0})
	}
	content, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.priorReaderCompatibility,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidence)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("an unreadable prior-reader schema must not authorize the barrier")
	}
	if !hasBlocker(auditManifest, "cannot read schema") {
		t.Errorf(
			"expected a prior-reader blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_QuarantinedClaimWithoutQuarantineStateIsBlocking(
	t *testing.T,
) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{})
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)

	// Claim a quarantined tBTC DKG output; the snapshot's tbtc quarantine
	// namespace holds none.
	record := &quiescenceReportEvidence{
		evidenceEnvelope: evidenceEnvelope{
			SchemaVersion:           evidenceSchemaVersion,
			EvidenceType:            "quiescence_report",
			GeneratedAt:             time.Now().UTC(),
			SnapshotAggregateSHA256: firstPass.Snapshot.AggregateSHA256,
		},
		QuiesceCause: "rollback drill",
	}
	record.ActivePermitsAtQuiescence = append(
		record.ActivePermitsAtQuiescence,
		struct {
			Ceremony            string `json:"ceremony"`
			Mode                string `json:"mode"`
			CanonicalStartBlock uint64 `json:"canonical_start_block"`
			Outcome             string `json:"outcome"`
		}{
			Ceremony:            "tbtc_dkg",
			Mode:                "security_v2",
			CanonicalStartBlock: 1_000,
			Outcome:             "quarantined",
		},
	)
	content, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.quiescenceReport,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidence)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error(
			"an unevidenced quarantined-output claim must not authorize " +
				"the barrier",
		)
	}
	if !hasBlocker(
		auditManifest,
		"the tbtc quarantine namespace holds none",
	) {
		t.Errorf(
			"expected a quarantine cross-check blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_TBTCQuarantineMetadataWithoutMembershipIsAFinding(
	t *testing.T,
) {
	storageDir := newTestStorage(t)

	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		testPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"tbtc-quarantine",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := quarantineHandle.Save(
		[]byte(`{`+
			`"schema_version":1,`+
			`"release_epoch":"security_v2_cutover",`+
			`"protocol_mode":"security_v2",`+
			`"cutover_block":100,`+
			`"canonical_start_block":900,`+
			`"ceremony":"tbtc_dkg",`+
			`"seed_hash":"aa",`+
			`"member_index":3,`+
			`"wallet_id":"bb",`+
			`"wallet_public_key_hash":"cc",`+
			`"failed_operation":"tbtc_dkg_signer_activation",`+
			`"last_observed_block":950,`+
			`"preserved_at":"2026-01-01T00:00:00Z"}`),
		"orphaned-wallet-directory",
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
	if !hasFinding(
		auditManifest,
		"tbtc quarantine output [orphaned-wallet-directory/3] has audit "+
			"metadata without a membership record",
	) {
		t.Errorf(
			"expected an orphaned-metadata finding, findings: %v",
			auditManifest.Findings,
		)
	}

	if got := len(auditManifest.TBTCQuarantinedOutputs); got != 1 {
		t.Fatalf("expected [1] tbtc quarantined output, got [%d]", got)
	}
	if auditManifest.TBTCQuarantinedOutputs[0].HasMembershipRecord {
		t.Error("expected the output to report its missing membership record")
	}
}

func TestRunAudit_UndecodableTBTCQuarantineMembershipIsAFinding(
	t *testing.T,
) {
	storageDir := newTestStorage(t)

	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		testPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"tbtc-quarantine",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := quarantineHandle.Save(
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
	if !hasFinding(
		auditManifest,
		"tbtc quarantine membership [some-wallet-directory/membership_1] "+
			"cannot be decoded",
	) {
		t.Errorf(
			"expected a quarantine decode finding, findings: %v",
			auditManifest.Findings,
		)
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
