package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/chain"
	ecdsaabi "github.com/keep-network/keep-core/pkg/chain/ethereum/ecdsa/gen/abi"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/storage"
)

const testPassword = "audit-test-password"

const (
	testWalletRegistryAddress       = "0x1111111111111111111111111111111111111111"
	testFinalizedEthereumBlock      = uint64(10_000)
	testChainEvidencePrivateKeyByte = byte(0x42)
)

func testCanonicalEthereumBlockHash(block uint64) string {
	return fmt.Sprintf("0x%064x", block+1)
}

func testChainEvidencePrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = testChainEvidencePrivateKeyByte
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testChainEvidencePublicKey() string {
	publicKey := testChainEvidencePrivateKey().Public().(ed25519.PublicKey)
	return hex.EncodeToString(publicKey)
}

type auditGateBlockCounter struct {
	block uint64
}

func (c *auditGateBlockCounter) CurrentBlock() (uint64, error) {
	return c.block, nil
}

func (c *auditGateBlockCounter) WaitForBlockHeight(uint64) error {
	return nil
}

func (c *auditGateBlockCounter) BlockHeightWaiter(
	uint64,
) (<-chan uint64, error) {
	result := make(chan uint64, 1)
	result <- c.block
	close(result)
	return result, nil
}

func (c *auditGateBlockCounter) WatchBlocks(
	ctx context.Context,
) <-chan uint64 {
	result := make(chan uint64)
	go func() {
		<-ctx.Done()
		close(result)
	}()
	return result
}

type auditGateMetrics struct{}

func (auditGateMetrics) IncrementCounter(string, float64) {}
func (auditGateMetrics) SetGauge(string, float64)         {}

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
	return newTestStorageWithQuiescencePermits(t, nil)
}

func newTestStorageWithQuiescencePermits(
	t *testing.T,
	permits []quiescencePermitEvidence,
) string {
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
			SeedHash:            strings.Repeat("a", 64),
			FailedOperation:     "beacon_dkg_result_publication",
			LastObservedBlock:   950,
		},
	); err != nil {
		t.Fatal(err)
	}

	participationHandle, err :=
		diskStorage.InitializeWorkPersistence("participation")
	if err != nil {
		t.Fatal(err)
	}
	recorder, err :=
		participation.NewPersistenceQuiescenceSnapshotRecorder(
			participationHandle,
		)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := participation.QuiescenceSnapshot{
		SchemaVersion:    participation.QuiescenceSnapshotSchemaVersion,
		CapturedAt:       time.Now().UTC().Add(-time.Minute),
		ReleaseVersion:   "v2.1.0",
		ReleaseRevision:  strings.Repeat("ef", 20),
		ReleaseEpoch:     participation.CompiledEpoch.String(),
		CutoverBlock:     1_000,
		CurrentBlock:     1_100,
		ClockAvailable:   true,
		State:            participation.StateQuiescing.String(),
		QuiesceCause:     "rollback drill",
		ActiveCeremonies: uint64(len(permits)),
	}
	for _, permit := range permits {
		snapshot.ActivePermits = append(
			snapshot.ActivePermits,
			participation.PermitSnapshot{
				Ceremony:            participation.Ceremony(permit.Ceremony),
				Mode:                permit.Mode,
				CanonicalStartBlock: permit.CanonicalStartBlock,
				WorkID:              permit.WorkID,
				PermitID:            permit.PermitID,
				IdentityBound:       true,
			},
		)
		switch permit.Mode {
		case participation.ModeLegacy.String():
			snapshot.ActiveLegacyCeremonies++
		case participation.ModeSecurityV2.String():
			snapshot.ActiveSecurityV2Ceremonies++
		}
	}
	sort.Slice(snapshot.ActivePermits, func(i, j int) bool {
		return permitSnapshotLess(
			snapshot.ActivePermits[i],
			snapshot.ActivePermits[j],
		)
	})
	if err := recorder.Record(snapshot); err != nil {
		t.Fatal(err)
	}
	for i, permit := range permits {
		record := testTerminalOutcomeRecord(
			permit,
			participation.PermitSnapshot{
				Ceremony:            participation.Ceremony(permit.Ceremony),
				Mode:                permit.Mode,
				CanonicalStartBlock: permit.CanonicalStartBlock,
				WorkID:              permit.WorkID,
				PermitID:            permit.PermitID,
				IdentityBound:       true,
			},
			fmt.Sprintf("test-result-%d", i),
			groupPublicKeyHex(activeMembership),
		)
		if err := recorder.RecordTerminalOutcome(record); err != nil {
			t.Fatal(err)
		}
	}

	return storageDir
}

func testTerminalOutcomeRecord(
	permit quiescencePermitEvidence,
	snapshot participation.PermitSnapshot,
	resultReference string,
	beaconSignerReference string,
) participation.TerminalOutcomeRecord {
	evidence := participation.TerminalEvidence{
		Kind:      participation.TerminalEvidenceProtocolResult,
		Reference: resultReference,
	}
	switch participation.TerminalOutcome(permit.Outcome) {
	case participation.TerminalOutcomeCompleted:
		// Each ceremony settles on the evidence class its result actually
		// lives in, mirroring what the node records in production. A fixture
		// that settled everything on a node-authored protocol digest would
		// exercise a shape the gate's own validator rejects.
		switch snapshot.Ceremony {
		case participation.TBTCDKG:
			evidence = participation.TerminalEvidence{
				Kind:            participation.TerminalEvidencePersistedTBTCSinger,
				Reference:       "test-tbtc-signer",
				MembershipIndex: group.MemberIndex(1),
			}
		case participation.BeaconDKG:
			evidence = participation.TerminalEvidence{
				Kind:            participation.TerminalEvidencePersistedBeaconSigner,
				Reference:       beaconSignerReference,
				MembershipIndex: group.MemberIndex(1),
			}
		case participation.TBTCSigning:
			evidence = participation.TerminalEvidence{
				Kind:      participation.TerminalEvidenceBitcoinTransaction,
				Reference: testBitcoinTransactionHash(resultReference),
			}
		case participation.TBTCInactivityClaim:
			evidence = participation.TerminalEvidence{
				Kind:      participation.TerminalEvidenceEthereumTransaction,
				Reference: resultReference,
			}
		case participation.BeaconRelayForwarding:
			evidence = participation.TerminalEvidence{
				Kind: participation.TerminalEvidenceForwarderClosed,
			}
		}
	case participation.TerminalOutcomeQuarantined:
		evidence = participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceQuarantinedTBTCSinger,
		}
		if snapshot.Ceremony == participation.BeaconDKG {
			evidence.Kind =
				participation.TerminalEvidenceQuarantinedBeaconSigner
		}
	case participation.TerminalOutcomeExhausted:
		evidence = participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceNoThreshold,
		}
	}

	return participation.TerminalOutcomeRecord{
		RecordedAt: time.Now().UTC(),
		Permit:     snapshot,
		Outcome:    participation.TerminalOutcome(permit.Outcome),
		Evidence:   evidence,
	}
}

// testBitcoinTransactionHash derives a canonical, unprefixed lowercase
// transaction hash from a fixture label, so a wallet action's evidence has the
// shape the Bitcoin reconciliation set can actually enumerate.
func testBitcoinTransactionHash(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func persistRealGateQuiescenceSnapshot(
	t *testing.T,
	storageDir string,
	permits []quiescencePermitEvidence,
) {
	t.Helper()

	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		testPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := diskStorage.InitializeWorkPersistence("participation")
	if err != nil {
		t.Fatal(err)
	}
	recorder, err :=
		participation.NewPersistenceQuiescenceSnapshotRecorder(handle)
	if err != nil {
		t.Fatal(err)
	}

	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: 1_000},
		&auditGateBlockCounter{block: 1_100},
		auditGateMetrics{},
		participation.WithArtifactIdentity(
			"v2.1.0",
			strings.Repeat("ef", 20),
		),
		participation.WithQuiescenceSnapshotRecorder(recorder),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()

	active := make([]participation.Permit, 0, len(permits))
	for _, expected := range permits {
		permit, err := gate.Begin(
			participation.Ceremony(expected.Ceremony),
			expected.CanonicalStartBlock,
			participation.PermitIdentity{
				WorkID:   expected.WorkID,
				PermitID: expected.PermitID,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if permit.Mode().String() != expected.Mode {
			t.Fatalf(
				"test permit mode [%s] does not match gate-selected mode [%s]",
				expected.Mode,
				permit.Mode(),
			)
		}
		active = append(active, permit)
	}

	gate.Quiesce(fmt.Errorf("rollback drill"))
	for i, permit := range active {
		record := testTerminalOutcomeRecord(
			permits[i],
			participation.PermitSnapshot{
				Ceremony:            permit.Ceremony(),
				Mode:                permit.Mode().String(),
				CanonicalStartBlock: permit.CanonicalStartBlock(),
				WorkID:              permit.WorkID(),
				PermitID:            permit.PermitID(),
				IdentityBound:       true,
			},
			fmt.Sprintf("real-gate-result-%d", i),
			"",
		)
		if err := permit.RecordTerminalOutcome(
			record.Outcome,
			record.Evidence,
		); err != nil {
			t.Fatal(err)
		}
		permit.Close()
	}
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

// newValidTBTCDKGResultEvidence constructs a complete accepted-event lineage
// and returns its derived wallet ID and seed work identity.
func newValidTBTCDKGResultEvidence(
	t *testing.T,
	seed *big.Int,
	startBlock uint64,
	originalGroupSize uint16,
	misbehavedMemberIndexes []uint8,
) (*tbtcDKGResultEvidence, string, string) {
	t.Helper()

	misbehaved := make(map[uint8]struct{}, len(misbehavedMemberIndexes))
	for _, memberIndex := range misbehavedMemberIndexes {
		misbehaved[memberIndex] = struct{}{}
	}

	members := make([]uint32, originalGroupSize)
	signingMemberIndexes := make([]*big.Int, 0, originalGroupSize)
	for i := uint16(0); i < originalGroupSize; i++ {
		members[i] = uint32(10_000 + i)
		if _, excluded := misbehaved[uint8(i+1)]; !excluded {
			signingMemberIndexes = append(
				signingMemberIndexes,
				new(big.Int).SetUint64(uint64(i+1)),
			)
		}
	}
	if len(signingMemberIndexes) == 0 {
		t.Fatal("test DKG result needs an operating member")
	}

	seedHex := fmt.Sprintf("0x%064x", seed)
	seedTag := seed.Uint64()
	log := func(blockNumber uint64, logIndex uint64) ethereumLogEvidence {
		return ethereumLogEvidence{
			TransactionHash: fmt.Sprintf(
				"0x%064x",
				(seedTag<<16)+(blockNumber<<2)+logIndex+1,
			),
			BlockHash:   testCanonicalEthereumBlockHash(blockNumber),
			BlockNumber: blockNumber,
			LogIndex:    logIndex,
		}
	}

	chainResult := tbtcDKGChainResultEvidence{
		SubmitterMemberIndex: uint16(signingMemberIndexes[0].Uint64()),
		GroupPublicKey: "0x" +
			"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		MisbehavedMemberIndexes: append(
			[]uint8(nil),
			misbehavedMemberIndexes...,
		),
		Signatures: "0x" + strings.Repeat(
			"02",
			65*len(signingMemberIndexes),
		),
		SigningMemberIndexes: signingMemberIndexes,
		Members:              members,
	}
	membersHash, err := computeTBTCDKGMembersHash(chainResult)
	if err != nil {
		t.Fatal(err)
	}
	chainResult.MembersHash = membersHash

	resultHash, err := computeTBTCDKGResultHash(chainResult)
	if err != nil {
		t.Fatal(err)
	}
	walletID, err := computeTBTCWalletID(chainResult.GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	approvalLog := log(startBlock+2, 0)
	walletCreatedLog := approvalLog
	walletCreatedLog.LogIndex = 1

	result := &tbtcDKGResultEvidence{
		Started: tbtcDKGStartedEventEvidence{
			ethereumLogEvidence: log(startBlock, 0),
			Seed:                seedHex,
		},
		Submitted: tbtcDKGResultSubmittedEventEvidence{
			ethereumLogEvidence: log(startBlock+1, 0),
			ResultHash:          resultHash,
			Seed:                seedHex,
			Result:              chainResult,
		},
		Approved: tbtcDKGResultApprovedEventEvidence{
			ethereumLogEvidence: approvalLog,
			ResultHash:          resultHash,
		},
		WalletCreated: tbtcWalletCreatedEventEvidence{
			ethereumLogEvidence: walletCreatedLog,
			WalletID:            walletID,
			DKGResultHash:       resultHash,
		},
	}
	seedHash, err := result.seedHash()
	if err != nil {
		t.Fatal(err)
	}

	return result, strings.TrimPrefix(walletID, "0x"), seedHash
}

func resignTestChainReconciliationEvidence(
	t *testing.T,
	record *chainReconciliationEvidence,
) {
	t.Helper()

	record.CollectorAttestation.Signature = ""
	payload, err := chainReconciliationSignaturePayload(record)
	if err != nil {
		t.Fatal(err)
	}
	record.CollectorAttestation.Signature = hex.EncodeToString(
		ed25519.Sign(testChainEvidencePrivateKey(), payload),
	)
}

func authenticateTestChainReconciliationEvidence(
	t *testing.T,
	record *chainReconciliationEvidence,
) {
	t.Helper()

	record.WalletRegistryAddress = testWalletRegistryAddress
	record.Receipts = nil

	canonicalBlocks := map[uint64]string{
		testFinalizedEthereumBlock: testCanonicalEthereumBlockHash(
			testFinalizedEthereumBlock,
		),
	}
	receiptIndexes := make(map[string]int)
	transactionIndex := uint64(0)

	addEvent := func(
		name string,
		event ethereumLogEvidence,
		result *tbtcDKGResultEvidence,
	) {
		t.Helper()

		topics, data, err := expectedTBTCDKGRawLog(name, result)
		if err != nil {
			t.Fatal(err)
		}
		for i, topic := range topics {
			if topic == "" {
				topics[i] = "0x" + strings.Repeat("0", 24) +
					strings.TrimPrefix(testWalletRegistryAddress, "0x")
			}
		}
		rawLog := ethereumRawLogEvidence{
			Address:  testWalletRegistryAddress,
			Topics:   topics,
			Data:     data,
			LogIndex: event.LogIndex,
		}

		receiptIndex, ok := receiptIndexes[event.TransactionHash]
		if !ok {
			receiptIndex = len(record.Receipts)
			receiptIndexes[event.TransactionHash] = receiptIndex
			record.Receipts = append(record.Receipts, ethereumReceiptEvidence{
				TransactionHash:  event.TransactionHash,
				BlockHash:        event.BlockHash,
				BlockNumber:      event.BlockNumber,
				TransactionIndex: transactionIndex,
				Status:           1,
			})
			transactionIndex++
		}
		record.Receipts[receiptIndex].Logs = append(
			record.Receipts[receiptIndex].Logs,
			rawLog,
		)
		canonicalBlocks[event.BlockNumber] = event.BlockHash
	}

	for _, wallet := range record.Wallets {
		if wallet.DKGResult == nil {
			continue
		}
		result := wallet.DKGResult
		addEvent(
			"DkgStarted",
			result.Started.ethereumLogEvidence,
			result,
		)
		addEvent(
			"DkgResultSubmitted",
			result.Submitted.ethereumLogEvidence,
			result,
		)
		addEvent(
			"DkgResultApproved",
			result.Approved.ethereumLogEvidence,
			result,
		)
		addEvent(
			"WalletCreated",
			result.WalletCreated.ethereumLogEvidence,
			result,
		)
	}

	blockNumbers := make([]uint64, 0, len(canonicalBlocks))
	for blockNumber := range canonicalBlocks {
		blockNumbers = append(blockNumbers, blockNumber)
	}
	sort.Slice(blockNumbers, func(i, j int) bool {
		return blockNumbers[i] < blockNumbers[j]
	})

	record.CollectorAttestation = ethereumCollectorAttestation{
		FinalizedBlockNumber: testFinalizedEthereumBlock,
		FinalizedBlockHash: testCanonicalEthereumBlockHash(
			testFinalizedEthereumBlock,
		),
	}
	for _, blockNumber := range blockNumbers {
		record.CollectorAttestation.CanonicalBlocks = append(
			record.CollectorAttestation.CanonicalBlocks,
			ethereumCanonicalBlockEvidence{
				BlockNumber: blockNumber,
				BlockHash:   canonicalBlocks[blockNumber],
			},
		)
	}
	resignTestChainReconciliationEvidence(t, record)
}

func TestComputeTBTCDKGResultHashMatchesGeneratedWalletRegistryABI(
	t *testing.T,
) {
	evidence, _, _ := newValidTBTCDKGResultEvidence(
		t,
		big.NewInt(42),
		1_000,
		4,
		[]uint8{1},
	)
	result := evidence.Submitted.Result

	parsed, err := ecdsaabi.WalletRegistryMetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	event, ok := parsed.Events["DkgResultSubmitted"]
	if !ok {
		t.Fatal("generated WalletRegistry ABI has no DkgResultSubmitted event")
	}
	if len(event.Inputs) != 3 {
		t.Fatalf(
			"expected DkgResultSubmitted to have 3 inputs, got %d",
			len(event.Inputs),
		)
	}

	groupPublicKey, err := decodeCanonicalEthereumBytes(
		result.GroupPublicKey,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := decodeCanonicalEthereumDynamicBytes(result.Signatures)
	if err != nil {
		t.Fatal(err)
	}
	membersHashBytes, err := decodeCanonicalEthereumBytes(
		result.MembersHash,
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	var membersHash [32]byte
	copy(membersHash[:], membersHashBytes)
	signingMemberIndexes := make([]*big.Int, len(result.SigningMemberIndexes))
	for i, memberIndex := range result.SigningMemberIndexes {
		signingMemberIndexes[i] = new(big.Int).Set(memberIndex)
	}

	encoded, err := (abi.Arguments{{Type: event.Inputs[2].Type}}).Pack(
		ecdsaabi.EcdsaDkgResult{
			SubmitterMemberIndex: new(big.Int).SetUint64(
				uint64(result.SubmitterMemberIndex),
			),
			GroupPubKey:              groupPublicKey,
			MisbehavedMembersIndices: result.MisbehavedMemberIndexes,
			Signatures:               signatures,
			SigningMembersIndices:    signingMemberIndexes,
			Members:                  result.Members,
			MembersHash:              membersHash,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "0x" + hex.EncodeToString(ethereumCrypto.Keccak256(encoded))

	actual, err := computeTBTCDKGResultHash(result)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf(
			"result hash disagrees with generated WalletRegistry ABI: "+
				"expected [%s], got [%s]",
			expected,
			actual,
		)
	}
}

// newValidEvidence builds every mandatory external rollback input, bound to
// the given already-audited manifest: every persisted wallet and group the
// manifest interprets is reconciled as registered and settled, and the prior
// reader covers every required schema.
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
	for walletIndex := range auditManifest.TBTCActiveWallets {
		wallet := &auditManifest.TBTCActiveWallets[walletIndex]
		startBlock := uint64(1)
		if auditManifest.ParticipationTerminalOutcomes != nil {
			for _, outcome := range auditManifest.ParticipationTerminalOutcomes.Outcomes {
				if outcome.Outcome ==
					participation.TerminalOutcomeCompleted &&
					outcome.Permit.Ceremony == participation.TBTCDKG &&
					outcome.Evidence.Reference == wallet.WalletStorageKey {
					startBlock = outcome.Permit.CanonicalStartBlock
					break
				}
			}
		}
		dkgResult, walletID, _ := newValidTBTCDKGResultEvidence(
			t,
			big.NewInt(int64(walletIndex+1)),
			startBlock,
			uint16(wallet.SigningGroupSize),
			[]uint8{},
		)
		if wallet.WalletID != walletID {
			t.Fatalf(
				"test wallet [%s] has ID [%s], but its synthetic accepted "+
					"event lineage derives [%s]",
				wallet.WalletStorageKey,
				wallet.WalletID,
				walletID,
			)
		}
		chainRecord.Wallets = append(chainRecord.Wallets, tbtcWalletChainEvidence{
			WalletStorageKey: wallet.WalletStorageKey,
			WalletID:         walletID,
			Registered:       true,
			DKGSettlement:    "approved",
			DKGResult:        dkgResult,
		})
	}
	for _, quarantined := range auditManifest.TBTCQuarantinedOutputs {
		walletID := quarantined.SignerWalletID
		if walletID == "" {
			walletID = quarantined.WalletID
		}
		chainRecord.Wallets = append(chainRecord.Wallets, tbtcWalletChainEvidence{
			WalletStorageKey: quarantined.WalletStorageKey,
			WalletID:         walletID,
			Registered:       false,
			DKGSettlement:    "none",
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
	for _, quarantined := range auditManifest.BeaconQuarantinedOutputs {
		chainRecord.BeaconGroups = append(chainRecord.BeaconGroups, struct {
			GroupPublicKey string `json:"group_public_key"`
			Registered     bool   `json:"registered"`
		}{
			GroupPublicKey: quarantined.GroupPublicKey,
			Registered:     false,
		})
	}
	authenticateTestChainReconciliationEvidence(t, chainRecord)

	bitcoinRecord := &bitcoinReconciliationEvidence{
		evidenceEnvelope: envelope("bitcoin_reconciliation"),
		BitcoinNetwork:   "mainnet",
		Complete:         true,
	}
	// A complete reconciliation enumerates every transaction the audited
	// wallets signed, including the ones the node recorded as its own wallet
	// actions' durable results.
	if auditManifest.ParticipationTerminalOutcomes != nil {
		for _, outcome := range auditManifest.ParticipationTerminalOutcomes.Outcomes {
			if outcome.Outcome != participation.TerminalOutcomeCompleted ||
				outcome.Evidence.Kind !=
					participation.TerminalEvidenceBitcoinTransaction {
				continue
			}
			bitcoinRecord.PendingTransactions = append(
				bitcoinRecord.PendingTransactions,
				struct {
					TransactionHash string `json:"transaction_hash"`
					State           string `json:"state"`
				}{
					TransactionHash: outcome.Evidence.Reference,
					State:           "mined",
				},
			)
		}
	}

	quiescenceEnvelope := envelope("quiescence_report")
	quiescenceRecord := &quiescenceReportEvidence{
		evidenceEnvelope: quiescenceEnvelope,
		ReleaseVersion:   "v2.1.0",
		ReleaseRevision:  strings.Repeat("ef", 20),
		ReleaseEpoch:     participation.CompiledEpoch.String(),
		CutoverBlock:     1_000,
		QuiesceCause:     "rollback drill",
	}
	if auditManifest.QuiescenceSnapshot != nil {
		for _, permit := range auditManifest.QuiescenceSnapshot.ActivePermits {
			outcome := participation.TerminalOutcomeCompleted
			if auditManifest.ParticipationTerminalOutcomes != nil {
				for _, terminal := range auditManifest.ParticipationTerminalOutcomes.Outcomes {
					if terminal.Permit == permit {
						outcome = terminal.Outcome
						break
					}
				}
			}
			quiescenceRecord.ActivePermitsAtQuiescence = append(
				quiescenceRecord.ActivePermitsAtQuiescence,
				quiescencePermitEvidence{
					Ceremony:            string(permit.Ceremony),
					Mode:                permit.Mode,
					CanonicalStartBlock: permit.CanonicalStartBlock,
					WorkID:              permit.WorkID,
					PermitID:            permit.PermitID,
					Outcome:             string(outcome),
				},
			)
		}
	}

	priorReaderRecord := &priorReaderCompatibilityEvidence{
		evidenceEnvelope:   envelope("prior_reader_compatibility"),
		PriorVersion:       "v2.0.0",
		PriorRevision:      strings.Repeat("ab", 20),
		PriorImageDigest:   "sha256:" + strings.Repeat("11", 32),
		ReleaseVersion:     "v2.1.0",
		ReleaseRevision:    strings.Repeat("ef", 20),
		ReleaseImageDigest: "sha256:" + strings.Repeat("22", 32),
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

// testExpectedIdentity returns the expected-identity inputs matching the
// values newValidEvidence and newTestStorage write, so identity binding
// passes unless a test deliberately mismatches it.
func testExpectedIdentity() expectedIdentityInputs {
	return expectedIdentityInputs{
		ethereumChainID:              "1",
		walletRegistryAddress:        testWalletRegistryAddress,
		finalizedEthereumBlockNumber: testFinalizedEthereumBlock,
		finalizedEthereumBlockHash: testCanonicalEthereumBlockHash(
			testFinalizedEthereumBlock,
		),
		chainEvidencePublicKey: testChainEvidencePublicKey(),
		bitcoinNetwork:         "mainnet",
		priorVersion:           "v2.0.0",
		priorRevision:          strings.Repeat("ab", 20),
		priorImageDigest:       "sha256:" + strings.Repeat("11", 32),
		releaseVersion:         "v2.1.0",
		releaseRevision:        strings.Repeat("ef", 20),
		releaseImageDigest:     "sha256:" + strings.Repeat("22", 32),
		releaseEpoch:           participation.CompiledEpoch.String(),
		cutoverBlock:           1_000,
		maxEvidenceAge:         24 * time.Hour,
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

func containsSubstring(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func updateQuiescenceReport(
	t *testing.T,
	evidence evidenceInputs,
	update func(*quiescenceReportEvidence),
) {
	t.Helper()

	content, err := os.ReadFile(evidence.quiescenceReport)
	if err != nil {
		t.Fatal(err)
	}

	record := &quiescenceReportEvidence{}
	if err := json.Unmarshal(content, record); err != nil {
		t.Fatal(err)
	}
	update(record)

	content, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidence.quiescenceReport, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func setQuiescencePermits(
	record *quiescenceReportEvidence,
	permits []quiescencePermitEvidence,
) {
	record.ActivePermitsAtQuiescence = append(
		[]quiescencePermitEvidence(nil),
		permits...,
	)
}

func TestRunAudit_ConsistentSnapshot(t *testing.T) {
	storageDir := newTestStorage(t)

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
	if err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, firstPass),
		testExpectedIdentity(),
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
		testExpectedIdentity(),
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

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
		testExpectedIdentity(),
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

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
		testExpectedIdentity(),
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

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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

	auditManifest, err := runAudit(storageDir, testPassword, evidence, testExpectedIdentity())
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
	permits := []quiescencePermitEvidence{{
		Ceremony:            "tbtc_dkg",
		Mode:                "security_v2",
		CanonicalStartBlock: 1_000,
		WorkID:              strings.Repeat("d", 64),
		PermitID:            "1",
		Outcome:             "quarantined",
	}}
	storageDir := newTestStorageWithQuiescencePermits(t, permits)

	firstPass, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
	setQuiescencePermits(
		record,
		permits,
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

	auditManifest, err := runAudit(storageDir, testPassword, evidence, testExpectedIdentity())
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
	if !hasFinding(
		auditManifest,
		"seed hash [aa] is not a canonical SHA-256 digest of 64 lowercase "+
			"hexadecimal characters",
	) {
		t.Errorf(
			"expected a malformed seed-hash finding, findings: %v",
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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

	_, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{
			chainReconciliation: filepath.Join(t.TempDir(), "does-not-exist"),
		},
		testExpectedIdentity(),
	)
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
			SeedHash:            strings.Repeat("b", 64),
			FailedOperation:     "beacon_dkg_result_publication",
			LastObservedBlock:   950,
		},
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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
			SeedHash:            strings.Repeat("c", 64),
			FailedOperation:     "beacon_dkg_result_publication",
			LastObservedBlock:   950,
		},
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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

	auditManifest, err := runAudit(storageDir, testPassword, evidenceInputs{}, testExpectedIdentity())
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

	auditManifest, err := runAudit(storageDir, "", evidenceInputs{}, testExpectedIdentity())
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

func TestRunAudit_MissingExpectedIdentityIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, firstPass),
		expectedIdentityInputs{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("missing expected identities must not authorize the barrier")
	}
	for _, fragment := range []string{
		"expected Ethereum chain ID is not supplied",
		"expected Bitcoin network is not supplied",
		"expected prior version is not supplied",
		"expected prior revision is not supplied",
		"expected prior image digest is not supplied",
		"expected release version is not supplied",
		"expected release revision is not supplied",
		"expected release image digest is not supplied",
		"expected release epoch is not supplied",
		"expected cutover block is not supplied",
		"no evidence freshness bound is supplied",
	} {
		if !hasBlocker(auditManifest, fragment) {
			t.Errorf(
				"expected the [%s] blocker, blockers: %v",
				fragment,
				auditManifest.RollbackBlockers,
			)
		}
	}
}

func TestRunAudit_MismatchedExpectedIdentityIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The evidence itself is schema-valid and records chain [1], network
	// [mainnet], version [v2.0.0]; the audit expects a different operational
	// target for each.
	mismatched := expectedIdentityInputs{
		ethereumChainID: "11155111",
		bitcoinNetwork:  "testnet",
		priorVersion:    "v1.9.9",
		priorRevision:   strings.Repeat("cd", 20),
		maxEvidenceAge:  24 * time.Hour,
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, firstPass),
		mismatched,
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("mismatched identities must not authorize the barrier")
	}
	for _, fragment := range []string{
		"reconciled against Ethereum chain [1], expected [11155111]",
		"reconciled against Bitcoin network [mainnet], expected [testnet]",
		"tested prior version [v2.0.0], expected [v1.9.9]",
		"tested prior revision",
	} {
		if !hasBlocker(auditManifest, fragment) {
			t.Errorf(
				"expected the [%s] blocker, blockers: %v",
				fragment,
				auditManifest.RollbackBlockers,
			)
		}
	}
}

func TestRunAudit_StaleEvidenceIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The evidence was generated a moment ago; a one-nanosecond freshness
	// bound makes every record stale.
	stale := testExpectedIdentity()
	stale.maxEvidenceAge = time.Nanosecond

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, firstPass),
		stale,
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("stale evidence must not authorize the barrier")
	}
	if !hasBlocker(auditManifest, "evidence freshness bound") {
		t.Errorf(
			"expected a freshness blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_UncoveredQuarantinedOutputIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Evidence generated from a manifest stripped of the quarantined output
	// reconciles the active state only.
	uncovered := *firstPass
	uncovered.BeaconQuarantinedOutputs = nil

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, &uncovered),
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("an unreconciled quarantined output must not authorize the barrier")
	}
	if !hasBlocker(auditManifest, "quarantined beacon group") ||
		!hasBlocker(auditManifest, "is not reconciled") {
		t.Errorf(
			"expected a quarantined-coverage blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_EvidenceForStateTheSnapshotDoesNotHoldIsBlocking(
	t *testing.T,
) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Evidence generated from a manifest holding one extra beacon group
	// reconciles state this snapshot does not hold.
	padded := *firstPass
	padded.BeaconActiveMemberships = append(
		append(
			[]beaconMembershipRecord{},
			firstPass.BeaconActiveMemberships...,
		),
		beaconMembershipRecord{
			GroupPublicKey: strings.Repeat("ee", 64),
			MemberIndex:    9,
			ChannelName:    "foreign-channel",
		},
	)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, &padded),
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("evidence for foreign state must not authorize the barrier")
	}
	if !hasBlocker(auditManifest, "that the snapshot does not hold") {
		t.Errorf(
			"expected a foreign-state blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_RegisteredQuarantinedOnlyShareIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)

	// Flip the quarantined group's chain state to registered: the share
	// exists only in quarantine, so a prior binary would run the group
	// without it.
	content, err := os.ReadFile(evidence.chainReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	record := &chainReconciliationEvidence{}
	if err := json.Unmarshal(content, record); err != nil {
		t.Fatal(err)
	}
	quarantinedGroup := firstPass.BeaconQuarantinedOutputs[0].GroupPublicKey
	for i := range record.BeaconGroups {
		if record.BeaconGroups[i].GroupPublicKey == quarantinedGroup {
			record.BeaconGroups[i].Registered = true
		}
	}
	content, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.chainReconciliation,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error(
			"a registered group with a quarantine-only share must not " +
				"authorize the barrier",
		)
	}
	if !hasBlocker(auditManifest, "preserved only in quarantine") {
		t.Errorf(
			"expected a quarantine-only-share blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_QuarantinedClaimWithMismatchedWorkIdentityIsBlocking(
	t *testing.T,
) {
	permits := []quiescencePermitEvidence{{
		Ceremony:            "beacon_dkg",
		Mode:                "legacy",
		CanonicalStartBlock: 900,
		WorkID:              strings.Repeat("f", 64),
		PermitID:            "2",
		Outcome:             "quarantined",
	}}
	storageDir := newTestStorageWithQuiescencePermits(t, permits)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)

	// The snapshot's only quarantined beacon output has this ceremony, mode,
	// anchor, and member index. The report substitutes another DKG seed hash;
	// those classifications and local member alone must not vouch for work
	// from another chain event.
	record := &quiescenceReportEvidence{
		evidenceEnvelope: evidenceEnvelope{
			SchemaVersion:           evidenceSchemaVersion,
			EvidenceType:            "quiescence_report",
			GeneratedAt:             time.Now().UTC(),
			SnapshotAggregateSHA256: firstPass.Snapshot.AggregateSHA256,
		},
		QuiesceCause: "rollback drill",
	}
	setQuiescencePermits(
		record,
		permits,
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

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error(
			"a work-mismatched quarantined-output claim must not " +
				"authorize the barrier",
		)
	}
	if !hasBlocker(
		auditManifest,
		"the beacon quarantine namespace holds none matching",
	) {
		t.Errorf(
			"expected an exact-permit-matching blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

// TestRunAudit_DuplicateCompletedPermitIdentityIsBlocking proves permit
// uniqueness is enforced for completed outcomes as well as quarantined ones.
// Otherwise a report with the expected entry count could repeat one completed
// permit while omitting a different permit that was still active.
func TestRunAudit_DuplicateCompletedPermitIdentityIsBlocking(t *testing.T) {
	completed := quiescencePermitEvidence{
		Ceremony:            string(participation.TBTCSigning),
		Mode:                participation.ModeLegacy.String(),
		CanonicalStartBlock: 900,
		WorkID:              "wallet-action-1",
		PermitID:            "wallet-action-1",
		Outcome:             "completed",
	}
	storageDir := newTestStorageWithQuiescencePermits(
		t,
		[]quiescencePermitEvidence{completed},
	)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)
	updateQuiescenceReport(
		t,
		evidence,
		func(record *quiescenceReportEvidence) {
			setQuiescencePermits(
				record,
				[]quiescencePermitEvidence{completed},
			)
			record.ActivePermitsAtQuiescence = []quiescencePermitEvidence{
				completed,
				completed,
			}
		},
	)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error(
			"a duplicated completed permit must not authorize the barrier",
		)
	}
	if !hasBlocker(
		auditManifest,
		"duplicates the full permit identity first recorded by entry [0]",
	) {
		t.Errorf(
			"expected a duplicate-permit blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

// TestRunAudit_MalformedQuiescencePermitIdentitiesAreBlocking proves the audit
// does not treat aliases, truncated seed hashes, or separator-bearing labels
// as exact local permit identities.
func TestRunAudit_MalformedQuiescencePermitIdentitiesAreBlocking(t *testing.T) {
	permits := []quiescencePermitEvidence{
		{
			Ceremony:            string(participation.TBTCDKG),
			Mode:                participation.ModeLegacy.String(),
			CanonicalStartBlock: 900,
			WorkID:              strings.Repeat("A", 64),
			PermitID:            "01",
			Outcome:             "completed",
		},
		{
			Ceremony: string(
				participation.BeaconRelaySigning,
			),
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              "relay-request-1",
			PermitID:            "member-1",
			Outcome:             "completed",
		},
		{
			Ceremony:            string(participation.TBTCSigning),
			Mode:                participation.ModeLegacy.String(),
			CanonicalStartBlock: 900,
			WorkID:              "wallet/action",
			PermitID:            "wallet~1",
			Outcome:             "completed",
		},
	}
	storageDir := newTestStorageWithQuiescencePermits(t, permits)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)
	updateQuiescenceReport(
		t,
		evidence,
		func(record *quiescenceReportEvidence) {
			setQuiescencePermits(record, permits)
		},
	)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("malformed permit identities must not authorize the barrier")
	}
	for _, fragment := range []string{
		"is not a canonical SHA-256 seed hash",
		"local permit identity [01] is not a canonical protocol member index",
		"local permit identity [member-1] is not a canonical protocol member index",
		"chain work identity [wallet/action] is not a stable evidence identifier",
		"local permit identity [wallet~1] is not a stable evidence identifier",
	} {
		if !hasBlocker(auditManifest, fragment) {
			t.Errorf(
				"expected identity-format blocker [%s], blockers: %v",
				fragment,
				auditManifest.RollbackBlockers,
			)
		}
	}
}

// TestRunAudit_CompleteNonemptyQuiescenceInventorySatisfiesBarrier proves a
// one-to-one terminal-outcome list with matching aggregate counts remains an
// authorizing record.
func TestRunAudit_CompleteNonemptyQuiescenceInventorySatisfiesBarrier(
	t *testing.T,
) {
	permits := []quiescencePermitEvidence{
		{
			Ceremony: string(
				participation.TBTCSigning,
			),
			Mode:                participation.ModeLegacy.String(),
			CanonicalStartBlock: 999,
			WorkID:              "wallet-action-legacy",
			PermitID:            "wallet-action-legacy",
			Outcome:             "completed",
		},
		{
			Ceremony: string(
				participation.BeaconRelaySigning,
			),
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              "relay-request-security-v2",
			PermitID:            "2",
			Outcome:             "completed",
		},
	}
	storageDir := newTestStorageWithQuiescencePermits(t, permits)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)
	updateQuiescenceReport(
		t,
		evidence,
		func(record *quiescenceReportEvidence) {
			setQuiescencePermits(record, permits)
		},
	)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !auditManifest.RollbackBarrierReady {
		t.Errorf(
			"expected a complete nonempty quiescence inventory to authorize "+
				"the barrier, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_ExternalCompletedCannotReplaceNodeExhaustedOutcome(
	t *testing.T,
) {
	permit := quiescencePermitEvidence{
		Ceremony:            string(participation.TBTCSigning),
		Mode:                participation.ModeLegacy.String(),
		CanonicalStartBlock: 999,
		WorkID:              "wallet-action-exhausted",
		PermitID:            "wallet-exhausted",
		Outcome:             string(participation.TerminalOutcomeExhausted),
	}
	storageDir := newTestStorageWithQuiescencePermits(
		t,
		[]quiescencePermitEvidence{permit},
	)
	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := newValidEvidence(t, firstPass)

	// An external generator labels the permit completed and supplies an
	// unrelated successful Bitcoin transaction. Neither can replace the
	// ceremony owner's durable no-threshold outcome.
	updateQuiescenceReport(
		t,
		evidence,
		func(record *quiescenceReportEvidence) {
			record.ActivePermitsAtQuiescence[0].Outcome =
				string(participation.TerminalOutcomeCompleted)
		},
	)
	bitcoinRecord := &bitcoinReconciliationEvidence{}
	content, err := os.ReadFile(evidence.bitcoinReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, bitcoinRecord); err != nil {
		t.Fatal(err)
	}
	bitcoinRecord.PendingTransactions = append(
		bitcoinRecord.PendingTransactions,
		struct {
			TransactionHash string `json:"transaction_hash"`
			State           string `json:"state"`
		}{
			TransactionHash: strings.Repeat("ab", 32),
			State:           "mined",
		},
	)
	content, err = json.MarshalIndent(bitcoinRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.bitcoinReconciliation,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if auditManifest.RollbackBarrierReady {
		t.Error(
			"an external completed label and unrelated successful transaction " +
				"must not replace the node-authored exhausted outcome",
		)
	}
	if !hasBlocker(
		auditManifest,
		"claims terminal outcome [completed], but the node-authored journal records [exhausted]",
	) {
		t.Errorf(
			"expected node-authored outcome mismatch blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestRunAudit_NodeCompletedDKGRequiresPersistedSigner(t *testing.T) {
	permit := quiescencePermitEvidence{
		Ceremony:            string(participation.TBTCDKG),
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: 1_000,
		WorkID:              strings.Repeat("d", 64),
		PermitID:            "1",
		Outcome:             string(participation.TerminalOutcomeCompleted),
	}
	storageDir := newTestStorageWithQuiescencePermits(
		t,
		[]quiescencePermitEvidence{permit},
	)
	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := newValidEvidence(t, firstPass)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if auditManifest.RollbackBarrierReady {
		t.Error(
			"a node-authored completed DKG outcome without its persisted " +
				"signer must not authorize the barrier",
		)
	}
	if !hasFinding(
		auditManifest,
		"active tbtc namespace holds no matching signer",
	) {
		t.Errorf(
			"expected persisted-signer corroboration finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

func TestValidateNodeTerminalOutcomes_DKGCompletionIsMembershipExact(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	workID := strings.Repeat("d", 64)
	permits := []participation.PermitSnapshot{
		{
			Ceremony:            participation.TBTCDKG,
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              workID,
			PermitID:            "1",
			IdentityBound:       true,
		},
		{
			Ceremony:            participation.TBTCDKG,
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              workID,
			PermitID:            "2",
			IdentityBound:       true,
		},
	}

	newManifest := func(
		secondReference string,
		secondMembership group.MemberIndex,
	) *manifest {
		return &manifest{
			QuiescenceSnapshot: &participation.QuiescenceSnapshot{
				CapturedAt:    capturedAt,
				ActivePermits: permits,
			},
			ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
				SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
				SnapshotCapturedAt: capturedAt,
				Outcomes: []participation.TerminalOutcomeRecord{
					{
						RecordedAt: time.Now().UTC(),
						Permit:     permits[0],
						Outcome:    participation.TerminalOutcomeCompleted,
						Evidence: participation.TerminalEvidence{
							Kind:            participation.TerminalEvidencePersistedTBTCSinger,
							Reference:       "wallet-storage-key",
							MembershipIndex: group.MemberIndex(1),
						},
					},
					{
						RecordedAt: time.Now().UTC(),
						Permit:     permits[1],
						Outcome:    participation.TerminalOutcomeCompleted,
						Evidence: participation.TerminalEvidence{
							Kind:            participation.TerminalEvidencePersistedTBTCSinger,
							Reference:       secondReference,
							MembershipIndex: secondMembership,
						},
					},
				},
			},
			TBTCActiveWallets: []tbtcWalletRecord{
				{
					WalletStorageKey: "wallet-storage-key",
					WalletID:         "wallet-id",
					MemberIndexes:    []uint8{1},
					SigningGroupSize: 2,
				},
			},
		}
	}

	tests := map[string]struct {
		manifest        *manifest
		expectedFinding string
	}{
		"missing second persisted membership": {
			manifest: newManifest(
				"wallet-storage-key",
				group.MemberIndex(2),
			),
			expectedFinding: "membership [2], but the active tbtc namespace holds no matching signer",
		},
		"one persisted membership reused by two permits": {
			manifest: newManifest(
				"wallet-storage-key",
				group.MemberIndex(1),
			),
			expectedFinding: "claim the same persisted signer [wallet-storage-key] membership [1]",
		},
		"wallet ID alias cannot replace the signer storage record": {
			manifest: newManifest(
				"wallet-id",
				group.MemberIndex(1),
			),
			expectedFinding: "persisted signer [wallet-id] membership [1], but the active tbtc namespace holds no matching signer",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			violations := validateNodeTerminalOutcomes(test.manifest)
			for _, violation := range violations {
				if strings.Contains(violation, test.expectedFinding) {
					return
				}
			}
			t.Fatalf(
				"expected exact-membership violation containing [%s], got: %v",
				test.expectedFinding,
				violations,
			)
		})
	}
}

// TestValidateNodeTerminalOutcomes_CompletedEvidenceKindIsPinnedPerCeremony
// proves the offline audit refuses a settlement recorded in the wrong evidence
// class. A wallet action's durable result is a Bitcoin transaction the audit
// can reconcile against the chain; a node-authored protocol digest in its place
// would clear the rollback journal on the node's own say-so after an ambiguous
// submission, with nothing canonical left to check it against.
func TestValidateNodeTerminalOutcomes_CompletedEvidenceKindIsPinnedPerCeremony(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	permit := participation.PermitSnapshot{
		Ceremony:            participation.TBTCSigning,
		Mode:                participation.ModeLegacy.String(),
		CanonicalStartBlock: 999,
		WorkID:              "wallet-action-legacy",
		PermitID:            "wallet-action-legacy",
		IdentityBound:       true,
	}

	newManifest := func(evidence participation.TerminalEvidence) *manifest {
		return &manifest{
			QuiescenceSnapshot: &participation.QuiescenceSnapshot{
				CapturedAt:    capturedAt,
				ActivePermits: []participation.PermitSnapshot{permit},
			},
			ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
				SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
				SnapshotCapturedAt: capturedAt,
				Outcomes: []participation.TerminalOutcomeRecord{
					{
						RecordedAt: time.Now().UTC(),
						Permit:     permit,
						Outcome:    participation.TerminalOutcomeCompleted,
						Evidence:   evidence,
					},
				},
			},
		}
	}

	forged := validateNodeTerminalOutcomes(newManifest(
		participation.TerminalEvidence{
			Kind:      participation.TerminalEvidenceProtocolResult,
			Reference: strings.Repeat("a", 64),
		},
	))
	rejected := false
	for _, violation := range forged {
		if strings.Contains(violation, "requires evidence kind [bitcoin_transaction]") {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Errorf(
			"a completed wallet action settled on a node-authored protocol "+
				"digest was not rejected, violations: %v",
			forged,
		)
	}

	honest := validateNodeTerminalOutcomes(newManifest(
		participation.TerminalEvidence{
			Kind:      participation.TerminalEvidenceBitcoinTransaction,
			Reference: strings.Repeat("a", 64),
		},
	))
	for _, violation := range honest {
		if strings.Contains(violation, "evidence is invalid") {
			t.Errorf(
				"the wallet action's own evidence class was rejected: [%s]",
				violation,
			)
		}
	}
}

// TestRunAudit_SignedTransactionMustBeEnumeratedByBitcoinReconciliation proves
// a wallet action the node recorded as completed cannot clear the barrier
// unless the attested-complete pending set names the exact transaction it
// signed. The node pins that hash before broadcasting, so a transaction missing
// from a complete reconciliation is precisely the ambiguous submission the
// rollback barrier exists to catch.
func TestRunAudit_SignedTransactionMustBeEnumeratedByBitcoinReconciliation(
	t *testing.T,
) {
	permits := []quiescencePermitEvidence{
		{
			Ceremony:            string(participation.TBTCSigning),
			Mode:                participation.ModeLegacy.String(),
			CanonicalStartBlock: 999,
			WorkID:              "wallet-action-legacy",
			PermitID:            "wallet-action-legacy",
			Outcome:             "completed",
		},
	}

	tests := map[string]struct {
		mutate          func(*bitcoinReconciliationEvidence)
		expectedBlocker string
	}{
		"the signed transaction is dropped from a complete set": {
			mutate: func(record *bitcoinReconciliationEvidence) {
				record.PendingTransactions = nil
			},
			expectedBlocker: "does not enumerate",
		},
		"an unrelated transaction stands in for the signed one": {
			mutate: func(record *bitcoinReconciliationEvidence) {
				record.PendingTransactions[0].TransactionHash =
					strings.Repeat("ab", 32)
			},
			expectedBlocker: "does not enumerate",
		},
		"the signed transaction is named in a noncanonical shape": {
			mutate: func(record *bitcoinReconciliationEvidence) {
				record.PendingTransactions[0].TransactionHash =
					strings.ToUpper(
						record.PendingTransactions[0].TransactionHash,
					)
			},
			expectedBlocker: "is not a canonical lowercase transaction hash",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			storageDir := newTestStorageWithQuiescencePermits(t, permits)

			firstPass, err := runAudit(
				storageDir,
				testPassword,
				evidenceInputs{},
				testExpectedIdentity(),
			)
			if err != nil {
				t.Fatal(err)
			}

			evidence := newValidEvidence(t, firstPass)
			updateQuiescenceReport(
				t,
				evidence,
				func(record *quiescenceReportEvidence) {
					setQuiescencePermits(record, permits)
				},
			)

			// The unmutated evidence must authorize the barrier, otherwise the
			// mutation below proves nothing about this check.
			baseline, err := runAudit(
				storageDir,
				testPassword,
				evidence,
				testExpectedIdentity(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !baseline.RollbackBarrierReady {
				t.Fatalf(
					"the unmutated evidence does not authorize the barrier, "+
						"blockers: %v",
					baseline.RollbackBlockers,
				)
			}

			updateBitcoinReconciliation(t, evidence, test.mutate)

			auditManifest, err := runAudit(
				storageDir,
				testPassword,
				evidence,
				testExpectedIdentity(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if auditManifest.RollbackBarrierReady {
				t.Fatalf(
					"a signed transaction the complete reconciliation does not " +
						"cover authorized the barrier",
				)
			}
			for _, blocker := range auditManifest.RollbackBlockers {
				if strings.Contains(blocker, test.expectedBlocker) {
					return
				}
			}
			t.Errorf(
				"expected a blocker containing [%s], blockers: %v",
				test.expectedBlocker,
				auditManifest.RollbackBlockers,
			)
		})
	}
}

// updateBitcoinReconciliation rewrites the supplied Bitcoin reconciliation
// evidence in place.
func updateBitcoinReconciliation(
	t *testing.T,
	evidence evidenceInputs,
	mutate func(*bitcoinReconciliationEvidence),
) {
	t.Helper()

	record := &bitcoinReconciliationEvidence{}
	content, err := os.ReadFile(evidence.bitcoinReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, record); err != nil {
		t.Fatal(err)
	}

	mutate(record)

	content, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.bitcoinReconciliation,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func TestValidateChainReconciliationEvidence_TBTCDKGPermitLineage(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	canonicalSeed := big.NewInt(42)
	canonicalResult, _, seedHash := newValidTBTCDKGResultEvidence(
		t,
		canonicalSeed,
		1_000,
		4,
		[]uint8{1},
	)
	resultHash := canonicalResult.resultHash()
	permits := []participation.PermitSnapshot{
		{
			Ceremony:            participation.TBTCDKG,
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              seedHash,
			PermitID:            "2",
			IdentityBound:       true,
		},
		{
			Ceremony:            participation.TBTCDKG,
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              seedHash,
			PermitID:            "3",
			IdentityBound:       true,
		},
	}

	newRunAndRecord := func(
		firstMembership group.MemberIndex,
		secondMembership group.MemberIndex,
		resultSeed *big.Int,
	) (*auditRun, *chainReconciliationEvidence) {
		dkgResult, resultWalletID, _ := newValidTBTCDKGResultEvidence(
			t,
			resultSeed,
			1_000,
			4,
			[]uint8{1},
		)
		auditManifest := &manifest{
			GeneratedAt: time.Now().UTC(),
			Snapshot: snapshotIdentity{
				AggregateSHA256: strings.Repeat("c", 64),
			},
			QuiescenceSnapshot: &participation.QuiescenceSnapshot{
				SchemaVersion: participation.QuiescenceSnapshotSchemaVersion,
				CapturedAt:    capturedAt,
				ActivePermits: permits,
			},
			ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
				SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
				SnapshotCapturedAt: capturedAt,
				Outcomes: []participation.TerminalOutcomeRecord{
					{
						RecordedAt: time.Now().UTC(),
						Permit:     permits[0],
						Outcome:    participation.TerminalOutcomeCompleted,
						Evidence: participation.TerminalEvidence{
							Kind:            participation.TerminalEvidencePersistedTBTCSinger,
							Reference:       "wallet-storage-key",
							MembershipIndex: firstMembership,
						},
					},
					{
						RecordedAt: time.Now().UTC(),
						Permit:     permits[1],
						Outcome:    participation.TerminalOutcomeCompleted,
						Evidence: participation.TerminalEvidence{
							Kind:            participation.TerminalEvidencePersistedTBTCSinger,
							Reference:       "wallet-storage-key",
							MembershipIndex: secondMembership,
						},
					},
				},
			},
			TBTCActiveWallets: []tbtcWalletRecord{
				{
					WalletStorageKey: "wallet-storage-key",
					WalletID:         resultWalletID,
					MemberIndexes: []uint8{
						uint8(firstMembership),
						uint8(secondMembership),
					},
					SigningGroupSize: 3,
				},
			},
		}
		run := &auditRun{
			manifest: auditManifest,
			expected: expectedIdentityInputs{
				ethereumChainID:              "1",
				walletRegistryAddress:        testWalletRegistryAddress,
				finalizedEthereumBlockNumber: testFinalizedEthereumBlock,
				finalizedEthereumBlockHash: testCanonicalEthereumBlockHash(
					testFinalizedEthereumBlock,
				),
				chainEvidencePublicKey: testChainEvidencePublicKey(),
				maxEvidenceAge:         time.Hour,
			},
		}
		record := &chainReconciliationEvidence{
			evidenceEnvelope: evidenceEnvelope{
				SchemaVersion:           evidenceSchemaVersion,
				EvidenceType:            "chain_reconciliation",
				GeneratedAt:             auditManifest.GeneratedAt,
				SnapshotAggregateSHA256: auditManifest.Snapshot.AggregateSHA256,
			},
			EthereumChainID: "1",
			Wallets: []tbtcWalletChainEvidence{
				{
					WalletStorageKey: "wallet-storage-key",
					WalletID:         resultWalletID,
					Registered:       true,
					DKGSettlement:    "approved",
					DKGResult:        dkgResult,
				},
			},
		}
		authenticateTestChainReconciliationEvidence(t, record)
		return run, record
	}

	t.Run("canonical original-to-final mapping", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if violations := run.validateChainReconciliationEvidence(content); len(violations) != 0 {
			t.Fatalf("expected exact DKG lineage to pass, got: %v", violations)
		}
	})

	t.Run("self-consistent lineage from untrusted generator", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)

		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = 0x24
		}
		untrustedKey := ed25519.NewKeyFromSeed(seed)
		record.CollectorAttestation.Signature = ""
		payload, err := chainReconciliationSignaturePayload(record)
		if err != nil {
			t.Fatal(err)
		}
		record.CollectorAttestation.Signature = hex.EncodeToString(
			ed25519.Sign(untrustedKey, payload),
		)

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"not signed by the independently trusted finalized-chain collector",
		) {
			t.Fatalf(
				"expected an unauthenticated-collector violation, got: %v",
				violations,
			)
		}
	})

	t.Run("correct event bytes from unrelated contract", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		record.Receipts[0].Logs[0].Address =
			"0x2222222222222222222222222222222222222222"
		resignTestChainReconciliationEvidence(t, record)

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"event was emitted by unrelated contract",
		) {
			t.Fatalf(
				"expected an unrelated-contract violation, got: %v",
				violations,
			)
		}
	})

	t.Run("failed receipt", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		record.Receipts[0].Status = 0
		resignTestChainReconciliationEvidence(t, record)

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(violations, "has failed status [0]") ||
			!containsSubstring(violations, "belongs to failed receipt") {
			t.Fatalf(
				"expected failed-receipt violations, got: %v",
				violations,
			)
		}
	})

	t.Run("non-canonical receipt block", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		record.Receipts[0].BlockHash = "0x" + strings.Repeat("f", 64)
		resignTestChainReconciliationEvidence(t, record)

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(violations, "names non-canonical block hash") {
			t.Fatalf(
				"expected a non-canonical-block violation, got: %v",
				violations,
			)
		}
	})

	t.Run("full-width signing member index is rejected by group bounds", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		fullWidthIndex := new(big.Int).Lsh(big.NewInt(1), 128)
		record.Wallets[0].DKGResult.Submitted.Result.
			SigningMemberIndexes[0] = fullWidthIndex

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"signing member ["+fullWidthIndex.String()+
				"] outside original group size",
		) {
			t.Fatalf(
				"expected full-width index to decode then fail group bounds, "+
					"got: %v",
				violations,
			)
		}
	})

	t.Run("caller-supplied result hash is recomputed", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		forgedHash := "0x" + strings.Repeat("f", 64)
		record.Wallets[0].DKGResult.Submitted.ResultHash = forgedHash
		record.Wallets[0].DKGResult.Approved.ResultHash = forgedHash
		record.Wallets[0].DKGResult.WalletCreated.DKGResultHash = forgedHash

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"does not match keccak256(abi.encode(result))",
		) {
			t.Fatalf(
				"expected a derived-result-hash violation, got: %v",
				violations,
			)
		}
	})

	t.Run("members hash is derived from the submitted result", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		result := record.Wallets[0].DKGResult
		result.Submitted.Result.MembersHash =
			"0x" + strings.Repeat("e", 64)
		// Keep the event's indexed result hash internally consistent with the
		// forged tuple. The independent operating-members derivation must
		// still reject it.
		forgedHash, err := computeTBTCDKGResultHash(result.Submitted.Result)
		if err != nil {
			t.Fatal(err)
		}
		result.Submitted.ResultHash = forgedHash
		result.Approved.ResultHash = forgedHash
		result.WalletCreated.DKGResultHash = forgedHash

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"does not match the derived operating-members hash",
		) {
			t.Fatalf(
				"expected a derived-members-hash violation, got: %v",
				violations,
			)
		}
	})

	t.Run("approval and wallet creation share one receipt", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		record.Wallets[0].DKGResult.WalletCreated.TransactionHash =
			"0x" + strings.Repeat("d", 64)

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"do not belong to the same approval receipt",
		) {
			t.Fatalf(
				"expected an accepted-event-lineage violation, got: %v",
				violations,
			)
		}
	})

	t.Run("swapped persisted memberships", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(2),
			group.MemberIndex(1),
			canonicalSeed,
		)
		// Storage existence and one-to-one claims alone accept this swap:
		// both final memberships really exist and neither is reused.
		if violations := validateNodeTerminalOutcomes(run.manifest); len(violations) != 0 {
			t.Fatalf(
				"expected node-local membership existence to be insufficient, got: %v",
				violations,
			)
		}

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		for _, expected := range []string{
			"maps to final membership [1], but names persisted membership [2]",
			"maps to final membership [2], but names persisted membership [1]",
		} {
			if !containsSubstring(violations, expected) {
				t.Errorf(
					"expected swapped-membership violation containing [%s], got: %v",
					expected,
					violations,
				)
			}
		}
	})

	t.Run("unrelated approved wallet", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			big.NewInt(43),
		)
		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		_, _, unrelatedSeedHash := newValidTBTCDKGResultEvidence(
			t,
			big.NewInt(43),
			1_000,
			4,
			[]uint8{1},
		)
		if !containsSubstring(
			violations,
			"persisted wallet [wallet-storage-key] was created by canonical "+
				"result ["+resultHash+"] for seed ["+unrelatedSeedHash+"]",
		) {
			t.Fatalf(
				"expected unrelated-approved-wallet violation, got: %v",
				violations,
			)
		}
	})
}

func TestValidateNodeTerminalOutcomes_DKGExhaustionNeedsChainProof(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	permit := participation.PermitSnapshot{
		Ceremony:            participation.TBTCDKG,
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: 1_000,
		WorkID:              strings.Repeat("d", 64),
		PermitID:            "1",
		IdentityBound:       true,
	}
	auditManifest := &manifest{
		QuiescenceSnapshot: &participation.QuiescenceSnapshot{
			CapturedAt:    capturedAt,
			ActivePermits: []participation.PermitSnapshot{permit},
		},
		ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
			SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
			SnapshotCapturedAt: capturedAt,
			Outcomes: []participation.TerminalOutcomeRecord{
				{
					RecordedAt: time.Now().UTC(),
					Permit:     permit,
					Outcome:    participation.TerminalOutcomeExhausted,
					Evidence: participation.TerminalEvidence{
						Kind: participation.TerminalEvidenceNoThreshold,
					},
				},
			},
		},
	}

	violations := validateNodeTerminalOutcomes(auditManifest)
	for _, violation := range violations {
		if strings.Contains(
			violation,
			"no chain-derived proof that another member did not publish",
		) {
			return
		}
	}
	t.Fatalf(
		"expected unauthenticated DKG exhaustion to be rejected, got: %v",
		violations,
	)
}

func TestRunAudit_NodeCompletedBeaconDKGMatchesPersistedSigner(t *testing.T) {
	permit := quiescencePermitEvidence{
		Ceremony:            string(participation.BeaconDKG),
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: 1_000,
		WorkID:              strings.Repeat("d", 64),
		PermitID:            "1",
		Outcome:             string(participation.TerminalOutcomeCompleted),
	}
	storageDir := newTestStorageWithQuiescencePermits(
		t,
		[]quiescencePermitEvidence{permit},
	)
	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := newValidEvidence(t, firstPass)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !auditManifest.RollbackBarrierReady {
		t.Errorf(
			"a node-authored completed beacon DKG outcome matching its active "+
				"signer should authorize the barrier, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

func TestValidateNodeTerminalOutcomes_RejectsUnsupportedEvidence(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	permit := participation.PermitSnapshot{
		Ceremony:            participation.TBTCSigning,
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: 1_000,
		WorkID:              "wallet-action",
		PermitID:            "wallet",
		IdentityBound:       true,
	}
	auditManifest := &manifest{
		QuiescenceSnapshot: &participation.QuiescenceSnapshot{
			CapturedAt:    capturedAt,
			ActivePermits: []participation.PermitSnapshot{permit},
		},
		ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
			SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
			SnapshotCapturedAt: capturedAt,
			Outcomes: []participation.TerminalOutcomeRecord{
				{
					RecordedAt: time.Now().UTC(),
					Permit:     permit,
					Outcome:    participation.TerminalOutcomeCompleted,
					Evidence: participation.TerminalEvidence{
						Kind: participation.TerminalEvidenceKind(
							"fabricated_result",
						),
						Reference: "fabricated-result",
					},
				},
			},
		},
	}

	violations := validateNodeTerminalOutcomes(auditManifest)
	for _, violation := range violations {
		if strings.Contains(violation, "evidence is invalid") {
			return
		}
	}
	t.Fatalf(
		"expected unsupported terminal evidence violation, got: %v",
		violations,
	)
}

// TestRunAudit_QuiescenceOutcomesMustCoverGateInventory proves terminal
// outcomes cannot authorize the barrier when they omit permits independently
// captured by the gate at the quiescence transition.
func TestRunAudit_QuiescenceOutcomesMustCoverGateInventory(t *testing.T) {
	permits := []quiescencePermitEvidence{
		{
			Ceremony:            string(participation.TBTCSigning),
			Mode:                participation.ModeLegacy.String(),
			CanonicalStartBlock: 999,
			WorkID:              "wallet-action-legacy",
			PermitID:            "wallet-action-legacy",
			Outcome:             "completed",
		},
		{
			Ceremony:            string(participation.BeaconRelaySigning),
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              "relay-request-security-v2",
			PermitID:            "2",
			Outcome:             "completed",
		},
	}
	storageDir := newTestStorageWithQuiescencePermits(t, permits)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		outcomes         []quiescencePermitEvidence
		blockerFragments []string
	}{
		"empty outcomes over nonempty inventory": {
			outcomes: nil,
			blockerFragments: []string{
				"contains [0] permits, but the node-authored gate snapshot declares total [2]",
				"contains [0] legacy permits, but the node-authored gate snapshot declares [1]",
				"contains [0] security-v2 permits, but the node-authored gate snapshot declares [1]",
			},
		},
		"shortened outcomes without duplicates": {
			outcomes: permits[:1],
			blockerFragments: []string{
				"contains [1] permits, but the node-authored gate snapshot declares total [2]",
				"contains [0] security-v2 permits, but the node-authored gate snapshot declares [1]",
				"node-authored gate inventory entry [0] has no terminal outcome",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := newValidEvidence(t, firstPass)
			updateQuiescenceReport(
				t,
				evidence,
				func(record *quiescenceReportEvidence) {
					setQuiescencePermits(record, permits)
					record.ActivePermitsAtQuiescence = append(
						[]quiescencePermitEvidence(nil),
						test.outcomes...,
					)
				},
			)

			auditManifest, err := runAudit(
				storageDir,
				testPassword,
				evidence,
				testExpectedIdentity(),
			)
			if err != nil {
				t.Fatal(err)
			}

			if auditManifest.RollbackBarrierReady {
				t.Error(
					"an incomplete terminal-outcome list must not " +
						"authorize the barrier",
				)
			}
			for _, fragment := range test.blockerFragments {
				if !hasBlocker(auditManifest, fragment) {
					t.Errorf(
						"expected coverage blocker [%s], blockers: %v",
						fragment,
						auditManifest.RollbackBlockers,
					)
				}
			}
		})
	}
}

// TestRunAudit_SelfAttestedEqualOmissionCannotHideRealGatePermit proves the
// prior report-only attack is closed: even if an external generator reports a
// shortened outcome list and would have shortened its own duplicate counts
// and inventory too, the audit reconciles against the independently persisted
// registry captured by the production gate.
func TestRunAudit_SelfAttestedEqualOmissionCannotHideRealGatePermit(
	t *testing.T,
) {
	permits := []quiescencePermitEvidence{
		{
			Ceremony:            string(participation.TBTCSigning),
			Mode:                participation.ModeLegacy.String(),
			CanonicalStartBlock: 999,
			WorkID:              "wallet-action-real-legacy",
			PermitID:            "wallet-real-legacy",
			Outcome:             "completed",
		},
		{
			Ceremony:            string(participation.BeaconRelaySigning),
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              "relay-request-real-security-v2",
			PermitID:            "2",
			Outcome:             "completed",
		},
	}

	storageDir := newTestStorage(t)
	persistRealGateQuiescenceSnapshot(t, storageDir, permits)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := newValidEvidence(t, firstPass)
	updateQuiescenceReport(
		t,
		evidence,
		func(record *quiescenceReportEvidence) {
			record.ActivePermitsAtQuiescence =
				[]quiescencePermitEvidence{permits[0]}
		},
	)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if auditManifest.RollbackBarrierReady {
		t.Error(
			"an external equal omission must not hide a permit captured by " +
				"the production gate",
		)
	}
	for _, fragment := range []string{
		"contains [1] permits, but the node-authored gate snapshot declares total [2]",
		"node-authored gate inventory entry [0] has no terminal outcome",
	} {
		if !hasBlocker(auditManifest, fragment) {
			t.Errorf(
				"expected node-authored inventory blocker [%s], blockers: %v",
				fragment,
				auditManifest.RollbackBlockers,
			)
		}
	}
}

func TestRunAudit_QuiescenceReportCannotPredateGateTransition(t *testing.T) {
	storageDir := newTestStorage(t)
	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if firstPass.QuiescenceSnapshot == nil {
		t.Fatal("test storage has no node-authored quiescence snapshot")
	}

	evidence := newValidEvidence(t, firstPass)
	updateQuiescenceReport(
		t,
		evidence,
		func(record *quiescenceReportEvidence) {
			record.GeneratedAt =
				firstPass.QuiescenceSnapshot.CapturedAt.Add(-time.Second)
		},
	)

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if auditManifest.RollbackBarrierReady {
		t.Error(
			"a terminal report generated before the node quiesced must not " +
				"authorize the barrier",
		)
	}
	if !hasBlocker(
		auditManifest,
		"node-authored quiescence gate snapshot was captured after the quiescence report was generated",
	) {
		t.Errorf(
			"expected transition-time blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

// TestRunAudit_QuiescencePermitModeMustMatchCutoverBoundary proves completed
// permits are subject to the same canonical-anchor arithmetic as quarantined
// outputs.
func TestRunAudit_QuiescencePermitModeMustMatchCutoverBoundary(t *testing.T) {
	tests := map[string]struct {
		mode            participation.ProtocolMode
		anchor          uint64
		blockerFragment string
	}{
		"legacy at C": {
			mode:            participation.ModeLegacy,
			anchor:          1_000,
			blockerFragment: "permit entry [0] claims mode [legacy] with canonical anchor [1000] at or after cutover block [1000]",
		},
		"security-v2 below C": {
			mode:            participation.ModeSecurityV2,
			anchor:          999,
			blockerFragment: "permit entry [0] claims mode [security_v2] with canonical anchor [999] before cutover block [1000]",
		},
		"zero canonical anchor": {
			mode:            participation.ModeLegacy,
			anchor:          0,
			blockerFragment: "permit entry [0] has zero canonical anchor under armed cutover block [1000]",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			permits := []quiescencePermitEvidence{{
				Ceremony: string(
					participation.TBTCSigning,
				),
				Mode:                test.mode.String(),
				CanonicalStartBlock: test.anchor,
				WorkID:              "wallet-action-boundary",
				PermitID:            "wallet-action-boundary",
				Outcome:             "completed",
			}}
			storageDir := newTestStorageWithQuiescencePermits(t, permits)
			firstPass, err := runAudit(
				storageDir,
				testPassword,
				evidenceInputs{},
				testExpectedIdentity(),
			)
			if err != nil {
				t.Fatal(err)
			}

			evidence := newValidEvidence(t, firstPass)
			updateQuiescenceReport(
				t,
				evidence,
				func(record *quiescenceReportEvidence) {
					setQuiescencePermits(record, permits)
				},
			)

			auditManifest, err := runAudit(
				storageDir,
				testPassword,
				evidence,
				testExpectedIdentity(),
			)
			if err != nil {
				t.Fatal(err)
			}

			if auditManifest.RollbackBarrierReady {
				t.Error(
					"a permit whose mode contradicts its canonical " +
						"anchor must not authorize the barrier",
				)
			}
			if !hasBlocker(auditManifest, test.blockerFragment) {
				t.Errorf(
					"expected cutover-arithmetic blocker [%s], blockers: %v",
					test.blockerFragment,
					auditManifest.RollbackBlockers,
				)
			}
		})
	}
}

// TestRunAudit_WrongExpectedReleaseEpochIsBlocking proves an expected release
// epoch differing from the audit build's own compiled epoch is a rollback
// blocker: the wrong audit tool cannot judge the audited state.
func TestRunAudit_WrongExpectedReleaseEpochIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	expected := testExpectedIdentity()
	expected.releaseEpoch = "some_other_epoch"

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		expected,
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("a wrong expected epoch must not authorize the barrier")
	}
	if !hasBlocker(
		auditManifest,
		"does not match this audit build's compiled epoch",
	) {
		t.Errorf(
			"expected a compiled-epoch blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

// TestRunAudit_MutableExpectedImageDigestIsBlocking proves an expected image
// reference that is not an immutable sha256 digest — a tag, a malformed
// digest — is a rollback blocker: a mutable reference cannot pin the
// artifact the rollback restores or leaves.
func TestRunAudit_MutableExpectedImageDigestIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	expected := testExpectedIdentity()
	expected.priorImageDigest = "keep-client:latest"
	expected.releaseImageDigest = "sha256:not-a-hex-digest"

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		expected,
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("a mutable image reference must not authorize the barrier")
	}
	if !hasBlocker(
		auditManifest,
		"the expected prior image digest [keep-client:latest] is not an "+
			"immutable sha256 image digest",
	) {
		t.Errorf(
			"expected a prior-digest blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
	if !hasBlocker(
		auditManifest,
		"the expected release image digest [sha256:not-a-hex-digest] is "+
			"not an immutable sha256 image digest",
	) {
		t.Errorf(
			"expected a release-digest blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

// TestRunAudit_MismatchedArtifactIdentityIsBlocking proves schema-valid
// evidence recording a different release artifact, prior image, or cutover
// block than the expected one blocks the barrier, and that quarantine
// metadata preserved under a different cutover block is a finding of its
// own.
func TestRunAudit_MismatchedArtifactIdentityIsBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The evidence records the artifact identities newValidEvidence writes;
	// the audit expects a different candidate build and cutover schedule.
	mismatched := testExpectedIdentity()
	mismatched.priorImageDigest = "sha256:" + strings.Repeat("44", 32)
	mismatched.releaseVersion = "v9.9.9"
	mismatched.releaseRevision = strings.Repeat("00", 20)
	mismatched.releaseImageDigest = "sha256:" + strings.Repeat("33", 32)
	mismatched.cutoverBlock = 2_000

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		newValidEvidence(t, firstPass),
		mismatched,
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("mismatched artifact identities must not authorize the barrier")
	}
	for _, fragment := range []string{
		"quiescing release version [v2.1.0], expected [v9.9.9]",
		"quiescing release revision",
		"quiesced under cutover block [1000], expected [2000]",
		"tested prior image digest",
		"writing release version [v2.1.0], expected [v9.9.9]",
		"writing release revision",
		"writing release image digest",
	} {
		if !hasBlocker(auditManifest, fragment) {
			t.Errorf(
				"expected the [%s] blocker, blockers: %v",
				fragment,
				auditManifest.RollbackBlockers,
			)
		}
	}
	if !hasFinding(
		auditManifest,
		"was preserved under cutover block [1000], not the expected "+
			"cutover block [2000]",
	) {
		t.Errorf(
			"expected a quarantine cutover-binding finding, findings: %v",
			auditManifest.Findings,
		)
	}
}

// TestRunAudit_DuplicateReconciliationEntriesAreBlocking proves duplicate
// wallet, wallet-ID, beacon-group, and schema-result entries in otherwise
// valid evidence are violations: duplicates cannot prove one-to-one coverage
// and can shadow a contradicting result.
func TestRunAudit_DuplicateReconciliationEntriesAreBlocking(t *testing.T) {
	storageDir := newTestStorage(t)

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)

	content, err := os.ReadFile(evidence.chainReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	chainRecord := &chainReconciliationEvidence{}
	if err := json.Unmarshal(content, chainRecord); err != nil {
		t.Fatal(err)
	}
	// Duplicate the persisted beacon group's entry, reconcile one fabricated
	// wallet twice, and claim its wallet ID from a second fabricated wallet.
	chainRecord.BeaconGroups = append(
		chainRecord.BeaconGroups,
		chainRecord.BeaconGroups[0],
	)
	walletEntry := tbtcWalletChainEvidence{
		WalletStorageKey: "duplicated-wallet",
		WalletID:         strings.Repeat("aa", 32),
		Registered:       false,
		DKGSettlement:    "none",
	}
	chainRecord.Wallets = append(chainRecord.Wallets, walletEntry, walletEntry)
	walletEntry.WalletStorageKey = "identity-thief-wallet"
	chainRecord.Wallets = append(chainRecord.Wallets, walletEntry)
	content, err = json.MarshalIndent(chainRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.chainReconciliation,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	content, err = os.ReadFile(evidence.priorReaderCompatibility)
	if err != nil {
		t.Fatal(err)
	}
	priorReaderRecord := &priorReaderCompatibilityEvidence{}
	if err := json.Unmarshal(content, priorReaderRecord); err != nil {
		t.Fatal(err)
	}
	// The duplicate contradicts the authoritative first result; it must be
	// rejected, not silently shadow it.
	priorReaderRecord.SchemaResults = append(
		priorReaderRecord.SchemaResults,
		struct {
			Schema     string `json:"schema"`
			Compatible bool   `json:"compatible"`
		}{Schema: requiredPriorReaderSchemas[0], Compatible: false},
	)
	content, err = json.MarshalIndent(priorReaderRecord, "", "  ")
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

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("duplicate reconciliation entries must not authorize the barrier")
	}
	for _, fragment := range []string{
		"beacon group [" +
			firstPass.BeaconActiveMemberships[0].GroupPublicKey +
			"] is reconciled more than once",
		"tbtc wallet [duplicated-wallet] is reconciled more than once",
		"is claimed by both tbtc wallet [duplicated-wallet] and tbtc " +
			"wallet [identity-thief-wallet]",
		"schema [" + requiredPriorReaderSchemas[0] + "] is covered more " +
			"than once",
	} {
		if !hasBlocker(auditManifest, fragment) {
			t.Errorf(
				"expected the [%s] blocker, blockers: %v",
				fragment,
				auditManifest.RollbackBlockers,
			)
		}
	}
}

// TestRunAudit_QuarantinedUnsettledOrMisidentifiedWalletIsBlocking proves a
// quarantined-only tBTC wallet whose reconciled DKG settlement is anything
// but an explicit no-result state — or whose reconciled wallet ID differs
// from the preserved output's identity — blocks the barrier: an unsettled
// result may still hand the prior binary a wallet whose share exists only in
// quarantine, and evidence for a different wallet proves nothing about this
// one.
func TestRunAudit_QuarantinedUnsettledOrMisidentifiedWalletIsBlocking(
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
			`"protocol_mode":"legacy",`+
			`"cutover_block":1000,`+
			`"canonical_start_block":900,`+
			`"ceremony":"tbtc_dkg",`+
			`"seed_hash":"aa",`+
			`"member_index":3,`+
			`"wallet_id":"bb",`+
			`"wallet_public_key_hash":"cc",`+
			`"failed_operation":"tbtc_dkg_signer_activation",`+
			`"last_observed_block":950,`+
			`"preserved_at":"2026-01-01T00:00:00Z"}`),
		"interrupted-wallet-directory",
		"/metadata_3",
	); err != nil {
		t.Fatal(err)
	}

	firstPass, err := runAudit(
		storageDir,
		testPassword,
		evidenceInputs{},
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	evidence := newValidEvidence(t, firstPass)

	content, err := os.ReadFile(evidence.chainReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	chainRecord := &chainReconciliationEvidence{}
	if err := json.Unmarshal(content, chainRecord); err != nil {
		t.Fatal(err)
	}
	// The quarantined wallet's result is reported as still pending, under a
	// wallet ID that is not the preserved output's identity.
	for i := range chainRecord.Wallets {
		if chainRecord.Wallets[i].WalletStorageKey ==
			"interrupted-wallet-directory" {
			chainRecord.Wallets[i].DKGSettlement = "pending"
			chainRecord.Wallets[i].WalletID = "ff"
		}
	}
	content, err = json.MarshalIndent(chainRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		evidence.chainReconciliation,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	auditManifest, err := runAudit(
		storageDir,
		testPassword,
		evidence,
		testExpectedIdentity(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if auditManifest.RollbackBarrierReady {
		t.Error("an unsettled quarantined wallet must not authorize the barrier")
	}
	if !hasBlocker(
		auditManifest,
		"quarantined tbtc wallet [interrupted-wallet-directory] has DKG "+
			"settlement [pending], expected [none]",
	) {
		t.Errorf(
			"expected a settlement blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
	if !hasBlocker(
		auditManifest,
		"quarantined tbtc wallet [interrupted-wallet-directory] is "+
			"reconciled under wallet ID [ff], but its preserved output "+
			"carries wallet ID [bb]",
	) {
		t.Errorf(
			"expected a wallet-identity blocker, blockers: %v",
			auditManifest.RollbackBlockers,
		)
	}
}

// addTestInactivityClaimedReceipt appends an authenticated receipt carrying a
// real ABI-encoded InactivityClaimed log for the given wallet and nonce, then
// re-attests and re-signs the record. The log is built from the generated
// WalletRegistry ABI so the audit's decode path is exercised against the exact
// bytes the contract emits.
func addTestInactivityClaimedReceipt(
	t *testing.T,
	record *chainReconciliationEvidence,
	address string,
	walletID [32]byte,
	nonce *big.Int,
	blockNumber uint64,
) {
	t.Helper()

	parsed, err := ecdsaabi.WalletRegistryMetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	event, ok := parsed.Events["InactivityClaimed"]
	if !ok {
		t.Fatal("generated WalletRegistry ABI has no InactivityClaimed event")
	}

	data, err := event.Inputs.NonIndexed().Pack(
		nonce,
		common.HexToAddress(testWalletRegistryAddress),
	)
	if err != nil {
		t.Fatal(err)
	}

	transactionHash := fmt.Sprintf("0x%064x", blockNumber*7+3)
	record.Receipts = append(record.Receipts, ethereumReceiptEvidence{
		TransactionHash:  transactionHash,
		BlockHash:        testCanonicalEthereumBlockHash(blockNumber),
		BlockNumber:      blockNumber,
		TransactionIndex: uint64(len(record.Receipts)),
		Status:           1,
		Logs: []ethereumRawLogEvidence{
			{
				Address: address,
				Topics: []string{
					strings.ToLower(event.ID.Hex()),
					"0x" + hex.EncodeToString(walletID[:]),
				},
				Data:     "0x" + hex.EncodeToString(data),
				LogIndex: 0,
			},
		},
	})

	record.CollectorAttestation.CanonicalBlocks = append(
		record.CollectorAttestation.CanonicalBlocks,
		ethereumCanonicalBlockEvidence{
			BlockNumber: blockNumber,
			BlockHash:   testCanonicalEthereumBlockHash(blockNumber),
		},
	)
	sort.Slice(
		record.CollectorAttestation.CanonicalBlocks,
		func(i, j int) bool {
			return record.CollectorAttestation.CanonicalBlocks[i].BlockNumber <
				record.CollectorAttestation.CanonicalBlocks[j].BlockNumber
		},
	)
	resignTestChainReconciliationEvidence(t, record)
}

// TestValidateChainReconciliationEvidence_InactivityClaimSettlement asserts a
// penalty a heartbeat filed is reconciled against the WalletRegistry rather
// than accepted on the node's own record. The claim runs under the heartbeat's
// permit and leaves no separate journal entry, so an unobserved or fabricated
// settlement must block the barrier instead of clearing it.
func TestValidateChainReconciliationEvidence_InactivityClaimSettlement(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	walletID := [32]byte{
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
		0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
	}
	const claimBlock = uint64(9_000)
	nonce := big.NewInt(17)

	settledReference, err := participation.InactivityClaimSettlementReference(
		walletID[:],
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}

	// A tBTC permit names itself with the wallet public key hash, which is what
	// the snapshot's own signer material resolves to the registry wallet ID.
	walletPublicKeyHash := strings.Repeat("ab", 20)

	permit := participation.PermitSnapshot{
		Ceremony:            participation.TBTCHeartbeat,
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: 8_000,
		WorkID:              strings.Repeat("d", 64),
		PermitID:            walletPublicKeyHash,
		IdentityBound:       true,
	}

	newRunAndRecord := func(
		settlement *participation.ChainSettlementRecord,
	) (*auditRun, *chainReconciliationEvidence) {
		auditManifest := &manifest{
			GeneratedAt: time.Now().UTC(),
			Snapshot: snapshotIdentity{
				AggregateSHA256: strings.Repeat("c", 64),
			},
			TBTCActiveWallets: []tbtcWalletRecord{
				{
					WalletStorageKey:    strings.Repeat("f", 40),
					WalletID:            hex.EncodeToString(walletID[:]),
					WalletPublicKeyHash: walletPublicKeyHash,
					MemberIndexes:       []uint8{1},
					SigningGroupSize:    1,
				},
			},
			QuiescenceSnapshot: &participation.QuiescenceSnapshot{
				SchemaVersion: participation.QuiescenceSnapshotSchemaVersion,
				CapturedAt:    capturedAt,
				ActivePermits: []participation.PermitSnapshot{permit},
			},
			ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
				SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
				SnapshotCapturedAt: capturedAt,
				Outcomes: []participation.TerminalOutcomeRecord{
					{
						RecordedAt: time.Now().UTC(),
						Permit:     permit,
						Outcome:    participation.TerminalOutcomeCompleted,
						Evidence: participation.TerminalEvidence{
							Kind:            participation.TerminalEvidenceProtocolResult,
							Reference:       strings.Repeat("e", 64),
							ChainSettlement: settlement,
						},
					},
				},
			},
		}
		run := &auditRun{
			manifest: auditManifest,
			expected: expectedIdentityInputs{
				ethereumChainID:              "1",
				walletRegistryAddress:        testWalletRegistryAddress,
				finalizedEthereumBlockNumber: testFinalizedEthereumBlock,
				finalizedEthereumBlockHash: testCanonicalEthereumBlockHash(
					testFinalizedEthereumBlock,
				),
				chainEvidencePublicKey: testChainEvidencePublicKey(),
				maxEvidenceAge:         time.Hour,
			},
		}
		record := &chainReconciliationEvidence{
			evidenceEnvelope: evidenceEnvelope{
				SchemaVersion:           evidenceSchemaVersion,
				EvidenceType:            "chain_reconciliation",
				GeneratedAt:             auditManifest.GeneratedAt,
				SnapshotAggregateSHA256: auditManifest.Snapshot.AggregateSHA256,
			},
			EthereumChainID: "1",
		}
		authenticateTestChainReconciliationEvidence(t, record)
		return run, record
	}

	validate := func(
		t *testing.T,
		run *auditRun,
		record *chainReconciliationEvidence,
	) []string {
		t.Helper()

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return run.validateChainReconciliationEvidence(content)
	}

	// The negative cases below differ from the passing one only in the
	// settlement or the claim log, so requiring the reason pins each failure to
	// the reconciliation instead of to some unrelated envelope defect.
	assertBlockedBy := func(t *testing.T, violations []string, reason string) {
		t.Helper()

		for _, violation := range violations {
			if strings.Contains(violation, reason) {
				return
			}
		}
		t.Fatalf(
			"expected a violation containing [%s], got: %v",
			reason,
			violations,
		)
	}

	// The wallet these outcomes punish is present only to identify itself, not
	// to be reconciled as persisted state, so the coverage that persisted
	// wallets owe the chain evidence is another test's subject. The passing
	// cases assert only that the settlement reconciliation itself is silent.
	assertSettles := func(t *testing.T, violations []string) {
		t.Helper()

		for _, violation := range violations {
			if strings.Contains(violation, "inactivity claim") {
				t.Fatalf(
					"expected a corroborated settlement to reconcile, got: %s",
					violation,
				)
			}
		}
	}

	t.Run("settlement corroborated by a canonical claim log", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			walletID,
			nonce,
			claimBlock,
		)
		assertSettles(t, validate(t, run, record))
	})

	t.Run("submission whose settlement stayed unresolved", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind: participation.ChainSettlementInactivityClaim,
		})
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			walletID,
			nonce,
			claimBlock,
		)
		// Even with the claim present on chain, an unresolved submission is
		// unreconciled: the node cannot say the log it never resolved is its
		// own.
		assertBlockedBy(
			t,
			validate(t, run, record),
			"could not resolve",
		)
	})

	// The check that keeps a real penalty from being borrowed: the log is
	// authentic, canonical, and emitted by the expected registry — it just
	// punishes a different wallet than the permit is about. Corroboration
	// alone cannot tell those apart, because every real claim on the chain
	// corroborates equally.
	t.Run("valid claim log belonging to another wallet", func(t *testing.T) {
		otherWalletID := walletID
		otherWalletID[0] ^= 0xff

		borrowedReference, err := participation.
			InactivityClaimSettlementReference(otherWalletID[:], nonce)
		if err != nil {
			t.Fatal(err)
		}

		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: borrowedReference,
		})
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			otherWalletID,
			nonce,
			claimBlock,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"reports settling inactivity claim",
		)
	})

	// A penalty against a wallet this node holds no key material for is not a
	// claim its heartbeat could have filed, so it cannot be bound and must not
	// pass on the corroborating log alone.
	t.Run("permit naming a wallet the snapshot does not hold", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		run.manifest.TBTCActiveWallets = nil
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			walletID,
			nonce,
			claimBlock,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"holds no signer material identifying that wallet",
		)
	})

	// Quarantined material identifies the punished wallet just as well: a
	// rollback that quarantines a signer does not unmake the penalty its
	// heartbeat filed.
	t.Run("permit bound through quarantined material", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		run.manifest.TBTCActiveWallets = nil
		run.manifest.TBTCQuarantinedOutputs = []tbtcQuarantineRecord{
			{
				WalletStorageKey:          strings.Repeat("f", 40),
				SignerWalletID:            hex.EncodeToString(walletID[:]),
				SignerWalletPublicKeyHash: walletPublicKeyHash,
				HasMembershipRecord:       true,
			},
		}
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			walletID,
			nonce,
			claimBlock,
		)
		assertSettles(t, validate(t, run, record))
	})

	t.Run("settlement with no matching claim log", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated WalletRegistry InactivityClaimed log",
		)
	})

	t.Run("claim log at a different nonce", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			walletID,
			new(big.Int).Add(nonce, big.NewInt(1)),
			claimBlock,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated WalletRegistry InactivityClaimed log",
		)
	})

	t.Run("claim log for a different wallet", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		otherWalletID := walletID
		otherWalletID[0] ^= 0xff
		addTestInactivityClaimedReceipt(
			t,
			record,
			testWalletRegistryAddress,
			otherWalletID,
			nonce,
			claimBlock,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated WalletRegistry InactivityClaimed log",
		)
	})

	t.Run("claim log from an unrelated contract", func(t *testing.T) {
		run, record := newRunAndRecord(&participation.ChainSettlementRecord{
			Kind:      participation.ChainSettlementInactivityClaim,
			Reference: settledReference,
		})
		addTestInactivityClaimedReceipt(
			t,
			record,
			"0x2222222222222222222222222222222222222222",
			walletID,
			nonce,
			claimBlock,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated WalletRegistry InactivityClaimed log",
		)
	})
}
