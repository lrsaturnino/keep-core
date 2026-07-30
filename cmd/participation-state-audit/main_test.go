package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/bls"
	"github.com/keep-network/keep-core/pkg/chain"
	beaconabi "github.com/keep-network/keep-core/pkg/chain/ethereum/beacon/gen/abi"
	ecdsaabi "github.com/keep-network/keep-core/pkg/chain/ethereum/ecdsa/gen/abi"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/storage"
)

const testPassword = "audit-test-password"

const (
	testWalletRegistryAddress       = "0x1111111111111111111111111111111111111111"
	testRandomBeaconAddress         = "0x3333333333333333333333333333333333333333"
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
		Signer:      newTestSigner(t, group.MemberIndex(1), testActiveGroupSecret),
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
	if _, err := quarantine.Preserve(
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
				OperatedMembers: testOperatedMembers(
					participation.Ceremony(permit.Ceremony),
					permit.PermitID,
				),
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
			t,
			permit,
			participation.PermitSnapshot{
				Ceremony:            participation.Ceremony(permit.Ceremony),
				Mode:                permit.Mode,
				CanonicalStartBlock: permit.CanonicalStartBlock,
				WorkID:              permit.WorkID,
				PermitID:            permit.PermitID,
				IdentityBound:       true,
				OperatedMembers: testOperatedMembers(
					participation.Ceremony(permit.Ceremony),
					permit.PermitID,
				),
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

// testPermitSeat reports the seat a per-seat ceremony names in its own permit
// identity, and zero for the permits that name none. A DKG member, a beacon
// group member and a relay signing membership each run one seat under one
// permit, so the identity is where their seat lives.
func testPermitSeat(
	ceremony participation.Ceremony,
	permitID string,
) group.MemberIndex {
	switch ceremony {
	case participation.TBTCDKG,
		participation.BeaconDKG,
		participation.BeaconRelaySigning:
	default:
		return 0
	}

	seat, err := strconv.ParseUint(permitID, 10, 8)
	if err != nil || seat == 0 {
		return 0
	}

	return group.MemberIndex(seat)
}

// testOperatedMembers renders the seats a fixture permit's holder operates, as
// the production node names them at issuance. The per-seat ceremonies take
// theirs from the permit identity; a wallet action takes the seat its transcript
// is written for; and the permits that operate none — a forwarder, a timeout
// monitor — name none.
func testOperatedMembers(
	ceremony participation.Ceremony,
	permitID string,
) participation.MemberIndexes {
	switch ceremony {
	case participation.BeaconRelayForwarding,
		participation.BeaconTimeoutReport:
		return nil
	}

	if seat := testPermitSeat(ceremony, permitID); seat != 0 {
		return participation.MemberIndexes{seat}
	}

	return participation.MemberIndexes{group.MemberIndex(1)}
}

// testTranscriptContribution renders the transcript a completed outcome of the
// given ceremony must carry, and nil for the ceremonies whose owners author
// none. The local membership is the one the record persists, so the two halves
// of the fixture describe one ceremony and a test that means to break the
// binding has to say so.
// testTranscriptContribution renders the transcript a completed outcome must
// carry. permitSeat is the seat in the permits' own index space that produced the
// local membership; it is read only for the ceremonies whose record speaks in a
// different space than their permits, and 0 stands for "the same seat".
func testTranscriptContribution(
	ceremony participation.Ceremony,
	local group.MemberIndex,
	permitSeat group.MemberIndex,
) *participation.TranscriptContribution {
	if !participation.AuthorsTranscriptContribution(ceremony) {
		return nil
	}

	if local == 0 {
		local = group.MemberIndex(1)
	}

	incorporated := participation.MemberIndexes{local}
	for _, peer := range []group.MemberIndex{1, 2, 3} {
		if peer != local {
			incorporated = append(incorporated, peer)
		}
	}
	slices.Sort(incorporated)

	return &participation.TranscriptContribution{
		IncorporatedMembers: incorporated,
		LocalMembers:        participation.MemberIndexes{local},
		PermitSpaceMembers: testPermitSpaceMembers(
			ceremony,
			incorporated,
			local,
			permitSeat,
		),
	}
}

// testPermitSpaceMembers renders a mapping from a transcript's seats back to the
// index space this work's permits were issued in, placing permitSeat under local
// and running consecutively either side of it, and nil for the ceremonies whose
// result already speaks in the permits' space.
//
// permitSeat must leave room for the seats below local, which every fixture here
// satisfies. A mapping that does not is left malformed rather than quietly
// adjusted: the gate's own set validation then refuses it, which is the loud
// failure a fixture that cannot mean what it says deserves.
func testPermitSpaceMembers(
	ceremony participation.Ceremony,
	incorporated participation.MemberIndexes,
	local group.MemberIndex,
	permitSeat group.MemberIndex,
) participation.MemberIndexes {
	if ceremony != participation.TBTCDKG {
		return nil
	}
	if permitSeat == 0 {
		permitSeat = local
	}

	position := slices.Index(incorporated, local)
	mapping := make(participation.MemberIndexes, len(incorporated))
	for i := range mapping {
		mapping[i] = group.MemberIndex(int(permitSeat) + i - position)
	}

	return mapping
}

func testTerminalOutcomeRecord(
	t *testing.T,
	permit quiescencePermitEvidence,
	snapshot participation.PermitSnapshot,
	resultReference string,
	beaconSignerReference string,
) participation.TerminalOutcomeRecord {
	t.Helper()

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
		case participation.BeaconRelaySigning:
			// A relay entry answers exactly one request, and the audit holds
			// the record to the request its permit names, so the fixture
			// derives the request from the permit rather than picking one.
			requestStartBlock, err := participation.ParseBeaconRelayWorkID(
				snapshot.WorkID,
			)
			if err != nil {
				t.Fatalf(
					"relay fixture work identity [%s] names no relay "+
						"request: [%v]",
					snapshot.WorkID,
					err,
				)
			}
			evidence = participation.TerminalEvidence{
				Kind: participation.TerminalEvidenceProtocolResult,
				Reference: testRelayEntryReference(
					requestStartBlock,
					testActiveGroupSecret,
					resultReference,
				),
			}
		case participation.BeaconRelayForwarding:
			evidence = participation.TerminalEvidence{
				Kind: participation.TerminalEvidenceForwarderClosed,
			}
		}
		// The transcript's local seat is the seat the permit was issued for
		// wherever the two share an index space. tBTC DKG is the exception:
		// its permit names a DKG index while its transcript is in the final
		// signing group's, so there the persisted membership is the local seat
		// and the permit's own seat is what the transcript maps it back to.
		local := evidence.MembershipIndex
		permitSeat := testPermitSeat(snapshot.Ceremony, snapshot.PermitID)
		if snapshot.Ceremony != participation.TBTCDKG && permitSeat != 0 {
			local = permitSeat
		}
		evidence.Contribution = testTranscriptContribution(
			snapshot.Ceremony,
			local,
			permitSeat,
		)
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

// testActiveGroupSecret is the scalar behind the active beacon membership every
// test storage holds. The fixture group's public key is its base multiple, so a
// test can produce entries that genuinely verify under the group the snapshot
// decoded rather than merely well-formed ones.
const testActiveGroupSecret = int64(42)

// testFixtureSelectedGroupID is the registry index the fixture beacon selects
// for every relay request it logs. It is the index the group behind
// testActiveGroupSecret is registered under, since the audit refuses a
// completed entry whose key is not the one the selected index is bound to.
const testFixtureSelectedGroupID = uint64(1)

// testRelayEntryReference derives a relay entry identity from a fixture label,
// signed for real by the given group. Passing the group's own secret is what
// makes the reference survive the audit's signature verification: the check is
// a pairing over actual curve points, so a shaped-but-fabricated identity is
// exactly what it exists to reject.
func testRelayEntryReference(
	requestStartBlock uint64,
	groupSecret int64,
	label string,
) string {
	secret := big.NewInt(groupSecret)
	previousEntry := altbn128.G1HashToPoint([]byte(label))

	reference, err := participation.BeaconRelayEntryReference(
		requestStartBlock,
		altbn128.G2Point{
			G2: new(bn256.G2).ScalarBaseMult(secret),
		}.Compress(),
		previousEntry.Marshal(),
		bls.SignG1(secret, previousEntry).Marshal(),
	)
	if err != nil {
		panic(err)
	}

	return reference
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
				OperatedMembers: testOperatedMembers(
					participation.Ceremony(expected.Ceremony),
					expected.PermitID,
				),
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
			t,
			permits[i],
			participation.PermitSnapshot{
				Ceremony:            permit.Ceremony(),
				Mode:                permit.Mode().String(),
				CanonicalStartBlock: permit.CanonicalStartBlock(),
				WorkID:              permit.WorkID(),
				PermitID:            permit.PermitID(),
				IdentityBound:       true,
				OperatedMembers: testOperatedMembers(
					permit.Ceremony(),
					permit.PermitID(),
				),
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
	record.RandomBeaconAddress = testRandomBeaconAddress
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
// testRelayRequestID derives the beacon request identifier a fixture request
// carries from the block it was made in. One request per block is what the
// fixtures model, so the block identifies the request as well as the beacon's
// own counter would.
func testRelayRequestID(requestStartBlock uint64) *big.Int {
	return new(big.Int).SetUint64(requestStartBlock*1_000 + 7)
}

// addTestBeaconRelayLogs appends the RandomBeacon logs the chain reconciliation
// needs to corroborate every beacon relay outcome the manifest's journal
// records as completed: the request each recovered entry answers, and the
// termination each accepted timeout report earned.
//
// The audit reads a relay result as this permit's only when the beacon's own
// request log sits in the permit's block over the entry it signs over, so a
// fixture that omits the log describes a node whose result answers no request
// the beacon ever made.
func addTestBeaconRelayLogs(
	t *testing.T,
	record *chainReconciliationEvidence,
	auditManifest *manifest,
) {
	t.Helper()

	if auditManifest.ParticipationTerminalOutcomes == nil {
		return
	}

	// Memberships of one request legitimately share it, so each request is
	// logged once however many outcomes name it.
	requested := make(map[string]struct{})
	addRequest := func(startBlock uint64, previousEntry []byte) {
		t.Helper()

		identity := relayEntryIdentity(startBlock, previousEntry)
		if _, done := requested[identity]; done {
			return
		}
		requested[identity] = struct{}{}

		addTestRelayEntryReceipt(
			t,
			record,
			testRandomBeaconAddress,
			"RelayEntryRequested",
			testRelayRequestID(startBlock),
			startBlock,
			testFixtureSelectedGroupID,
			previousEntry,
		)
	}

	// Every request above selects the one group these fixtures sign under, and
	// the audit holds a completed entry to the key that group is registered
	// against, so the registration has to be in the bundle for a corroborated
	// entry to settle at all. One registration covers every request: the
	// receipt is the group's, not the round's.
	registered := false
	registerSigningGroup := func() {
		t.Helper()

		if registered {
			return
		}
		registered = true

		addTestGroupRegisteredReceipt(
			t,
			record,
			testRandomBeaconAddress,
			testFixtureSelectedGroupID,
			new(bn256.G2).ScalarBaseMult(
				big.NewInt(testActiveGroupSecret),
			).Marshal(),
			uint64(1),
		)
	}

	for _, outcome := range auditManifest.ParticipationTerminalOutcomes.Outcomes {
		if outcome.Outcome != participation.TerminalOutcomeCompleted {
			continue
		}
		switch outcome.Permit.Ceremony {
		case participation.BeaconRelaySigning:
			startBlock, _, previousEntry, _, err := participation.
				ParseBeaconRelayEntryReference(outcome.Evidence.Reference)
			if err != nil {
				continue
			}
			addRequest(startBlock, previousEntry)
			registerSigningGroup()
		case participation.BeaconTimeoutReport:
			startBlock, requestID, terminatedGroupID, err := participation.
				ParseBeaconRelayTimeoutSettlementReference(
					outcome.Evidence.Reference,
				)
			if err != nil {
				continue
			}
			// A terminated request signs over a previous entry like any
			// other, but no permit record names it, so the fixture supplies a
			// point of its own rather than deriving one.
			addTestRelayEntryReceipt(
				t,
				record,
				testRandomBeaconAddress,
				"RelayEntryRequested",
				requestID,
				startBlock,
				uint64(1),
				new(bn256.G1).ScalarBaseMult(
					new(big.Int).SetUint64(startBlock+1),
				).Marshal(),
			)
			addTestRelayEntryReceipt(
				t,
				record,
				testRandomBeaconAddress,
				"RelayEntryTimedOut",
				requestID,
				startBlock+1,
				terminatedGroupID,
			)
		}
	}
}

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
	addTestBeaconRelayLogs(t, chainRecord, auditManifest)

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
					if terminal.Permit.Equal(permit) {
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
		randomBeaconAddress:          testRandomBeaconAddress,
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
	if _, err := quarantine.Preserve(
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
	if _, err := quarantine.Preserve(
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
		"expected WalletRegistry address is not supplied",
		"expected RandomBeacon address is not supplied",
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
		ethereumChainID:       "11155111",
		walletRegistryAddress: "0x0000000000000000000000000000000000000001",
		randomBeaconAddress:   "0x0000000000000000000000000000000000000002",
		bitcoinNetwork:        "testnet",
		priorVersion:          "v1.9.9",
		priorRevision:         strings.Repeat("cd", 20),
		maxEvidenceAge:        24 * time.Hour,
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
		"the WalletRegistry address [" + testWalletRegistryAddress + "]",
		"the RandomBeacon address [" + testRandomBeaconAddress + "]",
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
			WorkID:              participation.BeaconRelayWorkID(1),
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
			WorkID:              participation.BeaconRelayWorkID(1_000),
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

// TestValidateNodeTerminalOutcomes_OperatedMembershipsAreReconciled proves the
// offline audit holds a permit's operated seats to both records that carry them.
//
// The seats are fixed at issuance and copied into two places: the gate snapshot
// captured while the permit was live, and the journal record written when it
// closed. A reader building a fleet seat ownership map picks one of the two, and
// nothing else in either record constrains the field — an entry whose seats were
// widened, narrowed, or reassigned after the fact still names a real ceremony, a
// real permit and a real outcome. So the audit reconciles the two copies against
// each other, holds each to the shape its ceremony can have, and holds the
// transcript to the copy it travelled with.
func TestValidateNodeTerminalOutcomes_OperatedMembershipsAreReconciled(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)
	workID := strings.Repeat("d", 64)

	// Two DKG seats of one ceremony, both surviving into a two-member final
	// group: DKG seat 2 holds final seat 1 and DKG seat 3 holds final seat 2.
	newPermit := func(
		permitID string,
		operated participation.MemberIndexes,
	) participation.PermitSnapshot {
		return participation.PermitSnapshot{
			Ceremony:            participation.TBTCDKG,
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              workID,
			PermitID:            permitID,
			IdentityBound:       true,
			OperatedMembers:     operated,
		}
	}
	newRecord := func(
		permit participation.PermitSnapshot,
		membership group.MemberIndex,
		permitSeat group.MemberIndex,
	) participation.TerminalOutcomeRecord {
		return participation.TerminalOutcomeRecord{
			RecordedAt: time.Now().UTC(),
			Permit:     permit,
			Outcome:    participation.TerminalOutcomeCompleted,
			Evidence: participation.TerminalEvidence{
				Kind:            participation.TerminalEvidencePersistedTBTCSinger,
				Reference:       "wallet-storage-key",
				MembershipIndex: membership,
				Contribution: testTranscriptContribution(
					participation.TBTCDKG,
					membership,
					permitSeat,
				),
			},
		}
	}
	newManifest := func(
		inventory []participation.PermitSnapshot,
		outcomes []participation.TerminalOutcomeRecord,
	) *manifest {
		return &manifest{
			QuiescenceSnapshot: &participation.QuiescenceSnapshot{
				SchemaVersion: participation.QuiescenceSnapshotSchemaVersion,
				CapturedAt:    capturedAt,
				ActivePermits: inventory,
			},
			ParticipationTerminalOutcomes: &participation.TerminalOutcomeJournal{
				SchemaVersion:      participation.TerminalOutcomeJournalSchemaVersion,
				SnapshotCapturedAt: capturedAt,
				Outcomes:           outcomes,
			},
			TBTCActiveWallets: []tbtcWalletRecord{
				{
					WalletStorageKey: "wallet-storage-key",
					WalletID:         "wallet-id",
					MemberIndexes:    []uint8{1, 2},
					SigningGroupSize: 2,
				},
			},
		}
	}

	honestFirst := newPermit("2", participation.MemberIndexes{2})
	honestSecond := newPermit("3", participation.MemberIndexes{3})
	honestInventory := []participation.PermitSnapshot{honestFirst, honestSecond}

	// The baseline both sides agree on, so a mutation below is the only reason
	// any of these findings can appear.
	baseline := validateNodeTerminalOutcomes(newManifest(
		honestInventory,
		[]participation.TerminalOutcomeRecord{
			newRecord(honestFirst, group.MemberIndex(1), group.MemberIndex(2)),
			newRecord(honestSecond, group.MemberIndex(2), group.MemberIndex(3)),
		},
	))
	for _, violation := range baseline {
		if strings.Contains(violation, "operated membership") ||
			strings.Contains(violation, "outside its permit") {
			t.Errorf(
				"a journal agreeing with its own gate inventory was refused: [%s]",
				violation,
			)
		}
	}

	tests := map[string]struct {
		inventory       []participation.PermitSnapshot
		outcomes        []participation.TerminalOutcomeRecord
		expectedFinding string
	}{
		// A schema-1 snapshot carries no operated seats at all, so a journal
		// that names them is the only account of them and there is nothing left
		// to reconcile it against.
		"the gate inventory carries no operated seats": {
			inventory: []participation.PermitSnapshot{
				newPermit("2", nil),
				newPermit("3", nil),
			},
			outcomes: []participation.TerminalOutcomeRecord{
				newRecord(honestFirst, group.MemberIndex(1), group.MemberIndex(2)),
				newRecord(honestSecond, group.MemberIndex(2), group.MemberIndex(3)),
			},
			expectedFinding: "but the at-quiescence gate inventory issued the same permit",
		},
		"the journal widened one permit's operated seats": {
			inventory: honestInventory,
			outcomes: []participation.TerminalOutcomeRecord{
				newRecord(
					newPermit("2", participation.MemberIndexes{2, 3}),
					group.MemberIndex(1),
					group.MemberIndex(2),
				),
				newRecord(honestSecond, group.MemberIndex(2), group.MemberIndex(3)),
			},
			expectedFinding: "but the at-quiescence gate inventory issued the same permit",
		},
		// The same edit applied to both copies passes the reconciliation above,
		// so the shape its ceremony can have has to be reapplied to each.
		"both copies claim a second seat for a one-seat ceremony": {
			inventory: []participation.PermitSnapshot{
				newPermit("2", participation.MemberIndexes{2, 3}),
				honestSecond,
			},
			outcomes: []participation.TerminalOutcomeRecord{
				newRecord(
					newPermit("2", participation.MemberIndexes{2, 3}),
					group.MemberIndex(1),
					group.MemberIndex(2),
				),
				newRecord(honestSecond, group.MemberIndex(2), group.MemberIndex(3)),
			},
			expectedFinding: "runs one seat per permit",
		},
		"both copies claim a seat that is not the permit's own": {
			inventory: []participation.PermitSnapshot{
				newPermit("2", participation.MemberIndexes{4}),
				honestSecond,
			},
			outcomes: []participation.TerminalOutcomeRecord{
				newRecord(
					newPermit("2", participation.MemberIndexes{4}),
					group.MemberIndex(1),
					group.MemberIndex(4),
				),
				newRecord(honestSecond, group.MemberIndex(2), group.MemberIndex(3)),
			},
			expectedFinding: "runs one seat per permit",
		},
		"both copies carry a malformed operated set": {
			inventory: []participation.PermitSnapshot{
				newPermit("2", participation.MemberIndexes{2, 2}),
				honestSecond,
			},
			outcomes: []participation.TerminalOutcomeRecord{
				newRecord(
					newPermit("2", participation.MemberIndexes{2, 2}),
					group.MemberIndex(1),
					group.MemberIndex(2),
				),
				newRecord(honestSecond, group.MemberIndex(2), group.MemberIndex(3)),
			},
			expectedFinding: "operated memberships",
		},
		// The persisted memberships swapped under one shared, honest mapping.
		// This is the swap a reader of the raw seat numbers cannot see and the
		// mapping makes local: final seat 2 was produced by DKG seat 3, which is
		// not the seat this permit was issued to operate.
		"the persisted memberships were swapped under one mapping": {
			inventory: honestInventory,
			outcomes: []participation.TerminalOutcomeRecord{
				newRecord(honestFirst, group.MemberIndex(2), group.MemberIndex(3)),
				newRecord(honestSecond, group.MemberIndex(1), group.MemberIndex(2)),
			},
			expectedFinding: "which is not among the memberships",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			violations := validateNodeTerminalOutcomes(
				newManifest(test.inventory, test.outcomes),
			)
			if !containsSubstring(violations, test.expectedFinding) {
				t.Fatalf(
					"expected an operated-membership violation containing "+
						"[%s], got: %v",
					test.expectedFinding,
					violations,
				)
			}
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
			Contribution: testTranscriptContribution(
				participation.TBTCSigning,
				group.MemberIndex(1),
				group.MemberIndex(1),
			),
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
			OperatedMembers:     participation.MemberIndexes{2},
		},
		{
			Ceremony:            participation.TBTCDKG,
			Mode:                participation.ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              seedHash,
			PermitID:            "3",
			IdentityBound:       true,
			OperatedMembers:     participation.MemberIndexes{3},
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
							// Each record maps its own final seat back to the
							// DKG seat its own permit was issued for, so the
							// journal is internally consistent whichever way the
							// two persisted memberships are assigned. The two
							// mappings then disagree about how one final group
							// was rebuilt, and only the accepted result on chain
							// says which of them is the real one.
							Contribution: testTranscriptContribution(
								participation.TBTCDKG,
								firstMembership,
								group.MemberIndex(2),
							),
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
							Contribution: testTranscriptContribution(
								participation.TBTCDKG,
								secondMembership,
								group.MemberIndex(3),
							),
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
				randomBeaconAddress:          testRandomBeaconAddress,
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

	// The seat map is one statement about every seat of the final group, not
	// only about the one its author sat in. A rewrite that leaves the author's
	// own entry alone, and the length alone, satisfies every other check here:
	// the seed, the anchor and the persisted membership all still agree, the
	// author's operated seat still maps to its own final seat, and the map is
	// still an ascending set of the right size. What it changes is who the other
	// final seats belonged to — and a fleet-wide ownership map translated through
	// it hands those seats to original members that never held them, which reads
	// afterwards as seats some other release supplied.
	t.Run("rewritten remote seat mapping", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		outcome := &run.manifest.ParticipationTerminalOutcomes.Outcomes[0]
		mapping := outcome.Evidence.Contribution.PermitSpaceMembers
		if !slices.Equal(
			mapping,
			participation.MemberIndexes{2, 3, 4},
		) {
			t.Fatalf(
				"fixture no longer maps the canonical survivors, got: %v",
				mapping,
			)
		}
		// Only the last entry moves. The author sits in final seat 1, so its own
		// mapping is the first entry and is left exactly as it was.
		mapping[len(mapping)-1] = group.MemberIndex(5)

		// Everything the audit checked before this still passes, which is what
		// makes the rewrite worth refusing rather than a shape error.
		if violations := validateNodeTerminalOutcomes(run.manifest); len(violations) != 0 {
			t.Fatalf(
				"expected a rewritten remote entry to survive node-local "+
					"validation, got: %v",
				violations,
			)
		}

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"maps its final signing group back to original members [2 3 5], "+
				"but canonical result ["+resultHash+"] leaves survivors [2 3 4]",
		) {
			t.Fatalf(
				"expected a rewritten-seat-map violation, got: %v",
				violations,
			)
		}
	})

	// And the other half of the same map. A record naming a final group the
	// accepted result did not rebuild describes a different ceremony, however
	// well its own seat lines up inside it.
	t.Run("final signing group the result did not rebuild", func(t *testing.T) {
		run, record := newRunAndRecord(
			group.MemberIndex(1),
			group.MemberIndex(2),
			canonicalSeed,
		)
		contribution := run.manifest.
			ParticipationTerminalOutcomes.Outcomes[0].Evidence.Contribution
		contribution.IncorporatedMembers = participation.MemberIndexes{1, 2}
		contribution.PermitSpaceMembers = participation.MemberIndexes{2, 3}

		content, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		violations := run.validateChainReconciliationEvidence(content)
		if !containsSubstring(
			violations,
			"names final signing group [1 2], but canonical result ["+
				resultHash+"] rebuilds group [1 2 3] from its 3 accepted members",
		) {
			t.Fatalf(
				"expected a rebuilt-group violation, got: %v",
				violations,
			)
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
			WorkID:              participation.BeaconRelayWorkID(1_000),
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

// TestValidateRelayEntryTerminalResult asserts a beacon relay outcome is
// checked rather than believed.
//
// This is the one node-authored protocol result the offline audit can verify
// outright: a relay entry is a threshold BLS signature by the group over the
// previous entry, so the pairing itself decides. Anything a node could author
// alone — an entry it invented, an entry lifted from another group, an entry
// re-pointed at a different previous entry — fails that check, and a group the
// snapshot holds no membership of says nothing about what this node did even
// when its signature is genuine.
func TestValidateRelayEntryTerminalResult(t *testing.T) {
	const (
		heldGroupSecret    = int64(42)
		foreignGroupSecret = int64(77)
	)

	const requestStartBlock = uint64(1_000)

	heldGroupKey := hex.EncodeToString(
		altbn128.G2Point{
			G2: new(bn256.G2).ScalarBaseMult(big.NewInt(heldGroupSecret)),
		}.Compress(),
	)
	beaconGroupKeys := map[string]struct{}{heldGroupKey: {}}

	// reference renders an entry the given group really signed over the given
	// previous entry, answering the given request, so only the deliberate
	// mismatches below are wrong.
	reference := func(
		t *testing.T,
		requestStartBlock uint64,
		groupSecret int64,
		signingSecret int64,
		previousEntryLabel string,
		namedPreviousEntryLabel string,
	) string {
		t.Helper()

		signed := altbn128.G1HashToPoint([]byte(previousEntryLabel))
		named := altbn128.G1HashToPoint([]byte(namedPreviousEntryLabel))

		rendered, err := participation.BeaconRelayEntryReference(
			requestStartBlock,
			altbn128.G2Point{
				G2: new(bn256.G2).ScalarBaseMult(big.NewInt(groupSecret)),
			}.Compress(),
			named.Marshal(),
			bls.SignG1(big.NewInt(signingSecret), signed).Marshal(),
		)
		if err != nil {
			t.Fatal(err)
		}

		return rendered
	}

	tests := map[string]struct {
		workID    string
		reference func(t *testing.T) string
		valid     bool
	}{
		"an entry the named group signed over the named previous entry": {
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock, heldGroupSecret, heldGroupSecret, "seed", "seed")
			},
			valid: true,
		},
		// The forgery the check exists for: a node naming a group it belongs
		// to and an entry that group never produced.
		"an entry signed by nobody's threshold key": {
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock, heldGroupSecret, foreignGroupSecret, "seed", "seed")
			},
		},
		// A genuine signature re-pointed at a previous entry it was not made
		// over would let one relay round's result settle another's permit.
		"a genuine entry over a different previous entry": {
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock, heldGroupSecret, heldGroupSecret, "seed", "other-seed")
			},
		},
		// Genuine and self-consistent, but produced by a group this snapshot
		// has no membership of, so it reports nothing about this node.
		"a genuine entry of a group the snapshot does not hold": {
			reference: func(t *testing.T) string {
				return reference(
					t,
					requestStartBlock,
					foreignGroupSecret,
					foreignGroupSecret,
					"seed",
					"seed",
				)
			},
		},
		// The replay the request binding exists for: an entry this node's
		// group really produced, for a request this permit was not issued
		// for. The signature is genuine and stays genuine forever, so nothing
		// but the request it names contradicts it.
		"a genuine entry answering an earlier request": {
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock-1, heldGroupSecret, heldGroupSecret, "seed", "seed")
			},
		},
		"a genuine entry answering a later request": {
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock+1, heldGroupSecret, heldGroupSecret, "seed", "seed")
			},
		},
		"a permit whose work identity names no relay request": {
			workID: "wallet-action",
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock, heldGroupSecret, heldGroupSecret, "seed", "seed")
			},
		},
		"a permit whose request is not canonically rendered": {
			workID: "relay-request-0" + strconv.FormatUint(requestStartBlock, 10),
			reference: func(t *testing.T) string {
				return reference(t, requestStartBlock, heldGroupSecret, heldGroupSecret, "seed", "seed")
			},
		},
		"a reference that is not a canonical entry identity": {
			reference: func(*testing.T) string { return "relay-entry-1" },
		},
		"a well-formed reference whose components are not curve points": {
			reference: func(t *testing.T) string {
				notAPoint := bytes.Repeat([]byte{0xff}, 64)
				rendered, err := participation.BeaconRelayEntryReference(
					requestStartBlock,
					altbn128.G2Point{
						G2: new(bn256.G2).ScalarBaseMult(
							big.NewInt(heldGroupSecret),
						),
					}.Compress(),
					notAPoint,
					notAPoint,
				)
				if err != nil {
					t.Fatal(err)
				}
				return rendered
			},
		},
		// The degenerate forgery: the point at infinity pairs trivially, so an
		// entry and previous entry of all zeros would verify under any group
		// key without knowing anything about it.
		"the point at infinity, which verifies under any group": {
			reference: func(t *testing.T) string {
				infinity := make([]byte, 64)
				rendered, err := participation.BeaconRelayEntryReference(
					requestStartBlock,
					altbn128.G2Point{
						G2: new(bn256.G2).ScalarBaseMult(
							big.NewInt(heldGroupSecret),
						),
					}.Compress(),
					infinity,
					infinity,
				)
				if err != nil {
					t.Fatal(err)
				}
				return rendered
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			workID := test.workID
			if workID == "" {
				workID = participation.BeaconRelayWorkID(requestStartBlock)
			}

			violations := validateRelayEntryTerminalResult(
				0,
				workID,
				test.reference(t),
				beaconGroupKeys,
				make(map[string]relayEntryClaim),
			)

			if test.valid && len(violations) != 0 {
				t.Fatalf(
					"expected a verifiable relay entry to pass, got: %v",
					violations,
				)
			}
			if !test.valid && len(violations) == 0 {
				t.Fatal("expected the relay entry to be rejected")
			}
		})
	}
}

// TestValidateRelayEntryTerminalResult_OneEntryAnswersOneRequest asserts a
// relay result cannot close more than one relay request across the journal.
//
// A relay entry is deterministic for a given previous entry, so it belongs to
// exactly one request; the signature stays valid whatever request it is filed
// under. Without this the same genuine entry could settle every relay permit a
// node ever held, which is what the rollback barrier reads as completed work.
// Memberships of the same request legitimately recover and record the same
// entry, so those must still pass.
func TestValidateRelayEntryTerminalResult_OneEntryAnswersOneRequest(
	t *testing.T,
) {
	const (
		groupSecret             = int64(42)
		firstRequestStartBlock  = uint64(1_000)
		secondRequestStartBlock = uint64(2_000)
	)

	beaconGroupKeys := map[string]struct{}{
		hex.EncodeToString(altbn128.G2Point{
			G2: new(bn256.G2).ScalarBaseMult(big.NewInt(groupSecret)),
		}.Compress()): {},
	}
	claimed := make(map[string]relayEntryClaim)

	record := func(outcomeIndex int, requestStartBlock uint64) []string {
		return validateRelayEntryTerminalResult(
			outcomeIndex,
			participation.BeaconRelayWorkID(requestStartBlock),
			testRelayEntryReference(requestStartBlock, groupSecret, "seed"),
			beaconGroupKeys,
			claimed,
		)
	}

	if violations := record(0, firstRequestStartBlock); len(violations) != 0 {
		t.Fatalf("the first use of an entry was rejected: %v", violations)
	}

	// A second membership of the same request recovers the very same entry.
	if violations := record(1, firstRequestStartBlock); len(violations) != 0 {
		t.Errorf(
			"a second membership of the same request was rejected: %v",
			violations,
		)
	}

	if violations := record(2, secondRequestStartBlock); len(violations) == 0 {
		t.Error(
			"an entry already used for one request was accepted as the " +
				"result of another",
		)
	}
}

// testTimeoutSettlementReference renders the beacon settlement identity a
// completed timeout report outcome carries.
func testTimeoutSettlementReference(
	t *testing.T,
	requestStartBlock uint64,
	requestID int64,
	terminatedGroupID uint64,
) string {
	t.Helper()

	reference, err := participation.BeaconRelayTimeoutSettlementReference(
		requestStartBlock,
		big.NewInt(requestID),
		terminatedGroupID,
	)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

// TestValidateRelayTimeoutSettlement asserts the offline audit holds a
// completed timeout report to a settlement identity it can join to exactly one
// authenticated beacon log, and to the request its own permit was issued for.
func TestValidateRelayTimeoutSettlement(t *testing.T) {
	const requestStartBlock = uint64(1_000)

	tests := map[string]struct {
		workID          string
		reference       string
		expectViolation bool
	}{
		"a settlement terminating the permit's own request": {
			workID: participation.BeaconRelayWorkID(requestStartBlock),
			reference: testTimeoutSettlementReference(
				t,
				requestStartBlock,
				11,
				4,
			),
		},
		// A real penalty, earned by another request. Nothing about the log it
		// joins to is wrong; what is wrong is the permit it is settling.
		"a settlement terminating another request": {
			workID: participation.BeaconRelayWorkID(requestStartBlock),
			reference: testTimeoutSettlementReference(
				t,
				requestStartBlock+1,
				11,
				4,
			),
			expectViolation: true,
		},
		"a permit that names no relay request": {
			workID: "not-a-relay-request",
			reference: testTimeoutSettlementReference(
				t,
				requestStartBlock,
				11,
				4,
			),
			expectViolation: true,
		},
		// A digest is exactly what the record must not be: it names no log an
		// operator could fetch.
		"a digest standing in for a settlement": {
			workID: participation.BeaconRelayWorkID(requestStartBlock),
			reference: participation.TerminalResultReference(
				"domain",
				[]byte("result"),
			),
			expectViolation: true,
		},
		"a settlement identity missing its terminated group": {
			workID:          participation.BeaconRelayWorkID(requestStartBlock),
			reference:       "1000:11",
			expectViolation: true,
		},
		"a settlement identity with a padded request start block": {
			workID:          participation.BeaconRelayWorkID(requestStartBlock),
			reference:       "01000:11:4",
			expectViolation: true,
		},
		"a settlement identity with a padded request identifier": {
			workID:          participation.BeaconRelayWorkID(requestStartBlock),
			reference:       "1000:011:4",
			expectViolation: true,
		},
		"a settlement identity with a negative request identifier": {
			workID:          participation.BeaconRelayWorkID(requestStartBlock),
			reference:       "1000:-11:4",
			expectViolation: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			violations := validateRelayTimeoutSettlement(
				0,
				test.workID,
				test.reference,
				make(map[string]relayTimeoutSettlementClaim),
			)

			if hasViolation := len(violations) != 0; hasViolation !=
				test.expectViolation {
				t.Errorf(
					"unexpected violations\nexpected any: [%t]\nactual: %v",
					test.expectViolation,
					violations,
				)
			}
		})
	}
}

// TestValidateRelayTimeoutSettlement_OneSettlementAnswersOneRequest asserts a
// beacon settlement cannot settle two permits issued for different requests.
// The beacon terminates a request once, so the same request identifier and
// terminated group standing as a second request's result is a claim on a
// penalty that request never earned.
func TestValidateRelayTimeoutSettlement_OneSettlementAnswersOneRequest(
	t *testing.T,
) {
	const (
		firstRequestStartBlock  = uint64(1_000)
		secondRequestStartBlock = uint64(2_000)
	)

	claimed := make(map[string]relayTimeoutSettlementClaim)

	record := func(outcomeIndex int, requestStartBlock uint64) []string {
		return validateRelayTimeoutSettlement(
			outcomeIndex,
			participation.BeaconRelayWorkID(requestStartBlock),
			testTimeoutSettlementReference(t, requestStartBlock, 11, 4),
			claimed,
		)
	}

	if violations := record(0, firstRequestStartBlock); len(violations) != 0 {
		t.Fatalf("the first use of a settlement was rejected: %v", violations)
	}

	// The same permit's record written twice — a retried journal write — is the
	// same claim, not a replay.
	if violations := record(1, firstRequestStartBlock); len(violations) != 0 {
		t.Errorf(
			"a repeated record of the same settlement was rejected: %v",
			violations,
		)
	}

	if violations := record(2, secondRequestStartBlock); len(violations) == 0 {
		t.Error(
			"a settlement already used for one request was accepted as the " +
				"result of another",
		)
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
			WorkID:              participation.BeaconRelayWorkID(1_000),
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
				randomBeaconAddress:          testRandomBeaconAddress,
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

// addTestRelayEntryReceipt appends an authenticated receipt carrying a real
// ABI-encoded RandomBeacon relay lifecycle log, then re-attests and re-signs
// the record. The log is built from the generated RandomBeacon ABI so the
// audit's decode path is exercised against the exact bytes the contract emits.
//
// The non-indexed values are the ones each event actually carries: the
// terminated group for a timeout, the selected group and previous entry for a
// request, and the submitter and entry for a delivery.
func addTestRelayEntryReceipt(
	t *testing.T,
	record *chainReconciliationEvidence,
	address string,
	eventName string,
	requestID *big.Int,
	blockNumber uint64,
	values ...interface{},
) {
	t.Helper()

	parsed, err := beaconabi.RandomBeaconMetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	event, ok := parsed.Events[eventName]
	if !ok {
		t.Fatalf("generated RandomBeacon ABI has no %s event", eventName)
	}

	data, err := event.Inputs.NonIndexed().Pack(values...)
	if err != nil {
		t.Fatal(err)
	}

	var requestTopic [32]byte
	requestID.FillBytes(requestTopic[:])

	addTestBeaconLogReceipt(
		t,
		record,
		address,
		[]string{
			strings.ToLower(event.ID.Hex()),
			"0x" + hex.EncodeToString(requestTopic[:]),
		},
		data,
		blockNumber,
	)
}

// addTestGroupRegisteredReceipt appends an authenticated receipt carrying the
// RandomBeacon's own registration of a group: the registry index a request
// names the group by, and the hash of the public key it signs under. Both
// inputs are indexed, so the log carries them as topics and no data.
func addTestGroupRegisteredReceipt(
	t *testing.T,
	record *chainReconciliationEvidence,
	address string,
	groupID uint64,
	groupPublicKey []byte,
	blockNumber uint64,
) {
	t.Helper()

	parsed, err := beaconabi.RandomBeaconMetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	event, ok := parsed.Events["GroupRegistered"]
	if !ok {
		t.Fatal("generated RandomBeacon ABI has no GroupRegistered event")
	}

	var groupTopic [32]byte
	new(big.Int).SetUint64(groupID).FillBytes(groupTopic[:])

	addTestBeaconLogReceipt(
		t,
		record,
		address,
		[]string{
			strings.ToLower(event.ID.Hex()),
			"0x" + hex.EncodeToString(groupTopic[:]),
			"0x" + hex.EncodeToString(ethereumCrypto.Keccak256(groupPublicKey)),
		},
		nil,
		blockNumber,
	)
}

// addTestBeaconLogReceipt appends an authenticated receipt carrying one raw
// RandomBeacon log, then re-attests and re-signs the record.
func addTestBeaconLogReceipt(
	t *testing.T,
	record *chainReconciliationEvidence,
	address string,
	topics []string,
	data []byte,
	blockNumber uint64,
) {
	t.Helper()

	transactionHash := fmt.Sprintf(
		"0x%064x",
		blockNumber*31+uint64(len(record.Receipts))+1,
	)
	record.Receipts = append(record.Receipts, ethereumReceiptEvidence{
		TransactionHash:  transactionHash,
		BlockHash:        testCanonicalEthereumBlockHash(blockNumber),
		BlockNumber:      blockNumber,
		TransactionIndex: uint64(len(record.Receipts)),
		Status:           1,
		Logs: []ethereumRawLogEvidence{
			{
				Address:  address,
				Topics:   topics,
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
	deduplicated := record.CollectorAttestation.CanonicalBlocks[:0]
	for i, block := range record.CollectorAttestation.CanonicalBlocks {
		if i > 0 && block.BlockNumber == deduplicated[len(deduplicated)-1].
			BlockNumber {
			continue
		}
		deduplicated = append(deduplicated, block)
	}
	record.CollectorAttestation.CanonicalBlocks = deduplicated

	resignTestChainReconciliationEvidence(t, record)
}

// TestValidateChainReconciliationEvidence_RelayTimeoutSettlement asserts a
// relay entry timeout penalty a node recorded as its permit's result is
// reconciled against the RandomBeacon's own logs rather than accepted on the
// node's word.
//
// A node that filed a report which reverted, was dropped, or lost the race to
// another reporter renders exactly the same reference as one whose report the
// beacon accepted, so nothing in the journal tells the two apart. The
// authenticated logs do: the timeout must exist, the request it terminated
// must be the one this permit was issued for, and no delivered entry may
// answer that same request.
func TestValidateChainReconciliationEvidence_RelayTimeoutSettlement(
	t *testing.T,
) {
	capturedAt := time.Now().UTC().Add(-time.Minute)

	const requestStartBlock = uint64(9_100)
	const terminatedGroupID = uint64(4)
	const timeoutBlock = uint64(9_200)
	requestID := big.NewInt(77)

	// The previous entry the terminated request was signing over. The beacon
	// carries it in the request log; the audit only needs the log to exist at
	// the permit's block, so any well-formed byte string serves here.
	previousEntry := []byte{0x0a, 0x0b, 0x0c}

	permit := participation.PermitSnapshot{
		Ceremony:            participation.BeaconTimeoutReport,
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: requestStartBlock,
		WorkID:              participation.BeaconRelayWorkID(requestStartBlock),
		PermitID:            "monitor",
		IdentityBound:       true,
	}

	newRunAndRecord := func(
		reference string,
	) (*auditRun, *chainReconciliationEvidence) {
		auditManifest := &manifest{
			GeneratedAt: time.Now().UTC(),
			Snapshot: snapshotIdentity{
				AggregateSHA256: strings.Repeat("c", 64),
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
							Kind:      participation.TerminalEvidenceEthereumTransaction,
							Reference: reference,
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
				randomBeaconAddress:          testRandomBeaconAddress,
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

	addRequest := func(
		t *testing.T,
		record *chainReconciliationEvidence,
		blockNumber uint64,
	) {
		t.Helper()

		addTestRelayEntryReceipt(
			t,
			record,
			testRandomBeaconAddress,
			"RelayEntryRequested",
			requestID,
			blockNumber,
			terminatedGroupID,
			previousEntry,
		)
	}

	addTimeout := func(
		t *testing.T,
		record *chainReconciliationEvidence,
		address string,
		groupID uint64,
	) {
		t.Helper()

		addTestRelayEntryReceipt(
			t,
			record,
			address,
			"RelayEntryTimedOut",
			requestID,
			timeoutBlock,
			groupID,
		)
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

	// The negative cases below differ from the passing one only in the logs the
	// evidence carries, so requiring the reason pins each failure to the
	// settlement reconciliation instead of to some unrelated envelope defect.
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

	assertSettles := func(t *testing.T, violations []string) {
		t.Helper()

		for _, violation := range violations {
			if strings.Contains(violation, "relay entry timeout settlement") {
				t.Fatalf(
					"expected a corroborated settlement to reconcile, got: %s",
					violation,
				)
			}
		}
	}

	settledReference := testTimeoutSettlementReference(
		t,
		requestStartBlock,
		requestID.Int64(),
		terminatedGroupID,
	)

	t.Run("settlement corroborated by canonical beacon logs", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock)
		addTimeout(t, record, testRandomBeaconAddress, terminatedGroupID)
		assertSettles(t, validate(t, run, record))
	})

	// The report the node filed is all the journal ever holds. Without the
	// beacon's own termination log the penalty may never have happened, and an
	// unproven penalty is exactly what the barrier exists to hold.
	t.Run("settlement with no matching timeout log", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryTimedOut log",
		)
	})

	t.Run("timeout log terminating a different group", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock)
		addTimeout(t, record, testRandomBeaconAddress, terminatedGroupID+1)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryTimedOut log",
		)
	})

	// An identically shaped event from an attacker-deployed contract names no
	// penalty the beacon ever applied.
	t.Run("timeout log from an unrelated contract", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock)
		addTimeout(t, record, testWalletRegistryAddress, terminatedGroupID)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryTimedOut log",
		)
	})

	// The termination is real and this node may even have reported it, but
	// nothing yet says the request it terminated is the one this permit was
	// issued for. Without the request log the settlement cannot be bound to the
	// permit at all.
	t.Run("settlement with no matching request log", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addTimeout(t, record, testRandomBeaconAddress, terminatedGroupID)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryRequested log",
		)
	})

	// The check that keeps a real penalty from being borrowed: every genuine
	// termination on the chain corroborates equally, so the request it belongs
	// to has to sit in the block this permit names.
	t.Run("request log at another block", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock+1)
		addTimeout(t, record, testRandomBeaconAddress, terminatedGroupID)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"not the request start block the permit was issued for",
		)
	})

	// Nothing in the logs says which block a caller meant, so a request the
	// evidence places twice binds no permit rather than binding it to either.
	t.Run("request logged at two blocks", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock)
		addRequest(t, record, requestStartBlock+1)
		addTimeout(t, record, testRandomBeaconAddress, terminatedGroupID)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"at more than one block",
		)
	})

	// A delivered entry and a timeout are mutually exclusive endings. Evidence
	// carrying both settles nothing, whichever one the node recorded.
	t.Run("delivered entry answering the same request", func(t *testing.T) {
		run, record := newRunAndRecord(settledReference)
		addRequest(t, record, requestStartBlock)
		addTimeout(t, record, testRandomBeaconAddress, terminatedGroupID)
		addTestRelayEntryReceipt(
			t,
			record,
			testRandomBeaconAddress,
			"RelayEntrySubmitted",
			requestID,
			timeoutBlock,
			common.HexToAddress(testRandomBeaconAddress),
			[]byte{0x01, 0x02},
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"a delivered entry and a timeout cannot both settle one request",
		)
	})

	// A monitor that ended without a penalty records no settlement at all, so
	// there is nothing for this pass to corroborate and the absent beacon logs
	// are not held against it.
	t.Run("exhausted report naming no settlement", func(t *testing.T) {
		run, record := newRunAndRecord("")
		outcomes := run.manifest.ParticipationTerminalOutcomes.Outcomes
		outcomes[0].Outcome = participation.TerminalOutcomeExhausted
		outcomes[0].Evidence = participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceNoThreshold,
		}
		assertSettles(t, validate(t, run, record))
	})
}

// TestValidateChainReconciliationEvidence_RelayEntryResult asserts a recovered
// relay entry is bound to the beacon's own request before it closes a signing
// permit.
//
// The journal pass proves the entry is a threshold signature by a group whose
// key the snapshot holds, and every entry the beacon ever produced keeps that
// property forever. What it cannot prove is that this permit's ceremony
// produced it: the record's only tie to a request is a start block the node
// wrote beside an entry it chose. A historical entry relabelled with a live
// permit's block verifies exactly as well and was never in this journal for the
// replay guard to catch.
func TestValidateChainReconciliationEvidence_RelayEntryResult(t *testing.T) {
	capturedAt := time.Now().UTC().Add(-time.Minute)

	const requestStartBlock = uint64(9_400)
	const groupSecret = int64(0x5eed)
	const otherGroupSecret = int64(0x5eee)
	const selectedGroupID = uint64(1)
	const otherGroupID = uint64(7)

	// The uncompressed point is the form the registry stores and the beacon
	// hashes a group's identity from; the reference carries the compressed one.
	onChainGroupPublicKey := func(secret int64) []byte {
		return new(bn256.G2).ScalarBaseMult(big.NewInt(secret)).Marshal()
	}

	reference := testRelayEntryReference(
		requestStartBlock,
		groupSecret,
		"relay-entry-reconciliation",
	)
	_, _, previousEntry, entry, err := participation.
		ParseBeaconRelayEntryReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	requestID := testRelayRequestID(requestStartBlock)

	permit := participation.PermitSnapshot{
		Ceremony:            participation.BeaconRelaySigning,
		Mode:                participation.ModeSecurityV2.String(),
		CanonicalStartBlock: requestStartBlock,
		WorkID:              participation.BeaconRelayWorkID(requestStartBlock),
		PermitID:            "1",
		IdentityBound:       true,
	}

	newRunAndRecord := func() (*auditRun, *chainReconciliationEvidence) {
		auditManifest := &manifest{
			GeneratedAt: time.Now().UTC(),
			Snapshot: snapshotIdentity{
				AggregateSHA256: strings.Repeat("c", 64),
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
							Kind:      participation.TerminalEvidenceProtocolResult,
							Reference: reference,
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
				randomBeaconAddress:          testRandomBeaconAddress,
				finalizedEthereumBlockNumber: testFinalizedEthereumBlock,
				finalizedEthereumBlockHash: testCanonicalEthereumBlockHash(
					testFinalizedEthereumBlock,
				),
				chainEvidencePublicKey: testChainEvidencePublicKey(),
				maxEvidenceAge:         time.Hour,
			},
		}
		chainRecord := &chainReconciliationEvidence{
			evidenceEnvelope: evidenceEnvelope{
				SchemaVersion:           evidenceSchemaVersion,
				EvidenceType:            "chain_reconciliation",
				GeneratedAt:             auditManifest.GeneratedAt,
				SnapshotAggregateSHA256: auditManifest.Snapshot.AggregateSHA256,
			},
			EthereumChainID: "1",
		}
		authenticateTestChainReconciliationEvidence(t, chainRecord)
		return run, chainRecord
	}

	addRequestFromGroup := func(
		t *testing.T,
		record *chainReconciliationEvidence,
		id *big.Int,
		blockNumber uint64,
		selectedGroupID uint64,
		requestPreviousEntry []byte,
	) {
		t.Helper()

		addTestRelayEntryReceipt(
			t,
			record,
			testRandomBeaconAddress,
			"RelayEntryRequested",
			id,
			blockNumber,
			selectedGroupID,
			requestPreviousEntry,
		)
	}

	addRequest := func(
		t *testing.T,
		record *chainReconciliationEvidence,
		id *big.Int,
		blockNumber uint64,
		requestPreviousEntry []byte,
	) {
		t.Helper()

		addRequestFromGroup(
			t,
			record,
			id,
			blockNumber,
			selectedGroupID,
			requestPreviousEntry,
		)
	}

	// The selected group's registration is what binds the index the request
	// names to the key the record signs under, and the audit requires it, so
	// every case that is meant to settle has to supply it.
	addRegistration := func(
		t *testing.T,
		record *chainReconciliationEvidence,
		groupID uint64,
		secret int64,
	) {
		t.Helper()

		addTestGroupRegisteredReceipt(
			t,
			record,
			testRandomBeaconAddress,
			groupID,
			onChainGroupPublicKey(secret),
			requestStartBlock-100,
		)
	}

	addSelectedRegistration := func(
		t *testing.T,
		record *chainReconciliationEvidence,
	) {
		t.Helper()

		addRegistration(t, record, selectedGroupID, groupSecret)
	}

	addSubmission := func(
		t *testing.T,
		record *chainReconciliationEvidence,
		acceptedEntry []byte,
	) {
		t.Helper()

		addTestRelayEntryReceipt(
			t,
			record,
			testRandomBeaconAddress,
			"RelayEntrySubmitted",
			requestID,
			requestStartBlock+2,
			common.HexToAddress(testRandomBeaconAddress),
			acceptedEntry,
		)
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

	assertSettles := func(t *testing.T, violations []string) {
		t.Helper()

		for _, violation := range violations {
			if strings.Contains(violation, "reports relay entry") {
				t.Fatalf(
					"expected a corroborated relay entry to reconcile, got: %s",
					violation,
				)
			}
		}
	}

	t.Run("entry answering the permit's own request", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addSelectedRegistration(t, record)
		assertSettles(t, validate(t, run, record))
	})

	// The entry verifies under its group and answers the block the permit
	// names, and still nothing says the beacon ever made that request.
	t.Run("entry answering no logged request", func(t *testing.T) {
		run, record := newRunAndRecord()
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryRequested log makes a "+
				"request over that previous entry",
		)
	})

	// The relabelling case: a real entry from an earlier request carries that
	// request's previous entry, which the request at this permit's block is not
	// signing over.
	t.Run("request at the block over another previous entry", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(
			t,
			record,
			requestID,
			requestStartBlock,
			new(bn256.G1).ScalarBaseMult(big.NewInt(3)).Marshal(),
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryRequested log makes a "+
				"request over that previous entry",
		)
	})

	// The request the entry answers is real, but it was made in a block this
	// permit was not issued for.
	t.Run("request at another block", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock+1, previousEntry)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon RelayEntryRequested log makes a "+
				"request over that previous entry",
		)
	})

	// The beacon's request names the group it selected by a registry index, and
	// the registration binds that index to the key the group signs under. Here
	// the two agree with the record.
	t.Run("registration binding the selected group's own key", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addTestGroupRegisteredReceipt(
			t,
			record,
			testRandomBeaconAddress,
			selectedGroupID,
			onChainGroupPublicKey(groupSecret),
			requestStartBlock-100,
		)
		assertSettles(t, validate(t, run, record))
	})

	// The entry is a real threshold signature over this very request's previous
	// entry, and the pairing check passes, because the node holds a membership
	// of the group that produced it. It is simply not the group the beacon
	// selected, so the work it records is work the selected group never did.
	t.Run("entry signed by a group the request did not select", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addTestGroupRegisteredReceipt(
			t,
			record,
			testRandomBeaconAddress,
			selectedGroupID,
			onChainGroupPublicKey(otherGroupSecret),
			requestStartBlock-100,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"registered under public key hash",
		)
	})

	t.Run("selected group registered under two keys", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addTestGroupRegisteredReceipt(
			t,
			record,
			testRandomBeaconAddress,
			selectedGroupID,
			onChainGroupPublicKey(groupSecret),
			requestStartBlock-100,
		)
		addTestGroupRegisteredReceipt(
			t,
			record,
			testRandomBeaconAddress,
			selectedGroupID,
			onChainGroupPublicKey(otherGroupSecret),
			requestStartBlock-99,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"under more than one public key",
		)
	})

	t.Run("one request selecting two groups", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addRequestFromGroup(
			t,
			record,
			requestID,
			requestStartBlock,
			otherGroupID,
			previousEntry,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"select more than one group for request",
		)
	})

	// One identifier answering two requests would let either request's evidence
	// close the other's permit.
	t.Run("one identifier answering two requests", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addRequest(
			t,
			record,
			requestID,
			requestStartBlock,
			new(bn256.G1).ScalarBaseMult(big.NewInt(3)).Marshal(),
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"more than one request under identifier",
		)
	})

	// The registration is older than the request, so nothing about gathering
	// evidence around the request produces it — the generator has to be told to
	// fetch it, and the contract says so. A registration for some other group
	// binds the selected index to nothing, which is the same position as having
	// supplied none at all.
	t.Run("registration of an unrelated group", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addRegistration(t, record, otherGroupID, otherGroupSecret)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon GroupRegistered log registers "+
				"group [1]",
		)
	})

	// The discriminating case. Everything here is exactly what an honest
	// bundle looks like — a real request at the permit's block, a real
	// threshold entry over its previous entry that the pairing check accepts —
	// except that the group which produced the entry is not the one the beacon
	// selected. Nothing in the bundle says so, because the receipt that would
	// have said so is the one left out. Were absence read as consent, omitting
	// it would be all it takes to close a selected group's permit with another
	// group's work.
	t.Run("wrong group with the registration omitted", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequestFromGroup(
			t,
			record,
			requestID,
			requestStartBlock,
			otherGroupID,
			previousEntry,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"no authenticated RandomBeacon GroupRegistered log registers "+
				"group [7]",
		)
	})

	// The same omission on the selection side. Every log that indexes a request
	// identity also records the group it selected, so the audit's own decoder
	// cannot produce this pair; the join is asked directly rather than through
	// evidence that cannot express it. It still has to block, because what
	// makes the selection mandatory is that an entry with no selected group to
	// be held to is exactly the entry that was never checked.
	t.Run("request naming no selected group", func(t *testing.T) {
		violation := relayEntryGroupSelectionViolation(
			&relayEntryLifecycleLogs{
				requestGroups:               make(map[string]string),
				ambiguousRequestGroups:      make(map[string]struct{}),
				registeredGroupKeys:         make(map[string]string),
				ambiguousGroupRegistrations: make(map[string]struct{}),
			},
			0,
			reference,
			requestID.String(),
			nil,
		)
		if !strings.Contains(
			violation,
			"names the group selected to answer request",
		) {
			t.Fatalf(
				"expected an unselected group to block, got: [%s]",
				violation,
			)
		}
	})

	t.Run("two requests sharing one identity", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addRequest(
			t,
			record,
			new(big.Int).Add(requestID, big.NewInt(1)),
			requestStartBlock,
			previousEntry,
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"more than one request over that previous entry",
		)
	})

	t.Run("submission accepting the entry the node named", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addSelectedRegistration(t, record)
		addSubmission(t, record, entry)
		assertSettles(t, validate(t, run, record))
	})

	t.Run("submission accepting a different entry", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addSelectedRegistration(t, record)
		addSubmission(
			t,
			record,
			new(bn256.G1).ScalarBaseMult(big.NewInt(5)).Marshal(),
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"accepted a different entry",
		)
	})

	t.Run("two submissions accepting different entries", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addSelectedRegistration(t, record)
		addSubmission(t, record, entry)
		addSubmission(
			t,
			record,
			new(bn256.G1).ScalarBaseMult(big.NewInt(5)).Marshal(),
		)
		assertBlockedBy(
			t,
			validate(t, run, record),
			"more than one entry accepted for request",
		)
	})

	// A group's threshold recovers the entry whoever publishes it, so a
	// recovery whose submission reverted, was dropped, or lost the race is
	// still that ceremony's durable result. Requiring a submission would refuse
	// a completed ceremony for a transaction outcome that says nothing about
	// it.
	t.Run("recovered entry no submission answers", func(t *testing.T) {
		run, record := newRunAndRecord()
		addRequest(t, record, requestID, requestStartBlock, previousEntry)
		addSelectedRegistration(t, record)
		addTestRelayEntryReceipt(
			t,
			record,
			testRandomBeaconAddress,
			"RelayEntryTimedOut",
			requestID,
			requestStartBlock+2,
			uint64(1),
		)
		assertSettles(t, validate(t, run, record))
	})
}
