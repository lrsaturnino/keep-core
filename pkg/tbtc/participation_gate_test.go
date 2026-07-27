package tbtc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/dkg"
)

// TestSigningExecutor_Sign_RefusesLegacyMode proves the tECDSA signing
// executor fails closed for any mode other than security-v2: without a
// reviewed legacy tss-lib mode a legacy signing would emit a partially
// hardened transcript incompatible with both releases.
func TestSigningExecutor_Sign_RefusesLegacyMode(t *testing.T) {
	executor := &signingExecutor{}

	_, _, _, err := executor.sign(
		nil,
		big.NewInt(100),
		0,
		participation.ModeLegacy,
	)
	if err == nil {
		t.Fatal("expected a legacy-mode refusal error")
	}
	if !strings.Contains(err.Error(), "no reviewed legacy mode") {
		t.Errorf("unexpected refusal error: [%v]", err)
	}
}

// TestNode_BeginWalletActionPermit exercises the wallet action permit
// acquisition: the heartbeat maps to its own ceremony class, other actions
// are signing ceremonies, quiescence refuses, and a legacy-mode permit —
// possible while the chain is below the cutover block — is refused and
// released because the tECDSA stack cannot run it.
func TestNode_BeginWalletActionPermit(t *testing.T) {
	localChain := Connect()
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	t.Run("heartbeat ceremony class", func(t *testing.T) {
		n := &node{participationGate: newTestGate(t, blockCounter)}

		permit := n.beginWalletActionPermit(ActionHeartbeat, 1)
		if permit == nil {
			t.Fatal("expected a permit")
		}
		defer permit.Close()

		testutils.AssertStringsEqual(
			t,
			"permit ceremony",
			string(participation.TBTCHeartbeat),
			string(permit.Ceremony()),
		)
		testutils.AssertStringsEqual(
			t,
			"permit mode",
			participation.ModeSecurityV2.String(),
			permit.Mode().String(),
		)
	})

	t.Run("signing ceremony class", func(t *testing.T) {
		n := &node{participationGate: newTestGate(t, blockCounter)}

		permit := n.beginWalletActionPermit(ActionDepositSweep, 1)
		if permit == nil {
			t.Fatal("expected a permit")
		}
		defer permit.Close()

		testutils.AssertStringsEqual(
			t,
			"permit ceremony",
			string(participation.TBTCSigning),
			string(permit.Ceremony()),
		)
	})

	t.Run("refused while quiescing", func(t *testing.T) {
		gate := newTestGate(t, blockCounter)
		gate.Quiesce(fmt.Errorf("shutdown"))

		n := &node{participationGate: gate}

		if permit := n.beginWalletActionPermit(ActionRedemption, 1); permit != nil {
			permit.Close()
			t.Error("expected no permit while quiescing")
		}
	})

	t.Run("refused without a gate", func(t *testing.T) {
		n := &node{}

		if permit := n.beginWalletActionPermit(ActionRedemption, 1); permit != nil {
			permit.Close()
			t.Error("expected no permit without a gate")
		}
	})

	t.Run("legacy mode refused and released", func(t *testing.T) {
		// A cutover block far ahead pins every current anchor to the legacy
		// mode, which the tECDSA stack cannot run.
		gate, err := participation.NewGate(
			t.Context(),
			participation.Schedule{CutoverBlock: 1_000_000},
			blockCounter,
			testGateMetrics{},
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(gate.Close)

		n := &node{participationGate: gate}

		if permit := n.beginWalletActionPermit(ActionMovingFunds, 1); permit != nil {
			permit.Close()
			t.Error("expected no permit for the legacy mode")
		}

		snapshot := gate.State()
		testutils.AssertUintsEqual(
			t,
			"active ceremonies after the legacy refusal",
			0,
			snapshot.ActiveCeremonies,
		)
	})
}

// TestDkgExecutor_GenerateSigningGroup_RefusesLegacyMode proves that a DKG
// whose canonical anchor pins the legacy mode never starts a member
// goroutine: the executor's protocol dependencies are deliberately nil, so
// reaching the protocol would panic the test.
func TestDkgExecutor_GenerateSigningGroup_RefusesLegacyMode(t *testing.T) {
	localChain := Connect()
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate, err := participation.NewGate(
		t.Context(),
		participation.Schedule{CutoverBlock: 1_000_000},
		blockCounter,
		testGateMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	_, operatorPublicKey, err := operator.GenerateKeyPair(local_v1.DefaultCurve)
	if err != nil {
		t.Fatal(err)
	}

	de := &dkgExecutor{
		groupParameters: &GroupParameters{
			GroupSize:       5,
			GroupQuorum:     3,
			HonestThreshold: 2,
		},
		chain:             localChain,
		netProvider:       local.ConnectWithKey(operatorPublicKey),
		participationGate: gate,
		signerQuarantine: newSignerQuarantine(
			logger,
			&mockPersistenceHandle{},
		),
	}

	gsr := &GroupSelectionResult{
		OperatorsIDs:       chain.OperatorIDs{1, 2, 3, 4, 5},
		OperatorsAddresses: chain.Addresses{"0xAA", "0xBB", "0xCC", "0xDD", "0xEE"},
	}

	de.generateSigningGroup(
		logger.With(),
		big.NewInt(1),
		[]uint8{1},
		gsr,
		1,
		0,
	)

	// The member permit was refused and released before any goroutine.
	snapshot := gate.State()
	testutils.AssertUintsEqual(
		t,
		"active ceremonies after the legacy refusal",
		0,
		snapshot.ActiveCeremonies,
	)
}

// TestDkgExecutor_PreserveInterruptedSigner_Quarantines proves a refused
// activation of a signer whose wallet is not registered on chain preserves
// the share only in the protected quarantine namespace — never in the active
// wallet storage and never in the in-memory wallet cache.
func TestDkgExecutor_PreserveInterruptedSigner_Quarantines(t *testing.T) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	de.preserveInterruptedSigner(
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		fmt.Errorf("activation refused"),
	)

	if len(registryHandle.saved) != 0 {
		t.Errorf(
			"expected no active-namespace save, got [%d]",
			len(registryHandle.saved),
		)
	}
	if signers := de.walletRegistry.getSigners(
		result.PrivateKeyShare.PublicKey(),
	); len(signers) != 0 {
		t.Errorf("expected no activated signers, got [%d]", len(signers))
	}

	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)

	var metadataContent []byte
	expectedDirectory := getWalletStorageKey(result.PrivateKeyShare.PublicKey())
	for _, descriptor := range quarantineHandle.saved {
		testutils.AssertStringsEqual(
			t,
			"quarantine directory",
			expectedDirectory,
			descriptor.Directory(),
		)
		if strings.HasPrefix(descriptor.Name(), "/metadata_") {
			metadataContent, _ = descriptor.Content()
		}
	}
	if metadataContent == nil {
		t.Fatal("expected a quarantine metadata record")
	}

	var metadata QuarantinedSignerMetadata
	if err := json.Unmarshal(metadataContent, &metadata); err != nil {
		t.Fatal(err)
	}

	testutils.AssertUintsEqual(
		t,
		"metadata schema version",
		uint64(QuarantineSchemaVersion),
		uint64(metadata.SchemaVersion),
	)
	testutils.AssertStringsEqual(
		t,
		"metadata release epoch",
		participation.CompiledEpoch.String(),
		metadata.ReleaseEpoch,
	)
	testutils.AssertStringsEqual(
		t,
		"metadata protocol mode",
		participation.ModeSecurityV2.String(),
		metadata.ProtocolMode,
	)
	testutils.AssertStringsEqual(
		t,
		"metadata ceremony",
		string(participation.TBTCDKG),
		metadata.Ceremony,
	)
	testutils.AssertStringsEqual(
		t,
		"metadata failed operation",
		"tbtc_dkg_signer_activation",
		metadata.FailedOperation,
	)
	if metadata.SeedHash == "" {
		t.Error("expected a seed hash in the quarantine metadata")
	}
	if strings.Contains(metadata.SeedHash, big.NewInt(1).Text(16)) &&
		len(metadata.SeedHash) < 64 {
		t.Error("the raw seed must not appear in the quarantine metadata")
	}
	expectedWalletPKH := bitcoin.PublicKeyHash(result.PrivateKeyShare.PublicKey())
	testutils.AssertStringsEqual(
		t,
		"metadata wallet public key hash",
		hex.EncodeToString(expectedWalletPKH[:]),
		metadata.WalletPublicKeyHash,
	)
}

// TestDkgExecutor_PreserveInterruptedSigner_SavesRegisteredWithoutActivation
// proves a refused activation of a signer whose wallet is already registered
// on chain saves the share durably in the active namespace — a prior binary
// may legitimately load it — but never activates it in this process's wallet
// cache.
func TestDkgExecutor_PreserveInterruptedSigner_SavesRegisteredWithoutActivation(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	walletPublicKey := result.PrivateKeyShare.PublicKey()
	walletID, err := de.chain.CalculateWalletID(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	de.chain.(*localChain).setWallet(
		bitcoin.PublicKeyHash(walletPublicKey),
		&WalletChainData{EcdsaWalletID: walletID, State: StateLive},
	)

	permit := newTestPermit(participation.TBTCDKG)

	de.preserveInterruptedSigner(
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		fmt.Errorf("activation refused"),
	)

	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		1,
		len(registryHandle.saved),
	)
	if len(quarantineHandle.saved) != 0 {
		t.Errorf(
			"expected no quarantine records, got [%d]",
			len(quarantineHandle.saved),
		)
	}
	if signers := de.walletRegistry.getSigners(walletPublicKey); len(signers) != 0 {
		t.Errorf("expected no activated signers, got [%d]", len(signers))
	}
}

// setupPreserveScenario builds a dkgExecutor with observable active and
// quarantine persistence plus a completed DKG result, for exercising the
// interrupted-signer preservation paths.
func setupPreserveScenario(t *testing.T) (
	*dkgExecutor,
	*dkg.Result,
	*GroupSelectionResult,
	*mockPersistenceHandle,
	*mockPersistenceHandle,
) {
	t.Helper()

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     3,
		HonestThreshold: 2,
	}

	localChain := Connect()
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	registryHandle := &mockPersistenceHandle{}
	walletRegistry, err := newWalletRegistry(
		registryHandle,
		localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	quarantineHandle := &mockPersistenceHandle{}

	de := &dkgExecutor{
		groupParameters:   groupParameters,
		chain:             localChain,
		walletRegistry:    walletRegistry,
		participationGate: newTestGate(t, blockCounter),
		signerQuarantine:  newSignerQuarantine(logger, quarantineHandle),
	}

	result := &dkg.Result{
		Group: group.NewGroup(
			groupParameters.DishonestThreshold(),
			groupParameters.GroupSize,
		),
		PrivateKeyShare: tecdsa.NewPrivateKeyShare(testData[0]),
	}

	gsr := &GroupSelectionResult{
		OperatorsIDs:       chain.OperatorIDs{1, 2, 3, 4, 5},
		OperatorsAddresses: chain.Addresses{"0xAA", "0xBB", "0xCC", "0xDD", "0xEE"},
	}

	return de, result, gsr, registryHandle, quarantineHandle
}

// TestHeartbeatAction_PenaltySuppressedByFence proves a refused penalty
// fence suppresses the whole inactivity penalty path of a low-activity
// heartbeat: the consecutive-failure counter is not incremented, no claim is
// requested, and the action completes without an ordinary failure.
func TestHeartbeatAction_PenaltySuppressedByFence(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	heartbeatFailureCounter := newHeartbeatFailureCounter()

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	// Enough active members to sign, too few for a healthy heartbeat: the
	// normal path would count an inactivity failure.
	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers - 1

	inactivityClaimExecutor := &mockInactivityClaimExecutor{}

	permit := newTestPermit(participation.TBTCHeartbeat)
	permit.commitErr = participation.ErrPenaltySuppressed

	action := newHeartbeatAction(
		logger,
		hostChain,
		wallet{
			publicKey: mustUnmarshalPublicKey(t, walletPublicKeyHex),
		},
		mockExecutor,
		proposal,
		heartbeatFailureCounter,
		inactivityClaimExecutor,
		10,
		10+heartbeatTotalProposalValidityBlocks,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		permit,
	)

	if err := action.execute(); err != nil {
		t.Fatalf("a suppressed penalty must not be an ordinary failure: [%v]", err)
	}

	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after suppression",
		0,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	if inactivityClaimExecutor.sessionID != nil {
		t.Error("expected no inactivity claim after suppression")
	}
	if !permit.isClosed() {
		t.Error("expected the action to release its permit")
	}
}

// TestHeartbeatAction_PenaltySuppressedByQuiescingGate proves the real gate's
// quiescence suppresses a pending heartbeat penalty: a low-activity result
// during process quiescence neither increments the consecutive-failure
// counter nor files a claim, even when the counter is one failure short of
// the claim threshold.
func TestHeartbeatAction_PenaltySuppressedByQuiescingGate(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	// One failure short of the claim threshold: a normal low-activity result
	// would increment the counter and file a claim.
	heartbeatFailureCounter := newHeartbeatFailureCounter()
	for i := uint(0); i < heartbeatConsecutiveFailureThreshold-1; i++ {
		heartbeatFailureCounter.increment(walletPublicKeyStr)
	}

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	blockCounter, err := hostChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)
	permit, err := gate.Begin(participation.TBTCHeartbeat, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Quiescence begins while the heartbeat is in flight: the permit stays
	// alive to natural completion but new penalty state is suppressed.
	gate.Quiesce(fmt.Errorf("shutdown"))

	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers - 1

	inactivityClaimExecutor := &mockInactivityClaimExecutor{}

	action := newHeartbeatAction(
		logger,
		hostChain,
		wallet{
			publicKey: mustUnmarshalPublicKey(t, walletPublicKeyHex),
		},
		mockExecutor,
		proposal,
		heartbeatFailureCounter,
		inactivityClaimExecutor,
		10,
		10+heartbeatTotalProposalValidityBlocks,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		permit,
	)

	if err := action.execute(); err != nil {
		t.Fatalf("a suppressed penalty must not be an ordinary failure: [%v]", err)
	}

	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after suppression",
		uint64(heartbeatConsecutiveFailureThreshold-1),
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	if inactivityClaimExecutor.sessionID != nil {
		t.Error("expected no inactivity claim after suppression")
	}
}

// TestWalletTransactionExecutor_BroadcastRefusedByGate proves the commit
// fence runs before every Bitcoin broadcast attempt: a refused fence
// surfaces the gate sentinel and the transaction never reaches the Bitcoin
// chain.
func TestWalletTransactionExecutor_BroadcastRefusedByGate(t *testing.T) {
	permit := newTestPermit(participation.TBTCSigning)
	permit.commitErr = participation.ErrQuiescing

	btcChain := newLocalBitcoinChain()

	wte := &walletTransactionExecutor{
		btcChain:           btcChain,
		permit:             permit,
		broadcastOperation: "tbtc_deposit_sweep_bitcoin_broadcast",
	}

	tx := &bitcoin.Transaction{Version: 1}

	err := wte.broadcastTransaction(
		logger.With(),
		tx,
		10*time.Second,
		time.Millisecond,
	)
	if !errors.Is(err, participation.ErrQuiescing) {
		t.Fatalf("expected the gate sentinel, got [%v]", err)
	}

	if _, err := btcChain.GetTransaction(tx.Hash()); err == nil {
		t.Error("expected the transaction to never reach the Bitcoin chain")
	}

	operations := permit.commitOperations()
	testutils.AssertIntsEqual(t, "fence consultations", 1, len(operations))
	testutils.AssertStringsEqual(
		t,
		"fence operation",
		"tbtc_deposit_sweep_bitcoin_broadcast",
		operations[0],
	)
}
