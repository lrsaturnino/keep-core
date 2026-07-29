package tbtc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

func TestHeartbeatAction_HappyPath(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	startBlock := uint64(10)
	expiryBlock := startBlock + heartbeatTotalProposalValidityBlocks

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	// Set the heartbeat failure counter to `1` for the given wallet. The value
	// of the counter should be reset to `0` after executing the action.
	heartbeatFailureCounter := newHeartbeatFailureCounter()
	heartbeatFailureCounter.increment(walletPublicKeyStr)

	// sha256(sha256(messageToSign))
	sha256d, err := hex.DecodeString("38d30dacec5083c902952ce99fc0287659ad0b1ca2086827a8e78b0bef2c8bc1")
	if err != nil {
		t.Fatal(err)
	}

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	// Set the active operators count to the minimum required value.
	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers

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
		startBlock,
		expiryBlock,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		newTestPermit(participation.TBTCHeartbeat),
	)

	err = action.execute()
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertUintsEqual(
		t,
		"heartbeat failure count",
		0,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	testutils.AssertBigIntsEqual(
		t,
		"message to sign",
		new(big.Int).SetBytes(sha256d),
		mockExecutor.requestedMessage,
	)
	testutils.AssertUintsEqual(
		t,
		"start block",
		startBlock,
		mockExecutor.requestedStartBlock,
	)
	testutils.AssertBigIntsEqual(
		t,
		"inactivity claim executor session ID",
		nil, // executor not called.
		inactivityClaimExecutor.sessionID,
	)
}

func TestHeartbeatAction_OperatorUnstaking(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	startBlock := uint64(10)
	expiryBlock := startBlock + heartbeatTotalProposalValidityBlocks

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	heartbeatFailureCounter := newHeartbeatFailureCounter()

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(0))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	// Set the active operators count to the minimum required value.
	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers

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
		startBlock,
		expiryBlock,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		newTestPermit(participation.TBTCHeartbeat),
	)

	err = action.execute()
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertBigIntsEqual(
		t,
		"message to sign",
		nil, // sign not called
		mockExecutor.requestedMessage,
	)
}

func TestHeartbeatAction_Failure_SigningError(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	startBlock := uint64(10)
	expiryBlock := startBlock + heartbeatTotalProposalValidityBlocks

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

	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.shouldFail = true
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers

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
		startBlock,
		expiryBlock,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		newTestPermit(participation.TBTCHeartbeat),
	)

	// Do not expect the execution to result in an error. Signing error does not
	// mean the procedure failure.
	err = action.execute()

	expectedError := "heartbeat signing process errored out: [oofta]"
	if err == nil || err.Error() != expectedError {
		t.Errorf(
			"unexpected error\n"+
				"expected: %v\n"+
				"actual:   %v\n",
			expectedError,
			err,
		)
	}

	testutils.AssertUintsEqual(
		t,
		"heartbeat failure count",
		0,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	testutils.AssertBigIntsEqual(
		t,
		"inactivity claim executor session ID",
		nil, // executor not called.
		inactivityClaimExecutor.sessionID,
	)
}

func TestHeartbeatAction_Failure_TooFewActiveOperators(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	startBlock := uint64(10)
	expiryBlock := startBlock + heartbeatTotalProposalValidityBlocks

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

	// Set the active operators count just below the required number.
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
		startBlock,
		expiryBlock,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		newTestPermit(participation.TBTCHeartbeat),
	)

	// Do not expect the execution to result in an error. Signing error does not
	// mean the procedure failure.
	err = action.execute()
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertUintsEqual(
		t,
		"heartbeat failure count",
		1,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	testutils.AssertBigIntsEqual(
		t,
		"inactivity claim executor session ID",
		nil, // executor not called.
		inactivityClaimExecutor.sessionID,
	)
}

func TestHeartbeatAction_Failure_CounterExceeded(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	startBlock := uint64(10)
	expiryBlock := startBlock + heartbeatTotalProposalValidityBlocks

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	// sha256(sha256(messageToSign))
	sha256d, err := hex.DecodeString("38d30dacec5083c902952ce99fc0287659ad0b1ca2086827a8e78b0bef2c8bc1")
	if err != nil {
		t.Fatal(err)
	}

	// Set the heartbeat failure counter to `2` so that the next failure will
	// trigger operator inactivity claim execution.
	heartbeatFailureCounter := newHeartbeatFailureCounter()
	heartbeatFailureCounter.increment(walletPublicKeyStr)
	heartbeatFailureCounter.increment(walletPublicKeyStr)

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

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
		startBlock,
		expiryBlock,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		newTestPermit(participation.TBTCHeartbeat),
	)

	// Do not expect the execution to result in an error. Signing error does not
	// mean the procedure failure.
	err = action.execute()
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertUintsEqual(
		t,
		"heartbeat failure count",
		3,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	testutils.AssertBigIntsEqual(
		t,
		"inactivity claim executor session ID",
		new(big.Int).SetBytes(sha256d),
		inactivityClaimExecutor.sessionID,
	)
}

func TestHeartbeatAction_Failure_InactivityExecutionFailure(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	startBlock := uint64(10)
	expiryBlock := startBlock + heartbeatTotalProposalValidityBlocks

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	// sha256(sha256(messageToSign))
	sha256d, err := hex.DecodeString("38d30dacec5083c902952ce99fc0287659ad0b1ca2086827a8e78b0bef2c8bc1")
	if err != nil {
		t.Fatal(err)
	}

	// Set the heartbeat failure counter to `2` so that the next failure will
	// trigger operator inactivity claim execution.
	heartbeatFailureCounter := newHeartbeatFailureCounter()
	heartbeatFailureCounter.increment(walletPublicKeyStr)
	heartbeatFailureCounter.increment(walletPublicKeyStr)

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers - 1

	inactivityClaimExecutor := &mockInactivityClaimExecutor{}
	inactivityClaimExecutor.shouldFail = true

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
		startBlock,
		expiryBlock,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		newTestPermit(participation.TBTCHeartbeat),
	)

	err = action.execute()
	if err == nil {
		t.Fatal("expected error to be returned")
	}
	testutils.AssertStringsEqual(
		t,
		"error message",
		"error while notifying about operator inactivity [mock inactivity "+
			"claim executor error]]",
		err.Error(),
	)

	testutils.AssertUintsEqual(
		t,
		"heartbeat failure count",
		3,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	testutils.AssertBigIntsEqual(
		t,
		"inactivity claim executor session ID",
		new(big.Int).SetBytes(sha256d),
		inactivityClaimExecutor.sessionID,
	)
}

func TestHeartbeatFailureCounter_Increment(t *testing.T) {
	walletPublicKey := createMockSigner(t).wallet.publicKey
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		t.Fatal(t)
	}

	heartbeatFailureCounter := newHeartbeatFailureCounter()

	counterKey := hex.EncodeToString(walletPublicKeyBytes)

	// Check first increment.
	heartbeatFailureCounter.increment(counterKey)
	count := heartbeatFailureCounter.get(counterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		1,
		uint64(count),
	)

	// Check second increment.
	heartbeatFailureCounter.increment(counterKey)
	count = heartbeatFailureCounter.get(counterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		2,
		uint64(count),
	)
}

func TestHeartbeatFailureCounter_Reset(t *testing.T) {
	walletPublicKey := createMockSigner(t).wallet.publicKey
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		t.Fatal(t)
	}

	heartbeatFailureCounter := newHeartbeatFailureCounter()

	counterKey := hex.EncodeToString(walletPublicKeyBytes)

	// Check reset works as the first operation.
	heartbeatFailureCounter.reset(counterKey)
	count := heartbeatFailureCounter.get(counterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		0,
		uint64(count),
	)

	// Check reset works after an increment.
	heartbeatFailureCounter.increment(counterKey)
	heartbeatFailureCounter.reset(counterKey)

	count = heartbeatFailureCounter.get(counterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		0,
		uint64(count),
	)
}

func TestHeartbeatFailureCounter_Get(t *testing.T) {
	walletPublicKey := createMockSigner(t).wallet.publicKey
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		t.Fatal(t)
	}

	heartbeatFailureCounter := newHeartbeatFailureCounter()

	counterKey := hex.EncodeToString(walletPublicKeyBytes)

	// Check get works as the first operation.
	count := heartbeatFailureCounter.get(counterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		0,
		uint64(count),
	)

	// Check get works after an increment.
	heartbeatFailureCounter.increment(counterKey)
	count = heartbeatFailureCounter.get(counterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		1,
		uint64(count),
	)

	// Construct an arbitrary public key representing a different wallet.
	x, y := walletPublicKey.Curve.Double(walletPublicKey.X, walletPublicKey.Y)
	anotherWalletPublicKey := &ecdsa.PublicKey{
		Curve: walletPublicKey.Curve,
		X:     x,
		Y:     y,
	}
	anotherWalletPublicKeyBytes, err := marshalPublicKey(anotherWalletPublicKey)
	if err != nil {
		t.Fatal(t)
	}
	anotherCounterKey := hex.EncodeToString(anotherWalletPublicKeyBytes)

	// Check get works on another wallet.
	count = heartbeatFailureCounter.get(anotherCounterKey)
	testutils.AssertUintsEqual(
		t,
		"counter value",
		0,
		uint64(count),
	)
}

// runHeartbeatAction executes one heartbeat action for the given active-member
// count against the given permit and consecutive-failure counter, returning
// the signing and inactivity-claim executors for assertions.
func runHeartbeatAction(
	t *testing.T,
	hostChain *localChain,
	activeMembers uint32,
	failureCounter *heartbeatFailureCounter,
	startBlock uint64,
	permit participation.Permit,
) (*mockHeartbeatSigningExecutor, *mockInactivityClaimExecutor, error) {
	t.Helper()

	walletPublicKeyHex, err := hex.DecodeString(heartbeatTestWalletKey())
	if err != nil {
		t.Fatal(err)
	}

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = activeMembers

	inactivityClaimExecutor := &mockInactivityClaimExecutor{}

	action := newHeartbeatAction(
		logger,
		hostChain,
		wallet{
			publicKey: mustUnmarshalPublicKey(t, walletPublicKeyHex),
		},
		mockExecutor,
		proposal,
		failureCounter,
		inactivityClaimExecutor,
		startBlock,
		startBlock+heartbeatTotalProposalValidityBlocks,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		permit,
	)

	return mockExecutor, inactivityClaimExecutor, action.execute()
}

// heartbeatTestWalletKey returns the uncompressed public key hex of the
// wallet used by runHeartbeatAction, which is also its failure-counter key.
func heartbeatTestWalletKey() string {
	return "0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
		"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289"
}

// TestHeartbeatAction_InactivityBandMatrixBeforeCutover exercises the
// inactivity band against a real participation gate whose cutover block is
// far ahead, i.e. the pre-cutover fleet state where every heartbeat permit
// pins the legacy mode and penalty accounting follows the normal current
// rules: 51-69 active members produce a signature but count an inactivity
// failure, the third consecutive failure files exactly one claim, and 70
// active members reset the counter.
func TestHeartbeatAction_InactivityBandMatrixBeforeCutover(t *testing.T) {
	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))

	blockCounter, err := hostChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, blockCounter, 1_000_000)

	tests := map[string]struct {
		activeMembers    uint32
		initialFailures  uint
		expectedFailures uint64
		expectedClaims   int
	}{
		"51 members sign but count an inactivity failure": {
			activeMembers:    51,
			initialFailures:  0,
			expectedFailures: 1,
			expectedClaims:   0,
		},
		"60 members sign but count an inactivity failure": {
			activeMembers:    60,
			initialFailures:  0,
			expectedFailures: 1,
			expectedClaims:   0,
		},
		"69 members sign but count an inactivity failure": {
			activeMembers:    69,
			initialFailures:  0,
			expectedFailures: 1,
			expectedClaims:   0,
		},
		"70 members reset the counter": {
			activeMembers:    heartbeatSigningMinimumActiveMembers,
			initialFailures:  heartbeatConsecutiveFailureThreshold - 1,
			expectedFailures: 0,
			expectedClaims:   0,
		},
		"third consecutive failure files one claim": {
			activeMembers:    51,
			initialFailures:  heartbeatConsecutiveFailureThreshold - 1,
			expectedFailures: heartbeatConsecutiveFailureThreshold,
			expectedClaims:   1,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			failureCounter := newHeartbeatFailureCounter()
			for i := uint(0); i < test.initialFailures; i++ {
				failureCounter.increment(heartbeatTestWalletKey())
			}

			anchor, err := blockCounter.CurrentBlock()
			if err != nil {
				t.Fatal(err)
			}

			permit, err := gate.Begin(participation.TBTCHeartbeat, anchor)
			if err != nil {
				t.Fatal(err)
			}
			testutils.AssertStringsEqual(
				t,
				"permit mode before the cutover",
				participation.ModeLegacy.String(),
				permit.Mode().String(),
			)

			mockExecutor, inactivityClaimExecutor, err := runHeartbeatAction(
				t,
				hostChain,
				test.activeMembers,
				failureCounter,
				anchor,
				permit,
			)
			if err != nil {
				t.Fatal(err)
			}

			testutils.AssertStringsEqual(
				t,
				"signing mode",
				participation.ModeLegacy.String(),
				mockExecutor.requestedMode.String(),
			)
			testutils.AssertUintsEqual(
				t,
				"consecutive failure counter",
				test.expectedFailures,
				uint64(failureCounter.get(heartbeatTestWalletKey())),
			)
			testutils.AssertIntsEqual(
				t,
				"inactivity claims",
				test.expectedClaims,
				inactivityClaimExecutor.calls,
			)
		})
	}
}

// TestHeartbeatAction_LegacyAnchorFinishingAfterCutoverSuppressed proves the
// exact boundary rule of the release gate: a heartbeat anchored below the
// cutover block that finishes at or after it neither increments the
// consecutive-failure counter nor files a claim, even when the counter is one
// failure short of the claim threshold. The permit's mode stays legacy for
// its entire lifetime; only the new penalty state is suppressed.
func TestHeartbeatAction_LegacyAnchorFinishingAfterCutoverSuppressed(t *testing.T) {
	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))

	blockCounter, err := hostChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}
	cutoverBlock := anchor + 2

	gate := newTestGateWithCutover(t, blockCounter, cutoverBlock)

	permit, err := gate.Begin(participation.TBTCHeartbeat, anchor)
	if err != nil {
		t.Fatal(err)
	}
	testutils.AssertStringsEqual(
		t,
		"permit mode for the pre-cutover anchor",
		participation.ModeLegacy.String(),
		permit.Mode().String(),
	)

	// One failure short of the claim threshold: a normal low-activity result
	// would increment the counter and file a claim.
	failureCounter := newHeartbeatFailureCounter()
	for i := uint(0); i < heartbeatConsecutiveFailureThreshold-1; i++ {
		failureCounter.increment(heartbeatTestWalletKey())
	}

	// The heartbeat finishes at or after the cutover block.
	if err := blockCounter.WaitForBlockHeight(cutoverBlock); err != nil {
		t.Fatal(err)
	}

	mockExecutor, inactivityClaimExecutor, err := runHeartbeatAction(
		t,
		hostChain,
		51,
		failureCounter,
		anchor,
		permit,
	)
	if err != nil {
		t.Fatalf("a suppressed penalty must not be an ordinary failure: [%v]", err)
	}

	testutils.AssertStringsEqual(
		t,
		"signing mode",
		participation.ModeLegacy.String(),
		mockExecutor.requestedMode.String(),
	)
	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after suppression",
		uint64(heartbeatConsecutiveFailureThreshold-1),
		uint64(failureCounter.get(heartbeatTestWalletKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"inactivity claims",
		0,
		inactivityClaimExecutor.calls,
	)
}

// TestHeartbeatAction_SecurityV2AtOrAfterCutoverNormalRules proves a
// heartbeat anchored at or after the cutover block pins the security-v2 mode
// and follows the normal current rules: low-activity results increment the
// counter, the third consecutive failure files exactly one claim, and a
// healthy result resets the counter.
func TestHeartbeatAction_SecurityV2AtOrAfterCutoverNormalRules(t *testing.T) {
	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))

	blockCounter, err := hostChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)

	failureCounter := newHeartbeatFailureCounter()
	for i := uint(0); i < heartbeatConsecutiveFailureThreshold-1; i++ {
		failureCounter.increment(heartbeatTestWalletKey())
	}

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	permit, err := gate.Begin(participation.TBTCHeartbeat, anchor)
	if err != nil {
		t.Fatal(err)
	}
	testutils.AssertStringsEqual(
		t,
		"permit mode at or after the cutover",
		participation.ModeSecurityV2.String(),
		permit.Mode().String(),
	)

	// The third consecutive low-activity result files exactly one claim.
	mockExecutor, inactivityClaimExecutor, err := runHeartbeatAction(
		t,
		hostChain,
		69,
		failureCounter,
		anchor,
		permit,
	)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertStringsEqual(
		t,
		"signing mode",
		participation.ModeSecurityV2.String(),
		mockExecutor.requestedMode.String(),
	)
	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after the third failure",
		uint64(heartbeatConsecutiveFailureThreshold),
		uint64(failureCounter.get(heartbeatTestWalletKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"inactivity claims",
		1,
		inactivityClaimExecutor.calls,
	)

	// A healthy result resets the counter under the same normal rules.
	healthyPermit, err := gate.Begin(participation.TBTCHeartbeat, anchor)
	if err != nil {
		t.Fatal(err)
	}

	_, healthyClaimExecutor, err := runHeartbeatAction(
		t,
		hostChain,
		heartbeatSigningMinimumActiveMembers,
		failureCounter,
		anchor,
		healthyPermit,
	)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after the healthy heartbeat",
		0,
		uint64(failureCounter.get(heartbeatTestWalletKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"inactivity claims after the healthy heartbeat",
		0,
		healthyClaimExecutor.calls,
	)
}

type mockHeartbeatSigningExecutor struct {
	shouldFail           bool
	activeOperatorsCount uint32

	requestedMessage    *big.Int
	requestedStartBlock uint64
	requestedMode       participation.ProtocolMode
}

func (mhse *mockHeartbeatSigningExecutor) sign(
	ctx context.Context,
	message *big.Int,
	startBlock uint64,
	mode participation.ProtocolMode,
) (*tecdsa.Signature, *signingActivityReport, uint64, error) {
	mhse.requestedMessage = message
	mhse.requestedStartBlock = startBlock
	mhse.requestedMode = mode

	if mhse.shouldFail {
		return nil, nil, 0, fmt.Errorf("oofta")
	}

	activeMembers := make([]group.MemberIndex, 0)
	inactiveMembers := make([]group.MemberIndex, 0)

	for memberIndex := uint32(1); memberIndex <= 100; memberIndex++ {
		if memberIndex <= mhse.activeOperatorsCount {
			activeMembers = append(activeMembers, group.MemberIndex(memberIndex))
		} else {
			inactiveMembers = append(inactiveMembers, group.MemberIndex(memberIndex))
		}
	}

	activityReport := &signingActivityReport{
		activeMembers:   activeMembers,
		inactiveMembers: inactiveMembers,
	}

	return &tecdsa.Signature{}, activityReport, startBlock + 1, nil
}

type mockInactivityClaimExecutor struct {
	shouldFail bool
	// disposition is what the executor reports about the chain, independently
	// of shouldFail: a claim can be submitted or even settle and the call still
	// error.
	disposition inactivityClaimDisposition

	sessionID *big.Int
	calls     int
}

func (mice *mockInactivityClaimExecutor) claimInactivity(
	ctx context.Context,
	commitGuard participation.CommitGuard,
	inactiveMembersIndexes []group.MemberIndex,
	heartbeatFailed bool,
	sessionID *big.Int,
) (inactivityClaimDisposition, error) {
	mice.sessionID = sessionID
	mice.calls++

	if mice.shouldFail {
		return mice.disposition, fmt.Errorf("mock inactivity claim executor error")
	}

	return mice.disposition, nil
}
