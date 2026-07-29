package tbtc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

// assertRecordedTerminalOutcome checks that the ceremony owner authored exactly
// one terminal disposition of the expected shape and that the live gate's own
// validator accepts it for that ceremony. Running the authored record through
// the validator is what keeps the journal usable: an outcome the node writes but
// the gate rejects never reaches the rollback audit at all.
func assertRecordedTerminalOutcome(
	t *testing.T,
	permit *testPermit,
	expectedOutcome participation.TerminalOutcome,
	expectedKind participation.TerminalEvidenceKind,
) participation.TerminalEvidence {
	t.Helper()

	recorded := permit.recordedTerminalOutcomes()
	if len(recorded) != 1 {
		t.Fatalf(
			"expected exactly one terminal outcome, got [%d]",
			len(recorded),
		)
	}

	if recorded[0].outcome != expectedOutcome {
		t.Errorf(
			"unexpected terminal outcome\nexpected: [%s]\nactual:   [%s]",
			expectedOutcome,
			recorded[0].outcome,
		)
	}

	if recorded[0].evidence.Kind != expectedKind {
		t.Errorf(
			"unexpected terminal evidence kind\nexpected: [%s]\nactual:   [%s]",
			expectedKind,
			recorded[0].evidence.Kind,
		)
	}

	if err := participation.ValidateTerminalOutcome(
		permit.Ceremony(),
		recorded[0].outcome,
		recorded[0].evidence,
	); err != nil {
		t.Errorf(
			"the gate rejects the node-authored outcome for ceremony [%s]: [%v]",
			permit.Ceremony(),
			err,
		)
	}

	return recorded[0].evidence
}

// TestWalletTransactionExecutor_TerminalOutcome_NoSignedTransaction covers a
// wallet action that never reached a signed Bitcoin transaction. Nothing this
// node owns can land on the Bitcoin chain, so the rollback journal records the
// ceremony as exhausted.
func TestWalletTransactionExecutor_TerminalOutcome_NoSignedTransaction(t *testing.T) {
	permit := newTestPermit(participation.TBTCSigning)

	executor := &walletTransactionExecutor{
		permit:   permit,
		btcChain: newLocalBitcoinChain(),
	}

	executor.recordTerminalOutcome(&testutils.MockLogger{})

	evidence := assertRecordedTerminalOutcome(
		t,
		permit,
		participation.TerminalOutcomeExhausted,
		participation.TerminalEvidenceNoThreshold,
	)

	if evidence.Reference != "" {
		t.Errorf(
			"expected no evidence reference, got [%s]",
			evidence.Reference,
		)
	}
}

// TestWalletTransactionExecutor_TerminalOutcome_SignedTransaction covers a
// wallet action whose signing reached the threshold. The signed transaction is
// the action's durable result and any wallet member may put it on the Bitcoin
// network, so its hash must reach the journal for offline reconciliation.
func TestWalletTransactionExecutor_TerminalOutcome_SignedTransaction(t *testing.T) {
	privateKeyScalar := big.NewInt(100)
	executingWallet := generateWallet(privateKeyScalar)

	btcChain, transactionBuilder := buildSignTransactionFixture(t, executingWallet)

	sigHashes, err := transactionBuilder.ComputeSignatureHashes()
	if err != nil {
		t.Fatal(err)
	}

	privateKey := &ecdsa.PrivateKey{
		PublicKey: *executingWallet.publicKey,
		D:         privateKeyScalar,
	}
	signatures := make([]*tecdsa.Signature, len(sigHashes))
	for i, sigHash := range sigHashes {
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, sigHash.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		signatures[i] = &tecdsa.Signature{R: r, S: s}
	}

	const startBlock = uint64(0)
	signingExecutor := newMockWalletSigningExecutor()
	signingExecutor.setSignatures(sigHashes, startBlock, signatures)

	permit := newTestPermit(participation.TBTCSigning)

	executor := &walletTransactionExecutor{
		permit:          permit,
		btcChain:        btcChain,
		executingWallet: executingWallet,
		signingExecutor: signingExecutor,
		waitForBlockFn: func(ctx context.Context, _ uint64) error {
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			return nil
		},
	}

	signedTransaction, err := executor.signTransaction(
		&testutils.MockLogger{},
		transactionBuilder,
		startBlock,
		1000,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The action is recorded without any broadcast at all: the ceremony's
	// durable result is the signed transaction, and whether it reached the
	// Bitcoin network is exactly what the offline audit reconciles from this
	// hash.
	executor.recordTerminalOutcome(&testutils.MockLogger{})

	evidence := assertRecordedTerminalOutcome(
		t,
		permit,
		participation.TerminalOutcomeCompleted,
		participation.TerminalEvidenceBitcoinTransaction,
	)

	expectedReference := signedTransaction.Hash().Hex(bitcoin.ReversedByteOrder)
	if evidence.Reference != expectedReference {
		t.Errorf(
			"unexpected evidence reference\nexpected: [%s]\nactual:   [%s]",
			expectedReference,
			evidence.Reference,
		)
	}
}

// runHeartbeatActionForOutcome executes one heartbeat action against the given
// permit, using a fresh failure counter so no earlier heartbeat can push this
// one over the consecutive-failure threshold.
func runHeartbeatActionForOutcome(
	t *testing.T,
	hostChain *localChain,
	signingExecutor *mockHeartbeatSigningExecutor,
	proposal *HeartbeatProposal,
	permit participation.Permit,
) {
	t.Helper()

	runHeartbeatActionWithFailureCounter(
		t,
		hostChain,
		signingExecutor,
		&mockInactivityClaimExecutor{},
		newHeartbeatFailureCounter(),
		proposal,
		permit,
	)
}

// runHeartbeatActionWithFailureCounter executes one heartbeat action against a
// caller-owned failure counter and claim executor, so consecutive low-activity
// heartbeats can be driven up to the threshold that dispatches a claim.
func runHeartbeatActionWithFailureCounter(
	t *testing.T,
	hostChain *localChain,
	signingExecutor *mockHeartbeatSigningExecutor,
	claimExecutor *mockInactivityClaimExecutor,
	failureCounter *heartbeatFailureCounter,
	proposal *HeartbeatProposal,
	permit participation.Permit,
) {
	t.Helper()

	walletPublicKeyBytes, err := hex.DecodeString(heartbeatTestWalletKey())
	if err != nil {
		t.Fatal(err)
	}

	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	const startBlock = uint64(10)

	action := newHeartbeatAction(
		logger,
		hostChain,
		wallet{
			publicKey: mustUnmarshalPublicKey(t, walletPublicKeyBytes),
		},
		signingExecutor,
		proposal,
		failureCounter,
		claimExecutor,
		startBlock,
		startBlock+heartbeatTotalProposalValidityBlocks,
		func(ctx context.Context, blockHeight uint64) error { return nil },
		permit,
	)

	// The action's own error is not the subject here: every exit, successful or
	// not, must leave exactly one terminal disposition behind.
	_ = action.execute()
}

// TestHeartbeatAction_TerminalOutcomeBindsDispatchedInactivityClaim asserts a
// heartbeat that went on to file an inactivity claim is distinguishable in the
// journal from a healthy one. The claim runs under the heartbeat's own permit
// and leaves no separate record, so a reference naming only the signature would
// let the audit clear penalty state it never saw.
func TestHeartbeatAction_TerminalOutcomeBindsDispatchedInactivityClaim(
	t *testing.T,
) {
	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	// runToClaimThreshold drives consecutive low-activity heartbeats until the
	// claim threshold is crossed and returns the last heartbeat's evidence
	// reference together with the number of claims that were dispatched.
	runToClaimThreshold := func(
		t *testing.T,
		activeMembers uint32,
		runs int,
	) (string, int) {
		t.Helper()

		hostChain := Connect()
		hostChain.setOperatorsEligibleStake(big.NewInt(100000))

		claimExecutor := &mockInactivityClaimExecutor{}
		failureCounter := newHeartbeatFailureCounter()

		var reference string
		for run := 0; run < runs; run++ {
			permit := newTestPermit(participation.TBTCHeartbeat)

			runHeartbeatActionWithFailureCounter(
				t,
				hostChain,
				&mockHeartbeatSigningExecutor{
					activeOperatorsCount: activeMembers,
				},
				claimExecutor,
				failureCounter,
				proposal,
				permit,
			)

			reference = assertRecordedTerminalOutcome(
				t,
				permit,
				participation.TerminalOutcomeCompleted,
				participation.TerminalEvidenceProtocolResult,
			).Reference
		}

		return reference, claimExecutor.calls
	}

	claimed, claimCalls := runToClaimThreshold(
		t,
		heartbeatSigningMinimumActiveMembers-1,
		heartbeatConsecutiveFailureThreshold,
	)
	if claimCalls != 1 {
		t.Fatalf(
			"expected exactly one dispatched inactivity claim, got [%d]",
			claimCalls,
		)
	}

	healthy, healthyClaimCalls := runToClaimThreshold(
		t,
		heartbeatSigningMinimumActiveMembers,
		heartbeatConsecutiveFailureThreshold,
	)
	if healthyClaimCalls != 0 {
		t.Fatalf(
			"expected no dispatched inactivity claim, got [%d]",
			healthyClaimCalls,
		)
	}

	if claimed == healthy {
		t.Errorf(
			"a heartbeat that filed an inactivity claim and one that did not "+
				"produced the same evidence reference [%s]",
			claimed,
		)
	}
}

// TestHeartbeatPenaltyState_InactiveMemberBytesAreCanonical asserts the claimed
// member set contributes a deterministic identity: the signing activity report's
// ordering is incidental, so two records of the same claim must agree.
func TestHeartbeatPenaltyState_InactiveMemberBytesAreCanonical(t *testing.T) {
	ordered := heartbeatPenaltyState{
		claimDispatched: true,
		inactiveMembers: []group.MemberIndex{3, 9, 14},
	}
	shuffled := heartbeatPenaltyState{
		claimDispatched: true,
		inactiveMembers: []group.MemberIndex{14, 3, 9, 3},
	}

	if !bytes.Equal(ordered.inactiveMemberBytes(), shuffled.inactiveMemberBytes()) {
		t.Errorf(
			"one claimed member set produced two identities [%x] and [%x]",
			ordered.inactiveMemberBytes(),
			shuffled.inactiveMemberBytes(),
		)
	}

	disjoint := heartbeatPenaltyState{
		claimDispatched: true,
		inactiveMembers: []group.MemberIndex{3, 9, 15},
	}
	if bytes.Equal(ordered.inactiveMemberBytes(), disjoint.inactiveMemberBytes()) {
		t.Errorf(
			"two different claimed member sets produced the same identity [%x]",
			ordered.inactiveMemberBytes(),
		)
	}

	empty := heartbeatPenaltyState{}
	if empty.inactiveMemberBytes() != nil {
		t.Errorf(
			"a heartbeat that dispatched no claim named members [%x]",
			empty.inactiveMemberBytes(),
		)
	}
}

// TestHeartbeatAction_TerminalOutcome walks every exit of the heartbeat action
// and asserts the disposition it leaves in the rollback journal. The heartbeat's
// durable result is the threshold signature; the inactivity accounting that
// follows a low-activity signing does not change that.
func TestHeartbeatAction_TerminalOutcome(t *testing.T) {
	tests := map[string]struct {
		operatorUnstaking bool
		signingFails      bool
		activeMembers     uint32
		expectedOutcome   participation.TerminalOutcome
		expectedKind      participation.TerminalEvidenceKind
	}{
		"signing produced a signature": {
			activeMembers:   heartbeatSigningMinimumActiveMembers,
			expectedOutcome: participation.TerminalOutcomeCompleted,
			expectedKind:    participation.TerminalEvidenceProtocolResult,
		},
		"signing produced a signature below the activity threshold": {
			activeMembers:   heartbeatSigningMinimumActiveMembers - 1,
			expectedOutcome: participation.TerminalOutcomeCompleted,
			expectedKind:    participation.TerminalEvidenceProtocolResult,
		},
		"signing failed": {
			signingFails:    true,
			expectedOutcome: participation.TerminalOutcomeExhausted,
			expectedKind:    participation.TerminalEvidenceNoThreshold,
		},
		"operator is unstaking": {
			operatorUnstaking: true,
			activeMembers:     heartbeatSigningMinimumActiveMembers,
			expectedOutcome:   participation.TerminalOutcomeExhausted,
			expectedKind:      participation.TerminalEvidenceNoThreshold,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			hostChain := Connect()
			if test.operatorUnstaking {
				hostChain.setOperatorsEligibleStake(big.NewInt(0))
			} else {
				hostChain.setOperatorsEligibleStake(big.NewInt(100000))
			}

			permit := newTestPermit(participation.TBTCHeartbeat)
			signingExecutor := &mockHeartbeatSigningExecutor{
				shouldFail:           test.signingFails,
				activeOperatorsCount: test.activeMembers,
			}

			runHeartbeatActionForOutcome(
				t,
				hostChain,
				signingExecutor,
				&HeartbeatProposal{
					Message: [16]byte{
						0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					},
				},
				permit,
			)

			if test.operatorUnstaking &&
				signingExecutor.requestedMessage != nil {
				t.Error("an unstaking operator must not sign")
			}

			assertRecordedTerminalOutcome(
				t,
				permit,
				test.expectedOutcome,
				test.expectedKind,
			)
		})
	}
}

// TestHeartbeatAction_TerminalOutcomeBindsResultToProposal asserts the recorded
// evidence identifies the exact heartbeat that ran. Two heartbeats of the same
// wallet must not be interchangeable in the journal, otherwise the audit cannot
// tell which proposal a recorded result belongs to.
func TestHeartbeatAction_TerminalOutcomeBindsResultToProposal(t *testing.T) {
	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))

	references := make([]string, 0, 2)
	for _, message := range [][16]byte{
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
	} {
		permit := newTestPermit(participation.TBTCHeartbeat)

		runHeartbeatActionForOutcome(
			t,
			hostChain,
			&mockHeartbeatSigningExecutor{
				activeOperatorsCount: heartbeatSigningMinimumActiveMembers,
			},
			&HeartbeatProposal{Message: message},
			permit,
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidenceProtocolResult,
		)
		references = append(references, evidence.Reference)
	}

	if references[0] == references[1] {
		t.Errorf(
			"two distinct heartbeat proposals produced the same evidence "+
				"reference [%s]",
			references[0],
		)
	}
}

// TestCoordinationTerminalOutcome covers the wallet coordination procedure's
// disposition. The procedure's durable result is the proposal the wallet agreed
// on; the wallet action it dispatches runs under its own permit and reports its
// own outcome.
func TestCoordinationTerminalOutcome(t *testing.T) {
	walletPublicKeyBytes, err := hex.DecodeString(heartbeatTestWalletKey())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("no agreed result", func(t *testing.T) {
		permit := newTestPermit(participation.TBTCWalletCoordination)

		recordCoordinationTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			walletPublicKeyBytes,
			nil,
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeExhausted,
			participation.TerminalEvidenceNoThreshold,
		)

		if evidence.Reference != "" {
			t.Errorf(
				"expected no evidence reference, got [%s]",
				evidence.Reference,
			)
		}
	})

	t.Run("distinct windows produce distinct references", func(t *testing.T) {
		references := make([]string, 0, 2)
		for _, coordinationBlock := range []uint64{900, 1800} {
			permit := newTestPermit(participation.TBTCWalletCoordination)

			recordCoordinationTerminalOutcome(
				&testutils.MockLogger{},
				permit,
				walletPublicKeyBytes,
				&coordinationResult{
					window:   newCoordinationWindow(coordinationBlock),
					leader:   chain.Address("0xleader"),
					proposal: &HeartbeatProposal{},
				},
			)

			evidence := assertRecordedTerminalOutcome(
				t,
				permit,
				participation.TerminalOutcomeCompleted,
				participation.TerminalEvidenceProtocolResult,
			)
			references = append(references, evidence.Reference)
		}

		if references[0] == references[1] {
			t.Errorf(
				"two coordination windows produced the same evidence "+
					"reference [%s]",
				references[0],
			)
		}
	})

	// A wallet can agree on two different redemptions of the same action type
	// in the same window across a restart. An identity that named only the
	// action type would report both as the same durable result, so the offline
	// audit could clear one window's journal entry with the other's settlement.
	t.Run("distinct proposals of one action type produce distinct references", func(t *testing.T) {
		proposals := []CoordinationProposal{
			&RedemptionProposal{
				RedeemersOutputScripts: []bitcoin.Script{{0x01}},
				RedemptionTxFee:        big.NewInt(1000),
			},
			&RedemptionProposal{
				RedeemersOutputScripts: []bitcoin.Script{{0x02}},
				RedemptionTxFee:        big.NewInt(1000),
			},
		}

		references := make([]string, 0, len(proposals))
		for _, proposal := range proposals {
			permit := newTestPermit(participation.TBTCWalletCoordination)

			recordCoordinationTerminalOutcome(
				&testutils.MockLogger{},
				permit,
				walletPublicKeyBytes,
				&coordinationResult{
					window:   newCoordinationWindow(900),
					leader:   chain.Address("0xleader"),
					proposal: proposal,
				},
			)

			evidence := assertRecordedTerminalOutcome(
				t,
				permit,
				participation.TerminalOutcomeCompleted,
				participation.TerminalEvidenceProtocolResult,
			)
			references = append(references, evidence.Reference)
		}

		if references[0] == references[1] {
			t.Errorf(
				"two distinct redemption proposals in one window produced the "+
					"same evidence reference [%s]",
				references[0],
			)
		}
	})

	// A proposal the node cannot serialize has no faithful identity. Recording
	// a weaker reference would hand the audit a result it cannot pin down, and
	// recording exhausted would deny a dispatched wallet action, so the permit
	// must be left to close unresolved and block the offline barrier.
	t.Run("unserializable proposal records nothing", func(t *testing.T) {
		permit := newTestPermit(participation.TBTCWalletCoordination)

		recordCoordinationTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			walletPublicKeyBytes,
			&coordinationResult{
				window:   newCoordinationWindow(900),
				leader:   chain.Address("0xleader"),
				proposal: &unmarshalableProposal{},
			},
		)

		if recorded := permit.recordedTerminalOutcomes(); len(recorded) != 0 {
			t.Errorf(
				"expected no terminal outcome for an unidentifiable result, "+
					"got [%+v]",
				recorded,
			)
		}
	})
}

// unmarshalableProposal stands in for a proposal whose serialization fails.
type unmarshalableProposal struct{}

func (up *unmarshalableProposal) ActionType() WalletActionType {
	return ActionRedemption
}

func (up *unmarshalableProposal) ValidityBlocks() uint64 {
	return 0
}

func (up *unmarshalableProposal) Marshal() ([]byte, error) {
	return nil, errors.New("proposal cannot be serialized")
}

func (up *unmarshalableProposal) Unmarshal([]byte) error {
	return errors.New("proposal cannot be deserialized")
}

// TestRecordPermitTerminalOutcome_NilPermit asserts the recorder tolerates a nil
// permit. It runs deferred on the action's exit path, so a panic there would
// take down the action's goroutine after the work already finished.
func TestRecordPermitTerminalOutcome_NilPermit(t *testing.T) {
	recordPermitNoThreshold(&testutils.MockLogger{}, nil)
}

// TestSignatureComponentBytes covers the nil signature component the tECDSA
// signature type admits.
func TestSignatureComponentBytes(t *testing.T) {
	if bytes := signatureComponentBytes(nil); bytes != nil {
		t.Errorf("expected nil bytes for a nil component, got [%v]", bytes)
	}

	bytes := signatureComponentBytes(big.NewInt(258))
	if len(bytes) != 2 || bytes[0] != 0x01 || bytes[1] != 0x02 {
		t.Errorf("unexpected component bytes [%v]", bytes)
	}
}
