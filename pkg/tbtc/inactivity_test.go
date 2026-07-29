package tbtc

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/inactivity"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

func TestInactivityClaimExecutor_ClaimInactivity(t *testing.T) {
	executor, walletEcdsaID, chain := setupInactivityClaimExecutorScenario(t)

	initialNonce, err := chain.GetInactivityClaimNonce(walletEcdsaID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	message := big.NewInt(100)
	inactiveMembersIndexes := []group.MemberIndex{1, 4}

	disposition, err := executor.claimInactivity(
		ctx,
		newTestPermit(participation.TBTCInactivityClaim),
		inactiveMembersIndexes,
		true,
		message,
	)
	if err != nil {
		t.Fatal(err)
	}

	currentNonce, err := chain.GetInactivityClaimNonce(walletEcdsaID)
	if err != nil {
		t.Fatal(err)
	}

	expectedNonceDiff := uint64(1)
	nonceDiff := currentNonce.Uint64() - initialNonce.Uint64()

	testutils.AssertUintsEqual(
		t,
		"inactivity nonce difference",
		expectedNonceDiff,
		nonceDiff,
	)

	// A member reached the submitting call, so the disposition must say a
	// transaction exists rather than leave the caller to infer it.
	if !disposition.submissionAttempted {
		t.Error("expected the executor to report an attempted submission")
	}

	// The claim reached the chain, so the executor must report the settlement
	// its caller records; the reported identity has to be the wallet and the
	// nonce the claim consumed, not the wallet's current one.
	if disposition.settlement == nil {
		t.Fatal("expected the submitted inactivity claim to be reported settled")
	}
	if disposition.settlement.walletID != walletEcdsaID {
		t.Errorf(
			"unexpected settled wallet\nexpected: [0x%x]\nactual:   [0x%x]",
			walletEcdsaID,
			disposition.settlement.walletID,
		)
	}
	testutils.AssertBigIntsEqual(
		t,
		"settled inactivity claim nonce",
		initialNonce,
		disposition.settlement.nonce,
	)
}

// TestInactivityClaimExecutor_ClaimInactivity_UnrelatedWalletSettlement checks
// that a claim settled against a different wallet is not reported as this
// claim's settlement. The chain subscription is unfiltered, so the executor is
// the only thing standing between an unrelated penalty and a terminal record
// that names it.
func TestInactivityClaimExecutor_ClaimInactivity_UnrelatedWalletSettlement(
	t *testing.T,
) {
	walletID := [32]byte{0x01}
	nonce := big.NewInt(7)

	observer := newInactivityClaimSettlementObserver(walletID, nonce)

	for _, test := range []struct {
		name  string
		event *InactivityClaimedEvent
	}{
		{
			name:  "no event at all",
			event: nil,
		},
		{
			name: "another wallet at the same nonce",
			event: &InactivityClaimedEvent{
				WalletID: [32]byte{0x02},
				Nonce:    big.NewInt(7),
			},
		},
		{
			name: "the same wallet at a later nonce",
			event: &InactivityClaimedEvent{
				WalletID: walletID,
				Nonce:    big.NewInt(8),
			},
		},
		{
			name: "the same wallet with no nonce",
			event: &InactivityClaimedEvent{
				WalletID: walletID,
				Nonce:    nil,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if observer.observe(test.event) {
				t.Error("expected the event not to be attributed to the claim")
			}
			if observer.settled() != nil {
				t.Error("expected no settlement to be recorded")
			}
		})
	}

	matching := &InactivityClaimedEvent{
		WalletID:    walletID,
		Nonce:       big.NewInt(7),
		BlockNumber: 1000,
	}
	if !observer.observe(matching) {
		t.Fatal("expected the matching event to be attributed to the claim")
	}

	// Every controlled signer observes the same settlement; the record must
	// stay on the first observation so members cannot report different blocks
	// for one claim.
	if !observer.observe(&InactivityClaimedEvent{
		WalletID:    walletID,
		Nonce:       big.NewInt(7),
		BlockNumber: 2000,
	}) {
		t.Fatal("expected a repeated matching event to still match the claim")
	}
	if settled := observer.settled(); settled != matching {
		t.Errorf(
			"expected the first observation to be retained, got [%v]",
			settled,
		)
	}
}

// TestInactivityClaimExecutor_ResolveInactivityClaim walks every way one claim
// can end once publishing has stopped.
//
// The lifecycle these cases pin is the one a real provider imposes: the
// submitting call returns when the transaction is accepted, and the claim is
// mined — and announced — afterwards. Observation therefore has to outlive
// publishing, and the disposition has to keep "a transaction may exist" apart
// from "the penalty landed", because a rollback reads those differently.
func TestInactivityClaimExecutor_ResolveInactivityClaim(t *testing.T) {
	walletID := [32]byte{0x07}
	nonce := big.NewInt(0)

	settlementEvent := &InactivityClaimedEvent{
		WalletID:    walletID,
		Nonce:       big.NewInt(0),
		BlockNumber: 4242,
	}

	// mineCompetingClaim consumes the claim slot on chain without ever
	// reaching this node's subscription, which is what a settlement observed
	// by nobody here looks like.
	mineCompetingClaim := func(t *testing.T, localChain *localChain) {
		if err := localChain.SubmitInactivityClaim(
			&InactivityClaim{WalletID: walletID},
			new(big.Int).Set(nonce),
			nil,
		); err != nil {
			t.Fatalf("cannot settle the competing claim: [%v]", err)
		}
	}

	tests := map[string]struct {
		submissionAttempted bool
		// before runs against the chain before the resolution starts, standing
		// in for whatever already happened while publishing was running.
		before func(t *testing.T, localChain *localChain)
		// wait stands in for whatever the chain does while the bounded
		// settlement wait is in progress. It is nil for the cases that must
		// take no wait at all.
		wait func(
			t *testing.T,
			localChain *localChain,
			settlement *inactivityClaimSettlementObserver,
			ctx context.Context,
		) error
		expectedSettlement bool
		expectedWait       bool
	}{
		// The regression this whole lifecycle exists for: the claim's own
		// event arrives after every publishing goroutine has returned. The
		// call-wide subscription is still listening, so the penalty is
		// resolved instead of being reported as an unknown.
		"a settlement announced after publishing ended is resolved": {
			submissionAttempted: true,
			wait: func(
				_ *testing.T,
				_ *localChain,
				settlement *inactivityClaimSettlementObserver,
				ctx context.Context,
			) error {
				go settlement.observe(settlementEvent)
				// Blocking until cancellation makes the wait prove it ends on
				// the settlement rather than on its own deadline.
				<-ctx.Done()
				return ctx.Err()
			},
			expectedSettlement: true,
			expectedWait:       true,
		},
		// The subscription can miss the event entirely — a dropped
		// notification, a reorganized filter. The consumed nonce is the
		// chain's own receipt for the claim slot and resolves it anyway.
		"a settlement seen only as a consumed nonce is resolved": {
			submissionAttempted: true,
			wait: func(
				t *testing.T,
				localChain *localChain,
				_ *inactivityClaimSettlementObserver,
				_ context.Context,
			) error {
				mineCompetingClaim(t, localChain)
				return nil
			},
			expectedSettlement: true,
			expectedWait:       true,
		},
		// The one genuinely ambiguous case: a transaction was handed to the
		// chain and nothing came back. It must stay unresolved so the offline
		// barrier blocks on it.
		"a submission that never settles stays unresolved": {
			submissionAttempted: true,
			wait: func(
				_ *testing.T,
				_ *localChain,
				_ *inactivityClaimSettlementObserver,
				_ context.Context,
			) error {
				return nil
			},
			expectedWait: true,
		},
		// No member reached the submitting call, so nothing is in flight.
		// Waiting for it would only delay the heartbeat that owns the claim.
		"a claim that never reached the chain takes no wait": {},
		// Another node's submission can settle this claim slot while no
		// controlled member ever submits; the penalty is still on chain and
		// still this permit's.
		"a foreign settlement is resolved without any wait": {
			before:             mineCompetingClaim,
			expectedSettlement: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			localChain := Connect()
			settlement := newInactivityClaimSettlementObserver(
				walletID,
				new(big.Int).Set(nonce),
			)

			if test.before != nil {
				test.before(t, localChain)
			}

			var waited bool
			executor := &inactivityClaimExecutor{
				chain: localChain,
				waitForBlockFn: func(ctx context.Context, _ uint64) error {
					waited = true
					if test.wait == nil {
						return nil
					}
					return test.wait(t, localChain, settlement, ctx)
				},
			}

			disposition := executor.resolveInactivityClaim(
				context.Background(),
				&testutils.MockLogger{},
				settlement,
				walletID,
				new(big.Int).Set(nonce),
				test.submissionAttempted,
			)

			if disposition.submissionAttempted != test.submissionAttempted {
				t.Errorf(
					"unexpected submission attempt\nexpected: [%v]\nactual:   [%v]",
					test.submissionAttempted,
					disposition.submissionAttempted,
				)
			}
			if waited != test.expectedWait {
				t.Errorf(
					"unexpected settlement wait\nexpected: [%v]\nactual:   [%v]",
					test.expectedWait,
					waited,
				)
			}

			if !test.expectedSettlement {
				if disposition.settlement != nil {
					t.Fatalf(
						"expected no resolved settlement, got [%+v]",
						disposition.settlement,
					)
				}
				return
			}

			if disposition.settlement == nil {
				t.Fatal("expected the claim settlement to be resolved")
			}
			if disposition.settlement.walletID != walletID {
				t.Errorf(
					"unexpected settled wallet\nexpected: [0x%x]\nactual:   [0x%x]",
					walletID,
					disposition.settlement.walletID,
				)
			}
			testutils.AssertBigIntsEqual(
				t,
				"settled inactivity claim nonce",
				nonce,
				disposition.settlement.nonce,
			)
		})
	}
}

// TestInactivityClaimExecutor_ResolveInactivityClaim_ContextCancelled asserts a
// claim whose owning window closes mid-wait is reported unresolved rather than
// waited on past the deadline the heartbeat set for it.
func TestInactivityClaimExecutor_ResolveInactivityClaim_ContextCancelled(
	t *testing.T,
) {
	localChain := Connect()

	walletID := [32]byte{0x09}
	nonce := big.NewInt(0)

	settlement := newInactivityClaimSettlementObserver(walletID, nonce)

	ctx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx()

	executor := &inactivityClaimExecutor{
		chain: localChain,
		waitForBlockFn: func(ctx context.Context, _ uint64) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}

	disposition := executor.resolveInactivityClaim(
		ctx,
		&testutils.MockLogger{},
		settlement,
		walletID,
		nonce,
		true,
	)

	if !disposition.submissionAttempted {
		t.Error("expected the submission to stay on the record")
	}
	if disposition.settlement != nil {
		t.Errorf(
			"expected a canceled resolution to settle nothing, got [%+v]",
			disposition.settlement,
		)
	}
}

// TestInactivityClaimExecutor_ClaimInactivity_LateSettlement drives the whole
// executor against a chain that behaves like a real provider: submissions are
// accepted and mined only later. The claim's event therefore arrives after
// every publishing goroutine has returned, which is precisely when a
// per-publisher subscription would already be gone.
func TestInactivityClaimExecutor_ClaimInactivity_LateSettlement(t *testing.T) {
	executor, walletEcdsaID, localChain := setupInactivityClaimExecutorScenario(t)

	initialNonce, err := localChain.GetInactivityClaimNonce(walletEcdsaID)
	if err != nil {
		t.Fatal(err)
	}

	var mutex sync.Mutex
	var accepted []func()

	localChain.setInactivityClaimMiner(func(mine func()) {
		mutex.Lock()
		defer mutex.Unlock()

		accepted = append(accepted, mine)
	})

	// Every controlled member waits once for its submission delay and submits
	// immediately afterwards, so a wait requested once all of them have been
	// accepted can only be the executor's settlement resolution. Mining there
	// puts the claim's event strictly after the end of publishing.
	signerCount := len(executor.signers)
	waitForBlock := executor.waitForBlockFn
	listenersAtSettlement := -1
	executor.waitForBlockFn = func(ctx context.Context, block uint64) error {
		mutex.Lock()
		var mine func()
		if len(accepted) == signerCount {
			mine, accepted = accepted[0], nil
		}
		mutex.Unlock()

		if mine != nil {
			listenersAtSettlement = localChain.inactivityClaimedHandlerCount()
			mine()
		}

		return waitForBlock(ctx, block)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	disposition, err := executor.claimInactivity(
		ctx,
		newTestPermit(participation.TBTCInactivityClaim),
		[]group.MemberIndex{1, 4},
		true,
		big.NewInt(100),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !disposition.submissionAttempted {
		t.Error("expected the executor to report an attempted submission")
	}
	// The point of the lifecycle: the claim was announced with publishing
	// already over, and something was still listening for it.
	if listenersAtSettlement < 1 {
		t.Errorf(
			"the claim settled with [%d] subscriptions left listening",
			listenersAtSettlement,
		)
	}
	if disposition.settlement == nil {
		t.Fatal(
			"a claim mined after publishing ended was not reported settled",
		)
	}
	if disposition.settlement.walletID != walletEcdsaID {
		t.Errorf(
			"unexpected settled wallet\nexpected: [0x%x]\nactual:   [0x%x]",
			walletEcdsaID,
			disposition.settlement.walletID,
		)
	}
	testutils.AssertBigIntsEqual(
		t,
		"settled inactivity claim nonce",
		initialNonce,
		disposition.settlement.nonce,
	)
}

// TestInactivityClaimSettlementDeadline asserts the settlement wait's bound is
// rejected when it overflows rather than clamped to the top of the block range.
// A clamped bound leaves a wait nothing but the heartbeat window ends; the
// rejection reaches the same disposition — the claim stays unresolved and the
// offline barrier holds on it — and says why.
func TestInactivityClaimSettlementDeadline(t *testing.T) {
	const resolution = uint64(inactivityClaimSettlementResolutionBlocks)

	tests := map[string]struct {
		currentBlock     uint64
		expectedDeadline uint64
		expectedError    bool
	}{
		"an ordinary height": {
			currentBlock:     1_000_000,
			expectedDeadline: 1_000_000 + resolution,
		},
		"the highest height whose deadline is representable": {
			currentBlock:     math.MaxUint64 - resolution,
			expectedDeadline: math.MaxUint64,
		},
		"the lowest height whose deadline is not": {
			currentBlock:  math.MaxUint64 - resolution + 1,
			expectedError: true,
		},
		"the highest representable height": {
			currentBlock:  math.MaxUint64,
			expectedError: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			deadline, err := inactivityClaimSettlementDeadline(
				test.currentBlock,
			)

			if test.expectedError {
				if !errors.Is(err, errInactivityDeadlineOverflow) {
					t.Errorf(
						"expected an overflow rejection\nactual: [%v]",
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: [%v]", err)
			}
			if deadline != test.expectedDeadline {
				t.Errorf(
					"unexpected settlement deadline\n"+
						"expected: [%d]\nactual:   [%d]",
					test.expectedDeadline,
					deadline,
				)
			}
			// The property the bound exists for: a deadline the executor waits
			// on must never name a block the chain has already passed.
			if deadline < test.currentBlock {
				t.Errorf(
					"settlement deadline [%d] is below the current block [%d]",
					deadline,
					test.currentBlock,
				)
			}
		})
	}
}

// TestInactivityClaimSubmissionBlock asserts the staggered submission block is
// rejected on overflow. It is the last quantity derived before an irreversible
// on-chain claim, so a wrapped value would authorize the submission from
// arithmetic that had already lost its meaning.
func TestInactivityClaimSubmissionBlock(t *testing.T) {
	const step = uint64(inactivityClaimSubmissionDelayStepBlocks)

	tests := map[string]struct {
		currentBlock  uint64
		memberIndex   group.MemberIndex
		expectedBlock uint64
		expectedError bool
	}{
		"the first member never waits": {
			currentBlock:  1_000_000,
			memberIndex:   1,
			expectedBlock: 1_000_000,
		},
		"a later member waits its index out": {
			currentBlock:  1_000_000,
			memberIndex:   5,
			expectedBlock: 1_000_000 + 4*step,
		},
		"the first member at the top of the block range": {
			currentBlock:  math.MaxUint64,
			memberIndex:   1,
			expectedBlock: math.MaxUint64,
		},
		"the highest height that still admits the delay": {
			currentBlock:  math.MaxUint64 - 4*step,
			memberIndex:   5,
			expectedBlock: math.MaxUint64,
		},
		"one height past what the delay admits": {
			currentBlock:  math.MaxUint64 - 4*step + 1,
			memberIndex:   5,
			expectedError: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			submissionBlock, err := inactivityClaimSubmissionBlock(
				test.currentBlock,
				test.memberIndex,
			)

			if test.expectedError {
				if !errors.Is(err, errInactivityDeadlineOverflow) {
					t.Errorf(
						"expected an overflow rejection\nactual: [%v]",
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: [%v]", err)
			}
			if submissionBlock != test.expectedBlock {
				t.Errorf(
					"unexpected submission block\n"+
						"expected: [%d]\nactual:   [%d]",
					test.expectedBlock,
					submissionBlock,
				)
			}
			if submissionBlock < test.currentBlock {
				t.Errorf(
					"submission block [%d] is below the current block [%d]",
					submissionBlock,
					test.currentBlock,
				)
			}
		})
	}
}

func TestInactivityClaimExecutor_ClaimInactivity_Busy(t *testing.T) {
	executor, _, _ := setupInactivityClaimExecutorScenario(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	message := big.NewInt(100)
	inactiveMembersIndexes := []group.MemberIndex{1, 4}

	errChan := make(chan error, 1)
	go func() {
		_, err := executor.claimInactivity(
			ctx,
			newTestPermit(participation.TBTCInactivityClaim),
			inactiveMembersIndexes,
			true,
			message,
		)
		errChan <- err
	}()

	time.Sleep(100 * time.Millisecond)

	disposition, err := executor.claimInactivity(
		ctx,
		newTestPermit(participation.TBTCInactivityClaim),
		inactiveMembersIndexes,
		true,
		message,
	)
	testutils.AssertErrorsSame(t, errInactivityClaimExecutorBusy, err)

	// A refused call never subscribed to anything and never reached a
	// submitting call, so it can neither report a settlement observed by the
	// call that holds the executor nor claim a transaction of its own.
	if disposition.submissionAttempted {
		t.Error("expected a refused claim to report no attempted submission")
	}
	if disposition.settlement != nil {
		t.Errorf(
			"expected no settlement from a refused claim, got [%+v]",
			disposition.settlement,
		)
	}

	err = <-errChan
	if err != nil {
		t.Errorf("unexpected error: [%v]", err)
	}
}

func setupInactivityClaimExecutorScenario(t *testing.T) (
	*inactivityClaimExecutor,
	[32]byte,
	*localChain,
) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := ConnectWithKey(operatorPrivateKey)

	localProvider := local.ConnectWithKey(operatorPublicKey)

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(
		operatorPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	var operators []chain.Address
	for i := 0; i < groupParameters.GroupSize; i++ {
		operators = append(operators, operatorAddress)
	}

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(
		groupParameters.GroupSize,
	)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}

	signers := make([]*signer, len(testData))
	for i := range testData {
		privateKeyShare := tecdsa.NewPrivateKeyShare(testData[i])

		signers[i] = &signer{
			wallet: wallet{
				publicKey:             privateKeyShare.PublicKey(),
				signingGroupOperators: operators,
			},
			signingGroupMemberIndex: group.MemberIndex(i + 1),
			privateKeyShare:         privateKeyShare,
		}
	}

	keyStorePersistence := createMockKeyStorePersistence(t, signers...)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signers[0].wallet.publicKey)
	walletID, err := localChain.CalculateWalletID(signers[0].wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	localChain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: walletID,
			State:         StateLive,
		},
	)

	node, err := newNode(
		groupParameters,
		localChain,
		newLocalBitcoinChain(),
		localProvider,
		keyStorePersistence,
		&mockPersistenceHandle{},
		generator.StartScheduler(),
		&mockCoordinationProposalGenerator{},
		Config{},
	)
	if err != nil {
		t.Fatal(err)
	}

	executor, ok, err := node.getInactivityClaimExecutor(
		signers[0].wallet.publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}

	return executor, walletID, localChain
}

func TestSignClaim_SigningSuccessful(t *testing.T) {
	chain := Connect()
	inactivityClaimSigner := newInactivityClaimSigner(chain)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	claim := inactivity.NewClaimPreimage(
		big.NewInt(5),
		privateKeyShare.PublicKey(),
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signedClaim, err := inactivityClaimSigner.SignClaim(claim)
	if err != nil {
		t.Fatal(err)
	}

	expectedPublicKey := chain.Signing().PublicKey()
	if !reflect.DeepEqual(
		expectedPublicKey,
		signedClaim.PublicKey,
	) {
		t.Errorf(
			"unexpected public key\n"+
				"expected: %v\n"+
				"actual:   %v\n",
			expectedPublicKey,
			signedClaim.PublicKey,
		)
	}

	expectedInactivityClaimHash := inactivity.ClaimHash(
		sha3.Sum256(
			[]byte(fmt.Sprint(
				claim.Nonce,
				claim.WalletPublicKey,
				claim.InactiveMembersIndexes,
				claim.HeartbeatFailed,
			)),
		),
	)
	if expectedInactivityClaimHash != signedClaim.ClaimHash {
		t.Errorf(
			"unexpected claim hash\n"+
				"expected: %v\n"+
				"actual:   %v\n",
			expectedInactivityClaimHash,
			signedClaim.ClaimHash,
		)
	}

	// Since signature is different on every run (even if the same private key
	// and claim hash are used), simply verify if it's correct
	signatureVerification, err := chain.Signing().Verify(
		signedClaim.ClaimHash[:],
		signedClaim.Signature,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !signatureVerification {
		t.Errorf(
			"Signature [0x%x] was not generated properly for the claim hash "+
				"[0x%x]",
			signedClaim.Signature,
			signedClaim.ClaimHash,
		)
	}
}

func TestSignClaim_ErrorDuringInactivityClaimHashCalculation(t *testing.T) {
	chain := Connect()
	inactivityClaimSigner := newInactivityClaimSigner(chain)

	// Use nil as the claim to cause hash calculation error.
	_, err := inactivityClaimSigner.SignClaim(nil)

	expectedError := fmt.Errorf("claim is nil")
	if !reflect.DeepEqual(expectedError, err) {
		t.Errorf(
			"unexpected error\nexpected: %v\nactual:   %v\n",
			expectedError,
			err,
		)
	}
}

func TestVerifySignature_VerifySuccessful(t *testing.T) {
	chain := Connect()
	inactivityClaimSigner := newInactivityClaimSigner(chain)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	claim := inactivity.NewClaimPreimage(
		big.NewInt(5),
		privateKeyShare.PublicKey(),
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signedClaim, err := inactivityClaimSigner.SignClaim(claim)
	if err != nil {
		t.Fatal(err)
	}

	verificationSuccessful, err := inactivityClaimSigner.VerifySignature(
		signedClaim,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !verificationSuccessful {
		t.Fatal(
			"Expected successful verification of signature, but it was " +
				"unsuccessful",
		)
	}
}

func TestVerifySignature_VerifyFailure(t *testing.T) {
	chain := Connect()
	inactivityClaimSigner := newInactivityClaimSigner(chain)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	claim := inactivity.NewClaimPreimage(
		big.NewInt(5),
		privateKeyShare.PublicKey(),
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signedClaim, err := inactivityClaimSigner.SignClaim(claim)
	if err != nil {
		t.Fatal(err)
	}

	anotherClaim := inactivity.NewClaimPreimage(
		big.NewInt(6),
		privateKeyShare.PublicKey(),
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	anotherSignedClaim, err := inactivityClaimSigner.SignClaim(anotherClaim)
	if err != nil {
		t.Fatal(err)
	}

	// Assign signature from another claim to cause a signature verification
	// failure.
	signedClaim.Signature = anotherSignedClaim.Signature

	verificationSuccessful, err := inactivityClaimSigner.VerifySignature(
		signedClaim,
	)
	if err != nil {
		t.Fatal(err)
	}

	if verificationSuccessful {
		t.Fatal(
			"Expected unsuccessful verification of signature, but it was " +
				"successful",
		)
	}
}

func TestVerifySignature_VerifyError(t *testing.T) {
	chain := Connect()
	inactivityClaimSigner := newInactivityClaimSigner(chain)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	claim := inactivity.NewClaimPreimage(
		big.NewInt(5),
		privateKeyShare.PublicKey(),
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signedClaim, err := inactivityClaimSigner.SignClaim(claim)
	if err != nil {
		t.Fatal(err)
	}

	// Drop the last byte of the signature to cause an error during signature
	// verification.
	signedClaim.Signature = signedClaim.Signature[:len(signedClaim.Signature)-1]

	_, err = inactivityClaimSigner.VerifySignature(signedClaim)

	expectedError := fmt.Errorf(
		"failed to unmarshal signature: [asn1: syntax error: data truncated]",
	)
	if !reflect.DeepEqual(expectedError, err) {
		t.Errorf(
			"unexpected error\n"+
				"expected: [%+v]\n"+
				"actual:   [%+v]",
			expectedError,
			err,
		)
	}
}

// TestSubmitClaim_SubmissionAttemptAccounting pins which exits of the
// submitter count as handing a transaction to the chain.
//
// The distinction decides what a rollback may do. An exit above the submitting
// call — too few signatures, a claim another member already settled, a refused
// penalty fence, a closed window — provably left no transaction anywhere, and
// recording it as a possible penalty would block a homogeneous rollback over
// state that cannot exist. From the submitting call on the opposite holds: a
// call that returns an error may still have broadcast, so the attempt has to
// survive the error.
func TestSubmitClaim_SubmissionAttemptAccounting(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	publicKey := tecdsa.NewPrivateKeyShare(testData[0]).PublicKey()

	ecdsaWalletID := [32]byte{1, 2, 3}
	groupMembers := []uint32{1, 2, 2, 3, 5}
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	thresholdSignatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	tests := map[string]struct {
		signatures map[group.MemberIndex][]byte
		// claimNonce is the nonce the claim is built for; the wallet starts at
		// nonce zero.
		claimNonce int64
		// settledFirst mimics another member consuming the claim slot before
		// this member wakes from its submission delay.
		settledFirst bool
		// commitErr mimics the penalty fence refusing the submission.
		commitErr error
		// cancelled mimics the owning window closing before submission.
		cancelled       bool
		expectedAttempt bool
	}{
		"too few signatures to submit anything": {
			signatures: map[group.MemberIndex][]byte{
				1: []byte("signature 1"),
				2: []byte("signature 2"),
			},
		},
		"a claim another member already settled": {
			signatures:   thresholdSignatures,
			settledFirst: true,
		},
		"a refused penalty fence": {
			signatures: thresholdSignatures,
			commitErr:  participation.ErrPenaltySuppressed,
		},
		"a window closed before submission": {
			signatures: thresholdSignatures,
			cancelled:  true,
		},
		"a transaction the chain rejected": {
			signatures: thresholdSignatures,
			// A nonce the registry refuses still reaches it as a transaction.
			claimNonce:      12345,
			expectedAttempt: true,
		},
		"a transaction the chain accepted": {
			signatures:      thresholdSignatures,
			expectedAttempt: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			localChain := Connect()
			localChain.setWallet(
				bitcoin.PublicKeyHash(publicKey),
				&WalletChainData{EcdsaWalletID: ecdsaWalletID},
			)

			if test.settledFirst {
				if err := localChain.SubmitInactivityClaim(
					&InactivityClaim{WalletID: ecdsaWalletID},
					big.NewInt(0),
					groupMembers,
				); err != nil {
					t.Fatal(err)
				}
			}

			permit := newTestPermit(participation.TBTCInactivityClaim)
			permit.commitErr = test.commitErr

			submission := &inactivityClaimSubmissionAttempt{}

			submitter := newInactivityClaimSubmitter(
				&testutils.MockLogger{},
				localChain,
				groupParameters,
				groupMembers,
				testWaitForBlockFn(localChain),
				permit,
				submission,
			)

			ctx, cancelCtx := context.WithCancel(context.Background())
			defer cancelCtx()
			if test.cancelled {
				cancelCtx()
			}

			// SubmitClaim reports refusals and rejections through its error,
			// which the executor classifies separately; what is under test
			// here is only whether a transaction was handed to the chain.
			_ = submitter.SubmitClaim(
				ctx,
				group.MemberIndex(1),
				inactivity.NewClaimPreimage(
					big.NewInt(test.claimNonce),
					publicKey,
					[]group.MemberIndex{11, 22, 33},
					true,
				),
				test.signatures,
			)

			if submission.recorded() != test.expectedAttempt {
				t.Errorf(
					"unexpected submission attempt\nexpected: [%v]\nactual:   [%v]",
					test.expectedAttempt,
					submission.recorded(),
				)
			}
		})
	}
}

func TestSubmitClaim_MemberSubmitsClaim(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	chain := Connect()

	chain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	inactivityClaimSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		testWaitForBlockFn(chain),
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	memberIndex := group.MemberIndex(1)

	claim := inactivity.NewClaimPreimage(
		big.NewInt(0),
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	err = inactivityClaimSubmitter.SubmitClaim(
		ctx,
		memberIndex,
		claim,
		signatures,
	)
	if err != nil {
		t.Fatal(err)
	}

	expectedNonce := big.NewInt(1)

	nonce, err := chain.GetInactivityClaimNonce(ecdsaWalletID)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertBigIntsEqual(
		t,
		"inactivity nonce",
		expectedNonce,
		nonce,
	)
}

func TestSubmitClaim_AnotherMemberSubmitsClaim(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	chain := Connect()

	chain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	inactivityClaimSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		testWaitForBlockFn(chain),
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	claim := inactivity.NewClaimPreimage(
		big.NewInt(0),
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	// Set up a global listener that will cancel the common context upon claim
	// submission. That mimics the real-world scenario.
	chain.OnInactivityClaimed(
		func(event *InactivityClaimedEvent) {
			cancelCtx()
		},
	)

	// The second member has to be parked in its submission delay when the
	// first member submits, otherwise both submit and the wallet's nonce
	// advances twice. Holding its wait open until the first member is done is
	// what makes that ordering the test's own rather than the block counter's:
	// the delay is two blocks wide, so any wall-clock pause races it.
	secondMemberWaiting := make(chan struct{})
	releaseSecondMember := make(chan struct{})
	var waitMutex sync.Mutex
	waits := 0

	waitForBlock := inactivityClaimSubmitter.waitForBlockFn
	inactivityClaimSubmitter.waitForBlockFn = func(
		ctx context.Context,
		block uint64,
	) error {
		waitMutex.Lock()
		waits++
		held := waits == 1
		waitMutex.Unlock()

		// The second member's goroutine is the only one running until its
		// wait is observed, so the first wait to arrive is always its own.
		if held {
			close(secondMemberWaiting)
			select {
			case <-releaseSecondMember:
			case <-ctx.Done():
			}
		}

		return waitForBlock(ctx, block)
	}

	secondMemberSubmissionChannel := make(chan error)
	// Attempt to submit claim for the second member on a separate goroutine.
	go func() {
		secondMemberIndex := group.MemberIndex(2)
		secondMemberErr := inactivityClaimSubmitter.SubmitClaim(
			ctx,
			secondMemberIndex,
			claim,
			signatures,
		)
		secondMemberSubmissionChannel <- secondMemberErr
	}()

	<-secondMemberWaiting

	// While the second member is waiting for submission eligibility, submit the
	// claim with the first member.
	firstMemberIndex := group.MemberIndex(1)
	firstMemberErr := inactivityClaimSubmitter.SubmitClaim(
		ctx,
		firstMemberIndex,
		claim,
		signatures,
	)
	close(releaseSecondMember)
	if firstMemberErr != nil {
		t.Fatal(firstMemberErr)
	}

	// Check that the second member returned without errors
	secondMemberErr := <-secondMemberSubmissionChannel
	if secondMemberErr != nil {
		t.Fatal(secondMemberErr)
	}

	expectedNonce := big.NewInt(1)

	nonce, err := chain.GetInactivityClaimNonce(ecdsaWalletID)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertBigIntsEqual(
		t,
		"inactivity nonce",
		expectedNonce,
		nonce,
	)
}

func TestSubmitClaim_StaleNonceAfterDelayTreatedAsSubmitted(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	chain := Connect()

	chain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	claim := inactivity.NewClaimPreimage(
		big.NewInt(0),
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	firstMemberSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		func(context.Context, uint64) error { return nil },
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	var firstMemberSubmitErr error
	secondMemberSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		func(ctx context.Context, _ uint64) error {
			// Simulate another member submitting while this member is delayed.
			firstMemberSubmitErr = firstMemberSubmitter.SubmitClaim(
				ctx,
				group.MemberIndex(1),
				claim,
				signatures,
			)
			return nil
		},
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	err = secondMemberSubmitter.SubmitClaim(
		context.Background(),
		group.MemberIndex(2),
		claim,
		signatures,
	)
	if err != nil {
		t.Fatalf("expected stale nonce to be treated as already submitted: %v", err)
	}
	if firstMemberSubmitErr != nil {
		t.Fatalf("first member submission failed: %v", firstMemberSubmitErr)
	}

	expectedNonce := big.NewInt(1)
	nonce, err := chain.GetInactivityClaimNonce(ecdsaWalletID)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertBigIntsEqual(
		t,
		"inactivity nonce",
		expectedNonce,
		nonce,
	)
}

func TestSubmitClaim_InvalidResult(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	chain := Connect()

	chain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	inactivityClaimSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		testWaitForBlockFn(chain),
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	memberIndex := group.MemberIndex(1)

	claim := inactivity.NewClaimPreimage(
		big.NewInt(12345), // Use wrong nonce.
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	err = inactivityClaimSubmitter.SubmitClaim(
		ctx,
		memberIndex,
		claim,
		signatures,
	)

	expectedErr := fmt.Errorf("wrong inactivity claim nonce")
	if !reflect.DeepEqual(expectedErr, err) {
		t.Errorf(
			"unexpected error \nexpected: [%v]\nactual:   [%v]\n",
			expectedErr,
			err,
		)
	}
}

func TestSubmitClaim_ContextCancelled(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	chain := Connect()

	chain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	inactivityClaimSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		testWaitForBlockFn(chain),
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	ctx, cancelCtx := context.WithCancel(context.Background())

	// Simulate the case when timeout occurs and the context gets cancelled.
	cancelCtx()

	memberIndex := group.MemberIndex(1)

	claim := inactivity.NewClaimPreimage(
		big.NewInt(0),
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	err = inactivityClaimSubmitter.SubmitClaim(
		ctx,
		memberIndex,
		claim,
		signatures,
	)
	if err != nil {
		t.Errorf("unexpected error [%v]", err)
	}

	// Check the inactivity nonce is still 0.
	expectedNonce := big.NewInt(0)

	nonce, err := chain.GetInactivityClaimNonce(ecdsaWalletID)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertBigIntsEqual(
		t,
		"inactivity nonce",
		expectedNonce,
		nonce,
	)
}

func TestSubmitClaim_TooFewSignatures(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	chain := Connect()

	chain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	inactivityClaimSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		chain,
		groupParameters,
		groupMembers,
		testWaitForBlockFn(chain),
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	memberIndex := group.MemberIndex(1)

	claim := inactivity.NewClaimPreimage(
		big.NewInt(0),
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
	}

	err = inactivityClaimSubmitter.SubmitClaim(
		ctx,
		memberIndex,
		claim,
		signatures,
	)

	expectedError := fmt.Errorf(
		"could not submit inactivity claim with [2] signatures for group honest threshold [3]",
	)
	if !reflect.DeepEqual(expectedError, err) {
		t.Errorf(
			"unexpected error\n"+
				"expected: [%+v]\n"+
				"actual:   [%+v]",
			expectedError,
			err,
		)
	}
}

// TestSubmitClaim_NonceChangesDuringWait is a regression test for the TOCTOU
// race between the initial nonce read and the on-chain claim submission: a
// member that wakes from its index-based delay must re-read the nonce and
// abort if a competing member has already submitted, instead of attempting
// a doomed submission that the chain would reject with "wrong nonce".
func TestSubmitClaim_NonceChangesDuringWait(t *testing.T) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	publicKey := privateKeyShare.PublicKey()
	walletPublicKeyHash := bitcoin.PublicKeyHash(publicKey)
	ecdsaWalletID := [32]byte{1, 2, 3}

	localChain := Connect()

	localChain.setWallet(
		walletPublicKeyHash,
		&WalletChainData{
			EcdsaWalletID: ecdsaWalletID,
		},
	)

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	groupMembers := []uint32{1, 2, 2, 3, 5}

	signatures := map[group.MemberIndex][]byte{
		1: []byte("signature 1"),
		2: []byte("signature 2"),
		3: []byte("signature 3"),
		4: []byte("signature 4"),
	}

	competitorClaim := &InactivityClaim{
		WalletID: ecdsaWalletID,
	}

	// Simulate a competing member submitting on the first wait invocation.
	// The local chain's SubmitInactivityClaim bumps the nonce, so the
	// post-wait re-check should observe the change and abort.
	var hookFired bool
	hookedWaitForBlockFn := func(ctx context.Context, block uint64) error {
		if !hookFired {
			hookFired = true
			if submitErr := localChain.SubmitInactivityClaim(
				competitorClaim,
				big.NewInt(0),
				groupMembers,
			); submitErr != nil {
				return fmt.Errorf("competitor submission failed: %w", submitErr)
			}
		}
		return testWaitForBlockFn(localChain)(ctx, block)
	}

	inactivityClaimSubmitter := newInactivityClaimSubmitter(
		&testutils.MockLogger{},
		localChain,
		groupParameters,
		groupMembers,
		hookedWaitForBlockFn,
		newTestPermit(participation.TBTCInactivityClaim),
		&inactivityClaimSubmissionAttempt{},
	)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	claim := inactivity.NewClaimPreimage(
		big.NewInt(0),
		publicKey,
		[]group.MemberIndex{11, 22, 33},
		true,
	)

	// memberIndex=2 produces a non-zero submission delay so the wait fires
	// and the post-wait nonce re-check is exercised.
	err = inactivityClaimSubmitter.SubmitClaim(
		ctx,
		group.MemberIndex(2),
		claim,
		signatures,
	)
	if err != nil {
		t.Fatalf(
			"expected nil error after losing the submission race, got: %v",
			err,
		)
	}

	// The competitor's submission bumped the nonce to 1; our member must not
	// have advanced it further.
	finalNonce, err := localChain.GetInactivityClaimNonce(ecdsaWalletID)
	if err != nil {
		t.Fatal(err)
	}

	expectedNonce := big.NewInt(1)
	testutils.AssertBigIntsEqual(
		t,
		"inactivity nonce",
		expectedNonce,
		finalNonce,
	)
}
