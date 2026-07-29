package tbtc

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/exp/slices"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/signing"
)

// TestSigningDoneCheck is a happy path test.
func TestSigningDoneCheck(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	// Use components (shared channel + validator) so each goroutine below
	// gets its own signingDoneCheck instance. In production every operator
	// runs their own instance; sharing one here would race on its fields.
	components := setupSigningDoneCheckComponents(t, groupParameters)

	memberIndexes := make([]group.MemberIndex, components.groupSize)
	for i := range memberIndexes {
		memberIndex := group.MemberIndex(i + 1)
		memberIndexes[i] = memberIndex
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	message := big.NewInt(100)
	attemptNumber := uint64(2)
	// The members below exchange `500 + memberIndex` as their end block, so the
	// lowest of them sits exactly on the attempt's start block. The window's
	// lower edge is inclusive: a member that finished the moment the protocol
	// started did finish inside this attempt.
	attemptStartBlock := uint64(501)
	attemptTimeoutBlock := uint64(1000)
	attemptMemberIndexes := memberIndexes[:groupParameters.HonestThreshold]
	result := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(200),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}

	type outcome struct {
		memberIndex group.MemberIndex
		result      *signing.Result
		signers     participation.MemberIndexes
		endBlock    uint64
		err         error
	}

	wg := sync.WaitGroup{}
	wg.Add(len(memberIndexes))
	outcomesChan := make(chan *outcome, len(memberIndexes))

	for _, memberIndex := range memberIndexes {
		go func(memberIndex group.MemberIndex) {
			defer wg.Done()

			doneCheck := components.newCheck()

			doneCheck.listen(
				ctx,
				message,
				attemptNumber,
				attemptStartBlock,
				attemptTimeoutBlock,
				attemptMemberIndexes,
			)

			if slices.Contains(attemptMemberIndexes, memberIndex) {
				err := doneCheck.signalDone(
					ctx,
					memberIndex,
					message,
					attemptNumber,
					result,
					500+uint64(memberIndex),
				)
				if err != nil {
					outcomesChan <- &outcome{err: err}
					return
				}
			}

			result, signers, endBlock, err := doneCheck.waitUntilAllDone(ctx)

			outcomesChan <- &outcome{
				memberIndex: memberIndex,
				result:      result,
				signers:     signers,
				endBlock:    endBlock,
				err:         err,
			}
		}(memberIndex)
	}

	wg.Wait()
	close(outcomesChan)

	// We exchanged `500 + uint64(memberIndex)` and latest member has index 3.
	expectedEndBlock := 503

	for outcome := range outcomesChan {
		if outcome.err != nil {
			t.Errorf(
				"unexpected error for member [%v]: [%v]",
				outcome.memberIndex,
				outcome.err,
			)
		}

		if outcome.result == nil {
			t.Errorf("unexpected nil result")
		}

		if !result.Signature.Equals(outcome.result.Signature) {
			t.Errorf(
				"unexpected signature for member [%v]\n"+
					"expected: [%v]\n"+
					"actual:   [%v]",
				outcome.memberIndex,
				result.Signature,
				outcome.result.Signature,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("end block for member [%v]", outcome.memberIndex),
			expectedEndBlock,
			int(outcome.endBlock),
		)

		// Every member — including the ones the attempt excluded, which only
		// listen — comes away with the same population: the memberships whose
		// authenticated done checks carried this signature, in ascending order.
		// This is the fact a terminal record needs and a completion cannot
		// supply, so a member that could not name it would leave the ceremony's
		// participants to whichever party wrote the report.
		if !slices.Equal(
			outcome.signers,
			participation.MemberIndexes(attemptMemberIndexes),
		) {
			t.Errorf(
				"unexpected done signers for member [%v]\n"+
					"expected: [%v]\n"+
					"actual:   [%v]",
				outcome.memberIndex,
				attemptMemberIndexes,
				outcome.signers,
			)
		}
	}
}

// TestSigningDoneCheck_MissingConfirmation covers scenario when one member
// did not provide a done check on time.
func TestSigningDoneCheck_MissingConfirmation(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	doneCheck := setupSigningDoneCheck(t, groupParameters)

	memberIndexes := make([]group.MemberIndex, doneCheck.groupSize)
	for i := range memberIndexes {
		memberIndex := group.MemberIndex(i + 1)
		memberIndexes[i] = memberIndex
	}

	ctx, cancelCtx := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelCtx()

	message := big.NewInt(100)
	attemptNumber := uint64(1)
	attemptStartBlock := uint64(50)
	attemptTimeoutBlock := uint64(1000)
	attemptMemberIndexes := memberIndexes[:groupParameters.HonestThreshold]
	result := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(200),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}

	doneCheck.listen(
		ctx,
		message,
		attemptNumber,
		attemptStartBlock,
		attemptTimeoutBlock,
		attemptMemberIndexes,
	)

	for i := 1; i < groupParameters.HonestThreshold; i++ {
		err := doneCheck.signalDone(
			ctx,
			uint8(i),
			message,
			attemptNumber,
			result,
			100,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	returnedResult, signers, endBlock, err := doneCheck.waitUntilAllDone(ctx)

	if returnedResult != nil {
		t.Errorf("expected nil result, has [%v]", returnedResult)
	}
	if len(signers) != 0 {
		t.Errorf("expected no done signers, has [%v]", signers)
	}
	testutils.AssertIntsEqual(t, "end block", 0, int(endBlock))
	testutils.AssertErrorsSame(t, errWaitDoneTimedOut, err)
}

// TestSigningDoneCheck_AnotherSignature covers scenario when one member
// did provide signature other than other members.
func TestSigningDoneCheck_AnotherSignature(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	doneCheck := setupSigningDoneCheck(t, groupParameters)

	memberIndexes := make([]group.MemberIndex, doneCheck.groupSize)
	for i := range memberIndexes {
		memberIndex := group.MemberIndex(i + 1)
		memberIndexes[i] = memberIndex
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	message := big.NewInt(100)
	attemptNumber := uint64(1)
	attemptStartBlock := uint64(50)
	attemptTimeoutBlock := uint64(1000)
	attemptMemberIndexes := memberIndexes[:groupParameters.HonestThreshold]
	correctResult := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(200),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}
	incorrectResult := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(201),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}

	doneCheck.listen(
		ctx,
		message,
		attemptNumber,
		attemptStartBlock,
		attemptTimeoutBlock,
		attemptMemberIndexes,
	)

	// groupParameters.HonestThreshold members provide correct signature
	for i := 1; i < groupParameters.HonestThreshold; i++ {
		err := doneCheck.signalDone(
			ctx,
			uint8(i),
			message,
			attemptNumber,
			correctResult,
			100,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	// one member provides incorrect signature
	err := doneCheck.signalDone(
		ctx,
		uint8(groupParameters.HonestThreshold),
		message,
		attemptNumber,
		incorrectResult,
		100,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Give some time for the message handler goroutine
	time.Sleep(100 * time.Millisecond)

	returnedResult, signers, endBlock, err := doneCheck.waitUntilAllDone(ctx)

	if returnedResult != nil {
		t.Errorf("expected nil result, has [%v]", returnedResult)
	}
	// A population is only ever reported alongside a result the whole attempt
	// agreed on; members naming different signatures did not produce one
	// transcript, so there is nobody to name.
	if len(signers) != 0 {
		t.Errorf("expected no done signers, has [%v]", signers)
	}
	testutils.AssertIntsEqual(t, "end block", 0, int(endBlock))
	if !strings.Contains(err.Error(), "not matching signatures detected") {
		t.Errorf("unexpected error: [%v]", err)
	}
}

// TestSigningDoneCheck_SenderOutsideTheAttempt covers a done message from a
// signing group member the attempt did not select.
//
// Such a member computes nothing and signals nothing, so its done message
// attests to a transcript that never existed. Counting it is not merely
// untidy bookkeeping: the wait concludes as soon as the number of accepted
// messages reaches the number of selected members, so one message from an
// excluded member standing in for a lost message from a selected one both ends
// the attempt early and names a membership that never signed as having
// produced the signature. That name then travels into the release evidence as
// the population behind the result.
//
// The case is built to reach exactly that count: two of the three selected
// members signal, and an excluded member's message would complete the total.
func TestSigningDoneCheck_SenderOutsideTheAttempt(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	doneCheck := setupSigningDoneCheck(t, groupParameters)

	// The listener outlives the wait on purpose. The barrier below has to be
	// reachable on a loaded machine, while the wait's own deadline is the thing
	// this test asserts on, so the two get separate budgets instead of one
	// deadline that either makes the barrier flaky or the timeout slow.
	listenCtx, cancelListenCtx := context.WithTimeout(
		context.Background(),
		signingDoneListenBudget,
	)
	defer cancelListenCtx()

	message := big.NewInt(100)
	attemptNumber := uint64(1)
	attemptStartBlock := uint64(50)
	attemptTimeoutBlock := uint64(1000)
	attemptMemberIndexes := []group.MemberIndex{1, 2, 3}
	// Member 4 is a valid wallet member the attempt excluded, and it signals
	// first: messages reach the check's receive loop in the order they were sent
	// and are ruled on one at a time, so a membership accepted after this one is
	// evidence that this one was already seen and refused.
	signalingMemberIndexes := []group.MemberIndex{4, 1, 2}
	result := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(200),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}

	doneCheck.listen(
		listenCtx,
		message,
		attemptNumber,
		attemptStartBlock,
		attemptTimeoutBlock,
		attemptMemberIndexes,
	)

	for _, memberIndex := range signalingMemberIndexes {
		err := doneCheck.signalDone(
			listenCtx,
			memberIndex,
			message,
			attemptNumber,
			result,
			100,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	// The two selected members are accepted and the excluded one that preceded
	// them is not, which is only readable once the check has ruled on all three.
	awaitDoneSigners(t, doneCheck, participation.MemberIndexes{1, 2})

	waitCtx, cancelWaitCtx := context.WithTimeout(
		context.Background(),
		signingDoneWaitTimeout,
	)
	defer cancelWaitCtx()

	returnedResult, signers, endBlock, err := doneCheck.waitUntilAllDone(waitCtx)

	if returnedResult != nil {
		t.Errorf("expected nil result, has [%v]", returnedResult)
	}
	if len(signers) != 0 {
		t.Errorf("expected no done signers, has [%v]", signers)
	}
	testutils.AssertIntsEqual(t, "end block", 0, int(endBlock))
	testutils.AssertErrorsSame(t, errWaitDoneTimedOut, err)
}

// TestSigningDoneCheck_DoneChecksFromAnotherRun covers done messages produced by
// an earlier run of the same message under a different canonical anchor.
//
// The message and the attempt number do not identify an attempt: a wallet can be
// asked to sign the same message again from a later coordination window, and the
// new run's attempt numbering restarts from zero. Done messages retransmitted
// past their own window, or replayed, therefore match on both fields while
// describing the earlier run's transcript — a different set of selected members,
// reaching a signature over a different sequence of protocol messages. Accepting
// them would let the release evidence for this attempt be populated by a
// transcript this attempt had no part in.
//
// What separates the two runs is the block window each protocol ran in. The
// earlier run finished before this one's protocol started, so its end blocks lie
// below this attempt's start block.
func TestSigningDoneCheck_DoneChecksFromAnotherRun(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	doneCheck := setupSigningDoneCheck(t, groupParameters)

	listenCtx, cancelListenCtx := context.WithTimeout(
		context.Background(),
		signingDoneListenBudget,
	)
	defer cancelListenCtx()

	message := big.NewInt(100)
	attemptNumber := uint64(1)
	attemptStartBlock := uint64(900)
	attemptTimeoutBlock := uint64(930)
	attemptMemberIndexes := []group.MemberIndex{1, 2, 3, 4}
	// The memberships whose earlier-run messages are replayed here, and the one
	// whose in-window message follows them. The barrier membership sends nothing
	// from the earlier run, so the check accepting it and nothing else says
	// exactly one thing: every replayed message ahead of it was ruled on and
	// refused.
	staleMemberIndexes := []group.MemberIndex{1, 2, 3}
	barrierMemberIndex := group.MemberIndex(4)
	// The end block the earlier run's members finished at, before this attempt's
	// protocol started.
	staleEndBlock := uint64(130)
	// And a block inside this attempt's own window, which is what the check is
	// asking the earlier run's messages for.
	currentEndBlock := uint64(910)
	result := &signing.Result{
		Signature: &tecdsa.Signature{
			R:          big.NewInt(200),
			S:          big.NewInt(300),
			RecoveryID: 2,
		},
	}

	doneCheck.listen(
		listenCtx,
		message,
		attemptNumber,
		attemptStartBlock,
		attemptTimeoutBlock,
		attemptMemberIndexes,
	)

	for _, memberIndex := range staleMemberIndexes {
		err := doneCheck.signalDone(
			listenCtx,
			memberIndex,
			message,
			attemptNumber,
			result,
			staleEndBlock,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := doneCheck.signalDone(
		listenCtx,
		barrierMemberIndex,
		message,
		attemptNumber,
		result,
		currentEndBlock,
	); err != nil {
		t.Fatal(err)
	}

	awaitDoneSigners(
		t,
		doneCheck,
		participation.MemberIndexes{barrierMemberIndex},
	)

	waitCtx, cancelWaitCtx := context.WithTimeout(
		context.Background(),
		signingDoneWaitTimeout,
	)
	defer cancelWaitCtx()

	returnedResult, signers, endBlock, err := doneCheck.waitUntilAllDone(waitCtx)

	if returnedResult != nil {
		t.Errorf("expected nil result, has [%v]", returnedResult)
	}
	if len(signers) != 0 {
		t.Errorf("expected no done signers, has [%v]", signers)
	}
	testutils.AssertIntsEqual(t, "end block", 0, int(endBlock))
	testutils.AssertErrorsSame(t, errWaitDoneTimedOut, err)
}

// How long a refusal test's listener stays up. It is also the barrier's
// deadline: the two are the same budget because a barrier can only observe the
// check ruling on a message while the check is still listening.
//
// Generous because it is never spent. The barrier returns as soon as its
// evidence is in, so this bounds a broken build's failure rather than a working
// build's runtime.
const signingDoneListenBudget = 10 * time.Second

// How long a refusal test then waits for a conclusion it must not reach. Several
// done-check intervals wide, so the wait actually evaluates the accepted
// population and declines to conclude on it rather than expiring before its
// first tick.
const signingDoneWaitTimeout = 500 * time.Millisecond

// How often a barrier re-reads the accepted population. This bounds how long a
// test lingers after its evidence has arrived, not how long it may wait for it.
const signingDoneBarrierPollInterval = time.Millisecond

// awaitDoneSigners blocks until the check has accepted exactly the given
// memberships, and fails the test if it has not before the listener's budget
// runs out.
//
// A refusal is only observable once the check has seen the message it refused,
// and the accepted population reads identically before a message arrives and
// after it was refused. A fixed sleep followed by an assertion about what is
// absent therefore holds either way, and holds most readily on the machine least
// likely to have processed anything — the one running the whole suite at once —
// so it is a test that reports a refusal it never witnessed.
//
// Ordering is what makes the wait deterministic instead. Everything a test
// offers reaches one receive channel in send order and is ruled on by a single
// goroutine, so a membership present in the accepted population is evidence that
// every message sent before it was already accepted or refused. A test therefore
// offers the message it expects to be admitted last, and this function returns
// only on exactly the population it names.
func awaitDoneSigners(
	t *testing.T,
	doneCheck *signingDoneCheck,
	expected participation.MemberIndexes,
) {
	t.Helper()

	deadline := time.NewTimer(signingDoneListenBudget)
	defer deadline.Stop()

	ticker := time.NewTicker(signingDoneBarrierPollInterval)
	defer ticker.Stop()

	for {
		actual := recordedDoneSigners(doneCheck)
		if slices.Equal(actual, expected) {
			return
		}

		// The accepted population only ever grows, so a membership outside the
		// expected one is already a message the check admitted and had to
		// refuse. Saying so here names the defect, where waiting out the
		// deadline would only report that the population never settled.
		for _, signer := range actual {
			if !slices.Contains(expected, signer) {
				t.Fatalf(
					"the check accepted a done message from membership [%v]\n"+
						"expected: [%v]\n"+
						"actual:   [%v]",
					signer,
					expected,
					actual,
				)
			}
		}

		select {
		case <-deadline.C:
			t.Fatalf(
				"timed out waiting for the accepted done signers\n"+
					"expected: [%v]\n"+
					"actual:   [%v]",
				expected,
				recordedDoneSigners(doneCheck),
			)
		case <-ticker.C:
		}
	}
}

// recordedDoneSigners returns the memberships whose done messages the check
// accepted for the attempt it is listening for, ascending. A test that is about
// a refusal reads this so it asserts on a message the check saw and rejected
// rather than on one that had not arrived yet.
func recordedDoneSigners(
	doneCheck *signingDoneCheck,
) participation.MemberIndexes {
	doneCheck.attempt.doneSignersMutex.Lock()
	defer doneCheck.attempt.doneSignersMutex.Unlock()

	signers := make(
		participation.MemberIndexes,
		0,
		len(doneCheck.attempt.doneSigners),
	)
	for senderID := range doneCheck.attempt.doneSigners {
		signers = append(signers, senderID)
	}
	slices.Sort(signers)

	return signers
}

// signingDoneCheckComponents holds the shared state used to construct one or
// more signingDoneCheck instances that communicate over the same channel.
type signingDoneCheckComponents struct {
	groupSize           int
	broadcastChannel    net.BroadcastChannel
	membershipValidator *group.MembershipValidator
}

func (c *signingDoneCheckComponents) newCheck() *signingDoneCheck {
	return newSigningDoneCheck(c.groupSize, c.broadcastChannel, c.membershipValidator)
}

// setupSigningDoneCheckComponents builds the shared channel and validator
// without constructing the signingDoneCheck itself, so callers that need
// multiple independent instances (e.g. simulating N operators) can each
// call newCheck() separately.
func setupSigningDoneCheckComponents(
	t *testing.T,
	groupParameters *GroupParameters,
) *signingDoneCheckComponents {
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

	broadcastChannel, err := localProvider.BroadcastChannelFor("channel")
	if err != nil {
		t.Fatal(err)
	}

	broadcastChannel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &signingDoneMessage{}
	})

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		operators,
		localChain.Signing(),
	)

	return &signingDoneCheckComponents{
		groupSize:           groupParameters.GroupSize,
		broadcastChannel:    broadcastChannel,
		membershipValidator: membershipValidator,
	}
}

// setupSigningDoneCheck sets up an instance of the signing done check ready
// to perform test checks.
func setupSigningDoneCheck(
	t *testing.T,
	groupParameters *GroupParameters,
) *signingDoneCheck {
	return setupSigningDoneCheckComponents(t, groupParameters).newCheck()
}
