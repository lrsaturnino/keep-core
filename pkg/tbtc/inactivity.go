package tbtc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/ipfs/go-log/v2"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/inactivity"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

const (
	// inactivityClaimSubmissionDelayStepBlocks determines the delay step in blocks
	// that is used to calculate the submission delay period that should be respected
	// by the given member to avoid all members submitting the same inactivity claim
	// at the same time.
	inactivityClaimSubmissionDelayStepBlocks = 2

	// inactivityClaimSettlementResolutionBlocks bounds how long the executor
	// keeps looking for the settlement of a claim a member already handed to
	// the chain. The submitting call returns once the transaction reaches the
	// provider and the transaction is mined afterwards, so without a wait past
	// the end of publishing the claim's own event routinely arrives after the
	// executor stopped listening and a penalty that did land is reported as
	// unresolved. The bound is generous enough for an ordinary inclusion and
	// short enough to stay well inside the heartbeat window that owns the
	// claim, whose context cuts the wait short in any case.
	inactivityClaimSettlementResolutionBlocks = 12
)

// errInactivityClaimExecutorBusy is an error returned when the inactivity claim
// executor cannot execute the inactivity claim due to another inactivity claim
// execution in progress.
var errInactivityClaimExecutorBusy = fmt.Errorf("inactivity claim executor is busy")

type inactivityClaimExecutor struct {
	lock *semaphore.Weighted

	chain               Chain
	signers             []*signer
	broadcastChannel    net.BroadcastChannel
	membershipValidator *group.MembershipValidator
	groupParameters     *GroupParameters
	protocolLatch       *generator.ProtocolLatch

	waitForBlockFn waitForBlockFn
}

func newInactivityClaimExecutor(
	chain Chain,
	signers []*signer,
	broadcastChannel net.BroadcastChannel,
	membershipValidator *group.MembershipValidator,
	groupParameters *GroupParameters,
	protocolLatch *generator.ProtocolLatch,
	waitForBlockFn waitForBlockFn,
) *inactivityClaimExecutor {
	return &inactivityClaimExecutor{
		lock:                semaphore.NewWeighted(1),
		chain:               chain,
		signers:             signers,
		broadcastChannel:    broadcastChannel,
		membershipValidator: membershipValidator,
		groupParameters:     groupParameters,
		protocolLatch:       protocolLatch,
		waitForBlockFn:      waitForBlockFn,
	}
}

// inactivityClaimSettlement is the canonical identity of an inactivity claim
// that reached the chain: the wallet it was filed against and the nonce it
// consumed. The registry accepts a claim only at the wallet's current nonce and
// increments that nonce in the same call, so the pair names exactly one settled
// claim for all time.
type inactivityClaimSettlement struct {
	walletID [32]byte
	nonce    *big.Int
}

// inactivityClaimDisposition reports what one claimInactivity call did about
// the chain. The two facts are kept apart because they answer different
// questions and a rollback reads them differently.
//
// submissionAttempted answers whether a claim transaction can exist at all. It
// is false for every exit that provably precedes the submitting call — a busy
// executor, a failed wallet or nonce lookup, a signing round that never reached
// the threshold, a refused penalty fence, a canceled permit — and calling those
// ambiguous would block a rollback over a penalty that cannot be on chain.
//
// settlement answers whether the claim landed, and is nil only while that
// stays genuinely unknown after the executor has both listened for the
// settlement and asked the chain about it. That single remaining case is the
// one the offline barrier must treat as unreconciled.
type inactivityClaimDisposition struct {
	submissionAttempted bool
	settlement          *inactivityClaimSettlement
}

// claimInactivity signs and submits an operator inactivity claim. The commit
// guard is the owning ceremony's penalty fence: the terminal on-chain
// submission consults it immediately before submitting, so a claim derived
// from legacy work at or after the cutover block, or raced by process
// quiescence, is suppressed instead of creating new penalty state.
//
// The returned disposition is what the caller's terminal record reports about
// the chain. Dispatching a claim proves nothing by itself: publishing can fail,
// be suppressed, or be canceled mid-flight, a member's submission can lose the
// race to another member's, and a submission that does reach the chain is mined
// after the submitting call has already returned. The disposition separates the
// submission that may exist from the settlement that was resolved, so the
// record never has to guess which happened.
func (ice *inactivityClaimExecutor) claimInactivity(
	ctx context.Context,
	commitGuard participation.CommitGuard,
	inactiveMembersIndexes []group.MemberIndex,
	heartbeatFailed bool,
	sessionID *big.Int,
) (inactivityClaimDisposition, error) {
	if lockAcquired := ice.lock.TryAcquire(1); !lockAcquired {
		return inactivityClaimDisposition{}, errInactivityClaimExecutorBusy
	}
	defer ice.lock.Release(1)

	wallet := ice.wallet()

	walletPublicKeyHash := bitcoin.PublicKeyHash(wallet.publicKey)
	walletPublicKeyBytes, err := marshalPublicKey(wallet.publicKey)
	if err != nil {
		return inactivityClaimDisposition{}, fmt.Errorf(
			"cannot marshal wallet public key: [%v]",
			err,
		)
	}

	execLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
		zap.String("sessionID", fmt.Sprintf("0x%x", sessionID)),
	)

	walletRegistryData, err := ice.chain.GetWallet(walletPublicKeyHash)
	if err != nil {
		return inactivityClaimDisposition{}, fmt.Errorf(
			"could not get registry data on wallet: [%v]",
			err,
		)
	}

	nonce, err := ice.chain.GetInactivityClaimNonce(
		walletRegistryData.EcdsaWalletID,
	)
	if err != nil {
		return inactivityClaimDisposition{}, fmt.Errorf(
			"could not get nonce for wallet: [%v]",
			err,
		)
	}

	claim := inactivity.NewClaimPreimage(
		nonce,
		wallet.publicKey,
		inactiveMembersIndexes,
		heartbeatFailed,
	)

	groupMembers, err := ice.getWalletOperatorsIDs()
	if err != nil {
		return inactivityClaimDisposition{}, fmt.Errorf(
			"could not get wallet members info: [%v]",
			err,
		)
	}

	// The wallet identity and nonce this claim is built for are what makes an
	// observed event attributable to it. The registry accepts a claim only at
	// the wallet's current nonce and increments it in the same call, so exactly
	// one on-chain claim can ever carry this pair.
	settlement := newInactivityClaimSettlementObserver(
		walletRegistryData.EcdsaWalletID,
		nonce,
	)

	// Publishing runs under one context and one subscription for the whole
	// call. Subscribing per signer tied observation to the goroutine that
	// published, but a member returns from the submitting call as soon as the
	// transaction reaches the provider, so the claim's own event regularly
	// arrives after the last publisher — and its subscription — is gone.
	// Observation therefore starts before any member can publish and ends only
	// once the settlement below has been resolved or given up on.
	publishCtx, cancelPublishCtx := context.WithCancel(ctx)
	defer cancelPublishCtx()

	subscription := ice.chain.OnInactivityClaimed(
		func(event *InactivityClaimedEvent) {
			// The subscription is not filtered on chain, so an unrelated
			// wallet's claim arrives here too. Attributing it to this claim
			// would both abandon publishing for no reason and put another
			// wallet's settlement on this permit's terminal record.
			if !settlement.observe(event) {
				return
			}

			execLogger.Infof(
				"Inactivity claim submitted for wallet with ID [0x%x] and "+
					"nonce [%v] by notifier [%v] at block [%v]",
				event.WalletID,
				event.Nonce,
				event.Notifier,
				event.BlockNumber,
			)

			// The claim is settled; no member has anything left to publish.
			cancelPublishCtx()
		})
	defer subscription.Unsubscribe()

	submission := &inactivityClaimSubmissionAttempt{}

	wg := sync.WaitGroup{}
	wg.Add(len(ice.signers))

	for _, currentSigner := range ice.signers {
		go func(signer *signer) {
			ice.protocolLatch.Lock()
			defer ice.protocolLatch.Unlock()

			defer wg.Done()

			execLogger.Infof(
				"[member:%v] starting inactivity claim publishing",
				signer.signingGroupMemberIndex,
			)

			err := ice.publishInactivityClaim(
				publishCtx,
				execLogger,
				commitGuard,
				sessionID,
				signer.signingGroupMemberIndex,
				wallet.groupSize(),
				wallet.groupDishonestThreshold(
					ice.groupParameters.HonestThreshold,
				),
				groupMembers,
				ice.membershipValidator,
				claim,
				submission,
			)
			if err != nil {
				// A refused penalty fence or a gate-canceled permit is a
				// deliberate release-gate suppression, not an ordinary
				// publishing failure.
				if participation.IsGateRefusal(err) ||
					participation.IsGateRefusal(context.Cause(publishCtx)) {
					execLogger.Warnf(
						"[member:%v] inactivity claim suppressed by the "+
							"release gate: [%v]",
						signer.signingGroupMemberIndex,
						err,
					)
					return
				}
				if errors.Is(err, context.Canceled) {
					execLogger.Infof(
						"[member:%v] inactivity claim is no longer awaiting "+
							"publishing; aborting inactivity claim publishing",
						signer.signingGroupMemberIndex,
					)
					return
				}

				execLogger.Errorf(
					"[member:%v] inactivity claim publishing failed [%v]",
					signer.signingGroupMemberIndex,
					err,
				)
				return
			}
		}(currentSigner)
	}

	// Wait until all controlled signers complete their routine.
	wg.Wait()

	return ice.resolveInactivityClaim(
		ctx,
		execLogger,
		settlement,
		walletRegistryData.EcdsaWalletID,
		nonce,
		submission.recorded(),
	), nil
}

// resolveInactivityClaim decides what this call can honestly say about the
// chain once every controlled member has stopped publishing.
//
// An observed event answers directly. Failing that, the nonce answers
// indirectly: the registry accepts a claim only at the wallet's current nonce
// and increments it in the same call, so a nonce past the one this claim was
// built for means the registry emitted the settlement of exactly that claim
// slot, whether or not this node's subscription happened to see it. When
// neither answers and a member did hand a transaction to the chain, the claim
// is still plausibly in flight and is worth a bounded wait; when no member ever
// reached the submitting call there is nothing in flight to wait for and the
// wait would only delay the heartbeat.
func (ice *inactivityClaimExecutor) resolveInactivityClaim(
	ctx context.Context,
	execLogger log.StandardLogger,
	settlement *inactivityClaimSettlementObserver,
	walletID [32]byte,
	nonce *big.Int,
	submissionAttempted bool,
) inactivityClaimDisposition {
	disposition := inactivityClaimDisposition{
		submissionAttempted: submissionAttempted,
	}

	resolved := func() *inactivityClaimSettlement {
		if observed := settlement.settled(); observed != nil {
			return &inactivityClaimSettlement{
				walletID: observed.WalletID,
				nonce:    observed.Nonce,
			}
		}
		if ice.inactivityClaimNonceConsumed(execLogger, walletID, nonce) {
			return &inactivityClaimSettlement{
				walletID: walletID,
				nonce:    nonce,
			}
		}
		return nil
	}

	if disposition.settlement = resolved(); disposition.settlement != nil {
		return disposition
	}

	if !submissionAttempted {
		return disposition
	}

	ice.waitForInactivityClaimSettlement(ctx, execLogger, settlement)

	if disposition.settlement = resolved(); disposition.settlement != nil {
		return disposition
	}

	execLogger.Warnf(
		"inactivity claim for wallet with ID [0x%x] was submitted but not "+
			"observed to settle at nonce [%v]; the penalty is reported "+
			"unresolved",
		walletID,
		nonce,
	)

	return disposition
}

// inactivityClaimNonceConsumed reports whether the chain has moved past the
// nonce this claim was built for, which is the chain's own confirmation that
// the claim slot was settled. An unreadable nonce resolves nothing and leaves
// the claim unresolved, which is the conservative of the two readings.
func (ice *inactivityClaimExecutor) inactivityClaimNonceConsumed(
	execLogger log.StandardLogger,
	walletID [32]byte,
	nonce *big.Int,
) bool {
	currentNonce, err := ice.chain.GetInactivityClaimNonce(walletID)
	if err != nil {
		execLogger.Warnf(
			"cannot read the inactivity claim nonce of wallet with ID "+
				"[0x%x] to resolve the claim settlement: [%v]",
			walletID,
			err,
		)
		return false
	}

	return currentNonce != nil && nonce != nil && currentNonce.Cmp(nonce) > 0
}

// waitForInactivityClaimSettlement gives a submitted claim a bounded number of
// blocks to be mined. The call-wide subscription is still live, so an arriving
// settlement ends the wait immediately instead of letting it run to the
// deadline, and the caller's context — the heartbeat window that owns the claim
// — cuts it short whenever that window closes first.
func (ice *inactivityClaimExecutor) waitForInactivityClaimSettlement(
	ctx context.Context,
	execLogger log.StandardLogger,
	settlement *inactivityClaimSettlementObserver,
) {
	blockCounter, err := ice.chain.BlockCounter()
	if err != nil {
		execLogger.Warnf(
			"cannot get the block counter to wait for the inactivity claim "+
				"settlement: [%v]",
			err,
		)
		return
	}

	currentBlock, err := blockCounter.CurrentBlock()
	if err != nil {
		execLogger.Warnf(
			"cannot get the current block to wait for the inactivity claim "+
				"settlement: [%v]",
			err,
		)
		return
	}

	waitCtx, cancelWaitCtx := context.WithCancel(ctx)
	defer cancelWaitCtx()

	go func() {
		select {
		case <-settlement.observed():
			cancelWaitCtx()
		case <-waitCtx.Done():
		}
	}()

	deadline := currentBlock + inactivityClaimSettlementResolutionBlocks

	execLogger.Infof(
		"waiting until block [%v] for the submitted inactivity claim to settle",
		deadline,
	)

	if err := ice.waitForBlockFn(waitCtx, deadline); err != nil &&
		!errors.Is(err, context.Canceled) {
		execLogger.Warnf(
			"error while waiting for the inactivity claim settlement: [%v]",
			err,
		)
	}
}

// inactivityClaimSubmissionAttempt records that a controlled member handed an
// inactivity claim transaction to the chain. Every controlled signer publishes
// on its own goroutine and any of them can be the one that submits, so the
// record is written from arbitrary goroutines and read once publishing ends.
type inactivityClaimSubmissionAttempt struct {
	attempted atomic.Bool
}

// record marks that a claim transaction was handed to the chain. It is called
// immediately before the submitting call rather than after it: a call that
// returns an error may still have broadcast the transaction, and a penalty that
// might be on chain has to reach the terminal record as one.
func (a *inactivityClaimSubmissionAttempt) record() {
	a.attempted.Store(true)
}

// recorded reports whether any controlled member reached the submitting call.
func (a *inactivityClaimSubmissionAttempt) recorded() bool {
	return a.attempted.Load()
}

// inactivityClaimSettlementObserver collects the on-chain settlement of one
// inactivity claim. The chain delivers events off the publishing goroutines and
// keeps delivering them after publishing has ended, so the observation is
// shared state written from arbitrary goroutines and read by the resolution
// that outlives them.
type inactivityClaimSettlementObserver struct {
	walletID [32]byte
	nonce    *big.Int

	mutex sync.Mutex
	event *InactivityClaimedEvent
	// settlement is closed on the first matching observation so a bounded wait
	// can end the moment the claim is seen instead of always running to its
	// deadline.
	settlement chan struct{}
}

func newInactivityClaimSettlementObserver(
	walletID [32]byte,
	nonce *big.Int,
) *inactivityClaimSettlementObserver {
	return &inactivityClaimSettlementObserver{
		walletID:   walletID,
		nonce:      nonce,
		settlement: make(chan struct{}),
	}
}

// observe records event as this claim's settlement and reports whether it
// belongs to the claim at all. Only the wallet and nonce the claim was built
// for match: the nonce is consumed by the submission that emits it, so a
// matching event is the settlement of this exact claim and not of a later one
// against the same wallet.
func (o *inactivityClaimSettlementObserver) observe(
	event *InactivityClaimedEvent,
) bool {
	if event == nil ||
		event.WalletID != o.walletID ||
		event.Nonce == nil ||
		o.nonce == nil ||
		event.Nonce.Cmp(o.nonce) != 0 {
		return false
	}

	o.mutex.Lock()
	defer o.mutex.Unlock()

	// Each signer observes the same settlement; the first observation is the
	// one recorded so the reported block cannot drift between members.
	if o.event == nil {
		o.event = event
		close(o.settlement)
	}

	return true
}

// settled returns the observed settlement, or nil when the claim was never
// seen to reach the chain.
func (o *inactivityClaimSettlementObserver) settled() *InactivityClaimedEvent {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	return o.event
}

// observed returns a channel closed once this claim's settlement is seen. It
// lets a bounded wait react to the settlement rather than poll for it.
func (o *inactivityClaimSettlementObserver) observed() <-chan struct{} {
	return o.settlement
}

func (ice *inactivityClaimExecutor) getWalletOperatorsIDs() ([]uint32, error) {
	// Cache mapping operator addresses to their wallet member IDs. It helps to
	// limit the number of calls to the ETH client if some operator addresses
	// occur on the list multiple times.
	operatorIDCache := make(map[chain.Address]uint32)

	walletMemberIDs := make([]uint32, 0)

	for _, operatorAddress := range ice.wallet().signingGroupOperators {
		// Search for the operator address in the cache. Store the operator
		// address in the cache if it's not there.
		if operatorID, found := operatorIDCache[operatorAddress]; !found {
			fetchedOperatorID, err := ice.chain.GetOperatorID(operatorAddress)
			if err != nil {
				return nil, fmt.Errorf("could not get operator ID: [%w]", err)
			}
			operatorIDCache[operatorAddress] = fetchedOperatorID
			walletMemberIDs = append(walletMemberIDs, fetchedOperatorID)
		} else {
			walletMemberIDs = append(walletMemberIDs, operatorID)
		}
	}

	return walletMemberIDs, nil
}

func (ice *inactivityClaimExecutor) publishInactivityClaim(
	ctx context.Context,
	inactivityLogger log.StandardLogger,
	commitGuard participation.CommitGuard,
	sessionID *big.Int,
	memberIndex group.MemberIndex,
	groupSize int,
	dishonestThreshold int,
	groupMembers []uint32,
	membershipValidator *group.MembershipValidator,
	inactivityClaim *inactivity.ClaimPreimage,
	submission *inactivityClaimSubmissionAttempt,
) error {
	return inactivity.PublishClaim(
		ctx,
		inactivityLogger,
		sessionID.Text(16),
		memberIndex,
		ice.broadcastChannel,
		groupSize,
		dishonestThreshold,
		membershipValidator,
		newInactivityClaimSigner(ice.chain),
		newInactivityClaimSubmitter(
			inactivityLogger,
			ice.chain,
			ice.groupParameters,
			groupMembers,
			ice.waitForBlockFn,
			commitGuard,
			submission,
		),
		inactivityClaim,
	)
}

func (ice *inactivityClaimExecutor) wallet() wallet {
	// All signers belong to one wallet. Take that wallet from the
	// first signer.
	return ice.signers[0].wallet
}

// inactivityClaimSigner is responsible for signing the inactivity claim and
// verification of signatures generated by other group members.
type inactivityClaimSigner struct {
	chain Chain
}

func newInactivityClaimSigner(
	chain Chain,
) *inactivityClaimSigner {
	return &inactivityClaimSigner{
		chain: chain,
	}
}

func (ics *inactivityClaimSigner) SignClaim(claim *inactivity.ClaimPreimage) (
	*inactivity.SignedClaimHash,
	error,
) {
	if claim == nil {
		return nil, fmt.Errorf("claim is nil")
	}

	claimHash, err := ics.chain.CalculateInactivityClaimHash(claim)
	if err != nil {
		return nil, fmt.Errorf(
			"inactivity claim hash calculation failed [%w]",
			err,
		)
	}

	signing := ics.chain.Signing()

	signature, err := signing.Sign(claimHash[:])
	if err != nil {
		return nil, fmt.Errorf(
			"inactivity claim hash signing failed [%w]",
			err,
		)
	}

	return &inactivity.SignedClaimHash{
		PublicKey: signing.PublicKey(),
		Signature: signature,
		ClaimHash: claimHash,
	}, nil
}

// VerifySignature verifies if the signature was generated from the provided
// inactivity claim using the provided public key.
func (ics *inactivityClaimSigner) VerifySignature(
	signedClaim *inactivity.SignedClaimHash,
) (
	bool,
	error,
) {
	return ics.chain.Signing().VerifyWithPublicKey(
		signedClaim.ClaimHash[:],
		signedClaim.Signature,
		signedClaim.PublicKey,
	)
}

type inactivityClaimSubmitter struct {
	inactivityLogger log.StandardLogger

	chain           Chain
	groupParameters *GroupParameters
	groupMembers    []uint32

	waitForBlockFn waitForBlockFn

	// commitGuard fences the terminal on-chain submission with a penalty
	// commit check: a refusal is a release-gate decision, not an ordinary
	// submission failure.
	commitGuard participation.CommitGuard

	// submission is the executor-wide record of whether any controlled member
	// reached the submitting call. Every exit above that call is an exit the
	// caller may report as leaving no chain state behind.
	submission *inactivityClaimSubmissionAttempt
}

func newInactivityClaimSubmitter(
	inactivityLogger log.StandardLogger,
	chain Chain,
	groupParameters *GroupParameters,
	groupMembers []uint32,
	waitForBlockFn waitForBlockFn,
	commitGuard participation.CommitGuard,
	submission *inactivityClaimSubmissionAttempt,
) *inactivityClaimSubmitter {
	return &inactivityClaimSubmitter{
		inactivityLogger: inactivityLogger,
		chain:            chain,
		groupParameters:  groupParameters,
		groupMembers:     groupMembers,
		waitForBlockFn:   waitForBlockFn,
		commitGuard:      commitGuard,
		submission:       submission,
	}
}

func (ics *inactivityClaimSubmitter) SubmitClaim(
	ctx context.Context,
	memberIndex group.MemberIndex,
	claim *inactivity.ClaimPreimage,
	signatures map[group.MemberIndex][]byte,
) error {
	if len(signatures) < ics.groupParameters.HonestThreshold {
		return fmt.Errorf(
			"could not submit inactivity claim with [%v] signatures for "+
				"group honest threshold [%v]",
			len(signatures),
			ics.groupParameters.HonestThreshold,
		)
	}

	// The inactivity nonce at the beginning of the execution process.
	inactivityNonce := claim.Nonce

	walletPublicKeyHash := bitcoin.PublicKeyHash(claim.WalletPublicKey)

	walletRegistryData, err := ics.chain.GetWallet(walletPublicKeyHash)
	if err != nil {
		return fmt.Errorf("could not get registry data on wallet: [%v]", err)
	}

	ecdsaWalletID := walletRegistryData.EcdsaWalletID

	currentNonce, err := ics.chain.GetInactivityClaimNonce(
		ecdsaWalletID,
	)
	if err != nil {
		return fmt.Errorf("could not get nonce for wallet: [%v]", err)
	}

	if currentNonce.Cmp(inactivityNonce) > 0 {
		// Someone who was ahead of us in the queue submitted the claim. Giving up.
		ics.inactivityLogger.Infof(
			"[member:%v] inactivity claim already submitted; "+
				"aborting inactivity claim on-chain submission",
			memberIndex,
		)
		return nil
	}

	chainClaim, err := ics.chain.AssembleInactivityClaim(
		ecdsaWalletID,
		claim.InactiveMembersIndexes,
		signatures,
		claim.HeartbeatFailed,
	)
	if err != nil {
		return fmt.Errorf("could not assemble inactivity chain claim [%w]", err)
	}

	blockCounter, err := ics.chain.BlockCounter()
	if err != nil {
		return err
	}

	// We can't determine a common block at which the publication starts.
	// However, all we want here is to ensure the members does not submit
	// in the same time. This can be achieved by simply using the index-based
	// delay starting from the current block.
	currentBlock, err := blockCounter.CurrentBlock()
	if err != nil {
		return fmt.Errorf("cannot get current block: [%v]", err)
	}
	delayBlocks := uint64(memberIndex-1) * inactivityClaimSubmissionDelayStepBlocks
	submissionBlock := currentBlock + delayBlocks

	ics.inactivityLogger.Infof(
		"[member:%v] waiting for block [%v] to submit inactivity claim",
		memberIndex,
		submissionBlock,
	)

	err = ics.waitForBlockFn(ctx, submissionBlock)
	if err != nil {
		return fmt.Errorf(
			"error while waiting for inactivity claim submission block: [%v]",
			err,
		)
	}

	if ctx.Err() != nil {
		// The context was cancelled by the upstream. Regardless of the cause,
		// that means the inactivity execution is no longer awaiting the result,
		//  and we can safely return.
		ics.inactivityLogger.Infof(
			"[member:%v] inactivity execution is no longer awaiting the "+
				"result; aborting inactivity claim on-chain submission",
			memberIndex,
		)
		return nil
	}

	// Re-check the nonce after the delay wait. Another member may have
	// submitted the claim while we were waiting.
	currentNonce, err = ics.chain.GetInactivityClaimNonce(ecdsaWalletID)
	if err != nil {
		return fmt.Errorf("could not get nonce for wallet: [%v]", err)
	}

	if currentNonce.Cmp(inactivityNonce) > 0 {
		ics.inactivityLogger.Infof(
			"[member:%v] inactivity claim already submitted; "+
				"aborting inactivity claim on-chain submission",
			memberIndex,
		)
		return nil
	}

	ics.inactivityLogger.Infof(
		"[member:%v] submitting inactivity claim with [%v] supporting "+
			"member signatures",
		memberIndex,
		len(signatures),
	)

	// The last-moment penalty fence immediately before the irreversible
	// on-chain submission.
	if err := ics.commitGuard.CheckCommit(
		"tbtc_inactivity_claim_submission",
		participation.PenaltyCommit,
	); err != nil {
		return err
	}

	// Past this point the transaction may reach the provider and the chain, so
	// the attempt is recorded before the call and never after it: a submitting
	// call that returns an error may still have broadcast, and the executor
	// must go on to resolve a penalty that might exist.
	ics.submission.record()

	err = ics.chain.SubmitInactivityClaim(
		chainClaim,
		inactivityNonce,
		ics.groupMembers,
	)
	if err == nil {
		return nil
	}

	// The nonce can become stale between the initial check and actual
	// submission if another member submits the same claim first. In that
	// case, treat this as expected and return without error.
	currentNonce, nonceErr := ics.chain.GetInactivityClaimNonce(
		ecdsaWalletID,
	)
	if nonceErr == nil && currentNonce.Cmp(inactivityNonce) > 0 {
		ics.inactivityLogger.Infof(
			"[member:%v] inactivity claim already submitted by another "+
				"member; aborting inactivity claim on-chain submission",
			memberIndex,
		)
		return nil
	}

	return err
}
