package tbtc

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/ipfs/go-log/v2"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

const (
	// heartbeatTotalProposalValidityBlocks determines the total wallet
	// heartbeat proposal validity time expressed in blocks. In other words,
	// this is the worst-case time for a wallet heartbeat during which the
	// wallet is busy and cannot take another actions. It includes the total
	// duration needed to perform both signing the heartbeat message and
	// optionally notifying about operator inactivity if the heartbeat failed.
	// The value of 600 blocks is roughly 2 hours, assuming 12 seconds per block.
	heartbeatTotalProposalValidityBlocks = 600
	// heartbeatInactivityClaimValidityBlocks determines the duration that needs
	// to be preserved for the optional notification about operator inactivity
	// that follows a failed heartbeat signing.
	heartbeatInactivityClaimValidityBlocks = 300
	// heartbeatTimeoutSafetyMarginBlocks determines the duration of the safety
	// margin that must be preserved between the timeout of operator inactivity
	// notification and the timeout of the entire heartbeat action. This safety
	// margin prevents against the case where signing completes too late and
	// another action has been already requested by the coordinator. The value
	// of 25 blocks is roughly 5 minutes, assuming 12 seconds per block.
	heartbeatTimeoutSafetyMarginBlocks = 25
	// heartbeatSigningMinimumActiveOperators determines the minimum number of
	// active members during signing for a heartbeat to be considered valid.
	heartbeatSigningMinimumActiveMembers = 70
	// heartbeatConsecutiveFailuresThreshold determines the number of consecutive
	// heartbeat failures required to trigger inactivity operator notification.
	heartbeatConsecutiveFailureThreshold = 3
)

type HeartbeatProposal struct {
	Message [16]byte
}

func (hp *HeartbeatProposal) ActionType() WalletActionType {
	return ActionHeartbeat
}

func (hp *HeartbeatProposal) ValidityBlocks() uint64 {
	return heartbeatTotalProposalValidityBlocks
}

// heartbeatSigningExecutor is an interface meant to decouple the specific
// implementation of the signing executor from the heartbeat action.
type heartbeatSigningExecutor interface {
	sign(
		ctx context.Context,
		message *big.Int,
		startBlock uint64,
		mode participation.ProtocolMode,
	) (*tecdsa.Signature, *signingActivityReport, uint64, error)
}

// heartbeatInactivityClaimExecutor is an interface meant to decouple the
// specific implementation of the inactivity claim executor from the heartbeat
// action. The commit guard is the heartbeat permit's penalty fence: the claim
// is derived penalty work and inherits the heartbeat ceremony's permit.
type heartbeatInactivityClaimExecutor interface {
	claimInactivity(
		ctx context.Context,
		commitGuard participation.CommitGuard,
		inactiveMembersIndexes []group.MemberIndex,
		heartbeatFailed bool,
		sessionID *big.Int,
	) error
}

// heartbeatAction is a walletAction implementation handling heartbeat requests
// from the wallet coordinator.
type heartbeatAction struct {
	logger log.StandardLogger
	chain  Chain

	executingWallet wallet
	signingExecutor heartbeatSigningExecutor

	proposal       *HeartbeatProposal
	failureCounter *heartbeatFailureCounter

	inactivityClaimExecutor heartbeatInactivityClaimExecutor

	startBlock  uint64
	expiryBlock uint64

	waitForBlockFn waitForBlockFn

	// permit is the heartbeat ceremony's participation permit: it pins the
	// protocol mode for the heartbeat signing, fences the penalty path of any
	// derived inactivity work, and is released when the action's execution
	// ends.
	permit participation.Permit
}

func newHeartbeatAction(
	logger log.StandardLogger,
	chain Chain,
	executingWallet wallet,
	signingExecutor heartbeatSigningExecutor,
	proposal *HeartbeatProposal,
	failureCounter *heartbeatFailureCounter,
	inactivityClaimExecutor heartbeatInactivityClaimExecutor,
	startBlock uint64,
	expiryBlock uint64,
	waitForBlockFn waitForBlockFn,
	permit participation.Permit,
) *heartbeatAction {
	return &heartbeatAction{
		logger:                  logger,
		chain:                   chain,
		executingWallet:         executingWallet,
		signingExecutor:         signingExecutor,
		proposal:                proposal,
		failureCounter:          failureCounter,
		inactivityClaimExecutor: inactivityClaimExecutor,
		startBlock:              startBlock,
		expiryBlock:             expiryBlock,
		waitForBlockFn:          waitForBlockFn,
		permit:                  permit,
	}
}

// heartbeatPenaltyState is the penalty state a heartbeat left behind on top of
// its threshold signature. The inactivity claim derived from a low-activity
// heartbeat runs under the heartbeat's own permit, so the heartbeat's terminal
// record is the only place that disposition is reported. A record naming only
// the signature cannot tell a healthy heartbeat apart from one that went on to
// file an inactivity claim against named members, which is exactly the
// distinction the rollback audit has to reconcile.
type heartbeatPenaltyState struct {
	// claimDispatched is true once the action handed a claim to the inactivity
	// claim executor. It stays true when publishing then failed or was
	// suppressed: the audit must treat a dispatched claim as possibly settled.
	claimDispatched bool
	// inactiveMembers is the exact member set the dispatched claim names. It is
	// empty when no claim was dispatched.
	inactiveMembers []group.MemberIndex
}

// inactiveMemberBytes renders the claimed inactive member set as a canonical,
// order-independent byte string so the derived identity does not depend on the
// order the signing activity report happened to produce.
func (hps heartbeatPenaltyState) inactiveMemberBytes() []byte {
	if len(hps.inactiveMembers) == 0 {
		return nil
	}

	members := make([]group.MemberIndex, len(hps.inactiveMembers))
	copy(members, hps.inactiveMembers)
	slices.Sort(members)
	members = slices.Compact(members)

	bytes := make([]byte, len(members))
	for i, member := range members {
		bytes[i] = byte(member)
	}

	return bytes
}

// recordTerminalOutcome reports the heartbeat ceremony's node-owned final
// disposition on its participation permit. The heartbeat's durable result is
// the threshold signature it produced over the proposed message, qualified by
// the penalty state the same permit created; a heartbeat that never reached a
// signature — including one the release gate canceled — left no state behind
// and is recorded as exhausted.
func (ha *heartbeatAction) recordTerminalOutcome(
	signature *tecdsa.Signature,
	penalty heartbeatPenaltyState,
) {
	if signature == nil {
		recordPermitNoThreshold(ha.logger, ha.permit)
		return
	}

	// A dispatched claim gets its own domain so a healthy heartbeat's identity
	// can never be replayed as the settlement of one that claimed inactivity,
	// whatever member set the claim happened to name.
	domain := "tbtc_heartbeat_signature"
	if penalty.claimDispatched {
		domain = "tbtc_heartbeat_signature_with_inactivity_claim"
	}

	recordPermitTerminalOutcome(
		ha.logger,
		ha.permit,
		participation.TerminalOutcomeCompleted,
		participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceProtocolResult,
			Reference: participation.TerminalResultReference(
				domain,
				ha.proposal.Message[:],
				signatureComponentBytes(signature.R),
				signatureComponentBytes(signature.S),
				penalty.inactiveMemberBytes(),
			),
		},
	)
}

func (ha *heartbeatAction) execute() error {
	// heartbeatSignature holds the ceremony's durable result once signing
	// produces one, and heartbeatPenalty the penalty state the same permit went
	// on to create. The deferred recorder below reads their final values.
	var heartbeatSignature *tecdsa.Signature
	var heartbeatPenalty heartbeatPenaltyState

	// The action owns its permit from dispatch on; releasing it here ends the
	// ceremony's active accounting in the participation gate. The terminal
	// outcome is registered afterwards so it runs first and reaches the permit
	// while it is still open.
	defer ha.permit.Close()
	defer func() {
		ha.recordTerminalOutcome(heartbeatSignature, heartbeatPenalty)
	}()

	// Do not execute the heartbeat action if the operator is unstaking.
	isUnstaking, err := ha.isOperatorUnstaking()
	if err != nil {
		return fmt.Errorf(
			"failed to check if the operator is unstaking [%v]",
			err,
		)
	}

	if isUnstaking {
		ha.logger.Warn(
			"quitting the heartbeat action without signing because the " +
				"operator is unstaking",
		)
		return nil
	}

	walletPublicKey := ha.wallet().publicKey
	walletPublicKeyHash := bitcoin.PublicKeyHash(walletPublicKey)
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal wallet public key: [%v]", err)
	}

	walletKey := hex.EncodeToString(walletPublicKeyBytes)

	err = ha.chain.ValidateHeartbeatProposal(walletPublicKeyHash, ha.proposal)
	if err != nil {
		return fmt.Errorf("heartbeat proposal is invalid: [%v]", err)
	}

	messageBytes := bitcoin.ComputeHash(ha.proposal.Message[:])
	messageToSign := new(big.Int).SetBytes(messageBytes[:])

	// Just in case. This should never happen.
	if ha.expiryBlock < heartbeatInactivityClaimValidityBlocks {
		return fmt.Errorf("invalid proposal expiry block")
	}

	// The signing window is bound to the heartbeat permit: a permit
	// cancellation — clock failure, forced quiescence — stops the signing
	// exactly like the timeout block does.
	heartbeatSigningCtx, cancelHeartbeatSigningCtx := withCancelOnBlock(
		ha.permit.Context(),
		ha.expiryBlock-heartbeatInactivityClaimValidityBlocks,
		ha.waitForBlockFn,
	)
	defer cancelHeartbeatSigningCtx()

	signature, activityReport, _, err := ha.signingExecutor.sign(
		heartbeatSigningCtx,
		messageToSign,
		ha.startBlock,
		ha.permit.Mode(),
	)
	if err != nil {
		// Do not count this error as heartbeat inactivity failure. If the
		// process returned an error here, that likely means the group signing
		// threshold was not met. In such a case, the inactivity claim does not
		// have a chance for success anyway (it needs the group threshold to
		// be met as well). The wrapped cause lets the dispatcher tell a
		// gate-caused abort apart from an ordinary failure.
		return fmt.Errorf("heartbeat signing process errored out: [%w]", err)
	}

	// Signing reached the threshold, so the ceremony has a durable result the
	// rollback audit can identify, whatever the activity accounting below
	// decides about penalties.
	heartbeatSignature = signature

	// If the number of active members during signing was enough, we can
	// consider the heartbeat procedure as successful.
	activeMembersCount := len(activityReport.activeMembers)
	if activeMembersCount >= heartbeatSigningMinimumActiveMembers {
		ha.logger.Infof(
			"heartbeat generated signature [%s] for message [0x%x]",
			signature,
			ha.proposal.Message[:],
		)

		// Reset the counter of consecutive heartbeat inactivity failures.
		ha.failureCounter.reset(walletKey)

		return nil
	}

	// If the number of active members during signing was not enough, we
	// must consider the heartbeat procedure as an inactivity failure.
	ha.logger.Warnf(
		"heartbeat generated signature but minimum activity "+
			"threshold was not met ([%d/%d] members participated); "+
			"counting it as inactivity failure",
		activeMembersCount,
		heartbeatSigningMinimumActiveMembers,
	)

	// The consecutive-failure counter and any derived claim are new penalty
	// state. The permit's penalty fence suppresses both for legacy work at or
	// after the cutover block and for every permit once process quiescence
	// begins, so a boundary- or shutdown-caused low-activity result cannot
	// turn into punishment.
	if fenceErr := ha.permit.CheckCommit(
		"tbtc_heartbeat_inactivity_accounting",
		participation.PenaltyCommit,
	); fenceErr != nil {
		ha.logger.Warnf(
			"heartbeat inactivity penalty suppressed by the release "+
				"gate: [%v]",
			fenceErr,
		)
		return nil
	}

	// Increment the heartbeat inactivity failure counter.
	ha.failureCounter.increment(walletKey)

	// If the number of consecutive heartbeat inactivity failures does not
	// exceed the threshold, do not issue an inactivity claim yet.
	if ha.failureCounter.get(walletKey) < heartbeatConsecutiveFailureThreshold {
		ha.logger.Warnf(
			"not issuing an inactivity claim yet; current consecutive"+
				"heartbeat inactivity failure count is [%d/%d]",
			ha.failureCounter.get(walletKey),
			heartbeatConsecutiveFailureThreshold,
		)
		return nil
	}

	// This should not happen but check it just in case as inactivity claim
	// requires a non-empty inactive members set.
	if len(activityReport.inactiveMembers) == 0 {
		return fmt.Errorf(
			"inactivity claim aborted due to an undetermined set of inactive members",
		)
	}

	heartbeatInactivityCtx, cancelHeartbeatInactivityCtx := withCancelOnBlock(
		ha.permit.Context(),
		ha.expiryBlock-heartbeatTimeoutSafetyMarginBlocks,
		ha.waitForBlockFn,
	)
	defer cancelHeartbeatInactivityCtx()

	// Pin the penalty state before dispatching, not after: a claim the executor
	// may already have published must show up in the terminal record even if
	// the call below then errors out or the permit is canceled mid-flight.
	heartbeatPenalty = heartbeatPenaltyState{
		claimDispatched: true,
		inactiveMembers: activityReport.inactiveMembers,
	}

	// The value of consecutive heartbeat inactivity failures exceeds the threshold.
	// Proceed with operator inactivity claim. The claim is derived penalty
	// work: it inherits the heartbeat permit as its commit fence.
	err = ha.inactivityClaimExecutor.claimInactivity(
		heartbeatInactivityCtx,
		ha.permit,
		// It's safe to consider unstaking members as inactive members in the claim.
		// Inactive members are set ineligible for on-chain rewards for a certain
		// period of time. This is a desired outcome for unstaking members as well.
		activityReport.inactiveMembers,
		true,
		messageToSign,
	)
	if err != nil {
		return fmt.Errorf(
			"error while notifying about operator inactivity [%v]]",
			err,
		)
	}

	return nil
}

func (ha *heartbeatAction) wallet() wallet {
	return ha.executingWallet
}

func (ha *heartbeatAction) actionType() WalletActionType {
	return ActionHeartbeat
}

func (ha *heartbeatAction) isOperatorUnstaking() (bool, error) {
	stakingProvider, isRegistered, err := ha.chain.OperatorToStakingProvider()
	if err != nil {
		return false, fmt.Errorf(
			"failed to get staking provider for operator [%v]",
			err,
		)
	}

	if !isRegistered {
		return false, fmt.Errorf("staking provider not registered for operator")
	}

	// Eligible stake is defined as the currently authorized stake minus the
	// pending authorization decrease.
	eligibleStake, err := ha.chain.EligibleStake(stakingProvider)
	if err != nil {
		return false, fmt.Errorf(
			"failed to check eligible stake for operator [%v]",
			err,
		)
	}

	// The operator is considered unstaking if their eligible stake is `0`.
	return eligibleStake.Cmp(big.NewInt(0)) == 0, nil
}

// heartbeatFailureCounter holds counters keeping track of consecutive
// heartbeat failures. Each wallet has a separate counter. The key used in
// the map is the uncompressed public key (with 04 prefix) of the wallet.
type heartbeatFailureCounter struct {
	mutex    sync.Mutex
	counters map[string]uint
}

func newHeartbeatFailureCounter() *heartbeatFailureCounter {
	return &heartbeatFailureCounter{
		counters: make(map[string]uint),
	}
}

func (hfc *heartbeatFailureCounter) increment(walletPublicKey string) {
	hfc.mutex.Lock()
	defer hfc.mutex.Unlock()

	hfc.counters[walletPublicKey]++

}

func (hfc *heartbeatFailureCounter) reset(walletPublicKey string) {
	hfc.mutex.Lock()
	defer hfc.mutex.Unlock()

	hfc.counters[walletPublicKey] = 0
}

func (hfc *heartbeatFailureCounter) get(walletPublicKey string) uint {
	hfc.mutex.Lock()
	defer hfc.mutex.Unlock()

	return hfc.counters[walletPublicKey]
}
