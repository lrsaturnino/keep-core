package dkg

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sort"

	"github.com/ipfs/go-log/v2"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	dkgResult "github.com/keep-network/keep-core/pkg/beacon/dkg/result"
	"github.com/keep-network/keep-core/pkg/beacon/event"
	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// PublicationInterruptedError reports that the release gate stopped the
// ceremony after the group key material was generated but before an accepted
// on-chain publication of the result was observed. The orphaned signer must be
// preserved through the quarantine path: the result may still have been
// accepted on chain by other members, so the share cannot be dropped, and no
// acceptance was observed locally, so the share must not be activated.
type PublicationInterruptedError struct {
	// Cause is the gate error that interrupted the publication.
	Cause error
	// Signer carries the generated key material. Its group operators are the
	// full pre-acceptance selection: the accepted result, if any, may exclude
	// members, and only the offline state audit may resolve the final roster.
	Signer *ThresholdSigner
}

func (e *PublicationInterruptedError) Error() string {
	return fmt.Sprintf(
		"DKG result publication interrupted by the release gate "+
			"after key generation: [%v]",
		e.Cause,
	)
}

func (e *PublicationInterruptedError) Unwrap() error {
	return e.Cause
}

// ExecuteDKG runs the full distributed key generation lifecycle. The
// compatibility strategy bundle selects the ceremony's wire-sensitive
// cryptographic behavior and must be supplied explicitly.
//
// The context bounds the execution and must be the ceremony permit's context:
// canceling it aborts the protocol between block waits. The commit guard is
// consulted immediately before the terminal on-chain result submission. A
// successful return means an on-chain publication of the result was observed;
// a *PublicationInterruptedError return carries generated key material whose
// publication the gate interrupted.
func ExecuteDKG(
	ctx context.Context,
	logger log.StandardLogger,
	seed *big.Int,
	memberIndex group.MemberIndex,
	startBlockHeight uint64,
	beaconChain beaconchain.Interface,
	channel net.BroadcastChannel,
	membershipValidator *group.MembershipValidator,
	selectedOperators []chain.Address,
	strategies compatibility.Strategies,
	commitGuard participation.CommitGuard,
) (*ThresholdSigner, error) {
	beaconConfig := beaconChain.GetConfig()

	blockCounter, err := beaconChain.BlockCounter()
	if err != nil {
		return nil, fmt.Errorf("failed to get block counter: [%v]", err)
	}

	gjkr.RegisterUnmarshallers(channel)
	dkgResult.RegisterUnmarshallers(channel)

	sessionID := seed.Text(16)

	gjkrResult, gjkrEndBlockHeight, err := gjkr.Execute(
		ctx,
		logger,
		seed,
		sessionID,
		memberIndex,
		beaconConfig.GroupSize,
		blockCounter,
		channel,
		beaconConfig.DishonestThreshold(),
		membershipValidator,
		strategies,
		startBlockHeight,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"[member:%v] GJKR execution failed [%w]",
			memberIndex,
			err,
		)
	}

	// From this point on the group key material exists. A gate interruption —
	// the permit canceled or a commit fence refused — must surface the signer
	// for quarantine instead of dropping it.
	interruptedSigner := func(cause error) error {
		return &PublicationInterruptedError{
			Cause: cause,
			Signer: &ThresholdSigner{
				memberIndex:          memberIndex,
				groupPublicKey:       gjkrResult.GroupPublicKey,
				groupPrivateKeyShare: gjkrResult.GroupPrivateKeyShare,
				groupPublicKeyShares: gjkrResult.GroupPublicKeyShares(),
				groupOperators:       selectedOperators,
			},
		}
	}

	startPublicationBlockHeight := gjkrEndBlockHeight

	operatingMemberIndexes := gjkrResult.Group.OperatingMemberIndexes()

	// The buffer lets an in-flight event callback complete after the consumer
	// returned on cancellation or timeout, instead of blocking forever.
	dkgResultChannel := make(chan *event.DKGResultSubmission, 1)
	dkgResultSubscription := beaconChain.OnDKGResultSubmitted(
		func(event *event.DKGResultSubmission) {
			dkgResultChannel <- event
		},
	)
	defer dkgResultSubscription.Unsubscribe()

	err = dkgResult.Publish(
		ctx,
		logger,
		sessionID,
		memberIndex,
		gjkrResult.Group,
		membershipValidator,
		gjkrResult,
		channel,
		beaconChain,
		blockCounter,
		startPublicationBlockHeight,
		commitGuard,
	)
	if err != nil {
		if isGateInterruption(ctx, err) {
			return nil, interruptedSigner(err)
		}

		// Result publication failed. It means that either the result this
		// member proposed is not supported by the majority of group members or
		// that the chain interaction failed. In either case, we observe the
		// chain for the result published by any other group member and based
		// on that, we decide whether we should stay in the final group
		// or drop our membership.
		logger.Warnf(
			"[member:%v] DKG result publication process failed [%v]",
			memberIndex,
			err,
		)

		if operatingMemberIndexes, err = decideMemberFate(
			ctx,
			memberIndex,
			gjkrResult,
			dkgResultChannel,
			startPublicationBlockHeight,
			beaconChain,
			blockCounter,
		); err != nil {
			if isGateInterruption(ctx, err) {
				return nil, interruptedSigner(err)
			}
			return nil, err
		}
	}

	groupOperators, err := resolveGroupOperators(
		selectedOperators,
		operatingMemberIndexes,
		beaconConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve group operators: [%v]", err)
	}

	return &ThresholdSigner{
		memberIndex:          memberIndex,
		groupPublicKey:       gjkrResult.GroupPublicKey,
		groupPrivateKeyShare: gjkrResult.GroupPrivateKeyShare,
		groupPublicKeyShares: gjkrResult.GroupPublicKeyShares(),
		groupOperators:       groupOperators,
	}, nil
}

// isGateInterruption distinguishes a release-gate decision from an ordinary
// protocol failure: the ceremony context was canceled by the gate, or the
// error chain carries a gate sentinel from a refused commit fence.
func isGateInterruption(ctx context.Context, err error) bool {
	return ctx.Err() != nil || participation.IsGateRefusal(err)
}

// decideMemberFate decides what the member will do in case it failed
// publishing its DKG result. Member can stay in the group if it
// supports the same group public key as the one registered on-chain and
// the member is not considered as misbehaving by the group.
func decideMemberFate(
	ctx context.Context,
	playerIndex group.MemberIndex,
	gjkrResult *gjkr.Result,
	dkgResultChannel chan *event.DKGResultSubmission,
	startPublicationBlockHeight uint64,
	beaconChain beaconchain.Interface,
	blockCounter chain.BlockCounter,
) ([]group.MemberIndex, error) {
	dkgResultEvent, err := waitForDkgResultEvent(
		ctx,
		dkgResultChannel,
		startPublicationBlockHeight,
		beaconChain,
		blockCounter,
	)
	if err != nil {
		return nil, err
	}

	groupPublicKey, err := gjkrResult.GroupPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	// If member don't support the same group public key, it could not stay
	// in the group.
	if !bytes.Equal(groupPublicKey, dkgResultEvent.GroupPublicKey) {
		return nil, fmt.Errorf(
			"[member:%v] could not stay in the group because "+
				"member do not support the same group public key",
			playerIndex,
		)
	}

	misbehavedSet := make(map[group.MemberIndex]struct{})
	for _, misbehavedID := range dkgResultEvent.Misbehaved {
		misbehavedSet[misbehavedID] = struct{}{}
	}

	// If member is considered as misbehaved, it could not stay in the group.
	if _, isMisbehaved := misbehavedSet[playerIndex]; isMisbehaved {
		return nil, fmt.Errorf(
			"[member:%v] could not stay in the group because "+
				"member is considered as misbehaving",
			playerIndex,
		)
	}

	// Construct a new view of the operating members according to the accepted
	// DKG result.
	operatingMemberIndexes := make([]group.MemberIndex, 0)
	for _, memberID := range gjkrResult.Group.MemberIndexes() {
		if _, isMisbehaved := misbehavedSet[memberID]; !isMisbehaved {
			operatingMemberIndexes = append(operatingMemberIndexes, memberID)
		}
	}

	return operatingMemberIndexes, nil
}

func waitForDkgResultEvent(
	ctx context.Context,
	dkgResultChannel chan *event.DKGResultSubmission,
	startPublicationBlockHeight uint64,
	beaconChain beaconchain.Interface,
	blockCounter chain.BlockCounter,
) (*event.DKGResultSubmission, error) {
	config := beaconChain.GetConfig()

	timeoutBlock := startPublicationBlockHeight +
		dkgResult.PrePublicationBlocks() +
		(uint64(config.GroupSize) * config.ResultPublicationBlockStep)

	timeoutBlockChannel, err := blockCounter.BlockHeightWaiter(timeoutBlock)
	if err != nil {
		return nil, err
	}

	select {
	case dkgResultEvent := <-dkgResultChannel:
		return dkgResultEvent, nil
	case <-timeoutBlockChannel:
		return nil, fmt.Errorf("DKG result publication timed out")
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"waiting for the DKG result event canceled: [%w]",
			context.Cause(ctx),
		)
	}
}

// resolveGroupOperators takes two parameters:
//   - selectedOperators: Contains addresses of all selected operators. Slice
//     length equals to the groupSize. Each element with index N corresponds
//     to the group member with ID N+1.
//   - operatingGroupMembersIDs: Contains group members IDs that were neither
//     disqualified nor marked as inactive. Slice length is lesser than or equal
//     to the groupSize.
//
// Using those parameters, this function transforms the selectedOperators
// slice into another slice that contains addresses of all operators
// that were neither disqualified nor marked as inactive. This way, the
// resulting slice has only addresses of properly operating operators
// who form the resulting group.
//
// Example:
// selectedOperators: [member1, member2, member3, member4, member5]
// operatingGroupMembersIDs: [5, 1, 3]
// groupOperators: [member1, member3, member5]
func resolveGroupOperators(
	selectedOperators []chain.Address,
	operatingGroupMembersIDs []group.MemberIndex,
	beaconConfig *beaconchain.Config,
) ([]chain.Address, error) {
	if len(selectedOperators) != beaconConfig.GroupSize ||
		len(operatingGroupMembersIDs) < beaconConfig.HonestThreshold {
		return nil, fmt.Errorf("invalid input parameters")
	}

	sort.Slice(operatingGroupMembersIDs, func(i, j int) bool {
		return operatingGroupMembersIDs[i] < operatingGroupMembersIDs[j]
	})

	groupOperators := make(
		[]chain.Address,
		len(operatingGroupMembersIDs),
	)

	for i, operatingMemberID := range operatingGroupMembersIDs {
		groupOperators[i] = selectedOperators[operatingMemberID-1]
	}

	return groupOperators, nil
}
