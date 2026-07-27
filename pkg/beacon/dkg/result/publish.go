package result

import (
	"context"
	"fmt"

	"github.com/ipfs/go-log/v2"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/protocol/state"
)

// RegisterUnmarshallers initializes the given broadcast channel to be able to
// perform DKG result publication protocol interactions by registering all the
// required protocol message unmarshallers.
// The channel needs to be fully initialized before Publish is called.
func RegisterUnmarshallers(channel net.BroadcastChannel) {
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &DKGResultHashSignatureMessage{}
	})
}

// Publish executes Phase 13 and 14 of DKG as a state machine. First, the
// chosen result is hashed, signed, and sent over a broadcast channel. Then, all
// other signatures and results are received and accounted for. Those that match
// our own result and added to the list of votes. Finally, we submit the result
// along with everyone's votes.
//
// The context bounds the execution: canceling it aborts the publication
// between block waits. The commit guard is consulted immediately before the
// terminal on-chain submission; it must be the permit of the ceremony this
// publication concludes.
func Publish(
	ctx context.Context,
	logger log.StandardLogger,
	sessionID string,
	memberIndex group.MemberIndex,
	dkgGroup *group.Group,
	membershipValidator *group.MembershipValidator,
	result *gjkr.Result,
	channel net.BroadcastChannel,
	beaconChain beaconchain.Interface,
	blockCounter chain.BlockCounter,
	startBlockHeight uint64,
	commitGuard participation.CommitGuard,
) error {
	if commitGuard == nil {
		// Publishing without a fence would submit a result the release gate
		// never authorized; there is no implicit default.
		return fmt.Errorf("a commit guard is required to publish a DKG result")
	}

	initialState := &resultSigningState{
		channel:                 channel,
		beaconChain:             beaconChain,
		blockCounter:            blockCounter,
		member:                  NewSigningMember(logger, memberIndex, dkgGroup, membershipValidator, sessionID),
		result:                  convertGjkrResult(result),
		signatureMessages:       make([]*DKGResultHashSignatureMessage, 0),
		signingStartBlockHeight: startBlockHeight,
		commitGuard:             commitGuard,
	}

	stateMachine := state.NewSyncMachine(logger, ctx, channel, blockCounter, initialState)

	lastState, _, err := stateMachine.Execute(startBlockHeight)
	if err != nil {
		return err
	}

	_, ok := lastState.(*resultSubmissionState)
	if !ok {
		return fmt.Errorf("execution ended on state %T", lastState)
	}

	return nil
}
