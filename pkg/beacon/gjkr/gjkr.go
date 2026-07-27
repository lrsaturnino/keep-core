package gjkr

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/state"
)

// RegisterUnmarshallers initializes the given broadcast channel to be able to
// perform DKG protocol interactions by registering all the required protocol
// message unmarshallers.
// The channel needs to be fully initialized before Execute is called.
func RegisterUnmarshallers(channel net.BroadcastChannel) {
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &EphemeralPublicKeyMessage{}
	})

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &MemberCommitmentsMessage{}
	})

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &PeerSharesMessage{}
	})

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &SecretSharesAccusationsMessage{}
	})

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &MemberPublicKeySharePointsMessage{}
	})

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &PointsAccusationsMessage{}
	})

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &MisbehavedEphemeralKeysMessage{}
	})
}

// Execute runs the GJKR distributed key generation  protocol, given a
// broadcast channel to mediate with, a block counter used for time tracking,
// a player index to use in the group, dishonest threshold, and block height
// when DKG protocol should start.
// If the generation is successful, it returns a threshold group member which
// can participate in the signing group; if the generation fails, it returns an
// error.
//
// The compatibility strategy bundle carries every wire- and
// transcript-sensitive cryptographic decision of the ceremony — the ECDH
// derivation and the hash-to-point mapping behind the Pedersen generator H —
// and must be supplied explicitly; there is no implicit default mode.
//
// The context bounds the execution: canceling it aborts the protocol between
// block waits and the error carries the cancellation cause.
func Execute(
	ctx context.Context,
	logger log.StandardLogger,
	seed *big.Int,
	sessionID string,
	memberIndex group.MemberIndex,
	groupSize int,
	blockCounter chain.BlockCounter,
	channel net.BroadcastChannel,
	dishonestThreshold int,
	membershipValidator *group.MembershipValidator,
	strategies compatibility.Strategies,
	startBlockHeight uint64,
) (*Result, uint64, error) {
	logger.Debugf("[member:%v] initializing member", memberIndex)

	member, err := NewMember(
		logger,
		memberIndex,
		groupSize,
		dishonestThreshold,
		membershipValidator,
		seed,
		sessionID,
		strategies,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot create a new member: [%v]", err)
	}

	initialState := &ephemeralKeyPairGenerationState{
		channel: channel,
		member:  member.InitializeEphemeralKeysGeneration(),
	}

	stateMachine := state.NewSyncMachine(logger, ctx, channel, blockCounter, initialState)

	lastState, endBlockHeight, err := stateMachine.Execute(startBlockHeight)
	if err != nil {
		return nil, 0, err
	}

	finalizationState, ok := lastState.(*finalizationState)
	if !ok {
		return nil, 0, fmt.Errorf("execution ended on state: %T", lastState)
	}

	return finalizationState.result(), endBlockHeight, nil
}
