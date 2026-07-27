package state

import (
	"context"
	"fmt"

	"github.com/ipfs/go-log/v2"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net"
)

// For the entire time of state transition (delay + initiate), messages
// are not handled. We use a buffer to unblock producers and let
// them perform optional filtering/validation during that time.
// The size of that buffer should not be lower than the number of messages
// which can be delivered by the broadcast channel during the time the state
// is blocked on initiation.
// This version of the state machine requires a strict synchronization between
// participants, so this number is also the maximum number of messages that
// could be delivered in a single state.
const syncReceiveBuffer = 128

// SyncMachine is a state machine that executes states implementing the
// SyncState interface.
//
// SyncMachine is meant to be used with interactive protocols when participants
// are expected to synchronize based on the number of blocks being mined at the
// time the protocol is executing. Even if the given participant received all
// the necessary information to continue the protocol, the state machine waits
// with proceeding to the next step for the fixed duration of blocks. This
// approach is the most optimal when the protocol may finish successfully even
// if some members expected to participate in the execution are inactive.
type SyncMachine struct {
	logger       log.StandardLogger
	ctx          context.Context
	channel      net.BroadcastChannel
	blockCounter chain.BlockCounter
	initialState SyncState // first state from which execution starts
}

// NewSyncMachine returns a new protocol state machine.
//
// The context passed to NewSyncMachine must be active for the entire lifetime
// of the execution. Canceling it aborts the machine even while it is parked on
// a block wait — the start-block wait and the between-state delay waits are
// interruptible, so a stalled chain cannot hold a canceled execution hostage.
// Per-state work receives a context derived from it, and the machine returns
// the cancellation cause as its error.
func NewSyncMachine(
	logger log.StandardLogger,
	ctx context.Context,
	channel net.BroadcastChannel,
	blockCounter chain.BlockCounter,
	initialState SyncState,
) *SyncMachine {
	return &SyncMachine{
		logger:       logger,
		ctx:          ctx,
		channel:      channel,
		blockCounter: blockCounter,
		initialState: initialState,
	}
}

// Execute state machine starting with initial state up to finalization. It
// requires the broadcast channel to be pre-initialized.
func (sm *SyncMachine) Execute(startBlockHeight uint64) (SyncState, uint64, error) {
	recvChan := make(chan net.Message, syncReceiveBuffer)
	handler := func(msg net.Message) {
		recvChan <- msg
	}

	currentState := sm.initialState
	ctx, cancelCtx := context.WithCancel(sm.ctx)
	sm.channel.Recv(ctx, handler)

	sm.logger.Infof(
		"[member:%v] waiting for block [%v] to start execution",
		currentState.MemberIndex(),
		startBlockHeight,
	)
	err := waitForBlockHeight(ctx, sm.blockCounter, startBlockHeight)
	if err != nil {
		cancelCtx()
		return nil, 0, fmt.Errorf(
			"failed to wait for the execution start block: [%w]",
			err,
		)
	}

	lastStateEndBlockHeight := startBlockHeight

	blockWaiter, err := stateTransition(
		ctx,
		sm.logger,
		currentState,
		lastStateEndBlockHeight,
		sm.blockCounter,
	)
	if err != nil {
		cancelCtx()
		return nil, 0, err
	}

	for {
		select {
		case msg := <-recvChan:
			err := currentState.Receive(msg)
			if err != nil {
				sm.logger.Errorf(
					"[member:%v,state:%T] failed to receive a message: [%v]",
					currentState.MemberIndex(),
					currentState,
					err,
				)
			}

		case lastStateEndBlockHeight := <-blockWaiter:
			cancelCtx()

			nextState, err := currentState.Next()
			if err != nil {
				return nil, 0, fmt.Errorf(
					"failed to complete state [%T]: [%w]",
					currentState,
					err,
				)
			}

			if nextState == nil {
				sm.logger.Infof(
					"[member:%v,state:%T] reached final state at block: [%v]",
					currentState.MemberIndex(),
					currentState,
					lastStateEndBlockHeight,
				)
				return currentState, lastStateEndBlockHeight, nil
			}

			currentState = nextState
			ctx, cancelCtx = context.WithCancel(sm.ctx)
			sm.channel.Recv(ctx, handler)

			blockWaiter, err = stateTransition(
				ctx,
				sm.logger,
				currentState,
				lastStateEndBlockHeight,
				sm.blockCounter,
			)
			if err != nil {
				cancelCtx()
				return nil, 0, err
			}

		case <-sm.ctx.Done():
			cancelCtx()
			return nil, 0, fmt.Errorf(
				"execution of state [%T] canceled: [%w]",
				currentState,
				context.Cause(sm.ctx),
			)
		}
	}
}

func stateTransition(
	ctx context.Context,
	logger log.StandardLogger,
	currentState SyncState,
	lastStateEndBlockHeight uint64,
	blockCounter chain.BlockCounter,
) (<-chan uint64, error) {
	logger.Infof(
		"[member:%v,state:%T] transitioning to a new state at block: [%v]",
		currentState.MemberIndex(),
		currentState,
		lastStateEndBlockHeight,
	)

	// We delay the initialization of the new state by `initiateDelay` of blocks
	// to give all other participants a chance to enter the new state. This is
	// needed when state accepts only messages specific to that state.
	// In that case, if the message is sent too early, it is lost given that the
	// syncReceiveBuffer has the retransmissions filtered out.
	initiateDelay := lastStateEndBlockHeight + currentState.DelayBlocks()
	err := waitForBlockHeight(ctx, blockCounter, initiateDelay)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to wait [%v] blocks entering state [%T]: [%w]",
			currentState.DelayBlocks(),
			currentState,
			err,
		)
	}

	err = currentState.Initiate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate new state [%w]", err)
	}

	blockWaiter, err := blockCounter.BlockHeightWaiter(
		initiateDelay + currentState.ActiveBlocks(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize block height waiter at state [%T]: [%v]",
			currentState,
			err,
		)
	}

	logger.Infof(
		"[member:%v,state:%T] transitioned to new state",
		currentState.MemberIndex(),
		currentState,
	)

	return blockWaiter, nil
}

// waitForBlockHeight blocks until the given height is reached or the context
// ends, whichever happens first. A synchronous WaitForBlockHeight call would
// hold the machine hostage to a stalled chain even after its ceremony was
// canceled; interrupting the wait lets the caller observe the cancellation
// cause and run its recovery path instead.
func waitForBlockHeight(
	ctx context.Context,
	blockCounter chain.BlockCounter,
	blockHeight uint64,
) error {
	waiter, err := blockCounter.BlockHeightWaiter(blockHeight)
	if err != nil {
		return err
	}

	select {
	case <-waiter:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
