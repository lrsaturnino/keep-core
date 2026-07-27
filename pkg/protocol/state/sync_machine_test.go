package state

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net"
	netLocal "github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

var testLog map[uint64][]string
var blockCounter chain.BlockCounter

func TestSyncExecute(t *testing.T) {
	testLog = make(map[uint64][]string)

	localChain := local_v1.Connect(10, 5)
	blockCounter, _ = localChain.BlockCounter()
	provider := netLocal.Connect()
	channel, err := provider.BroadcastChannelFor("transitions_test")
	if err != nil {
		t.Fatal(err)
	}

	go func(blockCounter chain.BlockCounter) {
		blockCounter.WaitForBlockHeight(1)
		ctx, cancel := context.WithCancel(context.Background())
		channel.Send(ctx, &TestMessage{"message_1"})
		cancel()

		blockCounter.WaitForBlockHeight(4)
		ctx, cancel = context.WithCancel(context.Background())
		channel.Send(ctx, &TestMessage{"message_2"})
		cancel()

		blockCounter.WaitForBlockHeight(7)
		ctx, cancel = context.WithCancel(context.Background())
		channel.Send(ctx, &TestMessage{"message_3"})
		cancel()
	}(blockCounter)

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &TestMessage{}
	})

	initialState := testSyncState1{
		memberIndex: group.MemberIndex(1),
		channel:     channel,
	}

	stateMachine := NewSyncMachine(
		&testutils.MockLogger{},
		context.Background(),
		channel,
		blockCounter,
		initialState,
	)

	finalState, endBlockHeight, err := stateMachine.Execute(1)
	if err != nil {
		t.Errorf("unexpected error [%v]", err)
	}

	if _, ok := finalState.(*testSyncState5); !ok {
		t.Errorf("state is not final [%v]", finalState)
	}

	if endBlockHeight != 8 {
		t.Errorf("unexpected end block [%v]", endBlockHeight)
	}

	expectedTestLog := map[uint64][]string{
		1: {
			"1-state.testSyncState1-initiate",
			"1-state.testSyncState1-receive-message_1",
		},
		3: {"1-state.testSyncState2-initiate"},
		4: {"1-state.testSyncState2-receive-message_2"},
		6: {
			"1-state.testSyncState3-initiate",
			"1-state.testSyncState4-initiate",
		},
		7: {
			"1-state.testSyncState4-receive-message_3",
		},
		8: {
			"1-state.testSyncState5-initiate",
		},
	}

	if !reflect.DeepEqual(expectedTestLog, testLog) {
		t.Errorf("\nexpected: %v\nactual:   %v\n", expectedTestLog, testLog)
	}
}

// TestSyncExecute_ContextCancellation proves canceling the machine's parent
// context aborts the execution between states and surfaces the cancellation
// cause instead of running the protocol to its final state.
func TestSyncExecute_ContextCancellation(t *testing.T) {
	testLog = make(map[uint64][]string)

	localChain := local_v1.Connect(10, 5)
	blockCounter, _ = localChain.BlockCounter()
	provider := netLocal.Connect()
	channel, err := provider.BroadcastChannelFor("cancellation_test")
	if err != nil {
		t.Fatal(err)
	}

	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &TestMessage{}
	})

	initialState := testSyncState1{
		memberIndex: group.MemberIndex(1),
		channel:     channel,
	}

	cause := fmt.Errorf("cancellation cause")
	ctx, cancel := context.WithCancelCause(context.Background())

	stateMachine := NewSyncMachine(
		&testutils.MockLogger{},
		ctx,
		channel,
		blockCounter,
		initialState,
	)

	go func() {
		blockCounter.WaitForBlockHeight(2)
		cancel(cause)
	}()

	finalState, _, err := stateMachine.Execute(1)
	if finalState != nil {
		t.Errorf("expected no final state, got [%v]", finalState)
	}
	if !errors.Is(err, cause) {
		t.Errorf(
			"expected the cancellation cause in the error chain, got [%v]",
			err,
		)
	}
}

// TestSyncExecute_CancellationDuringStartWait proves canceling the machine
// while it is parked on the execution start-block wait — a chain that stalls
// before the ceremony begins — aborts the wait promptly with the cancellation
// cause instead of holding the machine until the start block arrives.
func TestSyncExecute_CancellationDuringStartWait(t *testing.T) {
	localChain := local_v1.Connect(10, 5)
	heldBlockCounter, _ := localChain.BlockCounter()
	provider := netLocal.Connect()
	channel, err := provider.BroadcastChannelFor("held_start_wait_test")
	if err != nil {
		t.Fatal(err)
	}
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &TestMessage{}
	})

	initialState := &testHeldWaitSyncState{
		memberIndex: group.MemberIndex(1),
		onInitiate: func() {
			t.Error("the initial state must not initiate before the start block")
		},
	}

	cause := fmt.Errorf("held start wait cancellation cause")
	ctx, cancel := context.WithCancelCause(context.Background())

	stateMachine := NewSyncMachine(
		&testutils.MockLogger{},
		ctx,
		channel,
		heldBlockCounter,
		initialState,
	)

	go func() {
		heldBlockCounter.WaitForBlockHeight(2)
		cancel(cause)
	}()

	// A start block the local counter cannot reach within the test keeps the
	// machine parked on the initial wait when the cancellation arrives.
	finalState, _, err := stateMachine.Execute(100000)
	if finalState != nil {
		t.Errorf("expected no final state, got [%v]", finalState)
	}
	if !errors.Is(err, cause) {
		t.Errorf(
			"expected the cancellation cause in the error chain, got [%v]",
			err,
		)
	}
}

// TestSyncExecute_CancellationDuringTransitionDelayWait proves canceling the
// machine while it is parked on a between-state delay wait — after an earlier
// state already completed its work — aborts the held wait promptly with the
// cancellation cause and never initiates the stalled state.
func TestSyncExecute_CancellationDuringTransitionDelayWait(t *testing.T) {
	localChain := local_v1.Connect(10, 5)
	heldBlockCounter, _ := localChain.BlockCounter()
	provider := netLocal.Connect()
	channel, err := provider.BroadcastChannelFor("held_delay_wait_test")
	if err != nil {
		t.Fatal(err)
	}
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &TestMessage{}
	})

	// The second state's delay stalls the machine between states, after the
	// first state finished; the cancellation must interrupt that held wait.
	stalledState := &testHeldWaitSyncState{
		memberIndex: group.MemberIndex(1),
		delayBlocks: 100000,
		onInitiate: func() {
			t.Error("the stalled state must not initiate during its delay wait")
		},
	}
	initialState := &testHeldWaitSyncState{
		memberIndex:  group.MemberIndex(1),
		activeBlocks: 1,
		next:         stalledState,
	}

	cause := fmt.Errorf("held delay wait cancellation cause")
	ctx, cancel := context.WithCancelCause(context.Background())

	stateMachine := NewSyncMachine(
		&testutils.MockLogger{},
		ctx,
		channel,
		heldBlockCounter,
		initialState,
	)

	go func() {
		heldBlockCounter.WaitForBlockHeight(4)
		cancel(cause)
	}()

	finalState, _, err := stateMachine.Execute(1)
	if finalState != nil {
		t.Errorf("expected no final state, got [%v]", finalState)
	}
	if !errors.Is(err, cause) {
		t.Errorf(
			"expected the cancellation cause in the error chain, got [%v]",
			err,
		)
	}
}

// testHeldWaitSyncState is a minimal state for the held-wait cancellation
// tests: its block bounds are configurable, initiation is observable, and it
// hands over to a preset next state.
type testHeldWaitSyncState struct {
	memberIndex  group.MemberIndex
	delayBlocks  uint64
	activeBlocks uint64
	next         SyncState
	onInitiate   func()
}

func (ts *testHeldWaitSyncState) DelayBlocks() uint64  { return ts.delayBlocks }
func (ts *testHeldWaitSyncState) ActiveBlocks() uint64 { return ts.activeBlocks }
func (ts *testHeldWaitSyncState) Initiate(ctx context.Context) error {
	if ts.onInitiate != nil {
		ts.onInitiate()
	}
	return nil
}
func (ts *testHeldWaitSyncState) Receive(msg net.Message) error { return nil }
func (ts *testHeldWaitSyncState) Next() (SyncState, error)      { return ts.next, nil }
func (ts *testHeldWaitSyncState) MemberIndex() group.MemberIndex {
	return ts.memberIndex
}

func addToTestLog(testState SyncState, functionName string) {
	currentBlock, _ := blockCounter.CurrentBlock()
	testLog[currentBlock] = append(
		testLog[currentBlock],
		fmt.Sprintf(
			"%v-%v-%v",
			testState.MemberIndex(),
			reflect.TypeOf(testState),
			functionName,
		),
	)
}

type testSyncState1 struct {
	memberIndex group.MemberIndex
	channel     net.BroadcastChannel
}

func (tss testSyncState1) DelayBlocks() uint64  { return 0 }
func (tss testSyncState1) ActiveBlocks() uint64 { return 2 }
func (tss testSyncState1) Initiate(ctx context.Context) error {
	addToTestLog(tss, "initiate")
	return nil
}
func (ts testSyncState1) Receive(msg net.Message) error {
	addToTestLog(
		ts,
		fmt.Sprintf("receive-%v", msg.Payload().(*TestMessage).content),
	)
	return nil
}
func (tss testSyncState1) Next() (SyncState, error)       { return &testSyncState2{tss}, nil }
func (tss testSyncState1) MemberIndex() group.MemberIndex { return tss.memberIndex }

type testSyncState2 struct {
	testSyncState1
}

func (tss testSyncState2) DelayBlocks() uint64  { return 0 }
func (tss testSyncState2) ActiveBlocks() uint64 { return 2 }
func (tss testSyncState2) Initiate(ctx context.Context) error {
	addToTestLog(tss, "initiate")
	return nil
}
func (ts testSyncState2) Receive(msg net.Message) error {
	addToTestLog(
		ts,
		fmt.Sprintf("receive-%v", msg.Payload().(*TestMessage).content),
	)
	return nil
}
func (tss testSyncState2) Next() (SyncState, error)       { return &testSyncState3{tss}, nil }
func (tss testSyncState2) MemberIndex() group.MemberIndex { return tss.memberIndex }

type testSyncState3 struct {
	testSyncState2
}

func (tss testSyncState3) DelayBlocks() uint64  { return 1 }
func (tss testSyncState3) ActiveBlocks() uint64 { return 0 }

func (tss testSyncState3) Initiate(ctx context.Context) error {
	addToTestLog(tss, "initiate")
	return nil
}

func (tss testSyncState3) Receive(msg net.Message) error {
	addToTestLog(
		tss,
		fmt.Sprintf("receive-%v", msg.Payload().(*TestMessage).content),
	)
	return nil
}

func (tss testSyncState3) Next() (SyncState, error)       { return &testSyncState4{tss}, nil }
func (tss testSyncState3) MemberIndex() group.MemberIndex { return tss.memberIndex }

type testSyncState4 struct {
	testSyncState3
}

func (ts testSyncState4) DelayBlocks() uint64  { return 0 }
func (ts testSyncState4) ActiveBlocks() uint64 { return 2 }
func (ts testSyncState4) Initiate(ctx context.Context) error {
	addToTestLog(ts, "initiate")
	return nil
}
func (ts testSyncState4) Receive(msg net.Message) error {
	addToTestLog(
		ts,
		fmt.Sprintf("receive-%v", msg.Payload().(*TestMessage).content),
	)
	return nil
}
func (tss testSyncState4) Next() (SyncState, error)       { return &testSyncState5{tss}, nil }
func (tss testSyncState4) MemberIndex() group.MemberIndex { return tss.memberIndex }

type testSyncState5 struct {
	testSyncState4
}

func (sts testSyncState5) DelayBlocks() uint64  { return 0 }
func (tss testSyncState5) ActiveBlocks() uint64 { return 0 }
func (tss testSyncState5) Initiate(ctx context.Context) error {
	addToTestLog(tss, "initiate")
	return nil
}
func (tss testSyncState5) Receive(msg net.Message) error {
	addToTestLog(
		tss,
		fmt.Sprintf("receive-%v", msg.Payload().(*TestMessage).content),
	)
	return nil
}
func (tss testSyncState5) Next() (SyncState, error)       { return nil, nil }
func (tss testSyncState5) MemberIndex() group.MemberIndex { return tss.memberIndex }

type TestMessage struct {
	content string
}

func (tm *TestMessage) Marshal() ([]byte, error) {
	return []byte(tm.content), nil
}

func (tm *TestMessage) Unmarshal(bytes []byte) error {
	tm.content = string(bytes)
	return nil
}

func (tm *TestMessage) Type() string {
	return "test_message"
}
