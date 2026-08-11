package tbtc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

func TestNode_GetSigningExecutor(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	localChain := Connect()
	localProvider := local.Connect()

	signer := createMockSigner(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := localChain.CalculateWalletID(signer.wallet.publicKey)
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

	// Populate the mock keystore with the mock signer's data. This is
	// required to make the node controlling the signer's wallet.
	keyStorePersistence := createMockKeyStorePersistence(t, signer)

	node, err := newNode(
		groupParameters,
		localChain,
		newLocalBitcoinChain(),
		localProvider,
		keyStorePersistence,
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKey := signer.wallet.publicKey
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertIntsEqual(
		t,
		"cache size",
		0,
		len(node.signingExecutors),
	)

	executor, ok, err := node.getSigningExecutor(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}

	testutils.AssertIntsEqual(
		t,
		"cache size",
		1,
		len(node.signingExecutors),
	)

	testutils.AssertIntsEqual(
		t,
		"signers count",
		1,
		len(executor.signers),
	)

	if !reflect.DeepEqual(signer, executor.signers[0]) {
		t.Errorf("executor holds an unexpected signer")
	}

	expectedChannel := fmt.Sprintf(
		"%s-%s",
		ProtocolName,
		hex.EncodeToString(walletPublicKeyBytes),
	)
	testutils.AssertStringsEqual(
		t,
		"broadcast channel",
		expectedChannel,
		executor.broadcastChannel.Name(),
	)

	_, ok, err = node.getSigningExecutor(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}

	// The executor was already created in the previous call so cached instance
	// should be returned and no new executors should be created.
	testutils.AssertIntsEqual(
		t,
		"cache size",
		1,
		len(node.signingExecutors),
	)

	// Construct an arbitrary public key representing a wallet that is not
	// controlled by the node. We need to make sure the public key's points
	// are on the curve to avoid troubles during processing.
	x, y := walletPublicKey.Curve.Double(walletPublicKey.X, walletPublicKey.Y)
	nonControlledWalletPublicKey := &ecdsa.PublicKey{
		Curve: walletPublicKey.Curve,
		X:     x,
		Y:     y,
	}

	_, ok, err = node.getSigningExecutor(nonControlledWalletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("node is not supposed to control wallet signers")
	}
}

func TestNode_GetCoordinationExecutor(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	localChain := Connect()
	localProvider := local.Connect()

	signer := createMockSigner(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := localChain.CalculateWalletID(signer.wallet.publicKey)
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

	// Populate the mock keystore with the mock signer's data. This is
	// required to make the node controlling the signer's wallet.
	keyStorePersistence := createMockKeyStorePersistence(t, signer)

	node, err := newNode(
		groupParameters,
		localChain,
		newLocalBitcoinChain(),
		localProvider,
		keyStorePersistence,
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKey := signer.wallet.publicKey
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertIntsEqual(
		t,
		"cache size",
		0,
		len(node.coordinationExecutors),
	)

	executor, ok, err := node.getCoordinationExecutor(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}

	testutils.AssertIntsEqual(
		t,
		"cache size",
		1,
		len(node.coordinationExecutors),
	)

	testutils.AssertIntsEqual(
		t,
		"signers count",
		1,
		len(executor.membersIndexes),
	)

	if !reflect.DeepEqual(
		signer.signingGroupMemberIndex,
		executor.membersIndexes[0],
	) {
		t.Errorf("executor holds an unexpected signer")
	}

	expectedChannel := fmt.Sprintf(
		"%s-%s-coordination",
		ProtocolName,
		hex.EncodeToString(walletPublicKeyBytes),
	)
	testutils.AssertStringsEqual(
		t,
		"broadcast channel",
		expectedChannel,
		executor.broadcastChannel.Name(),
	)

	_, ok, err = node.getCoordinationExecutor(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}

	// The executor was already created in the previous call so cached instance
	// should be returned and no new executors should be created.
	testutils.AssertIntsEqual(
		t,
		"cache size",
		1,
		len(node.coordinationExecutors),
	)

	// Construct an arbitrary public key representing a wallet that is not
	// controlled by the node. We need to make sure the public key's points
	// are on the curve to avoid troubles during processing.
	x, y := walletPublicKey.Curve.Double(walletPublicKey.X, walletPublicKey.Y)
	nonControlledWalletPublicKey := &ecdsa.PublicKey{
		Curve: walletPublicKey.Curve,
		X:     x,
		Y:     y,
	}

	_, ok, err = node.getCoordinationExecutor(nonControlledWalletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("node is not supposed to control wallet signers")
	}
}

func TestNode_RunCoordinationLayer(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	blockTime := 1 * time.Millisecond

	localChain := Connect(blockTime)
	localProvider := local.Connect()

	signer := createMockSigner(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := localChain.CalculateWalletID(signer.wallet.publicKey)
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

	// Populate the mock keystore with the mock signer's data. This is
	// required to make the node controlling the signer's wallet.
	keyStorePersistence := createMockKeyStorePersistence(t, signer)

	n, err := newNode(
		groupParameters,
		localChain,
		newLocalBitcoinChain(),
		localProvider,
		keyStorePersistence,
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Mock the coordination procedure execution. Return predefined results
	// on specific coordination windows.
	executeCoordinationProcedureFn := func(
		_ *node,
		window *coordinationWindow,
		walletPublicKey *ecdsa.PublicKey,
	) (*coordinationResult, bool) {
		if signer.wallet.publicKey.Equal(walletPublicKey) {
			result, ok := map[uint64]*coordinationResult{
				900: {
					window:   window,
					proposal: &mockCoordinationProposal{ActionDepositSweep},
				},
				// Omit window at block 1800 to make sure the layer doesn't
				// crash if no result is produced.
				2700: {
					window:   window,
					proposal: &mockCoordinationProposal{ActionRedemption},
				},
				// Put some trash value to make sure coordination windows
				// are distributed correctly.
				2705: {
					window:   window,
					proposal: &mockCoordinationProposal{ActionMovingFunds},
				},
				3600: {
					window:   window,
					proposal: &mockCoordinationProposal{ActionNoop},
				},
				4500: {
					window:   window,
					proposal: &mockCoordinationProposal{ActionMovedFundsSweep},
				},
			}[window.coordinationBlock]

			return result, ok
		}

		return nil, false
	}

	// Simply pass processed results to the channel.
	processedResultsChan := make(chan *coordinationResult, 5)
	processCoordinationResultFn := func(
		_ context.Context,
		_ *node,
		result *coordinationResult,
	) {
		processedResultsChan <- result
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	err = n.runCoordinationLayer(
		ctx,
		&coordinationLayerSettings{
			executeCoordinationProcedureFn: executeCoordinationProcedureFn,
			processCoordinationResultFn:    processCoordinationResultFn,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Set up a stop signal that will be triggered after the last coordination
	// window passes.
	waiter, err := localChain.blockCounter.BlockHeightWaiter(5000)
	if err != nil {
		t.Fatal(err)
	}

	var processedResults []*coordinationResult
loop:
	for {
		select {
		case result := <-processedResultsChan:
			if result == nil {
				continue
			}

			processedResults = append(processedResults, result)

			// Once the second-last coordination window is processed, stop the
			// coordination layer. In that case, the last window should not be
			// processed. This allows us to test that the coordination layer's
			// shutdown works as expected.
			if len(processedResults) == 3 {
				cancelCtx()
			}
		case <-waiter:
			break loop
		}
	}

	testutils.AssertIntsEqual(
		t,
		"processed results count",
		3,
		len(processedResults),
	)

	resultActionsByWindow := make(map[uint64]WalletActionType, len(processedResults))
	for _, result := range processedResults {
		resultActionsByWindow[result.window.coordinationBlock] =
			result.proposal.ActionType()
	}

	testutils.AssertIntsEqual(
		t,
		"processed coordination windows count",
		3,
		len(resultActionsByWindow),
	)

	firstAction, ok := resultActionsByWindow[900]
	if !ok {
		t.Fatal("expected coordination result for window at block 900")
	}
	testutils.AssertStringsEqual(
		t,
		"result for block 900",
		ActionDepositSweep.String(),
		firstAction.String(),
	)

	secondAction, ok := resultActionsByWindow[2700]
	if !ok {
		t.Fatal("expected coordination result for window at block 2700")
	}
	testutils.AssertStringsEqual(
		t,
		"result for block 2700",
		ActionRedemption.String(),
		secondAction.String(),
	)

	if _, ok := resultActionsByWindow[2705]; ok {
		t.Fatal("unexpected coordination result for non-window block 2705")
	}

	// Result processing is asynchronous, so by the time the test cancels the
	// coordination layer after the third processed result, either the 3600
	// window or the subsequent 4500 window may already be in flight.
	if thirdAction, ok := resultActionsByWindow[3600]; ok {
		testutils.AssertStringsEqual(
			t,
			"result for block 3600",
			ActionNoop.String(),
			thirdAction.String(),
		)
	} else {
		fourthAction, ok := resultActionsByWindow[4500]
		if !ok {
			t.Fatal("expected coordination result for block 3600 or 4500")
		}
		testutils.AssertStringsEqual(
			t,
			"result for block 4500",
			ActionMovedFundsSweep.String(),
			fourthAction.String(),
		)
	}
}

// TestNode_RunCoordinationLayer_StartsTransactionMonitor is the regression test
// for the lost transaction-monitor launch: the monitor was constructed, wired
// into every wallet action, and fed by every successful broadcast, but nothing
// ever started its polling loop. Registering a transaction therefore had no
// observable consequence - nothing polled confirmations, nothing evicted, and
// nothing alerted - while the stuck- and unmonitored-transaction counters sat at
// zero exactly as they do on a healthy node.
//
// This test drives the production lifecycle path and joins a real confirmation
// lookup, so it fails against a node that only constructs the monitor.
func TestNode_RunCoordinationLayer_StartsTransactionMonitor(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	localChain := Connect(1 * time.Millisecond)
	localProvider := local.Connect()

	btcChain := newRecordingTransactionConfirmationsChain()

	// The node archives closed wallets on construction, so the mock signer's
	// wallet has to be known to the chain first.
	signer := createMockSigner(t)
	walletID, err := localChain.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	localChain.setWallet(
		bitcoin.PublicKeyHash(signer.wallet.publicKey),
		&WalletChainData{
			EcdsaWalletID: walletID,
			State:         StateLive,
		},
	)

	n, err := newNode(
		groupParameters,
		localChain,
		btcChain,
		localProvider,
		createMockKeyStorePersistence(t, signer),
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wire metrics the way the production startup path does, so the liveness
	// telemetry under test travels the same route an operator's endpoint does.
	recorder := newCountingMetricsRecorder()
	n.setPerformanceMetrics(recorder)

	// Poll fast enough for the loop to make progress within the test, without
	// touching the production interval.
	setCheckInterval(n.transactionMonitor, 5*time.Millisecond)

	// A transaction the local chain has never seen: its lookup fails, so the
	// monitor keeps it tracked and keeps polling it.
	monitoredTxHash := bitcoin.Hash{0xab, 0xcd}
	n.transactionMonitor.track(monitoredTxHash, [20]byte{1})

	ctx, cancelCtx := context.WithCancel(context.Background())

	// The monitor goroutine is started by the call below and the node keeps no
	// handle on it, so the join is registered before the launch: whichever
	// assertion this test exits on, the loop is cancelled and awaited rather
	// than left polling the chain for the rest of the package run.
	joinOnCleanup(t, "the monitor goroutine", cancelCtx, n.transactionMonitor.stopped)

	// The coordination procedure is stubbed out; this test is about the monitor
	// the coordination layer owns, not about coordination results.
	err = n.runCoordinationLayer(
		ctx,
		&coordinationLayerSettings{
			executeCoordinationProcedureFn: func(
				*node,
				*coordinationWindow,
				*ecdsa.PublicKey,
			) (*coordinationResult, bool) {
				return nil, false
			},
			processCoordinationResultFn: func(
				context.Context,
				*node,
				*coordinationResult,
			) {
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// The proof that the loop is alive: a real confirmation lookup for the
	// pre-tracked transaction, joined through a channel rather than inferred
	// from elapsed time.
	select {
	case hash := <-btcChain.lookups:
		if hash != monitoredTxHash {
			t.Fatalf(
				"expected a confirmation lookup for [%s]; got [%s]",
				monitoredTxHash.Hex(bitcoin.ReversedByteOrder),
				hash.Hex(bitcoin.ReversedByteOrder),
			)
		}
	case <-time.After(5 * time.Second):
		t.Fatal(
			"no confirmation lookup within the timeout; the coordination layer " +
				"did not start the transaction monitor",
		)
	}

	if got := recorder.GetGaugeValue(
		clientinfo.MetricTransactionMonitorRunning,
	); got != 1 {
		t.Fatalf("expected the running gauge at [1]; got [%v]", got)
	}

	// A returned cycle is the metric an operator polls for forward progress.
	// Waiting on the recorder's own events keeps the timer out of the
	// synchronization path - it is only the failure bound.
	if !recorder.awaitCounterAtLeast(
		clientinfo.MetricTransactionMonitorCheckCyclesTotal,
		1,
		5*time.Second,
	) {
		t.Fatal("the monitor never counted a completed check cycle")
	}

	if got := recorder.trackedGauge(); got != 1 {
		t.Fatalf("expected the tracked-count gauge at [1]; got [%d]", got)
	}

	cancelCtx()

	// Two separate claims, and the gauge alone would only support the first.
	// The loop publishes zero from its defer path and then keeps unwinding, so
	// the gauge says the monitor announced it was stopping; the monitor's own
	// termination signal is what says the goroutine is actually gone. The node
	// starts that goroutine itself, so this channel is the only handle a test
	// has on it.
	if !recorder.awaitGauge(
		clientinfo.MetricTransactionMonitorRunning,
		0,
		5*time.Second,
	) {
		t.Fatal(
			"the monitor did not publish a stopped running gauge after the " +
				"node's context was cancelled",
		)
	}

	select {
	case <-n.transactionMonitor.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal(
			"the monitor goroutine did not terminate after the node's " +
				"context was cancelled",
		)
	}

	// The loop this test joined is provably gone, so what the remaining window
	// watches for is a second one: a duplicate launch site would leave a monitor
	// still polling this chain, at ten times the interval held open here.
	for len(btcChain.lookups) > 0 {
		<-btcChain.lookups
	}
	time.Sleep(50 * time.Millisecond)

	select {
	case hash := <-btcChain.lookups:
		t.Fatalf(
			"the monitor issued a confirmation lookup for [%s] after it stopped",
			hash.Hex(bitcoin.ReversedByteOrder),
		)
	default:
	}
}

type mockCoordinationProposal struct {
	action WalletActionType
}

func (mcp *mockCoordinationProposal) ActionType() WalletActionType {
	return mcp.action
}

func (mcp *mockCoordinationProposal) ValidityBlocks() uint64 {
	panic("unsupported")
}

func (mcp *mockCoordinationProposal) Marshal() ([]byte, error) {
	panic("unsupported")
}

func (mcp *mockCoordinationProposal) Unmarshal(bytes []byte) error {
	panic("unsupported")
}

// TestNode_HandleHeartbeatProposal_WalletNotControlled verifies that
// handleHeartbeatProposal returns without dispatching when the node does not
// control any signers for the given wallet.
func TestNode_HandleHeartbeatProposal_WalletNotControlled(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	uncontrolledWallet := uncontrolledWalletFor(signer)
	proposal := &HeartbeatProposal{Message: [16]byte{0x01}}

	n.handleHeartbeatProposal(uncontrolledWallet, proposal, 10, 100, newTestPermit(participation.TBTCHeartbeat))

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf("expected no dispatched actions for uncontrolled wallet, got %d", count)
	}
}

// TestNode_HandleHeartbeatProposal_WalletBusy verifies that
// handleHeartbeatProposal does not crash when the wallet dispatcher returns
// errWalletBusy (another action is already running on the same wallet).
func TestNode_HandleHeartbeatProposal_WalletBusy(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	walletKey := walletKeyFor(t, signer)

	func() {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		n.walletDispatcher.actions[walletKey] = ActionHeartbeat
	}()

	n.handleHeartbeatProposal(signer.wallet, &HeartbeatProposal{Message: [16]byte{0x02}}, 10, 100, newTestPermit(participation.TBTCHeartbeat))

	// The pre-populated entry must still be there -- our call did not modify it.
	actionType, ok := func() (WalletActionType, bool) {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		v, exists := n.walletDispatcher.actions[walletKey]
		return v, exists
	}()
	if !ok || actionType != ActionHeartbeat {
		t.Errorf(
			"expected actions map to retain pre-populated ActionHeartbeat, "+
				"got ok=%v actionType=%v",
			ok, actionType,
		)
	}
}

// TestNode_HandleHeartbeatProposal_DispatchesAction verifies the happy path:
// for a controlled wallet the action is dispatched and the dispatcher cleans
// up the entry once the goroutine completes.
func TestNode_HandleHeartbeatProposal_DispatchesAction(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)

	n.handleHeartbeatProposal(signer.wallet, &HeartbeatProposal{Message: [16]byte{0x03}}, 10, 100, newTestPermit(participation.TBTCHeartbeat))

	waitForDispatcherIdle(t, n)

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf(
			"expected walletDispatcher to be idle after action completed, got %d active actions",
			count,
		)
	}
}

// TestNode_HandleDepositSweepProposal_WalletNotControlled verifies that
// handleDepositSweepProposal skips dispatch for an uncontrolled wallet.
func TestNode_HandleDepositSweepProposal_WalletNotControlled(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	uncontrolledWallet := uncontrolledWalletFor(signer)
	proposal := &DepositSweepProposal{}

	n.handleDepositSweepProposal(uncontrolledWallet, proposal, 10, 100, newTestPermit(participation.TBTCSigning))

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf("expected no dispatched actions for uncontrolled wallet, got %d", count)
	}
}

// TestNode_HandleDepositSweepProposal_WalletBusy verifies that
// handleDepositSweepProposal handles errWalletBusy without panicking.
func TestNode_HandleDepositSweepProposal_WalletBusy(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	walletKey := walletKeyFor(t, signer)

	func() {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		n.walletDispatcher.actions[walletKey] = ActionDepositSweep
	}()

	n.handleDepositSweepProposal(signer.wallet, &DepositSweepProposal{}, 10, 100, newTestPermit(participation.TBTCSigning))

	actionType, ok := func() (WalletActionType, bool) {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		v, exists := n.walletDispatcher.actions[walletKey]
		return v, exists
	}()
	if !ok || actionType != ActionDepositSweep {
		t.Errorf(
			"expected pre-populated ActionDepositSweep to remain, got ok=%v actionType=%v",
			ok, actionType,
		)
	}
}

// TestNode_HandleDepositSweepProposal_DispatchesAction verifies the happy path:
// for a controlled wallet the action is dispatched and the dispatcher cleans
// up the entry once the goroutine completes (action will fail validation with
// the empty proposal, but the dispatch itself succeeds).
func TestNode_HandleDepositSweepProposal_DispatchesAction(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)

	n.handleDepositSweepProposal(
		signer.wallet,
		&DepositSweepProposal{SweepTxFee: big.NewInt(0)},
		10,
		100,
		newTestPermit(participation.TBTCSigning),
	)

	waitForDispatcherIdle(t, n)

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf(
			"expected walletDispatcher to be idle after action completed, got %d active actions",
			count,
		)
	}
}

// TestNode_HandleRedemptionProposal_WalletNotControlled verifies that
// handleRedemptionProposal skips dispatch for an uncontrolled wallet.
func TestNode_HandleRedemptionProposal_WalletNotControlled(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	uncontrolledWallet := uncontrolledWalletFor(signer)
	proposal := &RedemptionProposal{}

	n.handleRedemptionProposal(uncontrolledWallet, proposal, 10, 100, newTestPermit(participation.TBTCSigning))

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf("expected no dispatched actions for uncontrolled wallet, got %d", count)
	}
}

// TestNode_HandleRedemptionProposal_WalletBusy verifies that
// handleRedemptionProposal handles errWalletBusy without panicking.
func TestNode_HandleRedemptionProposal_WalletBusy(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	walletKey := walletKeyFor(t, signer)

	func() {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		n.walletDispatcher.actions[walletKey] = ActionRedemption
	}()

	n.handleRedemptionProposal(signer.wallet, &RedemptionProposal{RedemptionTxFee: big.NewInt(0)}, 10, 100, newTestPermit(participation.TBTCSigning))

	actionType, ok := func() (WalletActionType, bool) {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		v, exists := n.walletDispatcher.actions[walletKey]
		return v, exists
	}()
	if !ok || actionType != ActionRedemption {
		t.Errorf(
			"expected pre-populated ActionRedemption to remain, got ok=%v actionType=%v",
			ok, actionType,
		)
	}
}

// TestNode_HandleRedemptionProposal_DispatchesAction verifies the happy path:
// for a controlled wallet the action is dispatched and the dispatcher cleans
// up the entry once the goroutine completes (action will fail validation with
// the empty proposal, but the dispatch itself succeeds).
func TestNode_HandleRedemptionProposal_DispatchesAction(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)

	n.handleRedemptionProposal(
		signer.wallet,
		&RedemptionProposal{RedemptionTxFee: big.NewInt(0)},
		10,
		100,
		newTestPermit(participation.TBTCSigning),
	)

	waitForDispatcherIdle(t, n)

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf(
			"expected walletDispatcher to be idle after action completed, got %d active actions",
			count,
		)
	}
}

// TestNode_HandleMovingFundsProposal_WalletNotControlled verifies that
// handleMovingFundsProposal skips dispatch for an uncontrolled wallet.
func TestNode_HandleMovingFundsProposal_WalletNotControlled(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	uncontrolledWallet := uncontrolledWalletFor(signer)
	proposal := &MovingFundsProposal{}

	n.handleMovingFundsProposal(uncontrolledWallet, proposal, 10, 100, newTestPermit(participation.TBTCSigning))

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf("expected no dispatched actions for uncontrolled wallet, got %d", count)
	}
}

// TestNode_HandleMovingFundsProposal_WalletBusy verifies that
// handleMovingFundsProposal handles errWalletBusy without panicking.
func TestNode_HandleMovingFundsProposal_WalletBusy(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	walletKey := walletKeyFor(t, signer)

	func() {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		n.walletDispatcher.actions[walletKey] = ActionMovingFunds
	}()

	n.handleMovingFundsProposal(signer.wallet, &MovingFundsProposal{}, 10, 100, newTestPermit(participation.TBTCSigning))

	actionType, ok := func() (WalletActionType, bool) {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		v, exists := n.walletDispatcher.actions[walletKey]
		return v, exists
	}()
	if !ok || actionType != ActionMovingFunds {
		t.Errorf(
			"expected pre-populated ActionMovingFunds to remain, got ok=%v actionType=%v",
			ok, actionType,
		)
	}
}

// TestNode_HandleMovingFundsProposal_DispatchesAction verifies the happy path:
// for a controlled wallet the action is dispatched and the dispatcher cleans
// up the entry once the goroutine completes (action fails immediately because
// the wallet has no main UTXO, but the dispatch itself succeeds).
func TestNode_HandleMovingFundsProposal_DispatchesAction(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)

	n.handleMovingFundsProposal(signer.wallet, &MovingFundsProposal{}, 10, 100, newTestPermit(participation.TBTCSigning))

	waitForDispatcherIdle(t, n)

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf(
			"expected walletDispatcher to be idle after action completed, got %d active actions",
			count,
		)
	}
}

// TestNode_HandleMovedFundsSweepProposal_WalletNotControlled verifies that
// handleMovedFundsSweepProposal skips dispatch for an uncontrolled wallet.
func TestNode_HandleMovedFundsSweepProposal_WalletNotControlled(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	uncontrolledWallet := uncontrolledWalletFor(signer)
	proposal := &MovedFundsSweepProposal{}

	n.handleMovedFundsSweepProposal(uncontrolledWallet, proposal, 10, 100, newTestPermit(participation.TBTCSigning))

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf("expected no dispatched actions for uncontrolled wallet, got %d", count)
	}
}

// TestNode_HandleMovedFundsSweepProposal_WalletBusy verifies that
// handleMovedFundsSweepProposal handles errWalletBusy without panicking.
func TestNode_HandleMovedFundsSweepProposal_WalletBusy(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)
	walletKey := walletKeyFor(t, signer)

	func() {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		n.walletDispatcher.actions[walletKey] = ActionMovedFundsSweep
	}()

	n.handleMovedFundsSweepProposal(signer.wallet, &MovedFundsSweepProposal{}, 10, 100, newTestPermit(participation.TBTCSigning))

	actionType, ok := func() (WalletActionType, bool) {
		n.walletDispatcher.actionsMutex.Lock()
		defer n.walletDispatcher.actionsMutex.Unlock()
		v, exists := n.walletDispatcher.actions[walletKey]
		return v, exists
	}()
	if !ok || actionType != ActionMovedFundsSweep {
		t.Errorf(
			"expected pre-populated ActionMovedFundsSweep to remain, got ok=%v actionType=%v",
			ok, actionType,
		)
	}
}

// TestNode_HandleMovedFundsSweepProposal_DispatchesAction verifies the happy
// path: for a controlled wallet the action is dispatched and the dispatcher
// cleans up the entry once the goroutine completes (action will fail validation
// with the empty proposal, but the dispatch itself succeeds).
func TestNode_HandleMovedFundsSweepProposal_DispatchesAction(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)

	n.handleMovedFundsSweepProposal(
		signer.wallet,
		&MovedFundsSweepProposal{SweepTxFee: big.NewInt(0)},
		10,
		100,
		newTestPermit(participation.TBTCSigning),
	)

	waitForDispatcherIdle(t, n)

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf(
			"expected walletDispatcher to be idle after action completed, got %d active actions",
			count,
		)
	}
}

// TestProcessCoordinationResult_NoopActionReturnsEarly verifies that
// processCoordinationResult returns without dispatching any wallet action when
// the proposed action is ActionNoop.
func TestProcessCoordinationResult_NoopActionReturnsEarly(t *testing.T) {
	n, signer := setupNodeForHandlerTests(t)

	result := &coordinationResult{
		wallet: signer.wallet,
		window: newCoordinationWindow(100),
		proposal: &mockCoordinationProposal{
			action: ActionNoop,
		},
	}

	processCoordinationResult(context.Background(), n, result)

	if count := dispatchedActionsCount(n); count != 0 {
		t.Errorf("expected no dispatched actions for Noop result, got %d", count)
	}
}

// routingTestProposals returns one well-formed proposal per dispatchable
// wallet action, keyed by the action type it must route to.
func routingTestProposals() map[WalletActionType]CoordinationProposal {
	return map[WalletActionType]CoordinationProposal{
		ActionHeartbeat:       &HeartbeatProposal{Message: [16]byte{0x04}},
		ActionDepositSweep:    &DepositSweepProposal{},
		ActionRedemption:      &RedemptionProposal{RedemptionTxFee: big.NewInt(0)},
		ActionMovingFunds:     &MovingFundsProposal{},
		ActionMovedFundsSweep: &MovedFundsSweepProposal{SweepTxFee: big.NewInt(0)},
	}
}

// TestProcessCoordinationResult_RoutesToHandler verifies that every
// dispatchable proposal type reaches its handler and the wallet dispatcher
// under a real participation gate. Coordination results arrive before the
// window's end block, so processCoordinationResult must first wait for that
// block and only then acquire the permit anchored at it. The wallet is
// pre-marked busy so dispatch is rejected before the action's execute() method
// runs; the rejected-actions counter increment is positive proof the routed
// handler reached the dispatcher.
func TestProcessCoordinationResult_RoutesToHandler(t *testing.T) {
	for action, proposal := range routingTestProposals() {
		t.Run(action.String(), func(t *testing.T) {
			n, signer, recorder := setupNodeForRoutingTests(t)
			walletKey := markWalletBusy(t, n, signer)

			result := &coordinationResult{
				wallet:   signer.wallet,
				window:   newCoordinationWindow(100),
				proposal: proposal,
			}

			processCoordinationResult(context.Background(), n, result)

			rejected := recorder.counter(
				clientinfo.MetricWalletDispatcherRejectedTotal,
			)
			if rejected != 1 {
				t.Errorf(
					"expected exactly one rejected dispatch proving the "+
						"handler was invoked, got %v",
					rejected,
				)
			}

			// The busy sentinel must be untouched: dispatch was attempted but
			// returned errWalletBusy without modifying the map entry.
			_, ok := func() (WalletActionType, bool) {
				n.walletDispatcher.actionsMutex.Lock()
				defer n.walletDispatcher.actionsMutex.Unlock()
				v, exists := n.walletDispatcher.actions[walletKey]
				return v, exists
			}()
			if !ok {
				t.Error(
					"expected walletDispatcher to retain the busy sentinel " +
						"after routing",
				)
			}
		})
	}
}

// TestProcessCoordinationResult_AtCutoverAnchorDispatches verifies the exact
// cutover boundary: a wallet action whose canonical anchor equals the cutover
// block resolves to the security-v2 mode and reaches the dispatcher for every
// dispatchable proposal type.
func TestProcessCoordinationResult_AtCutoverAnchorDispatches(t *testing.T) {
	for action, proposal := range routingTestProposals() {
		t.Run(action.String(), func(t *testing.T) {
			n, signer, lc := setupNodeWithChain(t, 1*time.Millisecond)

			blockCounter, err := lc.BlockCounter()
			if err != nil {
				t.Fatal(err)
			}

			window := newCoordinationWindow(100)
			// The permit anchor is the window's end block; make it the exact
			// cutover block so the anchor sits right at C.
			n.participationGate = newTestGateWithCutover(
				t,
				blockCounter,
				window.endBlock(),
			)

			recorder := newDispatcherMetricsRecorder()
			n.walletDispatcher.setMetricsRecorder(recorder)

			markWalletBusy(t, n, signer)

			result := &coordinationResult{
				wallet:   signer.wallet,
				window:   window,
				proposal: proposal,
			}

			processCoordinationResult(context.Background(), n, result)

			rejected := recorder.counter(
				clientinfo.MetricWalletDispatcherRejectedTotal,
			)
			if rejected != 1 {
				t.Errorf(
					"expected the anchor at the exact cutover block to "+
						"dispatch, got %v rejected-dispatch increments",
					rejected,
				)
			}
		})
	}
}

// TestProcessCoordinationResult_BeforeCutoverAnchorDispatches verifies the
// other side of the cutover boundary: a wallet action whose canonical anchor
// is one block below the cutover block resolves to the legacy mode and reaches
// the dispatcher for every dispatchable proposal type.
func TestProcessCoordinationResult_BeforeCutoverAnchorDispatches(t *testing.T) {
	for action, proposal := range routingTestProposals() {
		t.Run(action.String(), func(t *testing.T) {
			n, signer, lc := setupNodeWithChain(t, 1*time.Millisecond)

			blockCounter, err := lc.BlockCounter()
			if err != nil {
				t.Fatal(err)
			}

			window := newCoordinationWindow(100)
			// The permit anchor is the window's end block; put the cutover one
			// block above it so the anchor sits at C-1 and pins legacy mode.
			n.participationGate = newTestGateWithCutover(
				t,
				blockCounter,
				window.endBlock()+1,
			)

			recorder := newDispatcherMetricsRecorder()
			n.walletDispatcher.setMetricsRecorder(recorder)

			walletKey := markWalletBusy(t, n, signer)

			result := &coordinationResult{
				wallet:   signer.wallet,
				window:   window,
				proposal: proposal,
			}

			processCoordinationResult(context.Background(), n, result)

			rejected := recorder.counter(
				clientinfo.MetricWalletDispatcherRejectedTotal,
			)
			if rejected != 1 {
				t.Errorf(
					"expected the pre-cutover legacy anchor to dispatch, "+
						"got %v rejected-dispatch increments",
					rejected,
				)
			}

			n.walletDispatcher.actionsMutex.Lock()
			_, ok := n.walletDispatcher.actions[walletKey]
			n.walletDispatcher.actionsMutex.Unlock()
			if !ok {
				t.Error("expected the busy sentinel to remain after dispatch")
			}
		})
	}
}

// setupNodeForClosureTests creates a node backed by a fast-block localChain
// (1 ms per block) so that WaitForBlockConfirmations (32 blocks) completes in
// ~32 ms instead of seconds.
func setupNodeForClosureTests(t *testing.T) (*node, *signer, *localChain) {
	t.Helper()

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	lc := Connect(1 * time.Millisecond)
	localProvider := local.Connect()

	signer := createMockSigner(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := lc.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	lc.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateLive,
	})

	n, err := newNode(
		groupParameters,
		lc,
		newLocalBitcoinChain(),
		localProvider,
		createMockKeyStorePersistence(t, signer),
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}

	return n, signer, lc
}

// newTestCutoverRoster builds a node-local cutover peer roster backed by the
// given chain's block counter and a no-op metrics sink, for wiring tests.
func newTestCutoverRoster(
	t *testing.T,
	ctx context.Context,
	lc *localChain,
) *participation.CutoverPeerRoster {
	t.Helper()

	blockCounter, err := lc.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	roster, err := participation.NewCutoverPeerRoster(
		ctx,
		blockCounter,
		1500,
		&clientinfo.NoOpPerformanceMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return roster
}

// TestNode_SetCutoverPeerRoster_PropagatesToExistingSigningExecutor verifies
// that installing the cutover peer roster reaches a signing executor that was
// already created before the roster was installed. This guards the
// initialization-ordering window in which a coordination round could create a
// signing executor before the roster is wired: without propagation such an
// executor would silently never record legacy-peer sightings.
func TestNode_SetCutoverPeerRoster_PropagatesToExistingSigningExecutor(t *testing.T) {
	n, signer, lc := setupNodeForClosureTests(t)

	// Create the signing executor BEFORE the roster is installed, simulating an
	// early coordination round that produced a signing executor.
	executor, ok, err := n.getSigningExecutor(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}
	if executor.cutoverPeerRoster != nil {
		t.Fatal("signing executor unexpectedly carries a roster before install")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	roster := newTestCutoverRoster(t, ctx, lc)
	defer roster.Close()

	n.setCutoverPeerRoster(roster)

	if executor.cutoverPeerRoster != roster {
		t.Error("pre-existing signing executor did not receive the roster")
	}
	if n.dkgExecutor.cutoverPeerRoster != roster {
		t.Error("DKG executor did not receive the roster")
	}
}

// TestNode_SetCutoverPeerRoster_ConcurrentInstall exercises concurrent roster
// installation and signing-executor creation under -race. Both paths take
// signingExecutorsMutex, so the field write and the executor cache read/write
// are serialized; regardless of ordering the resulting executor must carry the
// roster (created after install reads it from the node; created before install
// is reached by the propagation loop).
func TestNode_SetCutoverPeerRoster_ConcurrentInstall(t *testing.T) {
	n, signer, lc := setupNodeForClosureTests(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	roster := newTestCutoverRoster(t, ctx, lc)
	defer roster.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n.setCutoverPeerRoster(roster)
	}()
	go func() {
		defer wg.Done()
		_, _, _ = n.getSigningExecutor(signer.wallet.publicKey)
	}()
	wg.Wait()

	executor, ok, err := n.getSigningExecutor(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("node is supposed to control wallet signers")
	}
	if executor.cutoverPeerRoster != roster {
		t.Error(
			"signing executor did not receive the roster after concurrent install",
		)
	}
}

// TestArchiveClosedWallets_ArchivesClosedWallet verifies that a wallet whose
// on-chain state is StateClosed is removed from the node's registry.
func TestArchiveClosedWallets_ArchivesClosedWallet(t *testing.T) {
	n, signer, lc := setupNodeWithChain(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := lc.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	lc.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateClosed,
	})

	if err := n.archiveClosedWallets(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if keys := n.walletRegistry.getWalletsPublicKeys(); len(keys) != 0 {
		t.Errorf("expected empty registry after archiving, got %d wallets", len(keys))
	}
}

// TestArchiveClosedWallets_ArchivesTerminatedWallet verifies that a wallet in
// StateTerminated is also removed from the registry.
func TestArchiveClosedWallets_ArchivesTerminatedWallet(t *testing.T) {
	n, signer, lc := setupNodeWithChain(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := lc.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	lc.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateTerminated,
	})

	if err := n.archiveClosedWallets(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if keys := n.walletRegistry.getWalletsPublicKeys(); len(keys) != 0 {
		t.Errorf("expected empty registry after archiving terminated wallet, got %d wallets", len(keys))
	}
}

// TestArchiveClosedWallets_KeepsLiveWallet verifies that a live wallet is not
// removed from the registry.
func TestArchiveClosedWallets_KeepsLiveWallet(t *testing.T) {
	n, _, _ := setupNodeWithChain(t)

	if err := n.archiveClosedWallets(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if keys := n.walletRegistry.getWalletsPublicKeys(); len(keys) != 1 {
		t.Errorf("expected 1 wallet in registry, got %d", len(keys))
	}
}

// TestHandleWalletClosure_ArchivesWallet verifies the happy path: after
// WaitForBlockConfirmations, a closed wallet is removed from the registry.
func TestHandleWalletClosure_ArchivesWallet(t *testing.T) {
	n, signer, lc := setupNodeForClosureTests(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := lc.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Close the wallet before calling handleWalletClosure so that stateCheck
	// confirms closure immediately after the 32-block wait.
	lc.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateClosed,
	})

	if err := n.handleWalletClosure(walletID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if keys := n.walletRegistry.getWalletsPublicKeys(); len(keys) != 0 {
		t.Errorf("expected empty registry after closure handling, got %d wallets", len(keys))
	}
}

// TestHandleWalletClosure_SkipsUncontrolledWallet verifies that when the
// closed wallet is not in the node's registry the function returns nil without
// touching any other wallet.
func TestHandleWalletClosure_SkipsUncontrolledWallet(t *testing.T) {
	n, signer, lc := setupNodeForClosureTests(t)

	// Build a wallet that is NOT in the node's registry but IS on the chain.
	uncontrolled := uncontrolledWalletFor(signer)
	uncontrolledPKH := bitcoin.PublicKeyHash(uncontrolled.publicKey)
	uncontrolledID, err := lc.CalculateWalletID(uncontrolled.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	lc.setWallet(uncontrolledPKH, &WalletChainData{
		EcdsaWalletID: uncontrolledID,
		State:         StateClosed,
	})

	if err := n.handleWalletClosure(uncontrolledID); err != nil {
		t.Fatalf("unexpected error for uncontrolled wallet: %v", err)
	}

	// Signer's own wallet must be untouched.
	if keys := n.walletRegistry.getWalletsPublicKeys(); len(keys) != 1 {
		t.Errorf("expected signer wallet to remain in registry, got %d wallets", len(keys))
	}
}

// TestHandleWalletClosure_ReturnsErrorWhenNotConfirmed verifies that when the
// stateCheck finds the wallet still live (no reorg confirmed), an error is
// returned.
func TestHandleWalletClosure_ReturnsErrorWhenNotConfirmed(t *testing.T) {
	n, signer, lc := setupNodeForClosureTests(t)

	walletID, err := lc.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	// wallet is StateLive → IsWalletRegistered returns true → stateCheck = false
	if err := n.handleWalletClosure(walletID); err == nil {
		t.Fatal("expected error for unconfirmed closure, got nil")
	}
}

// setupNodeWithChain creates a fully-initialised node and returns the node,
// the signer, and the underlying *localChain so callers can manipulate chain
// state (e.g. close/terminate a wallet) after creation.
func setupNodeWithChain(
	t *testing.T,
	blockTime ...time.Duration,
) (*node, *signer, *localChain) {
	t.Helper()

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	lc := Connect(blockTime...)
	localProvider := local.Connect()

	signer := createMockSigner(t)

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)
	walletID, err := lc.CalculateWalletID(signer.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	lc.setWallet(walletPublicKeyHash, &WalletChainData{
		EcdsaWalletID: walletID,
		State:         StateLive,
	})

	n, err := newNode(
		groupParameters,
		lc,
		newLocalBitcoinChain(),
		localProvider,
		createMockKeyStorePersistence(t, signer),
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}

	return n, signer, lc
}

// setupNodeForHandlerTests is a convenience wrapper that discards the chain.
func setupNodeForHandlerTests(t *testing.T) (*node, *signer) {
	t.Helper()
	n, signer, _ := setupNodeWithChain(t)
	return n, signer
}

// dispatcherMetricsRecorder counts walletDispatcher counter increments so
// tests can positively observe that a dispatch was attempted.
type dispatcherMetricsRecorder struct {
	mu       sync.Mutex
	counters map[string]float64
}

func newDispatcherMetricsRecorder() *dispatcherMetricsRecorder {
	return &dispatcherMetricsRecorder{counters: make(map[string]float64)}
}

func (r *dispatcherMetricsRecorder) IncrementCounter(name string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[name] += value
}

func (r *dispatcherMetricsRecorder) SetGauge(string, float64) {}

func (r *dispatcherMetricsRecorder) RecordDuration(string, time.Duration) {}

func (r *dispatcherMetricsRecorder) counter(name string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counters[name]
}

// setupNodeForRoutingTests builds a node on a fast-block chain with a real
// participation gate whose cutover is already crossed, so that
// processCoordinationResult can wait for the coordination window's end block
// and acquire a security-v2 permit against it. The returned recorder counts
// walletDispatcher metrics and proves dispatch attempts.
func setupNodeForRoutingTests(
	t *testing.T,
) (*node, *signer, *dispatcherMetricsRecorder) {
	t.Helper()

	n, signer, lc := setupNodeWithChain(t, 1*time.Millisecond)

	blockCounter, err := lc.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	n.participationGate = newTestGate(t, blockCounter)

	recorder := newDispatcherMetricsRecorder()
	n.walletDispatcher.setMetricsRecorder(recorder)

	return n, signer, recorder
}

// markWalletBusy plants a busy sentinel for the signer's wallet in the
// dispatcher so a routed action is rejected with errWalletBusy before its
// execute() method runs; the rejection is observable through the dispatcher
// rejected-actions counter.
func markWalletBusy(t *testing.T, n *node, s *signer) string {
	t.Helper()

	walletKey := walletKeyFor(t, s)

	n.walletDispatcher.actionsMutex.Lock()
	defer n.walletDispatcher.actionsMutex.Unlock()
	n.walletDispatcher.actions[walletKey] = ActionNoop

	return walletKey
}

// uncontrolledWalletFor returns a wallet whose public key is NOT registered in
// the given signer's keystore -- constructed by doubling the signer's key.
func uncontrolledWalletFor(s *signer) wallet {
	pk := s.wallet.publicKey
	x, y := pk.Curve.Double(pk.X, pk.Y)
	return wallet{
		publicKey:             &ecdsa.PublicKey{Curve: pk.Curve, X: x, Y: y},
		signingGroupOperators: s.wallet.signingGroupOperators,
	}
}

// walletKeyFor returns the hex-encoded wallet key as stored in walletDispatcher.
func walletKeyFor(t *testing.T, s *signer) string {
	t.Helper()
	b, err := marshalPublicKey(s.wallet.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// dispatchedActionsCount returns the number of active actions in the
// walletDispatcher, holding the lock for the read.
func dispatchedActionsCount(n *node) int {
	n.walletDispatcher.actionsMutex.Lock()
	defer n.walletDispatcher.actionsMutex.Unlock()
	return len(n.walletDispatcher.actions)
}

// waitForDispatcherIdle polls until walletDispatcher has no active actions or
// the 2-second deadline is exceeded.
func waitForDispatcherIdle(t *testing.T, n *node) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for dispatchedActionsCount(n) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for walletDispatcher to become idle")
		}
		time.Sleep(time.Millisecond)
	}
}

// createMockSigner creates a mock signer instance that can be used for
// test cases that needs a placeholder signer. The produced signer cannot
// be used to test actual signing scenarios.
func createMockSigner(t *testing.T) *signer {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}

	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	signingGroupOperators := []chain.Address{
		"address-1",
		"address-2",
		"address-3",
		"address-3",
		"address-5",
	}

	return &signer{
		wallet: wallet{
			publicKey:             privateKeyShare.PublicKey(),
			signingGroupOperators: signingGroupOperators,
		},
		signingGroupMemberIndex: group.MemberIndex(1),
		privateKeyShare:         privateKeyShare,
	}
}

// createMockKeyStorePersistence creates a mock key store that can be used
// to create test node instances. The key store is populated with the given
// signers.
func createMockKeyStorePersistence(
	t *testing.T,
	signers ...*signer,
) *mockPersistenceHandle {
	walletToSigners := make(map[string][]*signer)
	for _, signer := range signers {
		keyBytes, err := marshalPublicKey(signer.wallet.publicKey)
		if err != nil {
			t.Fatal(err)
		}

		key := hex.EncodeToString(keyBytes)

		walletToSigners[key] = append(walletToSigners[key], signer)
	}

	descriptors := make([]persistence.DataDescriptor, 0)

	for key, signers := range walletToSigners {
		for i, signer := range signers {
			signerBytes, err := signer.Marshal()
			if err != nil {
				t.Fatal(err)
			}

			// Construct the descriptor in the same way as it happens in the
			// real world.
			descriptor := &mockDescriptor{
				name:      fmt.Sprintf("membership_%v", i+1),
				directory: key[2:], // trim the 04 prefix
				content:   signerBytes,
			}

			descriptors = append(descriptors, descriptor)
		}
	}

	return &mockPersistenceHandle{
		saved: descriptors,
	}
}

// newTestScheduler creates a scheduler with a permanently-locked latch so that
// checkProtocols stops all background workers within one tick (~1s). This
// prevents CPU-intensive pre-params generation from running during tests that
// do not exercise DKG.
func newTestScheduler(t *testing.T) *generator.Scheduler {
	t.Helper()
	sched := generator.StartScheduler()
	noGenLatch := generator.NewProtocolLatch()
	noGenLatch.Lock()
	sched.RegisterProtocol(noGenLatch)
	return sched
}
