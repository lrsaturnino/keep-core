package tbtc

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ipfs/go-log/v2"
	"github.com/keep-network/keep-common/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"

	"go.uber.org/zap"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/inactivity"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa/signing"
)

const (
	// signingAttemptsLimit determines the maximum number of signing attempts
	// that can be performed for the given message being subject of signing.
	//
	// The value of `5` should be enough to produce the signature even with
	// `2` malicious members in a signing group of `100` members. To produce
	// the signature, `51` members must be selected out of the honest `98`.
	// The probability of successful signing in that case is:
	// `P = (98 choose 51) / (100 choose 51) = ~0.24` which means we need
	// `5` attempts on the worst case.
	//
	// A greater limit does not necessarily make sense. Presence of more than
	// `2` malicious members in the signing group has a very small probability.
	// Moreover, the signature must be produced in the reasonable time.
	// That being said, the value `5` seems to be reasonable trade-off.
	signingAttemptsLimit = 5

	// walletClosureConfirmationBlocks determines the period used when waiting
	// for the wallet closure confirmation. This period ensures the wallet has
	// been definitely closed and the closing transaction will not be removed by
	// a chain reorganization.
	walletClosureConfirmationBlocks = 32
)

// TODO: Unit tests for `node.go`.

// node represents the current state of an ECDSA node.
type node struct {
	groupParameters *GroupParameters

	chain          Chain
	btcChain       bitcoin.Chain
	netProvider    net.Provider
	walletRegistry *walletRegistry

	// walletDispatcher ensures only one action is executed by a wallet at
	// a time. All possible activities of a created wallet must be represented
	// by appropriate actions dispatched through this component.
	walletDispatcher *walletDispatcher

	// protocolLatch makes sure no expensive number generator operations are
	// running when signing or generating a wallet key are executed. The
	// protocolLatch is used by dkgExecutor and signingExecutor.
	protocolLatch *generator.ProtocolLatch

	// dkgExecutor encapsulates the logic of distributed key generation.
	//
	// dkgExecutor MUST NOT be used outside this struct.
	dkgExecutor *dkgExecutor

	// heartbeatFailureCounter stores the counters of consecutive heartbeat
	// failures for each wallet.
	heartbeatFailureCounter *heartbeatFailureCounter

	inactivityClaimExecutorMutex sync.Mutex
	// inactivityClaimExecutors is the cache holding inactivity claim executors
	// for specific wallets. The cache key is the uncompressed public key
	// (with 04 prefix) of the wallet.
	// inactivityClaimExecutor encapsulates the logic of handling inactivity
	// claim signing and submitting.
	//
	// inactivityClaimExecutors MUST NOT be used outside this struct. Please use
	// wallet actions and walletDispatcher to execute an action on an existing
	// wallet.
	inactivityClaimExecutors map[string]*inactivityClaimExecutor

	signingExecutorsMutex sync.Mutex
	// signingExecutors is the cache holding signing executors for specific wallets.
	// The cache key is the uncompressed public key (with 04 prefix) of the wallet.
	// signingExecutor encapsulates the generic logic of signing messages.
	//
	// signingExecutors MUST NOT be used outside this struct. Please use
	// wallet actions and walletDispatcher to execute an action on an existing
	// wallet.
	signingExecutors map[string]*signingExecutor

	coordinationExecutorsMutex sync.Mutex
	// coordinationExecutors is the cache holding coordination executors for
	// specific wallets. The cache key is the uncompressed public key
	// (with 04 prefix) of the wallet. The coordinationExecutor encapsulates the
	// logic of the wallet coordination procedure.
	//
	// coordinationExecutors MUST NOT be used outside this struct.
	coordinationExecutors map[string]*coordinationExecutor

	// proposalGenerator is the implementation of the coordination proposal
	// generator used by the node.
	proposalGenerator CoordinationProposalGenerator

	// performanceMetrics is optional and used for recording performance metrics
	performanceMetrics interface {
		IncrementCounter(name string, value float64)
		SetGauge(name string, value float64)
		RecordDuration(name string, duration time.Duration)
	}

	// windowMetricsTracker tracks detailed metrics for individual coordination windows
	windowMetricsTracker *coordinationWindowMetrics

	// cutoverPeerRoster is the node-local, deduplicated record of post-cutover
	// legacy peer sightings. It is constructed unconditionally at process
	// startup beside the participation gate, including when client-info is
	// disabled, and is shared by the DKG and signing executors. It may be nil
	// in tests that do not exercise the cutover observability path.
	cutoverPeerRoster *participation.CutoverPeerRoster

	// participationGate issues the per-ceremony participation permits that pin
	// each ceremony's protocol mode from its canonical chain anchor. It is
	// constructed once at process startup beside the cutover peer roster and
	// shared with the beacon application. Every tBTC ceremony choke point —
	// DKG members, wallet coordination, wallet actions and their signings,
	// heartbeat and derived inactivity work — acquires a permit from it and
	// fails closed without one.
	participationGate participation.Gate
}

func walletPermitIdentity(
	workClass string,
	walletPublicKey *ecdsa.PublicKey,
	canonicalStartBlock uint64,
) participation.PermitIdentity {
	walletPublicKeyHash := bitcoin.PublicKeyHash(walletPublicKey)
	walletID := hex.EncodeToString(walletPublicKeyHash[:])

	return participation.PermitIdentity{
		WorkID: fmt.Sprintf(
			"%s-%d-%s",
			workClass,
			canonicalStartBlock,
			walletID,
		),
		PermitID: walletID,
	}
}

func newNode(
	groupParameters *GroupParameters,
	chain Chain,
	btcChain bitcoin.Chain,
	netProvider net.Provider,
	keyStorePersistance persistence.ProtectedHandle,
	workPersistence persistence.BasicHandle,
	scheduler *generator.Scheduler,
	proposalGenerator CoordinationProposalGenerator,
	config Config,
) (*node, error) {
	walletRegistry, err := newWalletRegistry(
		keyStorePersistance,
		chain.CalculateWalletID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create wallet registry: [%v]", err)
	}

	latch := generator.NewProtocolLatch()
	scheduler.RegisterProtocol(latch)

	node := &node{
		groupParameters:          groupParameters,
		chain:                    chain,
		btcChain:                 btcChain,
		netProvider:              netProvider,
		walletRegistry:           walletRegistry,
		walletDispatcher:         newWalletDispatcher(),
		protocolLatch:            latch,
		heartbeatFailureCounter:  newHeartbeatFailureCounter(),
		signingExecutors:         make(map[string]*signingExecutor),
		inactivityClaimExecutors: make(map[string]*inactivityClaimExecutor),
		coordinationExecutors:    make(map[string]*coordinationExecutor),
		proposalGenerator:        proposalGenerator,
	}

	// Archive any wallets that might have been closed or terminated while the
	// client was turned off.
	err = node.archiveClosedWallets()
	if err != nil {
		return nil, fmt.Errorf("cannot archive closed wallets: [%v]", err)
	}

	// Only the operator address is known at this point and can be pre-fetched.
	// The operator ID must be determined later as the operator may not be in
	// the sortition pool yet.
	operatorAddress, err := node.operatorAddress()
	if err != nil {
		return nil, fmt.Errorf("cannot get node's operator address: [%v]", err)
	}

	// TODO: This chicken and egg problem should be solved when
	// waitForBlockHeight becomes a part of BlockHeightWaiter interface.
	node.dkgExecutor = newDkgExecutor(
		node.groupParameters,
		node.operatorID,
		operatorAddress,
		chain,
		netProvider,
		walletRegistry,
		latch,
		config,
		workPersistence,
		scheduler,
		node.waitForBlockHeight,
	)

	return node, nil
}

// setPerformanceMetrics sets the performance metrics recorder for the node
// and wires it into components that support metrics.
func (n *node) setPerformanceMetrics(metrics interface {
	IncrementCounter(name string, value float64)
	SetGauge(name string, value float64)
	RecordDuration(name string, duration time.Duration)
}) {
	n.performanceMetrics = metrics

	// Initialize window metrics tracker with performance metrics
	// Keep metrics for the last 100 windows (approximately 25 hours at 900 blocks per window)
	if perfMetrics, ok := metrics.(clientinfo.PerformanceMetricsRecorder); ok {
		n.windowMetricsTracker = newCoordinationWindowMetrics(perfMetrics, 100)
	}

	if n.walletDispatcher != nil {
		n.walletDispatcher.setMetricsRecorder(metrics)
	}
	if n.dkgExecutor != nil {
		n.dkgExecutor.setMetricsRecorder(metrics)
	}

	// Wire redemption metrics to proposal generator if it supports it
	// This uses a type assertion to check if proposalGenerator is a *ProposalGenerator
	// from the tbtcpg package. We can't import tbtcpg here to avoid circular dependencies,
	// so we use an interface check instead.
	if pg, ok := n.proposalGenerator.(interface {
		SetRedemptionMetricsRecorder(recorder interface {
			SetGauge(name string, value float64)
		})
	}); ok {
		pg.SetRedemptionMetricsRecorder(metrics)
	}

	// Update metrics recorder for all cached coordination executors
	// This is important because executors may be created before metrics are set
	n.coordinationExecutorsMutex.Lock()
	for _, executor := range n.coordinationExecutors {
		executor.setMetricsRecorder(metrics)
	}
	n.coordinationExecutorsMutex.Unlock()
}

// setCutoverPeerRoster sets the node-local cutover peer roster and propagates it
// into the components that observe announcer session-ID mismatches. It is called
// once during initialization, before the coordination layer starts, so in
// practice no signing executor exists yet; the propagation loop is a defensive
// safeguard for any executor created by an early coordination round.
//
// The field write is guarded by signingExecutorsMutex because getSigningExecutor
// reads n.cutoverPeerRoster under the same lock when wiring a freshly created
// executor; without this the read/write pair would be an unsynchronized race.
func (n *node) setCutoverPeerRoster(roster *participation.CutoverPeerRoster) {
	n.signingExecutorsMutex.Lock()
	n.cutoverPeerRoster = roster
	for _, executor := range n.signingExecutors {
		executor.setCutoverPeerRoster(roster)
	}
	n.signingExecutorsMutex.Unlock()

	// The DKG executor is created once in newNode and never mutated
	// concurrently, so it is wired directly.
	if n.dkgExecutor != nil {
		n.dkgExecutor.setCutoverPeerRoster(roster)
	}
}

// GetCoordinationWindowsSummary returns a summary of coordination window metrics.
// Returns nil if the window metrics tracker is not initialized.
func (n *node) GetCoordinationWindowsSummary() *WindowMetricsSummary {
	if n.windowMetricsTracker == nil {
		return nil
	}
	summary := n.windowMetricsTracker.GetSummary()
	return &summary
}

// operatorAddress returns the node's operator address.
func (n *node) operatorAddress() (chain.Address, error) {
	_, operatorPublicKey, err := n.chain.OperatorKeyPair()
	if err != nil {
		return "", fmt.Errorf("failed to get operator public key: [%v]", err)
	}

	operatorAddress, err := n.chain.Signing().PublicKeyToAddress(operatorPublicKey)
	if err != nil {
		return "", fmt.Errorf(
			"failed to convert operator public key to address: [%v]",
			err,
		)
	}

	return operatorAddress, nil
}

// operatorAddress returns the node's operator ID.
func (n *node) operatorID() (chain.OperatorID, error) {
	operatorAddress, err := n.operatorAddress()
	if err != nil {
		return 0, fmt.Errorf("failed to get operator address: [%v]", err)
	}

	operatorID, err := n.chain.GetOperatorID(operatorAddress)
	if err != nil {
		return 0, fmt.Errorf("failed to get operator ID: [%v]", err)
	}

	return operatorID, nil
}

// joinDKGIfEligible takes a seed value and undergoes the process of the
// distributed key generation if this node's operator proves to be eligible for
// the group generated by that seed. This is an interactive on-chain process,
// and joinDKGIfEligible can block for an extended period of time while it
// completes the on-chain operation. The execution can be delayed by an
// arbitrary number of blocks using the delayBlocks argument. This allows
// confirming the state on-chain - e.g. wait for the required number of
// confirming blocks - before executing the off-chain action.
func (n *node) joinDKGIfEligible(
	seed *big.Int,
	startBlock uint64,
	delayBlocks uint64,
) {
	n.dkgExecutor.executeDkgIfEligible(seed, startBlock, delayBlocks)
}

// validateDKG performs the submitted DKG result validation process.
// If the result is not valid, this function submits an on-chain result
// challenge. If the result is valid and the given node was involved in the DKG,
// this function schedules an on-chain approve that is submitted once the
// challenge period elapses.
func (n *node) validateDKG(
	seed *big.Int,
	submissionBlock uint64,
	result *DKGChainResult,
	resultHash [32]byte,
) {
	n.dkgExecutor.executeDkgValidation(seed, submissionBlock, result, resultHash)
}

// getSigningExecutor gets the signing executor responsible for executing
// signing related to a specific wallet whose part is controlled by this node.
// The second boolean return value indicates whether the node controls at least
// one signer for the given wallet.
func (n *node) getSigningExecutor(
	walletPublicKey *ecdsa.PublicKey,
) (*signingExecutor, bool, error) {
	n.signingExecutorsMutex.Lock()
	defer n.signingExecutorsMutex.Unlock()

	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		return nil, false, fmt.Errorf("cannot marshal wallet public key: [%v]", err)
	}

	executorKey := hex.EncodeToString(walletPublicKeyBytes)

	if executor, exists := n.signingExecutors[executorKey]; exists {
		return executor, true, nil
	}

	executorLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
	)

	signers := n.walletRegistry.getSigners(walletPublicKey)
	if len(signers) == 0 {
		// This is not an error because the node simply does not control
		// the given wallet.
		return nil, false, nil
	}

	// All signers belong to one wallet. Take that wallet from the
	// first signer.
	wallet := signers[0].wallet

	channelName := fmt.Sprintf(
		"%s-%s",
		ProtocolName,
		hex.EncodeToString(walletPublicKeyBytes),
	)

	broadcastChannel, err := n.netProvider.BroadcastChannelFor(channelName)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get broadcast channel: [%v]", err)
	}

	signing.RegisterUnmarshallers(broadcastChannel)
	announcer.RegisterUnmarshaller(broadcastChannel)
	broadcastChannel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &signingDoneMessage{}
	})

	membershipValidator := group.NewMembershipValidator(
		executorLogger,
		wallet.signingGroupOperators,
		n.chain.Signing(),
	)

	err = broadcastChannel.SetFilter(membershipValidator.IsInGroup)
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not set filter for channel [%v]: [%v]",
			broadcastChannel.Name(),
			err,
		)
	}

	executorLogger.Infof(
		"signing executor created; controlling [%v] signers",
		len(signers),
	)

	blockCounter, err := n.chain.BlockCounter()
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not get block counter: [%v]",
			err,
		)
	}

	executor := newSigningExecutor(
		signers,
		broadcastChannel,
		membershipValidator,
		n.groupParameters,
		n.protocolLatch,
		blockCounter.CurrentBlock,
		n.waitForBlockHeight,
		signingAttemptsLimit,
	)

	// Wire metrics recorder if available
	if n.performanceMetrics != nil {
		executor.setMetricsRecorder(n.performanceMetrics)
	}

	// Wire the node-local cutover peer roster so the signing announcer can
	// record post-cutover legacy peer sightings.
	if n.cutoverPeerRoster != nil {
		executor.setCutoverPeerRoster(n.cutoverPeerRoster)
	}

	n.signingExecutors[executorKey] = executor

	return executor, true, nil
}

// getCoordinationExecutor gets the coordination executor responsible for
// executing coordination related to a specific wallet whose part is controlled
// by this node. The second boolean return value indicates whether the node
// controls at least one signer for the given wallet.
func (n *node) getCoordinationExecutor(
	walletPublicKey *ecdsa.PublicKey,
) (*coordinationExecutor, bool, error) {
	n.coordinationExecutorsMutex.Lock()
	defer n.coordinationExecutorsMutex.Unlock()

	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		return nil, false, fmt.Errorf("cannot marshal wallet public key: [%v]", err)
	}

	executorKey := hex.EncodeToString(walletPublicKeyBytes)

	if executor, exists := n.coordinationExecutors[executorKey]; exists {
		// Ensure metrics recorder is set if metrics are available
		// (executor may have been created before metrics were initialized)
		if n.performanceMetrics != nil {
			executor.setMetricsRecorder(n.performanceMetrics)
		}
		return executor, true, nil
	}

	executorLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
	)

	signers := n.walletRegistry.getSigners(walletPublicKey)
	if len(signers) == 0 {
		// This is not an error because the node simply does not control
		// the given wallet.
		return nil, false, nil
	}

	// All signers belong to one wallet. Take that wallet from the
	// first signer.
	wallet := signers[0].wallet

	channelName := fmt.Sprintf(
		"%s-%s-coordination",
		ProtocolName,
		hex.EncodeToString(walletPublicKeyBytes),
	)

	broadcastChannel, err := n.netProvider.BroadcastChannelFor(channelName)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get broadcast channel: [%v]", err)
	}

	broadcastChannel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &coordinationMessage{}
	})

	membershipValidator := group.NewMembershipValidator(
		executorLogger,
		wallet.signingGroupOperators,
		n.chain.Signing(),
	)

	err = broadcastChannel.SetFilter(membershipValidator.IsInGroup)
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not set filter for channel [%v]: [%v]",
			broadcastChannel.Name(),
			err,
		)
	}

	// The coordination executor does not need access to signers' key material.
	// It is enough to pass only their member indexes.
	membersIndexes := make([]group.MemberIndex, len(signers))
	for i, s := range signers {
		membersIndexes[i] = s.signingGroupMemberIndex
	}

	operatorAddress, err := n.operatorAddress()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get operator address: [%v]", err)
	}

	executor := newCoordinationExecutor(
		n.chain,
		wallet,
		membersIndexes,
		operatorAddress,
		n.proposalGenerator,
		broadcastChannel,
		membershipValidator,
		n.protocolLatch,
		n.waitForBlockHeight,
	)

	// Wire metrics recorder if available
	if n.performanceMetrics != nil {
		executor.setMetricsRecorder(n.performanceMetrics)
	}

	n.coordinationExecutors[executorKey] = executor

	executorLogger.Infof(
		"coordination executor created; controlling [%v] signers",
		len(signers),
	)

	return executor, true, nil
}

// getInactivityClaimExecutor gets the inactivity claim executor responsible for
// executing inactivity claim signing and submission related to a specific
// wallet whose part is controlled by this node. The second boolean return value
// indicates whether the node controls at least one signer for the given wallet.
func (n *node) getInactivityClaimExecutor(
	walletPublicKey *ecdsa.PublicKey,
) (*inactivityClaimExecutor, bool, error) {
	n.inactivityClaimExecutorMutex.Lock()
	defer n.inactivityClaimExecutorMutex.Unlock()

	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		return nil, false, fmt.Errorf("cannot marshal wallet public key: [%v]", err)
	}

	executorKey := hex.EncodeToString(walletPublicKeyBytes)

	if executor, exists := n.inactivityClaimExecutors[executorKey]; exists {
		return executor, true, nil
	}

	executorLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
	)

	signers := n.walletRegistry.getSigners(walletPublicKey)
	if len(signers) == 0 {
		// This is not an error because the node simply does not control
		// the given wallet.
		return nil, false, nil
	}

	// All signers belong to one wallet. Take that wallet from the first signer.
	wallet := signers[0].wallet

	channelName := fmt.Sprintf(
		"%s-%s-inactivity",
		ProtocolName,
		hex.EncodeToString(walletPublicKeyBytes),
	)

	broadcastChannel, err := n.netProvider.BroadcastChannelFor(channelName)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get broadcast channel: [%v]", err)
	}

	inactivity.RegisterUnmarshallers(broadcastChannel)

	membershipValidator := group.NewMembershipValidator(
		executorLogger,
		wallet.signingGroupOperators,
		n.chain.Signing(),
	)

	err = broadcastChannel.SetFilter(membershipValidator.IsInGroup)
	if err != nil {
		return nil, false, fmt.Errorf(
			"could not set filter for channel [%v]: [%v]",
			broadcastChannel.Name(),
			err,
		)
	}

	executorLogger.Infof(
		"inactivity executor created; controlling [%v] signers",
		len(signers),
	)

	executor := newInactivityClaimExecutor(
		n.chain,
		signers,
		broadcastChannel,
		membershipValidator,
		n.groupParameters,
		n.protocolLatch,
		n.waitForBlockHeight,
	)

	n.inactivityClaimExecutors[executorKey] = executor

	return executor, true, nil
}

// handleHeartbeatProposal handles an incoming heartbeat proposal by
// orchestrating and dispatching an appropriate wallet action.
func (n *node) handleHeartbeatProposal(
	wallet wallet,
	proposal *HeartbeatProposal,
	startBlock uint64,
	expiryBlock uint64,
	permit participation.Permit,
) {
	// Until the action is dispatched the permit is owned here and every
	// early return must release it; after a successful dispatch the action
	// owns it for its whole execution.
	permitHandedOff := false
	defer func() {
		if !permitHandedOff {
			permit.Close()
		}
	}()

	walletPublicKeyBytes, err := marshalPublicKey(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot marshal wallet public key: [%v]", err)
		return
	}

	signingExecutor, ok, err := n.getSigningExecutor(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot get signing executor: [%v]", err)
		return
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry using their
	// public key hash. However, we are doing it just in case. The API
	// contract of getSigningExecutor may change one day.
	if !ok {
		logger.Infof(
			"node does not control signers of wallet [0x%x]; "+
				"ignoring the received heartbeat request",
			walletPublicKeyBytes,
		)
		return
	}

	inactivityClaimExecutor, ok, err := n.getInactivityClaimExecutor(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot get inactivity claim executor: [%v]", err)
		return
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry using their
	// public key hash. However, we are doing it just in case. The API
	// contract of getInactivityClaimExecutor may change one day.
	if !ok {
		logger.Infof(
			"node does not control signers of wallet [0x%x]; "+
				"ignoring the received heartbeat request",
			walletPublicKeyBytes,
		)
		return
	}

	logger.Infof(
		"starting orchestration of the heartbeat action for wallet [0x%x]; "+
			"20-byte public key hash of that wallet is [0x%x]",
		walletPublicKeyBytes,
		bitcoin.PublicKeyHash(wallet.publicKey),
	)

	walletActionLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
		zap.String("action", ActionHeartbeat.String()),
		zap.Uint64("startBlock", startBlock),
		zap.Uint64("expiryBlock", expiryBlock),
	)
	walletActionLogger.Infof("dispatching wallet action")

	action := newHeartbeatAction(
		walletActionLogger,
		n.chain,
		wallet,
		signingExecutor,
		proposal,
		n.heartbeatFailureCounter,
		inactivityClaimExecutor,
		startBlock,
		expiryBlock,
		n.waitForBlockHeight,
		permit,
	)

	err = n.walletDispatcher.dispatch(action)
	if err != nil {
		walletActionLogger.Errorf("cannot dispatch wallet action: [%v]", err)
		return
	}
	permitHandedOff = true

	walletActionLogger.Infof("wallet action dispatched successfully")
}

// handleDepositSweepProposal handles an incoming deposit sweep proposal by
// orchestrating and dispatching an appropriate wallet action.
func (n *node) handleDepositSweepProposal(
	wallet wallet,
	proposal *DepositSweepProposal,
	startBlock uint64,
	expiryBlock uint64,
	permit participation.Permit,
) {
	// Until the action is dispatched the permit is owned here and every
	// early return must release it; after a successful dispatch the action
	// owns it for its whole execution.
	permitHandedOff := false
	defer func() {
		if !permitHandedOff {
			permit.Close()
		}
	}()

	walletPublicKeyBytes, err := marshalPublicKey(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot marshal wallet public key: [%v]", err)
		return
	}

	signingExecutor, ok, err := n.getSigningExecutor(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot get signing executor: [%v]", err)
		return
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry using their
	// public key hash. However, we are doing it just in case. The API
	// contract of getSigningExecutor may change one day.
	if !ok {
		logger.Infof(
			"node does not control signers of wallet [0x%x]; "+
				"ignoring the received deposit sweep proposal",
			walletPublicKeyBytes,
		)
		return
	}

	logger.Infof(
		"starting orchestration of the deposit sweep action for wallet [0x%x]; "+
			"20-byte public key hash of that wallet is [0x%x]",
		walletPublicKeyBytes,
		bitcoin.PublicKeyHash(wallet.publicKey),
	)

	walletActionLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
		zap.String("action", ActionDepositSweep.String()),
		zap.Uint64("startBlock", startBlock),
		zap.Uint64("expiryBlock", expiryBlock),
	)
	walletActionLogger.Infof("dispatching wallet action")

	action := newDepositSweepAction(
		walletActionLogger,
		n.chain,
		n.btcChain,
		wallet,
		signingExecutor,
		proposal,
		startBlock,
		expiryBlock,
		n.waitForBlockHeight,
		permit,
	)

	// Wire metrics recorder if available
	if n.performanceMetrics != nil {
		action.setMetricsRecorder(n.performanceMetrics)
	}

	err = n.walletDispatcher.dispatch(action)
	if err != nil {
		walletActionLogger.Errorf("cannot dispatch wallet action: [%v]", err)
		return
	}
	permitHandedOff = true

	walletActionLogger.Infof("wallet action dispatched successfully")
}

// handleRedemptionProposal handles an incoming redemption proposal by
// orchestrating and dispatching an appropriate wallet action.
func (n *node) handleRedemptionProposal(
	wallet wallet,
	proposal *RedemptionProposal,
	startBlock uint64,
	expiryBlock uint64,
	permit participation.Permit,
) {
	// Until the action is dispatched the permit is owned here and every
	// early return must release it; after a successful dispatch the action
	// owns it for its whole execution.
	permitHandedOff := false
	defer func() {
		if !permitHandedOff {
			permit.Close()
		}
	}()

	walletPublicKeyBytes, err := marshalPublicKey(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot marshal wallet public key: [%v]", err)
		return
	}

	signingExecutor, ok, err := n.getSigningExecutor(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot get signing executor: [%v]", err)
		return
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry using their
	// public key hash. However, we are doing it just in case. The API
	// contract of getSigningExecutor may change one day.
	if !ok {
		logger.Infof(
			"node does not control signers of wallet [0x%x]; "+
				"ignoring the received redemption proposal",
			walletPublicKeyBytes,
		)
		return
	}

	logger.Infof(
		"starting orchestration of the redemption action for wallet [0x%x]; "+
			"20-byte public key hash of that wallet is [0x%x]",
		walletPublicKeyBytes,
		bitcoin.PublicKeyHash(wallet.publicKey),
	)

	walletActionLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
		zap.String("action", ActionRedemption.String()),
		zap.Uint64("startBlock", startBlock),
		zap.Uint64("expiryBlock", expiryBlock),
	)
	walletActionLogger.Infof("dispatching wallet action")

	action := newRedemptionAction(
		walletActionLogger,
		n.chain,
		n.btcChain,
		wallet,
		signingExecutor,
		proposal,
		startBlock,
		expiryBlock,
		n.waitForBlockHeight,
		permit,
	)

	// Wire metrics recorder if available
	if n.performanceMetrics != nil {
		action.setMetricsRecorder(n.performanceMetrics)
	}

	err = n.walletDispatcher.dispatch(action)
	if err != nil {
		walletActionLogger.Errorf("cannot dispatch wallet action: [%v]", err)
		return
	}
	permitHandedOff = true

	walletActionLogger.Infof("wallet action dispatched successfully")
}

// handleMovingFundsProposal handles an incoming moving funds proposal by
// orchestrating and dispatching an appropriate wallet action.
func (n *node) handleMovingFundsProposal(
	wallet wallet,
	proposal *MovingFundsProposal,
	startBlock uint64,
	expiryBlock uint64,
	permit participation.Permit,
) {
	// Until the action is dispatched the permit is owned here and every
	// early return must release it; after a successful dispatch the action
	// owns it for its whole execution.
	permitHandedOff := false
	defer func() {
		if !permitHandedOff {
			permit.Close()
		}
	}()

	walletPublicKeyBytes, err := marshalPublicKey(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot marshal wallet public key: [%v]", err)
		return
	}

	signingExecutor, ok, err := n.getSigningExecutor(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot get signing executor: [%v]", err)
		return
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry using their
	// public key hash. However, we are doing it just in case. The API
	// contract of getSigningExecutor may change one day.
	if !ok {
		logger.Infof(
			"node does not control signers of wallet PKH [0x%x]; "+
				"ignoring the received moving funds proposal",
			walletPublicKeyBytes,
		)
		return
	}

	logger.Infof(
		"starting orchestration of the moving funds action for wallet [0x%x]; "+
			"20-byte public key hash of that wallet is [0x%x]",
		walletPublicKeyBytes,
		bitcoin.PublicKeyHash(wallet.publicKey),
	)

	walletActionLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
		zap.String("action", ActionMovingFunds.String()),
		zap.Uint64("startBlock", startBlock),
		zap.Uint64("expiryBlock", expiryBlock),
	)
	walletActionLogger.Infof("dispatching wallet action")

	action := newMovingFundsAction(
		walletActionLogger,
		n.chain,
		n.btcChain,
		wallet,
		signingExecutor,
		proposal,
		startBlock,
		expiryBlock,
		n.waitForBlockHeight,
		permit,
	)

	err = n.walletDispatcher.dispatch(action)
	if err != nil {
		walletActionLogger.Errorf("cannot dispatch wallet action: [%v]", err)
		return
	}
	permitHandedOff = true

	walletActionLogger.Infof("wallet action dispatched successfully")
}

// handleMovedFundsSweepProposal handles an incoming moved funds sweep proposal
// by orchestrating and dispatching an appropriate wallet action.
func (n *node) handleMovedFundsSweepProposal(
	wallet wallet,
	proposal *MovedFundsSweepProposal,
	startBlock uint64,
	expiryBlock uint64,
	permit participation.Permit,
) {
	// Until the action is dispatched the permit is owned here and every
	// early return must release it; after a successful dispatch the action
	// owns it for its whole execution.
	permitHandedOff := false
	defer func() {
		if !permitHandedOff {
			permit.Close()
		}
	}()

	walletPublicKeyBytes, err := marshalPublicKey(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot marshal wallet public key: [%v]", err)
		return
	}

	signingExecutor, ok, err := n.getSigningExecutor(wallet.publicKey)
	if err != nil {
		logger.Errorf("cannot get signing executor: [%v]", err)
		return
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry using their
	// public key hash. However, we are doing it just in case. The API
	// contract of getSigningExecutor may change one day.
	if !ok {
		logger.Infof(
			"node does not control signers of wallet PKH [0x%x]; "+
				"ignoring the received moved funds sweep proposal",
			walletPublicKeyBytes,
		)
		return
	}

	logger.Infof(
		"starting orchestration of the moved funds sweep action for wallet "+
			"[0x%x]; 20-byte public key hash of that wallet is [0x%x]",
		walletPublicKeyBytes,
		bitcoin.PublicKeyHash(wallet.publicKey),
	)

	walletActionLogger := logger.With(
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
		zap.String("action", ActionMovedFundsSweep.String()),
		zap.Uint64("startBlock", startBlock),
		zap.Uint64("expiryBlock", expiryBlock),
	)
	walletActionLogger.Infof("dispatching wallet action")

	action := newMovedFundsSweepAction(
		walletActionLogger,
		n.chain,
		n.btcChain,
		wallet,
		signingExecutor,
		proposal,
		startBlock,
		expiryBlock,
		n.waitForBlockHeight,
		permit,
	)

	err = n.walletDispatcher.dispatch(action)
	if err != nil {
		walletActionLogger.Errorf("cannot dispatch wallet action: [%v]", err)
		return
	}
	permitHandedOff = true

	walletActionLogger.Infof("wallet action dispatched successfully")
}

// coordinationLayerSettings represents settings for the coordination layer.
type coordinationLayerSettings struct {
	// executeCoordinationProcedureFn is a function executing the coordination
	// procedure for the given wallet and coordination window.
	executeCoordinationProcedureFn func(
		node *node,
		window *coordinationWindow,
		walletPublicKey *ecdsa.PublicKey,
	) (*coordinationResult, bool)

	// processCoordinationResultFn is a function processing the given
	// coordination result. The context bounds the processing lifetime and
	// is done when the coordination layer shuts down.
	processCoordinationResultFn func(
		ctx context.Context,
		node *node,
		result *coordinationResult,
	)
}

// runCoordinationLayer starts the coordination layer of the node. It is
// responsible for detecting new coordination windows, running coordination
// procedures for all wallets controlled by the node, and processing
// coordination results.
func (n *node) runCoordinationLayer(
	ctx context.Context,
	settings ...*coordinationLayerSettings,
) error {
	// Resolve settings for the coordination layer.
	var cls *coordinationLayerSettings
	switch len(settings) {
	case 1:
		cls = settings[0]
	default:
		cls = &coordinationLayerSettings{
			executeCoordinationProcedureFn: executeCoordinationProcedure,
			processCoordinationResultFn:    processCoordinationResult,
		}
	}

	blockCounter, err := n.chain.BlockCounter()
	if err != nil {
		return fmt.Errorf("cannot get block counter: [%w]", err)
	}

	coordinationResultChan := make(chan *coordinationResult)

	// Track the previous window to record its end when a new one starts
	// Use a mutex to safely access from multiple goroutines
	var previousWindowMu sync.Mutex
	var previousWindow *coordinationWindow

	// Prepare a callback function that will be called every time a new
	// coordination window is detected.
	onWindowFn := func(window *coordinationWindow) {
		previousWindowMu.Lock()
		// Record end of previous window if it exists
		if previousWindow != nil && n.windowMetricsTracker != nil {
			n.windowMetricsTracker.recordWindowEnd(previousWindow)
		}
		previousWindowMu.Unlock()

		// Track coordination window detection
		if n.performanceMetrics != nil {
			n.performanceMetrics.IncrementCounter(clientinfo.MetricCoordinationWindowsDetectedTotal, 1)
		}

		// Record window start in detailed metrics tracker
		if n.windowMetricsTracker != nil {
			n.windowMetricsTracker.recordWindowStart(window)
		}

		previousWindowMu.Lock()
		previousWindow = window
		previousWindowMu.Unlock()

		// Fetch all wallets controlled by the node. It is important to
		// get the wallets every time the window is triggered as the
		// node may have started controlling a new wallet in the meantime.
		walletsPublicKeys := n.walletRegistry.getWalletsPublicKeys()

		for _, currentWalletPublicKey := range walletsPublicKeys {
			// Run an independent coordination procedure for the given wallet
			// in a separate goroutine. The coordination result will be sent
			// to the coordination result channel.
			go func(walletPublicKey *ecdsa.PublicKey) {
				result, ok := cls.executeCoordinationProcedureFn(
					n,
					window,
					walletPublicKey,
				)
				if ok {
					coordinationResultChan <- result
				}
			}(currentWalletPublicKey)
		}
	}

	// Start the coordination windows watcher.
	go watchCoordinationWindows(
		ctx,
		blockCounter.WatchBlocks,
		onWindowFn,
	)

	// Start the coordination result processor.
	go func() {
		for {
			select {
			case result := <-coordinationResultChan:
				go cls.processCoordinationResultFn(ctx, n, result)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start a cleanup goroutine to record the end time of the last window on shutdown
	go func() {
		<-ctx.Done()
		// Record end time for the active window if it exists and hasn't been ended yet
		previousWindowMu.Lock()
		if previousWindow != nil && n.windowMetricsTracker != nil {
			n.windowMetricsTracker.recordWindowEnd(previousWindow)
		}
		previousWindowMu.Unlock()
	}()

	return nil
}

// executeCoordinationProcedure executes the coordination procedure for the
// given wallet and coordination window.
func executeCoordinationProcedure(
	node *node,
	window *coordinationWindow,
	walletPublicKey *ecdsa.PublicKey,
) (*coordinationResult, bool) {
	walletPublicKeyBytes, err := marshalPublicKey(walletPublicKey)
	if err != nil {
		logger.Errorf("cannot marshal wallet public key: [%v]", err)
		return nil, false
	}

	procedureLogger := logger.With(
		zap.Uint64("coordinationBlock", window.coordinationBlock),
		zap.String("wallet", fmt.Sprintf("0x%x", walletPublicKeyBytes)),
	)

	procedureLogger.Infof("starting coordination procedure")

	executor, ok, err := node.getCoordinationExecutor(walletPublicKey)
	if err != nil {
		procedureLogger.Errorf("cannot get coordination executor: [%v]", err)
		return nil, false
	}
	// This check is actually redundant. We know the node controls some
	// wallet signers as we just got the wallet from the registry.
	// However, we are doing it just in case. The API contract of
	// getWalletsPublicKeys and/or getCoordinationExecutor may change one day.
	if !ok {
		procedureLogger.Infof("node does not control signers of this wallet")
		return nil, false
	}

	if node.participationGate == nil {
		// Without the gate no permit can track the procedure for clock
		// failure and quiescence. Fail closed.
		procedureLogger.Errorf(
			"no participation gate; refusing the coordination procedure",
		)
		return nil, false
	}

	// One coordination permit tracks the procedure for clock failure and
	// quiescence, anchored at the window's coordination block. It ends with
	// the procedure and does not authorize or select the later wallet
	// action's cryptographic mode: the coordination wire format is shared by
	// both releases, so the permit's mode is telemetry here and the procedure
	// runs in either mode. A refusal is a gate decision, not an ordinary
	// coordination failure.
	permit, err := node.participationGate.Begin(
		participation.TBTCWalletCoordination,
		window.coordinationBlock,
		walletPermitIdentity(
			"wallet-coordination",
			walletPublicKey,
			window.coordinationBlock,
		),
	)
	if err != nil {
		procedureLogger.Warnf(
			"coordination procedure refused by the participation gate: [%v]",
			err,
		)
		return nil, false
	}
	// agreedResult holds the coordination procedure's durable result once the
	// wallet agrees on one. The deferred recorder below reads its final value.
	var agreedResult *coordinationResult

	// The terminal outcome is registered after the release so it runs first and
	// reaches the permit while it is still open.
	defer permit.Close()
	defer func() {
		recordCoordinationTerminalOutcome(
			procedureLogger,
			permit,
			walletPublicKeyBytes,
			agreedResult,
		)
	}()

	startTime := time.Now()
	result, err := executor.coordinate(permit.Context(), window)
	duration := time.Since(startTime)

	if err != nil {
		// A gate-canceled permit — clock failure, forced quiescence — ended
		// the procedure; that is a release-gate decision, not an ordinary
		// coordination failure.
		gateAborted := participation.IsGateRefusal(context.Cause(permit.Context()))
		if gateAborted {
			procedureLogger.Warnf(
				"coordination procedure canceled by the participation "+
					"gate: [%v]",
				err,
			)
		} else {
			procedureLogger.Errorf("coordination procedure failed: [%v]", err)
		}
		// Metrics are already recorded in executor.coordinate() for failures

		recordCoordinationOutcome(
			node,
			window,
			walletPublicKey,
			result,
			duration,
			err,
			gateAborted,
		)
		return nil, false
	}

	agreedResult = result

	procedureLogger.Infof(
		"coordination procedure finished successfully with result [%s]",
		result,
	)

	// Metrics are already recorded in executor.coordinate() for successful executions

	recordCoordinationOutcome(
		node,
		window,
		walletPublicKey,
		result,
		duration,
		nil,
		false,
	)

	return result, true
}

// recordCoordinationTerminalOutcome reports the coordination ceremony's
// node-owned final disposition on its participation permit. The procedure's
// durable result is the agreed proposal that dispatches the wallet action; the
// action itself runs under its own permit and reports its own outcome. A
// procedure that never agreed on a result — including one the release gate
// canceled — left nothing behind and is recorded as exhausted.
//
// The evidence binds the proposal's full serialized payload, not just its
// action type: a wallet can agree on two different deposit sweeps or two
// different redemptions in the same window across a restart, and an identity
// that only named the type would report both as the same durable result.
func recordCoordinationTerminalOutcome(
	procedureLogger log.StandardLogger,
	permit participation.Permit,
	walletPublicKeyBytes []byte,
	result *coordinationResult,
) {
	if result == nil {
		recordPermitNoThreshold(procedureLogger, permit)
		return
	}

	// A proposal the node cannot serialize has no faithful identity, and the
	// procedure did dispatch a wallet action, so neither a weaker reference nor
	// an exhausted record would be honest. Leaving the permit without a
	// terminal outcome closes it as unresolved, which blocks the offline
	// barrier until an operator reconciles the window by hand.
	proposalBytes, err := result.proposal.Marshal()
	if err != nil {
		procedureLogger.Errorf(
			"could not derive the coordination result identity for the "+
				"node-authored terminal outcome: [%v]",
			err,
		)
		return
	}

	coordinationBlock := make([]byte, 8)
	binary.BigEndian.PutUint64(coordinationBlock, result.window.coordinationBlock)

	recordPermitTerminalOutcome(
		procedureLogger,
		permit,
		participation.TerminalOutcomeCompleted,
		participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceProtocolResult,
			Reference: participation.TerminalResultReference(
				"tbtc_wallet_coordination_result",
				walletPublicKeyBytes,
				coordinationBlock,
				[]byte(result.leader),
				[]byte(result.proposal.ActionType().String()),
				proposalBytes,
			),
		},
	)
}

// recordCoordinationOutcome records one wallet's coordination outcome in the
// window metrics tracker. A gate-aborted procedure is deliberately not
// recorded at all: the release gate canceling a procedure is not a
// coordination failure of the wallet or the window, so it must not
// contaminate the window's coordinated/failed accounting that operators read
// as ordinary protocol health.
func recordCoordinationOutcome(
	node *node,
	window *coordinationWindow,
	walletPublicKey *ecdsa.PublicKey,
	result *coordinationResult,
	duration time.Duration,
	coordinationErr error,
	gateAborted bool,
) {
	if node.windowMetricsTracker == nil || gateAborted {
		return
	}

	walletPublicKeyHash := bitcoin.PublicKeyHash(walletPublicKey)

	if coordinationErr != nil {
		// Extract leader and faults from partial result if available
		// (e.g., when follower routine fails, we know who the leader was)
		leader := chain.Address("")
		var faults []*coordinationFault
		if result != nil {
			leader = result.leader
			faults = result.faults
		}
		node.windowMetricsTracker.recordWalletCoordination(
			window,
			walletPublicKeyHash,
			leader,
			"",
			false,
			duration,
			faults,
			coordinationErr, // capture the error message
		)
		return
	}

	actionType := ""
	if result.proposal != nil {
		actionType = result.proposal.ActionType().String()
	}
	node.windowMetricsTracker.recordWalletCoordination(
		window,
		walletPublicKeyHash,
		result.leader,
		actionType,
		true,
		duration,
		result.faults,
		nil, // no error on success
	)
}

// processCoordinationResult processes the given coordination result. The
// context bounds the pre-dispatch wait for the action's start block and is
// done when the coordination layer shuts down.
func processCoordinationResult(
	ctx context.Context,
	node *node,
	result *coordinationResult,
) {
	logger.Infof("processing coordination result [%s]", result)

	// TODO: In the future, create coordination faults cache and
	//       record faults from the processed results there.

	proposedAction := result.proposal.ActionType()

	if proposedAction == ActionNoop {
		// No-op proposal cannot be processed so return early to avoid
		// panicking on the ValidityBlocks call.
		return
	}

	startBlock := result.window.endBlock()
	expiryBlock := startBlock + result.proposal.ValidityBlocks()

	// Coordination normally concludes during the window's active phase, so
	// at this point the chain has not reached the window's end block that
	// anchors the action. The gate accepts only anchors at or below the
	// current height, hence the permit is acquired once the chain reaches
	// the anchor; the anchor itself stays the same for the whole action,
	// including all its retries.
	if err := node.waitForBlockHeight(ctx, startBlock); err != nil {
		logger.Errorf(
			"failed to wait for the [%s] wallet action start block [%v]: [%v]",
			proposedAction,
			startBlock,
			err,
		)
		return
	}
	if ctx.Err() != nil {
		// waitForBlockHeight returns nil when the context ends before the
		// height is reached; the coordination layer is shutting down, so
		// the action is dropped without touching the gate.
		return
	}

	// One action permit, acquired before the handler and the dispatcher are
	// set up and anchored at the proposal-processing start block. Every
	// signing and terminal commit of the dispatched action derives from it;
	// the heartbeat ceremony additionally fences its derived inactivity work
	// through it. The handlers hand the permit to the action, which owns it
	// until its execution ends.
	permit := node.beginWalletActionPermit(
		proposedAction,
		startBlock,
		result.wallet.publicKey,
	)
	if permit == nil {
		return
	}

	switch proposedAction {
	case ActionHeartbeat:
		if proposal, ok := result.proposal.(*HeartbeatProposal); ok {
			node.handleHeartbeatProposal(
				result.wallet,
				proposal,
				startBlock,
				expiryBlock,
				permit,
			)
			return
		}
	case ActionDepositSweep:
		if proposal, ok := result.proposal.(*DepositSweepProposal); ok {
			node.handleDepositSweepProposal(
				result.wallet,
				proposal,
				startBlock,
				expiryBlock,
				permit,
			)
			return
		}
	case ActionRedemption:
		if proposal, ok := result.proposal.(*RedemptionProposal); ok {
			node.handleRedemptionProposal(
				result.wallet,
				proposal,
				startBlock,
				expiryBlock,
				permit,
			)
			return
		}
	case ActionMovingFunds:
		if proposal, ok := result.proposal.(*MovingFundsProposal); ok {
			node.handleMovingFundsProposal(
				result.wallet,
				proposal,
				startBlock,
				expiryBlock,
				permit,
			)
			return
		}
	case ActionMovedFundsSweep:
		if proposal, ok := result.proposal.(*MovedFundsSweepProposal); ok {
			node.handleMovedFundsSweepProposal(
				result.wallet,
				proposal,
				startBlock,
				expiryBlock,
				permit,
			)
			return
		}
	default:
		logger.Errorf("no handler for coordination result [%s]", result)
	}

	// A mismatched proposal type or an unknown action never reached a
	// handler, so the permit is released here.
	permit.Close()
}

// beginWalletActionPermit acquires the participation permit for a wallet
// action about to be orchestrated. It fails closed: without a gate or on a
// gate refusal, no permit is returned and the action must not be dispatched.
func (n *node) beginWalletActionPermit(
	proposedAction WalletActionType,
	startBlock uint64,
	walletPublicKeys ...*ecdsa.PublicKey,
) participation.Permit {
	if n.participationGate == nil {
		logger.Errorf(
			"no participation gate; refusing the [%s] wallet action",
			proposedAction,
		)
		return nil
	}

	// The heartbeat is its own ceremony class because its penalty semantics
	// differ; every other wallet action is a signing ceremony.
	ceremony := participation.TBTCSigning
	if proposedAction == ActionHeartbeat {
		ceremony = participation.TBTCHeartbeat
	}

	var identities []participation.PermitIdentity
	if len(walletPublicKeys) > 1 {
		logger.Errorf(
			"refusing the [%s] wallet action: [%d] wallet identities supplied",
			proposedAction,
			len(walletPublicKeys),
		)
		return nil
	}
	if len(walletPublicKeys) == 1 {
		if walletPublicKeys[0] == nil {
			logger.Errorf(
				"refusing the [%s] wallet action: nil wallet identity",
				proposedAction,
			)
			return nil
		}
		identities = append(
			identities,
			walletPermitIdentity(
				fmt.Sprintf("wallet-action-%d", proposedAction),
				walletPublicKeys[0],
				startBlock,
			),
		)
	}

	permit, err := n.participationGate.Begin(
		ceremony,
		startBlock,
		identities...,
	)
	if err != nil {
		logger.Warnf(
			"[%s] wallet action refused by the participation gate: [%v]",
			proposedAction,
			err,
		)
		return nil
	}

	return permit
}

// archiveClosedWallets archives closed or terminated wallets.
func (n *node) archiveClosedWallets() error {
	// Get all the wallets controlled by the node.
	walletPublicKeys := n.walletRegistry.getWalletsPublicKeys()

	for _, walletPublicKey := range walletPublicKeys {
		walletPublicKeyHash := bitcoin.PublicKeyHash(walletPublicKey)

		walletID, err := n.chain.CalculateWalletID(walletPublicKey)
		if err != nil {
			return fmt.Errorf(
				"could not calculate wallet ID for wallet with public key "+
					"hash [0x%x]: [%v]",
				walletPublicKeyHash,
				err,
			)
		}

		isRegistered, err := n.chain.IsWalletRegistered(walletID)
		if err != nil {
			return fmt.Errorf(
				"could not check if wallet is registered for wallet with ID "+
					"[0x%x]: [%v]",
				walletPublicKeyHash,
				err,
			)
		}

		if !isRegistered {
			// If the wallet is no longer registered it means the wallet has
			// been closed or terminated.
			err := n.walletRegistry.archiveWallet(walletPublicKeyHash)
			if err != nil {
				return fmt.Errorf(
					"could not archive wallet with public key hash [0x%x]: [%v]",
					walletPublicKeyHash,
					err,
				)
			}

			logger.Infof(
				"successfully archived wallet with ID [0x%x] and public key "+
					"hash [0x%x]",
				walletID,
				walletPublicKeyHash,
			)
		}
	}

	return nil
}

// handleWalletClosure handles the wallet termination or closing process.
func (n *node) handleWalletClosure(walletID [32]byte) error {
	blockCounter, err := n.chain.BlockCounter()
	if err != nil {
		return fmt.Errorf("error getting block counter [%w]", err)
	}

	currentBlock, err := blockCounter.CurrentBlock()
	if err != nil {
		return fmt.Errorf("error getting current block [%w]", err)
	}

	// To verify there was no chain reorg and the wallet is really closed check
	// if it is registered. Both terminated and closed wallets are removed
	// from the ECDSA registry.
	stateCheck := func() (bool, error) {
		isRegistered, err := n.chain.IsWalletRegistered(walletID)
		if err != nil {
			return false, err
		}

		return !isRegistered, nil
	}

	// Wait a significant number of blocks to make sure the transaction has not
	// been reverted for some reason, e.g. due to a chain reorganization.
	result, err := ethereum.WaitForBlockConfirmations(
		blockCounter,
		currentBlock,
		walletClosureConfirmationBlocks,
		stateCheck,
	)
	if err != nil {
		return fmt.Errorf(
			"error while waiting for wallet closure confirmation [%w]",
			err,
		)
	}

	if !result {
		return fmt.Errorf("wallet closure not confirmed")
	}

	wallet, ok := n.walletRegistry.getWalletByID(walletID)
	if !ok {
		// Wallet was not found in the registry. The wallet is not controlled by
		// this node.
		logger.Infof(
			"node does not control wallet with ID [0x%x]; quitting wallet "+
				"archiving",
			walletID,
		)
		return nil
	}

	walletPublicKeyHash := bitcoin.PublicKeyHash(wallet.publicKey)

	err = n.walletRegistry.archiveWallet(walletPublicKeyHash)
	if err != nil {
		return fmt.Errorf("failed to archive the wallet: [%v]", err)
	}

	logger.Infof(
		"successfully archived wallet with wallet ID [0x%x] and public key "+
			"hash [0x%x]",
		walletID,
		walletPublicKeyHash,
	)

	return nil
}

// waitForBlockFn represents a function blocking the execution until the given
// block height.
type waitForBlockFn func(context.Context, uint64) error

// getCurrentBlockFn represents a function returning the current block height.
type getCurrentBlockFn func() (uint64, error)

// TODO: this should become a part of BlockHeightWaiter interface.
func (n *node) waitForBlockHeight(ctx context.Context, blockHeight uint64) error {
	blockCounter, err := n.chain.BlockCounter()
	if err != nil {
		return err
	}

	wait, err := blockCounter.BlockHeightWaiter(blockHeight)
	if err != nil {
		return err
	}

	select {
	case <-wait:
	case <-ctx.Done():
		// The block counter delivers exactly one notification per waiter
		// with a blocking send on an unbuffered channel once the height is
		// reached. Simply abandoning the channel would park that sender
		// goroutine forever, so a drain goroutine performs the single
		// receive and lets the eventual sender terminate.
		go func() { <-wait }()
	}

	return nil
}

// withCancelOnBlock returns a copy of the given ctx that is automatically
// cancelled on the given block or when the parent ctx is done. Note that the
// context can be cancelled earlier if the waitForBlockFn returns an error.
func withCancelOnBlock(
	ctx context.Context,
	block uint64,
	waitForBlockFn waitForBlockFn,
) (context.Context, context.CancelFunc) {
	blockCtx, cancelBlockCtx := context.WithCancel(ctx)

	go func() {
		defer cancelBlockCtx()

		err := waitForBlockFn(ctx, block)
		if err != nil {
			logger.Errorf(
				"failed to wait for block [%v]; "+
					"context cancelled earlier than expected",
				err,
			)
		}
	}()

	return blockCtx, cancelBlockCtx
}
