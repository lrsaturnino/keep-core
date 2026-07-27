package tbtc

// This file carries the in-repository part of the tBTC DKG cutover acceptance
// evidence: the production DKG retry loop and announcer over real local
// network providers, and real participation gates clocked by a local chain.
//
// The cases that require completing an actual tECDSA key-generation
// transcript are out of unit-suite reach: the legacy transcript is blocked on
// the reviewed tss-lib fork with an immutable per-party legacy mode, and the
// homogeneous full-crypto controls (and the on-chain 90-active/10-misbehaved
// consequence with reward ineligibility) belong to the exact-image rehearsal
// in scripts/release/pr4109 and the Solidity suite. What is proven here is
// the anchor-derived mode selection, its immutability across the cutover
// block, the quorum discipline of the retry loop, and the conversion of
// post-cutover legacy peers into exclusion, mismatch metrics, and roster
// evidence.

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa/dkg"
)

// dkgCutoverGroup is a local test group whose seats have distinct wire
// identities: one local provider and one operator per seat. The wire
// operator addresses come from the local chain's signing — raw public keys —
// while the roster operator addresses are normalized Ethereum addresses for
// the same seats, matching the two shapes a production group carries.
type dkgCutoverGroup struct {
	localChain      *localChain
	blockCounter    chain.BlockCounter
	providers       []net.Provider
	operators       chain.Addresses
	rosterOperators chain.Addresses
	validator       *group.MembershipValidator
}

// provider returns the network provider of the given 1-based member.
func (g *dkgCutoverGroup) provider(memberIndex group.MemberIndex) net.Provider {
	return g.providers[memberIndex-1]
}

// setupDKGCutoverGroup builds a distinct-identity local group of the given
// size over a chain with the given block time.
func setupDKGCutoverGroup(
	t *testing.T,
	groupSize int,
	blockTime time.Duration,
) *dkgCutoverGroup {
	t.Helper()

	g := &dkgCutoverGroup{}

	for i := 0; i < groupSize; i++ {
		operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
			local_v1.DefaultCurve,
		)
		if err != nil {
			t.Fatal(err)
		}

		if i == 0 {
			g.localChain = ConnectWithKey(operatorPrivateKey, blockTime)
		}

		g.providers = append(g.providers, local.ConnectWithKey(operatorPublicKey))

		operatorAddress, err := g.localChain.Signing().PublicKeyToAddress(
			operatorPublicKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		g.operators = append(g.operators, operatorAddress)

		g.rosterOperators = append(
			g.rosterOperators,
			chain.Address(fmt.Sprintf("0x%040x", i+1)),
		)
	}

	g.validator = group.NewMembershipValidator(
		&testutils.MockLogger{},
		g.operators,
		g.localChain.Signing(),
	)

	blockCounter, err := g.localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	g.blockCounter = blockCounter

	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	return g
}

// TestDKGCutover_SecurityV2AnchorUsesHardenedSessionIDs proves the
// smoke-gate-2 mode-selection rule for a post-cutover DKG: a canonical DKG
// anchor at the cutover block pins the security-v2 mode even when the local
// callback height is already past the cutover block, and the production retry
// loop derives the exact hardened session ID and proceeds with the full ready
// cohort.
func TestDKGCutover_SecurityV2AnchorUsesHardenedSessionIDs(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       3,
		GroupQuorum:     2,
		HonestThreshold: 2,
	}

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := ConnectWithKey(operatorPrivateKey, 20*time.Millisecond)
	localProvider := local.ConnectWithKey(operatorPublicKey)

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(
		operatorPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	var operators chain.Addresses
	for i := 0; i < groupParameters.GroupSize; i++ {
		operators = append(operators, operatorAddress)
	}

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	// Cross the cutover block before the ceremony starts: the canonical
	// anchor is the cutover block itself while the current height is already
	// past it.
	cutoverBlock := uint64(2)
	if err := blockCounter.WaitForBlockHeight(cutoverBlock + 1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, blockCounter, cutoverBlock)

	permit, err := gate.Begin(participation.TBTCDKG, cutoverBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	testutils.AssertStringsEqual(
		t,
		"permit mode for the anchor at the cutover block",
		participation.ModeSecurityV2.String(),
		permit.Mode().String(),
	)

	seed := big.NewInt(0x77997799)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "dkg")
	channelName := "dkg-cutover-hardened-test"

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		operators,
		localChain.Signing(),
	)

	channel, err := localProvider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	announcer.RegisterUnmarshaller(channel)

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	hardenedSessionIDs := []string{
		compatibility.SecurityV2().DKGSessionID(seed, 1),
		compatibility.SecurityV2().DKGSessionID(seed, 2),
	}
	for _, memberIndex := range []group.MemberIndex{2, 3} {
		startPeerAnnouncer(
			peersCtx,
			t,
			localProvider,
			channelName,
			membershipValidator,
			protocolID,
			memberIndex,
			hardenedSessionIDs,
		)
	}

	loopAnnouncer := announcer.New(protocolID, channel, membershipValidator)

	anchor := permit.CanonicalStartBlock()
	retryLoop := newDkgRetryLoop(
		logger,
		seed,
		permit.Mode(),
		anchor,
		group.MemberIndex(1),
		operators,
		groupParameters,
		loopAnnouncer,
		3,
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancelLoopCtx()

	expectedResult := &dkg.Result{}
	var attemptSessionIDs []string
	var attemptExclusions [][]group.MemberIndex

	result, err := retryLoop.start(
		loopCtx,
		newChainWaitForBlockFn(blockCounter),
		func(attempt *dkgAttemptParams) (*dkg.Result, error) {
			attemptSessionIDs = append(attemptSessionIDs, attempt.sessionID)
			attemptExclusions = append(
				attemptExclusions,
				attempt.excludedMembersIndexes,
			)
			return expectedResult, nil
		},
	)
	cancelPeers()
	if err != nil {
		t.Fatal(err)
	}
	if result != expectedResult {
		t.Error("expected the attempt's result")
	}

	testutils.AssertIntsEqual(t, "attempts", 1, len(attemptSessionIDs))
	testutils.AssertStringsEqual(
		t,
		"attempt session ID",
		fmt.Sprintf("dkg-%v-%016x", seed.Text(16), 1),
		attemptSessionIDs[0],
	)
	testutils.AssertStringsEqual(
		t,
		"attempt session ID format",
		announcer.SessionIDFormatHardenedDKG.String(),
		announcer.ClassifySessionIDFormat(attemptSessionIDs[0]).String(),
	)
	testutils.AssertIntsEqual(
		t,
		"excluded members",
		0,
		len(attemptExclusions[0]),
	)
}

// TestDKGCutover_LegacyAnchorPinnedThroughRetriesAcrossCutover proves the
// mode-pinning half of the smoke-gate-2 legacy case: a DKG canonically
// anchored below the cutover block keeps the legacy mode through every retry
// attempt — the production retry loop derives the exact prior-release session
// ID for a retry starting at or after the cutover block, and the permit's
// mode never mutates while the process state is already open_security_v2.
// The ceremony's cryptographic completion with prior-release peers stays
// blocked on the reviewed tss-lib fork and is recorded separately.
func TestDKGCutover_LegacyAnchorPinnedThroughRetriesAcrossCutover(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       3,
		GroupQuorum:     2,
		HonestThreshold: 2,
	}

	// Distinct wire identities per seat: the DKG retry algorithm derives the
	// attempt-2+ qualified set by excluding operators, which requires more
	// than one distinct operator address.
	cutoverGroup := setupDKGCutoverGroup(t, groupParameters.GroupSize, 20*time.Millisecond)
	blockCounter := cutoverGroup.blockCounter

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}
	cutoverBlock := anchor + 2

	gate := newTestGateWithCutover(t, blockCounter, cutoverBlock)

	permit, err := gate.Begin(participation.TBTCDKG, anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	testutils.AssertStringsEqual(
		t,
		"permit mode for the pre-cutover anchor",
		participation.ModeLegacy.String(),
		permit.Mode().String(),
	)

	seed := big.NewInt(0x881188)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "dkg")
	channelName := "dkg-cutover-pin-test"

	channel, err := cutoverGroup.provider(1).BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	announcer.RegisterUnmarshaller(channel)

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	// The legacy peers announce the exact prior-release session IDs of the
	// first three attempts, exactly as a prior binary would for this seed.
	legacySessionIDs := []string{
		compatibility.Legacy().DKGSessionID(seed, 1),
		compatibility.Legacy().DKGSessionID(seed, 2),
		compatibility.Legacy().DKGSessionID(seed, 3),
	}
	for _, memberIndex := range []group.MemberIndex{2, 3} {
		startPeerAnnouncer(
			peersCtx,
			t,
			cutoverGroup.provider(memberIndex),
			channelName,
			cutoverGroup.validator,
			protocolID,
			memberIndex,
			legacySessionIDs,
		)
	}

	loopAnnouncer := announcer.New(protocolID, channel, cutoverGroup.validator)

	retryLoop := newDkgRetryLoop(
		logger,
		seed,
		permit.Mode(),
		anchor,
		group.MemberIndex(1),
		cutoverGroup.operators,
		groupParameters,
		loopAnnouncer,
		3,
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		60*time.Second,
	)
	defer cancelLoopCtx()

	expectedResult := &dkg.Result{}

	type invokedAttempt struct {
		number     uint
		sessionID  string
		startBlock uint64
	}
	var invokedAttempts []invokedAttempt

	// The first invoked attempt fails so the loop retries at a start block
	// that is unambiguously at or after the cutover block. The retry
	// algorithm's seeded operator exclusion may skip the local member on one
	// retry, so the succeeding attempt is the second one actually invoked,
	// not necessarily attempt number two.
	result, err := retryLoop.start(
		loopCtx,
		newChainWaitForBlockFn(blockCounter),
		func(attempt *dkgAttemptParams) (*dkg.Result, error) {
			invokedAttempts = append(invokedAttempts, invokedAttempt{
				number:     attempt.number,
				sessionID:  attempt.sessionID,
				startBlock: attempt.startBlock,
			})

			if len(invokedAttempts) == 1 {
				return nil, fmt.Errorf("simulated first-attempt failure")
			}
			return expectedResult, nil
		},
	)
	cancelPeers()
	if err != nil {
		t.Fatal(err)
	}
	if result != expectedResult {
		t.Error("expected the retry attempt's result")
	}

	if len(invokedAttempts) < 2 {
		t.Fatalf(
			"expected at least two invoked attempts, got [%d]",
			len(invokedAttempts),
		)
	}
	for _, attempt := range invokedAttempts {
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt %d session ID", attempt.number),
			fmt.Sprintf("%v-%v", seed.Text(16), attempt.number),
			attempt.sessionID,
		)
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt %d session ID format", attempt.number),
			announcer.SessionIDFormatLegacy.String(),
			announcer.ClassifySessionIDFormat(attempt.sessionID).String(),
		)
	}

	lastAttempt := invokedAttempts[len(invokedAttempts)-1]
	if lastAttempt.startBlock < cutoverBlock {
		t.Errorf(
			"expected the retry attempt to start at or after the cutover "+
				"block [%d], got [%d]",
			cutoverBlock,
			lastAttempt.startBlock,
		)
	}

	testutils.AssertStringsEqual(
		t,
		"permit mode after crossing the cutover block",
		participation.ModeLegacy.String(),
		permit.Mode().String(),
	)
	snapshot := gate.State()
	testutils.AssertStringsEqual(
		t,
		"gate state after crossing the cutover block",
		participation.StateOpenSecurityV2.String(),
		snapshot.State.String(),
	)
}

// TestDKGCutover_PostCutoverSplitExcludesLegacyPeersAtQuorum proves the
// off-chain half of the smoke-gate-2 90/10 consequence, scaled to 5/4: a
// post-cutover DKG selection containing one prior-release peer proceeds once
// the security-v2 cohort alone reaches the group quorum, excludes exactly the
// legacy seat from the attempt — the exclusion that the tECDSA executor turns
// into the result's misbehaved-members output — and reports the straggler
// into mismatch metrics and the node-local roster under its operator. The
// on-chain acceptance of the 90-active boundary and the reward-ineligibility
// consequence live in the Solidity suite and the exact-image rehearsal.
func TestDKGCutover_PostCutoverSplitExcludesLegacyPeersAtQuorum(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	cutoverGroup := setupDKGCutoverGroup(t, groupParameters.GroupSize, 20*time.Millisecond)
	blockCounter := cutoverGroup.blockCounter

	gate := newTestGate(t, blockCounter)

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	permit, err := gate.Begin(participation.TBTCDKG, anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()

	seed := big.NewInt(0x5544)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "dkg")
	channelName := "dkg-cutover-split-quorum-test"

	channel, err := cutoverGroup.provider(1).BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	announcer.RegisterUnmarshaller(channel)

	recorder := newDispatcherMetricsRecorder()
	roster, err := participation.NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		1500,
		newCutoverFakeMetrics(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roster.Close)

	// The observer is wired exactly like the production DKG executor wires it.
	currentMode := permit.Mode()
	loopAnnouncer := announcer.New(
		protocolID,
		channel,
		cutoverGroup.validator,
		announcer.WithSessionMismatchObserver(func(
			observedProtocolID string,
			sender group.MemberIndex,
			expectedFormat announcer.SessionIDFormat,
			observedFormat announcer.SessionIDFormat,
		) {
			handleAnnouncerSessionMismatch(
				logger,
				nil,
				recorder,
				roster,
				currentMode,
				cutoverGroup.rosterOperators,
				observedProtocolID,
				sender,
				expectedFormat,
				observedFormat,
			)
		}),
	)

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	// Members 2-4 are current security-v2 peers; member 5 is a prior-release
	// binary that keeps announcing the legacy session ID after the cutover.
	hardenedSessionIDs := []string{
		compatibility.SecurityV2().DKGSessionID(seed, 1),
		compatibility.SecurityV2().DKGSessionID(seed, 2),
	}
	for _, memberIndex := range []group.MemberIndex{2, 3, 4} {
		startPeerAnnouncer(
			peersCtx,
			t,
			cutoverGroup.provider(memberIndex),
			channelName,
			cutoverGroup.validator,
			protocolID,
			memberIndex,
			hardenedSessionIDs,
		)
	}
	legacySessionIDs := []string{
		compatibility.Legacy().DKGSessionID(seed, 1),
		compatibility.Legacy().DKGSessionID(seed, 2),
	}
	startPeerAnnouncer(
		peersCtx,
		t,
		cutoverGroup.provider(5),
		channelName,
		cutoverGroup.validator,
		protocolID,
		group.MemberIndex(5),
		legacySessionIDs,
	)

	retryLoop := newDkgRetryLoop(
		logger,
		seed,
		permit.Mode(),
		anchor,
		group.MemberIndex(1),
		cutoverGroup.rosterOperators,
		groupParameters,
		loopAnnouncer,
		3,
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancelLoopCtx()

	expectedResult := &dkg.Result{}
	var attemptExclusions [][]group.MemberIndex

	result, err := retryLoop.start(
		loopCtx,
		newChainWaitForBlockFn(blockCounter),
		func(attempt *dkgAttemptParams) (*dkg.Result, error) {
			attemptExclusions = append(
				attemptExclusions,
				attempt.excludedMembersIndexes,
			)
			return expectedResult, nil
		},
	)
	cancelPeers()
	if err != nil {
		t.Fatal(err)
	}
	if result != expectedResult {
		t.Error("expected the attempt's result")
	}

	// The security-v2 cohort proceeded at quorum and excluded exactly the
	// legacy straggler's seat.
	testutils.AssertIntsEqual(t, "attempts", 1, len(attemptExclusions))
	testutils.AssertIntsEqual(
		t,
		"excluded members",
		1,
		len(attemptExclusions[0]),
	)
	testutils.AssertIntsEqual(
		t,
		"excluded member index",
		5,
		int(attemptExclusions[0][0]),
	)

	// The straggler became mismatch and cross-format evidence attributed to
	// its operator in the node-local roster.
	if mismatches := recorder.counter(
		clientinfo.MetricAnnouncerSessionIDMismatchTotal,
	); mismatches < 1 {
		t.Errorf("expected at least one mismatch, got [%v]", mismatches)
	}
	if crossFormat := recorder.counter(
		clientinfo.MetricAnnouncerCrossFormatPeerTotal,
	); crossFormat < 1 {
		t.Errorf("expected at least one cross-format peer, got [%v]", crossFormat)
	}

	rosterSnapshot := roster.Snapshot()
	testutils.AssertIntsEqual(
		t,
		"cutover roster operators",
		1,
		len(rosterSnapshot.Peers),
	)
	testutils.AssertStringsEqual(
		t,
		"roster operator address",
		string(cutoverGroup.rosterOperators[4]),
		rosterSnapshot.Peers[0].OperatorAddress,
	)
}

// TestDKGCutover_SplitBelowQuorumNeverStartsProtocol proves the quorum
// discipline of the post-cutover split: when the security-v2 cohort is below
// the group quorum because prior-release peers keep announcing legacy session
// IDs, the production retry loop never starts the DKG protocol at all, and
// every straggler is reported into mismatch metrics.
func TestDKGCutover_SplitBelowQuorumNeverStartsProtocol(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	cutoverGroup := setupDKGCutoverGroup(t, groupParameters.GroupSize, 20*time.Millisecond)
	blockCounter := cutoverGroup.blockCounter

	gate := newTestGate(t, blockCounter)

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	permit, err := gate.Begin(participation.TBTCDKG, anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()

	seed := big.NewInt(0x6655)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "dkg")
	channelName := "dkg-cutover-split-noquorum-test"

	channel, err := cutoverGroup.provider(1).BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	announcer.RegisterUnmarshaller(channel)

	recorder := newDispatcherMetricsRecorder()

	currentMode := permit.Mode()
	loopAnnouncer := announcer.New(
		protocolID,
		channel,
		cutoverGroup.validator,
		announcer.WithSessionMismatchObserver(func(
			observedProtocolID string,
			sender group.MemberIndex,
			expectedFormat announcer.SessionIDFormat,
			observedFormat announcer.SessionIDFormat,
		) {
			handleAnnouncerSessionMismatch(
				logger,
				nil,
				recorder,
				nil,
				currentMode,
				cutoverGroup.rosterOperators,
				observedProtocolID,
				sender,
				expectedFormat,
				observedFormat,
			)
		}),
	)

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	// Only member 2 is a current security-v2 peer — together with the local
	// member that is 2 ready members, below the quorum of 4. Members 3-5 are
	// prior-release binaries announcing legacy session IDs.
	startPeerAnnouncer(
		peersCtx,
		t,
		cutoverGroup.provider(2),
		channelName,
		cutoverGroup.validator,
		protocolID,
		group.MemberIndex(2),
		[]string{compatibility.SecurityV2().DKGSessionID(seed, 1)},
	)
	for _, memberIndex := range []group.MemberIndex{3, 4, 5} {
		startPeerAnnouncer(
			peersCtx,
			t,
			cutoverGroup.provider(memberIndex),
			channelName,
			cutoverGroup.validator,
			protocolID,
			memberIndex,
			[]string{compatibility.Legacy().DKGSessionID(seed, 1)},
		)
	}

	retryLoop := newDkgRetryLoop(
		logger,
		seed,
		permit.Mode(),
		anchor,
		group.MemberIndex(1),
		cutoverGroup.rosterOperators,
		groupParameters,
		loopAnnouncer,
		1,
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancelLoopCtx()

	var attemptCalls atomic.Uint64

	_, err = retryLoop.start(
		loopCtx,
		newChainWaitForBlockFn(blockCounter),
		func(attempt *dkgAttemptParams) (*dkg.Result, error) {
			attemptCalls.Add(1)
			return nil, fmt.Errorf("must never be reached")
		},
	)
	cancelPeers()

	if err == nil {
		t.Fatal("expected the loop to end without a result")
	}
	testutils.AssertUintsEqual(
		t,
		"DKG protocol invocations below quorum",
		0,
		attemptCalls.Load(),
	)

	if mismatches := recorder.counter(
		clientinfo.MetricAnnouncerSessionIDMismatchTotal,
	); mismatches < 3 {
		t.Errorf("expected at least three mismatches, got [%v]", mismatches)
	}
	if crossFormat := recorder.counter(
		clientinfo.MetricAnnouncerCrossFormatPeerTotal,
	); crossFormat < 3 {
		t.Errorf("expected at least three cross-format peers, got [%v]", crossFormat)
	}
}

// TestDKGCutover_GateQuiesceAbortSkipsOrdinaryDKGFailureMetrics proves the
// smoke-gate-2 metric-neutrality rule through the production DKG executor: a
// member goroutine ended by the gate's forced quiesce deadline does not
// increment the ordinary DKG failure counter.
func TestDKGCutover_GateQuiesceAbortSkipsOrdinaryDKGFailureMetrics(t *testing.T) {
	localChain := Connect(20 * time.Millisecond)

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)

	_, operatorPublicKey, err := operator.GenerateKeyPair(local_v1.DefaultCurve)
	if err != nil {
		t.Fatal(err)
	}

	recorder := newDispatcherMetricsRecorder()

	de := &dkgExecutor{
		groupParameters: &GroupParameters{
			GroupSize:       5,
			GroupQuorum:     4,
			HonestThreshold: 3,
		},
		chain:             localChain,
		netProvider:       local.ConnectWithKey(operatorPublicKey),
		protocolLatch:     generator.NewProtocolLatch(),
		waitForBlockFn:    newChainWaitForBlockFn(blockCounter),
		participationGate: gate,
		metricsRecorder:   recorder,
		signerQuarantine: newSignerQuarantine(
			logger,
			&mockPersistenceHandle{},
		),
	}

	gsr := &GroupSelectionResult{
		OperatorsIDs: chain.OperatorIDs{1, 2, 3, 4, 5},
		OperatorsAddresses: chain.Addresses{
			"0xAA", "0xBB", "0xCC", "0xDD", "0xEE",
		},
	}

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	// The single controlled member joins the DKG and blocks in the
	// announcement phase: the other four members never announce.
	de.generateSigningGroup(
		logger.With(),
		big.NewInt(0x11),
		[]uint8{1},
		gsr,
		anchor,
		0,
	)

	// Wait for the member permit to be active, then force the quiesce
	// deadline while the member goroutine is still in flight.
	waitForActiveCeremonies := func(expected uint64) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for gate.State().ActiveCeremonies != expected {
			if time.Now().After(deadline) {
				t.Fatalf(
					"gate never reached [%d] active ceremonies",
					expected,
				)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	waitForActiveCeremonies(1)
	gate.Quiesce(fmt.Errorf("rollback drill"))
	gate.Close()
	waitForActiveCeremonies(0)

	testutils.AssertIntsEqual(
		t,
		"ordinary DKG failures after the gate abort",
		0,
		int(recorder.counter(clientinfo.MetricDKGFailedTotal)),
	)
}

// TestDKGCutover_PriorReleaseInterop_BlockedOnReviewedTssLibFork records the
// remaining smoke-gate-2 cases that require a completed legacy tECDSA
// key-generation transcript: a canonical DKG event below the cutover block
// that confirms after it succeeding with prior binaries on every R1 node, and
// the homogeneous legacy control. The pinned tss-lib revision cannot produce
// the legacy proof transcript: the release specification requires an
// externally reviewed tss-lib fork with an immutable per-party
// legacy/security-v2 mode. Until that fork is reviewed and pinned, R1
// deliberately fails closed on legacy tBTC permits, and this acceptance
// evidence cannot exist. See scripts/release/pr4109/README.md for the hard
// dependency record.
func TestDKGCutover_PriorReleaseInterop_BlockedOnReviewedTssLibFork(t *testing.T) {
	t.Skip(
		"blocked on the reviewed tss-lib fork with an immutable per-party " +
			"legacy mode; until it is pinned, tECDSA cannot produce the " +
			"legacy proof transcript and R1 deliberately fails closed on " +
			"legacy tBTC permits",
	)
}
