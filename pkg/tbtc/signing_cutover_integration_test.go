package tbtc

// This file carries the in-repository part of the tBTC signing cutover
// acceptance evidence: real local network providers, the production announcer
// and retry logic, real participation gates clocked by a local chain, and
// completed homogeneous tECDSA transcripts in both legacy and security-v2
// modes. Exact-image bidirectional mixed-binary evidence remains part of the
// release rehearsal.

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/signing"
)

// newChainWaitForBlockFn builds a waitForBlockFn over the given block counter,
// mirroring the production node's implementation.
func newChainWaitForBlockFn(blockCounter chain.BlockCounter) waitForBlockFn {
	return func(ctx context.Context, blockHeight uint64) error {
		waiter, err := blockCounter.BlockHeightWaiter(blockHeight)
		if err != nil {
			return err
		}

		select {
		case <-waiter:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// startPeerAnnouncer simulates one remote peer of a ceremony: it keeps
// announcing the given member's participation with each of the given session
// IDs on its own broadcast channel instance until ctx is done. A peer stuck on
// a fixed wire format — a prior-release binary after the cutover block — is
// modeled by announcing that format's session IDs.
func startPeerAnnouncer(
	ctx context.Context,
	t *testing.T,
	provider net.Provider,
	channelName string,
	membershipValidator *group.MembershipValidator,
	protocolID string,
	memberIndex group.MemberIndex,
	sessionIDs []string,
) {
	t.Helper()

	channel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	announcer.RegisterUnmarshaller(channel)

	peerAnnouncer := announcer.New(protocolID, channel, membershipValidator)

	for _, sessionID := range sessionIDs {
		go func(sessionID string) {
			for {
				announceCtx, cancelAnnounceCtx := context.WithTimeout(
					ctx,
					10*local.RetransmissionTick,
				)
				// A canceled announcement is this goroutine's exit signal,
				// not an error.
				_, _ = peerAnnouncer.Announce(announceCtx, memberIndex, sessionID)
				cancelAnnounceCtx()

				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}(sessionID)
	}
}

// TestSigningCutover_HomogeneousSecurityV2AfterCutover proves smoke-gate case
// 9.2.2/9.2.4: a homogeneous R1 cohort whose wallet action is canonically
// anchored at the cutover block signs successfully in security-v2 mode with
// the production announcer and retry logic, even though the local callback
// height is already past the cutover block, and the completion fence admits
// the terminal commit.
func TestSigningCutover_HomogeneousSecurityV2AfterCutover(t *testing.T) {
	testSigningCutoverHomogeneous(t, participation.ModeSecurityV2)
}

// TestSigningCutover_HomogeneousLegacyAfterCutover proves that an R1 signing
// cohort selected by a pre-cutover canonical anchor completes with the
// historical transcript and session-ID format after the chain crosses the
// cutover. Dependency-level transcript regression tests pin those legacy
// challenges to the prior production formulas; exact-image bidirectional
// prior/R1 interoperability remains a release rehearsal gate.
func TestSigningCutover_HomogeneousLegacyAfterCutover(t *testing.T) {
	testSigningCutoverHomogeneous(t, participation.ModeLegacy)
}

func testSigningCutoverHomogeneous(
	t *testing.T,
	mode participation.ProtocolMode,
) {
	executor, localChain := setupSigningExecutorWithChain(t)

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	// Cross the cutover block before the ceremony starts. The canonical
	// anchor is the cutover block itself while the current height is already
	// past it — the late-confirmation shape of a post-cutover event.
	cutoverBlock := uint64(2)
	if err := blockCounter.WaitForBlockHeight(cutoverBlock + 1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, blockCounter, cutoverBlock)
	anchor := cutoverBlock
	if mode == participation.ModeLegacy {
		anchor = cutoverBlock - 1
	}

	permit, err := gate.Begin(participation.TBTCSigning, anchor)
	if err != nil {
		t.Fatal(err)
	}
	testutils.AssertStringsEqual(
		t,
		"permit mode for the canonical anchor",
		mode.String(),
		permit.Mode().String(),
	)

	message := big.NewInt(100)

	outcome, err := executor.sign(
		permit.Context(),
		message,
		0,
		permit.Mode(),
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKey := executor.wallet().publicKey
	if !ecdsa.Verify(
		walletPublicKey,
		message.Bytes(),
		outcome.signature.R,
		outcome.signature.S,
	) {
		t.Errorf("invalid signature: [%+v]", outcome.signature)
	}
	if outcome.endBlock == 0 {
		t.Error("expected a nonzero end block")
	}

	// The transcript travels with the signature: the memberships whose
	// authenticated done checks carried it, and the one this node operated.
	// Without it the ceremony's terminal record could say a threshold result
	// exists and not which parties reached it.
	// This executor operates every membership of the group, so the memberships
	// whose done checks carried the signature and the ones it operated are the
	// same set — the attempt's members, an honest majority or more.
	if outcome.contribution == nil ||
		len(outcome.contribution.IncorporatedMembers) <
			executor.groupParameters.HonestThreshold ||
		!slices.Equal(
			outcome.contribution.LocalMembers,
			outcome.contribution.IncorporatedMembers,
		) {
		t.Errorf(
			"unexpected transcript behind the signature: %+v",
			outcome.contribution,
		)
	}

	if err := permit.CheckCommit(
		"tbtc_signing_test_completion",
		participation.CompletionCommit,
	); err != nil {
		t.Errorf("expected the completion fence to admit the commit: [%v]", err)
	}

	permit.Close()

	snapshot := gate.State()
	testutils.AssertUintsEqual(
		t,
		"active ceremonies after the permit release",
		0,
		snapshot.ActiveCeremonies,
	)
}

// TestSigningCutover_LegacyAnchorPinnedThroughRetriesAcrossCutover proves the
// mode-pinning half of smoke-gate case 9.2.3: a wallet action canonically
// anchored below the cutover block keeps the legacy mode through every retry
// attempt — the production retry loop derives the exact prior-release session
// ID for an attempt starting at or after the cutover block, legacy peers
// announcing those IDs stay ready, the permit's mode never mutates while the
// process state is already open_security_v2, and the legacy completion commit
// remains admitted while a new penalty commit is refused. Completed
// cryptographic legacy interoperability is covered by the homogeneous legacy
// test above.
func TestSigningCutover_LegacyAnchorPinnedThroughRetriesAcrossCutover(t *testing.T) {
	// The group size equals the honest threshold so the loop's member-count
	// trimming cannot exclude the local member: every ready member is needed
	// for every attempt.
	groupParameters := &GroupParameters{
		GroupSize:       2,
		GroupQuorum:     2,
		HonestThreshold: 2,
	}

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := ConnectWithKey(operatorPrivateKey, 50*time.Millisecond)
	localProvider := local.ConnectWithKey(operatorPublicKey)

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(
		operatorPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	var operators []chain.Address
	for i := 0; i < groupParameters.GroupSize; i++ {
		operators = append(operators, operatorAddress)
	}

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}
	cutoverBlock := anchor + 2

	gate := newTestGateWithCutover(t, blockCounter, cutoverBlock)

	permit, err := gate.Begin(participation.TBTCSigning, anchor)
	if err != nil {
		t.Fatal(err)
	}
	testutils.AssertStringsEqual(
		t,
		"permit mode for the pre-cutover anchor",
		participation.ModeLegacy.String(),
		permit.Mode().String(),
	)

	message := big.NewInt(2211)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "signing")
	channelName := "signing-cutover-pin-test"

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

	// The legacy peers announce the exact prior-release session IDs of the
	// first two attempts, exactly as a prior binary would for this message.
	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	legacySessionIDs := []string{
		compatibility.Legacy().SigningSessionID(message, 0, 1),
		compatibility.Legacy().SigningSessionID(message, 0, 2),
	}
	startPeerAnnouncer(
		peersCtx,
		t,
		localProvider,
		channelName,
		membershipValidator,
		protocolID,
		group.MemberIndex(2),
		legacySessionIDs,
	)

	loopAnnouncer := announcer.New(protocolID, channel, membershipValidator)

	expectedResult := &signing.Result{
		Signature: &tecdsa.Signature{R: big.NewInt(1), S: big.NewInt(2)},
	}
	doneCheck := &mockSigningDoneCheck{
		waitUntilAllDoneOutcomeFn: func(
			attemptNumber uint64,
		) (*signing.Result, uint64, error) {
			currentBlock, err := blockCounter.CurrentBlock()
			if err != nil {
				return nil, 0, err
			}
			return expectedResult, currentBlock, nil
		},
	}

	retryLoop := newSigningRetryLoop(
		logger,
		message,
		permit.Mode(),
		anchor,
		group.MemberIndex(1),
		operators,
		groupParameters,
		loopAnnouncer,
		doneCheck,
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		60*time.Second,
	)
	defer cancelLoopCtx()

	var attemptSessionIDs []string
	var attemptStartBlocks []uint64

	result, err := retryLoop.start(
		loopCtx,
		newChainWaitForBlockFn(blockCounter),
		blockCounter.CurrentBlock,
		func(attempt *signingAttemptParams) (*signing.Result, uint64, error) {
			attemptSessionIDs = append(attemptSessionIDs, attempt.sessionID)
			attemptStartBlocks = append(attemptStartBlocks, attempt.startBlock)

			// The first attempt fails so the loop retries at a start block
			// that is unambiguously at or after the cutover block.
			if len(attemptSessionIDs) == 1 {
				return nil, 0, fmt.Errorf("simulated first-attempt failure")
			}

			currentBlock, err := blockCounter.CurrentBlock()
			if err != nil {
				return nil, 0, err
			}
			return expectedResult, currentBlock, nil
		},
	)
	cancelPeers()
	if err != nil {
		t.Fatal(err)
	}
	if result.result != expectedResult {
		t.Error("expected the second attempt's result")
	}

	testutils.AssertIntsEqual(t, "attempts", 2, len(attemptSessionIDs))
	for i, sessionID := range attemptSessionIDs {
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt %d session ID", i+1),
			fmt.Sprintf("%v-%v", message.Text(16), i+1),
			sessionID,
		)
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt %d session ID format", i+1),
			announcer.SessionIDFormatLegacy.String(),
			announcer.ClassifySessionIDFormat(sessionID).String(),
		)
	}

	if attemptStartBlocks[1] < cutoverBlock {
		t.Errorf(
			"expected the retry attempt to start at or after the cutover "+
				"block [%d], got [%d]",
			cutoverBlock,
			attemptStartBlocks[1],
		)
	}

	// The permit's mode never mutated even though the process state has
	// crossed to open_security_v2.
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

	// A legacy completion after the cutover block is admitted; a new legacy
	// penalty is not.
	if err := permit.CheckCommit(
		"tbtc_signing_test_completion",
		participation.CompletionCommit,
	); err != nil {
		t.Errorf("expected the legacy completion to be admitted: [%v]", err)
	}
	if err := permit.CheckCommit(
		"tbtc_signing_test_penalty",
		participation.PenaltyCommit,
	); !errors.Is(err, participation.ErrPenaltySuppressed) {
		t.Errorf("expected the legacy penalty to be suppressed, got [%v]", err)
	}

	permit.Close()
}

// TestSigningCutover_PostCutoverSplitFailsClosedWithEvidence proves smoke-gate
// case 9.2.5 end to end through the production signing executor: a post-cutover
// wallet action whose signing group is split between security-v2 members and
// prior-release peers that keep announcing legacy session IDs exhausts its
// retries below the signing threshold, returns no signature, and turns the
// stragglers into mismatch metrics and node-local cutover roster evidence
// attributed to their operator.
func TestSigningCutover_PostCutoverSplitFailsClosedWithEvidence(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := ConnectWithKey(operatorPrivateKey, 50*time.Millisecond)
	localProvider := local.ConnectWithKey(operatorPublicKey)

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(
		operatorPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The membership validator resolves wire senders through the local
	// chain's signing, whose addresses are raw public keys rather than
	// 20-byte Ethereum addresses. The roster inventory key is a normalized
	// Ethereum address, so the signers' operator list — the roster
	// attribution source — carries a proper address for the same seats.
	var operators []chain.Address
	rosterOperatorAddress := chain.Address(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	var rosterOperators []chain.Address
	for i := 0; i < groupParameters.GroupSize; i++ {
		operators = append(operators, operatorAddress)
		rosterOperators = append(rosterOperators, rosterOperatorAddress)
	}

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(
		groupParameters.GroupSize,
	)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}

	// The local node controls only two of the five signers — below the
	// signing threshold on its own.
	signers := make([]*signer, 2)
	for i := range signers {
		privateKeyShare := tecdsa.NewPrivateKeyShare(testData[i])
		signers[i] = &signer{
			wallet: wallet{
				publicKey:             privateKeyShare.PublicKey(),
				signingGroupOperators: rosterOperators,
			},
			signingGroupMemberIndex: group.MemberIndex(i + 1),
			privateKeyShare:         privateKeyShare,
		}
	}

	channelName := "signing-cutover-split-test"
	channel, err := localProvider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	signing.RegisterUnmarshallers(channel)
	announcer.RegisterUnmarshaller(channel)
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &signingDoneMessage{}
	})

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		operators,
		localChain.Signing(),
	)

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)

	currentBlock, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	permit, err := gate.Begin(participation.TBTCSigning, currentBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	testutils.AssertStringsEqual(
		t,
		"permit mode after the cutover",
		participation.ModeSecurityV2.String(),
		permit.Mode().String(),
	)

	executor := newSigningExecutor(
		signers,
		channel,
		membershipValidator,
		groupParameters,
		generator.NewProtocolLatch(),
		blockCounter.CurrentBlock,
		newChainWaitForBlockFn(blockCounter),
		2,
		gate,
	)

	recorder := newDispatcherMetricsRecorder()
	executor.setMetricsRecorder(recorder)

	roster, err := participation.NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testAuthoritativeClock{blockCounter},
		1500,
		newCutoverFakeMetrics(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roster.Close)
	executor.setCutoverPeerRoster(roster)

	// The prior-release peers keep announcing the legacy session IDs of the
	// first two attempts after the cutover block.
	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	message := big.NewInt(3344)
	legacySessionIDs := []string{
		compatibility.Legacy().SigningSessionID(message, 0, 1),
		compatibility.Legacy().SigningSessionID(message, 0, 2),
	}
	for _, memberIndex := range []group.MemberIndex{3, 4, 5} {
		startPeerAnnouncer(
			peersCtx,
			t,
			localProvider,
			channelName,
			membershipValidator,
			fmt.Sprintf("%v-%v", ProtocolName, "signing"),
			memberIndex,
			legacySessionIDs,
		)
	}

	outcome, err := executor.sign(
		permit.Context(),
		message,
		currentBlock+2,
		permit.Mode(),
	)
	cancelPeers()

	if err == nil || !strings.Contains(err.Error(), "all signers failed") {
		t.Fatalf("expected the retries to exhaust below threshold, got [%v]", err)
	}
	if outcome != nil {
		t.Errorf("expected no signing outcome, got [%+v]", outcome)
	}

	// The failure is an ordinary signing failure of the split cohort.
	testutils.AssertIntsEqual(
		t,
		"ordinary signing failures",
		1,
		int(recorder.counter(clientinfo.MetricSigningFailedTotal)),
	)

	// The legacy stragglers became mismatch and cross-format evidence.
	if mismatches := recorder.counter(
		clientinfo.MetricAnnouncerSessionIDMismatchTotal,
	); mismatches < 3 {
		t.Errorf(
			"expected at least three session ID mismatches, got [%v]",
			mismatches,
		)
	}
	if crossFormat := recorder.counter(
		clientinfo.MetricAnnouncerCrossFormatPeerTotal,
	); crossFormat < 3 {
		t.Errorf(
			"expected at least three cross-format peers, got [%v]",
			crossFormat,
		)
	}

	// The roster deduplicates the three seats to their one operator and
	// retains the per-seat sightings.
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
		string(rosterOperatorAddress),
		rosterSnapshot.Peers[0].OperatorAddress,
	)
	if sightings := len(rosterSnapshot.Peers[0].Sightings); sightings < 3 {
		t.Errorf("expected at least three sightings, got [%d]", sightings)
	}
}

// TestSigningCutover_LoopNeverInvokesSigningBelowThreshold proves the
// never-without-quorum half of smoke-gate case 9.2.5 at the retry-loop level:
// with the ready cohort below the signing threshold, the production retry loop
// never invokes the signing protocol at all, and every legacy peer is reported
// through the production mismatch handler into metrics and the node-local
// roster.
func TestSigningCutover_LoopNeverInvokesSigningBelowThreshold(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     4,
		HonestThreshold: 3,
	}

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := ConnectWithKey(operatorPrivateKey, 50*time.Millisecond)
	localProvider := local.ConnectWithKey(operatorPublicKey)

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(
		operatorPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// As in the executor-level split test, the wire identities come from the
	// local chain's signing while the roster attribution uses a proper
	// normalized Ethereum address for the same seats.
	var operators []chain.Address
	rosterOperatorAddress := chain.Address(
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	var rosterOperators []chain.Address
	for i := 0; i < groupParameters.GroupSize; i++ {
		operators = append(operators, operatorAddress)
		rosterOperators = append(rosterOperators, rosterOperatorAddress)
	}

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)

	anchor, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	permit, err := gate.Begin(participation.TBTCSigning, anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()

	message := big.NewInt(4455)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "signing")
	channelName := "signing-cutover-threshold-test"

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

	recorder := newDispatcherMetricsRecorder()
	roster, err := participation.NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testAuthoritativeClock{blockCounter},
		1500,
		newCutoverFakeMetrics(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roster.Close)

	// The observer is wired exactly like the production signing executor
	// wires it.
	currentMode := permit.Mode()
	loopAnnouncer := announcer.New(
		protocolID,
		channel,
		membershipValidator,
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
				gate.State().State.String(),
				rosterOperators,
				observedProtocolID,
				sender,
				expectedFormat,
				observedFormat,
			)
		}),
	)

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	legacySessionIDs := []string{
		compatibility.Legacy().SigningSessionID(message, 0, 1),
		compatibility.Legacy().SigningSessionID(message, 0, 2),
	}
	for _, memberIndex := range []group.MemberIndex{4, 5} {
		startPeerAnnouncer(
			peersCtx,
			t,
			localProvider,
			channelName,
			membershipValidator,
			protocolID,
			memberIndex,
			legacySessionIDs,
		)
	}

	retryLoop := newSigningRetryLoop(
		logger,
		message,
		permit.Mode(),
		anchor,
		group.MemberIndex(1),
		operators,
		groupParameters,
		loopAnnouncer,
		&mockSigningDoneCheck{},
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		8*time.Second,
	)
	defer cancelLoopCtx()

	var attemptCalls atomic.Uint64

	_, err = retryLoop.start(
		loopCtx,
		newChainWaitForBlockFn(blockCounter),
		blockCounter.CurrentBlock,
		func(attempt *signingAttemptParams) (*signing.Result, uint64, error) {
			attemptCalls.Add(1)
			return nil, 0, fmt.Errorf("must never be reached")
		},
	)
	cancelPeers()

	if err == nil {
		t.Fatal("expected the loop to end without a result")
	}
	testutils.AssertUintsEqual(
		t,
		"signing protocol invocations below threshold",
		0,
		attemptCalls.Load(),
	)

	// Both legacy peers were reported into metrics and the roster.
	if mismatches := recorder.counter(
		clientinfo.MetricAnnouncerSessionIDMismatchTotal,
	); mismatches < 2 {
		t.Errorf("expected at least two mismatches, got [%v]", mismatches)
	}
	if crossFormat := recorder.counter(
		clientinfo.MetricAnnouncerCrossFormatPeerTotal,
	); crossFormat < 2 {
		t.Errorf("expected at least two cross-format peers, got [%v]", crossFormat)
	}

	rosterSnapshot := roster.Snapshot()
	testutils.AssertIntsEqual(
		t,
		"cutover roster operators",
		1,
		len(rosterSnapshot.Peers),
	)

	sightedMembers := make(map[group.MemberIndex]bool)
	for _, sighting := range rosterSnapshot.Peers[0].Sightings {
		sightedMembers[sighting.MemberIndex] = true
	}
	if !sightedMembers[4] || !sightedMembers[5] {
		t.Errorf(
			"expected sightings for members 4 and 5, got [%v]",
			rosterSnapshot.Peers[0].Sightings,
		)
	}
}

// TestSigningCutover_GateQuiesceAbortSkipsOrdinaryFailureMetrics proves
// smoke-gate case 9.2.6 with a real gate: a signing canceled by the gate's
// forced quiesce deadline surfaces the gate sentinel and increments neither
// the ordinary signing failure nor the timeout counter.
func TestSigningCutover_GateQuiesceAbortSkipsOrdinaryFailureMetrics(t *testing.T) {
	executor, localChain := setupSigningExecutorWithChain(t)

	recorder := newDispatcherMetricsRecorder()
	executor.setMetricsRecorder(recorder)

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)

	permit, err := gate.Begin(participation.TBTCSigning, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Quiescence begins and the shutdown deadline arrives while the permit is
	// still active: the gate force-cancels it.
	quiesceDone := gate.Quiesce(fmt.Errorf("rollback drill"))
	gate.Close()
	<-quiesceDone

	_, err = executor.sign(
		permit.Context(),
		big.NewInt(555),
		0,
		permit.Mode(),
	)
	if !errors.Is(err, participation.ErrQuiesceDeadline) {
		t.Fatalf("expected the gate sentinel, got [%v]", err)
	}

	testutils.AssertIntsEqual(
		t,
		"signing operations",
		1,
		int(recorder.counter(clientinfo.MetricSigningOperationsTotal)),
	)
	testutils.AssertIntsEqual(
		t,
		"ordinary signing failures",
		0,
		int(recorder.counter(clientinfo.MetricSigningFailedTotal)),
	)
	testutils.AssertIntsEqual(
		t,
		"ordinary signing timeouts",
		0,
		int(recorder.counter(clientinfo.MetricSigningTimeoutsTotal)),
	)
}
