package tbtc

// This file carries the in-repository part of the tBTC DKG cutover acceptance
// evidence: the production DKG retry loop and announcer over real local
// network providers, real participation gates clocked by a local chain, and —
// for the security-v2 mode — complete tECDSA key-generation transcripts with
// fixture pre-parameters, including generated key material, misbehavior
// evidence, and signer persistence across a registry restart.
//
// The legacy-transcript cases remain out of unit-suite reach: they are
// blocked on the reviewed tss-lib fork with an immutable per-party legacy
// mode. The on-chain 90-active/10-misbehaved consequence with reward
// ineligibility belongs to the Solidity suite, and the exact-image
// mixed-release rehearsals — including transcript realness at the full
// hundred-member scale — to scripts/release/pr4109. What is proven here is
// the anchor-derived mode selection, its immutability across the cutover
// block, the quorum discipline of the retry loop, the real-transcript
// conversion of post-cutover legacy and silent peers into misbehaved-members
// evidence, mismatch metrics, and roster attribution, the exact
// production-scale first-attempt exclusion of the ten legacy seats at the
// ninety-member quorum, and the homogeneous security-v2 key-generation
// control.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/keep-network/keep-common/pkg/persistence"
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
	"github.com/keep-network/keep-core/pkg/tecdsa/dkg"
	"github.com/keep-network/keep-core/pkg/tecdsa/dkg/gen/pb"
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

// marshaledTestPreParams converts the given tss-lib local pre-parameters into
// the exact bytes the tECDSA pre-parameters storage persists, so a test
// executor can restore them through the pool's ordinary restart path instead
// of running the CPU-intensive generation. The layout mirrors the production
// PreParams marshaling.
func marshaledTestPreParams(
	t *testing.T,
	localPreParams keygen.LocalPreParams,
) []byte {
	t.Helper()

	pbPreParams := &pb.PreParams{
		Data: &pb.PreParams_LocalPreParams{
			PaillierSK: &pb.PreParams_PrivateKey{
				PublicKey: &pb.PreParams_PublicKey{
					N: localPreParams.PaillierSK.N.Bytes(),
				},
				LambdaN: localPreParams.PaillierSK.LambdaN.Bytes(),
				PhiN:    localPreParams.PaillierSK.PhiN.Bytes(),
			},
			NTilde: localPreParams.NTildei.Bytes(),
			H1I:    localPreParams.H1i.Bytes(),
			H2I:    localPreParams.H2i.Bytes(),
			Alpha:  localPreParams.Alpha.Bytes(),
			Beta:   localPreParams.Beta.Bytes(),
			P:      localPreParams.P.Bytes(),
			Q:      localPreParams.Q.Bytes(),
		},
		CreationTimestamp: timestamppb.Now(),
	}

	preParamsBytes, err := proto.Marshal(pbPreParams)
	if err != nil {
		t.Fatal(err)
	}

	return preParamsBytes
}

// newSeededTecdsaExecutor builds a real tECDSA DKG executor whose
// pre-parameters pool restores the given member's fixture pre-parameters from
// persistence — the executor's ordinary restart path — so an attempt can run
// the complete key-generation transcript without the CPU-intensive
// pre-parameters generation. The scheduler's permanently locked latch stops
// the pool's background generation within one scheduler tick.
func newSeededTecdsaExecutor(
	t *testing.T,
	localPreParams keygen.LocalPreParams,
) *dkg.Executor {
	t.Helper()

	workPersistence := &mockPersistenceHandle{
		saved: []persistence.DataDescriptor{
			&mockDescriptor{
				name:      "pp_seeded",
				directory: "preparams",
				content:   marshaledTestPreParams(t, localPreParams),
			},
		},
	}

	return dkg.NewExecutor(
		&testutils.MockLogger{},
		newTestScheduler(t),
		workPersistence,
		1,             // pool size: exactly the seeded entry
		2*time.Minute, // pre-params generation timeout
		time.Hour,     // pre-params generation delay
		1,             // pre-params generation concurrency
		10,            // key-generation concurrency, as in the protocol tests
	)
}

// dkgCutoverMemberOutcome carries one member's DKG retry-loop outcome across
// the per-member goroutine boundary.
type dkgCutoverMemberOutcome struct {
	memberIndex group.MemberIndex
	result      *dkg.Result
	sessionIDs  []string
	err         error
}

// runRealDKGCutoverMember mirrors the production per-member DKG pipeline over
// the given cutover group: one participation permit issued from the canonical
// anchor, the production broadcast-channel setup, announcer, and retry loop,
// and a real tECDSA key-generation execution per attempt. Announcer options
// let a member wire the production session-mismatch observer. The outcome is
// always delivered to the outcomes channel, exactly once.
func runRealDKGCutoverMember(
	ctx context.Context,
	cutoverGroup *dkgCutoverGroup,
	gate participation.Gate,
	groupParameters *GroupParameters,
	seed *big.Int,
	anchor uint64,
	memberIndex group.MemberIndex,
	tecdsaExecutor *dkg.Executor,
	outcomes chan<- *dkgCutoverMemberOutcome,
	announcerOptions ...announcer.Option,
) {
	outcome := &dkgCutoverMemberOutcome{memberIndex: memberIndex}
	defer func() { outcomes <- outcome }()

	permit, err := gate.Begin(participation.TBTCDKG, anchor)
	if err != nil {
		outcome.err = fmt.Errorf("gate refused the permit: [%w]", err)
		return
	}
	defer permit.Close()

	if permit.Mode() != participation.ModeSecurityV2 {
		outcome.err = fmt.Errorf(
			"unexpected permit mode [%s] for anchor [%v]",
			permit.Mode(),
			anchor,
		)
		return
	}

	channelName := fmt.Sprintf("%s-%s", ProtocolName, seed.Text(16))
	channel, err := cutoverGroup.provider(memberIndex).BroadcastChannelFor(
		channelName,
	)
	if err != nil {
		outcome.err = err
		return
	}

	dkg.RegisterUnmarshallers(channel)
	announcer.RegisterUnmarshaller(channel)
	if err := channel.SetFilter(cutoverGroup.validator.IsInGroup); err != nil {
		outcome.err = err
		return
	}

	memberAnnouncer := announcer.New(
		fmt.Sprintf("%v-%v", ProtocolName, "dkg"),
		channel,
		cutoverGroup.validator,
		announcerOptions...,
	)

	strategies, err := compatibility.StrategiesFor(permit.Mode())
	if err != nil {
		outcome.err = err
		return
	}

	retryLoop := newDkgRetryLoop(
		logger,
		seed,
		permit.Mode(),
		anchor,
		memberIndex,
		cutoverGroup.operators,
		groupParameters,
		memberAnnouncer,
		3,
	)

	waitFn := newChainWaitForBlockFn(cutoverGroup.blockCounter)

	outcome.result, outcome.err = retryLoop.start(
		ctx,
		waitFn,
		func(attempt *dkgAttemptParams) (*dkg.Result, error) {
			outcome.sessionIDs = append(outcome.sessionIDs, attempt.sessionID)

			attemptCtx, cancelAttemptCtx := withCancelOnBlock(
				ctx,
				attempt.timeoutBlock,
				waitFn,
			)
			defer cancelAttemptCtx()

			return tecdsaExecutor.Execute(
				attemptCtx,
				&testutils.MockLogger{},
				seed,
				attempt.sessionID,
				memberIndex,
				groupParameters.GroupSize,
				groupParameters.DishonestThreshold(),
				attempt.excludedMembersIndexes,
				channel,
				cutoverGroup.validator,
				strategies,
			)
		},
	)
}

// TestDKGCutover_HomogeneousSecurityV2RealKeyGeneration proves the smoke-gate-2
// homogeneous security-v2 control with a complete key-generation transcript: a
// full cohort whose ceremony is canonically anchored at the cutover block runs
// the production retry loop and announcer over real local network providers,
// executes the real tECDSA key-generation protocol under the hardened session
// ID, and every member derives the same wallet public key with no misbehavior
// evidence. The generated signers then pass through the production
// result-to-signer transformation and registry persistence, and a registry
// restart — a fresh registry over the same persistence — restores the wallet
// and all memberships. Result-publication fencing is covered separately by the
// completion-fence tests.
func TestDKGCutover_HomogeneousSecurityV2RealKeyGeneration(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       3,
		GroupQuorum:     2,
		HonestThreshold: 2,
	}

	// A block time roomy enough for the real key-generation transcript to
	// complete within one attempt's protocol window, race detector included.
	cutoverGroup := setupDKGCutoverGroup(
		t,
		groupParameters.GroupSize,
		100*time.Millisecond,
	)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(
		groupParameters.GroupSize,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Cross the cutover block before the ceremony starts: the canonical
	// anchor is the cutover block itself while the current height is already
	// past it.
	cutoverBlock := uint64(2)
	if err := cutoverGroup.blockCounter.WaitForBlockHeight(
		cutoverBlock + 1,
	); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, cutoverGroup.blockCounter, cutoverBlock)

	seed := big.NewInt(0x2C0DE)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		120*time.Second,
	)
	defer cancelLoopCtx()

	outcomes := make(
		chan *dkgCutoverMemberOutcome,
		groupParameters.GroupSize,
	)
	for i := 1; i <= groupParameters.GroupSize; i++ {
		memberIndex := group.MemberIndex(i)
		tecdsaExecutor := newSeededTecdsaExecutor(
			t,
			testData[i-1].LocalPreParams,
		)

		go runRealDKGCutoverMember(
			loopCtx,
			cutoverGroup,
			gate,
			groupParameters,
			seed,
			cutoverBlock,
			memberIndex,
			tecdsaExecutor,
			outcomes,
		)
	}

	results := make(map[group.MemberIndex]*dkg.Result)
	for i := 0; i < groupParameters.GroupSize; i++ {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf(
				"member [%v] failed: [%v]",
				outcome.memberIndex,
				outcome.err,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("attempts of member [%v]", outcome.memberIndex),
			1,
			len(outcome.sessionIDs),
		)
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt session ID of member [%v]", outcome.memberIndex),
			compatibility.SecurityV2().DKGSessionID(seed, 1),
			outcome.sessionIDs[0],
		)

		results[outcome.memberIndex] = outcome.result
	}

	referencePublicKeyBytes, err := results[1].GroupPublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	for memberIndex, result := range results {
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("misbehaved members of member [%v]", memberIndex),
			0,
			len(result.MisbehavedMembersIndexes()),
		)

		publicKeyBytes, err := result.GroupPublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(referencePublicKeyBytes, publicKeyBytes) {
			t.Errorf(
				"member [%v] derived group public key [0x%x] "+
					"instead of [0x%x]",
				memberIndex,
				publicKeyBytes,
				referencePublicKeyBytes,
			)
		}
	}

	// The production result-to-signer transformation and persistence: all
	// three memberships register against one registry, as a single node
	// controlling three seats would.
	walletPersistence := &mockPersistenceHandle{}
	walletRegistry, err := newWalletRegistry(
		walletPersistence,
		cutoverGroup.localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	registrar := &dkgExecutor{
		groupParameters: groupParameters,
		walletRegistry:  walletRegistry,
	}

	var walletPublicKey *ecdsa.PublicKey
	for memberIndex, result := range results {
		registeredSigner, err := registrar.registerSigner(
			result,
			memberIndex,
			cutoverGroup.operators,
		)
		if err != nil {
			t.Fatalf(
				"failed to register the signer of member [%v]: [%v]",
				memberIndex,
				err,
			)
		}
		walletPublicKey = registeredSigner.wallet.publicKey
	}

	testutils.AssertIntsEqual(
		t,
		"active signers after registration",
		groupParameters.GroupSize,
		len(walletRegistry.getSigners(walletPublicKey)),
	)

	// A registry restart: a fresh registry over the same persistence must
	// restore the wallet and all generated memberships.
	restartedRegistry, err := newWalletRegistry(
		walletPersistence,
		cutoverGroup.localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertIntsEqual(
		t,
		"active signers after the registry restart",
		groupParameters.GroupSize,
		len(restartedRegistry.getSigners(walletPublicKey)),
	)
}

// TestDKGCutover_RealKeyGenerationExcludesSilentPeer proves that the
// production retry loop and the real tECDSA key-generation protocol convert a
// silent post-cutover peer into misbehavior evidence: the two live members
// exclude the never-announcing seat at quorum, complete the real transcript
// without it, report it in the result's misbehaved members, and the
// production result-to-signer transformation resolves the reduced final
// signing group with remapped member indexes. This is the off-chain half of
// the 90-active/10-misbehaved consequence; the on-chain acceptance and reward
// ineligibility belong to the Solidity suite.
func TestDKGCutover_RealKeyGenerationExcludesSilentPeer(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       3,
		GroupQuorum:     2,
		HonestThreshold: 2,
	}

	cutoverGroup := setupDKGCutoverGroup(
		t,
		groupParameters.GroupSize,
		100*time.Millisecond,
	)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(
		groupParameters.GroupSize,
	)
	if err != nil {
		t.Fatal(err)
	}

	cutoverBlock := uint64(2)
	if err := cutoverGroup.blockCounter.WaitForBlockHeight(
		cutoverBlock + 1,
	); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, cutoverGroup.blockCounter, cutoverBlock)

	seed := big.NewInt(0x51137)
	silentMemberIndex := group.MemberIndex(2)
	liveMembersIndexes := []group.MemberIndex{1, 3}

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		120*time.Second,
	)
	defer cancelLoopCtx()

	outcomes := make(
		chan *dkgCutoverMemberOutcome,
		len(liveMembersIndexes),
	)
	for _, memberIndex := range liveMembersIndexes {
		tecdsaExecutor := newSeededTecdsaExecutor(
			t,
			testData[memberIndex-1].LocalPreParams,
		)

		go runRealDKGCutoverMember(
			loopCtx,
			cutoverGroup,
			gate,
			groupParameters,
			seed,
			cutoverBlock,
			memberIndex,
			tecdsaExecutor,
			outcomes,
		)
	}

	results := make(map[group.MemberIndex]*dkg.Result)
	for i := 0; i < len(liveMembersIndexes); i++ {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf(
				"member [%v] failed: [%v]",
				outcome.memberIndex,
				outcome.err,
			)
		}
		results[outcome.memberIndex] = outcome.result
	}

	referencePublicKeyBytes, err := results[1].GroupPublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, memberIndex := range liveMembersIndexes {
		result := results[memberIndex]

		misbehaved := result.MisbehavedMembersIndexes()
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("misbehaved members of member [%v]", memberIndex),
			1,
			len(misbehaved),
		)
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("misbehaved member index of member [%v]", memberIndex),
			int(silentMemberIndex),
			int(misbehaved[0]),
		)

		publicKeyBytes, err := result.GroupPublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(referencePublicKeyBytes, publicKeyBytes) {
			t.Errorf(
				"member [%v] derived group public key [0x%x] "+
					"instead of [0x%x]",
				memberIndex,
				publicKeyBytes,
				referencePublicKeyBytes,
			)
		}
	}

	// The reduced final signing group: the silent seat is dropped and the
	// remaining member indexes are remapped to consecutive positions.
	walletRegistry, err := newWalletRegistry(
		&mockPersistenceHandle{},
		cutoverGroup.localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	registrar := &dkgExecutor{
		groupParameters: groupParameters,
		walletRegistry:  walletRegistry,
	}

	expectedFinalIndexes := map[group.MemberIndex]group.MemberIndex{
		1: 1,
		3: 2,
	}
	for _, memberIndex := range liveMembersIndexes {
		registeredSigner, err := registrar.registerSigner(
			results[memberIndex],
			memberIndex,
			cutoverGroup.operators,
		)
		if err != nil {
			t.Fatalf(
				"failed to register the signer of member [%v]: [%v]",
				memberIndex,
				err,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("final signing group size of member [%v]", memberIndex),
			len(liveMembersIndexes),
			len(registeredSigner.wallet.signingGroupOperators),
		)
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("final member index of member [%v]", memberIndex),
			int(expectedFinalIndexes[memberIndex]),
			int(registeredSigner.signingGroupMemberIndex),
		)
	}
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

// TestDKGCutover_PostCutoverSplitExcludesLegacyPeersAtProductionScale proves
// the exact smoke-gate-2 90/10 exclusion arithmetic at the production group
// parameters: a post-cutover DKG selection over a hundred-member group whose
// ten prior-release seats keep announcing legacy session IDs proceeds in the
// first attempt — the security-v2 cohort alone is exactly the group quorum
// of ninety — and excludes exactly the ten legacy seats. This test pins the
// retry-loop exclusion vector only; the real result carrying key material
// and all ten excluded seats as misbehaved-members indexes is produced by
// TestDKGCutover_RealKeyGenerationExcludesTenLegacyPeers at the largest
// group this repository can drive with distinct real pre-parameters. Every
// legacy straggler is attributed to its operator in the node-local roster.
// The on-chain acceptance of the ninety-active boundary and the
// reward-ineligibility consequence live in the Solidity suite; transcript
// realness at this scale stays with the exact-image rehearsals.
func TestDKGCutover_PostCutoverSplitExcludesLegacyPeersAtProductionScale(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       100,
		GroupQuorum:     90,
		HonestThreshold: 51,
	}

	cutoverGroup := setupDKGCutoverGroup(t, groupParameters.GroupSize, 100*time.Millisecond)
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

	seed := big.NewInt(0x9010)
	protocolID := fmt.Sprintf("%v-%v", ProtocolName, "dkg")
	channelName := "dkg-cutover-split-production-scale-test"

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

	// Members 2-90 are current security-v2 peers — together with the local
	// member that is exactly the group quorum of ninety. Members 91-100 are
	// prior-release binaries that keep announcing the legacy session ID
	// after the cutover.
	firstLegacySeat := groupParameters.GroupQuorum + 1
	hardenedSessionIDs := []string{
		compatibility.SecurityV2().DKGSessionID(seed, 1),
		compatibility.SecurityV2().DKGSessionID(seed, 2),
	}
	for seat := 2; seat < firstLegacySeat; seat++ {
		memberIndex := group.MemberIndex(seat)
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
	for seat := firstLegacySeat; seat <= groupParameters.GroupSize; seat++ {
		memberIndex := group.MemberIndex(seat)
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

	// The security-v2 cohort proceeded at exactly the ninety-member quorum
	// in the first attempt and excluded exactly the ten legacy seats.
	testutils.AssertIntsEqual(t, "attempts", 1, len(attemptExclusions))
	excludedMembersIndexes := attemptExclusions[0]
	legacySeatCount := groupParameters.GroupSize - groupParameters.GroupQuorum
	testutils.AssertIntsEqual(
		t,
		"excluded members",
		legacySeatCount,
		len(excludedMembersIndexes),
	)
	for i, excludedMemberIndex := range excludedMembersIndexes {
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("excluded member at position [%v]", i),
			firstLegacySeat+i,
			int(excludedMemberIndex),
		)
	}

	// Every straggler became mismatch and cross-format evidence attributed
	// to its operator in the node-local roster.
	if mismatches := recorder.counter(
		clientinfo.MetricAnnouncerSessionIDMismatchTotal,
	); mismatches < float64(legacySeatCount) {
		t.Errorf(
			"expected at least [%v] mismatches, got [%v]",
			legacySeatCount,
			mismatches,
		)
	}
	if crossFormat := recorder.counter(
		clientinfo.MetricAnnouncerCrossFormatPeerTotal,
	); crossFormat < float64(legacySeatCount) {
		t.Errorf(
			"expected at least [%v] cross-format peers, got [%v]",
			legacySeatCount,
			crossFormat,
		)
	}

	rosterSnapshot := roster.Snapshot()
	testutils.AssertIntsEqual(
		t,
		"cutover roster operators",
		legacySeatCount,
		len(rosterSnapshot.Peers),
	)
	rosterOperatorAddresses := make(map[string]bool)
	for _, peer := range rosterSnapshot.Peers {
		rosterOperatorAddresses[peer.OperatorAddress] = true
	}
	for seat := firstLegacySeat; seat <= groupParameters.GroupSize; seat++ {
		operatorAddress := string(cutoverGroup.rosterOperators[seat-1])
		if !rosterOperatorAddresses[operatorAddress] {
			t.Errorf(
				"legacy seat [%v] operator [%s] missing from the roster",
				seat,
				operatorAddress,
			)
		}
	}
}

// TestDKGCutover_RealKeyGenerationExcludesLegacyPeerAtQuorum proves the
// off-chain half of the smoke-gate-2 90/10 consequence with a real
// transcript: a post-cutover DKG selection contains a live prior-release
// peer that keeps announcing the legacy session ID, the security-v2 cohort
// proceeds once it alone reaches the group quorum, completes the real tECDSA
// key-generation protocol without the legacy seat, and reports that seat in
// the result's misbehaved members — the exact output the submitted result
// carries into the Solidity suite's boundary acceptance and reward-ban
// proof. The straggler also becomes mismatch metrics and roster evidence
// attributed to its operator, and the production result-to-signer
// transformation resolves the reduced final signing group with remapped
// member indexes.
func TestDKGCutover_RealKeyGenerationExcludesLegacyPeerAtQuorum(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       3,
		GroupQuorum:     2,
		HonestThreshold: 2,
	}

	cutoverGroup := setupDKGCutoverGroup(
		t,
		groupParameters.GroupSize,
		100*time.Millisecond,
	)

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(
		groupParameters.GroupSize,
	)
	if err != nil {
		t.Fatal(err)
	}

	cutoverBlock := uint64(2)
	if err := cutoverGroup.blockCounter.WaitForBlockHeight(
		cutoverBlock + 1,
	); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, cutoverGroup.blockCounter, cutoverBlock)

	seed := big.NewInt(0x1E6AC1)
	legacyMemberIndex := group.MemberIndex(3)
	liveMembersIndexes := []group.MemberIndex{1, 2}

	recorder := newDispatcherMetricsRecorder()
	roster, err := participation.NewCutoverPeerRoster(
		context.Background(),
		cutoverGroup.blockCounter,
		1500,
		newCutoverFakeMetrics(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roster.Close)

	// The first live member observes announcement mismatches exactly like
	// the production DKG executor wires them: stragglers become metrics and
	// roster evidence. The permit mode is pinned to security-v2 by the
	// member pipeline itself.
	mismatchObserver := announcer.WithSessionMismatchObserver(func(
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
			participation.ModeSecurityV2,
			cutoverGroup.rosterOperators,
			observedProtocolID,
			sender,
			expectedFormat,
			observedFormat,
		)
	})

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	// Seat 3 is a prior-release binary that keeps announcing the legacy
	// session IDs after the cutover, on the same channel the live members
	// use for the ceremony.
	startPeerAnnouncer(
		peersCtx,
		t,
		cutoverGroup.provider(legacyMemberIndex),
		fmt.Sprintf("%s-%s", ProtocolName, seed.Text(16)),
		cutoverGroup.validator,
		fmt.Sprintf("%v-%v", ProtocolName, "dkg"),
		legacyMemberIndex,
		[]string{
			compatibility.Legacy().DKGSessionID(seed, 1),
			compatibility.Legacy().DKGSessionID(seed, 2),
		},
	)

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		120*time.Second,
	)
	defer cancelLoopCtx()

	outcomes := make(
		chan *dkgCutoverMemberOutcome,
		len(liveMembersIndexes),
	)
	for _, memberIndex := range liveMembersIndexes {
		tecdsaExecutor := newSeededTecdsaExecutor(
			t,
			testData[memberIndex-1].LocalPreParams,
		)

		var announcerOptions []announcer.Option
		if memberIndex == liveMembersIndexes[0] {
			announcerOptions = append(announcerOptions, mismatchObserver)
		}

		go runRealDKGCutoverMember(
			loopCtx,
			cutoverGroup,
			gate,
			groupParameters,
			seed,
			cutoverBlock,
			memberIndex,
			tecdsaExecutor,
			outcomes,
			announcerOptions...,
		)
	}

	results := make(map[group.MemberIndex]*dkg.Result)
	for i := 0; i < len(liveMembersIndexes); i++ {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf(
				"member [%v] failed: [%v]",
				outcome.memberIndex,
				outcome.err,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("attempts of member [%v]", outcome.memberIndex),
			1,
			len(outcome.sessionIDs),
		)
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt session ID of member [%v]", outcome.memberIndex),
			compatibility.SecurityV2().DKGSessionID(seed, 1),
			outcome.sessionIDs[0],
		)

		results[outcome.memberIndex] = outcome.result
	}
	cancelPeers()

	referencePublicKeyBytes, err := results[1].GroupPublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, memberIndex := range liveMembersIndexes {
		result := results[memberIndex]

		misbehaved := result.MisbehavedMembersIndexes()
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("misbehaved members of member [%v]", memberIndex),
			1,
			len(misbehaved),
		)
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("misbehaved member index of member [%v]", memberIndex),
			int(legacyMemberIndex),
			int(misbehaved[0]),
		)

		publicKeyBytes, err := result.GroupPublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(referencePublicKeyBytes, publicKeyBytes) {
			t.Errorf(
				"member [%v] derived group public key [0x%x] "+
					"instead of [0x%x]",
				memberIndex,
				publicKeyBytes,
				referencePublicKeyBytes,
			)
		}
	}

	// The reduced final signing group: the legacy seat is dropped and the
	// remaining member indexes are remapped to consecutive positions.
	walletRegistry, err := newWalletRegistry(
		&mockPersistenceHandle{},
		cutoverGroup.localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	registrar := &dkgExecutor{
		groupParameters: groupParameters,
		walletRegistry:  walletRegistry,
	}

	expectedFinalIndexes := map[group.MemberIndex]group.MemberIndex{
		1: 1,
		2: 2,
	}
	for _, memberIndex := range liveMembersIndexes {
		registeredSigner, err := registrar.registerSigner(
			results[memberIndex],
			memberIndex,
			cutoverGroup.operators,
		)
		if err != nil {
			t.Fatalf(
				"failed to register the signer of member [%v]: [%v]",
				memberIndex,
				err,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("final signing group size of member [%v]", memberIndex),
			len(liveMembersIndexes),
			len(registeredSigner.wallet.signingGroupOperators),
		)
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("final member index of member [%v]", memberIndex),
			int(expectedFinalIndexes[memberIndex]),
			int(registeredSigner.signingGroupMemberIndex),
		)
	}

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
		string(cutoverGroup.rosterOperators[legacyMemberIndex-1]),
		rosterSnapshot.Peers[0].OperatorAddress,
	)
}

// TestDKGCutover_RealKeyGenerationExcludesTenLegacyPeers proves the full
// ten-misbehaved-seat consequence of the post-cutover split with a real
// transcript: ten prior-release seats keep announcing legacy session IDs
// after the cutover, the security-v2 cohort — exactly the group quorum —
// runs the real tECDSA key-generation protocol without them, and every
// cohort member's result carries real key material together with all ten
// excluded seats as misbehaved-members indexes, the exact result shape whose
// hundred-member equivalent the Solidity suite accepts at the ninety-active
// boundary and punishes with the reward ban. The group size is the largest
// this repository can drive with distinct real pre-parameters per live
// member; the same arithmetic at the production hundred-member parameters is
// proven by TestDKGCutover_PostCutoverSplitExcludesLegacyPeersAtProductionScale
// and the exact-image rehearsals. All ten stragglers become mismatch metrics
// and deduplicated roster evidence, and the production result-to-signer
// transformation remaps the four survivors to consecutive final indexes.
func TestDKGCutover_RealKeyGenerationExcludesTenLegacyPeers(t *testing.T) {
	groupParameters := &GroupParameters{
		GroupSize:       14,
		GroupQuorum:     4,
		HonestThreshold: 4,
	}

	// A block time roomy enough for the four-party key-generation transcript
	// to complete within one attempt's protocol window, race detector
	// included.
	cutoverGroup := setupDKGCutoverGroup(
		t,
		groupParameters.GroupSize,
		200*time.Millisecond,
	)

	liveMembersIndexes := []group.MemberIndex{1, 12, 13, 14}
	legacyMembersIndexes := []group.MemberIndex{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(
		len(liveMembersIndexes),
	)
	if err != nil {
		t.Fatal(err)
	}

	cutoverBlock := uint64(2)
	if err := cutoverGroup.blockCounter.WaitForBlockHeight(
		cutoverBlock + 1,
	); err != nil {
		t.Fatal(err)
	}

	gate := newTestGateWithCutover(t, cutoverGroup.blockCounter, cutoverBlock)

	seed := big.NewInt(0x10E14)

	recorder := newDispatcherMetricsRecorder()
	roster, err := participation.NewCutoverPeerRoster(
		context.Background(),
		cutoverGroup.blockCounter,
		1500,
		newCutoverFakeMetrics(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roster.Close)

	// The first live member observes announcement mismatches exactly like
	// the production DKG executor wires them: stragglers become metrics and
	// roster evidence.
	mismatchObserver := announcer.WithSessionMismatchObserver(func(
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
			participation.ModeSecurityV2,
			cutoverGroup.rosterOperators,
			observedProtocolID,
			sender,
			expectedFormat,
			observedFormat,
		)
	})

	peersCtx, cancelPeers := context.WithCancel(context.Background())
	defer cancelPeers()

	// Seats 2-11 are prior-release binaries that keep announcing the legacy
	// session IDs after the cutover, on the same channel the live members
	// use for the ceremony.
	for _, legacyMemberIndex := range legacyMembersIndexes {
		startPeerAnnouncer(
			peersCtx,
			t,
			cutoverGroup.provider(legacyMemberIndex),
			fmt.Sprintf("%s-%s", ProtocolName, seed.Text(16)),
			cutoverGroup.validator,
			fmt.Sprintf("%v-%v", ProtocolName, "dkg"),
			legacyMemberIndex,
			[]string{
				compatibility.Legacy().DKGSessionID(seed, 1),
				compatibility.Legacy().DKGSessionID(seed, 2),
			},
		)
	}

	loopCtx, cancelLoopCtx := context.WithTimeout(
		context.Background(),
		300*time.Second,
	)
	defer cancelLoopCtx()

	outcomes := make(
		chan *dkgCutoverMemberOutcome,
		len(liveMembersIndexes),
	)
	for i, memberIndex := range liveMembersIndexes {
		tecdsaExecutor := newSeededTecdsaExecutor(
			t,
			testData[i].LocalPreParams,
		)

		var announcerOptions []announcer.Option
		if memberIndex == liveMembersIndexes[0] {
			announcerOptions = append(announcerOptions, mismatchObserver)
		}

		go runRealDKGCutoverMember(
			loopCtx,
			cutoverGroup,
			gate,
			groupParameters,
			seed,
			cutoverBlock,
			memberIndex,
			tecdsaExecutor,
			outcomes,
			announcerOptions...,
		)
	}

	results := make(map[group.MemberIndex]*dkg.Result)
	for i := 0; i < len(liveMembersIndexes); i++ {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf(
				"member [%v] failed: [%v]",
				outcome.memberIndex,
				outcome.err,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("attempts of member [%v]", outcome.memberIndex),
			1,
			len(outcome.sessionIDs),
		)
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("attempt session ID of member [%v]", outcome.memberIndex),
			compatibility.SecurityV2().DKGSessionID(seed, 1),
			outcome.sessionIDs[0],
		)

		results[outcome.memberIndex] = outcome.result
	}
	cancelPeers()

	referencePublicKeyBytes, err := results[1].GroupPublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(referencePublicKeyBytes) == 0 {
		t.Fatal("expected non-empty group public key bytes")
	}
	for _, memberIndex := range liveMembersIndexes {
		result := results[memberIndex]

		// The real result must report every one of the ten excluded seats —
		// and nothing else — as misbehaved.
		misbehaved := result.MisbehavedMembersIndexes()
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("misbehaved members of member [%v]", memberIndex),
			len(legacyMembersIndexes),
			len(misbehaved),
		)
		for i, legacyMemberIndex := range legacyMembersIndexes {
			testutils.AssertIntsEqual(
				t,
				fmt.Sprintf(
					"misbehaved member at position [%v] of member [%v]",
					i,
					memberIndex,
				),
				int(legacyMemberIndex),
				int(misbehaved[i]),
			)
		}

		publicKeyBytes, err := result.GroupPublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(referencePublicKeyBytes, publicKeyBytes) {
			t.Errorf(
				"member [%v] derived group public key [0x%x] "+
					"instead of [0x%x]",
				memberIndex,
				publicKeyBytes,
				referencePublicKeyBytes,
			)
		}
	}

	// The reduced final signing group: the ten legacy seats are dropped and
	// the four remaining member indexes are remapped to consecutive
	// positions.
	walletRegistry, err := newWalletRegistry(
		&mockPersistenceHandle{},
		cutoverGroup.localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	registrar := &dkgExecutor{
		groupParameters: groupParameters,
		walletRegistry:  walletRegistry,
	}

	expectedFinalIndexes := map[group.MemberIndex]group.MemberIndex{
		1:  1,
		12: 2,
		13: 3,
		14: 4,
	}
	for _, memberIndex := range liveMembersIndexes {
		registeredSigner, err := registrar.registerSigner(
			results[memberIndex],
			memberIndex,
			cutoverGroup.operators,
		)
		if err != nil {
			t.Fatalf(
				"failed to register the signer of member [%v]: [%v]",
				memberIndex,
				err,
			)
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("final signing group size of member [%v]", memberIndex),
			len(liveMembersIndexes),
			len(registeredSigner.wallet.signingGroupOperators),
		)
		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("final member index of member [%v]", memberIndex),
			int(expectedFinalIndexes[memberIndex]),
			int(registeredSigner.signingGroupMemberIndex),
		)
	}

	// Every straggler became mismatch and cross-format evidence attributed
	// to its operator in the node-local roster, deduplicated to the ten
	// distinct operators.
	if mismatches := recorder.counter(
		clientinfo.MetricAnnouncerSessionIDMismatchTotal,
	); mismatches < float64(len(legacyMembersIndexes)) {
		t.Errorf(
			"expected at least [%v] mismatches, got [%v]",
			len(legacyMembersIndexes),
			mismatches,
		)
	}
	if crossFormat := recorder.counter(
		clientinfo.MetricAnnouncerCrossFormatPeerTotal,
	); crossFormat < float64(len(legacyMembersIndexes)) {
		t.Errorf(
			"expected at least [%v] cross-format peers, got [%v]",
			len(legacyMembersIndexes),
			crossFormat,
		)
	}

	rosterSnapshot := roster.Snapshot()
	testutils.AssertIntsEqual(
		t,
		"cutover roster operators",
		len(legacyMembersIndexes),
		len(rosterSnapshot.Peers),
	)
	rosterOperatorAddresses := make(map[string]bool)
	for _, peer := range rosterSnapshot.Peers {
		rosterOperatorAddresses[peer.OperatorAddress] = true
	}
	for _, legacyMemberIndex := range legacyMembersIndexes {
		operatorAddress := string(
			cutoverGroup.rosterOperators[legacyMemberIndex-1],
		)
		if !rosterOperatorAddresses[operatorAddress] {
			t.Errorf(
				"legacy seat [%v] operator [%s] missing from the roster",
				legacyMemberIndex,
				operatorAddress,
			)
		}
	}
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
