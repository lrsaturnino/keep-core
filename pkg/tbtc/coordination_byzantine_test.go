package tbtc

// Tier-2 Byzantine coordination harness. tBTC's interceptable Byzantine surface
// is the wallet coordination procedure: a per-window leader broadcasts an action
// proposal and followers receive + validate it. Unlike DKG/signing (one shared
// channel, sender-attributed strategies), coordination uses PER-OPERATOR
// channels, so Byzantine behavior is expressed by wrapping a specific operator's
// outbound channel with an interception.Strategy.
//
// This harness lives in package tbtc (not a pkg/internal/* package like dkgtest
// or signingtest) because the coordination machinery - newCoordinationExecutor,
// coordinate, wallet, coordinationWindow, the local chain - is all unexported.
// Exporting it purely for tests would widen the production API for no runtime
// benefit; a test-only helper here is reusable by any test in the package, which
// is the maximal reuse Go visibility allows. It generalizes the setup of
// TestCoordinationExecutor_Coordinate, adding per-operator strategy injection.

import (
	"context"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/internal/interception"
	"github.com/keep-network/keep-core/pkg/net"
	netlocal "github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// byzantineCoordinationReport is one operator's outcome from a coordination run.
type byzantineCoordinationReport struct {
	operatorIndex int
	address       chain.Address
	result        *coordinationResult
	err           error
}

// dropAll is a channel-level Byzantine strategy: it drops every message the
// operator tries to send. Applied to a leader's channel, it models a leader that
// generates a proposal but never broadcasts it (silent/withholding leader).
func dropAll(interception.Outbound) []net.TaggedMarshaler { return nil }

// runByzantineCoordination sets up the canonical 3-operator / 10-seat redemption
// coordination scenario (deterministic operator keys => stable leader selection,
// matching TestCoordinationExecutor_Coordinate) and runs coordinate() for each
// operator concurrently. The outbound channel of operator i (1-based) is wrapped
// with strategies[i]; operators absent from the map get interception.PassThrough.
// channelName isolates this run in the process-global local broadcast registry.
func runByzantineCoordination(
	t *testing.T,
	channelName string,
	blockTime time.Duration,
	strategies map[int]interception.Strategy,
) []*byzantineCoordinationReport {
	publicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	var publicKeyHash [20]byte
	buffer, err := hex.DecodeString("aa768412ceed10bd423c025542ca90071f9fb62d")
	if err != nil {
		t.Fatal(err)
	}
	copy(publicKeyHash[:], buffer)

	parseScript := func(script string) bitcoin.Script {
		parsed, err := hex.DecodeString(script)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}

	coordinationBlock := uint64(900)

	type operatorFixture struct {
		chain              Chain
		address            chain.Address
		channel            net.BroadcastChannel
		waitForBlockHeight func(ctx context.Context, blockHeight uint64) error
	}

	generateOperator := func(index int, privateKey int64) *operatorFixture {
		// Deterministic addresses so leader selection is stable across runs.
		privateKeyBigInt := big.NewInt(privateKey)
		x, y := local_v1.DefaultCurve.ScalarBaseMult(privateKeyBigInt.Bytes())

		localChain := ConnectWithKey(
			&operator.PrivateKey{
				PublicKey: operator.PublicKey{
					Curve: operator.Secp256k1,
					X:     x,
					Y:     y,
				},
				D: privateKeyBigInt,
			},
			blockTime,
		)

		localChain.setBlockHashByNumber(
			coordinationBlock-32,
			"1422996cbcbc38fc924a46f4df5f9064279d3ab43396e58386dac9b87440d64f",
		)

		operatorAddress, err := localChain.operatorAddress()
		if err != nil {
			t.Fatal(err)
		}

		_, operatorPublicKey, err := localChain.OperatorKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		strategy := interception.PassThrough
		if s, ok := strategies[index]; ok {
			strategy = s
		}

		// Wrap this operator's outbound channel with its Byzantine strategy.
		broadcastChannel, err := interception.NewNetworkWithStrategy(
			netlocal.ConnectWithKey(operatorPublicKey),
			strategy,
		).BroadcastChannelFor(channelName)
		if err != nil {
			t.Fatal(err)
		}

		broadcastChannel.SetUnmarshaler(func() net.TaggedUnmarshaler {
			return &coordinationMessage{}
		})

		waitForBlockHeight := func(ctx context.Context, blockHeight uint64) error {
			blockCounter, err := localChain.BlockCounter()
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
			}
			return nil
		}

		return &operatorFixture{
			chain:              localChain,
			address:            operatorAddress,
			channel:            broadcastChannel,
			waitForBlockHeight: waitForBlockHeight,
		}
	}

	operator1 := generateOperator(1, 1)
	operator2 := generateOperator(2, 2)
	operator3 := generateOperator(3, 3)

	coordinatedWallet := wallet{
		publicKey: mustUnmarshalPublicKey(t, publicKeyHex),
		signingGroupOperators: []chain.Address{
			operator2.address,
			operator3.address,
			operator1.address,
			operator1.address,
			operator3.address,
			operator2.address,
			operator2.address,
			operator3.address,
			operator1.address,
			operator1.address,
		},
	}

	proposalGenerator := newMockCoordinationProposalGenerator(
		func(
			walletPublicKeyHash [20]byte,
			actionsChecklist []WalletActionType,
			_ uint,
		) (CoordinationProposal, error) {
			for _, action := range actionsChecklist {
				if walletPublicKeyHash == publicKeyHash && action == ActionRedemption {
					return &RedemptionProposal{
						RedeemersOutputScripts: []bitcoin.Script{
							parseScript("00148db50eb52063ea9d98b3eac91489a90f738986f6"),
							parseScript("76a9148db50eb52063ea9d98b3eac91489a90f738986f688ac"),
						},
						RedemptionTxFee: big.NewInt(10000),
					}, nil
				}
			}
			return &NoopProposal{}, nil
		},
	)

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		coordinatedWallet.signingGroupOperators,
		Connect().Signing(),
	)

	protocolLatch := generator.NewProtocolLatch()

	generateExecutor := func(op *operatorFixture) *coordinationExecutor {
		return newCoordinationExecutor(
			op.chain,
			coordinatedWallet,
			coordinatedWallet.membersByOperator(op.address),
			op.address,
			proposalGenerator,
			op.channel,
			membershipValidator,
			protocolLatch,
			op.waitForBlockHeight,
		)
	}

	window := newCoordinationWindow(coordinationBlock)

	reportChan := make(chan *byzantineCoordinationReport, 3)

	for i, op := range []*operatorFixture{operator1, operator2, operator3} {
		go func(operatorIndex int, op *operatorFixture) {
			result, err := generateExecutor(op).coordinate(context.Background(), window)
			reportChan <- &byzantineCoordinationReport{
				operatorIndex: operatorIndex,
				address:       op.address,
				result:        result,
				err:           err,
			}
		}(i+1, op)
	}

	reports := make([]*byzantineCoordinationReport, 0, 3)
	for len(reports) < 3 {
		reports = append(reports, <-reportChan)
	}
	slices.SortFunc(reports, func(a, b *byzantineCoordinationReport) int {
		return a.operatorIndex - b.operatorIndex
	})

	return reports
}

// TestByzantineCoordination_HonestBaseline runs the harness with no Byzantine
// strategy and confirms it reproduces the known-good coordination outcome:
// operator 2 is leader, all three operators agree on the redemption proposal,
// none errors. This is the equivalence proof that the interception seam (with
// PassThrough) does not perturb the protocol.
func TestByzantineCoordination_HonestBaseline(t *testing.T) {
	reports := runByzantineCoordination(t, t.Name(), 100*time.Millisecond, nil)

	testutils.AssertIntsEqual(t, "reports count", 3, len(reports))

	leader := reports[1].address // operator 2 is the expected leader

	for _, r := range reports {
		if r.err != nil {
			t.Errorf("operator %d errored: %v", r.operatorIndex, r.err)
			continue
		}
		if r.result == nil {
			t.Errorf("operator %d produced a nil result", r.operatorIndex)
			continue
		}
		if r.result.leader != leader {
			t.Errorf(
				"operator %d saw leader %s; want %s",
				r.operatorIndex, r.result.leader, leader,
			)
		}
		if r.result.proposal.ActionType() != ActionRedemption {
			t.Errorf(
				"operator %d coordinated action %v; want %v",
				r.operatorIndex, r.result.proposal.ActionType(), ActionRedemption,
			)
		}
		if len(r.result.faults) != 0 {
			t.Errorf("operator %d observed faults: %v", r.operatorIndex, r.result.faults)
		}
	}
}

// TestByzantineCoordination_WithholdingLeader applies a drop-all strategy to the
// leader's (operator 2's) outbound channel: the leader generates a proposal but
// never broadcasts it. The safety invariant under test is that a silent leader
// causes a denial of service (followers coordinate NO action) but can never make
// followers act on a proposal they did not receive, and cannot split them onto
// divergent outcomes. Fast blocks bound the follower timeout (active phase ends
// at coordinationBlock+80).
func TestByzantineCoordination_WithholdingLeader(t *testing.T) {
	reports := runByzantineCoordination(
		t,
		t.Name(),
		5*time.Millisecond,
		map[int]interception.Strategy{2: dropAll}, // operator 2 is the leader
	)

	testutils.AssertIntsEqual(t, "reports count", 3, len(reports))

	leaderReport := reports[1] // operator 2
	follower1 := reports[0]    // operator 1
	follower3 := reports[2]    // operator 3

	// The leader generated its proposal locally and believes it broadcast it.
	if leaderReport.err != nil {
		t.Errorf("leader (operator 2) errored: %v", leaderReport.err)
	}

	// Each follower fails to receive the withheld proposal and coordinates NO
	// action - a denial of service, not an unauthorized action.
	for _, f := range []*byzantineCoordinationReport{follower1, follower3} {
		if f.err == nil {
			t.Errorf("follower %d unexpectedly succeeded with a withholding leader", f.operatorIndex)
		}
		if f.result == nil {
			t.Errorf("follower %d produced no result", f.operatorIndex)
			continue
		}
		if f.result.proposal != nil {
			t.Errorf(
				"SAFETY VIOLATION: follower %d acted on a proposal (%v) it never received",
				f.operatorIndex, f.result.proposal.ActionType(),
			)
		}
	}

	// No split-brain: both followers reached the same (no-proposal) outcome.
	if (follower1.result.proposal == nil) != (follower3.result.proposal == nil) {
		t.Errorf("followers diverged: f1.proposal=%v f3.proposal=%v",
			follower1.result.proposal, follower3.result.proposal)
	}

	t.Logf("withholding leader: followers coordinated no action (DoS); leader err=%v", leaderReport.err)
}
