package beacon

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-common/pkg/persistence"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/beacon/event"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/generator"
	netLocal "github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// cutoverFakePersistence is an accept-everything persistence handle: signer
// registration succeeds without touching disk.
type cutoverFakePersistence struct{}

func (cutoverFakePersistence) Save([]byte, string, string) error     { return nil }
func (cutoverFakePersistence) Snapshot([]byte, string, string) error { return nil }
func (cutoverFakePersistence) Archive(string) error                  { return nil }
func (cutoverFakePersistence) ReadAll() (
	<-chan persistence.DataDescriptor,
	<-chan error,
) {
	data := make(chan persistence.DataDescriptor)
	errs := make(chan error)
	close(data)
	close(errs)
	return data, errs
}

// cutoverTestChain delegates to the local chain but returns a fixed group
// selection, since the local chain does not implement SelectGroup.
type cutoverTestChain struct {
	beaconchain.Interface
	selectedOperators chain.Addresses
}

func (c *cutoverTestChain) SelectGroup(*big.Int) (chain.Addresses, error) {
	return c.selectedOperators, nil
}

// cutoverGateMetrics is a race-safe recording sink for the participation gate.
type cutoverGateMetrics struct {
	mu       sync.Mutex
	counters map[string]float64
}

func newCutoverGateMetrics() *cutoverGateMetrics {
	return &cutoverGateMetrics{counters: make(map[string]float64)}
}

func (m *cutoverGateMetrics) IncrementCounter(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] += value
}

func (m *cutoverGateMetrics) SetGauge(string, float64) {}

func (m *cutoverGateMetrics) counter(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

// cutoverLocalChain is the local chain surface the harness needs: the full
// beacon chain interface plus the local result getter.
type cutoverLocalChain interface {
	beaconchain.Interface
	GetLastDKGResult() (
		*beaconchain.DKGResult,
		map[beaconchain.GroupMemberIndex][]byte,
	)
}

// cutoverNodeHarness bundles everything a node-level cutover test drives.
type cutoverNodeHarness struct {
	node        *node
	localChain  cutoverLocalChain
	gate        participation.Gate
	gateMetrics *cutoverGateMetrics
	anchorBlock uint64
	groupSize   int
}

// newCutoverNodeHarness builds a beacon node over the local chain and network
// with a real participation gate. The cutover block is derived from the
// current chain height through cutoverBlockFor, after the chain reached at
// least block one so the anchor is never zero. A nil selection puts the
// node's operator in every seat; a custom selection lets externally driven
// members hold the remaining seats.
func newCutoverNodeHarness(
	t *testing.T,
	groupSize int,
	honestThreshold int,
	cutoverBlockFor func(currentBlock uint64) uint64,
	selectionFor func(nodeAddress chain.Address) chain.Addresses,
) *cutoverNodeHarness {
	t.Helper()

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := local_v1.ConnectWithKey(
		groupSize,
		honestThreshold,
		operatorPrivateKey,
	)

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}
	currentBlock, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	gateMetrics := newCutoverGateMetrics()
	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: cutoverBlockFor(currentBlock)},
		blockCounter,
		gateMetrics,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	address, err := localChain.Signing().PublicKeyToAddress(operatorPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var selectedOperators chain.Addresses
	if selectionFor != nil {
		selectedOperators = selectionFor(address)
	} else {
		selectedOperators = make(chain.Addresses, groupSize)
		for i := range selectedOperators {
			selectedOperators[i] = address
		}
	}
	if len(selectedOperators) != groupSize {
		t.Fatalf(
			"selection has [%d] seats for group size [%d]",
			len(selectedOperators),
			groupSize,
		)
	}

	testChain := &cutoverTestChain{
		Interface:         localChain,
		selectedOperators: selectedOperators,
	}

	groupRegistry := registry.NewGroupRegistry(
		logger,
		testChain,
		cutoverFakePersistence{},
	)

	node := newNode(
		testChain,
		netLocal.ConnectWithKey(operatorPublicKey),
		groupRegistry,
		generator.StartScheduler(),
		gate,
	)

	return &cutoverNodeHarness{
		node:        node,
		localChain:  localChain,
		gate:        gate,
		gateMetrics: gateMetrics,
		anchorBlock: currentBlock,
		groupSize:   groupSize,
	}
}

func cutoverRandomSeed(t *testing.T) *big.Int {
	t.Helper()
	seed, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// runCeremonyToCompletion joins the DKG at the harness anchor and waits for
// the result publication and for every permit to be released.
func (h *cutoverNodeHarness) runCeremonyToCompletion(
	t *testing.T,
	seed *big.Int,
) {
	t.Helper()

	resultChan := make(chan uint64, h.groupSize)
	_ = h.localChain.OnDKGResultSubmitted(
		func(submission *event.DKGResultSubmission) {
			resultChan <- submission.BlockNumber
		},
	)

	h.node.JoinDKGIfEligible(seed, h.anchorBlock)

	select {
	case <-resultChan:
	case <-time.After(120 * time.Second):
		t.Fatal("no DKG result published before the timeout")
	}

	// Members close their permits after signer registration; wait for the
	// gate to drain so the assertion sees final accounting.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if h.gate.State().ActiveCeremonies == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("permits were not released after the ceremony completed")
}

// TestJoinDKGIfEligible_AnchorBelowCutoverRunsLegacyCeremony proves the node
// path end to end for a pre-cutover anchor: every locally controlled member
// receives a legacy permit from the shared gate and the homogeneous legacy
// ceremony completes, publishing a result.
func TestJoinDKGIfEligible_AnchorBelowCutoverRunsLegacyCeremony(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		5,
		3,
		// The anchor stays far below the cutover block for the whole run.
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)

	harness.runCeremonyToCompletion(t, cutoverRandomSeed(t))

	legacy := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeLegacyTotal,
	)
	securityV2 := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeSecurityV2Total,
	)
	if legacy != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] legacy permits, got [%f]",
			harness.groupSize,
			legacy,
		)
	}
	if securityV2 != 0 {
		t.Errorf("expected no security-v2 permits, got [%f]", securityV2)
	}
}

// TestJoinDKGIfEligible_AnchorAtCutoverRunsSecurityV2Ceremony proves the exact
// boundary through the node path: an anchor equal to the cutover block pins
// security-v2 for every local member and the homogeneous ceremony completes.
func TestJoinDKGIfEligible_AnchorAtCutoverRunsSecurityV2Ceremony(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		5,
		3,
		// The cutover block equals the anchor: anchor >= C selects
		// security-v2 from the first cutover block onward.
		func(currentBlock uint64) uint64 { return currentBlock },
		nil,
	)

	harness.runCeremonyToCompletion(t, cutoverRandomSeed(t))

	legacy := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeLegacyTotal,
	)
	securityV2 := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeSecurityV2Total,
	)
	if securityV2 != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] security-v2 permits, got [%f]",
			harness.groupSize,
			securityV2,
		)
	}
	if legacy != 0 {
		t.Errorf("expected no legacy permits, got [%f]", legacy)
	}
}

// TestJoinDKGIfEligible_QuiescedGateRefusesParticipation proves a quiescing
// gate refuses every local member synchronously: no member goroutine starts,
// no protocol traffic is sent, and no result can appear.
func TestJoinDKGIfEligible_QuiescedGateRefusesParticipation(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		5,
		3,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)

	harness.gate.Quiesce(fmt.Errorf("test shutdown"))

	harness.node.JoinDKGIfEligible(cutoverRandomSeed(t), harness.anchorBlock)

	refusals := harness.gateMetrics.counter(
		clientinfo.MetricParticipationRefusalsTotal,
	)
	if refusals != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] gate refusals, got [%f]",
			harness.groupSize,
			refusals,
		)
	}
	ceremonyRefusals := harness.gateMetrics.counter(
		clientinfo.ParticipationRefusalMetricName(
			string(participation.BeaconDKG),
		),
	)
	if ceremonyRefusals != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] beacon DKG refusals, got [%f]",
			harness.groupSize,
			ceremonyRefusals,
		)
	}
	if modes := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeLegacyTotal,
	) + harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeSecurityV2Total,
	); modes != 0 {
		t.Errorf("expected no permits to be issued, got [%f]", modes)
	}
	if result, _ := harness.localChain.GetLastDKGResult(); result != nil {
		t.Error("expected no DKG result with a quiesced gate")
	}
	if active := harness.gate.State().ActiveCeremonies; active != 0 {
		t.Errorf("expected no active ceremonies, got [%d]", active)
	}
}

// TestJoinDKGIfEligible_NilGateFailsClosed proves a node without a gate
// refuses DKG participation instead of selecting a protocol mode implicitly.
func TestJoinDKGIfEligible_NilGateFailsClosed(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		5,
		3,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)
	harness.node.participationGate = nil

	harness.node.JoinDKGIfEligible(cutoverRandomSeed(t), harness.anchorBlock)

	if result, _ := harness.localChain.GetLastDKGResult(); result != nil {
		t.Error("expected no DKG result without a participation gate")
	}
}

// signingOverrideChain shares the local chain's state and clock but signs
// with a different operator key, so externally driven members hold their own
// group seats.
type signingOverrideChain struct {
	beaconchain.Interface
	signer chain.Signing
}

func (c *signingOverrideChain) Signing() chain.Signing { return c.signer }

// TestJoinDKGIfEligible_LegacyAnchorInteroperatesWithLegacyPeers is the
// discriminating proof that the node derives the ceremony bundle from the
// permit rather than pinning one mode: the node controls two seats through
// the gate at a pre-cutover anchor, while three seats run standalone members
// with an explicitly legacy bundle — the pre-cutover peer behavior. The
// honest threshold of four is reachable only if the node's members actually
// speak legacy; a node wrongly selecting security-v2 would split the group
// into cohorts of two and three, neither reaching the threshold, and no
// result could be published.
func TestJoinDKGIfEligible_LegacyAnchorInteroperatesWithLegacyPeers(t *testing.T) {
	groupSize := 5
	honestThreshold := 4

	externalPrivateKey, externalPublicKey, err := operator.GenerateKeyPair(
		local_v1.DefaultCurve,
	)
	if err != nil {
		t.Fatal(err)
	}
	externalSigner := local_v1.NewSigner(externalPrivateKey)
	externalAddress, err := externalSigner.PublicKeyToAddress(externalPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	var selectedOperators chain.Addresses
	harness := newCutoverNodeHarness(
		t,
		groupSize,
		honestThreshold,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		func(nodeAddress chain.Address) chain.Addresses {
			selectedOperators = chain.Addresses{
				nodeAddress,
				nodeAddress,
				externalAddress,
				externalAddress,
				externalAddress,
			}
			return selectedOperators
		},
	)

	seed := cutoverRandomSeed(t)

	externalChain := &signingOverrideChain{
		Interface: harness.localChain,
		signer:    externalSigner,
	}
	externalProvider := netLocal.ConnectWithKey(externalPublicKey)
	externalChannel, err := externalProvider.BroadcastChannelFor(
		fmt.Sprintf("%s-%s", ProtocolName, seed.Text(16)),
	)
	if err != nil {
		t.Fatal(err)
	}
	membershipValidator := group.NewMembershipValidator(
		logger,
		selectedOperators,
		externalSigner,
	)

	externalErrors := make(chan error, 3)
	var externalWait sync.WaitGroup
	for _, memberIndex := range []group.MemberIndex{3, 4, 5} {
		externalWait.Add(1)
		go func(memberIndex group.MemberIndex) {
			defer externalWait.Done()
			_, err := dkg.ExecuteDKG(
				logger,
				seed,
				memberIndex,
				harness.anchorBlock,
				externalChain,
				externalChannel,
				membershipValidator,
				selectedOperators,
				compatibility.Legacy(),
			)
			if err != nil {
				externalErrors <- fmt.Errorf(
					"external member [%v]: %w",
					memberIndex,
					err,
				)
			}
		}(memberIndex)
	}

	harness.runCeremonyToCompletion(t, seed)

	externalWait.Wait()
	close(externalErrors)
	for err := range externalErrors {
		t.Errorf("external legacy member failed: [%v]", err)
	}

	legacy := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeLegacyTotal,
	)
	securityV2 := harness.gateMetrics.counter(
		clientinfo.MetricParticipationModeSecurityV2Total,
	)
	if legacy != 2 {
		t.Errorf("expected [2] legacy permits, got [%f]", legacy)
	}
	if securityV2 != 0 {
		t.Errorf("expected no security-v2 permits, got [%f]", securityV2)
	}
}
