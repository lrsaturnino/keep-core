package beacon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/keep-network/keep-common/pkg/persistence"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/beacon/event"
	"github.com/keep-network/keep-core/pkg/beacon/gjkr"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/net"
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

func TestBeaconPermitIdentitiesAreCanonical(t *testing.T) {
	seed := big.NewInt(123456789)
	seedHash := sha256.Sum256(seed.Bytes())

	dkgIdentity := beaconDKGPermitIdentity(seed, group.MemberIndex(17))
	if dkgIdentity.WorkID != hex.EncodeToString(seedHash[:]) {
		t.Errorf("unexpected DKG work ID [%s]", dkgIdentity.WorkID)
	}
	if dkgIdentity.PermitID != "17" {
		t.Errorf("unexpected DKG permit ID [%s]", dkgIdentity.PermitID)
	}

	relayIdentity := beaconRelayPermitIdentity(1234, "17")
	if relayIdentity.WorkID != "relay-request-1234" {
		t.Errorf("unexpected relay work ID [%s]", relayIdentity.WorkID)
	}
	if relayIdentity.PermitID != "17" {
		t.Errorf("unexpected relay permit ID [%s]", relayIdentity.PermitID)
	}
}

// cutoverRecordingPersistence records every saved file name so tests can
// assert exactly which namespace received signer material.
type cutoverRecordingPersistence struct {
	cutoverFakePersistence

	mu    sync.Mutex
	saves []string
	data  map[string][]byte
}

func (p *cutoverRecordingPersistence) Save(
	data []byte,
	directory string,
	name string,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := directory + name
	p.saves = append(p.saves, path)
	if p.data == nil {
		p.data = make(map[string][]byte)
	}
	p.data[path] = append([]byte(nil), data...)
	return nil
}

// savesContaining counts recorded saves whose path contains the given marker.
func (p *cutoverRecordingPersistence) savesContaining(marker string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, save := range p.saves {
		if strings.Contains(save, marker) {
			count++
		}
	}
	return count
}

// savedDataContaining returns copies of the bytes saved to matching paths.
func (p *cutoverRecordingPersistence) savedDataContaining(
	marker string,
) [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([][]byte, 0)
	for path, data := range p.data {
		if strings.Contains(path, marker) {
			result = append(result, append([]byte(nil), data...))
		}
	}
	return result
}

// cutoverFailableBlockCounter delegates to the real local chain clock until a
// test induces a synchronous read failure; waiters keep working, matching a
// failing RPC current-height call.
type cutoverFailableBlockCounter struct {
	chain.BlockCounter

	failing atomic.Bool
}

func (c *cutoverFailableBlockCounter) CurrentBlock() (uint64, error) {
	if c.failing.Load() {
		return 0, fmt.Errorf("induced clock failure")
	}
	return c.BlockCounter.CurrentBlock()
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
	node                  *node
	localChain            cutoverLocalChain
	gate                  participation.Gate
	gateMetrics           *cutoverGateMetrics
	gateClock             *cutoverFailableBlockCounter
	registryPersistence   *cutoverRecordingPersistence
	quarantinePersistence *cutoverRecordingPersistence
	anchorBlock           uint64
	groupSize             int
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
	gateClock := &cutoverFailableBlockCounter{BlockCounter: blockCounter}
	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: cutoverBlockFor(currentBlock)},
		gateClock,
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

	registryPersistence := &cutoverRecordingPersistence{}
	groupRegistry := registry.NewGroupRegistry(
		logger,
		testChain,
		registryPersistence,
	)

	quarantinePersistence := &cutoverRecordingPersistence{}
	signerQuarantine := registry.NewQuarantine(logger, quarantinePersistence)

	node := newNode(
		testChain,
		netLocal.ConnectWithKey(operatorPublicKey),
		groupRegistry,
		generator.StartScheduler(),
		gate,
		signerQuarantine,
	)

	return &cutoverNodeHarness{
		node:                  node,
		localChain:            localChain,
		gate:                  gate,
		gateMetrics:           gateMetrics,
		gateClock:             gateClock,
		registryPersistence:   registryPersistence,
		quarantinePersistence: quarantinePersistence,
		anchorBlock:           currentBlock,
		groupSize:             groupSize,
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
	h.waitForPermitRelease(t)
}

// waitForPermitRelease waits until every member goroutine released its permit,
// so assertions see the final gate accounting and every quarantine or
// registration write has happened.
func (h *cutoverNodeHarness) waitForPermitRelease(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if h.gate.State().ActiveCeremonies == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("permits were not released")
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

	// The standalone legacy peers run through their own always-legacy gate —
	// the pre-cutover peer behavior — so their execution path carries a permit
	// context and commit guard exactly like a production member.
	externalBlockCounter, err := harness.localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	externalMetrics := newCutoverGateMetrics()
	externalGate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{},
		externalBlockCounter,
		externalMetrics,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(externalGate.Close)

	externalErrors := make(chan error, 3)
	var externalWait sync.WaitGroup
	for _, memberIndex := range []group.MemberIndex{3, 4, 5} {
		externalPermit, err := externalGate.Begin(
			participation.BeaconDKG,
			harness.anchorBlock,
		)
		if err != nil {
			t.Fatal(err)
		}

		externalWait.Add(1)
		go func(memberIndex group.MemberIndex) {
			defer externalWait.Done()
			defer externalPermit.Close()
			_, _, err := dkg.ExecuteDKG(
				externalPermit.Context(),
				logger,
				seed,
				memberIndex,
				harness.anchorBlock,
				externalChain,
				externalChannel,
				membershipValidator,
				selectedOperators,
				compatibility.Legacy(),
				externalPermit,
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

// TestJoinDKGIfEligible_LegacyPermitCompletesAfterCutover proves a permit
// pinned from a pre-cutover anchor survives the cutover block and completes in
// legacy mode: the cutover falls in the middle of the ceremony, the process
// state transitions to open_security_v2, yet every member finishes with its
// legacy permit and the completion commits are accepted and counted as
// legacy completions after the cutover.
func TestJoinDKGIfEligible_LegacyPermitCompletesAfterCutover(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		5,
		3,
		// The cutover block falls inside the ceremony: the DKG protocol takes
		// tens of blocks beyond the GJKR phase alone, so block anchor+30 is
		// crossed while the ceremony is still running.
		func(currentBlock uint64) uint64 { return currentBlock + 30 },
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

	// The ceremony must genuinely have completed at or after the cutover
	// block: the process state already derives open_security_v2 while every
	// signer activation still committed under its legacy permit.
	if state := harness.gate.State(); state.State != participation.StateOpenSecurityV2 {
		t.Errorf(
			"expected the process state [%s] after the cutover, got [%s]",
			participation.StateOpenSecurityV2,
			state.State,
		)
	}
	completions := harness.gateMetrics.counter(
		clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal,
	)
	if completions < float64(harness.groupSize) {
		t.Errorf(
			"expected at least [%d] legacy completions after the cutover "+
				"(one signer activation per member), got [%f]",
			harness.groupSize,
			completions,
		)
	}

	// Every member's accepted signer was activated normally.
	if got := harness.registryPersistence.savesContaining("/membership_"); got != harness.groupSize {
		t.Errorf(
			"expected [%d] active membership saves, got [%d]",
			harness.groupSize,
			got,
		)
	}
	if got := harness.quarantinePersistence.savesContaining("/membership_"); got != 0 {
		t.Errorf("expected no quarantined memberships, got [%d]", got)
	}
}

// TestJoinDKGIfEligible_ForcedShutdownAfterKeyGenerationQuarantinesSigner
// proves the forced-quiescence path after share generation: the gate is
// force-closed inside the result publication window, when the group key
// material already exists but no on-chain publication was observed. Every
// member's orphaned signer must be preserved in the quarantine namespace, no
// active membership may be written, and nothing may reach the chain.
func TestJoinDKGIfEligible_ForcedShutdownAfterKeyGenerationQuarantinesSigner(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		2,
		2,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)

	blockCounter, err := harness.localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	// The trigger fires inside the result publication signing window: after
	// the last GJKR protocol block, before the earliest possible submission.
	trigger, err := blockCounter.BlockHeightWaiter(
		harness.anchorBlock + gjkr.ProtocolBlocks() + 2,
	)
	if err != nil {
		t.Fatal(err)
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-trigger
		harness.gate.Quiesce(fmt.Errorf("test shutdown"))
		harness.gate.Close()
	}()

	seed := cutoverRandomSeed(t)
	harness.node.JoinDKGIfEligible(seed, harness.anchorBlock)

	<-shutdownDone
	harness.waitForPermitRelease(t)

	if result, _ := harness.localChain.GetLastDKGResult(); result != nil {
		t.Error("expected no DKG result after the forced shutdown")
	}
	if got := harness.quarantinePersistence.savesContaining("/membership_"); got != harness.groupSize {
		t.Errorf(
			"expected [%d] quarantined memberships, got [%d]",
			harness.groupSize,
			got,
		)
	}
	if got := harness.quarantinePersistence.savesContaining("/metadata_"); got != harness.groupSize {
		t.Errorf(
			"expected [%d] quarantine metadata records, got [%d]",
			harness.groupSize,
			got,
		)
	}
	expectedSeedHash := sha256.Sum256(seed.Bytes())
	for _, data := range harness.quarantinePersistence.savedDataContaining(
		"/metadata_",
	) {
		metadata := &registry.QuarantinedSignerMetadata{}
		if err := json.Unmarshal(data, metadata); err != nil {
			t.Fatal(err)
		}
		if metadata.SeedHash != hex.EncodeToString(expectedSeedHash[:]) {
			t.Errorf(
				"unexpected quarantine seed hash [%s]",
				metadata.SeedHash,
			)
		}
	}
	if got := harness.registryPersistence.savesContaining("/membership_"); got != 0 {
		t.Errorf(
			"expected no active membership saves, got [%d]",
			got,
		)
	}
	forcedAborts := harness.gateMetrics.counter(
		clientinfo.MetricParticipationQuiesceForcedAbortsTotal,
	)
	if forcedAborts != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] forced aborts, got [%f]",
			harness.groupSize,
			forcedAborts,
		)
	}
}

// TestJoinDKGIfEligible_RefusedQuarantineMembershipIsNotAQuarantinedOutcome
// proves a share the quarantine namespace refused does not end its permit as
// quarantined, while the audit metadata naming the lost share is still
// written.
//
// The terminal outcome is what the offline audit and the rollback decision
// read as "this material is preserved and accounted for". A namespace that
// took the metadata but not the key material has preserved nothing, so
// claiming the outcome on the strength of the record alone would report key
// material that no namespace holds. The metadata is still attempted because it
// is the only thing that tells the audit a share was generated and lost.
func TestJoinDKGIfEligible_RefusedQuarantineMembershipIsNotAQuarantinedOutcome(
	t *testing.T,
) {
	harness := newCutoverNodeHarness(
		t,
		2,
		2,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)

	// The same forced-quiescence interruption as above, over a namespace that
	// will not accept the key material.
	refusing := &cutoverRefusingPersistence{refusedMarker: "/membership_"}
	harness.node.signerQuarantine = registry.NewQuarantine(logger, refusing)

	blockCounter, err := harness.localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	trigger, err := blockCounter.BlockHeightWaiter(
		harness.anchorBlock + gjkr.ProtocolBlocks() + 2,
	)
	if err != nil {
		t.Fatal(err)
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-trigger
		harness.gate.Quiesce(fmt.Errorf("test shutdown"))
		harness.gate.Close()
	}()

	harness.node.JoinDKGIfEligible(cutoverRandomSeed(t), harness.anchorBlock)

	<-shutdownDone
	harness.waitForPermitRelease(t)

	if got := refusing.savesContaining("/membership_"); got != 0 {
		t.Errorf("expected no membership to be accepted, got [%d]", got)
	}
	if got := refusing.savesContaining("/metadata_"); got != harness.groupSize {
		t.Errorf(
			"expected [%d] quarantine metadata records naming the lost "+
				"shares, got [%d]",
			harness.groupSize,
			got,
		)
	}

	for _, record := range harness.gate.State().RecentTerminalOutcomes {
		if record.Outcome == participation.TerminalOutcomeQuarantined {
			t.Errorf(
				"a share the namespace refused was reported as quarantined "+
					"[%v]",
				record,
			)
		}
	}
}

// cutoverRefusingPersistence is a namespace that refuses one record name while
// recording its neighbours, as a disk namespace does when a single file cannot
// be written.
type cutoverRefusingPersistence struct {
	cutoverRecordingPersistence

	refusedMarker string
}

func (p *cutoverRefusingPersistence) Save(
	data []byte,
	directory string,
	name string,
) error {
	if strings.Contains(name, p.refusedMarker) {
		return fmt.Errorf("cannot write [%s]", name)
	}

	return p.cutoverRecordingPersistence.Save(data, directory, name)
}

// TestJoinDKGIfEligible_ClockFailureAfterKeyGenerationQuarantinesSigner proves
// the chain-clock-failure path after share generation: the gate's synchronous
// clock reads start failing inside the result publication window. The commit
// fence and the clock supervisor fail closed, the permits are canceled with
// the clock sentinel, and every member's orphaned signer is preserved in the
// quarantine namespace without any on-chain submission.
func TestJoinDKGIfEligible_ClockFailureAfterKeyGenerationQuarantinesSigner(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		2,
		2,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)

	blockCounter, err := harness.localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	// The trigger fires inside the result publication signing window: after
	// the last GJKR protocol block, before the earliest possible submission.
	trigger, err := blockCounter.BlockHeightWaiter(
		harness.anchorBlock + gjkr.ProtocolBlocks() + 2,
	)
	if err != nil {
		t.Fatal(err)
	}

	clockFailed := make(chan struct{})
	go func() {
		defer close(clockFailed)
		<-trigger
		harness.gateClock.failing.Store(true)
	}()

	harness.node.JoinDKGIfEligible(cutoverRandomSeed(t), harness.anchorBlock)

	<-clockFailed
	harness.waitForPermitRelease(t)

	if result, _ := harness.localChain.GetLastDKGResult(); result != nil {
		t.Error("expected no DKG result after the clock failure")
	}
	if got := harness.quarantinePersistence.savesContaining("/membership_"); got != harness.groupSize {
		t.Errorf(
			"expected [%d] quarantined memberships, got [%d]",
			harness.groupSize,
			got,
		)
	}
	if got := harness.registryPersistence.savesContaining("/membership_"); got != 0 {
		t.Errorf(
			"expected no active membership saves, got [%d]",
			got,
		)
	}
	clockAborts := harness.gateMetrics.counter(
		clientinfo.MetricParticipationClockAbortsTotal,
	)
	if clockAborts != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] clock aborts, got [%f]",
			harness.groupSize,
			clockAborts,
		)
	}
}

// TestJoinDKGIfEligible_GateCancellationDuringKeyGenerationAbortsCleanly
// proves cancellation reaches a running ceremony before key material exists:
// the gate is force-closed right after the members start, every member aborts
// as a gate decision — not an ordinary DKG failure — and nothing is
// quarantined, registered, or submitted.
func TestJoinDKGIfEligible_GateCancellationDuringKeyGenerationAbortsCleanly(t *testing.T) {
	harness := newCutoverNodeHarness(
		t,
		2,
		2,
		func(currentBlock uint64) uint64 { return currentBlock + 100_000 },
		nil,
	)

	harness.node.JoinDKGIfEligible(cutoverRandomSeed(t), harness.anchorBlock)

	// The members are inside GJKR now: no group key material exists yet.
	harness.gate.Quiesce(fmt.Errorf("test shutdown"))
	harness.gate.Close()

	harness.waitForPermitRelease(t)

	if result, _ := harness.localChain.GetLastDKGResult(); result != nil {
		t.Error("expected no DKG result after the cancellation")
	}
	if got := harness.quarantinePersistence.savesContaining("/membership_"); got != 0 {
		t.Errorf(
			"expected no quarantined memberships before key generation, "+
				"got [%d]",
			got,
		)
	}
	if got := harness.registryPersistence.savesContaining("/membership_"); got != 0 {
		t.Errorf("expected no active membership saves, got [%d]", got)
	}
	forcedAborts := harness.gateMetrics.counter(
		clientinfo.MetricParticipationQuiesceForcedAbortsTotal,
	)
	if forcedAborts != float64(harness.groupSize) {
		t.Errorf(
			"expected [%d] forced aborts, got [%f]",
			harness.groupSize,
			forcedAborts,
		)
	}
}

// TestMonitorRelayEntry_LegacyTimeoutReportSuppressedAfterCutover proves the
// timeout-report penalty fence: a monitor holding a legacy permit whose
// timeout block falls at or after the cutover block must not report the
// timeout. The technical grace for pre-cutover work must never create new
// penalty state after the cutover.
func TestMonitorRelayEntry_LegacyTimeoutReportSuppressedAfterCutover(t *testing.T) {
	localChain := local_v1.Connect(5, 3)

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

	// The relay request anchors below the cutover block, but its timeout
	// block — request plus the relay entry timeout — falls after it.
	gateMetrics := newCutoverGateMetrics()
	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{CutoverBlock: currentBlock + 5},
		blockCounter,
		gateMetrics,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	node := &node{
		beaconChain:       localChain,
		participationGate: gate,
	}

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		node.MonitorRelayEntry(monitoredPreviousEntry, currentBlock)
	}()

	timeoutBlock := currentBlock +
		localChain.GetConfig().RelayEntryTimeout
	if err := blockCounter.WaitForBlockHeight(timeoutBlock + 2); err != nil {
		t.Fatal(err)
	}

	select {
	case <-monitorDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the monitor did not return after the timeout block")
	}

	if reports := localChain.GetRelayEntryTimeoutReports(); len(reports) != 0 {
		t.Errorf(
			"expected no timeout reports after the cutover, got [%v]",
			reports,
		)
	}
	refusals := gateMetrics.counter(
		clientinfo.MetricParticipationCommitRefusalsTotal,
	)
	if refusals != 1 {
		t.Errorf("expected [1] commit refusal, got [%f]", refusals)
	}
}

// TestMonitorRelayEntry_TimeoutReportedBelowCutover proves the monitor still
// files the timeout report while both the anchor and the timeout block stay
// below the cutover block: the penalty fence suppresses only post-cutover
// legacy penalties, not normal pre-cutover operation.
func TestMonitorRelayEntry_TimeoutReportedBelowCutover(t *testing.T) {
	localChain := local_v1.Connect(5, 3)

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
		participation.Schedule{CutoverBlock: currentBlock + 100_000},
		blockCounter,
		gateMetrics,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	node := &node{
		beaconChain:       localChain,
		participationGate: gate,
	}

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		node.MonitorRelayEntry(monitoredPreviousEntry, currentBlock)
	}()

	timeoutBlock := currentBlock +
		localChain.GetConfig().RelayEntryTimeout
	if err := blockCounter.WaitForBlockHeight(timeoutBlock + 2); err != nil {
		t.Fatal(err)
	}

	select {
	case <-monitorDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the monitor did not return after the timeout block")
	}

	if reports := localChain.GetRelayEntryTimeoutReports(); len(reports) != 1 {
		t.Errorf(
			"expected exactly one timeout report below the cutover, got [%v]",
			reports,
		)
	}
}

// cutoverStubForwarder is a controllable net.Forwarder for forwarding
// lifecycle tests.
type cutoverStubForwarder struct {
	closeOnce sync.Once
	done      chan struct{}
}

func newCutoverStubForwarder() *cutoverStubForwarder {
	return &cutoverStubForwarder{done: make(chan struct{})}
}

func (f *cutoverStubForwarder) Close() {
	f.closeOnce.Do(func() { close(f.done) })
}

func (f *cutoverStubForwarder) Done() <-chan struct{} { return f.done }

func (f *cutoverStubForwarder) closed() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// cutoverForwardingProvider delegates everything to the wrapped provider but
// hands out a controllable forwarder handle.
type cutoverForwardingProvider struct {
	net.Provider

	forwarder *cutoverStubForwarder
}

func (p *cutoverForwardingProvider) BroadcastChannelForwarderFor(string) (
	net.Forwarder,
	error,
) {
	return p.forwarder, nil
}

// TestForwardSignatureShares_GateCancellationClosesForwarder proves the
// forwarding permit owns the relay's lifecycle: the forwarding runs under a
// permit, and when the gate force-cancels it the forwarder handle is closed
// and the permit released.
func TestForwardSignatureShares_GateCancellationClosesForwarder(t *testing.T) {
	localChain := local_v1.Connect(5, 3)

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
		participation.Schedule{CutoverBlock: currentBlock + 100_000},
		blockCounter,
		gateMetrics,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	stubForwarder := newCutoverStubForwarder()
	node := &node{
		beaconChain: localChain,
		netProvider: &cutoverForwardingProvider{
			Provider:  netLocal.Connect(),
			forwarder: stubForwarder,
		},
		participationGate: gate,
	}

	groupPublicKeyBytes := new(bn256.G2).ScalarBaseMult(big.NewInt(1)).Marshal()
	node.ForwardSignatureShares(groupPublicKeyBytes, currentBlock)

	if active := gate.State().ActiveCeremonies; active != 1 {
		t.Fatalf("expected one active forwarding permit, got [%d]", active)
	}

	gate.Quiesce(fmt.Errorf("test shutdown"))
	gate.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if stubForwarder.closed() && gate.State().ActiveCeremonies == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !stubForwarder.closed() {
		t.Error("expected the forwarder to be closed on gate cancellation")
	}
	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Errorf("expected the forwarding permit released, got [%d]", active)
	}
}

// TestForwardSignatureShares_ForwarderEndClosesPermit proves the reverse
// lifecycle direction: when the relay ends on its own — TTL expiry or
// provider shutdown — the forwarding permit is released without gate action.
func TestForwardSignatureShares_ForwarderEndClosesPermit(t *testing.T) {
	localChain := local_v1.Connect(5, 3)

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
		participation.Schedule{CutoverBlock: currentBlock + 100_000},
		blockCounter,
		gateMetrics,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	stubForwarder := newCutoverStubForwarder()
	node := &node{
		beaconChain: localChain,
		netProvider: &cutoverForwardingProvider{
			Provider:  netLocal.Connect(),
			forwarder: stubForwarder,
		},
		participationGate: gate,
	}

	groupPublicKeyBytes := new(bn256.G2).ScalarBaseMult(big.NewInt(1)).Marshal()
	node.ForwardSignatureShares(groupPublicKeyBytes, currentBlock)

	if active := gate.State().ActiveCeremonies; active != 1 {
		t.Fatalf("expected one active forwarding permit, got [%d]", active)
	}

	// The relay ends naturally.
	stubForwarder.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if gate.State().ActiveCeremonies == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if active := gate.State().ActiveCeremonies; active != 0 {
		t.Errorf("expected the forwarding permit released, got [%d]", active)
	}
}
