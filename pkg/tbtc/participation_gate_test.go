package tbtc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/dkg"
)

func TestSigningExecutor_Sign_RefusesUnsetMode(t *testing.T) {
	executor := &signingExecutor{}

	_, err := executor.sign(
		nil,
		big.NewInt(100),
		0,
		participation.ProtocolMode(0),
	)
	if err == nil {
		t.Fatal("expected an unset-mode refusal error")
	}
	if !strings.Contains(err.Error(), "cannot select compatibility strategies") {
		t.Errorf("unexpected refusal error: [%v]", err)
	}
}

// TestNode_BeginWalletActionPermit exercises the wallet action permit
// acquisition: the heartbeat maps to its own ceremony class, other actions
// are signing ceremonies, quiescence refuses, and a legacy-mode permit remains
// available while the chain is below the cutover block.
func TestNode_BeginWalletActionPermit(t *testing.T) {
	localChain := Connect()
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	t.Run("heartbeat ceremony class", func(t *testing.T) {
		n := &node{participationGate: newTestGate(t, blockCounter)}

		permit := n.beginWalletActionPermit(ActionHeartbeat, 1)
		if permit == nil {
			t.Fatal("expected a permit")
		}
		defer permit.Close()

		testutils.AssertStringsEqual(
			t,
			"permit ceremony",
			string(participation.TBTCHeartbeat),
			string(permit.Ceremony()),
		)
		testutils.AssertStringsEqual(
			t,
			"permit mode",
			participation.ModeSecurityV2.String(),
			permit.Mode().String(),
		)
	})

	t.Run("signing ceremony class", func(t *testing.T) {
		n := &node{participationGate: newTestGate(t, blockCounter)}

		permit := n.beginWalletActionPermit(ActionDepositSweep, 1)
		if permit == nil {
			t.Fatal("expected a permit")
		}
		defer permit.Close()

		testutils.AssertStringsEqual(
			t,
			"permit ceremony",
			string(participation.TBTCSigning),
			string(permit.Ceremony()),
		)
	})

	t.Run("refused while quiescing", func(t *testing.T) {
		gate := newTestGate(t, blockCounter)
		gate.Quiesce(fmt.Errorf("shutdown"))

		n := &node{participationGate: gate}

		if permit := n.beginWalletActionPermit(ActionRedemption, 1); permit != nil {
			permit.Close()
			t.Error("expected no permit while quiescing")
		}
	})

	t.Run("refused without a gate", func(t *testing.T) {
		n := &node{}

		if permit := n.beginWalletActionPermit(ActionRedemption, 1); permit != nil {
			permit.Close()
			t.Error("expected no permit without a gate")
		}
	})

	t.Run("legacy mode admitted", func(t *testing.T) {
		// A cutover block far ahead pins every current anchor to the legacy
		// mode.
		gate, err := participation.NewGate(
			t.Context(),
			participation.Schedule{CutoverBlock: 1_000_000},
			blockCounter,
			testGateMetrics{},
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(gate.Close)

		n := &node{participationGate: gate}

		permit := n.beginWalletActionPermit(ActionMovingFunds, 1)
		if permit == nil {
			t.Fatal("expected a permit for the legacy mode")
		}
		testutils.AssertStringsEqual(
			t,
			"legacy permit mode",
			participation.ModeLegacy.String(),
			permit.Mode().String(),
		)

		snapshot := gate.State()
		testutils.AssertUintsEqual(
			t,
			"active ceremonies while the legacy permit is held",
			1,
			snapshot.ActiveCeremonies,
		)
		permit.Close()
	})
}

// TestDkgExecutor_PreserveInterruptedSigner_Quarantines proves a refused
// activation of a signer whose wallet is not registered on chain preserves
// the share only in the protected quarantine namespace — never in the active
// wallet storage and never in the in-memory wallet cache.
func TestDkgExecutor_PreserveInterruptedSigner_Quarantines(t *testing.T) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	de.preserveInterruptedSigner(
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		"tbtc_dkg_signer_activation",
		fmt.Errorf("activation refused"),
	)

	if len(registryHandle.saved) != 0 {
		t.Errorf(
			"expected no active-namespace save, got [%d]",
			len(registryHandle.saved),
		)
	}
	if signers := de.walletRegistry.getSigners(
		result.PrivateKeyShare.PublicKey(),
	); len(signers) != 0 {
		t.Errorf("expected no activated signers, got [%d]", len(signers))
	}

	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)

	var metadataContent []byte
	expectedDirectory := getWalletStorageKey(result.PrivateKeyShare.PublicKey())
	for _, descriptor := range quarantineHandle.saved {
		testutils.AssertStringsEqual(
			t,
			"quarantine directory",
			expectedDirectory,
			descriptor.Directory(),
		)
		if strings.HasPrefix(descriptor.Name(), "/metadata_") {
			metadataContent, _ = descriptor.Content()
		}
	}
	if metadataContent == nil {
		t.Fatal("expected a quarantine metadata record")
	}

	var metadata QuarantinedSignerMetadata
	if err := json.Unmarshal(metadataContent, &metadata); err != nil {
		t.Fatal(err)
	}

	testutils.AssertUintsEqual(
		t,
		"metadata schema version",
		uint64(QuarantineSchemaVersion),
		uint64(metadata.SchemaVersion),
	)
	testutils.AssertStringsEqual(
		t,
		"metadata release epoch",
		participation.CompiledEpoch.String(),
		metadata.ReleaseEpoch,
	)
	testutils.AssertStringsEqual(
		t,
		"metadata protocol mode",
		participation.ModeSecurityV2.String(),
		metadata.ProtocolMode,
	)
	testutils.AssertStringsEqual(
		t,
		"metadata ceremony",
		string(participation.TBTCDKG),
		metadata.Ceremony,
	)
	testutils.AssertStringsEqual(
		t,
		"metadata failed operation",
		"tbtc_dkg_signer_activation",
		metadata.FailedOperation,
	)
	if metadata.SeedHash == "" {
		t.Error("expected a seed hash in the quarantine metadata")
	}
	if strings.Contains(metadata.SeedHash, big.NewInt(1).Text(16)) &&
		len(metadata.SeedHash) < 64 {
		t.Error("the raw seed must not appear in the quarantine metadata")
	}
	expectedWalletPKH := bitcoin.PublicKeyHash(result.PrivateKeyShare.PublicKey())
	testutils.AssertStringsEqual(
		t,
		"metadata wallet public key hash",
		hex.EncodeToString(expectedWalletPKH[:]),
		metadata.WalletPublicKeyHash,
	)
}

// TestDkgExecutor_PreserveInterruptedSigner_SavesRegisteredWithoutActivation
// proves a refused activation of a signer whose wallet is already registered
// on chain saves the share durably in the active namespace — a prior binary
// may legitimately load it — but never activates it in this process's wallet
// cache.
func TestDkgExecutor_PreserveInterruptedSigner_SavesRegisteredWithoutActivation(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	walletPublicKey := result.PrivateKeyShare.PublicKey()
	walletID, err := de.chain.CalculateWalletID(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	de.chain.(*localChain).setWallet(
		bitcoin.PublicKeyHash(walletPublicKey),
		&WalletChainData{EcdsaWalletID: walletID, State: StateLive},
	)

	permit := newTestPermit(participation.TBTCDKG)

	de.preserveInterruptedSigner(
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		"tbtc_dkg_signer_activation",
		fmt.Errorf("activation refused"),
	)

	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		1,
		len(registryHandle.saved),
	)
	if len(quarantineHandle.saved) != 0 {
		t.Errorf(
			"expected no quarantine records, got [%d]",
			len(quarantineHandle.saved),
		)
	}
	if signers := de.walletRegistry.getSigners(walletPublicKey); len(signers) != 0 {
		t.Errorf("expected no activated signers, got [%d]", len(signers))
	}
}

// setupPreserveScenario builds a dkgExecutor with observable active and
// quarantine persistence plus a completed DKG result, for exercising the
// interrupted-signer preservation paths.
func setupPreserveScenario(t *testing.T) (
	*dkgExecutor,
	*dkg.Result,
	*GroupSelectionResult,
	*mockPersistenceHandle,
	*mockPersistenceHandle,
) {
	t.Helper()

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}

	groupParameters := &GroupParameters{
		GroupSize:       5,
		GroupQuorum:     3,
		HonestThreshold: 2,
	}

	localChain := Connect()
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	registryHandle := &mockPersistenceHandle{}
	walletRegistry, err := newWalletRegistry(
		registryHandle,
		localChain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

	quarantineHandle := &mockPersistenceHandle{}

	de := &dkgExecutor{
		groupParameters:   groupParameters,
		chain:             localChain,
		walletRegistry:    walletRegistry,
		participationGate: newTestGate(t, blockCounter),
		signerQuarantine:  newSignerQuarantine(logger, quarantineHandle),
	}

	result := &dkg.Result{
		Group: group.NewGroup(
			groupParameters.DishonestThreshold(),
			groupParameters.GroupSize,
		),
		PrivateKeyShare: tecdsa.NewPrivateKeyShare(testData[0]),
	}

	gsr := &GroupSelectionResult{
		OperatorsIDs:       chain.OperatorIDs{1, 2, 3, 4, 5},
		OperatorsAddresses: chain.Addresses{"0xAA", "0xBB", "0xCC", "0xDD", "0xEE"},
	}

	return de, result, gsr, registryHandle, quarantineHandle
}

// preserveOneSigner quarantines the signer the preserve scenario generates for
// the given seat and returns the wallet directory it was written under.
func preserveOneSigner(
	t *testing.T,
	de *dkgExecutor,
	result *dkg.Result,
	gsr *GroupSelectionResult,
	memberIndex group.MemberIndex,
) string {
	t.Helper()

	de.preserveInterruptedSigner(
		logger.With(),
		newTestPermit(participation.TBTCDKG),
		big.NewInt(1),
		result,
		memberIndex,
		gsr,
		"tbtc_dkg_signer_activation",
		fmt.Errorf("activation refused"),
	)

	return getWalletStorageKey(result.PrivateKeyShare.PublicKey())
}

// TestDkgExecutor_ReportQuarantinedSigners_CountsOutputsNotRecords proves the
// reported count is of preserved signer outputs, not of the records preservation
// writes: each output is stored as a membership beside its audit metadata, and
// counting both would report every quarantined share twice.
func TestDkgExecutor_ReportQuarantinedSigners_CountsOutputsNotRecords(t *testing.T) {
	de, result, gsr, _, quarantineHandle := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"records written for one preserved output",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportQuarantinedSigners_ExcludesActivatedSeat proves an
// output whose seat this process has activated stops being counted. The metric
// is of preserved material a rollback still has to account for, and a share the
// running node holds active is accounted for by the wallet cache itself.
func TestDkgExecutor_ReportQuarantinedSigners_ExcludesActivatedSeat(t *testing.T) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	walletStorageKey := preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers before activation",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)

	// The same wallet and the same seat, now activated from the active
	// namespace — the state a restart that adopted the share would be in.
	signer, err := de.buildFinalSigner(
		result,
		group.MemberIndex(1),
		gsr.OperatorsAddresses,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := de.walletRegistry.registerSigner(signer); err != nil {
		t.Fatal(err)
	}
	testutils.AssertBoolsEqual(
		t,
		"the preserved seat reads as active",
		true,
		de.walletRegistry.isSignerActive(
			walletStorageKey,
			group.MemberIndex(1),
		),
	)

	de.reportQuarantinedSigners(logger.With())

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after activation",
		0,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportQuarantinedSigners_KeepsCountOnUnreadableNamespace
// proves a namespace that cannot be enumerated leaves the last published count
// standing. Publishing zero there would report an empty quarantine, which is
// precisely what could not be established, and it is the one answer that reads
// as nothing left to account for.
func TestDkgExecutor_ReportQuarantinedSigners_KeepsCountOnUnreadableNamespace(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers before the namespace fails",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)

	de.signerQuarantine = newSignerQuarantine(
		logger,
		&unreadableHandle{},
	)

	de.reportQuarantinedSigners(logger.With())

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after the namespace fails",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportInitialQuarantinedSigners_BlocksOnUnreadableNamespace
// proves a process that cannot enumerate its quarantine namespace at startup
// reports the failure to its caller and publishes no count at all.
//
// Keeping the last published count is the right answer at runtime, where a
// number somebody published exists. On a cold start there is none: the gauge is
// registered at zero with the rest of the fixed family, so a scan that gives up
// quietly leaves that zero as the process's only word on the subject, and a
// fleet reading it concludes there is nothing left to account for. This is the
// one direction the count must never invent, so it is watched from a recorder
// that can tell a published zero from an unpublished one.
func TestDkgExecutor_ReportInitialQuarantinedSigners_BlocksOnUnreadableNamespace(
	t *testing.T,
) {
	de, _, _, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder
	de.signerQuarantine = newSignerQuarantine(logger, &unreadableHandle{})

	err := de.reportInitialQuarantinedSigners()
	if err == nil {
		t.Fatal(
			"an unreadable quarantine namespace must stop a cold start, not " +
				"leave the registered zero standing as the count",
		)
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("expected the underlying read error, got [%v]", err)
	}

	if value, published := recorder.gaugePublished(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
	); published {
		t.Errorf(
			"a count that could not be established was published as [%v]",
			value,
		)
	}
}

// TestDkgExecutor_ReportInitialQuarantinedSigners_PublishesWhatIsPreserved
// proves a readable namespace is counted and published at startup, so a
// restart inherits the outputs earlier processes on this host preserved rather
// than starting the count over.
func TestDkgExecutor_ReportInitialQuarantinedSigners_PublishesWhatIsPreserved(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))
	preserveOneSigner(t, de, result, gsr, group.MemberIndex(2))

	// A restart's first scan: the same namespace, a recorder that has
	// published nothing yet.
	restarted := newDispatchGaugeRecorder()
	de.metricsRecorder = restarted

	if err := de.reportInitialQuarantinedSigners(); err != nil {
		t.Fatal(err)
	}

	value, published := restarted.gaugePublished(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
	)
	if !published {
		t.Fatal("expected the inherited outputs to be counted at startup")
	}
	testutils.AssertIntsEqual(
		t,
		"quarantined signers a restart inherits",
		2,
		int(value),
	)
}

// TestDkgExecutor_ReportQuarantinedSigners_SerializesRecountAndPublication
// proves no two reporters recount the namespace at the same time, and that
// concurrent reporters agree on what they publish.
//
// Members of one ceremony quarantine independently, so reports can be raised
// concurrently. Interleaved scans do not corrupt anything — every piece of state
// they touch is individually guarded — but they can publish out of order and
// leave an earlier, smaller scan's count as the last word, which is the
// direction that reads as an all-clear. Serializing the scan with its
// publication is what rules that out, so the enumeration itself is what this
// watches: a scan that begins while another is open is the interleaving.
func TestDkgExecutor_ReportQuarantinedSigners_SerializesRecountAndPublication(
	t *testing.T,
) {
	de, result, gsr, _, quarantineHandle := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))
	preserveOneSigner(t, de, result, gsr, group.MemberIndex(2))

	// The same records, behind a namespace that holds every enumeration open
	// until released and reports how many were ever open at once.
	tracking := &scanTrackingHandle{
		mockPersistenceHandle: *quarantineHandle,
		entered:               make(chan struct{}, reporterCount),
		release:               make(chan struct{}),
	}
	de.signerQuarantine = newSignerQuarantine(logger, tracking)

	var wg sync.WaitGroup
	for range reporterCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			de.reportQuarantinedSigners(logger.With())
		}()
	}

	// One reporter is inside its enumeration; the wait then gives every other
	// reporter time to reach its own before any of them can finish. Reporters
	// that recount one at a time cannot join it there however long they are
	// given, so this bound decides how much evidence of interleaving the test
	// collects, never whether a serialized implementation passes.
	<-tracking.entered
	time.Sleep(100 * time.Millisecond)
	close(tracking.release)
	wg.Wait()

	testutils.AssertIntsEqual(
		t,
		"greatest number of enumerations open at once",
		1,
		int(tracking.peak.Load()),
	)
	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after concurrent reports",
		2,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// reporterCount is how many concurrent reporters the serialization test raises.
const reporterCount = 4

// scanTrackingHandle is a protected namespace that holds every enumeration open
// until released and records the greatest number that were open at once.
type scanTrackingHandle struct {
	mockPersistenceHandle

	entered  chan struct{}
	release  chan struct{}
	inFlight atomic.Int32
	peak     atomic.Int32
}

func (h *scanTrackingHandle) ReadAll() (
	<-chan persistence.DataDescriptor,
	<-chan error,
) {
	descriptors := make(chan persistence.DataDescriptor)
	errs := make(chan error)

	open := h.inFlight.Add(1)
	for {
		peak := h.peak.Load()
		if open <= peak || h.peak.CompareAndSwap(peak, open) {
			break
		}
	}

	select {
	case h.entered <- struct{}{}:
	default:
	}

	go func() {
		defer close(descriptors)
		defer close(errs)
		defer h.inFlight.Add(-1)

		<-h.release

		for _, descriptor := range h.saved {
			descriptors <- descriptor
		}
	}()

	return descriptors, errs
}

// TestSignerQuarantine_PreservedOutputs_CountsMembershipsOnly proves only the
// membership records are read as signer outputs. The namespace also holds the
// audit metadata, and a later schema or an operator may leave other names
// there; none of them is a preserved share.
func TestSignerQuarantine_PreservedOutputs_CountsMembershipsOnly(t *testing.T) {
	handle := &mockPersistenceHandle{}
	quarantine := newSignerQuarantine(logger, handle)

	for _, name := range []string{
		"/membership_1",
		"/metadata_1",
		"/membership_17",
		"/metadata_17",
		// Not signer outputs: seat zero is no seat, an unparsable seat names
		// none, and neither a later schema's record nor a stray file is a share.
		"/membership_0",
		"/membership_two",
		"/attestation_1",
		"/notes.txt",
	} {
		if err := handle.Save([]byte("x"), "wallet", name); err != nil {
			t.Fatal(err)
		}
	}

	outputs, err := quarantine.preservedOutputs()
	if err != nil {
		t.Fatal(err)
	}

	testutils.AssertIntsEqual(t, "preserved outputs", 2, len(outputs))

	seats := make(map[group.MemberIndex]string)
	for _, output := range outputs {
		seats[output.memberIndex] = output.walletStorageKey
	}
	for _, seat := range []group.MemberIndex{1, 17} {
		directory, found := seats[seat]
		if !found {
			t.Errorf("seat [%v] was not read as a preserved output", seat)
			continue
		}
		testutils.AssertStringsEqual(
			t,
			fmt.Sprintf("wallet directory of seat [%v]", seat),
			"wallet",
			directory,
		)
	}
}

// TestSignerQuarantine_PreservedOutputs_FailsOnUnreadableNamespace proves an
// enumeration error is returned rather than absorbed into a shorter list: a
// truncated count of preserved material is indistinguishable from an accurate
// low one.
func TestSignerQuarantine_PreservedOutputs_FailsOnUnreadableNamespace(t *testing.T) {
	quarantine := newSignerQuarantine(logger, &unreadableHandle{})

	outputs, err := quarantine.preservedOutputs()
	if err == nil {
		t.Fatalf("expected an error, got [%d] outputs", len(outputs))
	}
	if outputs != nil {
		t.Errorf("expected no outputs beside the error, got [%v]", outputs)
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("expected the underlying read error, got [%v]", err)
	}
}

// unreadableHandle is a protected namespace whose enumeration fails, as a disk
// namespace does when its directory cannot be read.
type unreadableHandle struct {
	mockPersistenceHandle
}

func (h *unreadableHandle) ReadAll() (
	<-chan persistence.DataDescriptor,
	<-chan error,
) {
	descriptors := make(chan persistence.DataDescriptor)
	errs := make(chan error, 1)

	errs <- fmt.Errorf("the quarantine directory is unreadable")
	close(descriptors)
	close(errs)

	return descriptors, errs
}

// unwritableRecordHandle is a protected namespace that refuses one record name
// while writing its neighbours, as a disk namespace does when a single file
// cannot be written.
type unwritableRecordHandle struct {
	mockPersistenceHandle

	// refusedNamePrefix names the record this namespace will not accept.
	refusedNamePrefix string
}

func (h *unwritableRecordHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	if strings.HasPrefix(name, h.refusedNamePrefix) {
		return fmt.Errorf("cannot write [%s]", name)
	}

	return h.mockPersistenceHandle.Save(data, directory, name)
}

// quarantineLogCapture records the error lines a preservation path emits, so a
// test can hold the operator's account of what was preserved to what the
// namespace actually holds. The operator log is the only account of a
// quarantine an operator reads at the time, and it is the one that was
// reporting a preserved share as lost.
type quarantineLogCapture struct {
	testutils.MockLogger

	mu     sync.Mutex
	errors []string
}

func (c *quarantineLogCapture) Errorf(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, fmt.Sprintf(format, args...))
}

func (c *quarantineLogCapture) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.errors, "\n")
}

// savedNames lists the record names a namespace accepted, in write order.
func savedNames(handle *mockPersistenceHandle) []string {
	names := make([]string, 0, len(handle.saved))
	for _, descriptor := range handle.saved {
		names = append(names, descriptor.Name())
	}
	return names
}

// TestSignerQuarantine_Preserve_AttemptsBothRecordsAndReportsWhatLanded proves
// neither half of a quarantine record is skipped because the other failed, and
// that the caller is told which of them the namespace actually holds.
//
// The two halves mean different things — the membership is the key material a
// rollback has to account for, the metadata is the record explaining it — and
// the error alone cannot say which one is on disk. A caller that guesses is how
// the operator log, the published count, and the offline audit come to describe
// the same directory differently.
func TestSignerQuarantine_Preserve_AttemptsBothRecordsAndReportsWhatLanded(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	signer, err := de.buildFinalSigner(
		result,
		group.MemberIndex(1),
		gsr.OperatorsAddresses,
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		refusedNamePrefix   string
		expectedSaved       []string
		membershipPersisted bool
		metadataPersisted   bool
	}{
		"both records land": {
			refusedNamePrefix:   "/nothing_is_refused",
			expectedSaved:       []string{"/membership_1", "/metadata_1"},
			membershipPersisted: true,
			metadataPersisted:   true,
		},
		"the metadata is refused": {
			refusedNamePrefix:   "/metadata_",
			expectedSaved:       []string{"/membership_1"},
			membershipPersisted: true,
			metadataPersisted:   false,
		},
		"the membership is refused": {
			refusedNamePrefix:   "/membership_",
			expectedSaved:       []string{"/metadata_1"},
			membershipPersisted: false,
			metadataPersisted:   true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			handle := &unwritableRecordHandle{
				refusedNamePrefix: test.refusedNamePrefix,
			}
			quarantine := newSignerQuarantine(logger, handle)

			state, err := quarantine.preserve(
				signer,
				QuarantinedSignerMetadata{
					ReleaseEpoch: participation.CompiledEpoch.String(),
					Ceremony:     string(participation.TBTCDKG),
				},
			)

			expectedComplete := test.membershipPersisted &&
				test.metadataPersisted
			if expectedComplete && err != nil {
				t.Fatalf("expected no error, got [%v]", err)
			}
			if !expectedComplete && err == nil {
				t.Fatal("expected a preservation error")
			}

			testutils.AssertBoolsEqual(
				t,
				"membership persisted",
				test.membershipPersisted,
				state.membershipPersisted,
			)
			testutils.AssertBoolsEqual(
				t,
				"metadata persisted",
				test.metadataPersisted,
				state.metadataPersisted,
			)

			got := savedNames(&handle.mockPersistenceHandle)
			if !reflect.DeepEqual(got, test.expectedSaved) {
				t.Errorf(
					"namespace holds %v, expected %v",
					got,
					test.expectedSaved,
				)
			}
		})
	}
}

// TestDkgExecutor_PreserveInterruptedSigner_RefusedMetadataStillAccountsForShare
// proves a share the namespace accepted is accounted for even when its audit
// metadata could not be written: the permit ends quarantined and the published
// count includes the output.
//
// The key material is on disk either way, so a rollback has to account for it
// either way. Reporting it as lost — the state the caller reported when the
// metadata write decided the whole outcome — leaves preserved key material
// that nothing claims.
func TestDkgExecutor_PreserveInterruptedSigner_RefusedMetadataStillAccountsForShare(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	handle := &unwritableRecordHandle{refusedNamePrefix: "/metadata_"}
	de.signerQuarantine = newSignerQuarantine(logger, handle)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	permit := newTestPermit(participation.TBTCDKG)
	operatorLog := &quarantineLogCapture{}

	de.preserveInterruptedSigner(
		operatorLog,
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		"tbtc_dkg_signer_activation",
		fmt.Errorf("activation refused"),
	)

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/membership_1"},
	) {
		t.Errorf("namespace holds %v, expected only the membership", got)
	}

	// What the operator is told has to be what the namespace holds. Reporting
	// a preserved share as lost is how key material ends up on a host that
	// nobody goes looking on.
	if logged := operatorLog.joined(); strings.Contains(
		logged,
		"only in memory",
	) || !strings.Contains(logged, "the share is preserved") {
		t.Errorf(
			"the operator log must report the share as preserved, got [%s]",
			logged,
		)
	}

	terminalOutcomes := permit.recordedTerminalOutcomes()
	testutils.AssertIntsEqual(t, "terminal outcomes", 1, len(terminalOutcomes))
	if len(terminalOutcomes) == 1 &&
		terminalOutcomes[0].outcome !=
			participation.TerminalOutcomeQuarantined {
		t.Errorf(
			"unexpected terminal outcome [%s]",
			terminalOutcomes[0].outcome,
		)
	}

	value, published := recorder.gaugePublished(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
	)
	if !published {
		t.Fatal("expected the preserved share to be counted")
	}
	testutils.AssertIntsEqual(t, "reported quarantined signers", 1, int(value))
}

// TestDkgExecutor_PreserveInterruptedSigner_RefusedMembershipIsNotQuarantined
// proves a share the namespace refused is not reported as quarantined: the
// permit records no terminal outcome and no count is published, while the audit
// metadata naming the lost share is still written.
//
// The metadata is what tells the offline audit a share was generated and not
// preserved. Skipping it because the membership failed first would leave the
// loss with no record at all.
func TestDkgExecutor_PreserveInterruptedSigner_RefusedMembershipIsNotQuarantined(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	handle := &unwritableRecordHandle{refusedNamePrefix: "/membership_"}
	de.signerQuarantine = newSignerQuarantine(logger, handle)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	permit := newTestPermit(participation.TBTCDKG)
	operatorLog := &quarantineLogCapture{}

	de.preserveInterruptedSigner(
		operatorLog,
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		"tbtc_dkg_signer_activation",
		fmt.Errorf("activation refused"),
	)

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/metadata_1"},
	) {
		t.Errorf("namespace holds %v, expected only the metadata", got)
	}

	// The share really is only in memory here, and the operator log has to say
	// so — and say that the audit record naming it did survive, since that is
	// the only thing left pointing at the loss.
	if logged := operatorLog.joined(); !strings.Contains(
		logged,
		"only in memory",
	) || !strings.Contains(logged, "auditMetadataPreserved=true") {
		t.Errorf(
			"the operator log must report the share as lost beside the "+
				"record that survived it, got [%s]",
			logged,
		)
	}

	if outcomes := permit.recordedTerminalOutcomes(); len(outcomes) != 0 {
		t.Errorf(
			"a share that never reached the namespace must not end the "+
				"permit, got %v",
			outcomes,
		)
	}

	if _, published := recorder.gaugePublished(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
	); published {
		t.Error(
			"no count may be published for a share the namespace refused",
		)
	}
}

// TestHeartbeatAction_PenaltySuppressedByFence proves a refused penalty
// fence suppresses the whole inactivity penalty path of a low-activity
// heartbeat: the consecutive-failure counter is not incremented, no claim is
// requested, and the action completes without an ordinary failure.
func TestHeartbeatAction_PenaltySuppressedByFence(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	heartbeatFailureCounter := newHeartbeatFailureCounter()

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	// Enough active members to sign, too few for a healthy heartbeat: the
	// normal path would count an inactivity failure.
	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers - 1

	inactivityClaimExecutor := &mockInactivityClaimExecutor{}

	permit := newTestPermit(participation.TBTCHeartbeat)
	permit.commitErr = participation.ErrPenaltySuppressed

	action := newHeartbeatAction(
		logger,
		hostChain,
		wallet{
			publicKey: mustUnmarshalPublicKey(t, walletPublicKeyHex),
		},
		mockExecutor,
		proposal,
		heartbeatFailureCounter,
		inactivityClaimExecutor,
		10,
		10+heartbeatTotalProposalValidityBlocks,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		permit,
	)

	if err := action.execute(); err != nil {
		t.Fatalf("a suppressed penalty must not be an ordinary failure: [%v]", err)
	}

	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after suppression",
		0,
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	if inactivityClaimExecutor.sessionID != nil {
		t.Error("expected no inactivity claim after suppression")
	}
	if !permit.isClosed() {
		t.Error("expected the action to release its permit")
	}
}

// TestHeartbeatAction_PenaltySuppressedByQuiescingGate proves the real gate's
// quiescence suppresses a pending heartbeat penalty: a low-activity result
// during process quiescence neither increments the consecutive-failure
// counter nor files a claim, even when the counter is one failure short of
// the claim threshold.
func TestHeartbeatAction_PenaltySuppressedByQuiescingGate(t *testing.T) {
	walletPublicKeyHex, err := hex.DecodeString(
		"0471e30bca60f6548d7b42582a478ea37ada63b402af7b3ddd57f0c95bb6843175" +
			"aa0d2053a91a050a6797d85c38f2909cb7027f2344a01986aa2f9f8ca7a0c289",
	)
	if err != nil {
		t.Fatal(err)
	}

	walletPublicKeyStr := hex.EncodeToString(walletPublicKeyHex)

	proposal := &HeartbeatProposal{
		Message: [16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	// One failure short of the claim threshold: a normal low-activity result
	// would increment the counter and file a claim.
	heartbeatFailureCounter := newHeartbeatFailureCounter()
	for i := uint(0); i < heartbeatConsecutiveFailureThreshold-1; i++ {
		heartbeatFailureCounter.increment(walletPublicKeyStr)
	}

	hostChain := Connect()
	hostChain.setOperatorsEligibleStake(big.NewInt(100000))
	hostChain.setHeartbeatProposalValidationResult(proposal, true)

	blockCounter, err := hostChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)
	permit, err := gate.Begin(participation.TBTCHeartbeat, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Quiescence begins while the heartbeat is in flight: the permit stays
	// alive to natural completion but new penalty state is suppressed.
	gate.Quiesce(fmt.Errorf("shutdown"))

	mockExecutor := &mockHeartbeatSigningExecutor{}
	mockExecutor.activeOperatorsCount = heartbeatSigningMinimumActiveMembers - 1

	inactivityClaimExecutor := &mockInactivityClaimExecutor{}

	action := newHeartbeatAction(
		logger,
		hostChain,
		wallet{
			publicKey: mustUnmarshalPublicKey(t, walletPublicKeyHex),
		},
		mockExecutor,
		proposal,
		heartbeatFailureCounter,
		inactivityClaimExecutor,
		10,
		10+heartbeatTotalProposalValidityBlocks,
		func(ctx context.Context, blockHeight uint64) error {
			return nil
		},
		permit,
	)

	if err := action.execute(); err != nil {
		t.Fatalf("a suppressed penalty must not be an ordinary failure: [%v]", err)
	}

	testutils.AssertUintsEqual(
		t,
		"consecutive failure counter after suppression",
		uint64(heartbeatConsecutiveFailureThreshold-1),
		uint64(heartbeatFailureCounter.get(walletPublicKeyStr)),
	)
	if inactivityClaimExecutor.sessionID != nil {
		t.Error("expected no inactivity claim after suppression")
	}
}

// TestWalletTransactionExecutor_BroadcastRefusedByGate proves the commit
// fence runs before every Bitcoin broadcast attempt: a refused fence
// surfaces the gate sentinel and the transaction never reaches the Bitcoin
// chain.
func TestWalletTransactionExecutor_BroadcastRefusedByGate(t *testing.T) {
	permit := newTestPermit(participation.TBTCSigning)
	permit.commitErr = participation.ErrQuiescing

	btcChain := newLocalBitcoinChain()

	wte := &walletTransactionExecutor{
		btcChain:           btcChain,
		permit:             permit,
		broadcastOperation: "tbtc_deposit_sweep_bitcoin_broadcast",
	}

	tx := &bitcoin.Transaction{Version: 1}

	err := wte.broadcastTransaction(
		logger.With(),
		tx,
		10*time.Second,
		time.Millisecond,
	)
	if !errors.Is(err, participation.ErrQuiescing) {
		t.Fatalf("expected the gate sentinel, got [%v]", err)
	}

	if _, err := btcChain.GetTransaction(tx.Hash()); err == nil {
		t.Error("expected the transaction to never reach the Bitcoin chain")
	}

	operations := permit.commitOperations()
	testutils.AssertIntsEqual(t, "fence consultations", 1, len(operations))
	testutils.AssertStringsEqual(
		t,
		"fence operation",
		"tbtc_deposit_sweep_bitcoin_broadcast",
		operations[0],
	)
}

// quarantinedFailedOperation decodes the single quarantine metadata record in
// the given handle and returns its failed-operation name.
func quarantinedFailedOperation(
	t *testing.T,
	quarantineHandle *mockPersistenceHandle,
) string {
	t.Helper()

	var metadataContent []byte
	for _, descriptor := range quarantineHandle.saved {
		if strings.HasPrefix(descriptor.Name(), "/metadata_") {
			metadataContent, _ = descriptor.Content()
		}
	}
	if metadataContent == nil {
		t.Fatal("expected a quarantine metadata record")
	}

	var metadata QuarantinedSignerMetadata
	if err := json.Unmarshal(metadataContent, &metadata); err != nil {
		t.Fatal(err)
	}

	return metadata.FailedOperation
}

// TestDkgExecutor_CompleteDkgCeremony_ActivatesAfterPublication proves the
// completion order of a DKG ceremony: the result publication concludes first,
// the activation fence is consulted only afterwards, and only then is the
// signer persisted in the active namespace and activated in the wallet cache.
func TestDkgExecutor_CompleteDkgCeremony_ActivatesAfterPublication(t *testing.T) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	published := false
	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(context.Context) error {
			// The activation fence must not have been consulted before the
			// publication concluded.
			testutils.AssertIntsEqual(
				t,
				"fence consultations during publication",
				0,
				len(permit.commitOperations()),
			)
			published = true
			return nil
		},
	)

	if !published {
		t.Fatal("expected the result publication to run")
	}
	if !activated {
		t.Fatal("expected the signer to be activated")
	}

	operations := permit.commitOperations()
	testutils.AssertIntsEqual(t, "fence consultations", 1, len(operations))
	testutils.AssertStringsEqual(
		t,
		"fence operation",
		"tbtc_dkg_signer_activation",
		operations[0],
	)

	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		1,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"activated signers",
		1,
		len(de.walletRegistry.getSigners(result.PrivateKeyShare.PublicKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		0,
		len(quarantineHandle.saved),
	)

	terminalOutcomes := permit.recordedTerminalOutcomes()
	testutils.AssertIntsEqual(
		t,
		"terminal outcomes",
		1,
		len(terminalOutcomes),
	)
	if len(terminalOutcomes) == 1 {
		if terminalOutcomes[0].outcome !=
			participation.TerminalOutcomeCompleted {
			t.Errorf(
				"unexpected terminal outcome [%s]",
				terminalOutcomes[0].outcome,
			)
		}
		if terminalOutcomes[0].evidence.MembershipIndex !=
			group.MemberIndex(1) {
			t.Errorf(
				"terminal outcome names membership [%d], expected [1]",
				terminalOutcomes[0].evidence.MembershipIndex,
			)
		}
	}
}

// TestDkgExecutor_CompleteDkgCeremony_RegistrationFailureQuarantinesOnly
// proves a registration failure between the concluded result publication and
// the wallet-cache activation preserves the generated share only in the
// protected quarantine namespace. The wallet ID calculation is the last
// fallible registration step, and its failure must not leave a partial record
// in the active namespace that a restart's — or any release's — active scan
// would load beside the quarantined copy.
func TestDkgExecutor_CompleteDkgCeremony_RegistrationFailureQuarantinesOnly(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	// The registry's wallet ID calculation fails while the chain's own
	// calculation keeps succeeding, so the preservation path can still check
	// the wallet's on-chain registration and choose quarantine.
	failingRegistry, err := newWalletRegistry(
		registryHandle,
		func(*ecdsa.PublicKey) ([32]byte, error) {
			return [32]byte{}, fmt.Errorf("wallet ID calculation failed")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	de.walletRegistry = failingRegistry

	permit := newTestPermit(participation.TBTCDKG)

	published := false
	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(context.Context) error {
			published = true
			return nil
		},
	)

	if !published {
		t.Fatal("expected the result publication to run")
	}
	if activated {
		t.Fatal("expected no signer activation")
	}

	operations := permit.commitOperations()
	testutils.AssertIntsEqual(t, "fence consultations", 1, len(operations))

	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		0,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"activated signers",
		0,
		len(de.walletRegistry.getSigners(result.PrivateKeyShare.PublicKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertStringsEqual(
		t,
		"quarantined failed operation",
		"tbtc_dkg_signer_registration",
		quarantinedFailedOperation(t, quarantineHandle),
	)
}

// TestDkgExecutor_CompleteDkgCeremony_PublicationGateRefusalQuarantines
// proves a submission fence refusal during result publication preserves the
// generated share only in the protected quarantine namespace: the activation
// fence is never consulted and the signer is neither saved to the active
// namespace nor activated in the wallet cache.
func TestDkgExecutor_CompleteDkgCeremony_PublicationGateRefusalQuarantines(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(context.Context) error {
			return fmt.Errorf(
				"completion commit refused: %w",
				participation.ErrClockUnavailable,
			)
		},
	)

	if activated {
		t.Fatal("expected no signer activation")
	}
	testutils.AssertIntsEqual(
		t,
		"fence consultations",
		0,
		len(permit.commitOperations()),
	)
	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		0,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"activated signers",
		0,
		len(de.walletRegistry.getSigners(result.PrivateKeyShare.PublicKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertStringsEqual(
		t,
		"quarantined failed operation",
		"tbtc_dkg_result_publication",
		quarantinedFailedOperation(t, quarantineHandle),
	)
}

// TestDkgExecutor_CompleteDkgCeremony_ClockLossDuringPublicationQuarantines
// proves a clock-failure permit cancellation racing the result publication —
// the publication itself surfaces only a plain context cancellation, the gate
// cause lives in the permit context — preserves the share only in quarantine
// and never activates it.
func TestDkgExecutor_CompleteDkgCeremony_ClockLossDuringPublicationQuarantines(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(publishCtx context.Context) error {
			// The gate loses the chain clock while the publication is in
			// flight: the permit is canceled with the gate cause and the
			// publication ends with a plain context cancellation.
			permit.cancel(participation.ErrClockUnavailable)
			<-publishCtx.Done()
			return publishCtx.Err()
		},
	)

	if activated {
		t.Fatal("expected no signer activation")
	}
	testutils.AssertIntsEqual(
		t,
		"fence consultations",
		0,
		len(permit.commitOperations()),
	)
	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		0,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"activated signers",
		0,
		len(de.walletRegistry.getSigners(result.PrivateKeyShare.PublicKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertStringsEqual(
		t,
		"quarantined failed operation",
		"tbtc_dkg_result_publication",
		quarantinedFailedOperation(t, quarantineHandle),
	)
}

// TestDkgExecutor_CompleteDkgCeremony_ActivatesWhenAnotherMemberSubmitted
// proves a publication ended by the on-chain submission event — another
// member submitted the result first — still activates the signer through the
// activation fence: the ceremony completed and the share is needed.
func TestDkgExecutor_CompleteDkgCeremony_ActivatesWhenAnotherMemberSubmitted(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return true },
		func(context.Context) error {
			return context.Canceled
		},
	)

	if !activated {
		t.Fatal("expected the signer to be activated")
	}
	operations := permit.commitOperations()
	testutils.AssertIntsEqual(t, "fence consultations", 1, len(operations))
	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		1,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"activated signers",
		1,
		len(de.walletRegistry.getSigners(result.PrivateKeyShare.PublicKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		0,
		len(quarantineHandle.saved),
	)
}

// TestDkgExecutor_CompleteDkgCeremony_TimeoutWithoutSubmissionQuarantines
// proves a publication window that closes without any observed submitted
// result preserves the share only in quarantine: the wallet may never appear
// on chain, so activating the signer would leave an active signer for an
// unpublished result.
func TestDkgExecutor_CompleteDkgCeremony_TimeoutWithoutSubmissionQuarantines(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)

	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(context.Context) error {
			return context.Canceled
		},
	)

	if activated {
		t.Fatal("expected no signer activation")
	}
	testutils.AssertIntsEqual(
		t,
		"fence consultations",
		0,
		len(permit.commitOperations()),
	)
	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		0,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertStringsEqual(
		t,
		"quarantined failed operation",
		"tbtc_dkg_result_publication",
		quarantinedFailedOperation(t, quarantineHandle),
	)
}

// TestDkgExecutor_CompleteDkgCeremony_ActivationFenceRefusalQuarantines
// proves a refused activation fence after a successful publication preserves
// the share only in quarantine when the wallet is not yet registered on
// chain, and never activates it in this process.
func TestDkgExecutor_CompleteDkgCeremony_ActivationFenceRefusalQuarantines(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	permit := newTestPermit(participation.TBTCDKG)
	permit.commitErr = participation.ErrQuiesceDeadline

	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(context.Context) error {
			return nil
		},
	)

	if activated {
		t.Fatal("expected no signer activation")
	}
	operations := permit.commitOperations()
	testutils.AssertIntsEqual(t, "fence consultations", 1, len(operations))
	testutils.AssertStringsEqual(
		t,
		"fence operation",
		"tbtc_dkg_signer_activation",
		operations[0],
	)
	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		0,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertStringsEqual(
		t,
		"quarantined failed operation",
		"tbtc_dkg_signer_activation",
		quarantinedFailedOperation(t, quarantineHandle),
	)
}

// TestDkgExecutor_CompleteDkgCeremony_QuiesceDeadlineRaceWithRealGate proves
// the deterministic forced-quiescence race against a real gate: the process
// shutdown deadline arrives while the result publication is in flight, the
// permit is force-canceled with the gate cause, and the generated share ends
// up only in quarantine — never active, never dropped.
func TestDkgExecutor_CompleteDkgCeremony_QuiesceDeadlineRaceWithRealGate(
	t *testing.T,
) {
	de, result, gsr, registryHandle, quarantineHandle := setupPreserveScenario(t)

	blockCounter, err := de.chain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}
	if err := blockCounter.WaitForBlockHeight(1); err != nil {
		t.Fatal(err)
	}

	gate := newTestGate(t, blockCounter)
	de.participationGate = gate

	permit, err := gate.Begin(participation.TBTCDKG, 1)
	if err != nil {
		t.Fatal(err)
	}

	activated := de.completeDkgCeremony(
		permit.Context(),
		logger.With(),
		permit,
		big.NewInt(1),
		result,
		group.MemberIndex(1),
		gsr,
		func() bool { return false },
		func(publishCtx context.Context) error {
			// The shutdown deadline arrives mid-publication: Close
			// force-cancels the permit with the gate cause and the
			// publication ends with a plain context cancellation.
			gate.Close()
			<-publishCtx.Done()
			return publishCtx.Err()
		},
	)

	if activated {
		t.Fatal("expected no signer activation")
	}
	testutils.AssertIntsEqual(
		t,
		"active-namespace saves",
		0,
		len(registryHandle.saved),
	)
	testutils.AssertIntsEqual(
		t,
		"activated signers",
		0,
		len(de.walletRegistry.getSigners(result.PrivateKeyShare.PublicKey())),
	)
	testutils.AssertIntsEqual(
		t,
		"quarantined records",
		2,
		len(quarantineHandle.saved),
	)
	testutils.AssertStringsEqual(
		t,
		"quarantined failed operation",
		"tbtc_dkg_result_publication",
		quarantinedFailedOperation(t, quarantineHandle),
	)
}

// TestSigningExecutor_Sign_GateCancellationSkipsFailureMetrics proves a
// gate-caused signing cancellation — clock failure carried as the context
// cause — leaves the ordinary signing failure and timeout counters unchanged
// and surfaces the gate sentinel, while an ordinary cancellation still counts
// as a failure and a timeout.
func TestSigningExecutor_Sign_GateCancellationSkipsFailureMetrics(t *testing.T) {
	executor := setupSigningExecutor(t)

	recorder := newDispatcherMetricsRecorder()
	executor.setMetricsRecorder(recorder)

	gateCtx, cancelGateCtx := context.WithCancelCause(context.Background())
	cancelGateCtx(participation.ErrClockUnavailable)

	_, err := executor.sign(
		gateCtx,
		big.NewInt(100),
		0,
		participation.ModeSecurityV2,
	)
	if !errors.Is(err, participation.ErrClockUnavailable) {
		t.Fatalf("expected the gate sentinel, got [%v]", err)
	}

	if failed := recorder.counter(clientinfo.MetricSigningFailedTotal); failed != 0 {
		t.Errorf("expected no ordinary signing failures, got [%v]", failed)
	}
	if timeouts := recorder.counter(clientinfo.MetricSigningTimeoutsTotal); timeouts != 0 {
		t.Errorf("expected no ordinary signing timeouts, got [%v]", timeouts)
	}

	// An ordinary cancellation without a gate cause still counts as an
	// ordinary failure and timeout.
	plainCtx, cancelPlainCtx := context.WithCancel(context.Background())
	cancelPlainCtx()

	_, err = executor.sign(
		plainCtx,
		big.NewInt(101),
		0,
		participation.ModeSecurityV2,
	)
	if err == nil {
		t.Fatal("expected an error from the canceled signing")
	}
	if errors.Is(err, participation.ErrClockUnavailable) {
		t.Fatalf("expected no gate sentinel, got [%v]", err)
	}

	if failed := recorder.counter(clientinfo.MetricSigningFailedTotal); failed != 1 {
		t.Errorf("expected one ordinary signing failure, got [%v]", failed)
	}
	if timeouts := recorder.counter(clientinfo.MetricSigningTimeoutsTotal); timeouts != 1 {
		t.Errorf("expected one ordinary signing timeout, got [%v]", timeouts)
	}
}

// dispatchGaugeRecorder extends the counting recorder with gauge capture so
// tests can wait for the dispatcher's active-actions gauge to return to zero
// — the gauge is reset only after an action's goroutine finished all its
// metric accounting.
type dispatchGaugeRecorder struct {
	*dispatcherMetricsRecorder

	gaugeMu sync.Mutex
	gauges  map[string]float64
}

func newDispatchGaugeRecorder() *dispatchGaugeRecorder {
	return &dispatchGaugeRecorder{
		dispatcherMetricsRecorder: newDispatcherMetricsRecorder(),
		gauges:                    make(map[string]float64),
	}
}

func (r *dispatchGaugeRecorder) SetGauge(name string, value float64) {
	r.gaugeMu.Lock()
	defer r.gaugeMu.Unlock()
	r.gauges[name] = value
}

func (r *dispatchGaugeRecorder) gauge(name string) float64 {
	r.gaugeMu.Lock()
	defer r.gaugeMu.Unlock()
	return r.gauges[name]
}

// gaugePublished reports the value alongside whether the gauge was published at
// all. A gauge nobody set reads back as zero, which is the one value a
// quarantine count must never be confused with.
func (r *dispatchGaugeRecorder) gaugePublished(name string) (float64, bool) {
	r.gaugeMu.Lock()
	defer r.gaugeMu.Unlock()
	value, published := r.gauges[name]
	return value, published
}

// TestWalletDispatcher_Dispatch_GateRefusalSkipsFailureMetrics proves a
// wallet action ended by a gate refusal is counted neither as an ordinary
// action failure nor as a success, on both the aggregate and the per-action
// counters, while an ordinary action error still counts as a failure.
func TestWalletDispatcher_Dispatch_GateRefusalSkipsFailureMetrics(t *testing.T) {
	walletDispatcher := newWalletDispatcher()
	recorder := newDispatchGaugeRecorder()
	walletDispatcher.setMetricsRecorder(recorder)

	actionWallet := generateWallet(big.NewInt(100))

	dispatchAndWait := func(action *mockWalletAction) {
		t.Helper()

		if err := walletDispatcher.dispatch(action); err != nil {
			t.Fatal(err)
		}
		// The active-actions gauge returns to zero only in the action
		// goroutine's final cleanup, after every counter update.
		deadline := time.Now().Add(10 * time.Second)
		for recorder.gauge(clientinfo.MetricWalletDispatcherActiveActions) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("the dispatched action never completed")
			}
			time.Sleep(time.Millisecond)
		}
	}

	dispatchAndWait(&mockWalletAction{
		executeFn: func() error {
			return fmt.Errorf(
				"broadcast refused: %w",
				participation.ErrQuiesceDeadline,
			)
		},
		actionWallet: actionWallet,
	})

	failedName := clientinfo.WalletActionMetricName("noop", "failed_total")
	successName := clientinfo.WalletActionMetricName("noop", "success_total")

	if failed := recorder.counter(clientinfo.MetricWalletActionFailedTotal); failed != 0 {
		t.Errorf("expected no aggregate action failures, got [%v]", failed)
	}
	if failed := recorder.counter(failedName); failed != 0 {
		t.Errorf("expected no per-action failures, got [%v]", failed)
	}
	if success := recorder.counter(successName); success != 0 {
		t.Errorf("expected no action successes, got [%v]", success)
	}

	dispatchAndWait(&mockWalletAction{
		executeFn: func() error {
			return fmt.Errorf("ordinary failure")
		},
		actionWallet: actionWallet,
	})

	if failed := recorder.counter(clientinfo.MetricWalletActionFailedTotal); failed != 1 {
		t.Errorf("expected one aggregate action failure, got [%v]", failed)
	}
	if failed := recorder.counter(failedName); failed != 1 {
		t.Errorf("expected one per-action failure, got [%v]", failed)
	}
	if success := recorder.counter(successName); success != 0 {
		t.Errorf("expected no action successes, got [%v]", success)
	}
}

// TestWalletTransactionExecutor_BroadcastAbortSurfacesGateCause proves an
// ended broadcast window caused by a gate permit cancellation surfaces the
// gate sentinel instead of the ordinary broadcast timeout.
func TestWalletTransactionExecutor_BroadcastAbortSurfacesGateCause(t *testing.T) {
	permit := newTestPermit(participation.TBTCSigning)
	permit.cancel(participation.ErrClockUnavailable)

	wte := &walletTransactionExecutor{
		btcChain: newLocalBitcoinChain(),
		permit:   permit,
	}

	err := wte.broadcastTransaction(
		logger.With(),
		&bitcoin.Transaction{Version: 1},
		10*time.Second,
		time.Millisecond,
	)
	if !errors.Is(err, participation.ErrClockUnavailable) {
		t.Fatalf("expected the gate sentinel, got [%v]", err)
	}
}
