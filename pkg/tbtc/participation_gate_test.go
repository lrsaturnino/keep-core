package tbtc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
		signerQuarantine: newSignerQuarantine(
			context.Background(),
			logger,
			quarantineHandle,
		),
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
		context.Background(),
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

// TestDkgExecutor_ReportQuarantinedSigners_AddsANewOutputToWhatTheLastScanFound
// proves a recount that fails after a new share was preserved reports the
// inherited outputs and the new one together.
//
// The material this process wrote and the material it inherited are known from
// different places: the first from its own confirmed writes, the second only
// from a scan. A node holding both that falls back to its own writes alone
// reports fewer preserved outputs than the namespace held before it started —
// and the more an earlier process left behind, the further under the truth the
// number lands.
func TestDkgExecutor_ReportQuarantinedSigners_AddsANewOutputToWhatTheLastScanFound(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	// Two outputs an earlier process on this host preserved, in a namespace
	// that serves the startup scan and nothing after it.
	handle := &scanBudgetHandle{readableScans: 1}
	for _, name := range []string{"/membership_1", "/membership_2"} {
		if err := handle.Save([]byte("x"), "inherited-wallet", name); err != nil {
			t.Fatal(err)
		}
	}
	de.signerQuarantine = newTestSignerQuarantine(handle, 1)

	if err := de.reportInitialQuarantinedSigners(); err != nil {
		t.Fatal(err)
	}
	testutils.AssertIntsEqual(
		t,
		"quarantined signers this process inherited",
		2,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)

	// A third, distinct output, preserved once the namespace can no longer be
	// enumerated: the write is confirmed, every recount around it fails.
	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after preserving a third output",
		3,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportQuarantinedSigners_CountsARepreservedSeatOnce proves
// preserving the same output twice does not raise the count twice.
//
// The count is of preserved shares, not of preservations. One seat of one
// wallet is one share however many times it is written — a retry, a second
// interruption of the same ceremony — and a count that adds a share the
// namespace holds one copy of describes a namespace this host does not have.
func TestDkgExecutor_ReportQuarantinedSigners_CountsARepreservedSeatOnce(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	handle := &scanBudgetHandle{readableScans: 1}
	for _, name := range []string{"/membership_1", "/membership_2"} {
		if err := handle.Save([]byte("x"), "inherited-wallet", name); err != nil {
			t.Fatal(err)
		}
	}
	de.signerQuarantine = newTestSignerQuarantine(handle, 1)

	if err := de.reportInitialQuarantinedSigners(); err != nil {
		t.Fatal(err)
	}

	// The same wallet and the same seat, preserved twice while the namespace
	// cannot be read back to settle what it holds.
	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))
	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after re-preserving one seat",
		3,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportQuarantinedSigners_DoesNotResurrectAClearedOutput
// proves an output a successful scan found gone is not brought back by the next
// scan that fails.
//
// What this process wrote is only a floor until the namespace can be asked
// about it. Once a scan does succeed, it has enumerated the namespace after
// every one of those writes, so a write it does not find is a record an
// operator cleared or a seat that was activated. Carrying that identity forward
// would let the next unreadable namespace raise the count back over an output
// nobody holds — a rollback sent looking for material that is not there, from a
// node that is otherwise reporting correctly.
func TestDkgExecutor_ReportQuarantinedSigners_DoesNotResurrectAClearedOutput(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	// Two enumerations: the one preservation takes when it is done, and the one
	// that follows the operator's repair. Everything after that fails.
	handle := &scanBudgetHandle{readableScans: 2}
	de.signerQuarantine = newTestSignerQuarantine(handle, 1)

	walletStorageKey := preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after preserving one output",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)

	// The operator clears the preserved record, having accounted for the share
	// by hand, and the recount that follows sees the namespace without it.
	if err := handle.Delete(walletStorageKey, "/membership_1"); err != nil {
		t.Fatal(err)
	}

	de.reportQuarantinedSigners(logger.With())

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after the record was cleared",
		0,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)

	// The namespace stops being readable. What this process wrote is no longer
	// its own to vouch for: a scan already established the namespace does not
	// hold it.
	de.reportQuarantinedSigners(logger.With())

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers once the namespace stops answering",
		0,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// scanBudgetHandle is a protected namespace that serves a fixed number of
// enumerations and fails every one after that, as a namespace does when its
// directory stops being readable while the process runs. Its writes always
// succeed: what it models is a node that can still preserve material it can no
// longer count.
type scanBudgetHandle struct {
	mockPersistenceHandle

	readableScans int

	mu    sync.Mutex
	scans int
}

func (h *scanBudgetHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.mockPersistenceHandle.Save(data, directory, name)
}

func (h *scanBudgetHandle) Delete(directory string, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.mockPersistenceHandle.Delete(directory, name)
}

func (h *scanBudgetHandle) ReadAll() (
	<-chan persistence.DataDescriptor,
	<-chan error,
) {
	h.mu.Lock()
	h.scans++
	readable := h.scans <= h.readableScans
	saved := append([]persistence.DataDescriptor(nil), h.saved...)
	h.mu.Unlock()

	descriptors := make(chan persistence.DataDescriptor, len(saved))
	errs := make(chan error, 1)

	defer close(descriptors)
	defer close(errs)

	if !readable {
		errs <- fmt.Errorf("the quarantine directory is unreadable")
		return descriptors, errs
	}

	for _, descriptor := range saved {
		descriptors <- descriptor
	}

	return descriptors, errs
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
	de.signerQuarantine = newSignerQuarantine(
		context.Background(),
		logger,
		&unreadableHandle{},
	)

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
	de.signerQuarantine = newSignerQuarantine(context.Background(), logger, tracking)

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
// records carrying key material are read as signer outputs — the membership of
// a pair and the combined handoff — and that a seat named by both is one
// output. The namespace also holds the audit metadata, and a later schema or an
// operator may leave other names there; none of them is a preserved share.
func TestSignerQuarantine_PreservedOutputs_CountsMembershipsOnly(t *testing.T) {
	handle := &mockPersistenceHandle{}
	quarantine := newSignerQuarantine(context.Background(), logger, handle)

	for _, name := range []string{
		"/membership_1",
		"/metadata_1",
		// The same seat, written again as one record when the namespace would
		// not complete the pair. One share, however many times it was offered.
		"/handoff_1",
		"/membership_17",
		"/metadata_17",
		// A seat the namespace only ever took whole.
		"/handoff_23",
		// Not signer outputs: seat zero is no seat, an unparsable seat names
		// none, and neither a later schema's record nor a stray file is a share.
		"/membership_0",
		"/membership_two",
		"/handoff_0",
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

	testutils.AssertIntsEqual(t, "preserved outputs", 3, len(outputs))

	seats := make(map[group.MemberIndex]string)
	for _, output := range outputs {
		seats[output.memberIndex] = output.walletStorageKey
	}
	for _, seat := range []group.MemberIndex{1, 17, 23} {
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
	quarantine := newSignerQuarantine(
		context.Background(),
		logger,
		&unreadableHandle{},
	)

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

// unwritableRecordHandle is a protected namespace that refuses the record names
// it is given while writing their neighbours, as a disk namespace does when
// particular files cannot be written.
//
// The names are a list because a preserved output is offered under more than
// one of them: refusing the record pair and refusing the output are different
// namespaces, and only the second one costs the node a share.
type unwritableRecordHandle struct {
	mockPersistenceHandle

	// refusedNamePrefixes name the records this namespace will not accept.
	refusedNamePrefixes []string
}

func (h *unwritableRecordHandle) refuses(name string) bool {
	for _, prefix := range h.refusedNamePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

func (h *unwritableRecordHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	if h.refuses(name) {
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

	mu       sync.Mutex
	errors   []string
	warnings []string
}

func (c *quarantineLogCapture) Errorf(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, fmt.Sprintf(format, args...))
}

func (c *quarantineLogCapture) Warnf(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

func (c *quarantineLogCapture) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.errors, "\n")
}

// joinedWarnings is kept apart from joined because the two say different
// things: an error line is a state an operator has to act on, a warning line is
// the record of what happened to an output.
func (c *quarantineLogCapture) joinedWarnings() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.warnings, "\n")
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
// no record of a quarantined output is skipped because another failed, and that
// the caller is told which of them the namespace actually holds.
//
// The records mean different things — the membership is the key material a
// rollback has to account for, the metadata is the record explaining it, the
// handoff is both at once — and the error alone cannot say which are on disk. A
// caller that guesses is how the operator log, the published count, and the
// offline audit come to describe the same directory differently.
//
// A name the namespace refuses does not decide the outcome: a round that cannot
// complete the pair offers the output whole under a name of its own, so only a
// namespace refusing everything leaves a share with nowhere to go.
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
		handoffPersisted    bool
	}{
		"both records land": {
			refusedNamePrefix:   "/nothing_is_refused",
			expectedSaved:       []string{"/membership_1", "/metadata_1"},
			membershipPersisted: true,
			metadataPersisted:   true,
		},
		"the metadata is refused": {
			refusedNamePrefix:   "/metadata_",
			expectedSaved:       []string{"/membership_1", "/handoff_1"},
			membershipPersisted: true,
			metadataPersisted:   false,
			handoffPersisted:    true,
		},
		"the membership is refused": {
			refusedNamePrefix:   "/membership_",
			expectedSaved:       []string{"/metadata_1", "/handoff_1"},
			membershipPersisted: false,
			metadataPersisted:   true,
			handoffPersisted:    true,
		},
		"the namespace refuses every record": {
			refusedNamePrefix: "/",
			expectedSaved:     []string{},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			handle := &unwritableRecordHandle{
				refusedNamePrefixes: []string{test.refusedNamePrefix},
			}
			// One round, then the process is taken to have ended: this asks
			// what a single pass writes and reports, not how long the retry
			// behind it lasts.
			quarantine := newTestSignerQuarantine(handle, 1)

			state, err := quarantine.preserve(
				signer,
				QuarantinedSignerMetadata{
					ReleaseEpoch: participation.CompiledEpoch.String(),
					Ceremony:     string(participation.TBTCDKG),
				},
				quarantineObserver{},
			)

			expectedComplete := test.handoffPersisted ||
				(test.membershipPersisted && test.metadataPersisted)
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
			testutils.AssertBoolsEqual(
				t,
				"handoff persisted",
				test.handoffPersisted,
				state.handoffPersisted,
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

// TestDkgExecutor_PreserveInterruptedSigner_RefusedMetadataLeavesThePermitUnresolved
// proves a share the namespace accepted without any audit record is counted but
// not called resolved: the published count includes the output, the permit ends
// with no terminal outcome, and the node stops taking new ceremonies.
//
// The key material is on disk, so a rollback has to account for it — that is the
// count. What is missing is everything that would let the offline audit match it
// against the chain: the mode, the canonical anchor, the ceremony, the seat, and
// the operation that was refused. Recording the permit as quarantined on the key
// material alone would hand the rollback decision a preserved share nothing
// explains and call the inventory complete.
//
// Both records that carry the audit fields are refused here, because either one
// of them landing is enough to explain the share.
func TestDkgExecutor_PreserveInterruptedSigner_RefusedMetadataLeavesThePermitUnresolved(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	handle := &unwritableRecordHandle{
		refusedNamePrefixes: []string{"/metadata_", "/handoff_"},
	}
	de.signerQuarantine = newTestSignerQuarantine(handle, 1)

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

	if outcomes := permit.recordedTerminalOutcomes(); len(outcomes) != 0 {
		t.Errorf(
			"a preserved share with no audit record explaining it must "+
				"leave the permit unresolved, got %v",
			outcomes,
		)
	}

	value, published := recorder.gaugePublished(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
	)
	if !published {
		t.Fatal("expected the preserved share to be counted")
	}
	testutils.AssertIntsEqual(t, "reported quarantined signers", 1, int(value))

	testutils.AssertBoolsEqual(
		t,
		"the gate quiesced on the unexplained share",
		true,
		de.participationGate.State().Quiescing,
	)
}

// TestDkgExecutor_PreserveInterruptedSigner_ProlongedRefusalStillEndsQuarantined
// proves the permit does resolve once both halves are durable, however long the
// namespace took to accept them.
//
// The blocking state exists to keep an incomplete output from being called
// resolved, not to make every namespace hiccup permanent. A metadata write that
// lands on a later round leaves an output the offline audit can reconcile, so
// the permit ends quarantined — while the node still stops taking new work,
// because it spent longer than a passing fault holding an output the namespace
// did not have.
func TestDkgExecutor_PreserveInterruptedSigner_ProlongedRefusalStillEndsQuarantined(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	// Refused far past the grace budget, then accepted — the namespace an
	// operator is repairing while the node holds the share. The handoff is
	// refused for as long, so what the retry is waiting on is the pair itself.
	handle := &flakyRecordHandle{
		namePrefixes: []string{"/metadata_", "/handoff_"},
		refusals:     quarantineGraceAttempts * 4,
	}
	de.signerQuarantine = newTestSignerQuarantine(handle, 50)

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

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/membership_1", "/metadata_1"},
	) {
		t.Errorf("namespace holds %v, expected both halves", got)
	}
	testutils.AssertIntsEqual(
		t,
		"metadata write attempts",
		quarantineGraceAttempts*4+1,
		handle.attemptCount(),
	)

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

	testutils.AssertBoolsEqual(
		t,
		"the gate quiesced while the namespace was refusing",
		true,
		de.participationGate.State().Quiescing,
	)
}

// TestDkgExecutor_PreserveInterruptedSigner_RefusedMembershipIsNotQuarantined
// proves a share no record of the namespace took is not reported as
// quarantined: the permit records no terminal outcome and no count is
// published, while the audit metadata naming the lost share is still written.
//
// The metadata is what tells the offline audit a share was generated and not
// preserved. Skipping it because the records carrying key material failed first
// would leave the loss with no record at all.
//
// Both of those records are refused here. A namespace that turns down only the
// membership still has the handoff to take the share in, and this is about the
// state where nothing did.
func TestDkgExecutor_PreserveInterruptedSigner_RefusedMembershipIsNotQuarantined(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	handle := &unwritableRecordHandle{
		refusedNamePrefixes: []string{"/membership_", "/handoff_"},
	}
	de.signerQuarantine = newTestSignerQuarantine(handle, 1)

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

// flakyRecordHandle refuses the first refusals writes of the named record and
// accepts every write after that, counting the attempts made on it. It stands
// for a namespace that is momentarily unwritable — a mount being restored, a
// disk an operator is draining — which is the condition a single-attempt write
// would report as permanently lost key material.
type flakyRecordHandle struct {
	mockPersistenceHandle

	// namePrefixes name the records this namespace refuses while it is
	// unwritable. The first of them is the one whose attempts are counted:
	// preservation writes it once per round for as long as it has not landed,
	// so its attempt number is the round number.
	namePrefixes []string
	refusals     int

	mu       sync.Mutex
	attempts int
}

func (h *flakyRecordHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	refused := false
	for _, prefix := range h.namePrefixes {
		if strings.HasPrefix(name, prefix) {
			refused = true
			break
		}
	}
	if !refused {
		return h.mockPersistenceHandle.Save(data, directory, name)
	}

	h.mu.Lock()
	if strings.HasPrefix(name, h.namePrefixes[0]) {
		h.attempts++
	}
	attempt := h.attempts
	h.mu.Unlock()

	if attempt <= h.refusals {
		return fmt.Errorf("cannot write [%s] yet", name)
	}

	return h.mockPersistenceHandle.Save(data, directory, name)
}

func (h *flakyRecordHandle) attemptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attempts
}

// newTestSignerQuarantine builds a quarantine store that retries exactly the way
// the production one does but ends its process lifetime after the given number
// of rounds instead of spending the real waits between them.
//
// Production preservation stops only with the process, because the key material
// it is holding cannot be generated again and no elapsed time makes discarding
// it safe. A test driving a namespace that never accepts the write therefore has
// to supply the ending itself: the round count is where this process is taken to
// have gone away.
func newTestSignerQuarantine(
	handle persistence.ProtectedHandle,
	roundsBeforeShutdown int,
) *signerQuarantine {
	quarantine := newSignerQuarantine(context.Background(), logger, handle)

	// Counted atomically because a store is shared by the members of a ceremony
	// that quarantine concurrently.
	var rounds atomic.Int64
	quarantine.wait = func(context.Context, time.Duration) bool {
		return rounds.Add(1) < int64(roundsBeforeShutdown)
	}

	return quarantine
}

// TestSignerQuarantine_Preserve_KeepsTryingThroughAProlongedRefusal proves key
// material is not declared lost because a namespace stayed unwritable for a
// while: preservation keeps the share in hand across far more refusals than a
// passing fault produces, and still writes it when the namespace comes back.
//
// The material on this path cannot be generated again, and the conditions that
// refuse a write are the ones an operator repairs — a mount being restored, a
// full disk being drained. A fixed attempt budget turns the length of that
// repair into the difference between a preserved share and a lost one, which is
// not a distinction the node is entitled to make.
func TestSignerQuarantine_Preserve_KeepsTryingThroughAProlongedRefusal(
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

	const refusals = quarantineGraceAttempts * 8

	// The handoff is refused for as long as the membership, so what is being
	// held across the repair is the key material itself and not a record that
	// already put it somewhere.
	handle := &flakyRecordHandle{
		namePrefixes: []string{"/membership_", "/handoff_"},
		refusals:     refusals,
	}

	// The notification the node acts on fires once and does not end the
	// attempt, so it is counted rather than allowed to stand in for a result.
	notifications := 0

	quarantine := newTestSignerQuarantine(handle, refusals*2)

	operatorLog := &quarantineLogCapture{}
	quarantine.logger = operatorLog

	state, err := quarantine.preserve(
		signer,
		QuarantinedSignerMetadata{
			ReleaseEpoch: participation.CompiledEpoch.String(),
			Ceremony:     string(participation.TBTCDKG),
		},
		quarantineObserver{
			stillIncomplete: func(quarantineState, error) { notifications++ },
		},
	)
	if err != nil {
		t.Fatalf(
			"expected the retried write to preserve the share, got [%v]",
			err,
		)
	}

	testutils.AssertBoolsEqual(
		t,
		"membership persisted",
		true,
		state.membershipPersisted,
	)
	testutils.AssertIntsEqual(
		t,
		"membership write attempts",
		refusals+1,
		handle.attemptCount(),
	)
	testutils.AssertIntsEqual(t, "block notifications", 1, notifications)

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/metadata_1", "/membership_1"},
	) {
		t.Errorf("namespace holds %v, expected both halves", got)
	}

	// The node was told, and the operator record says, that this share reached
	// no namespace. Leaving that as the last word would have an operator repair
	// a loss the namespace had already stopped being.
	if logged := operatorLog.joinedWarnings(); !strings.Contains(
		logged,
		"took the tbtc key material it had been refusing",
	) || !strings.Contains(
		logged,
		fmt.Sprintf("[round=%d]", refusals+1),
	) {
		t.Errorf(
			"the operator record must say which round the namespace took the "+
				"material in, got [%s]",
			logged,
		)
	}
}

// TestSignerQuarantine_Preserve_GivesUpOnlyWhenTheProcessEnds proves the retry
// has no deadline of its own: a namespace that never accepts the write is
// attempted every round until the process itself goes away, and the error says
// that is what ended it.
//
// The node is told once, well before that, that it is holding key material the
// namespace does not have — but being told is not the same as being finished,
// and preservation carries on behind the notification.
func TestSignerQuarantine_Preserve_GivesUpOnlyWhenTheProcessEnds(
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

	const roundsBeforeShutdown = quarantineGraceAttempts * 9

	handle := &flakyRecordHandle{
		namePrefixes: []string{"/membership_", "/handoff_"},
		refusals:     math.MaxInt32,
	}

	notifications := 0

	state, err := newTestSignerQuarantine(
		handle,
		roundsBeforeShutdown,
	).preserve(
		signer,
		QuarantinedSignerMetadata{
			ReleaseEpoch: participation.CompiledEpoch.String(),
			Ceremony:     string(participation.TBTCDKG),
		},
		quarantineObserver{
			stillIncomplete: func(quarantineState, error) { notifications++ },
		},
	)
	if err == nil {
		t.Fatal("expected a preservation error")
	}

	testutils.AssertBoolsEqual(
		t,
		"membership persisted",
		false,
		state.membershipPersisted,
	)
	testutils.AssertBoolsEqual(
		t,
		"metadata persisted",
		true,
		state.metadataPersisted,
	)
	testutils.AssertBoolsEqual(
		t,
		"handoff persisted",
		false,
		state.handoffPersisted,
	)
	testutils.AssertIntsEqual(
		t,
		"membership write attempts",
		roundsBeforeShutdown,
		handle.attemptCount(),
	)
	testutils.AssertIntsEqual(t, "block notifications", 1, notifications)

	if want := fmt.Sprintf(
		"in %d rounds before the process ended",
		roundsBeforeShutdown,
	); !strings.Contains(err.Error(), want) {
		t.Errorf(
			"the error must say the process ending is what stopped the "+
				"retry, got [%v]",
			err,
		)
	}
}

// latchedMembershipHandle refuses both halves of a preserved output until the
// given round, then takes the key material and goes on refusing the audit record
// for good.
//
// It stands for the namespace state a count has to survive: the share is down on
// disk while the record explaining it is still missing, and the preservation
// holding the pair open has not returned and, on this namespace, never will.
type latchedMembershipHandle struct {
	mockPersistenceHandle

	// membershipTakenAtRound is the round from which the key material is
	// accepted. The membership is attempted once per round for as long as it
	// has not landed, so its attempt count is the round number.
	membershipTakenAtRound int

	mu                 sync.Mutex
	membershipAttempts int
}

func (h *latchedMembershipHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	if !strings.HasPrefix(name, "/membership_") {
		return fmt.Errorf("cannot write [%s]", name)
	}

	h.mu.Lock()
	h.membershipAttempts++
	round := h.membershipAttempts
	h.mu.Unlock()

	if round < h.membershipTakenAtRound {
		return fmt.Errorf("cannot write [%s] yet", name)
	}

	return h.mockPersistenceHandle.Save(data, directory, name)
}

// TestDkgExecutor_PreserveInterruptedSigner_CountsTheShareTheNamespaceTakesMidRetry
// proves the reported count rises at the moment the namespace takes the key
// material, while the preservation that wrote it is still running and the audit
// record beside it is still being refused.
//
// The node is told once, after the grace rounds, that it is holding an output the
// namespace does not fully have, and quiescing on that notification is one-way.
// What follows it is not: a namespace can take the share several rounds later and
// go on refusing the record, and the preservation then keeps running for the rest
// of the process. A count taken from that notification, or from what preserve
// eventually returns, would report an empty quarantine for all of that time over
// a namespace holding key material — the all-clear a rollback decision must never
// be given.
func TestDkgExecutor_PreserveInterruptedSigner_CountsTheShareTheNamespaceTakesMidRetry(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	// The share lands well after the grace rounds are spent, so the node has
	// already been told the pair is incomplete by the time the namespace takes
	// it, and the preservation outlives the write by several more rounds.
	const membershipTakenAtRound = quarantineGraceAttempts + 3
	const roundsBeforeShutdown = membershipTakenAtRound + 3

	handle := &latchedMembershipHandle{
		membershipTakenAtRound: membershipTakenAtRound,
	}

	quarantine := newSignerQuarantine(context.Background(), logger, handle)

	// Sampled between rounds, which is inside the preservation: a count read
	// after preserve has returned cannot tell a gauge that rose at the write
	// from one that rose at the return, and the two are the whole question here.
	countAfterRound := make([]int, 0, roundsBeforeShutdown)
	round := 0
	quarantine.wait = func(context.Context, time.Duration) bool {
		round++
		countAfterRound = append(countAfterRound, int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)))
		return round < roundsBeforeShutdown
	}
	de.signerQuarantine = quarantine

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
		"rounds the preservation spent",
		roundsBeforeShutdown,
		len(countAfterRound),
	)

	for spentRound, count := range countAfterRound {
		// countAfterRound[i] is what the count said once round i+1 was over.
		expected := 0
		if spentRound+1 >= membershipTakenAtRound {
			expected = 1
		}

		testutils.AssertIntsEqual(
			t,
			fmt.Sprintf("reported quarantined signers after round %d",
				spentRound+1),
			expected,
			count,
		)
	}

	// The record explaining the share never landed, so this is the state the
	// count had to be right about rather than one preservation resolved.
	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/membership_1"},
	) {
		t.Errorf("namespace holds %v, expected only the key material", got)
	}

	if outcomes := permit.recordedTerminalOutcomes(); len(outcomes) != 0 {
		t.Errorf(
			"an output whose audit record never landed must not end the "+
				"permit, got %v",
			outcomes,
		)
	}
}

// TestDkgExecutor_PreserveInterruptedSigner_WritesTheAuditRecordAheadOfAnyScan
// proves the audit record is written without waiting on a namespace-wide read,
// and that no such read happens until both halves of the output are down.
//
// The share and the record explaining it are written in one round, the share
// first. Everything that runs between them delays the record, and a
// namespace-wide read is the slowest thing a node does to that namespace: the
// same directory trouble that makes an enumeration hang is what a preservation
// is racing in the first place. A share whose record was held up behind a scan
// is preserved material an offline audit cannot reconcile — the state this node
// quiesces over — reached because of the count rather than because the
// namespace refused the write.
func TestDkgExecutor_PreserveInterruptedSigner_WritesTheAuditRecordAheadOfAnyScan(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	handle := &heldScanHandle{release: make(chan struct{})}
	releaseScans := sync.OnceFunc(func() { close(handle.release) })
	defer releaseScans()

	de.signerQuarantine = newTestSignerQuarantine(handle, 1)

	preserved := make(chan struct{})
	go func() {
		defer close(preserved)
		de.preserveInterruptedSigner(
			logger.With(),
			newTestPermit(participation.TBTCDKG),
			big.NewInt(1),
			result,
			group.MemberIndex(1),
			gsr,
			"tbtc_dkg_signer_activation",
			fmt.Errorf("activation refused"),
		)
	}()

	// Both halves must land while every enumeration this namespace is asked for
	// is still held open. The bound decides how long the test waits for a write
	// that is not blocked, never whether an unblocked implementation passes.
	deadline := time.After(10 * time.Second)
	for {
		written := handle.written()
		if reflect.DeepEqual(
			written,
			[]string{"/membership_1", "/metadata_1"},
		) {
			break
		}

		select {
		case <-deadline:
			t.Fatalf(
				"the quarantine pair was not written while the namespace scan "+
					"was held open; namespace holds %v",
				written,
			)
		case <-time.After(5 * time.Millisecond):
		}
	}

	releaseScans()
	<-preserved

	// The recount still happens — it is what brings the count back to what the
	// namespace holds — but only once the output it is counting is complete.
	if writes := handle.writesBeforeScans(); len(writes) == 0 {
		t.Fatal("the namespace was never enumerated after the preservation")
	} else {
		for scan, written := range writes {
			testutils.AssertIntsEqual(
				t,
				fmt.Sprintf("records written when enumeration %d began", scan+1),
				2,
				written,
			)
		}
	}

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// heldScanHandle is a protected namespace whose enumerations are all held open
// until released, while its writes go through immediately — the shape of a
// namespace whose directory listing hangs. It records how many records had been
// written by the time each enumeration began, which is what says whether a
// write was waiting behind a scan or the other way round.
type heldScanHandle struct {
	mockPersistenceHandle

	release chan struct{}

	mu               sync.Mutex
	names            []string
	writesAtScanTime []int
}

func (h *heldScanHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.names = append(h.names, name)

	return h.mockPersistenceHandle.Save(data, directory, name)
}

func (h *heldScanHandle) written() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]string(nil), h.names...)
}

func (h *heldScanHandle) writesBeforeScans() []int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]int(nil), h.writesAtScanTime...)
}

func (h *heldScanHandle) ReadAll() (
	<-chan persistence.DataDescriptor,
	<-chan error,
) {
	h.mu.Lock()
	h.writesAtScanTime = append(h.writesAtScanTime, len(h.names))
	h.mu.Unlock()

	descriptors := make(chan persistence.DataDescriptor)
	errs := make(chan error)

	go func() {
		defer close(descriptors)
		defer close(errs)

		<-h.release

		h.mu.Lock()
		saved := append([]persistence.DataDescriptor(nil), h.saved...)
		h.mu.Unlock()

		for _, descriptor := range saved {
			descriptors <- descriptor
		}
	}()

	return descriptors, errs
}

// TestSignerQuarantine_Preserve_WritesOnlyTheHalfTheNamespaceLacks proves a
// round does not rewrite a half that already landed. The retry exists for the
// missing record, and rewriting the preserved one would keep touching key
// material the namespace has already accepted.
func TestSignerQuarantine_Preserve_WritesOnlyTheHalfTheNamespaceLacks(
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

	handle := &flakyRecordHandle{
		namePrefixes: []string{"/metadata_", "/handoff_"},
		refusals:     quarantineGraceAttempts + 2,
	}

	if _, err := newTestSignerQuarantine(handle, 50).preserve(
		signer,
		QuarantinedSignerMetadata{
			ReleaseEpoch: participation.CompiledEpoch.String(),
			Ceremony:     string(participation.TBTCDKG),
		},
		quarantineObserver{},
	); err != nil {
		t.Fatalf("expected the retried write to preserve the share, got [%v]", err)
	}

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/membership_1", "/metadata_1"},
	) {
		t.Errorf(
			"namespace holds %v, expected each half written exactly once",
			got,
		)
	}
}

// TestDkgExecutor_PreserveInterruptedSigner_LostShareBlocksNewCeremonies proves
// a share that reached no namespace stops this node from starting new work.
//
// The share existed only in the goroutine that generated it and the namespace
// refused it for the whole retry budget, so nothing an operator or the offline
// audit can read accounts for it. A node that keeps taking ceremonies after that
// builds further state on a host whose inventory is already known to be
// incomplete, and the rollback audit reconciles namespaces against the chain —
// it cannot reconcile a share nobody wrote down.
func TestDkgExecutor_PreserveInterruptedSigner_LostShareBlocksNewCeremonies(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	de.signerQuarantine = newTestSignerQuarantine(
		&unwritableRecordHandle{
			refusedNamePrefixes: []string{"/membership_", "/handoff_"},
		},
		1,
	)

	before := de.participationGate.State()
	testutils.AssertBoolsEqual(
		t,
		"the gate issues permits before the loss",
		true,
		before.Allowed,
	)

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	after := de.participationGate.State()
	testutils.AssertBoolsEqual(
		t,
		"the gate quiesced on the lost share",
		true,
		after.Quiescing,
	)
	testutils.AssertBoolsEqual(
		t,
		"the gate still issues permits",
		false,
		after.Allowed,
	)

	// A quiescing gate refuses before it looks at the anchor at all, which is
	// why the refusal has to be read by sentinel rather than by the fact that
	// one happened.
	if _, err := de.participationGate.Begin(
		participation.TBTCDKG,
		before.CurrentBlock,
		tbtcDKGPermitIdentity(big.NewInt(2), group.MemberIndex(1)),
	); !errors.Is(err, participation.ErrQuiescing) {
		t.Errorf(
			"a node holding a lost share must refuse new ceremonies, got [%v]",
			err,
		)
	}
}

// TestDkgExecutor_PreserveInterruptedSigner_RefusedActiveSaveFallsBackToQuarantine
// proves a registered wallet's share the active namespace refused is preserved
// in the quarantine namespace rather than dropped, and that the audit record
// says the active save is what was refused.
//
// The active namespace is where a restart would load the share from, so a write
// refused there leaves a registered wallet short a signer. The quarantine
// namespace is a separate namespace with its own failure modes: a share
// preserved there is recoverable and the offline audit reports it, where a
// dropped one is neither.
func TestDkgExecutor_PreserveInterruptedSigner_RefusedActiveSaveFallsBackToQuarantine(
	t *testing.T,
) {
	de, result, gsr, _, quarantineHandle := setupPreserveScenario(t)

	walletPublicKey := result.PrivateKeyShare.PublicKey()
	walletID, err := de.chain.CalculateWalletID(walletPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	de.chain.(*localChain).setWallet(
		bitcoin.PublicKeyHash(walletPublicKey),
		&WalletChainData{EcdsaWalletID: walletID, State: StateLive},
	)

	// The active namespace refuses the very record the registered wallet needs.
	activeHandle := &unwritableRecordHandle{refusedNamePrefixes: []string{"/membership_"}}
	de.walletRegistry, err = newWalletRegistry(
		activeHandle,
		de.chain.CalculateWalletID,
	)
	if err != nil {
		t.Fatal(err)
	}

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

	if got := savedNames(quarantineHandle); !reflect.DeepEqual(
		got,
		[]string{"/membership_1", "/metadata_1"},
	) {
		t.Errorf(
			"quarantine namespace holds %v, expected the refused share",
			got,
		)
	}

	metadata := &QuarantinedSignerMetadata{}
	for _, descriptor := range quarantineHandle.saved {
		if descriptor.Name() != "/metadata_1" {
			continue
		}
		content, err := descriptor.Content()
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(content, metadata); err != nil {
			t.Fatal(err)
		}
	}
	if want := "tbtc_dkg_signer_activation_after_refused_active_save"; metadata.
		FailedOperation != want {
		t.Errorf(
			"audit record says [%s], expected [%s]",
			metadata.FailedOperation,
			want,
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
}

// TestDkgExecutor_ReportQuarantinedSigners_PersistedShareSurvivesAnUnreadableRecount
// proves a share this process durably persisted is still counted when the
// recount that follows the write cannot read the namespace.
//
// Keeping the last published count is right when that count came from a scan
// that saw the namespace. It is wrong immediately after a write: the standing
// number is a cold start's zero, the namespace now holds key material, and
// leaving the zero up says a rollback has nothing to account for. What the scan
// failure cannot take away is what this process itself wrote.
func TestDkgExecutor_ReportQuarantinedSigners_PersistedShareSurvivesAnUnreadableRecount(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	// The cold start an operator reads first: an empty, readable namespace
	// counted and published as zero.
	if err := de.reportInitialQuarantinedSigners(); err != nil {
		t.Fatal(err)
	}
	if value, published := recorder.gaugePublished(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
	); !published || value != 0 {
		t.Fatalf(
			"expected a published zero to start from, got [%v] published=[%v]",
			value,
			published,
		)
	}

	// A namespace that takes the write and then cannot be listed.
	de.signerQuarantine = newTestSignerQuarantine(&unreadableHandle{}, 1)

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	testutils.AssertIntsEqual(
		t,
		"reported quarantined signers after the recount failed",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportInitialQuarantinedSigners_CountsAShareTheNamespaceTookLate
// proves the whole handoff survives a restart: a share the namespace refused for
// far longer than a passing fault, and then accepted, is counted by the next
// process that starts over the same namespace.
//
// The count is what a rollback decision reads, and it is taken by whichever
// process comes next rather than by the one that wrote. A preservation only the
// writing process knew about would leave the material invisible to exactly the
// decision it exists for — which is the same reason the retry is allowed to
// outlast any particular fault in the first place.
func TestDkgExecutor_ReportInitialQuarantinedSigners_CountsAShareTheNamespaceTookLate(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	handle := &flakyRecordHandle{
		namePrefixes: []string{"/membership_", "/handoff_"},
		refusals:     quarantineGraceAttempts * 5,
	}
	de.signerQuarantine = newTestSignerQuarantine(handle, 100)

	preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/metadata_1", "/membership_1"},
	) {
		t.Fatalf("namespace holds %v, expected both halves", got)
	}

	// The next process: a new executor over the namespace the last one left,
	// sharing none of its state — no floor, no standing count, no cache of
	// what was written.
	restarted, _, _, _, _ := setupPreserveScenario(t)
	recorder := newDispatchGaugeRecorder()
	restarted.metricsRecorder = recorder
	restarted.signerQuarantine = newTestSignerQuarantine(handle, 1)

	if err := restarted.reportInitialQuarantinedSigners(); err != nil {
		t.Fatal(err)
	}

	testutils.AssertIntsEqual(
		t,
		"preserved outputs the next process counts",
		1,
		int(recorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)
}

// TestDkgExecutor_ReportInitialQuarantinedSigners_RecoversAWholeOutputTheNamespaceWouldNotPair
// proves what a later process recovers when the namespace refuses the key
// material's own record for good: the combined handoff carries the share and
// everything that explains it, and the next process over the same namespace
// finds all of it.
//
// This is the state that used to cost a node a share. The membership record is
// where preservation prefers to put the material, the metadata beside it is only
// the explanation, and a namespace that took the second while refusing the first
// left a note about a share that reached no disk — the one half no ceremony can
// generate a second time. The handoff is one write carrying both, so the output
// survives under a name the namespace will take, and a process that starts over
// that namespace can read back the material, the seat and wallet it belongs to,
// and the mode, canonical anchor, ceremony, and refused operation the offline
// audit reconciles against the chain.
func TestDkgExecutor_ReportInitialQuarantinedSigners_RecoversAWholeOutputTheNamespaceWouldNotPair(
	t *testing.T,
) {
	de, result, gsr, _, _ := setupPreserveScenario(t)

	recorder := newDispatchGaugeRecorder()
	de.metricsRecorder = recorder

	// A namespace that will not take the key material's own record at all, and
	// takes the combined one only well after the grace rounds are spent — so the
	// node has already been told it is holding a share nothing has, and the
	// process is on its way out when the namespace finally comes back.
	const handoffTakenAtRound = quarantineGraceAttempts * 2
	handle := &latchedHandoffHandle{handoffTakenAtRound: handoffTakenAtRound}
	de.signerQuarantine = newTestSignerQuarantine(
		handle,
		handoffTakenAtRound+1,
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

	if got := savedNames(&handle.mockPersistenceHandle); !reflect.DeepEqual(
		got,
		[]string{"/metadata_1", "/handoff_1"},
	) {
		t.Fatalf(
			"namespace holds %v, expected the output preserved whole",
			got,
		)
	}

	// The namespace holds the material and its explanation, so this permit is
	// resolved rather than left for the offline barrier to block on.
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

	// The next process: a new executor over the namespace the last one left,
	// sharing none of its state — no floor, no standing count, no memory of what
	// was written.
	restarted, _, _, _, _ := setupPreserveScenario(t)
	restartedRecorder := newDispatchGaugeRecorder()
	restarted.metricsRecorder = restartedRecorder
	restarted.signerQuarantine = newSignerQuarantine(
		context.Background(),
		logger,
		handle,
	)

	if err := restarted.reportInitialQuarantinedSigners(); err != nil {
		t.Fatal(err)
	}

	testutils.AssertIntsEqual(
		t,
		"preserved outputs the next process counts",
		1,
		int(restartedRecorder.gauge(
			clientinfo.MetricParticipationQuarantinedTBTCSigners,
		)),
	)

	// Counting the record is not the same as being able to use it. The material
	// is recovery evidence, so the next process has to be able to read back both
	// what was preserved and what explains it.
	preserved := handle.savedRecord(t, "/handoff_1")
	content, err := preserved.Content()
	if err != nil {
		t.Fatal(err)
	}

	handoff, err := DecodeQuarantinedSignerHandoff(content)
	if err != nil {
		t.Fatalf("the preserved output cannot be read back: [%v]", err)
	}

	record, err := DecodeSignerAuditRecord(handoff.Signer)
	if err != nil {
		t.Fatalf("the preserved key material cannot be read back: [%v]", err)
	}

	testutils.AssertIntsEqual(
		t,
		"seat the preserved material was generated for",
		1,
		int(record.MemberIndex),
	)
	if expected := getWalletStorageKey(
		result.PrivateKeyShare.PublicKey(),
	); record.WalletStorageKey != expected {
		t.Errorf(
			"preserved material belongs to wallet [%s], expected [%s]",
			record.WalletStorageKey,
			expected,
		)
	}

	// The fields the offline audit matches against the chain travel with the
	// material, so a share recovered this way is reconcilable rather than just
	// countable.
	metadata := handoff.Metadata
	testutils.AssertStringsEqual(
		t,
		"protocol mode the preserved output was generated under",
		permit.Mode().String(),
		metadata.ProtocolMode,
	)
	testutils.AssertUintsEqual(
		t,
		"canonical anchor the preserved output was generated under",
		permit.CanonicalStartBlock(),
		metadata.CanonicalStartBlock,
	)
	testutils.AssertStringsEqual(
		t,
		"ceremony the preserved output was generated in",
		string(participation.TBTCDKG),
		metadata.Ceremony,
	)
	testutils.AssertStringsEqual(
		t,
		"operation that was refused",
		"tbtc_dkg_signer_activation",
		metadata.FailedOperation,
	)
	testutils.AssertStringsEqual(
		t,
		"release epoch that preserved the output",
		participation.CompiledEpoch.String(),
		metadata.ReleaseEpoch,
	)
}

// latchedHandoffHandle refuses the record carrying key material for good and
// takes the combined handoff only from the given round, as a namespace does when
// one particular file cannot be written and the rest of the directory is
// part-way through an operator's repair.
type latchedHandoffHandle struct {
	mockPersistenceHandle

	// handoffTakenAtRound is the round from which the combined record is
	// accepted. The membership is attempted once per round for as long as it has
	// not landed, and it never lands here, so its attempt count is the round
	// number.
	handoffTakenAtRound int

	mu                 sync.Mutex
	membershipAttempts int
}

func (h *latchedHandoffHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if strings.HasPrefix(name, "/membership_") {
		h.membershipAttempts++
		return fmt.Errorf("cannot write [%s]", name)
	}

	if strings.HasPrefix(name, "/handoff_") &&
		h.membershipAttempts < h.handoffTakenAtRound {
		return fmt.Errorf("cannot write [%s] yet", name)
	}

	return h.mockPersistenceHandle.Save(data, directory, name)
}

// savedRecord returns the record the namespace holds under the given name.
func (h *latchedHandoffHandle) savedRecord(
	t *testing.T,
	name string,
) persistence.DataDescriptor {
	t.Helper()

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, descriptor := range h.saved {
		if descriptor.Name() == name {
			return descriptor
		}
	}

	t.Fatalf("the namespace holds no record named [%s]", name)
	return nil
}

// TestSignerQuarantine_PreservedOutputs_RestartSeesWhatEachWriteFailureLeft
// proves what a later process finds in the namespace after a refused write.
// Whichever record of the pair the namespace would not take, the handoff
// carries the output whole, so the restart still finds one preserved share to
// account for. Only a namespace that refuses every record leaves nothing.
//
// The count is read by whichever process comes next, not by the one that wrote,
// so it is taken here by a store that shares nothing with the one that failed.
func TestSignerQuarantine_PreservedOutputs_RestartSeesWhatEachWriteFailureLeft(
	t *testing.T,
) {
	tests := map[string]struct {
		refusedNamePrefix string
		expectedOutputs   int
		expectedRecords   []string
	}{
		"the metadata write is refused": {
			refusedNamePrefix: "/metadata_",
			expectedOutputs:   1,
			expectedRecords:   []string{"/membership_1", "/handoff_1"},
		},
		"the membership write is refused": {
			refusedNamePrefix: "/membership_",
			expectedOutputs:   1,
			expectedRecords:   []string{"/metadata_1", "/handoff_1"},
		},
		"every write is refused": {
			refusedNamePrefix: "/",
			expectedOutputs:   0,
			expectedRecords:   []string{},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			de, result, gsr, _, _ := setupPreserveScenario(t)

			handle := &unwritableRecordHandle{
				refusedNamePrefixes: []string{test.refusedNamePrefix},
			}
			de.signerQuarantine = newTestSignerQuarantine(handle, 1)

			preserveOneSigner(t, de, result, gsr, group.MemberIndex(1))

			outputs, err := newTestSignerQuarantine(handle, 1).preservedOutputs()
			if err != nil {
				t.Fatal(err)
			}
			testutils.AssertIntsEqual(
				t,
				"preserved outputs a restart finds",
				test.expectedOutputs,
				len(outputs),
			)

			if got := savedNames(
				&handle.mockPersistenceHandle,
			); !reflect.DeepEqual(got, test.expectedRecords) {
				t.Errorf(
					"namespace holds %v, expected %v",
					got,
					test.expectedRecords,
				)
			}
		})
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
