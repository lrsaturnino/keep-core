package participation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/protocol/group"
)

type quiescencePersistenceRecorder struct {
	deleted   []string
	deleteErr error
	saved     map[string][]byte
}

func (p *quiescencePersistenceRecorder) Save(
	data []byte,
	directory string,
	name string,
) error {
	if p.saved == nil {
		p.saved = make(map[string][]byte)
	}
	p.saved[directory+"/"+name] = append([]byte(nil), data...)
	return nil
}

func (p *quiescencePersistenceRecorder) Delete(
	directory string,
	name string,
) error {
	p.deleted = append(p.deleted, directory+"/"+name)
	return p.deleteErr
}

func TestNewPersistenceQuiescenceSnapshotRecorder_InvalidatesPriorRun(
	t *testing.T,
) {
	persistence := &quiescencePersistenceRecorder{}

	if _, err := NewPersistenceQuiescenceSnapshotRecorder(
		persistence,
	); err != nil {
		t.Fatal(err)
	}

	expected := map[string]bool{
		QuiescenceSnapshotStorageDirectory + "/" +
			QuiescenceSnapshotStorageFile: false,
		QuiescenceSnapshotStorageDirectory + "/" +
			TerminalOutcomeJournalStorageFile: false,
	}
	for _, deleted := range persistence.deleted {
		if _, ok := expected[deleted]; ok {
			expected[deleted] = true
		}
	}
	for record, found := range expected {
		if found {
			continue
		}
		t.Errorf(
			"expected prior record [%s] to be invalidated; deletes: %v",
			record,
			persistence.deleted,
		)
	}
}

func TestNewPersistenceQuiescenceSnapshotRecorder_MissingPriorRunIsAllowed(
	t *testing.T,
) {
	persistence := &quiescencePersistenceRecorder{
		deleteErr: fs.ErrNotExist,
	}

	if _, err := NewPersistenceQuiescenceSnapshotRecorder(
		persistence,
	); err != nil {
		t.Fatal(err)
	}
}

func TestNewPersistenceQuiescenceSnapshotRecorder_DeleteFailureIsFatal(
	t *testing.T,
) {
	deleteErr := errors.New("delete failed")
	persistence := &quiescencePersistenceRecorder{
		deleteErr: deleteErr,
	}

	if _, err := NewPersistenceQuiescenceSnapshotRecorder(
		persistence,
	); !errors.Is(err, deleteErr) {
		t.Fatalf("expected delete failure, got [%v]", err)
	}
}

func TestPersistenceQuiescenceSnapshotRecorder_PersistsTerminalJournal(
	t *testing.T,
) {
	persistence := &quiescencePersistenceRecorder{}
	recorder, err := NewPersistenceQuiescenceSnapshotRecorder(persistence)
	if err != nil {
		t.Fatal(err)
	}

	capturedAt := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	if err := recorder.Record(QuiescenceSnapshot{
		SchemaVersion: QuiescenceSnapshotSchemaVersion,
		CapturedAt:    capturedAt,
	}); err != nil {
		t.Fatal(err)
	}

	outcome := TerminalOutcomeRecord{
		RecordedAt: capturedAt.Add(time.Second),
		Permit: PermitSnapshot{
			Ceremony:            TBTCSigning,
			Mode:                ModeSecurityV2.String(),
			CanonicalStartBlock: 1_000,
			WorkID:              "wallet-action",
			PermitID:            "wallet",
			IdentityBound:       true,
		},
		Outcome: TerminalOutcomeCompleted,
		Evidence: TerminalEvidence{
			Kind:      TerminalEvidenceProtocolResult,
			Reference: "result-digest",
		},
	}
	if err := recorder.RecordTerminalOutcome(outcome); err != nil {
		t.Fatal(err)
	}

	content := persistence.saved[QuiescenceSnapshotStorageDirectory+
		"/"+TerminalOutcomeJournalStorageFile]
	journal := &TerminalOutcomeJournal{}
	if err := json.Unmarshal(content, journal); err != nil {
		t.Fatal(err)
	}
	if journal.SchemaVersion != TerminalOutcomeJournalSchemaVersion {
		t.Errorf(
			"unexpected journal schema [%d]",
			journal.SchemaVersion,
		)
	}
	if !journal.SnapshotCapturedAt.Equal(capturedAt) {
		t.Errorf(
			"unexpected snapshot binding [%s]",
			journal.SnapshotCapturedAt,
		)
	}
	if len(journal.Outcomes) != 1 ||
		!journal.Outcomes[0].Equal(outcome) {
		t.Errorf("unexpected terminal outcomes: %+v", journal.Outcomes)
	}
}

func TestValidateTerminalOutcome_RejectsUnsupportedEvidence(t *testing.T) {
	err := ValidateTerminalOutcome(
		TBTCSigning,
		TerminalOutcomeCompleted,
		TerminalEvidence{
			Kind:      TerminalEvidenceKind("fabricated_result"),
			Reference: "fabricated-result",
		},
	)
	if err == nil {
		t.Fatal("expected unsupported terminal evidence to be rejected")
	}
}

func TestValidateTerminalOutcome_DKGCompletionRequiresExactMembership(
	t *testing.T,
) {
	tests := map[string]struct {
		ceremony Ceremony
		kind     TerminalEvidenceKind
	}{
		"tbtc": {
			ceremony: TBTCDKG,
			kind:     TerminalEvidencePersistedTBTCSinger,
		},
		"beacon": {
			ceremony: BeaconDKG,
			kind:     TerminalEvidencePersistedBeaconSigner,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			evidence := TerminalEvidence{
				Kind:      test.kind,
				Reference: "persisted-signer",
			}
			if err := ValidateTerminalOutcome(
				test.ceremony,
				TerminalOutcomeCompleted,
				evidence,
			); err == nil {
				t.Fatal(
					"expected DKG completion without a membership index " +
						"to be rejected",
				)
			}

			evidence.MembershipIndex = group.MemberIndex(7)
			if err := ValidateTerminalOutcome(
				test.ceremony,
				TerminalOutcomeCompleted,
				evidence,
			); err != nil {
				t.Fatalf(
					"expected exact persisted membership evidence to pass: [%v]",
					err,
				)
			}
		})
	}
}

func TestValidateTerminalOutcome_RejectsUnauthenticatedDKGExhaustion(
	t *testing.T,
) {
	for _, ceremony := range []Ceremony{TBTCDKG, BeaconDKG} {
		err := ValidateTerminalOutcome(
			ceremony,
			TerminalOutcomeExhausted,
			TerminalEvidence{Kind: TerminalEvidenceNoThreshold},
		)
		if err == nil {
			t.Errorf(
				"expected local no-threshold marker for [%s] to be rejected",
				ceremony,
			)
		}
	}
}

// TestTerminalResultReference_ComponentBoundariesAreBinding asserts the
// reference builder cannot be made to collide by shifting the boundary between
// two components. Concatenating adjacent components must not reproduce another
// call's digest, otherwise two different ceremony results could claim the same
// journal identity.
func TestTerminalResultReference_ComponentBoundariesAreBinding(t *testing.T) {
	shifted := map[string][][]byte{
		"split one way":     {[]byte("ab"), []byte("c")},
		"split another way": {[]byte("a"), []byte("bc")},
		"joined":            {[]byte("abc")},
	}

	seen := make(map[string]string)
	for name, components := range shifted {
		reference := TerminalResultReference("domain", components...)

		if previous, taken := seen[reference]; taken {
			t.Errorf(
				"[%s] collides with [%s] on reference [%s]",
				name,
				previous,
				reference,
			)
		}
		seen[reference] = name
	}
}

// TestTerminalResultReference_DomainSeparates asserts two ceremonies cannot
// derive the same reference from identical components.
func TestTerminalResultReference_DomainSeparates(t *testing.T) {
	components := [][]byte{{0x01, 0x02}}

	if TerminalResultReference("first_domain", components...) ==
		TerminalResultReference("second_domain", components...) {
		t.Error("distinct domains produced the same reference")
	}
}

// testCompletedResultReference renders a protocol-result reference the given
// ceremony accepts. Every ceremony but the beacon relay names a digest of its
// own result; a relay entry names the group, the previous entry and the entry
// itself so the offline audit can verify the signature, so no placeholder can
// stand in for one.
func testCompletedResultReference(
	t *testing.T,
	ceremony Ceremony,
	digest string,
) string {
	t.Helper()

	if ceremony != BeaconRelaySigning {
		return digest
	}

	reference, err := BeaconRelayEntryReference(
		bytes.Repeat([]byte{0x01}, beaconRelayEntryComponentLength),
		bytes.Repeat([]byte{0x02}, beaconRelayEntryComponentLength),
		bytes.Repeat([]byte{0x03}, beaconRelayEntryComponentLength),
	)
	if err != nil {
		t.Fatal(err)
	}

	return reference
}

// TestTerminalResultReference_IsAcceptedAsEvidence asserts a derived reference
// passes the journal's own identity rules, so a ceremony that authors one can
// actually record it.
func TestTerminalResultReference_IsAcceptedAsEvidence(t *testing.T) {
	for _, ceremony := range []Ceremony{
		TBTCHeartbeat,
		TBTCWalletCoordination,
		BeaconRelaySigning,
		BeaconTimeoutReport,
	} {
		if err := ValidateTerminalOutcome(
			ceremony,
			TerminalOutcomeCompleted,
			TerminalEvidence{
				Kind: TerminalEvidenceProtocolResult,
				Reference: testCompletedResultReference(
					t,
					ceremony,
					TerminalResultReference("domain", []byte("result")),
				),
			},
		); err != nil {
			t.Errorf(
				"derived reference rejected for ceremony [%s]: [%v]",
				ceremony,
				err,
			)
		}
	}
}

// TestBeaconRelayEntryReference_RoundTrips asserts the relay entry identity
// survives rendering and parsing unchanged, and that only its exact canonical
// rendering is accepted. An alias that names the same entry while failing every
// comparison the audit makes against it is indistinguishable from naming no
// entry at all.
func TestBeaconRelayEntryReference_RoundTrips(t *testing.T) {
	groupPublicKey := bytes.Repeat([]byte{0xa1}, beaconRelayEntryComponentLength)
	previousEntry := bytes.Repeat([]byte{0xb2}, beaconRelayEntryComponentLength)
	entry := bytes.Repeat([]byte{0xc3}, beaconRelayEntryComponentLength)

	reference, err := BeaconRelayEntryReference(
		groupPublicKey,
		previousEntry,
		entry,
	)
	if err != nil {
		t.Fatal(err)
	}

	parsedGroup, parsedPrevious, parsedEntry, err :=
		ParseBeaconRelayEntryReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []struct {
		name     string
		expected []byte
		actual   []byte
	}{
		{name: "group public key", expected: groupPublicKey, actual: parsedGroup},
		{name: "previous entry", expected: previousEntry, actual: parsedPrevious},
		{name: "entry", expected: entry, actual: parsedEntry},
	} {
		if !bytes.Equal(component.expected, component.actual) {
			t.Errorf(
				"%s did not round-trip\nexpected: [%x]\nactual:   [%x]",
				component.name,
				component.expected,
				component.actual,
			)
		}
	}

	short := bytes.Repeat([]byte{0x01}, beaconRelayEntryComponentLength-1)
	for _, test := range []struct {
		name           string
		groupPublicKey []byte
		previousEntry  []byte
		entry          []byte
	}{
		{name: "short group public key", groupPublicKey: short, previousEntry: previousEntry, entry: entry},
		{name: "short previous entry", groupPublicKey: groupPublicKey, previousEntry: short, entry: entry},
		{name: "short entry", groupPublicKey: groupPublicKey, previousEntry: previousEntry, entry: short},
	} {
		if _, err := BeaconRelayEntryReference(
			test.groupPublicKey,
			test.previousEntry,
			test.entry,
		); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
		}
	}

	for _, test := range []struct {
		name      string
		reference string
	}{
		{name: "no components", reference: ""},
		{name: "two components", reference: hex.EncodeToString(groupPublicKey) +
			":" + hex.EncodeToString(entry)},
		{name: "four components", reference: reference + ":" +
			hex.EncodeToString(entry)},
		{name: "uppercase alias", reference: strings.ToUpper(reference)},
		{name: "prefixed alias", reference: "0x" + reference},
	} {
		if _, _, _, err := ParseBeaconRelayEntryReference(
			test.reference,
		); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
		}
	}
}

// TestValidateTerminalOutcome_CompletedEvidenceKindIsPinnedPerCeremony asserts
// no ceremony can settle a completed permit with an evidence class other than
// the one its result actually lives in. The consequential direction is a
// ceremony whose result is external state — a Bitcoin spend, an Ethereum
// penalty submission — settling on a node-authored protocol digest instead,
// which would leave the offline audit nothing canonical to reconcile against.
func TestValidateTerminalOutcome_CompletedEvidenceKindIsPinnedPerCeremony(
	t *testing.T,
) {
	everyKind := []TerminalEvidenceKind{
		TerminalEvidencePersistedTBTCSinger,
		TerminalEvidencePersistedBeaconSigner,
		TerminalEvidenceBitcoinTransaction,
		TerminalEvidenceEthereumTransaction,
		TerminalEvidenceProtocolResult,
		TerminalEvidenceForwarderClosed,
	}

	for _, ceremony := range AllCeremonies() {
		expected, declared := completedEvidenceKinds[ceremony]
		if !declared {
			t.Errorf(
				"ceremony [%s] has no declared completed evidence kind; a "+
					"completed permit for it can never be recorded",
				ceremony,
			)
			continue
		}

		for _, kind := range everyKind {
			evidence := TerminalEvidence{Kind: kind}
			switch kind {
			case TerminalEvidencePersistedTBTCSinger,
				TerminalEvidencePersistedBeaconSigner:
				evidence.MembershipIndex = 1
				evidence.Reference = "persisted-signer-identity"
			case TerminalEvidenceForwarderClosed:
			default:
				evidence.Reference = testCompletedResultReference(
					t,
					ceremony,
					"durable-result-identity",
				)
			}

			err := ValidateTerminalOutcome(
				ceremony,
				TerminalOutcomeCompleted,
				evidence,
			)
			if kind == expected && err != nil {
				t.Errorf(
					"ceremony [%s] rejected its own evidence kind [%s]: [%v]",
					ceremony,
					kind,
					err,
				)
			}
			if kind != expected && err == nil {
				t.Errorf(
					"ceremony [%s] accepted foreign evidence kind [%s]; only "+
						"[%s] identifies its durable result",
					ceremony,
					kind,
					expected,
				)
			}
		}
	}
}

// TestInactivityClaimSettlementReference_RoundTrips asserts the canonical claim
// identity survives a round trip and that only the exact rendering is accepted.
// The audit joins this string to a chain log by comparison, so an alias that
// names the same claim in a different shape is indistinguishable from naming no
// claim at all.
func TestInactivityClaimSettlementReference_RoundTrips(t *testing.T) {
	walletID := make([]byte, inactivityClaimWalletIDLength)
	for i := range walletID {
		walletID[i] = byte(i + 1)
	}

	for _, nonce := range []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Lsh(big.NewInt(1), 200),
	} {
		reference, err := InactivityClaimSettlementReference(walletID, nonce)
		if err != nil {
			t.Fatalf("nonce [%s]: [%v]", nonce, err)
		}

		decodedWalletID, decodedNonce, err := ParseInactivityClaimSettlementReference(
			reference,
		)
		if err != nil {
			t.Fatalf("reference [%s]: [%v]", reference, err)
		}
		if !bytes.Equal(decodedWalletID, walletID) {
			t.Errorf(
				"reference [%s] round-tripped wallet [%x], expected [%x]",
				reference,
				decodedWalletID,
				walletID,
			)
		}
		if decodedNonce.Cmp(nonce) != 0 {
			t.Errorf(
				"reference [%s] round-tripped nonce [%s], expected [%s]",
				reference,
				decodedNonce,
				nonce,
			)
		}
	}
}

func TestInactivityClaimSettlementReference_RejectsNonCanonicalIdentities(
	t *testing.T,
) {
	walletID := make([]byte, inactivityClaimWalletIDLength)
	walletID[inactivityClaimWalletIDLength-1] = 0xab

	canonical, err := InactivityClaimSettlementReference(
		walletID,
		big.NewInt(12),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseInactivityClaimSettlementReference(
		canonical,
	); err != nil {
		t.Fatalf("the canonical rendering [%s] is rejected: [%v]", canonical, err)
	}

	shortWalletID := walletID[:inactivityClaimWalletIDLength-1]
	if _, err := InactivityClaimSettlementReference(
		shortWalletID,
		big.NewInt(12),
	); err == nil {
		t.Error("a short wallet identifier produced a claim identity")
	}
	if _, err := InactivityClaimSettlementReference(walletID, nil); err == nil {
		t.Error("a missing nonce produced a claim identity")
	}
	if _, err := InactivityClaimSettlementReference(
		walletID,
		big.NewInt(-1),
	); err == nil {
		t.Error("a negative nonce produced a claim identity")
	}

	for name, reference := range map[string]string{
		"no separator":        hex.EncodeToString(walletID) + "12",
		"uppercase wallet":    strings.ToUpper(hex.EncodeToString(walletID)) + ":12",
		"prefixed wallet":     "0x" + hex.EncodeToString(walletID) + ":12",
		"truncated wallet":    hex.EncodeToString(shortWalletID) + ":12",
		"zero-padded nonce":   hex.EncodeToString(walletID) + ":012",
		"hexadecimal nonce":   hex.EncodeToString(walletID) + ":0xc",
		"signed nonce":        hex.EncodeToString(walletID) + ":+12",
		"negative nonce":      hex.EncodeToString(walletID) + ":-12",
		"empty nonce":         hex.EncodeToString(walletID) + ":",
		"trailing separator":  canonical + ":",
		"non-numeric nonce":   hex.EncodeToString(walletID) + ":twelve",
		"non-hexadecimal key": strings.Repeat("z", 64) + ":12",
	} {
		if _, _, err := ParseInactivityClaimSettlementReference(
			reference,
		); err == nil {
			t.Errorf(
				"%s: alias [%s] was accepted as a canonical claim identity",
				name,
				reference,
			)
		}
	}
}

// TestValidateTerminalOutcome_ChainSettlementIsPinnedPerCeremony asserts only a
// ceremony with a code path that submits to a chain may report a settlement,
// and only of the kind it actually dispatches. Without the restriction any
// ceremony could attach a penalty submission it could not have made.
func TestValidateTerminalOutcome_ChainSettlementIsPinnedPerCeremony(
	t *testing.T,
) {
	walletID := make([]byte, inactivityClaimWalletIDLength)
	walletID[0] = 0x7f
	reference, err := InactivityClaimSettlementReference(
		walletID,
		big.NewInt(3),
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, ceremony := range AllCeremonies() {
		expectedKind, known := completedEvidenceKinds[ceremony]
		if !known {
			continue
		}

		evidence := TerminalEvidence{Kind: expectedKind}
		switch expectedKind {
		case TerminalEvidencePersistedTBTCSinger,
			TerminalEvidencePersistedBeaconSigner:
			evidence.MembershipIndex = 1
			evidence.Reference = "persisted-signer-identity"
		case TerminalEvidenceForwarderClosed:
		default:
			evidence.Reference = "durable-result-identity"
		}

		dispatches, permitted := chainSettlementKinds[ceremony]

		settled := evidence
		settled.ChainSettlement = &ChainSettlementRecord{
			Kind:      ChainSettlementInactivityClaim,
			Reference: reference,
		}
		err := ValidateTerminalOutcome(
			ceremony,
			TerminalOutcomeCompleted,
			settled,
		)
		if permitted && dispatches == ChainSettlementInactivityClaim {
			if err != nil {
				t.Errorf(
					"ceremony [%s] rejected the settlement it dispatches: [%v]",
					ceremony,
					err,
				)
			}
		} else if err == nil {
			t.Errorf(
				"ceremony [%s] accepted an inactivity claim settlement it has "+
					"no code path to file",
				ceremony,
			)
		}

		unknownKind := evidence
		unknownKind.ChainSettlement = &ChainSettlementRecord{
			Kind: "some_other_submission",
		}
		if err := ValidateTerminalOutcome(
			ceremony,
			TerminalOutcomeCompleted,
			unknownKind,
		); err == nil {
			t.Errorf(
				"ceremony [%s] accepted an undeclared chain settlement kind",
				ceremony,
			)
		}
	}
}

func TestValidateTerminalOutcome_ChainSettlementShapes(t *testing.T) {
	walletID := make([]byte, inactivityClaimWalletIDLength)
	walletID[0] = 0x11
	reference, err := InactivityClaimSettlementReference(
		walletID,
		big.NewInt(9),
	)
	if err != nil {
		t.Fatal(err)
	}

	heartbeatEvidence := func(
		settlement *ChainSettlementRecord,
	) TerminalEvidence {
		return TerminalEvidence{
			Kind:            TerminalEvidenceProtocolResult,
			Reference:       "heartbeat-result-identity",
			ChainSettlement: settlement,
		}
	}

	// A dispatch with no observed settlement is the deliberate unreconciled
	// record; rejecting it would force the node to either fabricate a claim
	// identity or hide the dispatch entirely.
	if err := ValidateTerminalOutcome(
		TBTCHeartbeat,
		TerminalOutcomeCompleted,
		heartbeatEvidence(&ChainSettlementRecord{
			Kind: ChainSettlementInactivityClaim,
		}),
	); err != nil {
		t.Errorf("an unobserved dispatch was rejected: [%v]", err)
	}

	if err := ValidateTerminalOutcome(
		TBTCHeartbeat,
		TerminalOutcomeCompleted,
		heartbeatEvidence(&ChainSettlementRecord{
			Kind:      ChainSettlementInactivityClaim,
			Reference: "not-a-claim-identity",
		}),
	); err == nil {
		t.Error("a settlement naming no canonical claim was accepted")
	}

	// The dispatch runs downstream of the heartbeat's own threshold signature,
	// so an outcome reporting no result cannot have reached one.
	if err := ValidateTerminalOutcome(
		TBTCHeartbeat,
		TerminalOutcomeExhausted,
		TerminalEvidence{
			Kind: TerminalEvidenceNoThreshold,
			ChainSettlement: &ChainSettlementRecord{
				Kind:      ChainSettlementInactivityClaim,
				Reference: reference,
			},
		},
	); err == nil {
		t.Error("an exhausted heartbeat reported a filed penalty")
	}
}
