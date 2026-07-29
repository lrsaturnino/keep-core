package participation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"math/big"
	"slices"
	"strconv"
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
			Kind:         TerminalEvidenceProtocolResult,
			Reference:    "result-digest",
			Contribution: testTranscriptContribution(TBTCSigning, 1),
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
		testWorkID(TBTCSigning),
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
				Kind:         test.kind,
				Reference:    "persisted-signer",
				Contribution: testTranscriptContribution(test.ceremony, 7),
			}
			if err := ValidateTerminalOutcome(
				test.ceremony,
				testWorkID(test.ceremony),
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
				testWorkID(test.ceremony),
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
			testWorkID(ceremony),
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

// testRelayRequestStartBlock is the relay request every relay-flavored fixture
// in this file answers. Relay evidence is only valid against the permit issued
// for its own request, so the reference and the work identity have to agree on
// one block.
const testRelayRequestStartBlock = uint64(4_100_900)

// testWorkID renders a work identity the given ceremony's permits would carry.
// Only the beacon relay ceremonies constrain it: their evidence names the
// request it answers, and the validator holds that to the request the permit
// was issued for.
func testWorkID(ceremony Ceremony) string {
	if isBeaconRelayCeremony(ceremony) {
		return BeaconRelayWorkID(testRelayRequestStartBlock)
	}
	return "work-identity"
}

// testTranscriptContribution renders the transcript a completed outcome of the
// given ceremony must carry, and nil for the ceremonies that author none. The
// local membership is passed in rather than fixed so a fixture that also names
// a persisted membership index agrees with its own transcript, leaving the
// disagreement to the tests that mean to provoke it.
func testTranscriptContribution(
	ceremony Ceremony,
	local group.MemberIndex,
) *TranscriptContribution {
	if _, authored := transcriptContributionCeremonies[ceremony]; !authored {
		return nil
	}

	incorporated := []group.MemberIndex{local}
	for _, peer := range []group.MemberIndex{1, 2, 3} {
		if peer != local {
			incorporated = append(incorporated, peer)
		}
	}
	slices.Sort(incorporated)

	return &TranscriptContribution{
		IncorporatedMembers: incorporated,
		LocalMembers:        []group.MemberIndex{local},
	}
}

// isBeaconRelayCeremony reports whether a ceremony's permits are issued for an
// on-chain relay request.
func isBeaconRelayCeremony(ceremony Ceremony) bool {
	return ceremony == BeaconRelaySigning ||
		ceremony == BeaconTimeoutReport ||
		ceremony == BeaconRelayForwarding
}

// testCompletedResultReference renders a completed-outcome reference the given
// ceremony accepts. Most ceremonies name a digest of their own result; the
// relay ceremonies name the request they answer, so no placeholder can stand
// in for one. A relay entry additionally names the group, the previous entry
// and the entry itself so the offline audit can verify the signature, and a
// timeout report names the beacon's own request identifier and terminated
// group so the audit can join it to an authenticated log.
func testCompletedResultReference(
	t *testing.T,
	ceremony Ceremony,
	digest string,
) string {
	t.Helper()

	if ceremony == BeaconTimeoutReport {
		reference, err := BeaconRelayTimeoutSettlementReference(
			testRelayRequestStartBlock,
			big.NewInt(7),
			3,
		)
		if err != nil {
			t.Fatal(err)
		}
		return reference
	}
	if ceremony != BeaconRelaySigning {
		return digest
	}

	reference, err := BeaconRelayEntryReference(
		testRelayRequestStartBlock,
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
//
// The list is exactly the ceremonies whose durable result is a protocol result.
// A timeout report is deliberately absent: its result is the beacon's own
// settlement record, so it has no derived reference to accept.
func TestTerminalResultReference_IsAcceptedAsEvidence(t *testing.T) {
	for _, ceremony := range []Ceremony{
		TBTCHeartbeat,
		TBTCWalletCoordination,
		BeaconRelaySigning,
	} {
		if err := ValidateTerminalOutcome(
			ceremony,
			testWorkID(ceremony),
			TerminalOutcomeCompleted,
			TerminalEvidence{
				Kind: TerminalEvidenceProtocolResult,
				Reference: testCompletedResultReference(
					t,
					ceremony,
					TerminalResultReference("domain", []byte("result")),
				),
				Contribution: testTranscriptContribution(ceremony, 1),
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

// TestBeaconRelayTimeoutSettlementReference_RoundTrips asserts the beacon
// settlement identity survives rendering and parsing unchanged, and that only
// its exact canonical rendering is accepted. An alias that names the same
// settlement while failing every comparison the audit makes against it is
// indistinguishable from naming no settlement at all.
func TestBeaconRelayTimeoutSettlementReference_RoundTrips(t *testing.T) {
	requestID := big.NewInt(4_294_967_297)
	const terminatedGroupID = uint64(9)

	reference, err := BeaconRelayTimeoutSettlementReference(
		testRelayRequestStartBlock,
		requestID,
		terminatedGroupID,
	)
	if err != nil {
		t.Fatal(err)
	}

	parsedStartBlock, parsedRequestID, parsedGroupID, err :=
		ParseBeaconRelayTimeoutSettlementReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStartBlock != testRelayRequestStartBlock {
		t.Errorf(
			"request start block did not round-trip\n"+
				"expected: [%d]\nactual:   [%d]",
			testRelayRequestStartBlock,
			parsedStartBlock,
		)
	}
	if parsedRequestID.Cmp(requestID) != 0 {
		t.Errorf(
			"request identifier did not round-trip\n"+
				"expected: [%s]\nactual:   [%s]",
			requestID,
			parsedRequestID,
		)
	}
	if parsedGroupID != terminatedGroupID {
		t.Errorf(
			"terminated group did not round-trip\n"+
				"expected: [%d]\nactual:   [%d]",
			terminatedGroupID,
			parsedGroupID,
		)
	}

	// A settlement with no request identifier names no log, so it cannot be
	// rendered at all rather than being rendered as an absent component.
	for _, test := range []struct {
		name      string
		requestID *big.Int
	}{
		{name: "missing request identifier", requestID: nil},
		{name: "negative request identifier", requestID: big.NewInt(-1)},
	} {
		if _, err := BeaconRelayTimeoutSettlementReference(
			testRelayRequestStartBlock,
			test.requestID,
			terminatedGroupID,
		); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
		}
	}

	for _, test := range []struct {
		name      string
		reference string
	}{
		{name: "no components", reference: ""},
		{name: "two components", reference: "1000:11"},
		{name: "four components", reference: reference + ":1"},
		{name: "prefixed alias", reference: "0x" + reference},
		// Any component rendered other than canonically names the same
		// settlement while comparing unequal to the reference the audit
		// rebuilds, which reads as naming none.
		{name: "zero-padded start block", reference: "0" + reference},
		{name: "signed start block", reference: "+" + reference},
		{name: "hexadecimal start block", reference: "0x" +
			strconv.FormatUint(testRelayRequestStartBlock, 16) + ":" +
			requestID.String() + ":" +
			strconv.FormatUint(terminatedGroupID, 10)},
		{name: "zero-padded request identifier", reference: strconv.FormatUint(
			testRelayRequestStartBlock, 10) + ":0" + requestID.String() + ":" +
			strconv.FormatUint(terminatedGroupID, 10)},
		{name: "signed request identifier", reference: strconv.FormatUint(
			testRelayRequestStartBlock, 10) + ":+" + requestID.String() + ":" +
			strconv.FormatUint(terminatedGroupID, 10)},
		{name: "negative request identifier", reference: strconv.FormatUint(
			testRelayRequestStartBlock, 10) + ":-11:" +
			strconv.FormatUint(terminatedGroupID, 10)},
		{name: "zero-padded terminated group", reference: strconv.FormatUint(
			testRelayRequestStartBlock, 10) + ":" + requestID.String() + ":09"},
		{name: "non-numeric terminated group", reference: strconv.FormatUint(
			testRelayRequestStartBlock, 10) + ":" + requestID.String() +
			":group"},
	} {
		if _, _, _, err := ParseBeaconRelayTimeoutSettlementReference(
			test.reference,
		); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
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
		testRelayRequestStartBlock,
		groupPublicKey,
		previousEntry,
		entry,
	)
	if err != nil {
		t.Fatal(err)
	}

	parsedStartBlock, parsedGroup, parsedPrevious, parsedEntry, err :=
		ParseBeaconRelayEntryReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	if parsedStartBlock != testRelayRequestStartBlock {
		t.Errorf(
			"request start block did not round-trip\n"+
				"expected: [%d]\nactual:   [%d]",
			testRelayRequestStartBlock,
			parsedStartBlock,
		)
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
			testRelayRequestStartBlock,
			test.groupPublicKey,
			test.previousEntry,
			test.entry,
		); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
		}
	}

	components := hex.EncodeToString(groupPublicKey) + ":" +
		hex.EncodeToString(previousEntry) + ":" + hex.EncodeToString(entry)
	for _, test := range []struct {
		name      string
		reference string
	}{
		{name: "no components", reference: ""},
		{name: "three components", reference: components},
		{name: "five components", reference: reference + ":" +
			hex.EncodeToString(entry)},
		{name: "uppercase alias", reference: strings.ToUpper(reference)},
		{name: "prefixed alias", reference: "0x" + reference},
		// A start block rendered any way but the canonical one names the same
		// request while comparing unequal to the permit's own rendering, which
		// is what the binding check reads.
		{name: "zero-padded start block", reference: "0" + reference},
		{name: "signed start block", reference: "+" + reference},
		{name: "hexadecimal start block", reference: "0x" +
			strconv.FormatUint(testRelayRequestStartBlock, 16) + ":" +
			components},
		{name: "non-numeric start block", reference: "block:" + components},
	} {
		if _, _, _, _, err := ParseBeaconRelayEntryReference(
			test.reference,
		); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
		}
	}
}

// TestBeaconRelayWorkID_RoundTrips asserts a relay permit's work identity
// names exactly one request start block and that only the exact rendering the
// node writes is read back. The audit compares the request a relay entry
// answers against the request its permit was issued for, so a work identity
// that parses loosely would let two renderings of one block — or a block that
// was never rendered at all — pass as agreement.
func TestBeaconRelayWorkID_RoundTrips(t *testing.T) {
	for _, startBlock := range []uint64{
		0,
		1,
		testRelayRequestStartBlock,
		math.MaxUint64,
	} {
		workID := BeaconRelayWorkID(startBlock)

		parsed, err := ParseBeaconRelayWorkID(workID)
		if err != nil {
			t.Fatalf("work identity [%s] was rejected: [%v]", workID, err)
		}
		if parsed != startBlock {
			t.Errorf(
				"work identity [%s] did not round-trip\n"+
					"expected: [%d]\nactual:   [%d]",
				workID,
				startBlock,
				parsed,
			)
		}
	}

	for _, test := range []struct {
		name   string
		workID string
	}{
		{name: "empty", workID: ""},
		{name: "no request", workID: "relay-entry-17"},
		{name: "no start block", workID: "relay-request-"},
		{name: "zero-padded", workID: "relay-request-017"},
		{name: "signed", workID: "relay-request-+17"},
		{name: "negative", workID: "relay-request--17"},
		{name: "hexadecimal", workID: "relay-request-0x11"},
		{name: "beyond uint64", workID: "relay-request-18446744073709551616"},
		{name: "trailing text", workID: "relay-request-17-timeout-monitor"},
	} {
		if _, err := ParseBeaconRelayWorkID(test.workID); err == nil {
			t.Errorf("expected [%s] to be rejected", test.name)
		}
	}
}

// TestValidateTerminalOutcome_RelayEntryIsBoundToItsRequest asserts a relay
// entry can only settle the permit issued for the request it answers. The
// consequential direction is a genuine historical entry, which verifies as a
// threshold signature forever, standing in as the result of an unrelated
// request whose work this node may never have completed.
func TestValidateTerminalOutcome_RelayEntryIsBoundToItsRequest(t *testing.T) {
	relayEvidence := func(startBlock uint64) TerminalEvidence {
		reference, err := BeaconRelayEntryReference(
			startBlock,
			bytes.Repeat([]byte{0xa1}, beaconRelayEntryComponentLength),
			bytes.Repeat([]byte{0xb2}, beaconRelayEntryComponentLength),
			bytes.Repeat([]byte{0xc3}, beaconRelayEntryComponentLength),
		)
		if err != nil {
			t.Fatal(err)
		}
		return TerminalEvidence{
			Kind:      TerminalEvidenceProtocolResult,
			Reference: reference,
			// The relay ceremony authors the population behind its entry, so a
			// completed record carrying none is refused before the reference is
			// ever read. This case is about the reference, so every record here
			// carries a well-formed transcript.
			Contribution: &TranscriptContribution{
				IncorporatedMembers: MemberIndexes{1, 2},
				LocalMembers:        MemberIndexes{2},
			},
		}
	}

	if err := ValidateTerminalOutcome(
		BeaconRelaySigning,
		BeaconRelayWorkID(testRelayRequestStartBlock),
		TerminalOutcomeCompleted,
		relayEvidence(testRelayRequestStartBlock),
	); err != nil {
		t.Fatalf("an entry answering its own request was rejected: [%v]", err)
	}

	// The widest reference a real relay round can produce still has to fit the
	// evidence bound. A bound that no longer admits it would reject genuine
	// results at the top of the block range as unnameable, which the recorder
	// reads as no result at all.
	if err := ValidateTerminalOutcome(
		BeaconRelaySigning,
		BeaconRelayWorkID(math.MaxUint64),
		TerminalOutcomeCompleted,
		relayEvidence(math.MaxUint64),
	); err != nil {
		t.Errorf("the widest relay entry reference was rejected: [%v]", err)
	}

	for _, test := range []struct {
		name       string
		workID     string
		startBlock uint64
	}{
		{
			name:       "an entry from an earlier request",
			workID:     BeaconRelayWorkID(testRelayRequestStartBlock),
			startBlock: testRelayRequestStartBlock - 1,
		},
		{
			name:       "an entry from a later request",
			workID:     BeaconRelayWorkID(testRelayRequestStartBlock),
			startBlock: testRelayRequestStartBlock + 1,
		},
		{
			name:       "a permit naming no relay request",
			workID:     "wallet-action",
			startBlock: testRelayRequestStartBlock,
		},
		{
			name:       "a permit whose request is not canonically rendered",
			workID:     "relay-request-0" + strconv.FormatUint(testRelayRequestStartBlock, 10),
			startBlock: testRelayRequestStartBlock,
		},
	} {
		if err := ValidateTerminalOutcome(
			BeaconRelaySigning,
			test.workID,
			TerminalOutcomeCompleted,
			relayEvidence(test.startBlock),
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
			evidence := TerminalEvidence{
				Kind:         kind,
				Contribution: testTranscriptContribution(ceremony, 1),
			}
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
				testWorkID(ceremony),
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

		evidence := TerminalEvidence{
			Kind:         expectedKind,
			Contribution: testTranscriptContribution(ceremony, 1),
		}
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
			testWorkID(ceremony),
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
			testWorkID(ceremony),
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
			Contribution:    testTranscriptContribution(TBTCHeartbeat, 1),
		}
	}

	// A dispatch with no observed settlement is the deliberate unreconciled
	// record; rejecting it would force the node to either fabricate a claim
	// identity or hide the dispatch entirely.
	if err := ValidateTerminalOutcome(
		TBTCHeartbeat,
		testWorkID(TBTCHeartbeat),
		TerminalOutcomeCompleted,
		heartbeatEvidence(&ChainSettlementRecord{
			Kind: ChainSettlementInactivityClaim,
		}),
	); err != nil {
		t.Errorf("an unobserved dispatch was rejected: [%v]", err)
	}

	if err := ValidateTerminalOutcome(
		TBTCHeartbeat,
		testWorkID(TBTCHeartbeat),
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
		testWorkID(TBTCHeartbeat),
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

// TestValidateTerminalOutcome_TranscriptContributionIsRequired asserts a
// ceremony whose owner authenticates its peers cannot record a completed
// threshold result without saying which memberships produced it.
//
// Without this the reader of a terminal record is left where every earlier
// reading of a mixed-release ceremony was: every member of one ceremony records
// the same completion and the same result identity, so the record cannot
// distinguish shares that combined from several parties from a single party that
// recovered the common result — and the population has to come from whichever
// party wrote the report.
func TestValidateTerminalOutcome_TranscriptContributionIsRequired(t *testing.T) {
	for ceremony, expectedKind := range completedEvidenceKinds {
		_, authored := transcriptContributionCeremonies[ceremony]

		evidence := TerminalEvidence{Kind: expectedKind}
		switch expectedKind {
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
			testWorkID(ceremony),
			TerminalOutcomeCompleted,
			evidence,
		)
		if authored && err == nil {
			t.Errorf(
				"ceremony [%s] completed a threshold result without naming "+
					"the memberships that produced it",
				ceremony,
			)
		}
		if !authored && err != nil {
			t.Errorf(
				"ceremony [%s] rejected its own completed evidence: [%v]",
				ceremony,
				err,
			)
		}

		// The mirror: a ceremony that authenticates no peer population must not
		// be able to attach one. A forwarder relays other members' shares and
		// computes nothing, and a coordination proposal comes from one leader;
		// letting either name a transcript would put a claim about other
		// parties into a record that has no local view to support it.
		evidence.Contribution = &TranscriptContribution{
			IncorporatedMembers: []group.MemberIndex{1, 2},
			LocalMembers:        []group.MemberIndex{1},
		}
		err = ValidateTerminalOutcome(
			ceremony,
			testWorkID(ceremony),
			TerminalOutcomeCompleted,
			evidence,
		)
		if !authored && err == nil {
			t.Errorf(
				"ceremony [%s] authored a transcript it cannot observe",
				ceremony,
			)
		}
		if authored && err != nil {
			t.Errorf(
				"ceremony [%s] rejected its own transcript: [%v]",
				ceremony,
				err,
			)
		}
	}
}

// TestValidateTerminalOutcome_TranscriptContributionShapes asserts the
// transcript is a well-formed set that places the recording node inside the
// population it describes.
func TestValidateTerminalOutcome_TranscriptContributionShapes(t *testing.T) {
	signingEvidence := func(
		contribution *TranscriptContribution,
	) TerminalEvidence {
		return TerminalEvidence{
			Kind:         TerminalEvidenceBitcoinTransaction,
			Reference:    "signed-transaction-hash",
			Contribution: contribution,
		}
	}

	refused := map[string]*TranscriptContribution{
		"no incorporated membership": {
			LocalMembers: []group.MemberIndex{1},
		},
		// An index of zero is no membership at all, and a reader that accepted
		// it would count a party that cannot exist toward a population.
		"a zero index": {
			IncorporatedMembers: []group.MemberIndex{0, 2},
			LocalMembers:        []group.MemberIndex{2},
		},
		// One encoding per set. Otherwise the same membership listed twice
		// inflates a population, and two records of one transcript compare
		// unequal for no reason a reader can see.
		"a repeated membership": {
			IncorporatedMembers: []group.MemberIndex{2, 2, 3},
			LocalMembers:        []group.MemberIndex{2},
		},
		"an unordered set": {
			IncorporatedMembers: []group.MemberIndex{3, 2},
			LocalMembers:        []group.MemberIndex{2},
		},
		"unordered local memberships": {
			IncorporatedMembers: []group.MemberIndex{1, 2, 3},
			LocalMembers:        []group.MemberIndex{3, 1},
		},
		// The node has to be inside the transcript it authors. A record whose
		// local membership is absent from the produced population is a report
		// about other parties, which is the one thing this field must not be
		// able to become.
		"a local membership outside the population": {
			IncorporatedMembers: []group.MemberIndex{1, 2},
			LocalMembers:        []group.MemberIndex{4},
		},
	}

	for name, contribution := range refused {
		if err := ValidateTerminalOutcome(
			TBTCSigning,
			testWorkID(TBTCSigning),
			TerminalOutcomeCompleted,
			signingEvidence(contribution),
		); err == nil {
			t.Errorf("a transcript with %s was accepted", name)
		}
	}

	// A node operating several memberships of one group records them all: the
	// memberships some other node supplied are what is left after removing
	// them, so an omitted local membership would be attributed elsewhere.
	if err := ValidateTerminalOutcome(
		TBTCSigning,
		testWorkID(TBTCSigning),
		TerminalOutcomeCompleted,
		signingEvidence(&TranscriptContribution{
			IncorporatedMembers: []group.MemberIndex{1, 2, 3, 7},
			LocalMembers:        []group.MemberIndex{2, 7},
		}),
	); err != nil {
		t.Errorf("a node operating several memberships was refused: [%v]", err)
	}

	// A wallet action owns its permit whether or not the attempt that produced
	// the signature selected any of the memberships this node operates. The
	// transcript it observed is still authenticated, and naming no local
	// membership is the honest reading of it; refusing the record would leave a
	// permit unresolved over work that demonstrably concluded.
	if err := ValidateTerminalOutcome(
		TBTCSigning,
		testWorkID(TBTCSigning),
		TerminalOutcomeCompleted,
		signingEvidence(&TranscriptContribution{
			IncorporatedMembers: []group.MemberIndex{1, 2, 3},
		}),
	); err != nil {
		t.Errorf(
			"a node that observed a result it did not sign was refused: [%v]",
			err,
		)
	}
}

// TestValidateTerminalOutcome_TranscriptContributionBindsPersistedMembership
// asserts a persisted DKG membership and the transcript behind it describe one
// ceremony. A record naming a membership it does not claim to have operated
// joins a result produced in one ceremony to a signer persisted from another.
func TestValidateTerminalOutcome_TranscriptContributionBindsPersistedMembership(
	t *testing.T,
) {
	evidence := func(local group.MemberIndex) TerminalEvidence {
		return TerminalEvidence{
			Kind:            TerminalEvidencePersistedTBTCSinger,
			Reference:       "wallet-storage-key",
			MembershipIndex: 4,
			Contribution: &TranscriptContribution{
				IncorporatedMembers: []group.MemberIndex{1, 4, 9},
				LocalMembers:        []group.MemberIndex{local},
			},
		}
	}

	if err := ValidateTerminalOutcome(
		TBTCDKG,
		testWorkID(TBTCDKG),
		TerminalOutcomeCompleted,
		evidence(4),
	); err != nil {
		t.Errorf("a persisted membership inside its own transcript was refused: [%v]", err)
	}

	if err := ValidateTerminalOutcome(
		TBTCDKG,
		testWorkID(TBTCDKG),
		TerminalOutcomeCompleted,
		evidence(9),
	); err == nil {
		t.Error("a persisted membership the node never claimed to operate was accepted")
	}
}

// TestValidateTerminalOutcome_TranscriptContributionNeedsAResult asserts an
// ending that produced nothing cannot carry a transcript. Quarantine, exhaustion
// and the unresolved marker left no threshold result behind, so a population
// attached to one would describe a ceremony that did not conclude.
func TestValidateTerminalOutcome_TranscriptContributionNeedsAResult(
	t *testing.T,
) {
	contribution := &TranscriptContribution{
		IncorporatedMembers: []group.MemberIndex{1, 2},
		LocalMembers:        []group.MemberIndex{1},
	}

	if err := ValidateTerminalOutcome(
		TBTCDKG,
		testWorkID(TBTCDKG),
		TerminalOutcomeQuarantined,
		TerminalEvidence{
			Kind:         TerminalEvidenceQuarantinedTBTCSinger,
			Contribution: contribution,
		},
	); err == nil {
		t.Error("a quarantined signer claimed a produced transcript")
	}

	if err := ValidateTerminalOutcome(
		TBTCSigning,
		testWorkID(TBTCSigning),
		TerminalOutcomeExhausted,
		TerminalEvidence{
			Kind:         TerminalEvidenceNoThreshold,
			Contribution: contribution,
		},
	); err == nil {
		t.Error("an exhausted ceremony claimed a produced transcript")
	}
}

// TestMemberIndexes_JSONRoundTrip asserts a transcript survives the journal as a
// membership list rather than as an opaque string. A member index is a byte, so
// the default encoding of a set of them is base64: the audit and the diagnostics
// scrape would both receive the one field that says who produced a result in a
// form they cannot join to a membership.
func TestMemberIndexes_JSONRoundTrip(t *testing.T) {
	contribution := &TranscriptContribution{
		IncorporatedMembers: []group.MemberIndex{1, 4, 255},
		LocalMembers:        []group.MemberIndex{4},
	}

	encoded, err := json.Marshal(contribution)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"incorporated_members":[1,4,255],"local_members":[4]}`
	if string(encoded) != expected {
		t.Errorf(
			"unexpected transcript encoding\nactual:   %s\nexpected: %s",
			encoded,
			expected,
		)
	}

	decoded := &TranscriptContribution{}
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(contribution) {
		t.Errorf("the transcript did not survive the journal: %+v", decoded)
	}

	// A record read outside the node that wrote it can be corrupt or forged, so
	// a value that is not a member index has to fail on the way in rather than
	// become a truncated index a reader would treat as a real membership.
	for _, invalid := range []string{
		`{"incorporated_members":[256],"local_members":[1]}`,
		`{"incorporated_members":[0],"local_members":[1]}`,
		`{"incorporated_members":[-1],"local_members":[1]}`,
		`{"incorporated_members":"AQQJ","local_members":[1]}`,
	} {
		if err := json.Unmarshal(
			[]byte(invalid),
			&TranscriptContribution{},
		); err == nil {
			t.Errorf("an invalid transcript was decoded: %s", invalid)
		}
	}
}

// TestTranscriptContribution_EqualComparesTheTranscript asserts the record is
// compared by the transcript it names. It travels by pointer and carries
// slices, so the default comparison would separate one observation from the
// same observation reloaded from the journal — which is what the terminal
// recorder's idempotent retry rests on.
func TestTranscriptContribution_EqualComparesTheTranscript(t *testing.T) {
	contribution := func() *TranscriptContribution {
		return &TranscriptContribution{
			IncorporatedMembers: []group.MemberIndex{1, 2, 3},
			LocalMembers:        []group.MemberIndex{2},
		}
	}

	if !contribution().Equal(contribution()) {
		t.Error("two records of one transcript compared unequal")
	}

	var absent *TranscriptContribution
	if absent.Equal(contribution()) || contribution().Equal(absent) {
		t.Error("a named transcript compared equal to none at all")
	}
	if !absent.Equal(nil) {
		t.Error("two records naming no transcript compared unequal")
	}

	differing := contribution()
	differing.IncorporatedMembers = []group.MemberIndex{1, 2, 4}
	if contribution().Equal(differing) {
		t.Error("two different populations compared equal")
	}

	// The same population with a different local half is a different node's
	// record of the same ceremony, and the recorder must not treat one as a
	// retry of the other.
	relabeled := contribution()
	relabeled.LocalMembers = []group.MemberIndex{3}
	if contribution().Equal(relabeled) {
		t.Error("two nodes' records of one ceremony compared equal")
	}
}
