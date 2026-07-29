package participation

import (
	"encoding/json"
	"errors"
	"io/fs"
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
	if len(journal.Outcomes) != 1 || journal.Outcomes[0] != outcome {
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

// TestTerminalResultReference_IsAcceptedAsEvidence asserts a derived reference
// passes the journal's own identity rules, so a ceremony that authors one can
// actually record it.
func TestTerminalResultReference_IsAcceptedAsEvidence(t *testing.T) {
	for _, ceremony := range []Ceremony{
		TBTCSigning,
		TBTCHeartbeat,
		TBTCWalletCoordination,
		BeaconRelaySigning,
		BeaconTimeoutReport,
	} {
		if err := ValidateTerminalOutcome(
			ceremony,
			TerminalOutcomeCompleted,
			TerminalEvidence{
				Kind:      TerminalEvidenceProtocolResult,
				Reference: TerminalResultReference("domain", []byte("result")),
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
