package beacon

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// recordingPermit is a minimal participation.Permit that captures the terminal
// dispositions its ceremony owner authors, so a test can assert what reaches
// the rollback journal without running a gate.
type recordingPermit struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	ceremony participation.Ceremony

	mu       sync.Mutex
	outcomes []recordedOutcome
}

type recordedOutcome struct {
	outcome  participation.TerminalOutcome
	evidence participation.TerminalEvidence
}

func newRecordingPermit(ceremony participation.Ceremony) *recordingPermit {
	ctx, cancel := context.WithCancelCause(context.Background())

	return &recordingPermit{ctx: ctx, cancel: cancel, ceremony: ceremony}
}

func (rp *recordingPermit) Context() context.Context { return rp.ctx }

func (rp *recordingPermit) Ceremony() participation.Ceremony { return rp.ceremony }

func (rp *recordingPermit) CanonicalStartBlock() uint64 { return 1 }

func (rp *recordingPermit) Mode() participation.ProtocolMode {
	return participation.ModeSecurityV2
}

func (rp *recordingPermit) WorkID() string { return "test-work" }

func (rp *recordingPermit) PermitID() string { return "1" }

func (rp *recordingPermit) CheckCommit(string, participation.CommitClass) error {
	return nil
}

func (rp *recordingPermit) RecordTerminalOutcome(
	outcome participation.TerminalOutcome,
	evidence participation.TerminalEvidence,
) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.outcomes = append(
		rp.outcomes,
		recordedOutcome{outcome: outcome, evidence: evidence},
	)

	return nil
}

func (rp *recordingPermit) Close() { rp.cancel(participation.ErrPermitClosed) }

func (rp *recordingPermit) recorded() []recordedOutcome {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	return append([]recordedOutcome(nil), rp.outcomes...)
}

// assertRecordedTerminalOutcome checks that the ceremony owner authored exactly
// one terminal disposition of the expected shape and that the live gate's own
// validator accepts it for that ceremony. An outcome the node writes but the
// gate rejects never reaches the rollback audit at all.
func assertRecordedTerminalOutcome(
	t *testing.T,
	permit *recordingPermit,
	expectedOutcome participation.TerminalOutcome,
	expectedKind participation.TerminalEvidenceKind,
) participation.TerminalEvidence {
	t.Helper()

	recorded := permit.recorded()
	if len(recorded) != 1 {
		t.Fatalf(
			"expected exactly one terminal outcome, got [%d]",
			len(recorded),
		)
	}

	if recorded[0].outcome != expectedOutcome {
		t.Errorf(
			"unexpected terminal outcome\nexpected: [%s]\nactual:   [%s]",
			expectedOutcome,
			recorded[0].outcome,
		)
	}

	if recorded[0].evidence.Kind != expectedKind {
		t.Errorf(
			"unexpected terminal evidence kind\nexpected: [%s]\nactual:   [%s]",
			expectedKind,
			recorded[0].evidence.Kind,
		)
	}

	if err := participation.ValidateTerminalOutcome(
		permit.Ceremony(),
		recorded[0].outcome,
		recorded[0].evidence,
	); err != nil {
		t.Errorf(
			"the gate rejects the node-authored outcome for ceremony [%s]: [%v]",
			permit.Ceremony(),
			err,
		)
	}

	return recorded[0].evidence
}

// TestRecordRelayEntryTerminalOutcome covers one relay signing membership's
// disposition. A relay entry is deterministic for a given previous entry, so
// the recovered entry is the ceremony's durable result and stays reconcilable
// against the chain whichever member published it.
func TestRecordRelayEntryTerminalOutcome(t *testing.T) {
	t.Run("no threshold reached", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconRelaySigning)

		recordRelayEntryTerminalOutcome(&testutils.MockLogger{}, permit, nil)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeExhausted,
			participation.TerminalEvidenceNoThreshold,
		)

		if evidence.Reference != "" {
			t.Errorf(
				"expected no evidence reference, got [%s]",
				evidence.Reference,
			)
		}
	})

	t.Run("entry recovered", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconRelaySigning)
		relayEntry := []byte{0x01, 0x02, 0x03, 0x04}

		recordRelayEntryTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayEntry,
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidenceProtocolResult,
		)

		expectedReference := hex.EncodeToString(relayEntry)
		if evidence.Reference != expectedReference {
			t.Errorf(
				"unexpected evidence reference\nexpected: [%s]\nactual:   [%s]",
				expectedReference,
				evidence.Reference,
			)
		}
	})
}

// TestRecordRelayEntryTerminalOutcome_FullWidthEntryFitsTheJournal asserts a
// real marshaled relay entry survives the journal's identity rules. A
// bn256.G1 point marshals to 64 bytes, so the hex reference is 128 characters
// and must not be rejected as an oversized or malformed token.
func TestRecordRelayEntryTerminalOutcome_FullWidthEntryFitsTheJournal(t *testing.T) {
	permit := newRecordingPermit(participation.BeaconRelaySigning)

	relayEntry := make([]byte, 64)
	for i := range relayEntry {
		relayEntry[i] = byte(i + 1)
	}

	recordRelayEntryTerminalOutcome(&testutils.MockLogger{}, permit, relayEntry)

	evidence := assertRecordedTerminalOutcome(
		t,
		permit,
		participation.TerminalOutcomeCompleted,
		participation.TerminalEvidenceProtocolResult,
	)

	if len(evidence.Reference) != 128 {
		t.Errorf(
			"expected a 128 character reference, got [%d] characters",
			len(evidence.Reference),
		)
	}
}

// TestRecordRelayTimeoutTerminalOutcome covers the relay entry monitor. The
// monitor exists only to file the penalty report, so only a filed report is a
// durable result; every other exit created no penalty state.
func TestRecordRelayTimeoutTerminalOutcome(t *testing.T) {
	t.Run("no timeout reported", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconTimeoutReport)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			100,
			0,
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeExhausted,
			participation.TerminalEvidenceNoThreshold,
		)

		if evidence.Reference != "" {
			t.Errorf(
				"expected no evidence reference, got [%s]",
				evidence.Reference,
			)
		}
	})

	t.Run("timeout reported", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconTimeoutReport)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			100,
			1000,
		)

		assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidenceProtocolResult,
		)
	})

	t.Run("distinct requests produce distinct references", func(t *testing.T) {
		references := make([]string, 0, 2)
		for _, relayRequestBlock := range []uint64{100, 200} {
			permit := newRecordingPermit(participation.BeaconTimeoutReport)

			recordRelayTimeoutTerminalOutcome(
				&testutils.MockLogger{},
				permit,
				relayRequestBlock,
				1000,
			)

			evidence := assertRecordedTerminalOutcome(
				t,
				permit,
				participation.TerminalOutcomeCompleted,
				participation.TerminalEvidenceProtocolResult,
			)
			references = append(references, evidence.Reference)
		}

		if references[0] == references[1] {
			t.Errorf(
				"two relay requests produced the same evidence reference [%s]",
				references[0],
			)
		}
	})
}
