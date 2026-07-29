package beacon

import (
	"bytes"
	"context"
	"math/big"
	"strconv"
	"sync"
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/bls"

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
	workID   string

	mu       sync.Mutex
	outcomes []recordedOutcome
}

type recordedOutcome struct {
	outcome  participation.TerminalOutcome
	evidence participation.TerminalEvidence
}

// testRelayRequestStartBlock is the relay request every relay permit in this
// file is issued for. Relay evidence names the request it answers and the gate
// holds it to the permit's own request, so the two have to agree on one block.
const testRelayRequestStartBlock = uint64(7_654_321)

func newRecordingPermit(ceremony participation.Ceremony) *recordingPermit {
	ctx, cancel := context.WithCancelCause(context.Background())

	// Beacon relay work is the one ceremony whose work identity is parsed
	// rather than only compared, so its permits carry the identity the node
	// would really issue.
	workID := "test-work"
	if ceremony == participation.BeaconRelaySigning ||
		ceremony == participation.BeaconTimeoutReport {
		workID = participation.BeaconRelayWorkID(testRelayRequestStartBlock)
	}

	return &recordingPermit{
		ctx:      ctx,
		cancel:   cancel,
		ceremony: ceremony,
		workID:   workID,
	}
}

// newRecordingRelayPermit issues a relay-flavored permit for one named relay
// request, so a test can vary the request its evidence has to answer.
func newRecordingRelayPermit(
	ceremony participation.Ceremony,
	requestStartBlock uint64,
) *recordingPermit {
	permit := newRecordingPermit(ceremony)
	permit.workID = participation.BeaconRelayWorkID(requestStartBlock)
	return permit
}

func (rp *recordingPermit) Context() context.Context { return rp.ctx }

func (rp *recordingPermit) Ceremony() participation.Ceremony { return rp.ceremony }

func (rp *recordingPermit) CanonicalStartBlock() uint64 { return 1 }

func (rp *recordingPermit) Mode() participation.ProtocolMode {
	return participation.ModeSecurityV2
}

func (rp *recordingPermit) WorkID() string { return rp.workID }

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
		permit.WorkID(),
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
// the recovered entry is the ceremony's durable result whichever member
// published it, and it is named together with the group and previous entry
// that make it verifiable rather than merely asserted.
func TestRecordRelayEntryTerminalOutcome(t *testing.T) {
	groupSecret := big.NewInt(42)

	groupPublicKey := altbn128.G2Point{
		G2: new(bn256.G2).ScalarBaseMult(groupSecret),
	}.Compress()
	previousEntryPoint := altbn128.G1HashToPoint([]byte("previous-entry"))
	previousEntry := previousEntryPoint.Marshal()
	relayEntry := bls.SignG1(groupSecret, previousEntryPoint).Marshal()

	t.Run("no threshold reached", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconRelaySigning)

		recordRelayEntryTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			testRelayRequestStartBlock,
			groupPublicKey,
			previousEntry,
			nil,
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

	t.Run("entry recovered", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconRelaySigning)

		recordRelayEntryTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			testRelayRequestStartBlock,
			groupPublicKey,
			previousEntry,
			relayEntry,
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidenceProtocolResult,
		)

		expectedReference, err := participation.BeaconRelayEntryReference(
			testRelayRequestStartBlock,
			groupPublicKey,
			previousEntry,
			relayEntry,
		)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Reference != expectedReference {
			t.Errorf(
				"unexpected evidence reference\nexpected: [%s]\nactual:   [%s]",
				expectedReference,
				evidence.Reference,
			)
		}

		// The decimal request start block and three 64-byte components in
		// hex, separated by three colons.
		expectedLength := len(strconv.FormatUint(
			testRelayRequestStartBlock, 10,
		)) + 3*128 + 3
		if len(evidence.Reference) != expectedLength {
			t.Errorf(
				"expected a %d character reference, got [%d] characters",
				expectedLength,
				len(evidence.Reference),
			)
		}
	})

	// A result the node cannot name verifiably must not reach the journal as
	// an unverifiable one. Leaving the permit unresolved blocks the offline
	// barrier, which is the safe reading of a result nobody can check.
	for name, test := range map[string]struct {
		previousEntry []byte
		relayEntry    []byte
	}{
		"entry that is not a full-width point": {
			previousEntry: previousEntry,
			relayEntry:    []byte{0x01, 0x02, 0x03, 0x04},
		},
		"previous entry that is not a curve point": {
			previousEntry: bytes.Repeat([]byte{0xff}, 64),
			relayEntry:    relayEntry,
		},
	} {
		t.Run(name, func(t *testing.T) {
			permit := newRecordingPermit(participation.BeaconRelaySigning)

			recordRelayEntryTerminalOutcome(
				&testutils.MockLogger{},
				permit,
				testRelayRequestStartBlock,
				groupPublicKey,
				test.previousEntry,
				test.relayEntry,
			)

			if recorded := permit.recorded(); len(recorded) != 0 {
				t.Errorf(
					"expected an unnameable entry to record no outcome, "+
						"got [%+v]",
					recorded,
				)
			}
		})
	}
}

// TestRecordRelayEntryTerminalOutcome_ReferenceVerifies asserts the recorded
// reference is not merely well formed but actually checks out: the entry it
// names verifies as the group's threshold signature over the previous entry it
// names. That pairing is the whole reason the reference carries points rather
// than a digest, so a record that could not be verified would defeat it.
func TestRecordRelayEntryTerminalOutcome_ReferenceVerifies(t *testing.T) {
	groupSecret := big.NewInt(42)
	previousEntryPoint := altbn128.G1HashToPoint([]byte("previous-entry"))

	permit := newRecordingPermit(participation.BeaconRelaySigning)

	recordRelayEntryTerminalOutcome(
		&testutils.MockLogger{},
		permit,
		testRelayRequestStartBlock,
		altbn128.G2Point{
			G2: new(bn256.G2).ScalarBaseMult(groupSecret),
		}.Compress(),
		previousEntryPoint.Marshal(),
		bls.SignG1(groupSecret, previousEntryPoint).Marshal(),
	)

	evidence := assertRecordedTerminalOutcome(
		t,
		permit,
		participation.TerminalOutcomeCompleted,
		participation.TerminalEvidenceProtocolResult,
	)

	_, groupPublicKeyBytes, previousEntryBytes, entryBytes, err :=
		participation.ParseBeaconRelayEntryReference(evidence.Reference)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := altbn128.DecompressToG2(groupPublicKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	previousEntry := new(bn256.G1)
	if _, err := previousEntry.Unmarshal(previousEntryBytes); err != nil {
		t.Fatal(err)
	}
	entry := new(bn256.G1)
	if _, err := entry.Unmarshal(entryBytes); err != nil {
		t.Fatal(err)
	}

	if !bls.VerifyG1(publicKey, previousEntry, entry) {
		t.Error(
			"the recorded relay entry does not verify as the named group's " +
				"signature over the named previous entry",
		)
	}
}

// TestRecordRelayTimeoutTerminalOutcome covers the relay entry monitor. The
// monitor exists only to file the penalty report, and only a report the beacon
// confirmed is a durable result; a report the node merely handed to a provider
// created no penalty state it can account for.
func TestRecordRelayTimeoutTerminalOutcome(t *testing.T) {
	const relayRequestBlock = uint64(100)

	t.Run("no timeout reported", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock,
			false,
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

	t.Run("timeout report the beacon confirmed", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock,
			true,
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidenceProtocolResult,
		)

		// The identity is fully determined by the request, so the node has no
		// component left to choose.
		expected := participation.BeaconRelayTimeoutReportReference(
			relayRequestBlock,
		)
		if evidence.Reference != expected {
			t.Errorf(
				"unexpected evidence reference\nexpected: [%s]\nactual:   [%s]",
				expected,
				evidence.Reference,
			)
		}
	})

	t.Run("distinct requests produce distinct references", func(t *testing.T) {
		references := make([]string, 0, 2)
		for _, requestBlock := range []uint64{100, 200} {
			permit := newRecordingRelayPermit(
				participation.BeaconTimeoutReport,
				requestBlock,
			)

			recordRelayTimeoutTerminalOutcome(
				&testutils.MockLogger{},
				permit,
				requestBlock,
				true,
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

	// The report a node filed for one request must not settle the permit it
	// holds for another. A filed report has no offline proof at all, so the
	// only thing standing between it and an arbitrary claim is that its
	// identity is derived from the permit's own request.
	t.Run("a report filed for another request", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock+1,
			true,
		)

		recorded := permit.recorded()
		if len(recorded) != 1 {
			t.Fatalf("expected one terminal outcome, got [%d]", len(recorded))
		}
		if err := participation.ValidateTerminalOutcome(
			permit.Ceremony(),
			permit.WorkID(),
			recorded[0].outcome,
			recorded[0].evidence,
		); err == nil {
			t.Error(
				"a timeout report naming another request settled this permit",
			)
		}
	})
}
