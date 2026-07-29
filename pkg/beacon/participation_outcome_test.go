package beacon

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"strconv"
	"sync"
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/bls"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/beacon/event"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/protocol/group"
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

// localMemberships builds the group memberships a node operates, carrying only
// the member indexes the relay transcript is read against.
func localMemberships(
	memberIndexes ...group.MemberIndex,
) []*registry.Membership {
	memberships := make([]*registry.Membership, 0, len(memberIndexes))
	for _, memberIndex := range memberIndexes {
		memberships = append(memberships, &registry.Membership{
			Signer: dkg.NewThresholdSigner(memberIndex, nil, nil, nil, nil),
		})
	}

	return memberships
}

// TestBeaconDKGTranscriptContribution covers the transcript a completed beacon
// DKG publishes: the members the key material was generated with, and this
// node's own seat among them. A completion alone cannot carry that — every
// member of a finished DKG writes the same word and names the same group key
// whatever population produced it — so the group key this record names would
// otherwise be indistinguishable from a share one party generated and persisted
// on its own.
func TestBeaconDKGTranscriptContribution(t *testing.T) {
	groupPublicKey := hex.EncodeToString(
		altbn128.G2Point{
			G2: new(bn256.G2).ScalarBaseMult(big.NewInt(42)),
		}.Compress(),
	)

	t.Run("operating member", func(t *testing.T) {
		signer := dkg.NewThresholdSigner(3, nil, nil, nil, nil)
		operating := participation.MemberIndexes{1, 3, 4}

		contribution := beaconDKGTranscriptContribution(signer, operating)

		expected := &participation.TranscriptContribution{
			IncorporatedMembers: operating,
			LocalMembers:        participation.MemberIndexes{3},
		}
		if !contribution.Equal(expected) {
			t.Fatalf(
				"unexpected transcript contribution\n"+
					"expected: [%+v]\nactual:   [%+v]",
				expected,
				contribution,
			)
		}

		if err := participation.ValidateTerminalOutcome(
			participation.BeaconDKG,
			"test-work",
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidence{
				Kind:            participation.TerminalEvidencePersistedBeaconSigner,
				Reference:       groupPublicKey,
				MembershipIndex: signer.MemberID(),
				Contribution:    contribution,
			},
		); err != nil {
			t.Errorf(
				"the gate rejects the node-authored beacon DKG outcome: [%v]",
				err,
			)
		}
	})

	// A signer persisted from a ceremony whose accepted result excluded it is
	// incoherent rather than something to write down, so the seat is not claimed
	// and the record fails closed at the gate: the permit is left unresolved and
	// the offline barrier blocks on it, which is the safe reading of key material
	// no transcript accounts for.
	t.Run("member outside the operating set", func(t *testing.T) {
		signer := dkg.NewThresholdSigner(5, nil, nil, nil, nil)
		operating := participation.MemberIndexes{1, 3, 4}

		contribution := beaconDKGTranscriptContribution(signer, operating)

		if len(contribution.LocalMembers) != 0 {
			t.Errorf(
				"expected no local membership, got [%v]",
				contribution.LocalMembers,
			)
		}

		if err := participation.ValidateTerminalOutcome(
			participation.BeaconDKG,
			"test-work",
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidence{
				Kind:            participation.TerminalEvidencePersistedBeaconSigner,
				Reference:       groupPublicKey,
				MembershipIndex: signer.MemberID(),
				Contribution:    contribution,
			},
		); err == nil {
			t.Error(
				"the gate accepted a persisted membership the transcript " +
					"does not account for",
			)
		}
	})
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
			nil,
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

	// The memberships whose authenticated shares were combined into the entry,
	// two of which this node does not operate.
	incorporated := participation.MemberIndexes{1, 3, 4}

	t.Run("entry recovered", func(t *testing.T) {
		permit := newRecordingPermit(participation.BeaconRelaySigning)

		recordRelayEntryTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			testRelayRequestStartBlock,
			groupPublicKey,
			previousEntry,
			relayEntry,
			incorporated,
			localMemberships(3, 5),
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

		// The transcript behind the entry, which the reference cannot carry: an
		// entry is deterministic for a given previous entry, so its identity
		// reads the same whether several parties supplied the shares it was
		// recovered from or one party held every seat. Membership 5 is this
		// node's and contributed no share to this entry, so it is not part of
		// the population, and memberships 1 and 4 are seats some other node
		// supplied — which is the only part of the transcript this record can
		// attribute elsewhere.
		expectedContribution := &participation.TranscriptContribution{
			IncorporatedMembers: incorporated,
			LocalMembers:        participation.MemberIndexes{3},
		}
		if !evidence.Contribution.Equal(expectedContribution) {
			t.Errorf(
				"unexpected transcript contribution\n"+
					"expected: [%+v]\nactual:   [%+v]",
				expectedContribution,
				evidence.Contribution,
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
				participation.MemberIndexes{1, 3, 4},
				localMemberships(3),
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
		participation.MemberIndexes{2},
		localMemberships(2),
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

// beaconTimeoutSettlement builds the beacon's own record of a terminated relay
// request, as the chain handle resolves it from canonical logs.
func beaconTimeoutSettlement(
	requestBlock uint64,
	requestID int64,
	terminatedGroupID uint64,
) *event.RelayEntryTimeoutSettlement {
	return &event.RelayEntryTimeoutSettlement{
		RequestID:            big.NewInt(requestID),
		TerminatedGroupID:    terminatedGroupID,
		RequestBlockNumber:   requestBlock,
		RequestPreviousEntry: []byte("previous-entry"),
		BlockNumber:          requestBlock + 64,
		ContractAddress:      "0xbeac0n",
	}
}

// TestRecordRelayTimeoutTerminalOutcome covers the relay entry monitor. The
// monitor exists only to file the penalty report, and only the settlement the
// beacon itself recorded is a durable result; a report the node merely handed
// to a provider created no penalty state it can account for.
func TestRecordRelayTimeoutTerminalOutcome(t *testing.T) {
	const relayRequestBlock = uint64(100)

	t.Run("no settlement the beacon recorded", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock,
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

	t.Run("a settlement the beacon recorded", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock,
			beaconTimeoutSettlement(relayRequestBlock, 7, 3),
		)

		evidence := assertRecordedTerminalOutcome(
			t,
			permit,
			participation.TerminalOutcomeCompleted,
			participation.TerminalEvidenceEthereumTransaction,
		)

		// The identity names the authenticated log the audit joins to: the
		// beacon's own request identifier and the group it terminated.
		expected, err := participation.BeaconRelayTimeoutSettlementReference(
			relayRequestBlock,
			big.NewInt(7),
			3,
		)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Reference != expected {
			t.Errorf(
				"unexpected evidence reference\nexpected: [%s]\nactual:   [%s]",
				expected,
				evidence.Reference,
			)
		}
	})

	// A settlement whose identity cannot be rendered is one the offline audit
	// could not join to any log, so it must not clear the rollback barrier.
	t.Run("a settlement naming no request identifier", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		settlement := beaconTimeoutSettlement(relayRequestBlock, 7, 3)
		settlement.RequestID = nil

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock,
			settlement,
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

	t.Run("distinct requests produce distinct references", func(t *testing.T) {
		references := make([]string, 0, 2)
		for i, requestBlock := range []uint64{100, 200} {
			permit := newRecordingRelayPermit(
				participation.BeaconTimeoutReport,
				requestBlock,
			)

			recordRelayTimeoutTerminalOutcome(
				&testutils.MockLogger{},
				permit,
				requestBlock,
				beaconTimeoutSettlement(requestBlock, int64(i+1), 3),
			)

			evidence := assertRecordedTerminalOutcome(
				t,
				permit,
				participation.TerminalOutcomeCompleted,
				participation.TerminalEvidenceEthereumTransaction,
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

	// A settlement the beacon recorded against one request must not settle the
	// permit a node holds for another. The penalty is real either way, so the
	// component that keeps it on its own permit is the request start block the
	// identity leads with.
	t.Run("a settlement recorded for another request", func(t *testing.T) {
		permit := newRecordingRelayPermit(
			participation.BeaconTimeoutReport,
			relayRequestBlock,
		)

		recordRelayTimeoutTerminalOutcome(
			&testutils.MockLogger{},
			permit,
			relayRequestBlock+1,
			beaconTimeoutSettlement(relayRequestBlock+1, 7, 3),
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
				"a timeout settlement naming another request settled this permit",
			)
		}
	})
}
