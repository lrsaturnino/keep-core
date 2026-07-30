package participation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// A permit's operated seats are the fleet's only complete account of who held
// which seat on one piece of work: they are recorded before the ceremony runs,
// so they survive an ending that produced no result at all. These tests hold
// that account to the two things a reader of it depends on — that it is there
// whatever became of the permit, and that the record written afterwards cannot
// contradict it.

// TestPermit_OperatedSeatsSurviveEveryEnding is the case an ownership map built
// from completions gets wrong. A node that operated a seat and then ended
// without a threshold result operated it just as much as one that finished, and
// a reader that cannot see the seat attributes it to whoever else was on the
// network.
func TestPermit_OperatedSeatsSurviveEveryEnding(t *testing.T) {
	const cutover = uint64(1_000)

	tests := map[string]struct {
		ceremony Ceremony
		identity PermitIdentity
		outcome  TerminalOutcome
		evidence TerminalEvidence
	}{
		"a signing that reached no threshold": {
			ceremony: TBTCSigning,
			identity: PermitIdentity{
				WorkID:          "wallet-action-exhausted",
				PermitID:        "wallet",
				OperatedMembers: MemberIndexes{3, 9},
			},
			outcome:  TerminalOutcomeExhausted,
			evidence: TerminalEvidence{Kind: TerminalEvidenceNoThreshold},
		},
		"a DKG whose key material was quarantined": {
			ceremony: BeaconDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("b", 64),
				PermitID:        "4",
				OperatedMembers: MemberIndexes{4},
			},
			outcome: TerminalOutcomeQuarantined,
			evidence: TerminalEvidence{
				Kind: TerminalEvidenceQuarantinedBeaconSigner,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gate, err := newGate(
				context.Background(),
				Schedule{CutoverBlock: cutover},
				newGateBlockCounter(cutover),
				newFakeMetrics(),
				inertPollInterval,
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(gate.Close)

			permit, err := gate.Begin(test.ceremony, cutover, test.identity)
			if err != nil {
				t.Fatal(err)
			}

			// While the permit is live.
			held := gate.State().ActivePermits
			if len(held) != 1 {
				t.Fatalf("expected one held permit, got [%d]", len(held))
			}
			assertOperatedMembers(
				t,
				"the held permit",
				held[0].OperatedMembers,
				test.identity.OperatedMembers,
			)

			if err := permit.RecordTerminalOutcome(
				test.outcome,
				test.evidence,
			); err != nil {
				t.Fatal(err)
			}
			permit.Close()

			// And after it ended with nothing to show for itself.
			closed := gate.State().RecentTerminalOutcomes
			if len(closed) != 1 {
				t.Fatalf("expected one closed permit, got [%d]", len(closed))
			}
			if closed[0].Outcome != test.outcome {
				t.Fatalf("unexpected outcome [%s]", closed[0].Outcome)
			}
			assertOperatedMembers(
				t,
				"the closed permit",
				closed[0].Permit.OperatedMembers,
				test.identity.OperatedMembers,
			)
		})
	}
}

// TestPermit_UnresolvedEndingStillNamesItsSeats covers the ending no ceremony
// owner writes: a permit closed without any disposition at all. It is the
// ending a crashed or abandoned ceremony leaves behind, and it is exactly the
// case where a reader most needs to know which seats the holder was operating.
func TestPermit_UnresolvedEndingStillNamesItsSeats(t *testing.T) {
	const cutover = uint64(1_000)
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	permit, err := gate.Begin(
		BeaconRelaySigning,
		cutover,
		PermitIdentity{
			WorkID:          BeaconRelayWorkID(cutover),
			PermitID:        "6",
			OperatedMembers: MemberIndexes{6},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	permit.Close()

	closed := gate.State().RecentTerminalOutcomes
	if len(closed) != 1 {
		t.Fatalf("expected one closed permit, got [%d]", len(closed))
	}
	if closed[0].Outcome != terminalOutcomeUnresolved {
		t.Fatalf(
			"expected the fail-closed unresolved marker, got [%s]",
			closed[0].Outcome,
		)
	}
	assertOperatedMembers(
		t,
		"the unresolved permit",
		closed[0].Permit.OperatedMembers,
		MemberIndexes{6},
	)
}

// TestPermit_TranscriptCannotClaimAnUnoperatedSeat holds the later account to
// the earlier one. Without this the operated set would be decorative: a holder
// could announce one seat and then record a result produced with another, and a
// reader would have two node-authored answers and no rule for choosing.
func TestPermit_TranscriptCannotClaimAnUnoperatedSeat(t *testing.T) {
	const cutover = uint64(1_000)

	tests := map[string]struct {
		ceremony Ceremony
		identity PermitIdentity
		evidence TerminalEvidence
	}{
		"a signing transcript naming a seat the permit never operated": {
			ceremony: TBTCSigning,
			identity: PermitIdentity{
				WorkID:          "wallet-action-overclaimed",
				PermitID:        "wallet",
				OperatedMembers: MemberIndexes{3},
			},
			evidence: TerminalEvidence{
				Kind:      TerminalEvidenceBitcoinTransaction,
				Reference: "signed-transaction-hash",
				Contribution: &TranscriptContribution{
					IncorporatedMembers: MemberIndexes{3, 5},
					LocalMembers:        MemberIndexes{3, 5},
				},
			},
		},
		"a heartbeat transcript naming only an unoperated seat": {
			ceremony: TBTCHeartbeat,
			identity: PermitIdentity{
				WorkID:          "heartbeat-overclaimed",
				PermitID:        "wallet",
				OperatedMembers: MemberIndexes{3},
			},
			evidence: TerminalEvidence{
				Kind:      TerminalEvidenceProtocolResult,
				Reference: "heartbeat-result-identity",
				Contribution: &TranscriptContribution{
					IncorporatedMembers: MemberIndexes{5, 7},
					LocalMembers:        MemberIndexes{5},
				},
			},
		},
		"a beacon DKG persisting a seat the permit never operated": {
			ceremony: BeaconDKG,
			identity: PermitIdentity{
				WorkID:          strings.Repeat("c", 64),
				PermitID:        "4",
				OperatedMembers: MemberIndexes{4},
			},
			evidence: TerminalEvidence{
				Kind:            TerminalEvidencePersistedBeaconSigner,
				Reference:       "persisted-beacon-signer",
				MembershipIndex: 5,
				Contribution: &TranscriptContribution{
					IncorporatedMembers: MemberIndexes{4, 5},
					LocalMembers:        MemberIndexes{5},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gate, err := newGate(
				context.Background(),
				Schedule{CutoverBlock: cutover},
				newGateBlockCounter(cutover),
				newFakeMetrics(),
				inertPollInterval,
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(gate.Close)

			permit, err := gate.Begin(test.ceremony, cutover, test.identity)
			if err != nil {
				t.Fatal(err)
			}
			defer permit.Close()

			err = permit.RecordTerminalOutcome(
				TerminalOutcomeCompleted,
				test.evidence,
			)
			if !errors.Is(err, ErrInvalidTerminalOutcome) {
				t.Fatalf(
					"expected the record to be refused as invalid, got [%v]",
					err,
				)
			}
		})
	}
}

// TestPermit_TBTCDKGTranscriptIsNotHeldToItsPermitSeat is the exemption, tested
// so it cannot be removed by someone who reads the binding above as universal.
// A tBTC DKG permit is issued for a DKG member index while its transcript and
// persisted membership are in the final signing group's index space, rebuilt
// after inactive and disqualified members are removed — so the same node
// legitimately runs seat 9 of the ceremony and persists seat 7 of the group.
func TestPermit_TBTCDKGTranscriptIsNotHeldToItsPermitSeat(t *testing.T) {
	const cutover = uint64(1_000)
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	permit, err := gate.Begin(
		TBTCDKG,
		cutover,
		PermitIdentity{
			WorkID:          strings.Repeat("d", 64),
			PermitID:        "9",
			OperatedMembers: MemberIndexes{9},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()

	if err := permit.RecordTerminalOutcome(
		TerminalOutcomeCompleted,
		TerminalEvidence{
			Kind:            TerminalEvidencePersistedTBTCSinger,
			Reference:       "wallet-storage-key",
			MembershipIndex: 7,
			Contribution: &TranscriptContribution{
				IncorporatedMembers: MemberIndexes{1, 2, 3, 4, 5, 6, 7},
				LocalMembers:        MemberIndexes{7},
			},
		},
	); err != nil {
		t.Fatalf(
			"a final signing group seat was refused against the DKG seat its "+
				"permit was issued for: [%v]",
			err,
		)
	}
}

// TestValidatePermitOperatedOwnership_RejectsMalformedOperatedSets checks the
// generic set shape at the offline reader's entry point too. The journal is read
// outside the node that wrote it, so a record edited after the fact has to fail
// here rather than reach an ownership map as a seat counted twice.
func TestValidatePermitOperatedOwnership_RejectsMalformedOperatedSets(
	t *testing.T,
) {
	tests := map[string]MemberIndexes{
		"unordered":  {4, 2},
		"repeated":   {2, 2},
		"zero index": {0},
	}

	for name, operated := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePermitOperatedOwnership(
				TBTCSigning,
				operated,
				TerminalOutcomeExhausted,
				TerminalEvidence{Kind: TerminalEvidenceNoThreshold},
			); err == nil {
				t.Fatal("a malformed operated set was accepted")
			}
		})
	}
}

// TestPermit_OperatedSeatsAreNotAliased covers the two directions a slice can
// leak. The caller still holds the slice it passed to Begin, and every reader
// receives one from a snapshot, so neither may reach the permit's own record.
func TestPermit_OperatedSeatsAreNotAliased(t *testing.T) {
	const cutover = uint64(1_000)
	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	supplied := MemberIndexes{3, 9}
	permit, err := gate.Begin(
		TBTCSigning,
		cutover,
		PermitIdentity{
			WorkID:          "wallet-action-aliasing",
			PermitID:        "wallet",
			OperatedMembers: supplied,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()

	// The caller's own slice, rewritten after issuance.
	supplied[0] = 200

	held := gate.State().ActivePermits
	if len(held) != 1 {
		t.Fatalf("expected one held permit, got [%d]", len(held))
	}
	assertOperatedMembers(
		t,
		"the held permit after the caller rewrote its slice",
		held[0].OperatedMembers,
		MemberIndexes{3, 9},
	)

	// And a reader's copy, rewritten after the snapshot was taken.
	held[0].OperatedMembers[1] = 201
	again := gate.State().ActivePermits
	assertOperatedMembers(
		t,
		"the held permit after a reader rewrote its snapshot",
		again[0].OperatedMembers,
		MemberIndexes{3, 9},
	)
}

// TestPermit_ConcurrentReadersSeeTheirOwnOperatedSeats runs the snapshot path
// against a live gate under -race. A permit's operated set is read by every
// diagnostics scrape while other ceremonies are being issued and closed, and a
// snapshot handing out a window onto shared state would be a data race rather
// than a wrong answer.
func TestPermit_ConcurrentReadersSeeTheirOwnOperatedSeats(t *testing.T) {
	const cutover = uint64(1_000)
	const ceremonies = 16
	const readers = 8

	gate, err := newGate(
		context.Background(),
		Schedule{CutoverBlock: cutover},
		newGateBlockCounter(cutover),
		newFakeMetrics(),
		inertPollInterval,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	start := make(chan struct{})
	stop := make(chan struct{})
	var writers, scrapers sync.WaitGroup

	for i := 0; i < ceremonies; i++ {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			<-start
			permit, err := gate.Begin(
				TBTCSigning,
				cutover,
				PermitIdentity{
					WorkID:          fmt.Sprintf("wallet-action-%d", i),
					PermitID:        fmt.Sprintf("wallet-%d", i),
					OperatedMembers: MemberIndexes{group.MemberIndex(i + 1)},
				},
			)
			if err != nil {
				t.Errorf("[%d] refused: [%v]", i, err)
				return
			}
			permit.Close()
		}(i)
	}

	for i := 0; i < readers; i++ {
		scrapers.Add(1)
		go func() {
			defer scrapers.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				snapshot := gate.State()
				// Every reading is mutated in place, so an implementation
				// handing out shared backing arrays races here rather than
				// merely returning a stale value.
				for _, held := range snapshot.ActivePermits {
					for seat := range held.OperatedMembers {
						held.OperatedMembers[seat] = 255
					}
				}
				for _, closed := range snapshot.RecentTerminalOutcomes {
					for seat := range closed.Permit.OperatedMembers {
						closed.Permit.OperatedMembers[seat] = 255
					}
				}
			}
		}()
	}

	close(start)
	writers.Wait()
	close(stop)
	scrapers.Wait()

	// Nothing a reader did may have reached the gate's own account.
	for _, closed := range gate.State().RecentTerminalOutcomes {
		if len(closed.Permit.OperatedMembers) != 1 ||
			closed.Permit.OperatedMembers[0] == 255 {
			t.Fatalf(
				"a reader's rewrite reached the gate's account of [%s]: %v",
				closed.Permit.PermitID,
				closed.Permit.OperatedMembers,
			)
		}
	}
}

func assertOperatedMembers(
	t *testing.T,
	subject string,
	actual MemberIndexes,
	expected MemberIndexes,
) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Fatalf("%s names %v, expected %v", subject, actual, expected)
	}
	for i, seat := range expected {
		if actual[i] != seat {
			t.Fatalf("%s names %v, expected %v", subject, actual, expected)
		}
	}
}
