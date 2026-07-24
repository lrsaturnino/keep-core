package announcer

import (
	"context"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"

	fuzz "github.com/google/gofuzz"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/internal/pbutils"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

func TestAnnouncementMessage_MarshalingRoundtrip(t *testing.T) {
	msg := &announcementMessage{
		senderID:   group.MemberIndex(38),
		protocolID: "protocol",
		sessionID:  "session",
	}
	unmarshaled := &announcementMessage{}

	err := pbutils.RoundTrip(msg, unmarshaled)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(msg, unmarshaled) {
		t.Fatalf("unexpected content of unmarshaled message")
	}
}

func TestFuzzAnnouncementMessage_MarshalingRoundtrip(t *testing.T) {
	for i := 0; i < 10; i++ {
		var (
			senderID   group.MemberIndex
			protocolID string
			sessionID  string
		)

		f := fuzz.New().NilChance(0.1).
			NumElements(0, 512).
			Funcs(pbutils.FuzzFuncs()...)

		f.Fuzz(&senderID)
		f.Fuzz(&protocolID)
		f.Fuzz(&sessionID)

		msg := &announcementMessage{
			senderID:   senderID,
			protocolID: protocolID,
			sessionID:  sessionID,
		}

		_ = pbutils.RoundTrip(msg, &announcementMessage{})
	}
}

func TestFuzzAnnouncementMessage_Unmarshaler(t *testing.T) {
	pbutils.FuzzUnmarshaler(&announcementMessage{})
}

func TestAnnouncer(t *testing.T) {
	protocolID := "protocol-test"
	groupSize := 5
	honestThreshold := 3

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

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(
		operatorPublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	var operators []chain.Address
	for i := 0; i < groupSize; i++ {
		operators = append(operators, operatorAddress)
	}

	localProvider := local.ConnectWithKey(operatorPublicKey)

	type memberResult struct {
		memberIndex         group.MemberIndex
		readyMembersIndexes []group.MemberIndex
	}

	type memberError struct {
		memberIndex group.MemberIndex
		err         error
	}

	var tests = map[string]struct {
		message                  *big.Int
		announcingMembersIndexes []group.MemberIndex
		expectedResults          map[group.MemberIndex][]group.MemberIndex
	}{
		"all members members announced readiness": {
			message:                  big.NewInt(100),
			announcingMembersIndexes: []group.MemberIndex{1, 2, 3, 4, 5},
			expectedResults: map[group.MemberIndex][]group.MemberIndex{
				1: {1, 2, 3, 4, 5},
				2: {1, 2, 3, 4, 5},
				3: {1, 2, 3, 4, 5},
				4: {1, 2, 3, 4, 5},
				5: {1, 2, 3, 4, 5},
			},
		},
		"part of members announced readiness": {
			message:                  big.NewInt(200),
			announcingMembersIndexes: []group.MemberIndex{1, 3, 5},
			expectedResults: map[group.MemberIndex][]group.MemberIndex{
				1: {1, 3, 5},
				3: {1, 3, 5},
				5: {1, 3, 5},
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			broadcastChannel, err := localProvider.BroadcastChannelFor(
				test.message.Text(16),
			)
			if err != nil {
				t.Fatal(err)
			}

			membershipValidator := group.NewMembershipValidator(
				&testutils.MockLogger{},
				operators,
				localChain.Signing(),
			)

			RegisterUnmarshaller(broadcastChannel)

			announcer := New(
				protocolID,
				broadcastChannel,
				membershipValidator,
			)

			resultsChan := make(
				chan *memberResult,
				len(test.announcingMembersIndexes),
			)
			errorsChan := make(
				chan *memberError,
				len(test.announcingMembersIndexes),
			)

			wg := sync.WaitGroup{}
			wg.Add(len(test.announcingMembersIndexes))

			for _, announcingMemberIndex := range test.announcingMembersIndexes {
				go func(memberIndex group.MemberIndex) {
					defer wg.Done()

					ctx, cancelCtx := context.WithTimeout(
						context.Background(),
						3*local.RetransmissionTick,
					)
					defer cancelCtx()

					readyMembersIndexes, err := announcer.Announce(
						ctx,
						memberIndex,
						"session-test",
					)
					if err != nil {
						errorsChan <- &memberError{memberIndex, err}
						return
					}

					resultsChan <- &memberResult{memberIndex, readyMembersIndexes}
				}(announcingMemberIndex)
			}

			wg.Wait()

			close(resultsChan)
			results := make(map[group.MemberIndex][]group.MemberIndex)
			for r := range resultsChan {
				results[r.memberIndex] = r.readyMembersIndexes
			}

			close(errorsChan)
			errors := make(map[group.MemberIndex]error)
			for e := range errorsChan {
				errors[e.memberIndex] = e.err
			}

			testutils.AssertIntsEqual(
				t,
				"errors count",
				0,
				len(errors),
			)

			if !reflect.DeepEqual(test.expectedResults, results) {
				t.Errorf(
					"unexpected results\n"+
						"expected: [%v]\n"+
						"actual:   [%v]",
					test.expectedResults,
					results,
				)
			}
		})
	}
}

func TestClassifySessionIDFormat(t *testing.T) {
	tests := map[string]struct {
		sessionID string
		expected  SessionIDFormat
	}{
		"hardened dkg": {
			sessionID: "dkg-abc123-0000000000000001",
			expected:  SessionIDFormatHardenedDKG,
		},
		"hardened dkg with hex attempt": {
			sessionID: "dkg-0-000000000000000a",
			expected:  SessionIDFormatHardenedDKG,
		},
		"hardened signing": {
			sessionID: "signing-deadbeef-0000000000000010-0000000000000002",
			expected:  SessionIDFormatHardenedSigning,
		},
		"legacy dkg/signing": {
			sessionID: "abc123-5",
			expected:  SessionIDFormatLegacy,
		},
		"legacy zero seed zero attempt": {
			sessionID: "0-0",
			expected:  SessionIDFormatLegacy,
		},
		"legacy long hex": {
			sessionID: "deadbeef42",
			expected:  SessionIDFormatUnknown, // single token, no separator
		},
		"legacy hex and decimal": {
			sessionID: "deadbeef-42",
			expected:  SessionIDFormatLegacy,
		},
		"dkg wrong attempt width": {
			sessionID: "dkg-abc-123",
			expected:  SessionIDFormatUnknown,
		},
		"dkg too long attempt": {
			sessionID: "dkg-abc123-00000000000000001",
			expected:  SessionIDFormatUnknown,
		},
		"dkg non-hex attempt": {
			sessionID: "dkg-abc-000000000000000g",
			expected:  SessionIDFormatUnknown,
		},
		"dkg uppercase seed": {
			sessionID: "dkg-ABC-0000000000000001",
			expected:  SessionIDFormatUnknown,
		},
		"signing too few parts": {
			sessionID: "signing-abc-0000000000000001",
			expected:  SessionIDFormatUnknown,
		},
		"signing non-hex last part": {
			sessionID: "signing-abc-0000000000000001-000000000000000g",
			expected:  SessionIDFormatUnknown,
		},
		"legacy non-decimal attempt": {
			sessionID: "abc-xyz",
			expected:  SessionIDFormatUnknown,
		},
		"single token": {
			sessionID: "abc123",
			expected:  SessionIDFormatUnknown,
		},
		"empty": {
			sessionID: "",
			expected:  SessionIDFormatUnknown,
		},
		"too many parts": {
			sessionID: "a-b-c-d-e",
			expected:  SessionIDFormatUnknown,
		},
		"hex prefix rejected": {
			sessionID: "0xabc-5",
			expected:  SessionIDFormatUnknown,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			actual := ClassifySessionIDFormat(test.sessionID)
			if actual != test.expected {
				t.Errorf(
					"unexpected format for [%s]\nexpected: %v\nactual:   %v",
					test.sessionID,
					test.expected,
					actual,
				)
			}
		})
	}
}

func TestIsCrossFormatMismatch(t *testing.T) {
	tests := map[string]struct {
		a        SessionIDFormat
		b        SessionIDFormat
		expected bool
	}{
		"legacy vs hardened dkg":        {SessionIDFormatLegacy, SessionIDFormatHardenedDKG, true},
		"hardened dkg vs legacy":        {SessionIDFormatHardenedDKG, SessionIDFormatLegacy, true},
		"legacy vs hardened signing":    {SessionIDFormatLegacy, SessionIDFormatHardenedSigning, true},
		"legacy vs legacy":              {SessionIDFormatLegacy, SessionIDFormatLegacy, false},
		"hardened dkg vs hardened sign": {SessionIDFormatHardenedDKG, SessionIDFormatHardenedSigning, false},
		"hardened dkg vs hardened dkg":  {SessionIDFormatHardenedDKG, SessionIDFormatHardenedDKG, false},
		"legacy vs unknown":             {SessionIDFormatLegacy, SessionIDFormatUnknown, false},
		"unknown vs hardened dkg":       {SessionIDFormatUnknown, SessionIDFormatHardenedDKG, false},
		"unknown vs unknown":            {SessionIDFormatUnknown, SessionIDFormatUnknown, false},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			if actual := IsCrossFormatMismatch(test.a, test.b); actual != test.expected {
				t.Errorf(
					"unexpected cross-format result for (%v, %v): got %v, want %v",
					test.a, test.b, actual, test.expected,
				)
			}
		})
	}
}

type recordedMismatch struct {
	protocolID string
	sender     group.MemberIndex
	expected   SessionIDFormat
	observed   SessionIDFormat
}

type mismatchRecorder struct {
	mu      sync.Mutex
	records []recordedMismatch
}

func (r *mismatchRecorder) observer() SessionMismatchObserver {
	return func(
		protocolID string,
		sender group.MemberIndex,
		expected SessionIDFormat,
		observed SessionIDFormat,
	) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.records = append(r.records, recordedMismatch{
			protocolID: protocolID,
			sender:     sender,
			expected:   expected,
			observed:   observed,
		})
	}
}

func (r *mismatchRecorder) snapshot() []recordedMismatch {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedMismatch, len(r.records))
	copy(out, r.records)
	return out
}

// newMismatchObserverFixture builds a five-member group whose members all share
// a single operator address (so membership is valid for any in-range index) and
// returns a local network provider bound to that operator's key together with a
// matching membership validator.
func newMismatchObserverFixture(t *testing.T) (net.Provider, *group.MembershipValidator) {
	t.Helper()

	const groupSize = 5
	const honestThreshold = 3

	privateKey, publicKey, err := operator.GenerateKeyPair(local_v1.DefaultCurve)
	if err != nil {
		t.Fatal(err)
	}

	localChain := local_v1.ConnectWithKey(groupSize, honestThreshold, privateKey)

	operatorAddress, err := localChain.Signing().PublicKeyToAddress(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	operators := make([]chain.Address, groupSize)
	for i := range operators {
		operators[i] = operatorAddress
	}

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		operators,
		localChain.Signing(),
	)

	return local.ConnectWithKey(publicKey), membershipValidator
}

func sendAnnouncement(
	t *testing.T,
	ctx context.Context,
	channel net.BroadcastChannel,
	senderID group.MemberIndex,
	protocolID string,
	sessionID string,
) {
	t.Helper()

	err := channel.Send(ctx, &announcementMessage{
		senderID:   senderID,
		protocolID: protocolID,
		sessionID:  sessionID,
	})
	if err != nil {
		t.Fatalf("cannot send crafted announcement: [%v]", err)
	}
}

// TestAnnouncer_SessionMismatchObserver verifies that the observer fires once
// per membership-valid, protocol-matched sender whose session ID differs from
// the local one, that identical session IDs do not fire it, and that the
// classified formats are correct (cross-format vs same-format).
func TestAnnouncer_SessionMismatchObserver(t *testing.T) {
	const protocolID = "announcer-mismatch-observer-protocol"
	const channelName = "announcer-mismatch-observer"

	provider, membershipValidator := newMismatchObserverFixture(t)

	receiverChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(receiverChannel)

	senderChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(senderChannel)

	recorder := &mismatchRecorder{}
	receiver := New(
		protocolID,
		receiverChannel,
		membershipValidator,
		WithSessionMismatchObserver(recorder.observer()),
	)

	// The local node runs the hardened DKG session ID.
	const receiverSessionID = "dkg-abc123-0000000000000001"

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*local.RetransmissionTick,
	)
	defer cancel()

	// Crafted announcements are scheduled with retransmission, so the receiver
	// catches them once its Recv handler is registered inside Announce.
	// member 2: legacy session ID -> cross-format mismatch
	sendAnnouncement(t, ctx, senderChannel, 2, protocolID, "abc123-5")
	// member 2 again with a different legacy ID -> deduplicated (same sender)
	sendAnnouncement(t, ctx, senderChannel, 2, protocolID, "abc123-6")
	// member 3: a different hardened DKG session ID -> same-format mismatch
	sendAnnouncement(t, ctx, senderChannel, 3, protocolID, "dkg-def456-0000000000000002")
	// member 4: identical session ID -> not a mismatch, must not fire
	sendAnnouncement(t, ctx, senderChannel, 4, protocolID, receiverSessionID)

	if _, err := receiver.Announce(ctx, 1, receiverSessionID); err != nil {
		t.Fatal(err)
	}

	records := recorder.snapshot()

	// Deduplicate to unique senders (already guaranteed by the announcer, but
	// assert it explicitly).
	bySender := make(map[group.MemberIndex]recordedMismatch)
	for _, r := range records {
		if existing, ok := bySender[r.sender]; ok {
			t.Errorf(
				"sender %d observed more than once (per-call dedup failed): %+v and %+v",
				r.sender, existing, r,
			)
		}
		bySender[r.sender] = r
	}

	if _, ok := bySender[4]; ok {
		t.Errorf("member 4 announced an identical session ID and must not be observed as a mismatch")
	}

	member2, ok := bySender[2]
	if !ok {
		t.Fatalf("expected member 2 (legacy) to be observed as a mismatch; records: %+v", records)
	}
	if member2.expected != SessionIDFormatHardenedDKG || member2.observed != SessionIDFormatLegacy {
		t.Errorf(
			"member 2 unexpected formats: expected=%v observed=%v",
			member2.expected, member2.observed,
		)
	}
	if !IsCrossFormatMismatch(member2.expected, member2.observed) {
		t.Errorf("member 2 should be a cross-format (legacy vs hardened) mismatch")
	}

	member3, ok := bySender[3]
	if !ok {
		t.Fatalf("expected member 3 (hardened) to be observed as a mismatch; records: %+v", records)
	}
	if member3.expected != SessionIDFormatHardenedDKG || member3.observed != SessionIDFormatHardenedDKG {
		t.Errorf(
			"member 3 unexpected formats: expected=%v observed=%v",
			member3.expected, member3.observed,
		)
	}
	if IsCrossFormatMismatch(member3.expected, member3.observed) {
		t.Errorf("member 3 should be a same-format mismatch, not cross-format")
	}

	if member2.protocolID != protocolID || member3.protocolID != protocolID {
		t.Errorf("observer received unexpected protocol ID")
	}
}

// TestAnnouncer_SessionMismatchObserver_Rejections verifies that the observer
// is NOT invoked for senders rejected by membership or protocol-ID validation,
// while a valid mismatching sender (positive control) IS observed — proving the
// rejections are real and not merely non-delivery.
func TestAnnouncer_SessionMismatchObserver_Rejections(t *testing.T) {
	const protocolID = "announcer-mismatch-rejections-protocol"
	const channelName = "announcer-mismatch-rejections"

	provider, membershipValidator := newMismatchObserverFixture(t)

	receiverChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(receiverChannel)

	senderChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(senderChannel)

	recorder := &mismatchRecorder{}
	receiver := New(
		protocolID,
		receiverChannel,
		membershipValidator,
		WithSessionMismatchObserver(recorder.observer()),
	)

	const receiverSessionID = "dkg-abc123-0000000000000001"

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*local.RetransmissionTick,
	)
	defer cancel()

	// member index 6 is out of the 5-member group -> membership invalid.
	sendAnnouncement(t, ctx, senderChannel, 6, protocolID, "abc123-5")
	// wrong protocol ID -> rejected before the mismatch check.
	sendAnnouncement(t, ctx, senderChannel, 3, "some-other-protocol", "abc123-5")
	// positive control: valid member, matching protocol, mismatching session ID.
	sendAnnouncement(t, ctx, senderChannel, 4, protocolID, "abc123-7")

	if _, err := receiver.Announce(ctx, 1, receiverSessionID); err != nil {
		t.Fatal(err)
	}

	records := recorder.snapshot()

	seen := make(map[group.MemberIndex]bool)
	for _, r := range records {
		seen[r.sender] = true
	}

	if seen[6] {
		t.Errorf("membership-invalid member 6 must not be observed")
	}
	if seen[3] {
		t.Errorf("protocol-mismatched member 3 must not be observed")
	}
	if !seen[4] {
		t.Fatalf(
			"positive control member 4 must be observed; the harness delivered nothing. records: %+v",
			records,
		)
	}
}

// TestAnnouncer_NilObserverCompatibility verifies that an announcer created
// without an observer (and one created with an explicit nil observer) still
// completes normally when it receives mismatching announcements.
func TestAnnouncer_NilObserverCompatibility(t *testing.T) {
	const protocolID = "announcer-nil-observer-protocol"
	const channelName = "announcer-nil-observer"

	provider, membershipValidator := newMismatchObserverFixture(t)

	receiverChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(receiverChannel)

	senderChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(senderChannel)

	// No observer option, plus an explicit nil observer, must both be safe.
	receiver := New(
		protocolID,
		receiverChannel,
		membershipValidator,
		WithSessionMismatchObserver(nil),
	)

	const receiverSessionID = "dkg-abc123-0000000000000001"

	ctx, cancel := context.WithTimeout(
		context.Background(),
		6*local.RetransmissionTick,
	)
	defer cancel()

	sendAnnouncement(t, ctx, senderChannel, 2, protocolID, "abc123-5")

	readyMembers, err := receiver.Announce(ctx, 1, receiverSessionID)
	if err != nil {
		t.Fatal(err)
	}

	// The only ready member is the receiver itself; the mismatching member 2 is
	// discarded and does not appear.
	if !reflect.DeepEqual(readyMembers, []group.MemberIndex{1}) {
		t.Errorf("unexpected ready members: %v", readyMembers)
	}
}

// TestAnnouncer_SessionMismatchObserver_RawIDsAbsent verifies that the observer
// carries only classified formats, never the raw session ID strings.
func TestAnnouncer_SessionMismatchObserver_RawIDsAbsent(t *testing.T) {
	const protocolID = "announcer-raw-ids-absent-protocol"
	const channelName = "announcer-raw-ids-absent"

	provider, membershipValidator := newMismatchObserverFixture(t)

	receiverChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(receiverChannel)

	senderChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		t.Fatal(err)
	}
	RegisterUnmarshaller(senderChannel)

	// A distinctive raw seed that must never surface in the observer output.
	const rawSeed = "cafebabedeadbeef"
	const observedSessionID = rawSeed + "-99"
	const receiverSessionID = "dkg-" + rawSeed + "-0000000000000001"

	recorder := &mismatchRecorder{}
	receiver := New(
		protocolID,
		receiverChannel,
		membershipValidator,
		WithSessionMismatchObserver(recorder.observer()),
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*local.RetransmissionTick,
	)
	defer cancel()

	sendAnnouncement(t, ctx, senderChannel, 2, protocolID, observedSessionID)

	if _, err := receiver.Announce(ctx, 1, receiverSessionID); err != nil {
		t.Fatal(err)
	}

	records := recorder.snapshot()
	if len(records) == 0 {
		t.Fatalf("expected the mismatch to be observed")
	}

	for _, r := range records {
		// The only strings the observer carries are the protocol ID and the
		// format Stringers; none may contain the raw seed component.
		fields := []string{
			r.protocolID,
			r.expected.String(),
			r.observed.String(),
		}
		for _, f := range fields {
			if strings.Contains(f, rawSeed) {
				t.Errorf("observer leaked raw session ID material in %q", f)
			}
		}
	}
}

func TestUnreadyMembers(t *testing.T) {
	tests := map[string]struct {
		readyMembers []group.MemberIndex
		groupSize    int
		expected     []group.MemberIndex
	}{
		"all members are ready": {
			readyMembers: []group.MemberIndex{1, 2, 3, 4, 5},
			groupSize:    5,
			expected:     []group.MemberIndex{},
		},
		"some members are not ready": {
			readyMembers: []group.MemberIndex{1, 3, 5},
			groupSize:    5,
			expected:     []group.MemberIndex{2, 4},
		},
		"no members are ready": {
			readyMembers: []group.MemberIndex{},
			groupSize:    5,
			expected:     []group.MemberIndex{1, 2, 3, 4, 5},
		},
		"group size is zero": {
			readyMembers: []group.MemberIndex{},
			groupSize:    0,
			expected:     []group.MemberIndex{},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			result := UnreadyMembers(test.readyMembers, test.groupSize)

			if !reflect.DeepEqual(test.expected, result) {
				t.Errorf(
					"unexpected result\nexpected: %v\nactual:   %v",
					test.expected,
					result,
				)
			}
		})
	}
}
