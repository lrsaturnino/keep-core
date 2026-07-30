package registry

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"

	"github.com/keep-network/keep-common/pkg/persistence"
)

// TestQuarantine_Preserve_AttemptsBothRecordsAndReportsWhatLanded proves no
// record of a quarantined output is skipped because another failed, and that
// the caller is told which of them the namespace actually holds.
//
// The records mean different things — the membership is the key material a
// rollback has to account for, the metadata is the record explaining it, the
// handoff is both at once — and the error alone cannot say which are on disk. A
// caller that guesses is how the operator log and the offline audit come to
// describe the same directory differently.
//
// A name the namespace refuses does not decide the outcome: a round that cannot
// complete the pair offers the output whole under a name of its own, so only a
// namespace refusing everything leaves a share with nowhere to go.
func TestQuarantine_Preserve_AttemptsBothRecordsAndReportsWhatLanded(
	t *testing.T,
) {
	membership := &Membership{Signer: signer1, ChannelName: channelName1}

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
			expectedSaved:     nil,
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
			quarantine := newTestQuarantine(handle, 1)

			state, err := quarantine.Preserve(
				membership,
				QuarantinedSignerMetadata{
					ReleaseEpoch: "security_v2_cutover",
					Ceremony:     "beacon_dkg",
				},
				nil,
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
				state.MembershipPersisted,
			)
			testutils.AssertBoolsEqual(
				t,
				"metadata persisted",
				test.metadataPersisted,
				state.MetadataPersisted,
			)
			testutils.AssertBoolsEqual(
				t,
				"handoff persisted",
				test.handoffPersisted,
				state.HandoffPersisted,
			)

			if !reflect.DeepEqual(handle.savedNames, test.expectedSaved) {
				t.Errorf(
					"namespace holds %v, expected %v",
					handle.savedNames,
					test.expectedSaved,
				)
			}
		})
	}
}

// flakyRecordHandle refuses the first refusals writes of the named record and
// accepts every write after that, counting the attempts made on it. It stands
// for a namespace that is unwritable for a while — a mount being restored, a
// disk an operator is draining — which is the condition a bounded write budget
// would report as permanently lost key material.
type flakyRecordHandle struct {
	unwritableRecordHandle

	// namePrefixes name the records this namespace refuses while it is
	// unwritable. The first of them is the one whose attempts are counted:
	// preservation writes it once per round for as long as it has not landed,
	// so its attempt number is the round number.
	namePrefixes []string
	refusals     int

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
		return h.unwritableRecordHandle.Save(data, directory, name)
	}

	if strings.HasPrefix(name, h.namePrefixes[0]) {
		h.attempts++
	}
	if h.attempts <= h.refusals {
		return fmt.Errorf("cannot write [%s] yet", name)
	}

	return h.unwritableRecordHandle.Save(data, directory, name)
}

// newTestQuarantine builds a quarantine store that retries exactly the way the
// production one does but ends its process lifetime after the given number of
// rounds instead of spending the real waits between them.
//
// Production preservation stops only with the process, because the key material
// it is holding cannot be generated again and no elapsed time makes discarding
// it safe. A test driving a namespace that never accepts the write therefore has
// to supply the ending itself: the round count is where this process is taken to
// have gone away.
func newTestQuarantine(
	handle persistence.ProtectedHandle,
	roundsBeforeShutdown int,
) *Quarantine {
	quarantine := NewQuarantine(
		context.Background(),
		&testutils.MockLogger{},
		handle,
	)

	rounds := 0
	quarantine.wait = func(context.Context, time.Duration) bool {
		rounds++
		return rounds < roundsBeforeShutdown
	}

	return quarantine
}

// TestQuarantine_Preserve_KeepsTryingThroughAProlongedRefusal proves key
// material is not declared lost because a namespace stayed unwritable for a
// while: preservation keeps the share in hand across far more refusals than a
// passing fault produces, and still writes it when the namespace comes back.
//
// A beacon share is worse to lose than most: the group it belongs to may already
// have an accepted result, so a member that cannot produce its share permanently
// reduces that group's usable threshold. The conditions that refuse a write are
// the ones an operator repairs, and a fixed attempt budget turns the length of
// that repair into the difference between a preserved share and a lost one.
func TestQuarantine_Preserve_KeepsTryingThroughAProlongedRefusal(t *testing.T) {
	const refusals = quarantineGraceAttempts * 8

	handle := &flakyRecordHandle{
		unwritableRecordHandle: unwritableRecordHandle{
			refusedNamePrefixes: []string{"/nothing_is_refused"},
		},
		// The handoff is refused for as long as the membership, so what is being
		// held across the repair is the key material itself and not a record
		// that already put it somewhere.
		namePrefixes: []string{"/membership_", "/handoff_"},
		refusals:     refusals,
	}

	// The notification the node acts on fires once and does not end the
	// attempt, so it is counted rather than allowed to stand in for a result.
	notifications := 0

	quarantine := newTestQuarantine(handle, refusals*2)

	operatorLog := &warningCapture{}
	quarantine.logger = operatorLog

	state, err := quarantine.Preserve(
		&Membership{Signer: signer1, ChannelName: channelName1},
		QuarantinedSignerMetadata{
			ReleaseEpoch: "security_v2_cutover",
			Ceremony:     "beacon_dkg",
		},
		func(QuarantineState, error) { notifications++ },
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
		state.MembershipPersisted,
	)
	testutils.AssertIntsEqual(
		t,
		"membership write attempts",
		refusals+1,
		handle.attempts,
	)
	testutils.AssertIntsEqual(t, "block notifications", 1, notifications)

	if !reflect.DeepEqual(
		handle.savedNames,
		[]string{"/metadata_1", "/membership_1"},
	) {
		t.Errorf(
			"namespace holds %v, expected both halves",
			handle.savedNames,
		)
	}

	// The node was told, and the operator record says, that this share reached
	// no namespace. Leaving that as the last word would have an operator repair
	// a loss the namespace had already stopped being.
	if logged := operatorLog.joined(); !strings.Contains(
		logged,
		"took the beacon key material it had been refusing",
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

// TestQuarantine_Preserve_GivesUpOnlyWhenTheProcessEnds proves the retry has no
// deadline of its own: a namespace that never accepts the write is attempted
// every round until the process itself goes away, and the error says that is
// what ended it.
//
// The node is told once, well before that, that it is holding key material the
// namespace does not have — but being told is not the same as being finished,
// and preservation carries on behind the notification.
func TestQuarantine_Preserve_GivesUpOnlyWhenTheProcessEnds(t *testing.T) {
	const roundsBeforeShutdown = quarantineGraceAttempts * 9

	handle := &flakyRecordHandle{
		unwritableRecordHandle: unwritableRecordHandle{
			refusedNamePrefixes: []string{"/nothing_is_refused"},
		},
		namePrefixes: []string{"/membership_", "/handoff_"},
		refusals:     math.MaxInt32,
	}

	notifications := 0

	state, err := newTestQuarantine(handle, roundsBeforeShutdown).Preserve(
		&Membership{Signer: signer1, ChannelName: channelName1},
		QuarantinedSignerMetadata{
			ReleaseEpoch: "security_v2_cutover",
			Ceremony:     "beacon_dkg",
		},
		func(QuarantineState, error) { notifications++ },
	)
	if err == nil {
		t.Fatal("expected a preservation error")
	}

	testutils.AssertBoolsEqual(
		t,
		"membership persisted",
		false,
		state.MembershipPersisted,
	)
	testutils.AssertBoolsEqual(
		t,
		"metadata persisted",
		true,
		state.MetadataPersisted,
	)
	testutils.AssertBoolsEqual(
		t,
		"handoff persisted",
		false,
		state.HandoffPersisted,
	)
	testutils.AssertIntsEqual(
		t,
		"membership write attempts",
		roundsBeforeShutdown,
		handle.attempts,
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

// TestQuarantine_Preserve_WritesOnlyTheHalfTheNamespaceLacks proves a round does
// not rewrite a half that already landed. The retry exists for the missing
// record, and rewriting the preserved one would keep touching key material the
// namespace has already accepted.
func TestQuarantine_Preserve_WritesOnlyTheHalfTheNamespaceLacks(t *testing.T) {
	handle := &flakyRecordHandle{
		unwritableRecordHandle: unwritableRecordHandle{
			refusedNamePrefixes: []string{"/nothing_is_refused"},
		},
		// The handoff is refused for as long as the metadata, so what the retry
		// is waiting on is the pair itself.
		namePrefixes: []string{"/metadata_", "/handoff_"},
		refusals:     quarantineGraceAttempts + 2,
	}

	if _, err := newTestQuarantine(handle, 50).Preserve(
		&Membership{Signer: signer1, ChannelName: channelName1},
		QuarantinedSignerMetadata{
			ReleaseEpoch: "security_v2_cutover",
			Ceremony:     "beacon_dkg",
		},
		nil,
	); err != nil {
		t.Fatalf(
			"expected the retried write to preserve the share, got [%v]",
			err,
		)
	}

	if !reflect.DeepEqual(
		handle.savedNames,
		[]string{"/membership_1", "/metadata_1"},
	) {
		t.Errorf(
			"namespace holds %v, expected each half written exactly once",
			handle.savedNames,
		)
	}
}

// TestQuarantine_Preserve_RecoversAWholeOutputTheNamespaceWouldNotPair proves
// what a later process recovers when the namespace refuses the key material's
// own record for good: the combined handoff carries the share and everything
// that explains it, and both read back.
//
// This is the state that used to cost a node a share. The membership record is
// where preservation prefers to put the material, the metadata beside it is only
// the explanation, and a namespace that took the second while refusing the first
// left a note about a share that reached no disk. A beacon share is the worse
// one to lose: its group may already have an accepted result, and a member that
// cannot produce its share permanently reduces that group's usable threshold.
//
// The handoff is one write carrying both, so the output survives under a name
// the namespace will take, and what comes next can read back the material, the
// group and seat it belongs to, and the mode, canonical anchor, ceremony, and
// refused operation the offline audit reconciles against the chain.
func TestQuarantine_Preserve_RecoversAWholeOutputTheNamespaceWouldNotPair(
	t *testing.T,
) {
	// The combined record is taken only well after the grace rounds are spent,
	// so the node has already been told it is holding a share nothing has by the
	// time the namespace comes back.
	const handoffTakenAtRound = quarantineGraceAttempts * 2

	handle := &latchedHandoffHandle{handoffTakenAtRound: handoffTakenAtRound}

	state, err := newTestQuarantine(handle, handoffTakenAtRound+1).Preserve(
		&Membership{Signer: signer1, ChannelName: channelName1},
		QuarantinedSignerMetadata{
			ReleaseEpoch:        "security_v2_cutover",
			ProtocolMode:        "security_v2",
			CanonicalStartBlock: 4321,
			Ceremony:            "beacon_dkg",
			FailedOperation:     "beacon_dkg_result_publication",
		},
		nil,
	)
	if err != nil {
		t.Fatalf("expected the output to be preserved whole, got [%v]", err)
	}

	testutils.AssertBoolsEqual(
		t,
		"membership persisted",
		false,
		state.MembershipPersisted,
	)
	testutils.AssertBoolsEqual(
		t,
		"handoff persisted",
		true,
		state.HandoffPersisted,
	)
	testutils.AssertBoolsEqual(
		t,
		"the output is preserved whole",
		true,
		state.Complete(),
	)

	if !reflect.DeepEqual(
		handle.savedNames,
		[]string{"/metadata_1", "/handoff_1"},
	) {
		t.Fatalf(
			"namespace holds %v, expected the output preserved whole",
			handle.savedNames,
		)
	}

	// Counting a record is not the same as being able to use it. The next
	// process reads the preserved output the way the offline audit does, and has
	// to find the group and seat the material belongs to.
	handoff, err := DecodeQuarantinedSignerHandoff(
		handle.savedContent["/handoff_1"],
	)
	if err != nil {
		t.Fatalf("the preserved output cannot be read back: [%v]", err)
	}

	preserved := &Membership{}
	if err := preserved.Unmarshal(handoff.Membership); err != nil {
		t.Fatalf("the preserved key material cannot be read back: [%v]", err)
	}

	if got, expected := preserved.Signer.MemberID(),
		signer1.MemberID(); got != expected {
		t.Errorf(
			"preserved material was generated for seat [%v], expected [%v]",
			got,
			expected,
		)
	}
	if got, expected := preserved.Signer.GroupPublicKeyBytesCompressed(),
		signer1.GroupPublicKeyBytesCompressed(); !reflect.DeepEqual(
		got,
		expected,
	) {
		t.Errorf(
			"preserved material belongs to group [%x], expected [%x]",
			got,
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
		"security_v2",
		metadata.ProtocolMode,
	)
	testutils.AssertUintsEqual(
		t,
		"canonical anchor the preserved output was generated under",
		4321,
		metadata.CanonicalStartBlock,
	)
	testutils.AssertStringsEqual(
		t,
		"ceremony the preserved output was generated in",
		"beacon_dkg",
		metadata.Ceremony,
	)
	testutils.AssertStringsEqual(
		t,
		"operation that was refused",
		"beacon_dkg_result_publication",
		metadata.FailedOperation,
	)
	testutils.AssertStringsEqual(
		t,
		"group the preserved output belongs to",
		hex.EncodeToString(signer1.GroupPublicKeyBytesCompressed()),
		metadata.GroupPublicKey,
	)
}

// latchedHandoffHandle refuses the record carrying key material for good and
// takes the combined handoff only from the given round, as a namespace does when
// one particular file cannot be written and the rest of the directory is
// part-way through an operator's repair.
type latchedHandoffHandle struct {
	unwritableRecordHandle

	// handoffTakenAtRound is the round from which the combined record is
	// accepted. The membership is attempted once per round for as long as it has
	// not landed, and it never lands here, so its attempt count is the round
	// number.
	handoffTakenAtRound int

	membershipAttempts int
}

func (h *latchedHandoffHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	if strings.HasPrefix(name, "/membership_") {
		h.membershipAttempts++
		return fmt.Errorf("cannot write [%s]", name)
	}

	if strings.HasPrefix(name, "/handoff_") &&
		h.membershipAttempts < h.handoffTakenAtRound {
		return fmt.Errorf("cannot write [%s] yet", name)
	}

	return h.unwritableRecordHandle.Save(data, directory, name)
}

// warningCapture records the warning lines a preservation emits, so a test can
// hold the operator's account of a preserved output to what the namespace
// actually holds. That account is the only description of a quarantine an
// operator reads at the time it matters.
type warningCapture struct {
	testutils.MockLogger

	warnings []string
}

func (c *warningCapture) Warnf(format string, args ...interface{}) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

func (c *warningCapture) joined() string {
	return strings.Join(c.warnings, "\n")
}

// unwritableRecordHandle is a protected namespace that refuses the record names
// it is given while writing their neighbours, as a disk namespace does when
// particular files cannot be written.
//
// The names are a list because a preserved output is offered under more than
// one of them: refusing the record pair and refusing the output are different
// namespaces, and only the second one costs the node a share.
type unwritableRecordHandle struct {
	// refusedNamePrefixes name the records this namespace will not accept.
	refusedNamePrefixes []string

	savedNames []string

	// savedContent keeps what each accepted record holds, so a test can read a
	// preserved record back the way a later process would rather than only
	// observe that a write happened.
	savedContent map[string][]byte
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

	h.savedNames = append(h.savedNames, name)

	if h.savedContent == nil {
		h.savedContent = make(map[string][]byte)
	}
	h.savedContent[name] = append([]byte(nil), data...)

	return nil
}

func (h *unwritableRecordHandle) Snapshot(
	data []byte,
	directory string,
	name string,
) error {
	panic("not implemented")
}

func (h *unwritableRecordHandle) ReadAll() (
	<-chan persistence.DataDescriptor,
	<-chan error,
) {
	panic("not implemented")
}

func (h *unwritableRecordHandle) Archive(directory string) error {
	panic("not implemented")
}
