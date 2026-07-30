package registry

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/internal/testutils"

	"github.com/keep-network/keep-common/pkg/persistence"
)

// TestQuarantine_Preserve_AttemptsBothRecordsAndReportsWhatLanded proves
// neither half of a quarantine record is skipped because the other failed, and
// that the caller is told which of them the namespace actually holds.
//
// The two halves mean different things — the membership is the key material a
// rollback has to account for, the metadata is the record explaining it — and
// the error alone cannot say which one is on disk. A caller that guesses is how
// the operator log and the offline audit come to describe the same directory
// differently.
func TestQuarantine_Preserve_AttemptsBothRecordsAndReportsWhatLanded(
	t *testing.T,
) {
	membership := &Membership{Signer: signer1, ChannelName: channelName1}

	tests := map[string]struct {
		refusedNamePrefix   string
		expectedSaved       []string
		membershipPersisted bool
		metadataPersisted   bool
	}{
		"both records land": {
			refusedNamePrefix:   "/nothing_is_refused",
			expectedSaved:       []string{"/membership_1", "/metadata_1"},
			membershipPersisted: true,
			metadataPersisted:   true,
		},
		"the metadata is refused": {
			refusedNamePrefix:   "/metadata_",
			expectedSaved:       []string{"/membership_1"},
			membershipPersisted: true,
			metadataPersisted:   false,
		},
		"the membership is refused": {
			refusedNamePrefix:   "/membership_",
			expectedSaved:       []string{"/metadata_1"},
			membershipPersisted: false,
			metadataPersisted:   true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			handle := &unwritableRecordHandle{
				refusedNamePrefix: test.refusedNamePrefix,
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

			expectedComplete := test.membershipPersisted &&
				test.metadataPersisted
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

	namePrefix string
	refusals   int

	attempts int
}

func (h *flakyRecordHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	if !strings.HasPrefix(name, h.namePrefix) {
		return h.unwritableRecordHandle.Save(data, directory, name)
	}

	h.attempts++
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
			refusedNamePrefix: "/nothing_is_refused",
		},
		namePrefix: "/membership_",
		refusals:   refusals,
	}

	// The notification the node acts on fires once and does not end the
	// attempt, so it is counted rather than allowed to stand in for a result.
	notifications := 0

	state, err := newTestQuarantine(handle, refusals*2).Preserve(
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
			refusedNamePrefix: "/nothing_is_refused",
		},
		namePrefix: "/membership_",
		refusals:   math.MaxInt32,
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
			refusedNamePrefix: "/nothing_is_refused",
		},
		namePrefix: "/metadata_",
		refusals:   quarantineGraceAttempts + 2,
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

// unwritableRecordHandle is a protected namespace that refuses one record name
// while writing its neighbours, as a disk namespace does when a single file
// cannot be written.
type unwritableRecordHandle struct {
	// refusedNamePrefix names the record this namespace will not accept.
	refusedNamePrefix string

	savedNames []string
}

func (h *unwritableRecordHandle) Save(
	data []byte,
	directory string,
	name string,
) error {
	if strings.HasPrefix(name, h.refusedNamePrefix) {
		return fmt.Errorf("cannot write [%s]", name)
	}

	h.savedNames = append(h.savedNames, name)

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
