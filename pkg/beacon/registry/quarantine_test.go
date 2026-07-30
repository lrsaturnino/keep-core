package registry

import (
	"fmt"
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
			quarantine := NewQuarantine(&testutils.MockLogger{}, handle)

			state, err := quarantine.Preserve(
				membership,
				QuarantinedSignerMetadata{
					ReleaseEpoch: "security_v2_cutover",
					Ceremony:     "beacon_dkg",
				},
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
// for a namespace that is momentarily unwritable — a mount being restored, a
// disk an operator is draining — which is the condition a single-attempt write
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
// production one does but does not spend the wait between attempts, so a test
// can exercise the whole budget without sleeping through it.
func newTestQuarantine(handle persistence.ProtectedHandle) *Quarantine {
	quarantine := NewQuarantine(&testutils.MockLogger{}, handle)
	quarantine.sleep = func(time.Duration) {}

	return quarantine
}

// TestQuarantine_Preserve_RetriesARefusedWrite proves key material is not
// declared lost on the first refusal: a namespace that accepts the write on a
// later attempt still preserves the share, and the caller is told it landed.
//
// A beacon share is worse to lose than most: the group it belongs to may already
// have an accepted result, so a member that cannot produce its share permanently
// reduces that group's usable threshold. The conditions that refuse a write are
// usually the ones that clear, and concluding permanent loss from one attempt
// throws away a share the very next write would have kept.
func TestQuarantine_Preserve_RetriesARefusedWrite(t *testing.T) {
	handle := &flakyRecordHandle{
		unwritableRecordHandle: unwritableRecordHandle{
			refusedNamePrefix: "/nothing_is_refused",
		},
		namePrefix: "/membership_",
		refusals:   quarantineSaveAttempts - 1,
	}

	state, err := newTestQuarantine(handle).Preserve(
		&Membership{Signer: signer1, ChannelName: channelName1},
		QuarantinedSignerMetadata{
			ReleaseEpoch: "security_v2_cutover",
			Ceremony:     "beacon_dkg",
		},
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
		quarantineSaveAttempts,
		handle.attempts,
	)

	if !reflect.DeepEqual(
		handle.savedNames,
		[]string{"/membership_1", "/metadata_1"},
	) {
		t.Errorf(
			"namespace holds %v, expected both halves",
			handle.savedNames,
		)
	}
}

// TestQuarantine_Preserve_SpendsTheWholeBudgetBeforeReportingLoss proves a
// namespace that refuses every attempt is retried for the whole budget before
// the loss stands, and that the error says how many attempts were spent — the
// difference between one unlucky write and a namespace that will not take the
// share at all.
func TestQuarantine_Preserve_SpendsTheWholeBudgetBeforeReportingLoss(
	t *testing.T,
) {
	handle := &flakyRecordHandle{
		unwritableRecordHandle: unwritableRecordHandle{
			refusedNamePrefix: "/nothing_is_refused",
		},
		namePrefix: "/membership_",
		refusals:   quarantineSaveAttempts + 1,
	}

	state, err := newTestQuarantine(handle).Preserve(
		&Membership{Signer: signer1, ChannelName: channelName1},
		QuarantinedSignerMetadata{
			ReleaseEpoch: "security_v2_cutover",
			Ceremony:     "beacon_dkg",
		},
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
	testutils.AssertIntsEqual(
		t,
		"membership write attempts",
		quarantineSaveAttempts,
		handle.attempts,
	)
	if want := fmt.Sprintf(
		"in %d attempts",
		quarantineSaveAttempts,
	); !strings.Contains(err.Error(), want) {
		t.Errorf(
			"the error must say the whole budget was spent, got [%v]",
			err,
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
