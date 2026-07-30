package registry

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

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
