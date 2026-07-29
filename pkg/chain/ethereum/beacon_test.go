package ethereum

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/keep-network/keep-core/pkg/chain/ethereum/beacon/gen/abi"
)

// TestSoleCanonicalLog_SkipsOrphanedBranches asserts the selection a relay
// entry timeout settlement is assembled from ignores logs the backend marked as
// removed and refuses to choose between two live matches.
//
// The removed flag is what a reorg leaves behind on a log that no longer
// belongs to the canonical chain. A settlement built on one would claim a
// penalty over state the chain has already abandoned, which is precisely the
// claim this lookup exists to prevent.
func TestSoleCanonicalLog_SkipsOrphanedBranches(t *testing.T) {
	previousEntry := []byte("previous-entry-of-the-reported-request")
	otherPreviousEntry := []byte("previous-entry-after-a-delivered-entry")

	requestLog := func(
		removed bool,
		entry []byte,
	) *abi.RandomBeaconRelayEntryRequested {
		return &abi.RandomBeaconRelayEntryRequested{
			PreviousEntry: entry,
			Raw:           types.Log{Removed: removed},
		}
	}

	tests := map[string]struct {
		requests          []*abi.RandomBeaconRelayEntryRequested
		expectedIndex     int
		expectedAmbiguous bool
	}{
		"no requests at all": {
			requests:      nil,
			expectedIndex: -1,
		},
		"one live request over the named previous entry": {
			requests: []*abi.RandomBeaconRelayEntryRequested{
				requestLog(false, previousEntry),
			},
			expectedIndex: 0,
		},
		// The reorg case: the only log naming the request belongs to an
		// orphaned branch, so the canonical chain holds no such request.
		"the only matching request was reorged out": {
			requests: []*abi.RandomBeaconRelayEntryRequested{
				requestLog(true, previousEntry),
			},
			expectedIndex: -1,
		},
		// The same request re-mined on the new branch after the orphaned one.
		// The live log is the canonical answer and the removed one must not
		// make the pair look ambiguous.
		"a request re-mined after being reorged out": {
			requests: []*abi.RandomBeaconRelayEntryRequested{
				requestLog(true, previousEntry),
				requestLog(false, previousEntry),
			},
			expectedIndex: 1,
		},
		"another request in the same block": {
			requests: []*abi.RandomBeaconRelayEntryRequested{
				requestLog(false, otherPreviousEntry),
				requestLog(false, previousEntry),
			},
			expectedIndex: 1,
		},
		"two live requests over the named previous entry": {
			requests: []*abi.RandomBeaconRelayEntryRequested{
				requestLog(false, previousEntry),
				requestLog(false, previousEntry),
			},
			expectedIndex:     -1,
			expectedAmbiguous: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			requests := test.requests

			index, ambiguous := soleCanonicalLog(
				len(requests),
				func(i int) bool {
					return !requests[i].Raw.Removed &&
						bytes.Equal(requests[i].PreviousEntry, previousEntry)
				},
			)

			if index != test.expectedIndex {
				t.Errorf(
					"unexpected log index\nexpected: [%d]\nactual:   [%d]",
					test.expectedIndex,
					index,
				)
			}
			if ambiguous != test.expectedAmbiguous {
				t.Errorf(
					"unexpected ambiguity\nexpected: [%t]\nactual:   [%t]",
					test.expectedAmbiguous,
					ambiguous,
				)
			}
		})
	}
}
