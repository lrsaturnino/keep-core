package ethereum

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
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

// TestRelayEntryTimeoutSettlement asserts the reading a filed timeout report is
// claimed as a penalty on.
//
// The monitor's permit closes as completed on whatever this returns, and that
// record clears the rollback barrier the penalty exists to hold. So the
// endings a request can actually have are enumerated here rather than left to
// the one path a passing case exercises: the report was accepted, the report
// never landed, the group delivered late, the delivery itself was reorged away,
// and the termination was.
func TestRelayEntryTimeoutSettlement(t *testing.T) {
	const contractAddress = "0x1111111111111111111111111111111111111111"
	const terminatedGroupID = uint64(4)
	const requestBlock = uint64(1_000)
	const timeoutBlock = uint64(1_100)

	requestID := big.NewInt(77)
	previousEntry := []byte("previous-entry-of-the-reported-request")
	timeoutTransaction := common.HexToHash("0xabc")

	request := &abi.RandomBeaconRelayEntryRequested{
		RequestId:     requestID,
		GroupId:       1,
		PreviousEntry: previousEntry,
		Raw:           types.Log{BlockNumber: requestBlock},
	}

	submission := func(removed bool) *abi.RandomBeaconRelayEntrySubmitted {
		return &abi.RandomBeaconRelayEntrySubmitted{
			RequestId: requestID,
			Entry:     []byte("the group's answer"),
			Raw:       types.Log{BlockNumber: timeoutBlock, Removed: removed},
		}
	}
	timeout := func(
		removed bool,
		groupID uint64,
	) *abi.RandomBeaconRelayEntryTimedOut {
		return &abi.RandomBeaconRelayEntryTimedOut{
			RequestId:         requestID,
			TerminatedGroupId: groupID,
			Raw: types.Log{
				BlockNumber: timeoutBlock,
				TxHash:      timeoutTransaction,
				Removed:     removed,
			},
		}
	}

	tests := map[string]struct {
		submissions      []*abi.RandomBeaconRelayEntrySubmitted
		timeouts         []*abi.RandomBeaconRelayEntryTimedOut
		expectSettlement bool
		expectError      bool
		expectedGroupID  uint64
	}{
		"the report was accepted": {
			timeouts:         []*abi.RandomBeaconRelayEntryTimedOut{timeout(false, terminatedGroupID)},
			expectSettlement: true,
			expectedGroupID:  terminatedGroupID,
		},
		// The report reverted, was dropped, or lost the race to another
		// reporter: the beacon is exactly as it was and no penalty was earned.
		"no termination was recorded": {},
		// The group answered after the report was filed. A delivered entry and
		// a timeout are mutually exclusive endings, so the delivery ends the
		// claim before the timeout logs are even weighed.
		"the group delivered late": {
			submissions: []*abi.RandomBeaconRelayEntrySubmitted{submission(false)},
			timeouts:    []*abi.RandomBeaconRelayEntryTimedOut{timeout(false, terminatedGroupID)},
		},
		"the group delivered and no termination followed": {
			submissions: []*abi.RandomBeaconRelayEntrySubmitted{submission(false)},
		},
		// The branch carrying the delivery was abandoned, so it answers
		// nothing and the live termination stands.
		"the delivery was reorged out": {
			submissions:      []*abi.RandomBeaconRelayEntrySubmitted{submission(true)},
			timeouts:         []*abi.RandomBeaconRelayEntryTimedOut{timeout(false, terminatedGroupID)},
			expectSettlement: true,
			expectedGroupID:  terminatedGroupID,
		},
		// The mirror case: the termination is the log the chain abandoned, so
		// the penalty went with it.
		"the termination was reorged out": {
			timeouts: []*abi.RandomBeaconRelayEntryTimedOut{timeout(true, terminatedGroupID)},
		},
		"a termination re-mined after being reorged out": {
			timeouts: []*abi.RandomBeaconRelayEntryTimedOut{
				timeout(true, terminatedGroupID+1),
				timeout(false, terminatedGroupID),
			},
			expectSettlement: true,
			expectedGroupID:  terminatedGroupID,
		},
		// Nothing says which group the settlement should name, and picking
		// either would rest a penalty on an ordering the chain never promised.
		"two live terminations": {
			timeouts: []*abi.RandomBeaconRelayEntryTimedOut{
				timeout(false, terminatedGroupID),
				timeout(false, terminatedGroupID+1),
			},
			expectError: true,
		},
		"a live delivery among reorged ones": {
			submissions: []*abi.RandomBeaconRelayEntrySubmitted{
				submission(true),
				submission(false),
			},
			timeouts: []*abi.RandomBeaconRelayEntryTimedOut{timeout(false, terminatedGroupID)},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			settlement, err := relayEntryTimeoutSettlement(
				request,
				test.submissions,
				test.timeouts,
				contractAddress,
			)

			if test.expectError {
				if err == nil {
					t.Fatal("expected an ambiguous reading to be refused")
				}
				if settlement != nil {
					t.Error("a refused reading must claim no settlement")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: [%v]", err)
			}

			if !test.expectSettlement {
				if settlement != nil {
					t.Fatalf(
						"expected no penalty to be claimed, got group [%d]",
						settlement.TerminatedGroupID,
					)
				}
				return
			}
			if settlement == nil {
				t.Fatal("expected an accepted report to be claimed as settled")
			}

			if settlement.RequestID.Cmp(requestID) != 0 {
				t.Errorf(
					"unexpected request identifier\nexpected: [%s]\nactual:   [%s]",
					requestID,
					settlement.RequestID,
				)
			}
			if settlement.TerminatedGroupID != test.expectedGroupID {
				t.Errorf(
					"unexpected terminated group\nexpected: [%d]\nactual:   [%d]",
					test.expectedGroupID,
					settlement.TerminatedGroupID,
				)
			}
			if settlement.RequestBlockNumber != requestBlock {
				t.Errorf(
					"unexpected request block\nexpected: [%d]\nactual:   [%d]",
					requestBlock,
					settlement.RequestBlockNumber,
				)
			}
			if !bytes.Equal(settlement.RequestPreviousEntry, previousEntry) {
				t.Error("the settlement names another request's previous entry")
			}
			if settlement.BlockNumber != timeoutBlock {
				t.Errorf(
					"unexpected settlement block\nexpected: [%d]\nactual:   [%d]",
					timeoutBlock,
					settlement.BlockNumber,
				)
			}
			if settlement.TransactionHash != timeoutTransaction {
				t.Error("the settlement names another transaction")
			}
			if settlement.ContractAddress != contractAddress {
				t.Errorf(
					"unexpected contract\nexpected: [%s]\nactual:   [%s]",
					contractAddress,
					settlement.ContractAddress,
				)
			}
		})
	}
}

// TestRelayEntryTimeoutSettlement_DoesNotAliasTheRequestLog asserts the
// settlement carries its own copy of the previous entry the request signs over.
//
// The record outlives the log slice the caller read it from, and a settlement
// that aliased that memory would name whatever a later read wrote over it.
func TestRelayEntryTimeoutSettlement_DoesNotAliasTheRequestLog(t *testing.T) {
	previousEntry := []byte("previous-entry-of-the-reported-request")
	request := &abi.RandomBeaconRelayEntryRequested{
		RequestId:     big.NewInt(77),
		PreviousEntry: previousEntry,
		Raw:           types.Log{BlockNumber: 1_000},
	}

	settlement, err := relayEntryTimeoutSettlement(
		request,
		nil,
		[]*abi.RandomBeaconRelayEntryTimedOut{
			{
				RequestId:         request.RequestId,
				TerminatedGroupId: 4,
				Raw:               types.Log{BlockNumber: 1_100},
			},
		},
		"0x1111111111111111111111111111111111111111",
	)
	if err != nil {
		t.Fatal(err)
	}
	if settlement == nil {
		t.Fatal("expected an accepted report to be claimed as settled")
	}

	for i := range previousEntry {
		previousEntry[i] = 0
	}
	if bytes.Equal(settlement.RequestPreviousEntry, previousEntry) {
		t.Error("the settlement aliases the request log's previous entry")
	}

	request.RequestId.SetInt64(0)
	if settlement.RequestID.Sign() == 0 {
		t.Error("the settlement aliases the request log's identifier")
	}
}
