package ethereum

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
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

// relayEntryChainView is one branch of the chain as a backend would serve it:
// the head it reports, the hash it holds at each height, and the logs it
// returns for each of the three reads a settlement is composed from.
type relayEntryChainView struct {
	head        uint64
	blockHashes map[uint64]common.Hash
	requests    []*abi.RandomBeaconRelayEntryRequested
	submissions []*abi.RandomBeaconRelayEntrySubmitted
	timeouts    []*abi.RandomBeaconRelayEntryTimedOut
}

// relayEntryLogRead records the bounds one read was made with, so a test can
// assert the three reads were bounded by one view instead of each running
// against whatever the head happened to be.
type relayEntryLogRead struct {
	name       string
	startBlock uint64
	endBlock   uint64
	requestID  *big.Int
}

// scriptedRelayEntryLogs is a backend whose chain view moves from one branch to
// another part-way through the reads a settlement is composed from.
//
// A reorg is not something a settlement can be tested against by handing it
// pre-composed log slices: the whole question is what happens when the reads
// disagree about which branch they answer, and that only exists between the
// calls. Switching the served branch at a named read reproduces it exactly.
type scriptedRelayEntryLogs struct {
	before relayEntryChainView
	after  relayEntryChainView

	// reorgBefore names the read the view moves to the second branch at: one
	// of "requests", "submissions", "timeouts", or "confirm" for the re-read
	// of the end block once the log reads are done.
	reorgBefore string

	// blockHashErrors holds the heights the backend cannot answer a hash for.
	blockHashErrors map[uint64]error

	reorged      bool
	timeoutsRead bool
	pinnedHead   uint64
	reads        []relayEntryLogRead
}

func (srel *scriptedRelayEntryLogs) view() *relayEntryChainView {
	if srel.reorged {
		return &srel.after
	}

	return &srel.before
}

func (srel *scriptedRelayEntryLogs) reorgAt(read string) {
	if srel.reorgBefore == read {
		srel.reorged = true
	}
}

func (srel *scriptedRelayEntryLogs) CurrentBlock() (uint64, error) {
	srel.pinnedHead = srel.view().head
	return srel.pinnedHead, nil
}

func (srel *scriptedRelayEntryLogs) BlockHashByNumber(blockNumber uint64) (
	[32]byte,
	error,
) {
	// The confirming read is the one that asks for the pinned head again after
	// all the logs are in hand.
	if srel.timeoutsRead && blockNumber == srel.pinnedHead {
		srel.reorgAt("confirm")
	}

	if err, failing := srel.blockHashErrors[blockNumber]; failing {
		return [32]byte{}, err
	}

	blockHash, held := srel.view().blockHashes[blockNumber]
	if !held {
		return [32]byte{}, fmt.Errorf("the view holds no block [%v]", blockNumber)
	}

	return blockHash, nil
}

func (srel *scriptedRelayEntryLogs) RelayEntryRequests(
	startBlock, endBlock uint64,
) ([]*abi.RandomBeaconRelayEntryRequested, error) {
	srel.reorgAt("requests")
	srel.reads = append(
		srel.reads,
		relayEntryLogRead{"requests", startBlock, endBlock, nil},
	)

	return srel.view().requests, nil
}

func (srel *scriptedRelayEntryLogs) RelayEntrySubmissions(
	startBlock, endBlock uint64,
	requestID *big.Int,
) ([]*abi.RandomBeaconRelayEntrySubmitted, error) {
	srel.reorgAt("submissions")
	srel.reads = append(
		srel.reads,
		relayEntryLogRead{"submissions", startBlock, endBlock, requestID},
	)

	return srel.view().submissions, nil
}

func (srel *scriptedRelayEntryLogs) RelayEntryTimeouts(
	startBlock, endBlock uint64,
	requestID *big.Int,
) ([]*abi.RandomBeaconRelayEntryTimedOut, error) {
	srel.reorgAt("timeouts")
	srel.reads = append(
		srel.reads,
		relayEntryLogRead{"timeouts", startBlock, endBlock, requestID},
	)
	srel.timeoutsRead = true

	return srel.view().timeouts, nil
}

// TestResolveRelayEntryTimeoutSettlement asserts the three reads a relay entry
// timeout settlement is composed from answer one view of the chain.
//
// The request, the entry submissions and the terminations are three separate
// backend calls, and a reorg between any two of them can hand back a request
// from one branch and the same request ID's termination from another. That
// pairing was never held by any canonical view of the chain, and a penalty
// claimed on it would be a penalty for something that did not happen. So each
// seam a branch can move at is exercised here, along with the readings that
// must survive one: a log the view has abandoned closes nothing, and a delivery
// whose block cannot be checked stops the claim rather than being dropped from
// it.
func TestResolveRelayEntryTimeoutSettlement(t *testing.T) {
	const contractAddress = "0x1111111111111111111111111111111111111111"
	const requestBlock = uint64(1_000)
	const submissionBlock = uint64(1_050)
	const timeoutBlock = uint64(1_100)
	const head = uint64(2_000)
	const groupOnFirstBranch = uint64(4)
	const groupOnSecondBranch = uint64(9)

	requestID := big.NewInt(77)
	previousEntry := []byte("previous-entry-of-the-reported-request")

	// Both branches carry the same request ID at the same heights. That is what
	// makes a cross-branch composition look coherent to everything except the
	// branch check itself.
	branchHash := func(branch string, blockNumber uint64) common.Hash {
		return common.HexToHash(fmt.Sprintf("0x%s%d", branch, blockNumber))
	}
	branchHashes := func(branch string) map[uint64]common.Hash {
		return map[uint64]common.Hash{
			requestBlock:    branchHash(branch, requestBlock),
			submissionBlock: branchHash(branch, submissionBlock),
			timeoutBlock:    branchHash(branch, timeoutBlock),
			head:            branchHash(branch, head),
		}
	}
	request := func(branch string) *abi.RandomBeaconRelayEntryRequested {
		return &abi.RandomBeaconRelayEntryRequested{
			RequestId:     new(big.Int).Set(requestID),
			GroupId:       1,
			PreviousEntry: previousEntry,
			Raw: types.Log{
				BlockNumber: requestBlock,
				BlockHash:   branchHash(branch, requestBlock),
			},
		}
	}
	submission := func(branch string) *abi.RandomBeaconRelayEntrySubmitted {
		return &abi.RandomBeaconRelayEntrySubmitted{
			RequestId: new(big.Int).Set(requestID),
			Entry:     []byte("the group's answer"),
			Raw: types.Log{
				BlockNumber: submissionBlock,
				BlockHash:   branchHash(branch, submissionBlock),
			},
		}
	}
	timeout := func(
		branch string,
		groupID uint64,
	) *abi.RandomBeaconRelayEntryTimedOut {
		return &abi.RandomBeaconRelayEntryTimedOut{
			RequestId:         new(big.Int).Set(requestID),
			TerminatedGroupId: groupID,
			Raw: types.Log{
				BlockNumber: timeoutBlock,
				BlockHash:   branchHash(branch, timeoutBlock),
			},
		}
	}

	// The branch the request was made on, terminated by an accepted report.
	firstBranch := func() relayEntryChainView {
		return relayEntryChainView{
			head:        head,
			blockHashes: branchHashes("a"),
			requests: []*abi.RandomBeaconRelayEntryRequested{
				request("a"),
			},
			timeouts: []*abi.RandomBeaconRelayEntryTimedOut{
				timeout("a", groupOnFirstBranch),
			},
		}
	}
	// The branch that replaces it: the same request, terminated against another
	// group. Composed with the first branch's request it reads as a settlement.
	secondBranch := func() relayEntryChainView {
		return relayEntryChainView{
			head:        head,
			blockHashes: branchHashes("b"),
			requests: []*abi.RandomBeaconRelayEntryRequested{
				request("b"),
			},
			timeouts: []*abi.RandomBeaconRelayEntryTimedOut{
				timeout("b", groupOnSecondBranch),
			},
		}
	}

	tests := map[string]struct {
		logs             *scriptedRelayEntryLogs
		expectSettlement bool
		expectError      bool
		expectedGroupID  uint64
		expectedReads    []string
	}{
		"one view holds the request and its termination": {
			logs: &scriptedRelayEntryLogs{
				before: firstBranch(),
			},
			expectSettlement: true,
			expectedGroupID:  groupOnFirstBranch,
			expectedReads:    []string{"requests", "submissions", "timeouts"},
		},
		// The reorg lands between the request read and the termination read, so
		// the composition would pair a request this view no longer holds with a
		// termination the request read never saw.
		"the view moves between the request and the termination reads": {
			logs: &scriptedRelayEntryLogs{
				before:      firstBranch(),
				after:       secondBranch(),
				reorgBefore: "timeouts",
			},
			expectError:   true,
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
		"the view moves between the request and the delivery reads": {
			logs: &scriptedRelayEntryLogs{
				before: firstBranch(),
				after: func() relayEntryChainView {
					view := secondBranch()
					view.submissions = []*abi.RandomBeaconRelayEntrySubmitted{
						submission("b"),
					}
					return view
				}(),
				reorgBefore: "submissions",
			},
			expectError:   true,
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
		// Every read answered the first branch, but the branch was gone by the
		// time they were composed. The settlement would be a reading of a chain
		// this node no longer follows.
		"the view moves once the reads are done": {
			logs: &scriptedRelayEntryLogs{
				before:      firstBranch(),
				after:       secondBranch(),
				reorgBefore: "confirm",
			},
			expectError:   true,
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
		// A stable view that hands back a termination mined on a branch it has
		// abandoned. The report was not accepted on the chain this node
		// follows, so it closes nothing.
		"a termination from an abandoned branch": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				view.timeouts = []*abi.RandomBeaconRelayEntryTimedOut{
					timeout("b", groupOnSecondBranch),
				}
				return &scriptedRelayEntryLogs{before: view}
			}(),
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
		// The mirror case, and the one that must not be over-corrected: a
		// delivery the view has abandoned answers nothing, so the termination
		// this view does hold still stands.
		"a delivery from an abandoned branch": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				view.submissions = []*abi.RandomBeaconRelayEntrySubmitted{
					submission("b"),
				}
				return &scriptedRelayEntryLogs{before: view}
			}(),
			expectSettlement: true,
			expectedGroupID:  groupOnFirstBranch,
			expectedReads:    []string{"requests", "submissions", "timeouts"},
		},
		"a delivery this view holds": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				view.submissions = []*abi.RandomBeaconRelayEntrySubmitted{
					submission("a"),
				}
				return &scriptedRelayEntryLogs{before: view}
			}(),
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
		// The request itself is the log the view abandoned. There is no request
		// to terminate, so the reads stop before the termination is weighed.
		"the request is from an abandoned branch": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				view.requests = []*abi.RandomBeaconRelayEntryRequested{
					request("b"),
				}
				return &scriptedRelayEntryLogs{before: view}
			}(),
			expectedReads: []string{"requests"},
		},
		// A view behind the request cannot hold the request, let alone its
		// termination. Nothing is read and nothing is claimed.
		"the head has not reached the request": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				view.head = requestBlock - 1
				view.blockHashes[requestBlock-1] = branchHash("a", requestBlock-1)
				return &scriptedRelayEntryLogs{before: view}
			}(),
			expectedReads: nil,
		},
		// A log past the bound the read was given is a backend answering a
		// different question than the one asked, not a later block to accept.
		"a termination past the block the read was bounded by": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				beyond := timeout("a", groupOnFirstBranch)
				beyond.Raw.BlockNumber = head + 1
				view.timeouts = []*abi.RandomBeaconRelayEntryTimedOut{beyond}
				return &scriptedRelayEntryLogs{before: view}
			}(),
			expectError:   true,
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
		// The delivery cannot be placed on a branch, so whether the group
		// answered is unknown. Dropping it would turn an unreadable block into
		// a penalty.
		"the block a delivery was mined in cannot be read": {
			logs: func() *scriptedRelayEntryLogs {
				view := firstBranch()
				view.submissions = []*abi.RandomBeaconRelayEntrySubmitted{
					submission("a"),
				}
				return &scriptedRelayEntryLogs{
					before: view,
					blockHashErrors: map[uint64]error{
						submissionBlock: fmt.Errorf("no such block"),
					},
				}
			}(),
			expectError:   true,
			expectedReads: []string{"requests", "submissions", "timeouts"},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			logs := test.logs

			settlement, err := resolveRelayEntryTimeoutSettlement(
				logs,
				contractAddress,
				requestBlock,
				previousEntry,
			)

			var readNames []string
			for _, read := range logs.reads {
				readNames = append(readNames, read.name)

				if read.startBlock != requestBlock {
					t.Errorf(
						"the %s read starts at block [%d], not at the request "+
							"block [%d]",
						read.name,
						read.startBlock,
						requestBlock,
					)
				}

				// The request read is pinned to the one block the request was
				// made in; the two that follow it are bounded by the head the
				// view was pinned to, so all three answer one snapshot.
				expectedEnd := logs.pinnedHead
				if read.name == "requests" {
					expectedEnd = requestBlock
				}
				if read.endBlock != expectedEnd {
					t.Errorf(
						"the %s read is bounded by block [%d], not by the "+
							"pinned block [%d]",
						read.name,
						read.endBlock,
						expectedEnd,
					)
				}

				if read.requestID != nil && read.requestID.Cmp(requestID) != 0 {
					t.Errorf(
						"the %s read filters on request [%s], not on the "+
							"request that was found [%s]",
						read.name,
						read.requestID,
						requestID,
					)
				}
			}
			if !reflect.DeepEqual(readNames, test.expectedReads) {
				t.Errorf(
					"unexpected reads\nexpected: %v\nactual:   %v",
					test.expectedReads,
					readNames,
				)
			}

			if test.expectError {
				if err == nil {
					t.Fatal(
						"expected a reading that does not answer one view of " +
							"the chain to be refused",
					)
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
		})
	}
}
