package beacon

import (
	"context"
	"errors"
	"math"
	"math/big"
	"sync"
	"testing"

	"github.com/keep-network/keep-core/internal/testutils"
	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/beacon/event"
	"github.com/keep-network/keep-core/pkg/chain"
)

// reportedPreviousEntry is the previous entry the relay request under test is
// signing over. relayedPreviousEntry is what the beacon's previous entry
// becomes once that request is answered — a distinct value, because the relay
// advances only by a delivered entry.
var (
	reportedPreviousEntry = []byte("previous-entry-of-the-reported-request")
	relayedPreviousEntry  = []byte("previous-entry-after-a-delivered-entry")
)

// errUnscriptedSettlement is what the scripted chain answers when a test did
// not script the settlement lookup. Reaching it means the reconciliation
// consulted state the test did not intend it to, which must not read as a
// deliberate outcome.
var errUnscriptedSettlement = errors.New("settlement lookup not scripted")

// relayTimeoutLookup records one settlement lookup the reconciliation made.
type relayTimeoutLookup struct {
	requestBlockNumber uint64
	previousEntry      string
}

// relayStateChain answers only the settlement lookup the timeout report
// reconciliation makes. Every other method of the beacon interface is left to
// the embedded nil interface, so a reconciliation that reached for the relay
// slot — the state whose readings cannot tell an accepted report from a chain
// view taken before the request existed — would panic instead of silently
// deciding on it.
type relayStateChain struct {
	beaconchain.Interface

	mutex sync.Mutex
	// reads counts settlement lookups, so a scripted chain can change its
	// answer as the reconciliation polls.
	reads int
	// askedFor records what each lookup asked about, so a test can hold the
	// reconciliation to the request its permit was issued for.
	askedFor []relayTimeoutLookup

	// settlement answers one lookup. A nil settlement with a nil error is the
	// chain saying it holds no record of the request being terminated, which
	// covers a report not yet mined and a chain a reorg left the request out
	// of alike.
	settlement func(read int) (*event.RelayEntryTimeoutSettlement, error)

	// entries is the delivery channel the reconciliation reads. onRead lets a
	// scripted chain push a relay entry onto it at a chosen point in the poll,
	// which is how the race between a late delivery and the settlement lookup
	// is driven deterministically.
	entries chan *event.RelayEntrySubmitted
	onRead  func(read int, entries chan *event.RelayEntrySubmitted)
}

func (c *relayStateChain) RelayEntryTimeoutSettlement(
	requestBlockNumber uint64,
	requestPreviousEntry []byte,
) (*event.RelayEntryTimeoutSettlement, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.reads++
	c.askedFor = append(c.askedFor, relayTimeoutLookup{
		requestBlockNumber: requestBlockNumber,
		previousEntry:      string(requestPreviousEntry),
	})
	if c.onRead != nil {
		c.onRead(c.reads, c.entries)
	}
	if c.settlement == nil {
		return nil, errUnscriptedSettlement
	}
	return c.settlement(c.reads)
}

// terminatedRequest builds the beacon's own record that the reported request
// was terminated by an accepted timeout report.
func terminatedRequest(
	requestBlockNumber uint64,
) *event.RelayEntryTimeoutSettlement {
	return &event.RelayEntryTimeoutSettlement{
		RequestID:            big.NewInt(11),
		TerminatedGroupID:    4,
		RequestBlockNumber:   requestBlockNumber,
		RequestPreviousEntry: reportedPreviousEntry,
		BlockNumber:          requestBlockNumber + 64,
		ContractAddress:      "0xbeac0n",
	}
}

// noSettlement scripts a beacon that holds no record of the reported request
// being terminated, however often it is asked.
func noSettlement(int) (*event.RelayEntryTimeoutSettlement, error) {
	return nil, nil
}

// alwaysSettled scripts a beacon that answers every lookup with the same
// record.
func alwaysSettled(
	settlement *event.RelayEntryTimeoutSettlement,
) func(int) (*event.RelayEntryTimeoutSettlement, error) {
	return func(int) (*event.RelayEntryTimeoutSettlement, error) {
		return settlement, nil
	}
}

// settledFrom scripts a beacon that records the termination only from the
// given lookup onwards, which is how a report that mines some blocks after the
// submitting call returned is driven deterministically.
func settledFrom(
	read int,
	settlement *event.RelayEntryTimeoutSettlement,
) func(int) (*event.RelayEntryTimeoutSettlement, error) {
	return func(current int) (*event.RelayEntryTimeoutSettlement, error) {
		if current < read {
			return nil, nil
		}
		return settlement, nil
	}
}

// countingBlockCounter advances one block per wait, so a bounded resolution
// loop terminates deterministically without any real timing.
type countingBlockCounter struct {
	chain.BlockCounter

	mutex   sync.Mutex
	height  uint64
	waits   int
	blockFn func(height uint64) (uint64, error)
}

func (b *countingBlockCounter) CurrentBlock() (uint64, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.blockFn != nil {
		return b.blockFn(b.height)
	}
	return b.height, nil
}

func (b *countingBlockCounter) WaitForBlockHeight(blockNumber uint64) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.waits++
	if blockNumber > b.height {
		b.height = blockNumber
	}
	return nil
}

// submittedEntries builds the relay entry delivery channel the reconciliation
// reads, pre-loaded with the deliveries the monitor's live subscription would
// have handed it.
func submittedEntries(blockNumbers ...uint64) chan *event.RelayEntrySubmitted {
	entries := make(chan *event.RelayEntrySubmitted, len(blockNumbers)+1)
	for _, blockNumber := range blockNumbers {
		entries <- &event.RelayEntrySubmitted{BlockNumber: blockNumber}
	}
	return entries
}

// TestRelayTimeoutReportSettled asserts a filed relay entry timeout report is
// claimed as a penalty only when the beacon holds its own record that the
// reported request was terminated.
//
// The submitting call returns once a provider accepts the transaction, which
// says nothing about whether it mined, reverted, or was dropped. Nor does a
// quiet subscription say anything: the event carrying a delivery arrives
// strictly after the state read that would have observed its effect can return,
// so an empty channel means "not yet", never "never".
//
// The reading that settles the report is the beacon's settlement record and
// nothing else. That record is resolved from canonical chain state on every
// lookup, so it can neither be manufactured by an ordering between this node's
// reads and its event deliveries, nor outlive a reorg that removed the state it
// rests on. Every other reading leaves the rollback barrier in place, which is
// what it exists for.
func TestRelayTimeoutReportSettled(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	// A settlement the beacon holds for a neighbouring request. It is a real
	// penalty, just not this permit's.
	otherRequest := terminatedRequest(relayRequestBlock + 1)

	// A settlement over a previous entry the reported request was not signing
	// over, which is a different request made in the same block.
	otherPreviousEntry := terminatedRequest(relayRequestBlock)
	otherPreviousEntry.RequestPreviousEntry = relayedPreviousEntry

	// A settlement with nothing to join an authenticated log by.
	anonymousRequest := terminatedRequest(relayRequestBlock)
	anonymousRequest.RequestID = nil

	tests := map[string]struct {
		chain          *relayStateChain
		entries        chan *event.RelayEntrySubmitted
		expectSettled  bool
		expectNoLookup bool
	}{
		// The beacon terminated the reported request. Nothing but an accepted
		// timeout report does that.
		"the beacon recorded the reported request as terminated": {
			chain: &relayStateChain{
				settlement: alwaysSettled(terminatedRequest(relayRequestBlock)),
			},
			expectSettled: true,
		},
		// The report mines a few blocks after the call returned, which is the
		// ordinary case the bounded wait exists for.
		"the beacon records the termination a few blocks later": {
			chain: &relayStateChain{
				settlement: settledFrom(
					4,
					terminatedRequest(relayRequestBlock),
				),
			},
			expectSettled: true,
		},
		// The consequential case: the provider took the transaction and the
		// beacon never recorded a termination, so no penalty exists to claim.
		// This is also every chain view a reorg removed the request from — the
		// lookup is resolved afresh each time, so a view that no longer holds
		// the request holds no record for this node to claim either.
		"the beacon holds no record of the request being terminated": {
			chain: &relayStateChain{settlement: noSettlement},
		},
		// The group delivered late. There is no penalty to claim, and the
		// delivery ends the reconciliation before the beacon is asked again.
		"an entry was delivered before the beacon was asked": {
			chain:          &relayStateChain{settlement: noSettlement},
			entries:        submittedEntries(relayRequestBlock + 20),
			expectNoLookup: true,
		},
		// The same race one observation later: the delivery reaches this node
		// while the beacon is being asked, and the answer it gives is still no
		// record.
		"an entry is delivered while the beacon is being asked": {
			chain: &relayStateChain{
				settlement: noSettlement,
				onRead: func(
					read int,
					entries chan *event.RelayEntrySubmitted,
				) {
					if read == 2 {
						entries <- &event.RelayEntrySubmitted{
							BlockNumber: relayRequestBlock + 20,
						}
					}
				},
			},
		},
		"the beacon cannot be asked for its settlement record": {
			chain: &relayStateChain{
				settlement: func(int) (
					*event.RelayEntryTimeoutSettlement,
					error,
				) {
					return nil, errors.New("not implemented")
				},
			},
		},
		// A chain that keeps no relay request lifecycle at all answers every
		// lookup with an error, which is not a penalty.
		"the chain exposes no settlement records": {
			chain: &relayStateChain{},
		},
		// The three ways a record can fail to answer the reported request. Each
		// one is a settlement that exists, so refusing it is what keeps a real
		// penalty on the permit that earned it.
		"the beacon answers with another request's termination": {
			chain: &relayStateChain{settlement: alwaysSettled(otherRequest)},
		},
		"the beacon answers with a termination over another previous entry": {
			chain: &relayStateChain{
				settlement: alwaysSettled(otherPreviousEntry),
			},
		},
		"the beacon answers with a termination naming no request identifier": {
			chain: &relayStateChain{
				settlement: alwaysSettled(anonymousRequest),
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			entries := test.entries
			if entries == nil {
				entries = submittedEntries()
			}
			test.chain.entries = entries

			node := &node{beaconChain: test.chain}

			settlement := node.relayTimeoutReportSettled(
				context.Background(),
				&testutils.MockLogger{},
				&countingBlockCounter{height: 5_000},
				relayRequestBlock,
				reportedPreviousEntry,
				entries,
			)

			if settled := settlement != nil; settled != test.expectSettled {
				t.Errorf(
					"unexpected settlement\nexpected: [%t]\nactual:   [%t]",
					test.expectSettled,
					settled,
				)
			}

			if test.expectNoLookup {
				if len(test.chain.askedFor) != 0 {
					t.Errorf(
						"the reconciliation asked the beacon [%d] times "+
							"after seeing a delivered entry",
						len(test.chain.askedFor),
					)
				}
				return
			}

			// Whatever the outcome, every lookup names the request the permit
			// was issued for. A lookup that drifted onto another request could
			// answer with a penalty this permit never earned.
			for _, lookup := range test.chain.askedFor {
				if lookup.requestBlockNumber != relayRequestBlock ||
					lookup.previousEntry != string(reportedPreviousEntry) {
					t.Errorf(
						"the reconciliation asked about the request of block "+
							"[%d] over previous entry [%s]",
						lookup.requestBlockNumber,
						lookup.previousEntry,
					)
				}
			}
		})
	}
}

// TestRelayTimeoutReportSettled_DecidesWithoutEventDelivery is the ordering
// guarantee stated as a test: the settled reading is taken from canonical chain
// state alone, so no delay on this node's relay entry callback can turn a
// delivery into a penalty, and no delay can withhold a penalty the beacon
// recorded.
//
// Both subtests run with the subscription channel empty for the entire
// reconciliation — the harshest form of "the callback has not arrived yet" —
// and assert the outcome the chain state alone dictates. The channel is then
// handed an event afterwards to confirm nothing in the window consumed or
// depended on it.
func TestRelayTimeoutReportSettled_DecidesWithoutEventDelivery(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	tests := map[string]struct {
		chain         *relayStateChain
		expectSettled bool
	}{
		// A late entry answered the request and the event announcing it reaches
		// this node only after the reconciliation has returned. The beacon
		// recorded no termination, so there is nothing to claim.
		"a request answered by a delivery no event has announced yet": {
			chain: &relayStateChain{settlement: noSettlement},
		},
		// The mirror image: an accepted report is claimed on the beacon's own
		// record, with no event ever delivered to help.
		"a terminated request with no event ever delivered": {
			chain: &relayStateChain{
				settlement: alwaysSettled(terminatedRequest(relayRequestBlock)),
			},
			expectSettled: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			entries := submittedEntries()
			test.chain.entries = entries

			node := &node{beaconChain: test.chain}

			settlement := node.relayTimeoutReportSettled(
				context.Background(),
				&testutils.MockLogger{},
				&countingBlockCounter{height: 5_000},
				relayRequestBlock,
				reportedPreviousEntry,
				entries,
			)

			if settled := settlement != nil; settled != test.expectSettled {
				t.Errorf(
					"unexpected settlement\nexpected: [%t]\nactual:   [%t]",
					test.expectSettled,
					settled,
				)
			}
			if test.chain.reads == 0 {
				t.Error("the reconciliation never asked the beacon")
			}

			// The callback the production subscription would have run, now
			// that the reconciliation is over. Nothing should have been
			// waiting on it and nothing should have consumed it.
			entries <- &event.RelayEntrySubmitted{
				BlockNumber: relayRequestBlock + 20,
			}
			if len(entries) != 1 {
				t.Errorf(
					"the reconciliation consumed [%d] deliveries it was "+
						"never handed",
					len(entries)-1,
				)
			}
		})
	}
}

// TestRelayTimeoutReportSettled_WithoutPreviousEntryClaimsNothing asserts a
// monitor that does not know what previous entry its request was signing over
// refuses the claim outright. The beacon identifies the terminated request by
// that entry, so there is no request to ask about at all.
func TestRelayTimeoutReportSettled_WithoutPreviousEntryClaimsNothing(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	for _, previousEntry := range [][]byte{nil, {}} {
		chain := &relayStateChain{
			settlement: alwaysSettled(terminatedRequest(relayRequestBlock)),
		}
		node := &node{beaconChain: chain}

		if node.relayTimeoutReportSettled(
			context.Background(),
			&testutils.MockLogger{},
			&countingBlockCounter{height: 5_000},
			relayRequestBlock,
			previousEntry,
			submittedEntries(),
		) != nil {
			t.Errorf(
				"a report on a request with previous entry [%v] was claimed "+
					"as settled",
				previousEntry,
			)
		}
		if chain.reads != 0 {
			t.Errorf(
				"the reconciliation asked the beacon [%d] times without the "+
					"previous entry that identifies the request",
				chain.reads,
			)
		}
	}
}

// TestRelayTimeoutReportSettled_IsBounded asserts the reconciliation gives up
// rather than following a beacon that never records the termination. An
// unbounded wait would hold the monitor's goroutine and its permit open past
// the quiescence transition that has to capture it.
//
// It also pins that the decision is re-derived from the chain on every polled
// block rather than remembered between them. A reconciliation that carried an
// answer forward would be deciding on process-local history, which no reorg can
// take back.
func TestRelayTimeoutReportSettled_IsBounded(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	blockCounter := &countingBlockCounter{height: 5_000}
	chain := &relayStateChain{settlement: noSettlement}
	node := &node{beaconChain: chain}

	if node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		blockCounter,
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) != nil {
		t.Fatal("a request the beacon never terminated was claimed as settled")
	}

	if blockCounter.waits > relayEntryTimeoutReportResolutionBlocks {
		t.Errorf(
			"the reconciliation waited [%d] blocks, past its bound of [%d]",
			blockCounter.waits,
			relayEntryTimeoutReportResolutionBlocks,
		)
	}
	if chain.reads != blockCounter.waits+1 {
		t.Errorf(
			"the reconciliation made [%d] settlement lookups over [%d] "+
				"polled blocks; the decision must be re-derived from the "+
				"chain on every one of them",
			chain.reads,
			blockCounter.waits+1,
		)
	}
}

// TestRelayTimeoutReportSettled_CanceledPermitClaimsNothing asserts a monitor
// whose permit the release gate closed mid-resolution does not claim a penalty
// it never saw recorded.
func TestRelayTimeoutReportSettled_CanceledPermitClaimsNothing(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	ctx, cancel := context.WithCancelCause(context.Background())

	blockCounter := &countingBlockCounter{height: 5_000}
	blockCounter.blockFn = func(height uint64) (uint64, error) {
		cancel(errors.New("quiescence"))
		return height, nil
	}

	node := &node{beaconChain: &relayStateChain{settlement: noSettlement}}

	if node.relayTimeoutReportSettled(
		ctx,
		&testutils.MockLogger{},
		blockCounter,
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) != nil {
		t.Error("a canceled resolution claimed the report as settled")
	}
}

// TestRelayTimeoutReportSettled_UnrepresentableBoundClaimsNothing asserts a
// resolution bound the block range cannot represent is rejected rather than
// clamped, and that the rejection reaches the beacon not at all.
//
// Clamping to the top of the range would silently widen the window the monitor
// holds its permit open for; running the loop against a wrapped bound would
// close it before the beacon could answer while still reading as a bounded
// observation. Refusing outright reaches the honest disposition — no penalty
// claimed — without either pretence.
func TestRelayTimeoutReportSettled_UnrepresentableBoundClaimsNothing(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	chain := &relayStateChain{
		settlement: alwaysSettled(terminatedRequest(relayRequestBlock)),
	}
	node := &node{beaconChain: chain}

	if node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		&countingBlockCounter{height: math.MaxUint64 - 1},
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) != nil {
		t.Error(
			"a report whose resolution bound is not representable was " +
				"claimed as settled",
		)
	}
	if chain.reads != 0 {
		t.Errorf(
			"the reconciliation asked the beacon [%d] times without a "+
				"representable bound",
			chain.reads,
		)
	}
}

// TestRelayTimeoutReportSettled_ResolvesAtTopOfBlockRange asserts the highest
// height that still admits a representable bound resolves normally, so the
// rejection above is the overflow itself and not an off-by-one that gives up a
// block early.
func TestRelayTimeoutReportSettled_ResolvesAtTopOfBlockRange(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	chain := &relayStateChain{
		settlement: settledFrom(2, terminatedRequest(relayRequestBlock)),
	}
	node := &node{beaconChain: chain}

	if node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		&countingBlockCounter{
			height: math.MaxUint64 - relayEntryTimeoutReportResolutionBlocks,
		},
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) == nil {
		t.Error(
			"a report confirmed at the top of the block range was not " +
				"claimed as settled",
		)
	}
	if chain.reads < 2 {
		t.Errorf(
			"the reconciliation gave up after [%d] reads at the top of the "+
				"block range",
			chain.reads,
		)
	}
}

// TestRelayEntryTimeoutBlock asserts the block a group runs out of time at is
// rejected when the sum overflows instead of wrapping to a block already
// passed. A wrapped timeout block fires its waiter at once, so the monitor
// would file a penalty against a group that has had no chance to deliver.
func TestRelayEntryTimeoutBlock(t *testing.T) {
	tests := map[string]struct {
		relayRequestBlock uint64
		relayEntryTimeout uint64
		expectedBlock     uint64
		expectedError     bool
	}{
		"an ordinary request": {
			relayRequestBlock: 1_000,
			relayEntryTimeout: 100,
			expectedBlock:     1_100,
		},
		"the highest request block that still admits the timeout": {
			relayRequestBlock: math.MaxUint64 - 100,
			relayEntryTimeout: 100,
			expectedBlock:     math.MaxUint64,
		},
		"a request block one past what the timeout admits": {
			relayRequestBlock: math.MaxUint64 - 99,
			relayEntryTimeout: 100,
			expectedError:     true,
		},
		"a timeout that overflows the block range on its own": {
			relayRequestBlock: 1,
			relayEntryTimeout: math.MaxUint64,
			expectedError:     true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			timeoutBlock, err := relayEntryTimeoutBlock(
				test.relayRequestBlock,
				test.relayEntryTimeout,
			)

			if test.expectedError {
				if !errors.Is(err, errRelayEntryDeadlineOverflow) {
					t.Errorf(
						"expected an overflow rejection\nactual: [%v]",
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: [%v]", err)
			}
			if timeoutBlock != test.expectedBlock {
				t.Errorf(
					"unexpected timeout block\nexpected: [%v]\nactual:   [%v]",
					test.expectedBlock,
					timeoutBlock,
				)
			}
		})
	}
}

// TestRelayEntryTimeoutReportResolutionDeadline asserts the resolution bound is
// rejected on overflow rather than clamped to the top of the block range.
func TestRelayEntryTimeoutReportResolutionDeadline(t *testing.T) {
	tests := map[string]struct {
		currentBlock     uint64
		expectedDeadline uint64
		expectedError    bool
	}{
		"an ordinary height": {
			currentBlock:     5_000,
			expectedDeadline: 5_000 + relayEntryTimeoutReportResolutionBlocks,
		},
		"the highest height that still admits the bound": {
			currentBlock:     math.MaxUint64 - relayEntryTimeoutReportResolutionBlocks,
			expectedDeadline: math.MaxUint64,
		},
		"one height past what the bound admits": {
			currentBlock:  math.MaxUint64 - relayEntryTimeoutReportResolutionBlocks + 1,
			expectedError: true,
		},
		"the top of the block range": {
			currentBlock:  math.MaxUint64,
			expectedError: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			deadline, err := relayEntryTimeoutReportResolutionDeadline(
				test.currentBlock,
			)

			if test.expectedError {
				if !errors.Is(err, errRelayEntryDeadlineOverflow) {
					t.Errorf(
						"expected an overflow rejection\nactual: [%v]",
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: [%v]", err)
			}
			if deadline != test.expectedDeadline {
				t.Errorf(
					"unexpected deadline\nexpected: [%v]\nactual:   [%v]",
					test.expectedDeadline,
					deadline,
				)
			}
		})
	}
}
