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

// errUnscriptedPreviousEntry is what the scripted chain answers when a test did
// not script the previous entry read. Reaching it means the reconciliation
// consulted state the test did not intend it to, which must not read as a
// deliberate outcome.
var errUnscriptedPreviousEntry = errors.New("previous entry not scripted")

// relayStateChain answers only the three relay request reads the timeout report
// reconciliation makes. Every other method of the beacon interface is left to
// the embedded nil interface, so a reconciliation that reached for anything
// else would fail the test loudly instead of silently widening what it trusts.
type relayStateChain struct {
	beaconchain.Interface

	mutex sync.Mutex
	// reads counts calls to IsEntryInProgress, so a scripted chain can change
	// its answer as the reconciliation polls.
	reads int

	inProgress    func(read int) (bool, error)
	startBlock    func(read int) (*big.Int, error)
	previousEntry func(read int) ([]byte, error)
	inProgressErr error

	// entries is the delivery channel the reconciliation reads. onRead lets a
	// scripted chain push a relay entry onto it at a chosen point in the poll,
	// which is how the races between a late delivery and the slot emptying are
	// driven deterministically.
	entries chan *event.RelayEntrySubmitted
	onRead  func(read int, entries chan *event.RelayEntrySubmitted)
}

func (c *relayStateChain) IsEntryInProgress() (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.reads++
	if c.onRead != nil {
		c.onRead(c.reads, c.entries)
	}
	if c.inProgressErr != nil {
		return false, c.inProgressErr
	}
	return c.inProgress(c.reads)
}

func (c *relayStateChain) CurrentRequestStartBlock() (*big.Int, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.startBlock(c.reads)
}

func (c *relayStateChain) CurrentRequestPreviousEntry() ([]byte, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.previousEntry == nil {
		return nil, errUnscriptedPreviousEntry
	}
	return c.previousEntry(c.reads)
}

// heldPreviousEntry scripts a beacon whose current request is built on the
// given previous entry regardless of when it is read.
func heldPreviousEntry(entry []byte) func(int) ([]byte, error) {
	return func(int) ([]byte, error) { return entry, nil }
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
// claimed as a penalty only when the beacon's own canonical state records one.
//
// The submitting call returns once a provider accepts the transaction, which
// says nothing about whether it mined, reverted, or was dropped. Departure from
// the in-flight slot is not enough either: a late relay entry empties the very
// same slot an accepted report empties. Nor is a quiet subscription — the event
// carrying a delivery arrives strictly after the state read that saw the slot
// already emptied can return, so an empty channel means "not yet", never "never".
//
// The one reading that settles the report is the beacon holding the reported
// request past its start block while still building on the previous entry that
// request was signing over. Only accepting a timeout report re-anchors a request
// without advancing the relay. Every other reading leaves the rollback barrier
// in place, which is what it exists for.
func TestRelayTimeoutReportSettled(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	retriedStartBlock := func(int) (*big.Int, error) {
		return new(big.Int).SetUint64(relayRequestBlock + 9), nil
	}

	tests := map[string]struct {
		chain          *relayStateChain
		entries        chan *event.RelayEntrySubmitted
		expectedResult bool
	}{
		// The beacon handed the reported request to a fresh group without
		// advancing the relay. Nothing but an accepted report does that.
		"the beacon retried the reported request under a new group": {
			chain: &relayStateChain{
				inProgress:    func(int) (bool, error) { return true, nil },
				startBlock:    retriedStartBlock,
				previousEntry: heldPreviousEntry(reportedPreviousEntry),
			},
			expectedResult: true,
		},
		// The report mines a few blocks after the call returned, which is the
		// ordinary case the bounded wait exists for.
		"the beacon retries a few blocks after the report is filed": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(read int) (*big.Int, error) {
					if read < 4 {
						return new(big.Int).SetUint64(relayRequestBlock), nil
					}
					return retriedStartBlock(read)
				},
				previousEntry: heldPreviousEntry(reportedPreviousEntry),
			},
			expectedResult: true,
		},
		// The timeout path that finds no group to retry with empties the slot,
		// and the request opened next is still built on the previous entry the
		// reported one was signing over. The relay never advanced, so the
		// penalty stands.
		"the emptied slot is refilled by a request on the same previous entry": {
			chain: &relayStateChain{
				inProgress: func(read int) (bool, error) {
					return read >= 3, nil
				},
				startBlock:    retriedStartBlock,
				previousEntry: heldPreviousEntry(reportedPreviousEntry),
			},
			expectedResult: true,
		},
		// An empty slot on its own says only that the request is over. A
		// delivered entry leaves exactly the same trace, so an empty slot that
		// nothing explains before the bound is not a penalty.
		"the beacon holds no request and nothing explains the empty slot": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return false, nil },
			},
		},
		// The group delivered. The relay advanced onto the delivered entry, so
		// every request opened afterwards names a different previous entry.
		"the emptied slot is refilled by a request on the delivered entry": {
			chain: &relayStateChain{
				inProgress: func(read int) (bool, error) {
					return read >= 3, nil
				},
				startBlock:    retriedStartBlock,
				previousEntry: heldPreviousEntry(relayedPreviousEntry),
			},
		},
		"the beacon advanced onto a different previous entry": {
			chain: &relayStateChain{
				inProgress:    func(int) (bool, error) { return true, nil },
				startBlock:    retriedStartBlock,
				previousEntry: heldPreviousEntry(relayedPreviousEntry),
			},
		},
		// The group delivered late. The slot is empty for that reason, not
		// because the report was accepted, so there is no penalty to claim.
		"an entry was delivered before the slot emptied": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return false, nil },
			},
			entries: submittedEntries(relayRequestBlock + 20),
		},
		// The same race one observation later: the slot reads empty first and
		// the delivery that emptied it reaches this node right after.
		"an entry is delivered as the slot is read empty": {
			chain: &relayStateChain{
				inProgress: func(read int) (bool, error) {
					return read < 2, nil
				},
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock), nil
				},
				onRead: func(read int, entries chan *event.RelayEntrySubmitted) {
					if read == 2 {
						entries <- &event.RelayEntrySubmitted{
							BlockNumber: relayRequestBlock + 20,
						}
					}
				},
			},
		},
		// The consequential case: the provider took the transaction but the
		// beacon still holds the very request the report was filed against, so
		// no penalty exists to claim.
		"the reported request still holds the beacon": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock), nil
				},
			},
		},
		// An entry that arrives mid-window ends the reconciliation against the
		// report even though the beacon would have retried the request later.
		"an entry is delivered while the report is still resolving": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(read int) (*big.Int, error) {
					if read < 4 {
						return new(big.Int).SetUint64(relayRequestBlock), nil
					}
					return retriedStartBlock(read)
				},
				previousEntry: heldPreviousEntry(reportedPreviousEntry),
				onRead: func(read int, entries chan *event.RelayEntrySubmitted) {
					if read == 2 {
						entries <- &event.RelayEntrySubmitted{
							BlockNumber: relayRequestBlock + 20,
						}
					}
				},
			},
		},
		"the beacon cannot say whether a request is in progress": {
			chain: &relayStateChain{
				inProgressErr: errors.New("not implemented"),
			},
		},
		"the beacon cannot say which request is in progress": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return nil, errors.New("not implemented")
				},
			},
		},
		// A nil or unrepresentable start block names no request, which cannot
		// be compared against the one reported on.
		"the beacon reports no start block": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) { return nil, nil },
			},
		},
		"the beacon reports a start block outside the block range": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).Lsh(big.NewInt(1), 70), nil
				},
			},
		},
		// Without the beacon's previous entry there is no way to tell a retry
		// from a fresh request, which is the whole discrimination.
		"the beacon cannot say what previous entry it is building on": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: retriedStartBlock,
				previousEntry: func(int) ([]byte, error) {
					return nil, errors.New("not implemented")
				},
			},
		},
		"the beacon reports an empty previous entry": {
			chain: &relayStateChain{
				inProgress:    func(int) (bool, error) { return true, nil },
				startBlock:    retriedStartBlock,
				previousEntry: heldPreviousEntry(nil),
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

			settled := node.relayTimeoutReportSettled(
				context.Background(),
				&testutils.MockLogger{},
				&countingBlockCounter{height: 5_000},
				relayRequestBlock,
				reportedPreviousEntry,
				entries,
			)

			if settled != test.expectedResult {
				t.Errorf(
					"unexpected settlement\nexpected: [%t]\nactual:   [%t]",
					test.expectedResult,
					settled,
				)
			}
		})
	}
}

// TestRelayTimeoutReportSettled_DecidesWithoutEventDelivery is the ordering
// guarantee stated as a test: the settled reading is taken from canonical chain
// state alone, so no delay on this node's relay entry callback can turn a
// delivery into a penalty.
//
// Both subtests run with the subscription channel empty for the entire
// reconciliation — the harshest form of "the callback has not arrived yet" —
// and assert the outcome the chain state alone dictates. The delivered case is
// then handed its event afterwards to confirm nothing in the window consumed
// or depended on it.
func TestRelayTimeoutReportSettled_DecidesWithoutEventDelivery(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	tests := map[string]struct {
		chain          *relayStateChain
		expectedResult bool
	}{
		// The iter-6 hazard exactly: the slot reads empty for the whole window
		// because a late entry emptied it, and the event announcing that entry
		// reaches this node only after the reconciliation has returned.
		"a slot emptied by a delivery no event has announced yet": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return false, nil },
			},
		},
		// The same delivery once the relay has visibly moved on, still with no
		// event in hand.
		"a relay advanced past the reported request with no event in hand": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock + 9), nil
				},
				previousEntry: heldPreviousEntry(relayedPreviousEntry),
			},
		},
		// The mirror image: an accepted report is claimed on chain state alone,
		// with no event ever delivered to help.
		"a retried request with no event ever delivered": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock + 9), nil
				},
				previousEntry: heldPreviousEntry(reportedPreviousEntry),
			},
			expectedResult: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			entries := submittedEntries()
			test.chain.entries = entries

			node := &node{beaconChain: test.chain}

			settled := node.relayTimeoutReportSettled(
				context.Background(),
				&testutils.MockLogger{},
				&countingBlockCounter{height: 5_000},
				relayRequestBlock,
				reportedPreviousEntry,
				entries,
			)

			if settled != test.expectedResult {
				t.Errorf(
					"unexpected settlement\nexpected: [%t]\nactual:   [%t]",
					test.expectedResult,
					settled,
				)
			}
			if test.chain.reads == 0 {
				t.Error("the reconciliation never read the beacon")
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
// refuses the claim outright rather than falling back on the slot reading the
// previous entry exists to disambiguate.
func TestRelayTimeoutReportSettled_WithoutPreviousEntryClaimsNothing(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	for _, previousEntry := range [][]byte{nil, {}} {
		chain := &relayStateChain{
			inProgress: func(int) (bool, error) { return true, nil },
			startBlock: func(int) (*big.Int, error) {
				return new(big.Int).SetUint64(relayRequestBlock + 9), nil
			},
			previousEntry: heldPreviousEntry(reportedPreviousEntry),
		}
		node := &node{beaconChain: chain}

		if node.relayTimeoutReportSettled(
			context.Background(),
			&testutils.MockLogger{},
			&countingBlockCounter{height: 5_000},
			relayRequestBlock,
			previousEntry,
			submittedEntries(),
		) {
			t.Errorf(
				"a report on a request with previous entry [%v] was claimed "+
					"as settled",
				previousEntry,
			)
		}
		if chain.reads != 0 {
			t.Errorf(
				"the reconciliation read the beacon [%d] times without a "+
					"previous entry to compare against",
				chain.reads,
			)
		}
	}
}

// TestRelayTimeoutReportSettled_IsBounded asserts the reconciliation gives up
// rather than following a beacon that never releases the reported request. An
// unbounded wait would hold the monitor's goroutine and its permit open past
// the quiescence transition that has to capture it.
func TestRelayTimeoutReportSettled_IsBounded(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	blockCounter := &countingBlockCounter{height: 5_000}
	node := &node{
		beaconChain: &relayStateChain{
			inProgress: func(int) (bool, error) { return true, nil },
			startBlock: func(int) (*big.Int, error) {
				return new(big.Int).SetUint64(relayRequestBlock), nil
			},
		},
	}

	if node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		blockCounter,
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) {
		t.Fatal("a request that never left the beacon was claimed as settled")
	}

	if blockCounter.waits > relayEntryTimeoutReportResolutionBlocks {
		t.Errorf(
			"the reconciliation waited [%d] blocks, past its bound of [%d]",
			blockCounter.waits,
			relayEntryTimeoutReportResolutionBlocks,
		)
	}
}

// TestRelayTimeoutReportSettled_CanceledPermitClaimsNothing asserts a monitor
// whose permit the release gate closed mid-resolution does not claim a penalty
// it never saw confirmed.
func TestRelayTimeoutReportSettled_CanceledPermitClaimsNothing(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	ctx, cancel := context.WithCancelCause(context.Background())

	blockCounter := &countingBlockCounter{height: 5_000}
	blockCounter.blockFn = func(height uint64) (uint64, error) {
		cancel(errors.New("quiescence"))
		return height, nil
	}

	node := &node{
		beaconChain: &relayStateChain{
			inProgress: func(int) (bool, error) { return true, nil },
			startBlock: func(int) (*big.Int, error) {
				return new(big.Int).SetUint64(relayRequestBlock), nil
			},
		},
	}

	if node.relayTimeoutReportSettled(
		ctx,
		&testutils.MockLogger{},
		blockCounter,
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) {
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
		inProgress: func(int) (bool, error) { return false, nil },
	}
	node := &node{beaconChain: chain}

	if node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		&countingBlockCounter{height: math.MaxUint64 - 1},
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) {
		t.Error(
			"a report whose resolution bound is not representable was " +
				"claimed as settled",
		)
	}
	if chain.reads != 0 {
		t.Errorf(
			"the reconciliation read the beacon [%d] times without a "+
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
		inProgress: func(int) (bool, error) { return true, nil },
		startBlock: func(read int) (*big.Int, error) {
			if read < 2 {
				return new(big.Int).SetUint64(relayRequestBlock), nil
			}
			return new(big.Int).SetUint64(relayRequestBlock + 9), nil
		},
		previousEntry: heldPreviousEntry(reportedPreviousEntry),
	}
	node := &node{beaconChain: chain}

	if !node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		&countingBlockCounter{
			height: math.MaxUint64 - relayEntryTimeoutReportResolutionBlocks,
		},
		relayRequestBlock,
		reportedPreviousEntry,
		submittedEntries(),
	) {
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
