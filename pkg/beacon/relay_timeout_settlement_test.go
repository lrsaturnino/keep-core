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

// relayStateChain answers only the two relay request reads the timeout report
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
// claimed as a penalty only when the beacon's own state says the reported
// request left the in-flight slot *because of the report*.
//
// The submitting call returns once a provider accepts the transaction, which
// says nothing about whether it mined, reverted, or was dropped. Departure is
// not enough either: a late relay entry empties the very same slot, and the
// request that opens next looks identical whichever of the two ended the
// previous one. A monitor that read its own submission — or a bare departure —
// as the penalty would clear the rollback barrier that exists precisely to hold
// a penalty nobody can account for, so every ambiguous reading has to leave the
// permit unclaimed.
func TestRelayTimeoutReportSettled(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	tests := map[string]struct {
		chain          *relayStateChain
		entries        chan *event.RelayEntrySubmitted
		expectedResult bool
	}{
		"the beacon holds no request and no entry was delivered": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return false, nil },
			},
			expectedResult: true,
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
		// A different request holding the slot proves the reported one is over
		// but not what ended it: an entry this node's subscription missed and
		// an accepted report read exactly alike from here.
		"a different request holds the beacon": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock + 1), nil
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
		// The report mines a few blocks after the call returned, which is the
		// ordinary case the bounded wait exists for.
		"the request leaves the beacon a few blocks later": {
			chain: &relayStateChain{
				inProgress: func(read int) (bool, error) {
					return read < 4, nil
				},
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock), nil
				},
			},
			expectedResult: true,
		},
		// An entry that arrives mid-window ends the reconciliation against the
		// report even though the beacon would have released the slot later.
		"an entry is delivered while the report is still resolving": {
			chain: &relayStateChain{
				inProgress: func(read int) (bool, error) {
					return read < 4, nil
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
		inProgress: func(read int) (bool, error) { return read < 2, nil },
		startBlock: func(int) (*big.Int, error) {
			return new(big.Int).SetUint64(relayRequestBlock), nil
		},
	}
	node := &node{beaconChain: chain}

	if !node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		&countingBlockCounter{
			height: math.MaxUint64 - relayEntryTimeoutReportResolutionBlocks,
		},
		relayRequestBlock,
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
