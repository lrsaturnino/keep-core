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
}

func (c *relayStateChain) IsEntryInProgress() (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.reads++
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

// TestRelayTimeoutReportSettled asserts a filed relay entry timeout report is
// claimed as a penalty only when the beacon itself confirms the request left
// the in-flight slot.
//
// The submitting call returns once a provider accepts the transaction, which
// says nothing about whether it mined, reverted, or was dropped. A monitor that
// read its own submission as the penalty would clear the rollback barrier that
// exists precisely to hold a penalty nobody can account for, so every reading
// short of a confirmed departure has to leave the permit unclaimed.
func TestRelayTimeoutReportSettled(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	tests := map[string]struct {
		chain          *relayStateChain
		expectedResult bool
	}{
		"the beacon holds no request at all": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return false, nil },
			},
			expectedResult: true,
		},
		"a different request holds the beacon": {
			chain: &relayStateChain{
				inProgress: func(int) (bool, error) { return true, nil },
				startBlock: func(int) (*big.Int, error) {
					return new(big.Int).SetUint64(relayRequestBlock + 1), nil
				},
			},
			expectedResult: true,
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
			node := &node{beaconChain: test.chain}

			settled := node.relayTimeoutReportSettled(
				context.Background(),
				&testutils.MockLogger{},
				&countingBlockCounter{height: 5_000},
				relayRequestBlock,
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
	) {
		t.Error("a canceled resolution claimed the report as settled")
	}
}

// TestRelayTimeoutReportSettled_DeadlineDoesNotWrap asserts the resolution
// bound stays ahead of the height it is set from. A wrapped deadline names a
// block already passed, which would end the reconciliation before the beacon
// had a chance to answer and turn every late-mining report into an unclaimed
// one.
func TestRelayTimeoutReportSettled_DeadlineDoesNotWrap(t *testing.T) {
	const relayRequestBlock = uint64(1_000)

	reads := 0
	node := &node{
		beaconChain: &relayStateChain{
			inProgress: func(read int) (bool, error) {
				reads = read
				return read < 2, nil
			},
			startBlock: func(int) (*big.Int, error) {
				return new(big.Int).SetUint64(relayRequestBlock), nil
			},
		},
	}

	if !node.relayTimeoutReportSettled(
		context.Background(),
		&testutils.MockLogger{},
		&countingBlockCounter{height: math.MaxUint64 - 1},
		relayRequestBlock,
	) {
		t.Error(
			"a report confirmed at the top of the block range was not " +
				"claimed as settled",
		)
	}
	if reads < 2 {
		t.Errorf(
			"the reconciliation gave up after [%d] reads at the top of the "+
				"block range",
			reads,
		)
	}
}
