package beacon

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

type testAuthoritativeClock struct{ chain.BlockCounter }

func (c testAuthoritativeClock) CurrentHeight(
	context.Context,
) (uint64, error) {
	return c.CurrentBlock()
}

var relayEntryTimeout = uint64(15)

// monitoredPreviousEntry stands in for the previous entry the relay request
// under monitoring is signing over. The monitor carries it so it can tell an
// accepted timeout report from a late delivery; these tests only need it to be
// a request the monitor can name.
var monitoredPreviousEntry = []byte("monitored-request-previous-entry")

// newMonitorTestNode builds the minimal node a relay entry monitoring test
// needs: the local chain plus a real participation gate with the
// developer-only disabled schedule, in which timeout reports stay allowed.
func newMonitorTestNode(
	t *testing.T,
	localChain beaconchain.Interface,
) *node {
	t.Helper()

	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	gate, err := participation.NewGate(
		context.Background(),
		participation.Schedule{},
		blockCounter,
		testAuthoritativeClock{blockCounter},
		newCutoverGateMetrics(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	return &node{
		beaconChain:       localChain,
		participationGate: gate,
	}
}

func TestMonitorRelayEntryOnChain_EntrySubmitted(t *testing.T) {
	localChain := local_v1.Connect(5, 3)

	node := newMonitorTestNode(t, localChain)

	blockCounter, err := node.beaconChain.BlockCounter()
	if err != nil {
		fmt.Printf("failed to setup a block counter: [%v]", err)
	}

	startBlockHeight, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	go node.MonitorRelayEntry(monitoredPreviousEntry, startBlockHeight)

	// the window to get a relay entry is from currentBlock to (currentBlock+relayEntryTimeout)
	// we subtract arbitarly 5 blocks to be within this window. Ex. 0 + 15 - 5
	relayEntrySubmissionWindow := startBlockHeight + relayEntryTimeout - 5
	err = blockCounter.WaitForBlockHeight(relayEntrySubmissionWindow)
	if err != nil {
		fmt.Printf(
			"failed to wait for a block: [%v]: [%v]",
			relayEntrySubmissionWindow,
			err,
		)
	}

	err = localChain.SubmitRelayEntry(big.NewInt(1).Bytes())
	if err != nil {
		t.Fatal(err)
	}

	err = blockCounter.WaitForBlockHeight(startBlockHeight + relayEntryTimeout)
	if err != nil {
		t.Fatal(err)
	}

	timeoutsReport := localChain.GetRelayEntryTimeoutReports()
	numberOfReports := len(timeoutsReport)

	if numberOfReports != 0 {
		t.Fatalf(
			"expected 0 relay entry timeout reports; has: [%v]",
			numberOfReports,
		)
	}
}

func TestMonitorRelayEntryOnChain_EntryNotSubmitted(t *testing.T) {
	localChain := local_v1.Connect(5, 3)

	node := newMonitorTestNode(t, localChain)

	blockCounter, err := node.beaconChain.BlockCounter()
	if err != nil {
		fmt.Printf("failed to setup a block counter: [%v]", err)
	}

	startBlockHeight, err := blockCounter.CurrentBlock()
	if err != nil {
		t.Fatal(err)
	}

	go node.MonitorRelayEntry(monitoredPreviousEntry, startBlockHeight)

	relayEntryTimeoutFromStart := startBlockHeight + relayEntryTimeout

	// we want to exceed the relay entry timeout to report that a relay entry
	// was not submitted. 5 is an arbitrary number to exceed relayEntryTimeout.
	err = blockCounter.WaitForBlockHeight(relayEntryTimeoutFromStart + 5)
	if err != nil {
		t.Fatal(err)
	}

	timeoutsReport := localChain.GetRelayEntryTimeoutReports()
	numberOfReports := len(timeoutsReport)

	if numberOfReports != 1 {
		t.Fatalf(
			"Number of timeout reports does not match\nexpected: [%v]\nactual:   [%v]",
			1,
			numberOfReports,
		)
	}

	if timeoutsReport[0] != relayEntryTimeoutFromStart {
		t.Fatalf(
			"Timeout reporting must happen only after a relay entry timeout\nexpected: [%v]\nactual:   [%v]",
			relayEntryTimeoutFromStart,
			timeoutsReport[0],
		)
	}
}
