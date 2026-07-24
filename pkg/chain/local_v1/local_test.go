package local_v1

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/keep-network/keep-core/pkg/beacon/event"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
)

func TestLocalSubmitRelayEntry(t *testing.T) {
	chainHandle := Connect(10, 4)

	err := chainHandle.SubmitRelayEntry(big.NewInt(19).Bytes())
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalOnEntrySubmitted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	chainHandle := Connect(10, 4)

	eventFired := make(chan *event.RelayEntrySubmitted)

	subscription := chainHandle.OnRelayEntrySubmitted(
		func(entry *event.RelayEntrySubmitted) {
			eventFired <- entry
		},
	)

	defer subscription.Unsubscribe()

	err := chainHandle.SubmitRelayEntry(big.NewInt(20).Bytes())
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-eventFired:
		// expected
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLocalOnEntrySubmittedUnsubscribed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	chainHandle := Connect(10, 4)

	eventFired := make(chan *event.RelayEntrySubmitted)

	subscription := chainHandle.OnRelayEntrySubmitted(
		func(entry *event.RelayEntrySubmitted) {
			eventFired <- entry
		},
	)

	subscription.Unsubscribe()

	err := chainHandle.SubmitRelayEntry(big.NewInt(1).Bytes())
	if err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-eventFired:
		t.Fatalf("Event should have not been received due to the cancelled subscription: [%v]", event)
	case <-ctx.Done():
		// expected execution of goroutine
	}
}

func TestLocalOnGroupRegistered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	chainHandle := Connect(10, 4)

	eventFired := make(chan *event.GroupRegistration)

	subscription := chainHandle.OnGroupRegistered(
		func(entry *event.GroupRegistration) {
			eventFired <- entry
		},
	)

	defer subscription.Unsubscribe()

	groupPublicKey := []byte("1")
	memberIndex := beaconchain.GroupMemberIndex(1)
	dkgResult := &beaconchain.DKGResult{GroupPublicKey: groupPublicKey}
	signatures := map[beaconchain.GroupMemberIndex][]byte{
		1: []byte{101},
		2: []byte{102},
		3: []byte{103},
		4: []byte{104},
	}

	err := chainHandle.SubmitDKGResult(memberIndex, dkgResult, signatures)
	if err != nil {
		t.Fatal(err)
	}

	expectedGroupRegistrationEvent := &event.GroupRegistration{
		GroupPublicKey: groupPublicKey,
	}

	select {
	case event := <-eventFired:
		if !reflect.DeepEqual(event, expectedGroupRegistrationEvent) {
			t.Fatalf(
				"Unexpected group registration entry\nExpected: [%v]\nActual:   [%v]",
				expectedGroupRegistrationEvent,
				event,
			)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLocalOnGroupRegisteredUnsubscribed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	chainHandle := Connect(10, 4)

	eventFired := make(chan *event.GroupRegistration)

	subscription := chainHandle.OnGroupRegistered(
		func(entry *event.GroupRegistration) {
			eventFired <- entry
		},
	)

	subscription.Unsubscribe()

	groupPublicKey := []byte("1")
	memberIndex := beaconchain.GroupMemberIndex(1)
	dkgResult := &beaconchain.DKGResult{GroupPublicKey: groupPublicKey}
	signatures := map[beaconchain.GroupMemberIndex][]byte{
		1: []byte{101},
		2: []byte{102},
		3: []byte{103},
		4: []byte{104},
	}

	err := chainHandle.SubmitDKGResult(memberIndex, dkgResult, signatures)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-eventFired:
		t.Fatalf("Event should have not been received due to the cancelled subscription: [%v]", event)
	case <-ctx.Done():
		// expected execution of goroutine
	}
}

func TestLocalOnDKGResultSubmitted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	chainHandle := Connect(10, 4)

	eventFired := make(chan *event.DKGResultSubmission)

	subscription := chainHandle.OnDKGResultSubmitted(
		func(request *event.DKGResultSubmission) {
			eventFired <- request
		},
	)

	defer subscription.Unsubscribe()

	groupPublicKey := []byte("1")
	memberIndex := beaconchain.GroupMemberIndex(1)
	dkgResult := &beaconchain.DKGResult{GroupPublicKey: groupPublicKey}
	signatures := map[beaconchain.GroupMemberIndex][]byte{
		1: []byte{101},
		2: []byte{102},
		3: []byte{103},
		4: []byte{104},
	}

	err := chainHandle.SubmitDKGResult(memberIndex, dkgResult, signatures)
	if err != nil {
		t.Fatal(err)
	}

	expectedResultSubmissionEvent := &event.DKGResultSubmission{
		MemberIndex:    uint32(memberIndex),
		GroupPublicKey: groupPublicKey,
	}

	select {
	case event := <-eventFired:
		if !reflect.DeepEqual(event, expectedResultSubmissionEvent) {
			t.Fatalf(
				"Unexpected DKG result submission event\nExpected: [%v]\nActual:   [%v]",
				expectedResultSubmissionEvent,
				event,
			)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLocalOnDKGResultSubmittedUnsubscribed(t *testing.T) {
	ctx, cancel := newTestContext()
	defer cancel()

	chainHandle := Connect(10, 4)

	eventFired := make(chan *event.DKGResultSubmission)

	subscription := chainHandle.OnDKGResultSubmitted(
		func(event *event.DKGResultSubmission) {
			eventFired <- event
		},
	)

	subscription.Unsubscribe()

	groupPublicKey := []byte("1")
	memberIndex := beaconchain.GroupMemberIndex(1)
	dkgResult := &beaconchain.DKGResult{GroupPublicKey: groupPublicKey}
	signatures := map[beaconchain.GroupMemberIndex][]byte{
		1: []byte{101},
		2: []byte{102},
		3: []byte{103},
		4: []byte{104},
	}

	err := chainHandle.SubmitDKGResult(memberIndex, dkgResult, signatures)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-eventFired:
		t.Fatalf("Event should have not been received due to the cancelled subscription: [%v]", event)
	case <-ctx.Done():
		// expected execution of goroutine
	}
}

func TestWatchBlocks(t *testing.T) {
	c := Connect(10, 4)
	blockCounter, err := c.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	watcher1 := blockCounter.WatchBlocks(ctx1)
	watcher2 := blockCounter.WatchBlocks(ctx2)

	watcher1ReceivedCount := 0
	watcher2ReceivedCount := 0
	// The watcher channels are closed once their context is cancelled, so each
	// consumer goroutine exits its range loop then. Closing a done channel on
	// exit gives the main goroutine a happens-before edge to read the counters
	// without racing the increments.
	watcher1Done := make(chan struct{})
	watcher2Done := make(chan struct{})
	go func() {
		defer close(watcher1Done)
		for range watcher1 {
			watcher1ReceivedCount++
		}
	}()
	go func() {
		defer close(watcher2Done)
		for range watcher2 {
			watcher2ReceivedCount++
		}
	}()

	time.Sleep(600 * time.Millisecond)
	cancel1()
	time.Sleep(600 * time.Millisecond)
	cancel2()

	// Wait for both consumers to drain and exit before reading their counters.
	<-watcher1Done
	<-watcher2Done

	if watcher1ReceivedCount != 1 {
		t.Errorf("watcher 1 should receive [1] block, has [%v]", watcher1ReceivedCount)
	}
	if watcher2ReceivedCount != 2 {
		t.Errorf("watcher 2 should receive [2] block, has [%v]", watcher2ReceivedCount)
	}
}

func TestWatchBlocksNonBlocking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()

	c := Connect(10, 4)
	blockCounter, err := c.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	_ = blockCounter.WatchBlocks(ctx)        // does not read blocks
	watcher := blockCounter.WatchBlocks(ctx) // does read blocks

	var receivedCount uint64
	// The watcher channel is closed once the context is cancelled, so the
	// consumer goroutine exits its range loop then. Closing done on exit gives
	// the main goroutine a happens-before edge to read receivedCount.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range watcher {
			receivedCount++
		}
	}()

	<-ctx.Done()
	<-done

	if receivedCount != 2 {
		t.Errorf("watcher should receive [2] blocks, has [%v]", receivedCount)
	}
}

func TestLocalBlockHeightWaiter(t *testing.T) {
	var tests = map[string]struct {
		blockHeight      uint64
		initialDelay     time.Duration
		expectedWaitTime time.Duration
	}{
		"returns immediately for genesis block": {
			blockHeight:      0,
			expectedWaitTime: 0,
		},
		"returns immediately for block height already reached": {
			blockHeight:      2,
			initialDelay:     3 * defaultBlockTime,
			expectedWaitTime: 0,
		},
		"waits for block height not yet reached": {
			blockHeight:      5,
			initialDelay:     2 * defaultBlockTime,
			expectedWaitTime: 3 * defaultBlockTime,
		},
	}

	for testName, test := range tests {
		test := test
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			c := Connect(10, 4)

			blockCounter, err := c.BlockCounter()
			if err != nil {
				t.Fatalf("failed to set up block counter: [%v]", err)
			}

			time.Sleep(test.initialDelay)

			start := time.Now().UTC()
			blockCounter.WaitForBlockHeight(test.blockHeight)
			end := time.Now().UTC()

			elapsed := end.Sub(start)

			// Block waiter should wait for test.expectedWaitTime minus some
			// margin at minimum; the margin is needed because clock is not
			// always that precise. Setting it to 5ms for this test.
			minMargin := time.Duration(5) * time.Millisecond
			if elapsed < (test.expectedWaitTime - minMargin) {
				t.Errorf(
					"waited less than expected; expected [%v] at min, waited [%v]",
					test.expectedWaitTime,
					elapsed,
				)
			}

			// Block waiter should wait for test.expectedWaitTime plus some
			// margin at maximum; the margin is the time needed for the return
			// instructions to execute, setting it to 25ms for this test.
			maxMargin := time.Duration(25) * time.Millisecond
			if elapsed > (test.expectedWaitTime + maxMargin) {
				t.Errorf(
					"waited longer than expected; expected %v at max, waited %v",
					test.expectedWaitTime,
					elapsed,
				)
			}
		})
	}
}

func TestLocalIsGroupStale(t *testing.T) {
	group1 := localGroup{
		groupPublicKey:          []byte{'v'},
		registrationBlockHeight: 1,
	}

	group2 := localGroup{
		groupPublicKey:          []byte{'i'},
		registrationBlockHeight: 1,
	}

	group3 := localGroup{
		groupPublicKey:          []byte{'d'},
		registrationBlockHeight: 1,
	}

	availableGroups := []localGroup{group1, group2, group3}

	var tests = map[string]struct {
		group           localGroup
		expectedResult  bool
		simulatedHeight uint64
	}{
		"found a first group": {
			group: localGroup{
				groupPublicKey: group1.groupPublicKey,
			},
			simulatedHeight: group1.registrationBlockHeight + 2,
			expectedResult:  false,
		},
		"found a second group": {
			group: localGroup{
				groupPublicKey: group2.groupPublicKey,
			},
			simulatedHeight: group2.registrationBlockHeight + 3,
			expectedResult:  false,
		},
		"group was not found": {
			group: localGroup{
				groupPublicKey: []byte{'z'},
			},
			simulatedHeight: 1,
			expectedResult:  true,
		},
		"a third group was found and current block has passed the expiration and operation timeout": {
			group: localGroup{
				groupPublicKey: group3.groupPublicKey,
			},
			simulatedHeight: group3.registrationBlockHeight +
				groupActiveTime +
				relayRequestTimeout +
				1,
			expectedResult: true,
		},
		"a second group was found and current block is the same as an active time and operation timeout": {
			group: localGroup{
				groupPublicKey: group2.groupPublicKey,
			},
			simulatedHeight: group2.registrationBlockHeight +
				groupActiveTime +
				relayRequestTimeout,
			expectedResult: false,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			chainHandle := &localChain{
				groups:          availableGroups,
				simulatedHeight: test.simulatedHeight,
			}
			actualResult, err := chainHandle.IsStaleGroup(test.group.groupPublicKey)
			if err != nil {
				t.Fatal(err)
			}

			if actualResult != test.expectedResult {
				t.Fatalf("\nCheck for a group removal eligibility failed. \nexpected: %v\nactual:   %v\n", test.expectedResult, actualResult)
			}
		})
	}
}

func TestLocalSubmitDKGResult(t *testing.T) {
	chainHandle := Connect(10, 4)

	memberIndex := beaconchain.GroupMemberIndex(1)
	result := &beaconchain.DKGResult{
		GroupPublicKey: []byte{11},
	}

	signatures := map[beaconchain.GroupMemberIndex][]byte{
		1: []byte{101},
		2: []byte{102},
		3: []byte{103},
		4: []byte{104},
	}

	err := chainHandle.SubmitDKGResult(memberIndex, result, signatures)
	if err != nil {
		t.Fatal(err)
	}

	groupRegistered, err := chainHandle.IsGroupRegistered(result.GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !groupRegistered {
		t.Fatalf("Group not registered")
	}
}

func TestLocalSubmitDKGResultWithSignatures(t *testing.T) {
	groupSize := 5
	honestThreshold := 3

	chainHandle := Connect(groupSize, honestThreshold)

	var tests = map[string]struct {
		signatures    map[beaconchain.GroupMemberIndex][]byte
		expectedError error
	}{
		"no signatures": {
			signatures:    map[beaconchain.GroupMemberIndex][]byte{},
			expectedError: fmt.Errorf("failed to submit result with [0] signatures for honest threshold [%v]", honestThreshold),
		},
		"one signature": {
			signatures: map[beaconchain.GroupMemberIndex][]byte{
				1: []byte{101},
			},
			expectedError: fmt.Errorf("failed to submit result with [1] signatures for honest threshold [%v]", honestThreshold),
		},
		"one less signature than threshold": {
			signatures: map[beaconchain.GroupMemberIndex][]byte{
				1: []byte{101},
				2: []byte{102},
			},
			expectedError: fmt.Errorf("failed to submit result with [2] signatures for honest threshold [%v]", honestThreshold),
		},
		"threshold signatures": {
			signatures: map[beaconchain.GroupMemberIndex][]byte{
				1: []byte{101},
				2: []byte{102},
				3: []byte{103},
			},
			expectedError: nil,
		},
		"one more signature than threshold": {
			signatures: map[beaconchain.GroupMemberIndex][]byte{
				1: []byte{101},
				2: []byte{102},
				3: []byte{103},
				4: []byte{104},
			},
			expectedError: nil,
		},
		"signatures from all group members": {
			signatures: map[beaconchain.GroupMemberIndex][]byte{
				1: []byte{101},
				2: []byte{102},
				3: []byte{103},
				4: []byte{104},
				5: []byte{105},
			},
			expectedError: nil,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			memberIndex := uint8(1)
			result := &beaconchain.DKGResult{
				GroupPublicKey: []byte{11},
			}

			err := chainHandle.SubmitDKGResult(
				memberIndex,
				result,
				test.signatures,
			)

			if !reflect.DeepEqual(test.expectedError, err) {
				t.Fatalf(
					"Unexpected error\nExpected: [%v]\nActual:   [%v]\n",
					test.expectedError,
					err,
				)
			}
		})
	}
}

// TestGetLastDKGResultConcurrentAccess pins the synchronization contract between
// SubmitDKGResult, which reassigns lastSubmittedDKGResult and
// lastSubmittedDKGResultSignatures under handlerMutex, and GetLastDKGResult,
// which must read those same fields under the same lock. A lock-free getter is a
// data race against the concurrent writers even though the functional assertions
// below still pass, so this test is only meaningful under `go test -race`.
//
// The goroutines are coordinated so the race is exercised reliably rather than
// by luck of the scheduler:
//   - every reader enters a read loop and reports readiness only after it has
//     executed GetLastDKGResult at least once;
//   - the writers stay blocked until all readers have reported readiness, so no
//     field reassignment can begin before the readers are already reading;
//   - the readers keep reading until writesComplete is closed, which happens
//     strictly after every writer has returned.
//
// Consequently each reader keeps looping over GetLastDKGResult across the whole
// window in which the writers reassign the shared fields, and those reads carry
// no happens-before edge ordering them against the writes — the condition the
// race detector needs to flag a lock-free getter. Keeping the readers live and
// reading for the entire write window (rather than doing a fixed number of reads
// that could all land before the first write) also keeps the racy read and write
// temporally adjacent, which is what makes -race report the race deterministically
// instead of missing it once the writer's shadow state is evicted. The
// coordination uses only WaitGroups and channel closes: no sleeps, timeouts, or
// fixed read counts.
func TestGetLastDKGResultConcurrentAccess(t *testing.T) {
	groupSize := 10
	honestThreshold := 4

	chainHandle := Connect(groupSize, honestThreshold)

	const submitters = 8
	const readers = 8

	// A threshold-satisfying signature set reused by every submitter; the map is
	// never mutated in place, matching SubmitDKGResult's reassign-only contract.
	signatures := map[beaconchain.GroupMemberIndex][]byte{
		1: {101},
		2: {102},
		3: {103},
		4: {104},
	}

	// writersStart gates the writers. It is closed only after readersReady
	// reports that every reader is already inside its read loop, so no writer can
	// reassign lastSubmittedDKGResult / lastSubmittedDKGResultSignatures until the
	// readers are actively reading those same fields.
	writersStart := make(chan struct{})
	// writesComplete is closed only after every writer has returned from
	// SubmitDKGResult. Readers keep calling GetLastDKGResult until they observe it
	// closed, so they stay live for the entire window in which the writers
	// reassign the shared fields. This removes the false-negative window of a
	// fixed read count, where every read could complete before the first write
	// landed and the race detector would observe no overlapping accesses.
	writesComplete := make(chan struct{})

	// readersReady lets the main goroutine wait until every reader has entered
	// its read loop (and taken at least one read) before releasing the writers.
	// readersWg tracks reader shutdown; writersWg tracks writer completion.
	var readersReady sync.WaitGroup
	var readersWg sync.WaitGroup
	var writersWg sync.WaitGroup
	readersReady.Add(readers)
	readersWg.Add(readers)
	writersWg.Add(submitters)

	for i := 0; i < readers; i++ {
		go func() {
			defer readersWg.Done()
			reported := false
			for {
				// Read the shared fields, then touch the returned snapshot so
				// the read cannot be optimized away.
				result, sigs := chainHandle.GetLastDKGResult()
				if result != nil {
					_ = len(result.GroupPublicKey)
					_ = len(sigs)
				}

				// Report readiness once, after the first read has executed, so
				// the main goroutine only releases the writers once every reader
				// is provably already reading GetLastDKGResult.
				if !reported {
					reported = true
					readersReady.Done()
				}

				// Keep reading until every writer has returned. This keeps the
				// reader live for the whole write phase with no sleep, timeout,
				// or fixed read count.
				select {
				case <-writesComplete:
					return
				default:
				}
			}
		}()
	}

	for i := 0; i < submitters; i++ {
		go func(index int) {
			defer writersWg.Done()
			<-writersStart
			memberIndex := beaconchain.GroupMemberIndex(uint8(index%groupSize) + 1)
			result := &beaconchain.DKGResult{
				GroupPublicKey: []byte{byte(index)},
			}
			if err := chainHandle.SubmitDKGResult(
				memberIndex,
				result,
				signatures,
			); err != nil {
				t.Errorf("unexpected error submitting DKG result: [%v]", err)
			}
		}(i)
	}

	// Barrier: wait until every reader is inside its read loop, then release the
	// writers. Because the readers are already reading and only stop once
	// writesComplete is closed (strictly after every writer returns), each reader
	// keeps calling GetLastDKGResult throughout the writers' reassignment window,
	// with no happens-before edge ordering those reads against the writes.
	readersReady.Wait()
	close(writersStart)
	writersWg.Wait()
	close(writesComplete)
	readersWg.Wait()

	// After every submission completes, the getter must return one of the
	// submitted results together with its signatures.
	result, sigs := chainHandle.GetLastDKGResult()
	if result == nil {
		t.Fatal("expected a last DKG result after concurrent submissions")
	}
	if len(sigs) != len(signatures) {
		t.Fatalf(
			"unexpected signatures count\nexpected: [%v]\nactual:   [%v]",
			len(signatures),
			len(sigs),
		)
	}
}

func TestCalculateDKGResultHash(t *testing.T) {
	localChain := &localChain{}

	dkgResult := &beaconchain.DKGResult{
		GroupPublicKey: []byte{3, 40, 200},
		Misbehaved:     []byte{1, 2, 8, 14},
	}
	expectedHashString := "97a94a3b11a0f780c9510df852ac7f77072085d5bda4b07e5d198396dd4f68e5"

	actualHash, err := localChain.CalculateDKGResultHash(dkgResult)
	if err != nil {
		t.Fatal(err)
	}

	expectedHash := beaconchain.DKGResultHash{}
	copy(
		expectedHash[:],
		common.Hex2Bytes(expectedHashString)[:32],
	)

	if expectedHash != actualHash {
		t.Fatalf("\nexpected: %x\nactual:   %x\n",
			expectedHash,
			actualHash,
		)
	}
}

func newTestContext(timeout ...time.Duration) (context.Context, context.CancelFunc) {
	defaultTimeout := 3 * time.Second
	if len(timeout) > 0 {
		defaultTimeout = timeout[0]
	}
	return context.WithTimeout(context.Background(), defaultTimeout)
}

func TestNextGroupIndex(t *testing.T) {
	var tests = map[string]struct {
		previousEntry  int
		numberOfGroups int
		expectedIndex  int
	}{
		"zero groups": {
			previousEntry:  12,
			numberOfGroups: 0,
			expectedIndex:  0,
		},
		"fewer groups than the previous entry value": {
			previousEntry:  13,
			numberOfGroups: 4,
			expectedIndex:  1,
		},
		"more groups than the previous entry value": {
			previousEntry:  3,
			numberOfGroups: 12,
			expectedIndex:  3,
		},
	}

	for nextGroupIndexTest, test := range tests {
		t.Run(nextGroupIndexTest, func(t *testing.T) {
			bigPreviousEntry := big.NewInt(int64(test.previousEntry))
			bigNumberOfGroups := test.numberOfGroups
			expectedIndex := test.expectedIndex

			actualIndex := selectGroup(bigPreviousEntry, bigNumberOfGroups)

			if actualIndex != expectedIndex {
				t.Fatalf(
					"Unexpected group index selected\nexpected: [%v]\nactual:   [%v]\n",
					expectedIndex,
					actualIndex,
				)
			}
		})
	}
}
