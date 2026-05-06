package retransmission

import (
	"reflect"
	"sort"
	"testing"
)

func TestStandardStrategy(t *testing.T) {
	strategy := WithStandardStrategy()

	retransmitInvocations := make(map[int]bool)

	for i := 1; i <= 10; i++ {
		err := strategy.Tick(func() error {
			retransmitInvocations[i] = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	expectedRetransmitInvocations := map[int]bool{
		1:  true,
		2:  true,
		3:  true,
		4:  true,
		5:  true,
		6:  true,
		7:  true,
		8:  true,
		9:  true,
		10: true,
	}
	if !reflect.DeepEqual(expectedRetransmitInvocations, retransmitInvocations) {
		t.Errorf(
			"unexpected invocations\n"+
				"expected: [%v]\n"+
				"actual:   [%v]",
			expectedRetransmitInvocations,
			retransmitInvocations,
		)
	}
}

func TestBackoffStrategy(t *testing.T) {
	strategy := WithBackoffStrategy()

	retransmitInvocations := make(map[int]bool)

	for i := 1; i <= 100; i++ {
		err := strategy.Tick(func() error {
			retransmitInvocations[i] = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	expectedRetransmitInvocations := map[int]bool{
		1:  true,
		3:  true,
		6:  true,
		11: true,
		20: true,
		37: true,
		70: true,
	}
	if !reflect.DeepEqual(expectedRetransmitInvocations, retransmitInvocations) {
		t.Errorf(
			"unexpected invocations\n"+
				"expected: [%v]\n"+
				"actual:   [%v]",
			expectedRetransmitInvocations,
			retransmitInvocations,
		)
	}
}

// TestBackoffStrategy_TickSequence verifies the complete ordered fire sequence
// across 200 ticks. The sequence must be deterministic: each fire advances
// retransmitTick by delay+1 and doubles delay, so the gaps are 2, 3, 5, 9, 17,
// 33, 65, ... producing fires at ticks 1, 3, 6, 11, 20, 37, 70, 135.
func TestBackoffStrategy_TickSequence(t *testing.T) {
	strategy := WithBackoffStrategy()

	var fired []int
	for i := 1; i <= 200; i++ {
		tick := i
		_ = strategy.Tick(func() error {
			fired = append(fired, tick)
			return nil
		})
	}

	sort.Ints(fired)

	expected := []int{1, 3, 6, 11, 20, 37, 70, 135}
	if !reflect.DeepEqual(expected, fired) {
		t.Errorf(
			"unexpected fire sequence\nexpected: %v\nactual:   %v",
			expected,
			fired,
		)
	}
}
