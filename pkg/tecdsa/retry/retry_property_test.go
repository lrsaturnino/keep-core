package retry

import (
	"fmt"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/keep-network/keep-core/pkg/chain"
)

// Property-based (model-based) coverage for the retry-participant selection,
// targeting the class of security-audit finding F-009: the seat-counting
// eligibility filter must never return a participant subset that is too small
// to retry with. The original F-009 defect mis-counted
// one operator's seats when judging triplet eligibility, which could admit a
// triplet whose exclusion left FEWER than retryParticipantsCount seats. The
// "large enough" invariant below is exactly what such a defect violates, now
// checked across a wide, randomly generated input space rather than a handful
// of hand-picked tables.

// drawGroupMembers builds a random operator group: N distinct operators, each
// holding a random number of seats (a seat == one entry in groupMembers).
// Returns the expanded member slice and the total seat count.
func drawGroupMembers(t *rapid.T) ([]chain.Address, int) {
	nOps := rapid.IntRange(4, 10).Draw(t, "numOperators")
	var groupMembers []chain.Address
	for i := 0; i < nOps; i++ {
		op := chain.Address(fmt.Sprintf("operator-%d", i))
		seats := rapid.IntRange(1, 5).Draw(t, fmt.Sprintf("seats-%d", i))
		for s := 0; s < seats; s++ {
			groupMembers = append(groupMembers, op)
		}
	}
	return groupMembers, len(groupMembers)
}

// assertRetryInvariants checks the three properties every selection result must
// satisfy: it is a sub-multiset of the group, it retains at least
// retryParticipantsCount seats (the F-009 invariant), and it is deterministic
// for a fixed (seed, retryCount).
func assertRetryInvariants(
	t *rapid.T,
	fn func([]chain.Address, int64, uint, uint) ([]chain.Address, error),
	groupMembers []chain.Address,
	seed int64,
	retryCount uint,
	retryParticipantsCount int,
) {
	subset, err := fn(groupMembers, seed, retryCount, uint(retryParticipantsCount))
	if err != nil {
		// Too many retries to satisfy, or more seats requested than exist:
		// a legitimate error return, not an invariant we assert over.
		return
	}

	// (1) sub-multiset: the subset cannot contain more seats of any operator
	// than the group holds.
	groupSeats := map[chain.Address]int{}
	for _, m := range groupMembers {
		groupSeats[m]++
	}
	subsetSeats := map[chain.Address]int{}
	for _, m := range subset {
		subsetSeats[m]++
		if subsetSeats[m] > groupSeats[m] {
			t.Fatalf("subset holds more seats of %q than the group does", m)
		}
	}

	// (2) F-009: the surviving subset must retain at least
	// retryParticipantsCount seats. A mis-counted eligibility filter that
	// admits an over-large exclusion breaks exactly this.
	if len(subset) < retryParticipantsCount {
		t.Fatalf(
			"subset too small: got %d seats, need >= %d (group=%d, retryCount=%d, seed=%d)",
			len(subset), retryParticipantsCount, len(groupMembers), retryCount, seed,
		)
	}

	// (3) determinism: identical inputs must yield an identical subset.
	subset2, err2 := fn(groupMembers, seed, retryCount, uint(retryParticipantsCount))
	if err2 != nil || !reflect.DeepEqual(subset, subset2) {
		t.Fatalf("non-deterministic selection for fixed inputs")
	}
}

func TestRapidEvaluateRetryParticipantsForKeyGeneration(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		groupMembers, total := drawGroupMembers(t)
		retryParticipantsCount := rapid.IntRange(1, total).Draw(t, "retryParticipantsCount")
		seed := int64(rapid.IntRange(0, 1<<30).Draw(t, "seed"))
		retryCount := uint(rapid.IntRange(0, 60).Draw(t, "retryCount"))

		assertRetryInvariants(
			t,
			EvaluateRetryParticipantsForKeyGeneration,
			groupMembers, seed, retryCount, retryParticipantsCount,
		)
	})
}

func TestRapidEvaluateRetryParticipantsForSigning(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		groupMembers, total := drawGroupMembers(t)
		retryParticipantsCount := rapid.IntRange(1, total).Draw(t, "retryParticipantsCount")
		seed := int64(rapid.IntRange(0, 1<<30).Draw(t, "seed"))
		retryCount := uint(rapid.IntRange(0, 60).Draw(t, "retryCount"))

		assertRetryInvariants(
			t,
			EvaluateRetryParticipantsForSigning,
			groupMembers, seed, retryCount, retryParticipantsCount,
		)
	})
}
