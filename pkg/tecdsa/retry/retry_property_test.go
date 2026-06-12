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
//
// Success and failure are asserted explicitly against a capacity model rather
// than skipped on error: a regression that makes the selection always fail
// (or succeed past its exclusion capacity) fails the suite instead of
// silently passing it.

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

// drawSeed draws a full-range int64 seed. Production seeds are message
// hashes reinterpreted as int64, so negative values are reachable and must
// be exercised.
func drawSeed(t *rapid.T) int64 {
	return rapid.Int64().Draw(t, "seed")
}

// keyGenExclusionCapacity mirrors the documented exclusion model of
// EvaluateRetryParticipantsForKeyGeneration: retries walk eligible single
// operators, then eligible pairs, then eligible triplets, and fail once all
// are exhausted. The capacity is therefore the count of exclusion candidates
// whose removal still leaves at least retryParticipantsCount seats; the
// function must succeed for retryCount below it and fail at or above it.
func keyGenExclusionCapacity(
	groupMembers []chain.Address,
	retryParticipantsCount int,
) int {
	total := len(groupMembers)
	seatCount := map[chain.Address]int{}
	for _, m := range groupMembers {
		seatCount[m]++
	}

	var ops []chain.Address
	for op, seats := range seatCount {
		if total-seats >= retryParticipantsCount {
			ops = append(ops, op)
		}
	}

	capacity := len(ops)
	for i := 0; i < len(ops)-1; i++ {
		for j := i + 1; j < len(ops); j++ {
			if total-seatCount[ops[i]]-seatCount[ops[j]] >= retryParticipantsCount {
				capacity++
			}
		}
	}
	for i := 0; i < len(ops)-2; i++ {
		for j := i + 1; j < len(ops)-1; j++ {
			for k := j + 1; k < len(ops); k++ {
				if total-seatCount[ops[i]]-seatCount[ops[j]]-seatCount[ops[k]] >=
					retryParticipantsCount {
					capacity++
				}
			}
		}
	}
	return capacity
}

// distinctOperators returns the number of distinct operators holding at least
// one seat in members.
func distinctOperators(members []chain.Address) int {
	set := map[chain.Address]bool{}
	for _, m := range members {
		set[m] = true
	}
	return len(set)
}

// assertRetryInvariants checks the properties every SUCCESSFUL selection must
// satisfy: it is a sub-multiset of the group, operators are included
// all-or-nothing (an operator never loses only part of its seats), it retains
// at least retryParticipantsCount seats (the F-009 invariant), and it is
// deterministic for a fixed (seed, retryCount). The call itself must succeed;
// callers are responsible for only requesting satisfiable selections and for
// asserting the error path separately.
func assertRetryInvariants(
	t *rapid.T,
	fn func([]chain.Address, int64, uint, uint) ([]chain.Address, error),
	groupMembers []chain.Address,
	seed int64,
	retryCount uint,
	retryParticipantsCount int,
) []chain.Address {
	subset, err := fn(groupMembers, seed, retryCount, uint(retryParticipantsCount))
	if err != nil {
		t.Fatalf(
			"selection failed for a satisfiable request: %v (group=%d, count=%d, retryCount=%d, seed=%d)",
			err, len(groupMembers), retryParticipantsCount, retryCount, seed,
		)
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

	// (2) all-or-nothing: selection operates on whole operators, so an
	// included operator must keep every seat it holds in the group.
	for op, n := range subsetSeats {
		if n != groupSeats[op] {
			t.Fatalf(
				"operator %q partially included: %d of %d seats",
				op, n, groupSeats[op],
			)
		}
	}

	// (3) F-009: the surviving subset must retain at least
	// retryParticipantsCount seats. A mis-counted eligibility filter that
	// admits an over-large exclusion breaks exactly this.
	if len(subset) < retryParticipantsCount {
		t.Fatalf(
			"subset too small: got %d seats, need >= %d (group=%d, retryCount=%d, seed=%d)",
			len(subset), retryParticipantsCount, len(groupMembers), retryCount, seed,
		)
	}

	// (4) determinism: identical inputs must yield an identical subset.
	subset2, err2 := fn(groupMembers, seed, retryCount, uint(retryParticipantsCount))
	if err2 != nil || !reflect.DeepEqual(subset, subset2) {
		t.Fatalf("non-deterministic selection for fixed inputs")
	}

	return subset
}

func TestRapidEvaluateRetryParticipantsForKeyGeneration(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		groupMembers, total := drawGroupMembers(t)
		retryParticipantsCount := rapid.IntRange(1, total).Draw(t, "retryParticipantsCount")
		seed := drawSeed(t)
		retryCount := uint(rapid.IntRange(0, 60).Draw(t, "retryCount"))

		capacity := keyGenExclusionCapacity(groupMembers, retryParticipantsCount)

		if int(retryCount) >= capacity {
			// Every eligible single/pair/triplet exclusion is exhausted:
			// the function must report that, not fabricate a selection.
			_, err := EvaluateRetryParticipantsForKeyGeneration(
				groupMembers, seed, retryCount, uint(retryParticipantsCount),
			)
			if err == nil {
				t.Fatalf(
					"expected exhaustion error: retryCount=%d >= capacity=%d",
					retryCount, capacity,
				)
			}
			return
		}

		subset := assertRetryInvariants(
			t,
			EvaluateRetryParticipantsForKeyGeneration,
			groupMembers, seed, retryCount, retryParticipantsCount,
		)

		// Key-generation retries work by exclusion: every successful
		// selection removes exactly one single, pair, or triplet of
		// operators. An implementation that excludes nobody (returns the
		// group unchanged) satisfies the size invariants but defeats the
		// retry mechanism entirely; this assertion catches it.
		excluded := distinctOperators(groupMembers) - distinctOperators(subset)
		if excluded < 1 || excluded > 3 {
			t.Fatalf(
				"expected 1-3 operators excluded, got %d (retryCount=%d)",
				excluded, retryCount,
			)
		}
	})
}

func TestRapidEvaluateRetryParticipantsForSigning(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		groupMembers, total := drawGroupMembers(t)
		retryParticipantsCount := rapid.IntRange(1, total).Draw(t, "retryParticipantsCount")
		seed := drawSeed(t)
		retryCount := uint(rapid.IntRange(0, 60).Draw(t, "retryCount"))

		// Signing selection only fails when more seats are requested than
		// exist, which the generators never do — so every call here must
		// succeed. (Unlike key generation there is no exclusion guarantee:
		// requesting all seats legitimately selects the whole group.)
		assertRetryInvariants(
			t,
			EvaluateRetryParticipantsForSigning,
			groupMembers, seed, retryCount, retryParticipantsCount,
		)
	})
}

// TestRapidEvaluateRetryParticipantsRejectsOversizedRequest pins the one
// documented error path shared by both selection functions: requesting more
// seats than the group holds must fail rather than return a too-small subset.
func TestRapidEvaluateRetryParticipantsRejectsOversizedRequest(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		groupMembers, total := drawGroupMembers(t)
		oversized := uint(rapid.IntRange(total+1, 2*total+1).Draw(t, "oversized"))
		seed := drawSeed(t)
		retryCount := uint(rapid.IntRange(0, 60).Draw(t, "retryCount"))

		if _, err := EvaluateRetryParticipantsForSigning(
			groupMembers, seed, retryCount, oversized,
		); err == nil {
			t.Fatalf("signing: expected error for %d seats of %d", oversized, total)
		}
		if _, err := EvaluateRetryParticipantsForKeyGeneration(
			groupMembers, seed, retryCount, oversized,
		); err == nil {
			t.Fatalf("keygen: expected error for %d seats of %d", oversized, total)
		}
	})
}
