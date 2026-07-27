package cmd

import (
	"math"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAwaitQuiesce_NaturalCompletion(t *testing.T) {
	quiesceDone := make(chan struct{})
	close(quiesceDone)

	reason := awaitQuiesce(quiesceDone, make(chan os.Signal), time.Hour)
	if reason != "completed" {
		t.Errorf("expected reason [completed], got [%s]", reason)
	}
}

func TestAwaitQuiesce_SecondSignalForces(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM

	reason := awaitQuiesce(make(chan struct{}), signals, time.Hour)
	if reason != "forced_by_signal" {
		t.Errorf("expected reason [forced_by_signal], got [%s]", reason)
	}
}

func TestAwaitQuiesce_BackstopDeadline(t *testing.T) {
	reason := awaitQuiesce(
		make(chan struct{}),
		make(chan os.Signal),
		time.Millisecond,
	)
	if reason != "backstop_deadline" {
		t.Errorf("expected reason [backstop_deadline], got [%s]", reason)
	}
}

// TestQuiesceBackstopDeadline_DominatesCompletionBound pins the wall-clock
// backstop to the block-derived completion bound plus the reviewed block
// margin: the drain must always be given at least the conservative wall-clock
// equivalent of the longest legitimately in-flight work, plus the margins.
func TestQuiesceBackstopDeadline_DominatesCompletionBound(t *testing.T) {
	bound := uint64(1200)
	expected := time.Duration(bound+quiesceReviewedMarginBlocks)*
		quiesceUpperBlockIntervalSeconds*time.Second +
		quiesceBackstopMargin

	got, err := quiesceBackstopDeadline(bound)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if got != expected {
		t.Errorf(
			"expected backstop [%s] for bound [%d], got [%s]",
			expected,
			bound,
			got,
		)
	}
	if got <= quiesceBackstopMargin {
		t.Error("the backstop must exceed the margin for a nonzero bound")
	}
}

// TestQuiesceBackstopDeadline_RejectsOverflow proves every step of the
// deadline calculation is overflow-checked: a bound that cannot be converted
// to a wall-clock deadline is a startup error, never a silently truncated
// grace period.
func TestQuiesceBackstopDeadline_RejectsOverflow(t *testing.T) {
	overflowingBounds := map[string]uint64{
		"block margin addition overflows": math.MaxUint64 - 1,
		"seconds multiplication overflows": math.MaxUint64/
			quiesceUpperBlockIntervalSeconds - 1,
		"duration conversion overflows": math.MaxInt64/
			uint64(time.Second) + 1,
	}

	for name, bound := range overflowingBounds {
		t.Run(name, func(t *testing.T) {
			if _, err := quiesceBackstopDeadline(bound); err == nil {
				t.Errorf(
					"expected an overflow error for bound [%d]",
					bound,
				)
			}
		})
	}
}
