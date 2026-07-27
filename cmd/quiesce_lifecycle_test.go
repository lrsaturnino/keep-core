package cmd

import (
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
// backstop to the block-derived completion bound: the drain must always be
// given at least the conservative wall-clock equivalent of the longest
// legitimately in-flight work, plus the processing margin.
func TestQuiesceBackstopDeadline_DominatesCompletionBound(t *testing.T) {
	bound := uint64(1200)
	expected := time.Duration(bound)*quiesceUpperBlockIntervalSeconds*
		time.Second + quiesceBackstopMargin

	if got := quiesceBackstopDeadline(bound); got != expected {
		t.Errorf(
			"expected backstop [%s] for bound [%d], got [%s]",
			expected,
			bound,
			got,
		)
	}
	if quiesceBackstopDeadline(bound) <= quiesceBackstopMargin {
		t.Error("the backstop must exceed the margin for a nonzero bound")
	}
}
