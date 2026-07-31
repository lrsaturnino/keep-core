package cmd

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

func TestEvidenceWindowSignalController_OpenAndClose(t *testing.T) {
	tests := map[string]struct {
		initialActive bool
		signal        os.Signal
		expected      bool
	}{
		"open": {
			initialActive: false,
			signal:        syscall.SIGUSR1,
			expected:      true,
		},
		"close": {
			initialActive: true,
			signal:        syscall.SIGUSR2,
			expected:      false,
		},
	}

	for testName, testCase := range tests {
		t.Run(testName, func(t *testing.T) {
			evidenceWindow := participation.NewCutoverEvidenceWindowSignal()
			evidenceWindow.SetActive(testCase.initialActive)

			signals := make(chan os.Signal, 1)
			signals <- testCase.signal
			close(signals)

			done := startEvidenceWindowSignalController(
				context.Background(),
				evidenceWindow,
				signals,
			)

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the evidence-window signal controller did not stop")
			}

			if evidenceWindow.Active() != testCase.expected {
				t.Errorf(
					"unexpected evidence-window state: got [%t], want [%t]",
					evidenceWindow.Active(),
					testCase.expected,
				)
			}
		})
	}
}

func TestEvidenceWindowSignalController_CannotCloseRollbackWindow(
	t *testing.T,
) {
	evidenceWindow := participation.NewCutoverEvidenceWindowSignal()
	evidenceWindow.HoldActive()

	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGUSR2
	close(signals)

	done := startEvidenceWindowSignalController(
		context.Background(),
		evidenceWindow,
		signals,
	)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the evidence-window signal controller did not stop")
	}

	if !evidenceWindow.Active() {
		t.Fatal("SIGUSR2 closed an evidence window held active for rollback")
	}
}
