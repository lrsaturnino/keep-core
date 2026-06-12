package dkgtest

import (
	"fmt"
	"sync"

	"github.com/keep-network/keep-core/internal/testutils"
)

// capturingLogger is a thread-safe log.StandardLogger that records Errorf
// messages emitted during a DKG run, discarding every other level via the
// embedded MockLogger. Byzantine scenarios use it to assert on protocol-internal
// diagnostics that are otherwise invisible (MockLogger drops them) - notably the
// F-008 reconstruction guard's "missing revealed share" Error. Whether that
// Error appears is what distinguishes "no reconstruction gap occurred" from "a
// gap occurred but the defensive guard absorbed it"; without capturing it, a
// non-crashing run cannot tell the two apart.
//
// One instance is shared by every member goroutine in a run, so the mutex is
// load-bearing: members log concurrently.
type capturingLogger struct {
	*testutils.MockLogger
	mu     sync.Mutex
	errorf []string
}

func newCapturingLogger() *capturingLogger {
	return &capturingLogger{MockLogger: &testutils.MockLogger{}}
}

// Errorf overrides the embedded no-op to record the formatted message.
func (l *capturingLogger) Errorf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errorf = append(l.errorf, fmt.Sprintf(format, args...))
}

// snapshot returns a copy of the captured Errorf messages. Call after all
// member goroutines have finished (no concurrent writers).
func (l *capturingLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.errorf))
	copy(out, l.errorf)
	return out
}
