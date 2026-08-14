package tbtc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// countingMetricsRecorder is a PerformanceMetricsRecorder that records counter
// increments and gauge values so tests can assert the monitor's metrics fired.
//
// It is safe for concurrent use: the monitor publishes from its run goroutine
// while track publishes from the broadcast path, and tests read it from the
// test goroutine, so an unsynchronized map here would be a data race of the
// harness's own making rather than of the code under test.
type countingMetricsRecorder struct {
	mutex    sync.Mutex
	counters map[string]float64
	gauges   map[string]float64

	// gaugeSets counts publications per gauge, not just the value that settled.
	// Some of what the monitor must not do on a cancelled context is invisible
	// in the values alone: a check pass that opens and immediately returns
	// still reconciles the tracked-count gauge to the same number it already
	// held. Counting the calls is what makes "a pass was opened at all"
	// observable to a test.
	gaugeSets map[string]int

	// events carries one signal per recorded metric so a test can wait on the
	// transition itself instead of polling a timer for it. The buffer is far
	// larger than any single test's traffic; the sends are still non-blocking so
	// a monitor that keeps recording after a test stopped reading is never
	// stalled by the harness. await treats a signal as "something changed, look
	// again" rather than as the value itself, so a dropped signal costs an
	// earlier wake-up, never a wrong verdict.
	events chan struct{}
}

func newCountingMetricsRecorder() *countingMetricsRecorder {
	return &countingMetricsRecorder{
		counters:  make(map[string]float64),
		gauges:    make(map[string]float64),
		gaugeSets: make(map[string]int),
		events:    make(chan struct{}, 1024),
	}
}

func (c *countingMetricsRecorder) IncrementCounter(name string, value float64) {
	c.mutex.Lock()
	c.counters[name] += value
	c.mutex.Unlock()

	c.signal()
}
func (c *countingMetricsRecorder) RecordDuration(string, time.Duration) {}
func (c *countingMetricsRecorder) SetGauge(name string, value float64) {
	c.mutex.Lock()
	c.gauges[name] = value
	c.gaugeSets[name]++
	c.mutex.Unlock()

	c.signal()
}

func (c *countingMetricsRecorder) signal() {
	select {
	case c.events <- struct{}{}:
	default:
	}
}

// await blocks until the recorded metrics satisfy the predicate, waking on the
// recorder's own events rather than on a polling timer. The deadline is a
// failure bound, not the synchronization mechanism.
func (c *countingMetricsRecorder) await(
	predicate func() bool,
	timeout time.Duration,
) bool {
	deadline := time.After(timeout)

	for {
		if predicate() {
			return true
		}

		select {
		case <-c.events:
		case <-deadline:
			// One last look: the value may have settled between the final
			// event and the deadline firing.
			return predicate()
		}
	}
}

// awaitCounterAtLeast blocks until the named counter reaches want.
func (c *countingMetricsRecorder) awaitCounterAtLeast(
	name string,
	want float64,
	timeout time.Duration,
) bool {
	return c.await(
		func() bool { return c.GetCounterValue(name) >= want },
		timeout,
	)
}

// awaitGauge blocks until the named gauge holds want.
func (c *countingMetricsRecorder) awaitGauge(
	name string,
	want float64,
	timeout time.Duration,
) bool {
	return c.await(func() bool { return c.GetGaugeValue(name) == want }, timeout)
}
func (c *countingMetricsRecorder) GetCounterValue(name string) float64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.counters[name]
}
func (c *countingMetricsRecorder) GetGaugeValue(name string) float64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.gauges[name]
}

// gaugeSetCount returns how many times the named gauge has been published.
func (c *countingMetricsRecorder) gaugeSetCount(name string) int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.gaugeSets[name]
}

// trackedGauge returns the tracked-transaction gauge as an int for comparison
// against tracked-set lengths.
func (c *countingMetricsRecorder) trackedGauge() int {
	return int(c.GetGaugeValue(
		clientinfo.MetricTransactionMonitorTrackedTransactions,
	))
}

// ageTransaction backdates the broadcast time of a tracked transaction to
// simulate the passage of time.
func ageTransaction(
	tm *transactionMonitor,
	txHash bitcoin.Hash,
	by time.Duration,
) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if t, ok := tm.tracked[txHash]; ok {
		t.broadcastAt = t.broadcastAt.Add(-by)
	}
}

func isTracked(tm *transactionMonitor, txHash bitcoin.Hash) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	_, ok := tm.tracked[txHash]
	return ok
}

func trackedCount(tm *transactionMonitor) int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.tracked)
}

// joinOnCleanup registers a bounded join for a goroutine the test has just
// spawned: release unwedges whatever the goroutine may be blocked on (nil when
// there is nothing to unwedge), and the cleanup then waits for its done channel.
//
// Registering it at the spawn site rather than at the end of the test body is
// the point: an assertion that aborts the test earlier still joins the
// goroutine, instead of leaving it parked on a deliberately blocked fake for
// the remainder of the package run. Cleanups run last-in-first-out, so
// goroutines are joined in reverse spawn order.
func joinOnCleanup(
	t *testing.T,
	what string,
	release func(),
	done <-chan struct{},
) {
	t.Helper()

	t.Cleanup(func() {
		if release != nil {
			release()
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("%s outlived the test", what)
		}
	})
}

// countCheckPasses installs a recording wrapper around the check pass the run
// loop invokes and returns a function reporting how many times the loop reached
// it. The wrapper delegates to the real pass, so the loop behaves exactly as it
// does in production.
//
// This is the only way to observe the loop's post-tick cancellation guard. A
// pass entered on a cancelled context returns at its own entry guard without a
// lookup, a metric, or any other external effect, so the guard's removal is
// otherwise invisible - see transactionMonitor.checkFn.
func countCheckPasses(tm *transactionMonitor) func() int {
	var (
		mutex  sync.Mutex
		passes int
	)

	tm.mu.Lock()
	tm.checkFn = func(ctx context.Context) {
		mutex.Lock()
		passes++
		mutex.Unlock()

		tm.check(ctx)
	}
	tm.mu.Unlock()

	return func() int {
		mutex.Lock()
		defer mutex.Unlock()
		return passes
	}
}

type blockingTransactionConfirmationsChain struct {
	*localBitcoinChain

	blockedHash   bitcoin.Hash
	lookupMutex   sync.Mutex
	lookupCount   int
	startedOnce   sync.Once
	doneOnce      sync.Once
	releaseOnce   sync.Once
	lookupStarted chan struct{}
	lookupRelease chan struct{}
	lookupDone    chan struct{}
}

func newBlockingTransactionConfirmationsChain(
	blockedHash bitcoin.Hash,
) *blockingTransactionConfirmationsChain {
	return &blockingTransactionConfirmationsChain{
		localBitcoinChain: newLocalBitcoinChain(),
		blockedHash:       blockedHash,
		lookupStarted:     make(chan struct{}),
		lookupRelease:     make(chan struct{}),
		lookupDone:        make(chan struct{}),
	}
}

func (c *blockingTransactionConfirmationsChain) GetTransactionConfirmations(
	ctx context.Context,
	transactionHash bitcoin.Hash,
) (uint, error) {
	if transactionHash == c.blockedHash {
		c.lookupMutex.Lock()
		c.lookupCount++
		c.lookupMutex.Unlock()

		c.startedOnce.Do(func() { close(c.lookupStarted) })

		// Signal on every exit from the blocked branch, not just the manual
		// release. A test that cancels the run context needs to join the lookup
		// it unblocked; if only the release path signalled, the cancellation
		// path - the one under test - would be unobservable.
		defer c.doneOnce.Do(func() { close(c.lookupDone) })

		// Block until released, but honor the context so a check pass that hits
		// its budget can cancel the lookup instead of stalling on the backend.
		select {
		case <-c.lookupRelease:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}

	return c.localBitcoinChain.GetTransactionConfirmations(ctx, transactionHash)
}

// release unblocks the fake's blocked lookup. It is idempotent so a test can
// register it as a cleanup and still release explicitly along the happy path.
func (c *blockingTransactionConfirmationsChain) release() {
	c.releaseOnce.Do(func() { close(c.lookupRelease) })
}

func (c *blockingTransactionConfirmationsChain) getLookupCount() int {
	c.lookupMutex.Lock()
	defer c.lookupMutex.Unlock()
	return c.lookupCount
}

// recordingTransactionConfirmationsChain reports every confirmation lookup it
// serves on a buffered channel, so a test can join a real lookup instead of
// inferring one from elapsed time.
type recordingTransactionConfirmationsChain struct {
	*localBitcoinChain

	lookups chan bitcoin.Hash
}

func newRecordingTransactionConfirmationsChain() *recordingTransactionConfirmationsChain {
	return &recordingTransactionConfirmationsChain{
		localBitcoinChain: newLocalBitcoinChain(),
		// Buffered so a monitor that keeps polling after the test has taken the
		// lookup it was waiting for is never blocked by an unread channel.
		lookups: make(chan bitcoin.Hash, 128),
	}
}

func (c *recordingTransactionConfirmationsChain) GetTransactionConfirmations(
	ctx context.Context,
	transactionHash bitcoin.Hash,
) (uint, error) {
	select {
	case c.lookups <- transactionHash:
	default:
	}

	return c.localBitcoinChain.GetTransactionConfirmations(ctx, transactionHash)
}

// drainLookups collects every confirmation lookup the chain has recorded so
// far, without blocking.
func drainLookups(c *recordingTransactionConfirmationsChain) []bitcoin.Hash {
	var lookups []bitcoin.Hash

	for {
		select {
		case hash := <-c.lookups:
			lookups = append(lookups, hash)
		default:
			return lookups
		}
	}
}

// cancellingMetricsRecorder cancels an armed context from inside the next
// tracked-count publication. Publishing that gauge is the one thing a check
// pass does between finishing one transaction and starting the next, which
// makes it the seam for landing a cancellation in that window on demand.
type cancellingMetricsRecorder struct {
	*countingMetricsRecorder

	mutex  sync.Mutex
	cancel context.CancelFunc
}

func (c *cancellingMetricsRecorder) SetGauge(name string, value float64) {
	c.countingMetricsRecorder.SetGauge(name, value)

	if name != clientinfo.MetricTransactionMonitorTrackedTransactions {
		return
	}

	c.mutex.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mutex.Unlock()

	if cancel != nil {
		cancel()
	}
}

// armOnTrackedCount makes the next tracked-count publication - and only the
// next one - cancel the given context.
func (c *cancellingMetricsRecorder) armOnTrackedCount(cancel context.CancelFunc) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cancel = cancel
}

// cancelledContext returns a context that is already cancelled the ordinary
// way: Done closed and Err set.
func cancelledContext() context.Context {
	ctx, cancelCtx := context.WithCancel(context.Background())
	cancelCtx()
	return ctx
}

// observedCancellationContext reports cancellation through Err while leaving
// Done open forever. Real contexts do both at once, which is exactly what makes
// the run loop's post-tick guard hard to reach: with Done closed and a tick
// pending, select picks between the two arms at random, so a test can only hope
// to land on the tick. Withholding Done leaves the tick as the loop's only ready
// case and pins it to the branch the guard defends - the one a real node takes
// whenever a tick and a shutdown coincide and the coin lands on the tick.
//
// This is deliberately not a context you could hand to production code; it is an
// instrument for reproducing one scheduling outcome on demand.
type observedCancellationContext struct {
	context.Context
}

func (observedCancellationContext) Done() <-chan struct{} { return nil }

func (observedCancellationContext) Err() error { return context.Canceled }

func TestTransactionMonitor(t *testing.T) {
	chain := newLocalBitcoinChain()
	recorder := newCountingMetricsRecorder()

	monitor := newTransactionMonitor(chain)
	monitor.setMetricsRecorder(recorder)

	tx := &bitcoin.Transaction{}
	txHash := tx.Hash()
	monitor.track(txHash, [20]byte{1, 2, 3})

	if got := recorder.trackedGauge(); got != 1 {
		t.Fatalf("expected tracked-count gauge [1] after insertion; got [%d]", got)
	}

	stuckCount := func() float64 {
		return recorder.GetCounterValue(clientinfo.MetricStuckWalletTransactionsTotal)
	}

	// Fresh: not yet stuck.
	monitor.check(context.Background())
	if got := stuckCount(); got != 0 {
		t.Fatalf("expected no alert for a fresh transaction; got counter [%v]", got)
	}

	// Just below the threshold: still not stuck. The alert condition is strictly
	// greater than the threshold. Testing exactly at the threshold is omitted
	// deliberately: with a real clock the check-time drift always nudges the
	// elapsed time a hair past any exact backdated value, so it cannot be pinned
	// deterministically without an injectable clock.
	ageTransaction(monitor, txHash, defaultStuckTransactionThreshold-time.Minute)
	monitor.check(context.Background())
	if got := stuckCount(); got != 0 {
		t.Fatalf("expected no alert at the threshold boundary; got counter [%v]", got)
	}

	// Past the threshold: flagged as stuck exactly once across repeated checks.
	ageTransaction(monitor, txHash, 2*time.Minute) // now threshold + 1 minute total
	monitor.check(context.Background())
	monitor.check(context.Background())
	if got := stuckCount(); got != 1 {
		t.Fatalf("expected exactly one alert; got counter [%v]", got)
	}

	// Once the transaction confirms, it stops being tracked.
	if err := chain.BroadcastTransaction(tx); err != nil {
		t.Fatalf("unexpected error confirming transaction: [%v]", err)
	}
	monitor.check(context.Background())
	if isTracked(monitor, txHash) {
		t.Fatal("expected confirmed transaction to be untracked")
	}
	if got := recorder.trackedGauge(); got != 0 {
		t.Fatalf(
			"expected tracked-count gauge [0] after confirmed removal; got [%d]",
			got,
		)
	}
}

// TestTransactionMonitor_GivesUpOnNeverConfirming verifies that a transaction
// that never confirms is eventually evicted so it cannot fill the tracking
// table.
func TestTransactionMonitor_GivesUpOnNeverConfirming(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)

	tx := &bitcoin.Transaction{}
	txHash := tx.Hash()
	monitor.track(txHash, [20]byte{})

	// Age it beyond the maximum tracking age; on its first check it is past both
	// the stuck threshold and the give-up age. It must still fire exactly one
	// stuck alert (the alert runs before eviction) and then be evicted rather
	// than tracked forever.
	ageTransaction(monitor, txHash, transactionMonitorMaxTrackingAge+time.Minute)
	monitor.check(context.Background())

	if got := recorder.GetCounterValue(
		clientinfo.MetricStuckWalletTransactionsTotal,
	); got != 1 {
		t.Fatalf("expected one stuck alert before eviction; got counter [%v]", got)
	}
	if isTracked(monitor, txHash) {
		t.Fatal("expected a never-confirming transaction to be evicted")
	}
	if got := recorder.trackedGauge(); got != 0 {
		t.Fatalf(
			"expected tracked-count gauge [0] after age eviction; got [%d]",
			got,
		)
	}
}

// TestTransactionMonitor_CheckBudgetBoundsLookup verifies that a chain lookup
// cannot keep the monitor's sole check goroutine blocked beyond the check
// budget.
func TestTransactionMonitor_CheckBudgetBoundsLookup(t *testing.T) {
	blockedTxHash := bitcoin.Hash{1}
	chain := newBlockingTransactionConfirmationsChain(blockedTxHash)
	monitor := newTransactionMonitor(chain)

	monitor.track(blockedTxHash, [20]byte{})

	checkDone := make(chan struct{})
	go func() {
		monitor.checkWithBudget(context.Background(), 500*time.Millisecond)
		close(checkDone)
	}()
	// Releasing the intentionally blocked backend is what lets the pass return
	// if the budget did not, so the join has to come after it.
	joinOnCleanup(t, "the check pass", chain.release, checkDone)

	select {
	case <-chain.lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("confirmation lookup did not start")
	}

	// The backend never unblocks, so only the check budget can release the pass.
	// This is the crux: the monitor threads the budgeted context into the chain
	// call, so budget expiry cancels the lookup and the pass returns. If it did
	// not, this would block until the timeout below and fail.
	select {
	case <-checkDone:
	case <-time.After(2 * time.Second):
		t.Fatal("transaction check remained blocked after its budget expired")
	}

	if got := chain.getLookupCount(); got != 1 {
		t.Fatalf("expected exactly one confirmation lookup; got [%d]", got)
	}

	// The cancelled lookup is treated as unconfirmed, so the transaction stays
	// tracked and is retried on a later pass.
	if !isTracked(monitor, blockedTxHash) {
		t.Fatal("expected transaction with a cancelled lookup to remain tracked")
	}
}

// TestTransactionMonitor_BudgetExpiryStillAlertsOldest verifies that when a
// check pass hits its time budget while looking up the oldest tracked
// transaction, that transaction still fires its stuck alert (the alert needs no
// network data) instead of being starved pass after pass. The remaining
// transactions are deferred to the next pass rather than alerted on without a
// lookup, so they cannot false-alert on age alone. This is the multi-transaction
// dual of CheckBudgetBoundsLookup: it guards against head-of-line starvation
// when a hung backend consistently eats the whole budget on the oldest entry.
func TestTransactionMonitor_BudgetExpiryStillAlertsOldest(t *testing.T) {
	blockedTxHash := bitcoin.Hash{1} // oldest; its lookup hangs until the budget expires
	chain := newBlockingTransactionConfirmationsChain(blockedTxHash)
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(chain)
	monitor.setMetricsRecorder(recorder)

	newerTxHash := bitcoin.Hash{2}
	monitor.track(blockedTxHash, [20]byte{})
	monitor.track(newerTxHash, [20]byte{})

	// Both transactions are past the stuck threshold; the blocked one is older so
	// oldest-first ordering checks it first and its lookup consumes the budget.
	ageTransaction(monitor, blockedTxHash, defaultStuckTransactionThreshold+2*time.Hour)
	ageTransaction(monitor, newerTxHash, defaultStuckTransactionThreshold+time.Hour)

	checkDone := make(chan struct{})
	go func() {
		monitor.checkWithBudget(context.Background(), 200*time.Millisecond)
		close(checkDone)
	}()
	joinOnCleanup(t, "the check pass", chain.release, checkDone)

	select {
	case <-checkDone:
	case <-time.After(2 * time.Second):
		t.Fatal("check pass did not return after its budget expired")
	}

	// The oldest transaction's lookup was cancelled by the budget, but its
	// age-based alert must still fire - exactly once, for the oldest only. Before
	// the fix the pass returned on budget expiry before alerting, leaving this at
	// 0; if the never-looked-up newer transaction were also alerted it would be 2.
	if got := recorder.GetCounterValue(
		clientinfo.MetricStuckWalletTransactionsTotal,
	); got != 1 {
		t.Fatalf("expected exactly one stuck alert (oldest only); got counter [%v]", got)
	}

	// A cancelled lookup is not a confirmation, so the oldest stays tracked; the
	// newer transaction was deferred, not confirmed, so it stays tracked too.
	if !isTracked(monitor, blockedTxHash) {
		t.Fatal("expected the oldest transaction to remain tracked after a cancelled lookup")
	}
	if !isTracked(monitor, newerTxHash) {
		t.Fatal("expected the deferred newer transaction to remain tracked")
	}

	// Only the oldest transaction's lookup was attempted; the pass returned
	// before reaching the newer one.
	if got := chain.getLookupCount(); got != 1 {
		t.Fatalf("expected exactly one lookup (only the oldest was attempted); got [%d]", got)
	}
}

// TestTransactionMonitor_CapacityBound verifies the tracking table does not grow
// past its bound.
func TestTransactionMonitor_CapacityBound(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)

	const excess = 10
	for i := 0; i < transactionMonitorMaxTracked+excess; i++ {
		var h bitcoin.Hash
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		monitor.track(h, [20]byte{})
	}

	if got := trackedCount(monitor); got != transactionMonitorMaxTracked {
		t.Fatalf(
			"expected tracking table bounded to [%d]; got [%d]",
			transactionMonitorMaxTracked,
			got,
		)
	}

	// The transactions that could not be tracked once the table filled must be
	// surfaced via the unmonitored-transactions metric.
	if got := recorder.GetCounterValue(
		clientinfo.MetricUnmonitoredWalletTransactionsTotal,
	); got != excess {
		t.Fatalf(
			"expected [%d] unmonitored-transaction increments; got [%v]",
			excess,
			got,
		)
	}

	// A rejected insertion leaves the tracked set at the cap, so the gauge must
	// report the cap rather than counting the transactions that were turned away.
	if got := recorder.trackedGauge(); got != transactionMonitorMaxTracked {
		t.Fatalf(
			"expected tracked-count gauge [%d] after capacity rejection; got [%d]",
			transactionMonitorMaxTracked,
			got,
		)
	}
}

// TestTransactionMonitor_TrackedGaugeConvergesUnderConcurrency verifies the
// tracked-count gauge settles on the real tracked-set size after concurrent
// insertions and removals, rather than on whichever publisher happened to reach
// the recorder last.
func TestTransactionMonitor_TrackedGaugeConvergesUnderConcurrency(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)

	const transactions = 200

	hash := func(i int) bitcoin.Hash {
		var h bitcoin.Hash
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		return h
	}

	// Pre-track the transactions the removers will delete, so inserts and
	// removals genuinely interleave instead of the removals finding an empty set.
	for i := transactions; i < 2*transactions; i++ {
		monitor.track(hash(i), [20]byte{})
	}

	var wg sync.WaitGroup
	for i := 0; i < transactions; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			monitor.track(hash(i), [20]byte{})
		}(i)
		go func(i int) {
			defer wg.Done()
			monitor.remove(hash(transactions + i))
		}(i)
	}
	wg.Wait()

	if got, want := recorder.trackedGauge(), trackedCount(monitor); got != want {
		t.Fatalf(
			"tracked-count gauge [%d] does not match the tracked set size [%d]",
			got,
			want,
		)
	}
	if got := recorder.trackedGauge(); got != transactions {
		t.Fatalf(
			"expected tracked-count gauge [%d] after the concurrent mutations; got [%d]",
			transactions,
			got,
		)
	}
}

// TestTransactionMonitor_SnapshotByAge verifies the check pass iterates tracked
// transactions oldest-first, so an old transaction near the stuck threshold is
// never starved when a pass hits its time budget (Go map order is randomized).
func TestTransactionMonitor_SnapshotByAge(t *testing.T) {
	monitor := newTransactionMonitor(newLocalBitcoinChain())

	var h1, h2, h3 bitcoin.Hash
	h1[0], h2[0], h3[0] = 1, 2, 3
	monitor.track(h1, [20]byte{})
	monitor.track(h2, [20]byte{})
	monitor.track(h3, [20]byte{})

	// Backdate broadcast times so the age order is h2 (oldest), h3, h1 (newest).
	// The hour-scale gaps dwarf the sub-second differences in track() times.
	ageTransaction(monitor, h1, 1*time.Hour)
	ageTransaction(monitor, h2, 3*time.Hour)
	ageTransaction(monitor, h3, 2*time.Hour)

	ordered := monitor.snapshotByAge()

	want := []bitcoin.Hash{h2, h3, h1}
	if len(ordered) != len(want) {
		t.Fatalf("expected [%d] entries; got [%d]", len(want), len(ordered))
	}
	for i, w := range want {
		if ordered[i].hash != w {
			t.Fatalf(
				"snapshotByAge not oldest-first at index [%d]\nexpected: %v\ngot:      %v",
				i, want, []bitcoin.Hash{ordered[0].hash, ordered[1].hash, ordered[2].hash},
			)
		}
	}
	// Broadcast times must be non-decreasing across the ordered snapshot.
	for i := 1; i < len(ordered); i++ {
		if ordered[i].broadcastAt.Before(ordered[i-1].broadcastAt) {
			t.Fatalf("entry [%d] is older than entry [%d]; not sorted oldest-first", i, i-1)
		}
	}
}

// setCheckInterval shortens the monitor's private polling interval so run-loop
// tests can exercise a real tick without waiting out the production one.
func setCheckInterval(tm *transactionMonitor, interval time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.checkInterval = interval
}

// TestTransactionMonitor_DefaultCheckInterval pins the production polling
// interval to the constructor. The interval is only ever shortened by package
// tests through their own seam, so a constructed monitor must always carry the
// production value - a monitor built with a shorter one would multiply the
// confirmation-query load on the Bitcoin backend.
func TestTransactionMonitor_DefaultCheckInterval(t *testing.T) {
	monitor := newTransactionMonitor(newLocalBitcoinChain())

	if monitor.checkInterval != transactionMonitorCheckInterval {
		t.Fatalf(
			"expected the constructor to install the production check interval "+
				"[%s]; got [%s]",
			transactionMonitorCheckInterval,
			monitor.checkInterval,
		)
	}
}

// TestTransactionMonitor_RunRefusesNonPositiveInterval verifies the run loop
// refuses an invalid internal interval instead of letting time.NewTicker panic
// and take the node down, and that it does not advertise itself as running.
func TestTransactionMonitor_RunRefusesNonPositiveInterval(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)
	setCheckInterval(monitor, 0)

	ctx, cancelCtx := context.WithCancel(context.Background())

	runDone := make(chan struct{})
	go func() {
		monitor.run(ctx)
		close(runDone)
	}()
	joinOnCleanup(t, "the run loop", cancelCtx, runDone)

	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("run did not return on a non-positive check interval")
	}

	if got := recorder.GetGaugeValue(
		clientinfo.MetricTransactionMonitorRunning,
	); got != 0 {
		t.Fatalf(
			"a monitor that refused to start must not report itself running; "+
				"got gauge [%v]",
			got,
		)
	}
}

// TestTransactionMonitor_RunWithoutMetricsRecorder verifies that whether the
// monitor runs is not controlled by the client-info configuration: a node with
// metrics disabled has no recorder wired, and it must still poll and still stop
// cleanly. It keeps the warn-level stuck-transaction logs, which are all such a
// node has.
func TestTransactionMonitor_RunWithoutMetricsRecorder(t *testing.T) {
	chain := newRecordingTransactionConfirmationsChain()

	// Deliberately no setMetricsRecorder call.
	monitor := newTransactionMonitor(chain)
	setCheckInterval(monitor, time.Millisecond)
	monitor.track(bitcoin.Hash{1}, [20]byte{})

	ctx, cancelCtx := context.WithCancel(context.Background())

	runDone := make(chan struct{})
	go func() {
		monitor.run(ctx)
		close(runDone)
	}()
	joinOnCleanup(t, "the run loop", cancelCtx, runDone)

	select {
	case <-chain.lookups:
	case <-time.After(2 * time.Second):
		t.Fatal("a monitor without a metrics recorder did not poll")
	}

	cancelCtx()

	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("a monitor without a metrics recorder did not stop on cancellation")
	}
}

// TestTransactionMonitor_RunStopsOnContextCancellation verifies the run loop is
// bound to the context it was started with: cancelling it releases the in-flight
// confirmation lookup and terminates the goroutine, and the aborted pass is not
// counted as forward progress.
func TestTransactionMonitor_RunStopsOnContextCancellation(t *testing.T) {
	blockedTxHash := bitcoin.Hash{1}
	chain := newBlockingTransactionConfirmationsChain(blockedTxHash)
	recorder := newCountingMetricsRecorder()

	monitor := newTransactionMonitor(chain)
	monitor.setMetricsRecorder(recorder)
	setCheckInterval(monitor, 5*time.Millisecond)
	monitor.track(blockedTxHash, [20]byte{})

	ctx, cancelCtx := context.WithCancel(context.Background())

	runDone := make(chan struct{})
	go func() {
		monitor.run(ctx)
		close(runDone)
	}()

	// Unwedge and join everything this test may have left blocked, whichever
	// assertion it exits on. Cancelling first is what the loop is supposed to
	// respond to; releasing the backend afterwards covers the case where it did
	// not, so a failing run still reports a bounded result instead of parking a
	// goroutine on the intentionally blocked fake for the rest of the package.
	joinOnCleanup(
		t,
		"the run loop",
		func() {
			cancelCtx()
			chain.release()
		},
		runDone,
	)

	// Join the real lookup rather than assuming a tick has fired by now.
	select {
	case <-chain.lookupStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("confirmation lookup did not start; the run loop is not polling")
	}

	if got := recorder.GetGaugeValue(
		clientinfo.MetricTransactionMonitorRunning,
	); got != 1 {
		t.Fatalf("expected the running gauge at [1] while polling; got [%v]", got)
	}

	// The backend stays blocked, so only the run context can release the pass:
	// cancellation has to reach the chain call through the check budget's
	// derived context.
	cancelCtx()

	// Both the in-flight lookup and the loop itself have to come back, and they
	// share a single one-second budget so a slow release cannot be paid for
	// twice. Joining the lookup is the part that proves cancellation reached
	// the chain call: the loop returning on its own would not.
	cancellationDeadline := time.After(time.Second)
	for _, awaited := range []struct {
		what string
		done <-chan struct{}
	}{
		{"the in-flight confirmation lookup", chain.lookupDone},
		{"the run loop", runDone},
	} {
		select {
		case <-awaited.done:
		case <-cancellationDeadline:
			t.Fatalf(
				"%s did not return within one second of its context being "+
					"cancelled",
				awaited.what,
			)
		}
	}

	if got := recorder.GetGaugeValue(
		clientinfo.MetricTransactionMonitorRunning,
	); got != 0 {
		t.Fatalf("expected the running gauge back at [0] after stop; got [%v]", got)
	}

	// The only pass that ran was aborted by cancellation, so it is not forward
	// progress and must not be counted.
	if got := recorder.GetCounterValue(
		clientinfo.MetricTransactionMonitorCheckCyclesTotal,
	); got != 0 {
		t.Fatalf(
			"a cycle aborted by cancellation must not be counted; got counter [%v]",
			got,
		)
	}
}

// TestTransactionMonitor_CancelledContextStartsNoLookup covers all three ways
// the monitor can meet an already-cancelled context, so no entry point is left
// resting on another's guard:
//
//   - run reaches its select with cancellation pending and takes the Done arm;
//   - run reaches its select with a tick delivered and cancellation already
//     observable, which is the case the post-tick guard exists for; and
//   - checkWithBudget is entered directly, which is what actually guarantees no
//     confirmation lookup escapes.
//
// The two run cases and the direct case are deliberately not interchangeable,
// and neither is allowed to rest on the other's guard. The loop's post-tick
// guard keeps a stopping node from opening a pass at all; the pass's entry
// guard keeps one that was entered anyway from doing any work. Because the run
// path flows through checkWithBudget, no lookup and no metric escapes either
// way, so the shared assertions below cannot tell the two apart - the run cases
// additionally require that the loop never reached its check pass, which is
// what fails if the post-tick guard is deleted.
func TestTransactionMonitor_CancelledContextStartsNoLookup(t *testing.T) {
	tests := map[string]struct {
		context func() context.Context
		invoke  func(monitor *transactionMonitor, ctx context.Context)
	}{
		"run with cancellation pending": {
			context: cancelledContext,
			invoke: func(monitor *transactionMonitor, ctx context.Context) {
				monitor.run(ctx)
			},
		},
		"run with a tick delivered": {
			// Only the ticker arm of the loop's select is ever ready under this
			// context, so the loop cannot avoid the tick the way it can under a
			// real cancellation - see observedCancellationContext.
			context: func() context.Context {
				return observedCancellationContext{context.Background()}
			},
			invoke: func(monitor *transactionMonitor, ctx context.Context) {
				monitor.run(ctx)
			},
		},
		"checkWithBudget entered directly": {
			context: cancelledContext,
			invoke: func(monitor *transactionMonitor, ctx context.Context) {
				monitor.checkWithBudget(ctx, transactionMonitorCheckBudget)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chain := newRecordingTransactionConfirmationsChain()
			recorder := newCountingMetricsRecorder()

			monitor := newTransactionMonitor(chain)
			monitor.setMetricsRecorder(recorder)
			// Short enough that a run loop ignoring the cancellation would have
			// ticked and looked up well within the join below.
			setCheckInterval(monitor, time.Millisecond)
			monitor.track(bitcoin.Hash{1}, [20]byte{})

			// Zero for the direct case by construction - it bypasses the loop -
			// and zero for the run cases only if their guard held.
			checkPasses := countCheckPasses(monitor)

			ctx := test.context()

			done := make(chan struct{})
			go func() {
				test.invoke(monitor, ctx)
				close(done)
			}()
			// Cancellation is already pending, so there is nothing to release;
			// a monitor that ignores it entirely is reported as an outlived
			// goroutine rather than silently left behind.
			joinOnCleanup(t, "the monitor", nil, done)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("the monitor did not return on an already-cancelled context")
			}

			if got := checkPasses(); got != 0 {
				t.Fatalf(
					"the run loop opened [%d] check pass(es) on a context it "+
						"could already see was cancelled",
					got,
				)
			}

			select {
			case hash := <-chain.lookups:
				t.Fatalf(
					"no confirmation lookup may start once cancellation is "+
						"observed; got a lookup for [%s]",
					hash.Hex(bitcoin.ReversedByteOrder),
				)
			default:
			}

			if got := recorder.GetCounterValue(
				clientinfo.MetricTransactionMonitorCheckCyclesTotal,
			); got != 0 {
				t.Fatalf("expected no counted cycles; got counter [%v]", got)
			}

			// track published the tracked-count gauge once before any of this
			// ran, and nothing here may publish it again. A pass that returns
			// at its entry guard reconciles nothing, and the run cases never
			// open one - so a second publication means some entry point started
			// work after cancellation was observable, even though it issued no
			// request.
			if got := recorder.gaugeSetCount(
				clientinfo.MetricTransactionMonitorTrackedTransactions,
			); got != 1 {
				t.Fatalf(
					"expected the tracked-count gauge to be published once, by "+
						"track; got [%d] publications",
					got,
				)
			}
		})
	}
}

// TestTransactionMonitor_CancellationMidPassStopsNextLookup covers the third
// window a shutdown can arrive in: after one transaction's lookup has returned
// and before the next one's begins, while the pass is doing its own bookkeeping.
// The pass must stop there rather than issue one more request.
//
// Neither of the other two guards covers this. The pass's entry guard saw a live
// context, and so did the post-lookup guard of the transaction that had already
// been served. The window is reached deterministically by cancelling from inside
// the tracked-count publication that removing the first, confirmed transaction
// triggers.
func TestTransactionMonitor_CancellationMidPassStopsNextLookup(t *testing.T) {
	chain := newRecordingTransactionConfirmationsChain()

	// Confirmed on the chain, so the pass removes it - and publishing the
	// tracked count on the way is the hook this test cancels from.
	confirmedTx := &bitcoin.Transaction{}
	confirmedTxHash := confirmedTx.Hash()
	if err := chain.BroadcastTransaction(confirmedTx); err != nil {
		t.Fatalf("unexpected error confirming transaction: [%v]", err)
	}

	deferredTxHash := bitcoin.Hash{0xff}

	recorder := &cancellingMetricsRecorder{
		countingMetricsRecorder: newCountingMetricsRecorder(),
	}
	monitor := newTransactionMonitor(chain)
	monitor.setMetricsRecorder(recorder)

	monitor.track(confirmedTxHash, [20]byte{})
	monitor.track(deferredTxHash, [20]byte{})

	// Oldest-first ordering has to serve the confirmed transaction first for the
	// cancellation to land between the two lookups.
	ageTransaction(monitor, confirmedTxHash, time.Hour)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// Armed only now, so the two publications track already made are not the
	// ones that fire it.
	recorder.armOnTrackedCount(cancelCtx)

	monitor.check(ctx)

	lookups := drainLookups(chain)

	if len(lookups) != 1 {
		t.Fatalf(
			"expected the pass to stop at the transaction it had not started "+
				"yet, leaving exactly one lookup; got [%d]",
			len(lookups),
		)
	}
	if lookups[0] != confirmedTxHash {
		t.Fatalf(
			"expected the single lookup to be the one already in progress "+
				"[%s]; got [%s]",
			confirmedTxHash.Hex(bitcoin.ReversedByteOrder),
			lookups[0].Hex(bitcoin.ReversedByteOrder),
		)
	}

	// Never looked up, so it is neither confirmed nor evicted - it waits for the
	// next pass, which on a real node is the next node's turn to run one.
	if !isTracked(monitor, deferredTxHash) {
		t.Fatal("expected the transaction the pass never reached to remain tracked")
	}
}

// TestTransactionMonitor_RunCountsCompletedCycles verifies a pass that runs to
// its own conclusion is counted, which is the metric an operator polls to tell a
// live loop from an inert one. The empty tracked set is deliberate: an idle node
// must still show forward progress.
func TestTransactionMonitor_RunCountsCompletedCycles(t *testing.T) {
	recorder := newCountingMetricsRecorder()
	monitor := newTransactionMonitor(newLocalBitcoinChain())
	monitor.setMetricsRecorder(recorder)
	setCheckInterval(monitor, time.Millisecond)

	ctx, cancelCtx := context.WithCancel(context.Background())

	runDone := make(chan struct{})
	go func() {
		monitor.run(ctx)
		close(runDone)
	}()
	joinOnCleanup(t, "the run loop", cancelCtx, runDone)

	// Woken by the recorder's own event, so the timer is only the failure bound.
	if !recorder.awaitCounterAtLeast(
		clientinfo.MetricTransactionMonitorCheckCyclesTotal,
		1,
		2*time.Second,
	) {
		t.Fatal("the run loop never counted a completed check cycle")
	}

	cancelCtx()

	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("run loop did not terminate after its context was cancelled")
	}
}
