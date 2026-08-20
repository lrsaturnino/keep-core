package participation

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	log2 "github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

var fixedTestTime = time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)

func fixedClock() func() time.Time {
	return func() time.Time { return fixedTestTime }
}

type capturedRosterLogEntry struct {
	Logger  string `json:"logger"`
	Message string `json:"msg"`
}

func captureRosterLogs(
	t *testing.T,
	fn func(),
) []capturedRosterLogEntry {
	return captureRosterLogsWithObserver(t, func(<-chan capturedRosterLogEntry) {
		fn()
	})
}

func captureRosterLogsWithObserver(
	t *testing.T,
	fn func(<-chan capturedRosterLogEntry),
) []capturedRosterLogEntry {
	t.Helper()

	const subsystem = "keep-participation"
	if err := log2.SetLogLevel(subsystem, "debug"); err != nil {
		t.Fatal(err)
	}

	pipe := log2.NewPipeReader()

	var mutex sync.Mutex
	var entries []capturedRosterLogEntry
	observed := make(chan capturedRosterLogEntry, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)

		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			var entry capturedRosterLogEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				continue
			}
			if entry.Logger != subsystem {
				continue
			}

			mutex.Lock()
			entries = append(entries, entry)
			mutex.Unlock()

			observed <- entry
		}
	}()

	fn(observed)

	if err := pipe.Close(); err != nil {
		t.Logf("could not close log pipe reader: %v", err)
	}
	<-done

	mutex.Lock()
	defer mutex.Unlock()
	return append([]capturedRosterLogEntry(nil), entries...)
}

// fakeBlockCounter is a controllable chain.BlockCounter for tests.
type fakeBlockCounter struct {
	mu    sync.Mutex
	block uint64
	err   error
}

func newFakeBlockCounter(block uint64) *fakeBlockCounter {
	return &fakeBlockCounter{block: block}
}

func (f *fakeBlockCounter) set(block uint64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = block
	f.err = err
}

func (f *fakeBlockCounter) CurrentBlock() (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.block, f.err
}

func (f *fakeBlockCounter) WaitForBlockHeight(uint64) error { return nil }

func (f *fakeBlockCounter) BlockHeightWaiter(uint64) (<-chan uint64, error) {
	ch := make(chan uint64, 1)
	close(ch)
	return ch, nil
}

func (f *fakeBlockCounter) WatchBlocks(ctx context.Context) <-chan uint64 {
	ch := make(chan uint64)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

type testRosterAuthoritativeClock struct {
	blockCounter chain.BlockCounter
}

func (c testRosterAuthoritativeClock) CurrentHeight(
	context.Context,
) (uint64, error) {
	return c.blockCounter.CurrentBlock()
}

type mutableRosterClock struct {
	mu  sync.Mutex
	now time.Time
}

func newMutableRosterClock(now time.Time) *mutableRosterClock {
	return &mutableRosterClock{now: now}
}

func (c *mutableRosterClock) set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = now
}

func (c *mutableRosterClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

type manualRosterTicker struct {
	ticks     chan time.Time
	processed chan struct{}
	stopOnce  sync.Once
	stopped   chan struct{}
}

func newManualRosterTicker() *manualRosterTicker {
	return &manualRosterTicker{
		ticks:     make(chan time.Time, 1),
		processed: make(chan struct{}, 1),
		stopped:   make(chan struct{}),
	}
}

func (t *manualRosterTicker) Ticks() <-chan time.Time {
	return t.ticks
}

func (t *manualRosterTicker) MarkProcessed() {
	t.processed <- struct{}{}
}

func (t *manualRosterTicker) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopped)
	})
}

func (t *manualRosterTicker) tick(at time.Time) {
	t.ticks <- at
}

func newRunLoopTestRoster(
	t *testing.T,
	initialBlock uint64,
	retention uint64,
	clock *mutableRosterClock,
	ticker *manualRosterTicker,
	options ...CutoverPeerRosterOption,
) (*CutoverPeerRoster, *fakeBlockCounter) {
	t.Helper()

	blockCounter := newFakeBlockCounter(initialBlock)
	tickerOption := withCutoverPeerRosterTickerFactory(
		func(interval time.Duration) cutoverPeerRosterTicker {
			if interval != rosterSweepInterval {
				t.Fatalf(
					"unexpected roster sweep interval [%s], expected [%s]",
					interval,
					rosterSweepInterval,
				)
			}

			return ticker
		},
	)
	options = append(options, tickerOption)

	roster, err := newCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testRosterAuthoritativeClock{blockCounter},
		retention,
		newFakeMetrics(),
		clock.Now,
		options...,
	)
	if err != nil {
		t.Fatalf("failed to construct roster: [%v]", err)
	}
	t.Cleanup(roster.Close)

	return roster, blockCounter
}

func driveRosterRunLoopTick(
	t *testing.T,
	clock *mutableRosterClock,
	ticker *manualRosterTicker,
	at time.Time,
) {
	t.Helper()

	clock.set(at)
	ticker.tick(at)

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	select {
	case <-ticker.processed:
	case <-timeout.C:
		t.Fatal("roster run loop did not process the injected cadence tick")
	}
}

func waitForRosterLog(
	t *testing.T,
	observed <-chan capturedRosterLogEntry,
	expected string,
) {
	t.Helper()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case entry := <-observed:
			if entry.Message == expected {
				return
			}
		case <-timeout.C:
			t.Fatalf("roster run loop did not emit log [%s]", expected)
		}
	}
}

// fakeMetrics is a recording CutoverRosterMetricsRecorder.
type fakeMetrics struct {
	mu       sync.Mutex
	gauges   map[string]float64
	counters map[string]float64
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{
		gauges:   make(map[string]float64),
		counters: make(map[string]float64),
	}
}

func (m *fakeMetrics) IncrementCounter(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] += value
}

func (m *fakeMetrics) SetGauge(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = value
}

func (m *fakeMetrics) gauge(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gauges[name]
}

func (m *fakeMetrics) counter(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

func (m *fakeMetrics) hasGauge(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.gauges[name]
	return ok
}

func (m *fakeMetrics) hasCounter(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.counters[name]
	return ok
}

func newTestRoster(
	t *testing.T,
	initialBlock uint64,
	retention uint64,
) (*CutoverPeerRoster, *fakeBlockCounter, *fakeMetrics) {
	t.Helper()
	bc := newFakeBlockCounter(initialBlock)
	metrics := newFakeMetrics()
	roster, err := newCutoverPeerRoster(
		context.Background(),
		bc,
		testRosterAuthoritativeClock{bc},
		retention,
		metrics,
		fixedClock(),
	)
	if err != nil {
		t.Fatalf("failed to construct roster: [%v]", err)
	}
	t.Cleanup(roster.Close)
	return roster, bc, metrics
}

// validAddress returns a distinct valid 20-byte hex operator address for i.
func validAddress(i int) chain.Address {
	return chain.Address(fmt.Sprintf("0x%040x", i))
}

func observeStraggler(
	r *CutoverPeerRoster,
	protocolID string,
	memberIndex group.MemberIndex,
	address chain.Address,
) {
	r.ObserveLegacy(
		protocolID,
		memberIndex,
		address,
		ModeSecurityV2,
		announcer.SessionIDFormatHardenedDKG,
		announcer.SessionIDFormatLegacy,
	)
}

func TestCutoverPeerRoster_ConstructionRejectsZeroRetention(t *testing.T) {
	blockCounter := newFakeBlockCounter(0)
	_, err := NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testRosterAuthoritativeClock{blockCounter},
		0,
		newFakeMetrics(),
	)
	if err == nil {
		t.Fatal("expected an error for zero retention")
	}
}

func TestCutoverPeerRoster_ConstructionRejectsOverflowRetention(t *testing.T) {
	blockCounter := newFakeBlockCounter(0)
	_, err := NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testRosterAuthoritativeClock{blockCounter},
		maxSafeMetricInteger+1,
		newFakeMetrics(),
	)
	if err == nil {
		t.Fatal("expected an error for precision-unsafe retention")
	}
}

func TestCutoverPeerRoster_ConstructionRejectsUnprojectableCutoverSchedule(
	t *testing.T,
) {
	blockCounter := newFakeBlockCounter(0)
	_, err := NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testRosterAuthoritativeClock{blockCounter},
		1000,
		newFakeMetrics(),
		WithCutoverSchedule(Schedule{
			CutoverBlock: maxSafeMetricInteger + 1,
		}),
	)
	if err == nil {
		t.Fatal("expected an error for a precision-unsafe cutover schedule")
	}
}

func TestCutoverPeerRoster_ConstructionRejectsNilEvidenceWindowSignal(
	t *testing.T,
) {
	blockCounter := newFakeBlockCounter(0)
	_, err := NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		testRosterAuthoritativeClock{blockCounter},
		1000,
		newFakeMetrics(),
		WithCutoverEvidenceWindowSignal(nil),
	)
	if err == nil {
		t.Fatal("expected an error for a nil evidence-window signal")
	}
}

func TestCutoverPeerRoster_ConstructionInitializesMetricsAtZero(t *testing.T) {
	_, _, metrics := newTestRoster(t, 100, 1000)

	for _, name := range []string{
		metricLegacyPeersCurrent,
		metricLegacyPeerOldestAgeBlocks,
		metricLegacyPeerRosterRevision,
	} {
		if !metrics.hasGauge(name) {
			t.Errorf("expected gauge %q to be registered", name)
		}
		if metrics.gauge(name) != 0 {
			t.Errorf("expected gauge %q to be initialized to zero", name)
		}
	}
	for _, name := range []string{
		metricLegacyPeerAdditionsTotal,
		metricLegacyPeerEvictionsTotal,
	} {
		if !metrics.hasCounter(name) {
			t.Errorf("expected counter %q to be registered", name)
		}
		if metrics.counter(name) != 0 {
			t.Errorf("expected counter %q to be initialized to zero", name)
		}
	}
}

func TestCutoverPeerRoster_ConstructionClockFailureIsTolerated(t *testing.T) {
	bc := newFakeBlockCounter(0)
	bc.set(0, fmt.Errorf("clock unavailable"))

	roster, err := NewCutoverPeerRoster(
		context.Background(),
		bc,
		testRosterAuthoritativeClock{bc},
		1000,
		newFakeMetrics(),
	)
	if err != nil {
		t.Fatalf("construction should tolerate a clock error, got: [%v]", err)
	}
	t.Cleanup(roster.Close)

	snapshot := roster.Snapshot()
	if snapshot.ClockAvailable {
		t.Error("expected clock to be marked unavailable after a construction clock error")
	}
}

func TestCutoverPeerRoster_ConstructionUsesAuthoritativeClock(t *testing.T) {
	blockCounter := newFakeBlockCounter(1234)
	clock := &staticAuthClock{
		height: 1234,
		err:    fmt.Errorf("authoritative clock unavailable"),
	}

	roster, err := NewCutoverPeerRoster(
		context.Background(),
		blockCounter,
		clock,
		1000,
		newFakeMetrics(),
	)
	if err != nil {
		t.Fatalf("construction should tolerate a clock error, got: [%v]", err)
	}
	t.Cleanup(roster.Close)

	snapshot := roster.Snapshot()
	if snapshot.ClockAvailable {
		t.Error(
			"counter height must not make the roster ready when the " +
				"authoritative clock is unavailable",
		)
	}
	if snapshot.CurrentBlock != 0 {
		t.Errorf(
			"counter height must not seed current block; got [%d]",
			snapshot.CurrentBlock,
		)
	}
}

func TestCutoverPeerRoster_EntryLogIncludesResolvedCutoverBlock(t *testing.T) {
	const (
		cutoverBlock = uint64(1000)
		currentBlock = uint64(1005)
	)

	expected := fmt.Sprintf(
		"protocol legacy peer entered cutover roster "+
			"[operator=%s] [protocol=%s] [member=%d] "+
			"[firstSeenBlock=%d] [cutoverBlock=%d]",
		validAddress(1),
		"tbtc-dkg",
		3,
		currentBlock,
		cutoverBlock,
	)

	entries := captureRosterLogs(t, func() {
		blockCounter := newFakeBlockCounter(currentBlock)
		roster, err := NewCutoverPeerRoster(
			context.Background(),
			blockCounter,
			testRosterAuthoritativeClock{blockCounter},
			1000,
			newFakeMetrics(),
			WithCutoverSchedule(Schedule{CutoverBlock: cutoverBlock}),
		)
		if err != nil {
			t.Fatalf("failed to construct roster: [%v]", err)
		}

		observeStraggler(roster, "tbtc-dkg", 3, validAddress(1))
		roster.Close()
	})

	for _, entry := range entries {
		if entry.Message == expected {
			return
		}
	}

	t.Errorf(
		"expected roster entry log [%s], got: %+v",
		expected,
		entries,
	)
}

func TestCutoverPeerRoster_ObserveLegacyRecordsStraggler(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)

	observeStraggler(roster, "tbtc-dkg", 3, validAddress(1))

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(snapshot.Peers))
	}
	peer := snapshot.Peers[0]
	if peer.OperatorAddress != "0x"+fmt.Sprintf("%040x", 1) {
		t.Errorf("unexpected operator address: %s", peer.OperatorAddress)
	}
	if len(peer.Sightings) != 1 {
		t.Fatalf("expected 1 sighting, got %d", len(peer.Sightings))
	}
	if peer.Sightings[0].FirstSeenBlock != 500 || peer.Sightings[0].LastSeenBlock != 500 {
		t.Errorf("unexpected sighting blocks: %+v", peer.Sightings[0])
	}
}

func TestCutoverPeerRoster_ObserveLegacyStampsFreshBlockAtCutover(t *testing.T) {
	// The roster's cached height is only refreshed by the 30-second sweep loop.
	// A straggler observed the instant the chain reaches the cutover block C must
	// be stamped at C, not the stale C-1 the cache still holds, or the central
	// fleet collector would discard it as pre-cutover evidence.
	const cutover = 1000
	roster, bc, _ := newTestRoster(t, cutover-1, 1000)

	// The chain advances to C, but no sweep has run yet: the cached height is
	// still C-1.
	bc.set(cutover, nil)

	observeStraggler(roster, "tbtc-dkg", 3, validAddress(1))

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(snapshot.Peers))
	}
	sighting := snapshot.Peers[0].Sightings[0]
	if sighting.FirstSeenBlock != cutover || sighting.LastSeenBlock != cutover {
		t.Errorf(
			"straggler must be stamped at the fresh height C=%d, got first=%d last=%d",
			cutover, sighting.FirstSeenBlock, sighting.LastSeenBlock,
		)
	}
	if snapshot.Peers[0].FirstSeenBlock != cutover {
		t.Errorf(
			"peer first-seen must reflect the fresh height C=%d, got %d",
			cutover, snapshot.Peers[0].FirstSeenBlock,
		)
	}
}

func TestCutoverPeerRoster_ObserveLegacyClockErrorRetainsStateMintsNothing(t *testing.T) {
	// On a clock-read failure at observation time the roster must retain existing
	// state and mint NO new sighting: stamping a sighting with the stale cached
	// height risks placing a genuinely post-cutover observation below C, where the
	// central fleet collector would discard it as pre-cutover evidence. An
	// existing entry (recorded while the clock was healthy) is preserved unchanged.
	const seeded = 900
	roster, bc, _ := newTestRoster(t, seeded, 1000)

	// First observe a straggler while the clock is healthy so there is existing
	// state to preserve.
	observeStraggler(roster, "p", 1, validAddress(1))
	before := roster.Snapshot()
	if len(before.Peers) != 1 {
		t.Fatalf("precondition: expected 1 peer recorded while healthy, got %d", len(before.Peers))
	}

	// Now a different straggler is observed at the instant the clock fails.
	bc.set(0, fmt.Errorf("clock unavailable"))
	observeStraggler(roster, "p", 1, validAddress(2))

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf(
			"a clock error must mint no new sighting; expected the 1 existing peer, got %d",
			len(snapshot.Peers),
		)
	}
	if snapshot.Peers[0].OperatorAddress != before.Peers[0].OperatorAddress {
		t.Errorf(
			"existing state must be retained unchanged on a clock error: got %s, want %s",
			snapshot.Peers[0].OperatorAddress, before.Peers[0].OperatorAddress,
		)
	}
	if snapshot.ClockAvailable {
		t.Error("expected the clock to be marked unavailable after a failed read")
	}
}

func TestCutoverPeerRoster_ObserveLegacyFiltersNonStragglers(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)

	// Not security-v2 -> ignored.
	roster.ObserveLegacy("p", 1, validAddress(1), ModeLegacy,
		announcer.SessionIDFormatHardenedDKG, announcer.SessionIDFormatLegacy)
	// Expected format not hardened -> ignored.
	roster.ObserveLegacy("p", 1, validAddress(2), ModeSecurityV2,
		announcer.SessionIDFormatLegacy, announcer.SessionIDFormatLegacy)
	// Observed format not legacy (e.g. a hardened peer) -> ignored.
	roster.ObserveLegacy("p", 1, validAddress(3), ModeSecurityV2,
		announcer.SessionIDFormatHardenedDKG, announcer.SessionIDFormatHardenedDKG)
	// Member index zero -> ignored.
	roster.ObserveLegacy("p", 0, validAddress(4), ModeSecurityV2,
		announcer.SessionIDFormatHardenedDKG, announcer.SessionIDFormatLegacy)
	// Invalid operator address -> ignored.
	roster.ObserveLegacy("p", 1, chain.Address("not-an-address"), ModeSecurityV2,
		announcer.SessionIDFormatHardenedDKG, announcer.SessionIDFormatLegacy)

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 0 {
		t.Fatalf("expected no peers recorded, got %d: %+v", len(snapshot.Peers), snapshot.Peers)
	}
}

func TestCutoverPeerRoster_HardenedObservationDoesNotClear(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)

	observeStraggler(roster, "p", 1, validAddress(1))
	// A later hardened observation for the same operator must not clear it.
	roster.ObserveLegacy("p", 1, validAddress(1), ModeSecurityV2,
		announcer.SessionIDFormatHardenedDKG, announcer.SessionIDFormatHardenedDKG)

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected the legacy entry to be retained, got %d peers", len(snapshot.Peers))
	}
}

func TestCutoverPeerRoster_DedupAcrossSeatsAndReporters(t *testing.T) {
	roster, _, metrics := newTestRoster(t, 500, 1000)

	address := validAddress(7)

	// The same operator observed at multiple seats (member indexes) and via
	// repeated retransmissions of the same seat.
	observeStraggler(roster, "tbtc-dkg", 3, address)
	observeStraggler(roster, "tbtc-dkg", 3, address) // retransmission, dedup
	observeStraggler(roster, "tbtc-dkg", 5, address) // different seat
	observeStraggler(roster, "tbtc-signing", 3, address)

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected 1 deduplicated operator, got %d", len(snapshot.Peers))
	}
	// (dkg,3), (dkg,5), (signing,3) => 3 distinct sightings.
	if got := len(snapshot.Peers[0].Sightings); got != 3 {
		t.Fatalf("expected 3 distinct sightings, got %d", got)
	}
	if metrics.counter(metricLegacyPeerAdditionsTotal) != 1 {
		t.Errorf(
			"expected exactly one operator addition, got %v",
			metrics.counter(metricLegacyPeerAdditionsTotal),
		)
	}
}

func TestCutoverPeerRoster_AddressNormalization(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)

	base := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// The same address in different spellings must collapse to one entry.
	observeStraggler(roster, "p", 1, chain.Address("0x"+base))
	observeStraggler(roster, "p", 1, chain.Address("0X"+base))
	observeStraggler(roster, "p", 1, chain.Address(base))
	observeStraggler(roster, "p", 1, chain.Address("  0x"+base+"  "))
	// Uppercase hex must also normalize to lowercase.
	upper := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	observeStraggler(roster, "p", 1, chain.Address(upper))

	snapshot := roster.Snapshot()
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected 1 normalized operator, got %d", len(snapshot.Peers))
	}
	if snapshot.Peers[0].OperatorAddress != "0x"+base {
		t.Errorf("unexpected normalized address: %s", snapshot.Peers[0].OperatorAddress)
	}
}

func TestCutoverPeerRoster_Retention(t *testing.T) {
	const initialBlock = 1000
	const retention = 100

	roster, _, _ := newTestRoster(t, initialBlock, retention)
	observeStraggler(roster, "p", 1, validAddress(1))

	// At exactly lastSeen+retention the entry is still retained.
	roster.Sweep(initialBlock + retention)
	if got := len(roster.Snapshot().Peers); got != 1 {
		t.Fatalf("expected entry retained at the retention boundary, got %d peers", got)
	}

	// One block past the window it is evicted.
	roster.Sweep(initialBlock + retention + 1)
	if got := len(roster.Snapshot().Peers); got != 0 {
		t.Fatalf("expected entry evicted past the retention window, got %d peers", got)
	}
}

func TestCutoverPeerRoster_ClockFailureRetainsAndEvictsNothing(t *testing.T) {
	roster, bc, _ := newTestRoster(t, 1000, 100)
	observeStraggler(roster, "p", 1, validAddress(1))

	// A clock failure during a poll must retain state and evict nothing, even
	// though the (unread) height would be well past the retention window.
	bc.set(1_000_000, fmt.Errorf("clock unavailable"))
	roster.pollAndSweep()

	snapshot := roster.Snapshot()
	if snapshot.ClockAvailable {
		t.Error("expected clock to be marked unavailable")
	}
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected entry retained on clock failure, got %d peers", len(snapshot.Peers))
	}

	// When the clock recovers, normal sweeping resumes.
	bc.set(1_000_000, nil)
	roster.pollAndSweep()
	if got := len(roster.Snapshot().Peers); got != 0 {
		t.Fatalf("expected entry evicted after clock recovery, got %d peers", got)
	}
}

func TestCutoverPeerRoster_RestartStartsEmpty(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)
	observeStraggler(roster, "p", 1, validAddress(1))
	roster.Close()

	// The node-local roster is in-memory: a fresh process starts empty.
	fresh, _, _ := newTestRoster(t, 500, 1000)
	if got := len(fresh.Snapshot().Peers); got != 0 {
		t.Fatalf("expected a fresh roster to be empty, got %d peers", got)
	}
}

func TestCutoverPeerRoster_47From3Versus47From47(t *testing.T) {
	// 47 sightings distributed over 3 operator addresses -> 3 operators that
	// together carry all 47 sightings.
	rosterA, _, _ := newTestRoster(t, 500, 100000)
	counts := []int{16, 16, 15} // 47 total
	for opIndex, seats := range counts {
		for seat := 1; seat <= seats; seat++ {
			observeStraggler(rosterA, "p", group.MemberIndex(seat), validAddress(opIndex))
		}
	}
	snapA := rosterA.Snapshot()
	if len(snapA.Peers) != 3 {
		t.Fatalf("expected 3 operators, got %d", len(snapA.Peers))
	}
	totalSightings := 0
	for _, p := range snapA.Peers {
		totalSightings += len(p.Sightings)
	}
	if totalSightings != 47 {
		t.Fatalf("expected 47 total sightings across 3 operators, got %d", totalSightings)
	}

	// 47 sightings from 47 distinct addresses -> 47 operators.
	rosterB, _, _ := newTestRoster(t, 500, 100000)
	for i := 0; i < 47; i++ {
		observeStraggler(rosterB, "p", 1, validAddress(1000+i))
	}
	snapB := rosterB.Snapshot()
	if len(snapB.Peers) != 47 {
		t.Fatalf("expected 47 operators, got %d", len(snapB.Peers))
	}
}

func TestCutoverPeerRoster_DeterministicSnapshotJSON(t *testing.T) {
	build := func(order []int) []byte {
		t.Helper()
		roster, _, _ := newTestRoster(t, 1000, 100000)
		for _, i := range order {
			observeStraggler(roster, "tbtc-dkg", group.MemberIndex(i+1), validAddress(i))
			observeStraggler(roster, "tbtc-signing", group.MemberIndex(i+1), validAddress(i))
		}
		data, err := json.Marshal(roster.Snapshot())
		if err != nil {
			t.Fatalf("failed to marshal snapshot: [%v]", err)
		}
		return data
	}

	forward := build([]int{0, 1, 2, 3, 4})
	shuffled := build([]int{3, 1, 4, 0, 2})

	if string(forward) != string(shuffled) {
		t.Errorf(
			"snapshot JSON is not deterministic across insertion orders\nforward:  %s\nshuffled: %s",
			forward,
			shuffled,
		)
	}
}

func TestCutoverPeerRoster_Metrics(t *testing.T) {
	const initialBlock = 1000
	const retention = 100

	roster, _, metrics := newTestRoster(t, initialBlock, retention)

	observeStraggler(roster, "p", 1, validAddress(1))
	if metrics.gauge(metricLegacyPeersCurrent) != 1 {
		t.Errorf("expected peers_current=1, got %v", metrics.gauge(metricLegacyPeersCurrent))
	}
	if metrics.counter(metricLegacyPeerAdditionsTotal) != 1 {
		t.Errorf("expected additions_total=1, got %v", metrics.counter(metricLegacyPeerAdditionsTotal))
	}
	if metrics.gauge(metricLegacyPeerRosterRevision) < 1 {
		t.Errorf("expected roster_revision>=1, got %v", metrics.gauge(metricLegacyPeerRosterRevision))
	}

	// Oldest age = current block - oldest first-seen block.
	roster.Sweep(initialBlock + 5)
	if metrics.gauge(metricLegacyPeerOldestAgeBlocks) != 5 {
		t.Errorf("expected oldest_age_blocks=5, got %v", metrics.gauge(metricLegacyPeerOldestAgeBlocks))
	}

	// Evict and confirm counters/gauges.
	roster.Sweep(initialBlock + retention + 1)
	if metrics.counter(metricLegacyPeerEvictionsTotal) != 1 {
		t.Errorf("expected evictions_total=1, got %v", metrics.counter(metricLegacyPeerEvictionsTotal))
	}
	if metrics.gauge(metricLegacyPeersCurrent) != 0 {
		t.Errorf("expected peers_current=0 after eviction, got %v", metrics.gauge(metricLegacyPeersCurrent))
	}
}

func TestCutoverPeerRoster_CloseIdempotent(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)
	roster.Close()
	roster.Close() // must not panic or block
}

// TestCutoverPeerRoster_ConcurrentCloseSafe races two Close calls on a real
// roster with a live background sweep loop. Each Close joins the sweep loop
// under sync.Once, so both concurrent callers must return without panicking,
// double-closing the join channel, or blocking forever on the join; a later
// Close after shutdown must remain a safe no-op.
func TestCutoverPeerRoster_ConcurrentCloseSafe(t *testing.T) {
	roster, _, _ := newTestRoster(t, 500, 1000)

	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		roster.Close()
		close(firstDone)
	}()
	go func() {
		roster.Close()
		close(secondDone)
	}()

	for _, done := range []<-chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal(
				"a concurrent Close did not return; Close did not safely " +
					"join the sweep loop under the double-close overlap",
			)
		}
	}

	thirdDone := make(chan struct{})
	go func() {
		roster.Close()
		close(thirdDone)
	}()
	select {
	case <-thirdDone:
	case <-time.After(5 * time.Second):
		t.Fatal("a Close after shutdown blocked; Close is not idempotent")
	}
}

func TestCutoverPeerRoster_RunLogsEmptySnapshotDuringEvidenceWindowAtCadence(
	t *testing.T,
) {
	const currentBlock = uint64(1005)

	expected := fmt.Sprintf(
		"protocol cutover peer roster snapshot [currentBlock=%d] "+
			"[clockAvailable=true] [legacyPeers=0] "+
			"[oldestFirstSeenBlock=0] [rosterRevision=0]",
		currentBlock,
	)

	entries := captureRosterLogsWithObserver(t, func(
		observed <-chan capturedRosterLogEntry,
	) {
		evidenceWindow := NewCutoverEvidenceWindowSignal()
		evidenceWindow.SetActive(true)
		clock := newMutableRosterClock(fixedTestTime)
		ticker := newManualRosterTicker()
		roster, _ := newRunLoopTestRoster(
			t,
			currentBlock,
			1000,
			clock,
			ticker,
			WithCutoverEvidenceWindowSignal(evidenceWindow),
		)

		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(rosterSnapshotLogInterval-time.Second),
		)
		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(rosterSnapshotLogInterval),
		)
		waitForRosterLog(t, observed, expected)
		roster.Close()

		select {
		case <-ticker.stopped:
		default:
			t.Error("roster run loop did not stop its cadence source")
		}
	})

	assertRosterLogCount(t, entries, expected, 1)
}

func TestCutoverPeerRoster_RunLogsNonemptySnapshotAfterCutover(
	t *testing.T,
) {
	const (
		cutoverBlock = uint64(1000)
		currentBlock = cutoverBlock + 5
	)

	expected := fmt.Sprintf(
		"protocol cutover peer roster snapshot [currentBlock=%d] "+
			"[clockAvailable=true] [legacyPeers=1] "+
			"[oldestFirstSeenBlock=%d] [rosterRevision=1]",
		currentBlock,
		currentBlock,
	)

	entries := captureRosterLogsWithObserver(t, func(
		observed <-chan capturedRosterLogEntry,
	) {
		evidenceWindow := NewCutoverEvidenceWindowSignal()
		clock := newMutableRosterClock(fixedTestTime)
		ticker := newManualRosterTicker()
		roster, _ := newRunLoopTestRoster(
			t,
			currentBlock,
			1000,
			clock,
			ticker,
			WithCutoverSchedule(Schedule{CutoverBlock: cutoverBlock}),
			WithCutoverEvidenceWindowSignal(evidenceWindow),
		)

		observeStraggler(roster, "tbtc-dkg", 3, validAddress(1))
		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(rosterSnapshotLogInterval),
		)
		waitForRosterLog(t, observed, expected)
		roster.Close()
	})

	assertRosterLogCount(t, entries, expected, 1)
}

func TestCutoverPeerRoster_RunLogsClockUnavailableSnapshotDuringEvidenceWindow(
	t *testing.T,
) {
	const lastCurrentBlock = uint64(900)

	expected := fmt.Sprintf(
		"protocol cutover peer roster snapshot [currentBlock=%d] "+
			"[clockAvailable=false] [legacyPeers=0] "+
			"[oldestFirstSeenBlock=0] [rosterRevision=0]",
		lastCurrentBlock,
	)

	entries := captureRosterLogsWithObserver(t, func(
		observed <-chan capturedRosterLogEntry,
	) {
		evidenceWindow := NewCutoverEvidenceWindowSignal()
		evidenceWindow.SetActive(true)
		clock := newMutableRosterClock(fixedTestTime)
		ticker := newManualRosterTicker()
		roster, blockCounter := newRunLoopTestRoster(
			t,
			lastCurrentBlock,
			1000,
			clock,
			ticker,
			WithCutoverEvidenceWindowSignal(evidenceWindow),
		)

		blockCounter.set(0, fmt.Errorf("clock unavailable"))
		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(rosterSnapshotLogInterval),
		)
		waitForRosterLog(t, observed, expected)
		roster.Close()
	})

	assertRosterLogCount(t, entries, expected, 1)
}

func TestCutoverPeerRoster_RunHonorsEvidenceWindowOnOffAtCadence(t *testing.T) {
	const currentBlock = uint64(1005)

	expected := fmt.Sprintf(
		"protocol cutover peer roster snapshot [currentBlock=%d] "+
			"[clockAvailable=true] [legacyPeers=0] "+
			"[oldestFirstSeenBlock=0] [rosterRevision=0]",
		currentBlock,
	)

	entries := captureRosterLogsWithObserver(t, func(
		observed <-chan capturedRosterLogEntry,
	) {
		evidenceWindow := NewCutoverEvidenceWindowSignal()
		clock := newMutableRosterClock(fixedTestTime)
		ticker := newManualRosterTicker()
		roster, _ := newRunLoopTestRoster(
			t,
			currentBlock,
			1000,
			clock,
			ticker,
			WithCutoverEvidenceWindowSignal(evidenceWindow),
		)

		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(rosterSnapshotLogInterval),
		)
		if !evidenceWindow.SetActive(true) {
			t.Error("expected opening the evidence window to change its state")
		}
		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(2*rosterSnapshotLogInterval),
		)
		waitForRosterLog(t, observed, expected)
		if !evidenceWindow.SetActive(false) {
			t.Error("expected closing the evidence window to change its state")
		}
		driveRosterRunLoopTick(
			t,
			clock,
			ticker,
			fixedTestTime.Add(3*rosterSnapshotLogInterval),
		)
		roster.Close()
	})

	assertRosterLogCount(t, entries, expected, 1)
}

func TestCutoverEvidenceWindowSignal_HoldActive(t *testing.T) {
	evidenceWindow := NewCutoverEvidenceWindowSignal()

	if evidenceWindow.Active() {
		t.Fatal("a new evidence window must be inactive")
	}
	if !evidenceWindow.HoldActive() {
		t.Error("holding an inactive evidence window should change its state")
	}
	if !evidenceWindow.Active() {
		t.Fatal("a held evidence window must be active")
	}
	if evidenceWindow.SetActive(false) {
		t.Error("a held evidence window must reject a close")
	}
	if !evidenceWindow.Active() {
		t.Fatal("a rejected close must leave the evidence window active")
	}
}

func TestCutoverEvidenceWindowSignal_ConcurrentAccess(t *testing.T) {
	evidenceWindow := NewCutoverEvidenceWindowSignal()

	var workers sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()

			for iteration := 0; iteration < 100; iteration++ {
				evidenceWindow.SetActive((worker+iteration)%2 == 0)
				_ = evidenceWindow.Active()
			}
		}(worker)
	}
	workers.Wait()

	evidenceWindow.HoldActive()
	if !evidenceWindow.Active() {
		t.Fatal("the evidence window must remain active after a concurrent hold")
	}
}

func assertRosterLogCount(
	t *testing.T,
	entries []capturedRosterLogEntry,
	expected string,
	expectedCount int,
) {
	t.Helper()

	actualCount := 0
	for _, entry := range entries {
		if entry.Message == expected {
			actualCount++
		}
	}
	if actualCount != expectedCount {
		t.Errorf(
			"expected roster log [%s] %d time(s), got %d in: %+v",
			expected,
			expectedCount,
			actualCount,
			entries,
		)
	}
}
