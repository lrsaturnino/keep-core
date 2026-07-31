package participation

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-log/v2"
	"golang.org/x/time/rate"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

var rosterLogger = log.Logger("keep-participation")

// CutoverPeerRosterSchemaVersion is the schema version of the node-local
// cutover peer roster snapshot. It is bumped whenever the snapshot JSON shape
// changes incompatibly.
const CutoverPeerRosterSchemaVersion uint32 = 1

// maxSafeMetricInteger is the largest integer that a float64 (the gauge/counter
// backing type) can represent exactly. Retention values above it cannot be
// projected to metrics without precision loss and are rejected at construction.
const maxSafeMetricInteger = uint64(1) << 53

// The roster reports through the client-info performance registry, which adds
// the "performance_" application prefix. These are therefore the internal
// (unprefixed) names; they are exposed as performance_announcer_legacy_peer*.
// Referencing the clientinfo constants keeps a single source of truth for the
// exact exported metric names.
const (
	metricLegacyPeersCurrent        = clientinfo.MetricAnnouncerLegacyPeersCurrent
	metricLegacyPeerOldestAgeBlocks = clientinfo.MetricAnnouncerLegacyPeerOldestAgeBlocks
	metricLegacyPeerRosterRevision  = clientinfo.MetricAnnouncerLegacyPeerRosterRevision
	metricLegacyPeerAdditionsTotal  = clientinfo.MetricAnnouncerLegacyPeerAdditionsTotal
	metricLegacyPeerEvictionsTotal  = clientinfo.MetricAnnouncerLegacyPeerEvictionsTotal
)

const (
	// rosterSweepInterval is how often the background loop reads the chain clock
	// to evict stale entries and refresh metrics.
	rosterSweepInterval = 30 * time.Second
	// rosterSnapshotLogInterval is how often a required roster snapshot is
	// logged at INFO.
	rosterSnapshotLogInterval = 5 * time.Minute
)

// CutoverPeerSighting is a single deduplicated observation of a legacy peer at a
// specific group member position within a specific protocol. It never carries
// raw session identifiers or other sensitive material.
type CutoverPeerSighting struct {
	ProtocolID     string            `json:"protocol"`
	MemberIndex    group.MemberIndex `json:"member_index"`
	FirstSeenBlock uint64            `json:"first_seen_block"`
	LastSeenBlock  uint64            `json:"last_seen_block"`
	FirstSeenAt    time.Time         `json:"first_seen_at"`
	LastSeenAt     time.Time         `json:"last_seen_at"`
}

// CutoverPeerEntry is the deduplicated per-operator roster entry. All sightings
// for one operator address — across seats, protocols, and reporters — collapse
// into a single entry with multiple sightings.
type CutoverPeerEntry struct {
	OperatorAddress string                `json:"operator_address"`
	FirstSeenBlock  uint64                `json:"first_seen_block"`
	LastSeenBlock   uint64                `json:"last_seen_block"`
	Sightings       []CutoverPeerSighting `json:"sightings"`
}

// CutoverPeerRosterSnapshot is a deterministic, point-in-time view of the
// node-local roster suitable for diagnostics exposure and evidence capture.
type CutoverPeerRosterSnapshot struct {
	SchemaVersion    uint32             `json:"schema_version"`
	ProcessStartedAt time.Time          `json:"process_started_at"`
	GeneratedAt      time.Time          `json:"generated_at"`
	CurrentBlock     uint64             `json:"current_block"`
	ClockAvailable   bool               `json:"clock_available"`
	RetentionBlocks  uint64             `json:"retention_blocks"`
	RosterRevision   uint64             `json:"roster_revision"`
	Peers            []CutoverPeerEntry `json:"peers"`
}

// CutoverRosterMetricsRecorder is the minimal metrics sink the roster needs. It
// is satisfied by the client-info performance metrics registry.
type CutoverRosterMetricsRecorder interface {
	IncrementCounter(name string, value float64)
	SetGauge(name string, value float64)
}

// CutoverEvidenceWindowSignal is an operator-controlled, process-local signal
// indicating that periodic cutover roster logs are being captured as
// go/no-go or rollback evidence. It controls only whether an empty roster is
// logged: it is never consulted by Gate, ObserveLegacy, or any protocol-mode
// decision.
//
// The zero value is an inactive, usable signal.
type CutoverEvidenceWindowSignal struct {
	mutex      sync.RWMutex
	active     bool
	heldActive bool
}

// NewCutoverEvidenceWindowSignal creates an inactive evidence-window signal.
func NewCutoverEvidenceWindowSignal() *CutoverEvidenceWindowSignal {
	return &CutoverEvidenceWindowSignal{}
}

// Active reports whether periodic roster logs must include an empty snapshot.
func (s *CutoverEvidenceWindowSignal) Active() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.active
}

// SetActive opens or closes the evidence window and reports whether its state
// changed. A signal held active for rollback cannot be closed.
func (s *CutoverEvidenceWindowSignal) SetActive(active bool) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !active && s.heldActive {
		return false
	}
	if s.active == active {
		return false
	}

	s.active = active
	return true
}

// HoldActive opens the evidence window irreversibly for this process and
// reports whether its visible state changed. The shutdown controller uses this
// before quiescence so a later operator close signal cannot suppress rollback
// evidence while the process is draining.
func (s *CutoverEvidenceWindowSignal) HoldActive() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	changed := !s.active
	s.active = true
	s.heldActive = true
	return changed
}

type cutoverPeerRosterOptions struct {
	cutoverBlock   uint64
	evidenceWindow *CutoverEvidenceWindowSignal
	tickerFactory  cutoverPeerRosterTickerFactory
}

// CutoverPeerRosterOption configures immutable cutover context used by the
// node-local roster's observability contract.
type CutoverPeerRosterOption func(*cutoverPeerRosterOptions) error

// cutoverPeerRosterTicker is the narrow cadence source consumed by the roster
// loop. Keeping the ticker behind this seam lets the production run path be
// exercised deterministically without shortening the five-minute evidence
// contract or adding sleeps to tests.
type cutoverPeerRosterTicker interface {
	Ticks() <-chan time.Time
	MarkProcessed()
	Stop()
}

type cutoverPeerRosterTickerFactory func(time.Duration) cutoverPeerRosterTicker

type wallClockCutoverPeerRosterTicker struct {
	ticker *time.Ticker
}

func newWallClockCutoverPeerRosterTicker(
	interval time.Duration,
) cutoverPeerRosterTicker {
	return &wallClockCutoverPeerRosterTicker{
		ticker: time.NewTicker(interval),
	}
}

func (t *wallClockCutoverPeerRosterTicker) Ticks() <-chan time.Time {
	return t.ticker.C
}

func (t *wallClockCutoverPeerRosterTicker) MarkProcessed() {}

func (t *wallClockCutoverPeerRosterTicker) Stop() {
	t.ticker.Stop()
}

// withCutoverPeerRosterTickerFactory replaces the wall-clock cadence source.
// It is intentionally package-private: production always uses real time while
// same-package tests drive the exact run-loop boundary deterministically.
func withCutoverPeerRosterTickerFactory(
	factory cutoverPeerRosterTickerFactory,
) CutoverPeerRosterOption {
	return func(options *cutoverPeerRosterOptions) error {
		if factory == nil {
			return fmt.Errorf("cutover peer roster ticker factory is required")
		}

		options.tickerFactory = factory
		return nil
	}
}

// WithCutoverSchedule gives the roster the exact resolved schedule supplied to
// the process participation gate. The roster does not use the schedule to
// classify or authorize observations; it carries C only so an entry log names
// the cutover boundary the observation is evidence for.
func WithCutoverSchedule(schedule Schedule) CutoverPeerRosterOption {
	return func(options *cutoverPeerRosterOptions) error {
		if err := validateMetricProjectable(schedule.CutoverBlock); err != nil {
			return fmt.Errorf("invalid roster cutover schedule: [%w]", err)
		}

		options.cutoverBlock = schedule.CutoverBlock
		return nil
	}
}

// WithCutoverEvidenceWindowSignal supplies the process-local evidence-window
// signal observed by the roster's periodic logger. The signal has no effect on
// roster contents, cutover classification, or protocol authorization.
func WithCutoverEvidenceWindowSignal(
	signal *CutoverEvidenceWindowSignal,
) CutoverPeerRosterOption {
	return func(options *cutoverPeerRosterOptions) error {
		if signal == nil {
			return fmt.Errorf("cutover evidence-window signal is required")
		}

		options.evidenceWindow = signal
		return nil
	}
}

type sightingKey struct {
	protocolID  string
	memberIndex group.MemberIndex
}

type peerState struct {
	operatorAddress string
	firstSeenBlock  uint64
	lastSeenBlock   uint64
	firstSeenAt     time.Time
	lastSeenAt      time.Time
	sightings       map[sightingKey]*CutoverPeerSighting
}

// CutoverPeerRoster is a node-local, deduplicated record of post-cutover legacy
// peer sightings, keyed by normalized operator address. A later hardened
// observation never clears an entry, because it does not prove every instance
// for that operator is current. Eviction means only "not recently observed".
type CutoverPeerRoster struct {
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	loopDone  chan struct{}
	ticker    cutoverPeerRosterTicker

	blockCounter    chain.BlockCounter
	retentionBlocks uint64
	cutoverBlock    uint64
	evidenceWindow  *CutoverEvidenceWindowSignal
	metrics         CutoverRosterMetricsRecorder
	clock           func() time.Time

	processStartedAt time.Time

	logLimiter *rate.Limiter

	mu             sync.Mutex
	peers          map[string]*peerState
	rosterRevision uint64
	currentBlock   uint64
	clockAvailable bool
}

// NewCutoverPeerRoster constructs a roster. It rejects zero or precision-unsafe
// retention, synchronously reads the chain clock to seed the current block,
// initializes all fixed metrics to zero, and starts one context-bound sweep
// loop. The roster is intended to be constructed unconditionally, including
// when client-info diagnostics are disabled. A process with an active cutover
// schedule supplies WithCutoverSchedule using the same resolved Schedule given
// to its Gate; omitting it represents the developer-only disabled schedule.
func NewCutoverPeerRoster(
	ctx context.Context,
	blockCounter chain.BlockCounter,
	retentionBlocks uint64,
	metrics CutoverRosterMetricsRecorder,
	options ...CutoverPeerRosterOption,
) (*CutoverPeerRoster, error) {
	return newCutoverPeerRoster(
		ctx,
		blockCounter,
		retentionBlocks,
		metrics,
		time.Now,
		options...,
	)
}

// newCutoverPeerRoster is the clock-injecting constructor. The clock is fixed
// before the background loop starts, so callers (including tests) may supply a
// deterministic clock without racing the loop.
func newCutoverPeerRoster(
	ctx context.Context,
	blockCounter chain.BlockCounter,
	retentionBlocks uint64,
	metrics CutoverRosterMetricsRecorder,
	clock func() time.Time,
	optionFunctions ...CutoverPeerRosterOption,
) (*CutoverPeerRoster, error) {
	options := &cutoverPeerRosterOptions{
		evidenceWindow: NewCutoverEvidenceWindowSignal(),
		tickerFactory:  newWallClockCutoverPeerRosterTicker,
	}
	for _, option := range optionFunctions {
		if option == nil {
			return nil, fmt.Errorf("nil cutover peer roster option")
		}
		if err := option(options); err != nil {
			return nil, fmt.Errorf(
				"invalid cutover peer roster option: [%w]",
				err,
			)
		}
	}

	if retentionBlocks == 0 {
		return nil, fmt.Errorf("retention blocks must be non-zero")
	}
	if retentionBlocks > maxSafeMetricInteger {
		return nil, fmt.Errorf(
			"retention blocks [%d] exceeds the maximum precisely projectable "+
				"metric value [%d]",
			retentionBlocks,
			maxSafeMetricInteger,
		)
	}
	if blockCounter == nil {
		return nil, fmt.Errorf("block counter is required")
	}
	if metrics == nil {
		return nil, fmt.Errorf("metrics recorder is required")
	}

	ticker := options.tickerFactory(rosterSweepInterval)
	if ticker == nil {
		return nil, fmt.Errorf("cutover peer roster ticker is required")
	}

	loopCtx, cancel := context.WithCancel(ctx)

	roster := &CutoverPeerRoster{
		ctx:             loopCtx,
		cancel:          cancel,
		loopDone:        make(chan struct{}),
		ticker:          ticker,
		blockCounter:    blockCounter,
		retentionBlocks: retentionBlocks,
		cutoverBlock:    options.cutoverBlock,
		evidenceWindow:  options.evidenceWindow,
		metrics:         metrics,
		clock:           clock,
		logLimiter:      rate.NewLimiter(rate.Every(30*time.Second), 5),
		peers:           make(map[string]*peerState),
	}

	roster.processStartedAt = roster.clock()

	// Synchronously seed the current block from the chain clock. A clock error
	// here is tolerated: the roster is still constructed with the clock marked
	// unavailable, so it can be built unconditionally beside the gate.
	if currentBlock, err := blockCounter.CurrentBlock(); err != nil {
		rosterLogger.Warnf(
			"cutover peer roster could not read the chain clock at "+
				"construction: [%v]; continuing with the clock marked "+
				"unavailable",
			err,
		)
		roster.clockAvailable = false
	} else {
		roster.currentBlock = currentBlock
		roster.clockAvailable = true
	}

	roster.initMetrics()

	go roster.run()

	return roster, nil
}

// initMetrics registers every fixed metric at its zero value so scrapers see a
// complete metric set from the start.
func (r *CutoverPeerRoster) initMetrics() {
	r.metrics.SetGauge(metricLegacyPeersCurrent, 0)
	r.metrics.SetGauge(metricLegacyPeerOldestAgeBlocks, 0)
	r.metrics.SetGauge(metricLegacyPeerRosterRevision, 0)
	r.metrics.IncrementCounter(metricLegacyPeerAdditionsTotal, 0)
	r.metrics.IncrementCounter(metricLegacyPeerEvictionsTotal, 0)
}

func (r *CutoverPeerRoster) run() {
	defer close(r.loopDone)
	defer r.ticker.Stop()

	lastSnapshotLog := r.processStartedAt

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.ticker.Ticks():
			r.pollAndSweep()

			now := r.clock()
			if now.Sub(lastSnapshotLog) >= rosterSnapshotLogInterval {
				lastSnapshotLog = now
				r.logSnapshotIfRequired()
			}
			r.ticker.MarkProcessed()
		}
	}
}

// pollAndSweep reads the chain clock and either sweeps at the new height or, on
// a clock error, retains all state and evicts nothing.
func (r *CutoverPeerRoster) pollAndSweep() {
	currentBlock, err := r.blockCounter.CurrentBlock()
	if err != nil {
		r.markClockUnavailable()
		return
	}
	r.Sweep(currentBlock)
}

func (r *CutoverPeerRoster) markClockUnavailable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clockAvailable = false
}

// ObserveLegacy records a single post-cutover legacy sighting. Only genuine
// stragglers are recorded: the local permit must be security-v2, the local
// (expected) format hardened, and the observed peer format legacy. Everything
// else — including a hardened observation — is ignored. Observations are
// deduplicated by operator address and by (protocol, member index).
func (r *CutoverPeerRoster) ObserveLegacy(
	protocolID string,
	memberIndex group.MemberIndex,
	operatorAddress chain.Address,
	permitMode ProtocolMode,
	expectedFormat announcer.SessionIDFormat,
	observedFormat announcer.SessionIDFormat,
) {
	if permitMode != ModeSecurityV2 {
		return
	}
	if !expectedFormat.IsHardened() {
		return
	}
	if observedFormat != announcer.SessionIDFormatLegacy {
		return
	}
	// Member indexes are 1-based group positions; index 0 is never valid.
	if memberIndex == 0 {
		return
	}

	normalized, ok := normalizeOperatorAddress(operatorAddress)
	if !ok {
		return
	}

	// Stamp the sighting with a synchronously read chain height rather than the
	// height cached by the 30-second sweep loop. Immediately after the cutover
	// block C the cached height can still lag below C; a straggler stamped below C
	// would be discarded by the central fleet collector as pre-cutover evidence,
	// losing a genuine post-cutover legacy sighting. The read happens outside the
	// lock so a slow chain call never blocks Snapshot/Sweep.
	currentBlock, clockErr := r.blockCounter.CurrentBlock()
	now := r.clock()

	r.mu.Lock()
	defer r.mu.Unlock()

	if clockErr != nil {
		// On a clock-read failure, retain existing roster state and mint no new
		// sighting. Stamping a sighting with the stale cached height risks placing
		// a genuinely post-cutover observation below C, where the central fleet
		// collector would discard it as pre-cutover evidence — a worse outcome than
		// deferring the record until the clock recovers, when the same persistent
		// straggler will be re-observed with a correct height. The block-clock rule
		// is to retain state and evict/record nothing on clock failure.
		r.clockAvailable = false
		return
	}
	r.currentBlock = currentBlock
	r.clockAvailable = true
	block := r.currentBlock

	entry, existed := r.peers[normalized]
	if !existed {
		entry = &peerState{
			operatorAddress: normalized,
			firstSeenBlock:  block,
			lastSeenBlock:   block,
			firstSeenAt:     now,
			lastSeenAt:      now,
			sightings:       make(map[sightingKey]*CutoverPeerSighting),
		}
		r.peers[normalized] = entry

		r.metrics.IncrementCounter(metricLegacyPeerAdditionsTotal, 1)

		if r.logLimiter.Allow() {
			rosterLogger.Infof(
				"protocol legacy peer entered cutover roster "+
					"[operator=%s] [protocol=%s] [member=%d] "+
					"[firstSeenBlock=%d] [cutoverBlock=%d]",
				normalized,
				protocolID,
				memberIndex,
				block,
				r.cutoverBlock,
			)
		}
	} else {
		if block < entry.firstSeenBlock {
			entry.firstSeenBlock = block
			entry.firstSeenAt = now
		}
		if block > entry.lastSeenBlock {
			entry.lastSeenBlock = block
		}
		entry.lastSeenAt = now
	}

	key := sightingKey{protocolID: protocolID, memberIndex: memberIndex}
	sighting, sightingExisted := entry.sightings[key]
	if !sightingExisted {
		entry.sightings[key] = &CutoverPeerSighting{
			ProtocolID:     protocolID,
			MemberIndex:    memberIndex,
			FirstSeenBlock: block,
			LastSeenBlock:  block,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		}
	} else {
		if block < sighting.FirstSeenBlock {
			sighting.FirstSeenBlock = block
			sighting.FirstSeenAt = now
		}
		if block > sighting.LastSeenBlock {
			sighting.LastSeenBlock = block
		}
		sighting.LastSeenAt = now
	}

	r.rosterRevision++
	r.refreshMetricsLocked()
}

// Sweep advances the roster to the given current block, evicting any operator
// whose most recent sighting is older than the retention window, and refreshes
// the metrics. It also marks the clock available, since a concrete block was
// supplied.
func (r *CutoverPeerRoster) Sweep(currentBlock uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.currentBlock = currentBlock
	r.clockAvailable = true

	for address, entry := range r.peers {
		threshold := retentionThreshold(entry.lastSeenBlock, r.retentionBlocks)
		if currentBlock > threshold {
			delete(r.peers, address)
			r.rosterRevision++
			r.metrics.IncrementCounter(metricLegacyPeerEvictionsTotal, 1)

			if r.logLimiter.Allow() {
				rosterLogger.Infof(
					"protocol legacy peer evicted from local cutover roster "+
						"[operator=%s] [lastSeenBlock=%d] [currentBlock=%d] "+
						"[retentionBlocks=%d] [reason=observation_expired]",
					address,
					entry.lastSeenBlock,
					currentBlock,
					r.retentionBlocks,
				)
			}
		}
	}

	r.refreshMetricsLocked()
}

// Snapshot returns a deterministic point-in-time view of the roster. Peers are
// sorted by operator address; each peer's sightings are sorted by protocol then
// member index.
func (r *CutoverPeerRoster) Snapshot() CutoverPeerRosterSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.snapshotLocked()
}

func (r *CutoverPeerRoster) snapshotLocked() CutoverPeerRosterSnapshot {
	peers := make([]CutoverPeerEntry, 0, len(r.peers))

	for _, entry := range r.peers {
		sightings := make([]CutoverPeerSighting, 0, len(entry.sightings))
		for _, sighting := range entry.sightings {
			sightings = append(sightings, *sighting)
		}
		sort.Slice(sightings, func(i, j int) bool {
			if sightings[i].ProtocolID != sightings[j].ProtocolID {
				return sightings[i].ProtocolID < sightings[j].ProtocolID
			}
			return sightings[i].MemberIndex < sightings[j].MemberIndex
		})

		peers = append(peers, CutoverPeerEntry{
			OperatorAddress: entry.operatorAddress,
			FirstSeenBlock:  entry.firstSeenBlock,
			LastSeenBlock:   entry.lastSeenBlock,
			Sightings:       sightings,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].OperatorAddress < peers[j].OperatorAddress
	})

	return CutoverPeerRosterSnapshot{
		SchemaVersion:    CutoverPeerRosterSchemaVersion,
		ProcessStartedAt: r.processStartedAt,
		GeneratedAt:      r.clock(),
		CurrentBlock:     r.currentBlock,
		ClockAvailable:   r.clockAvailable,
		RetentionBlocks:  r.retentionBlocks,
		RosterRevision:   r.rosterRevision,
		Peers:            peers,
	}
}

// Close stops and joins the background sweep loop. It is idempotent.
func (r *CutoverPeerRoster) Close() {
	r.closeOnce.Do(func() {
		r.cancel()
		<-r.loopDone
	})
}

// refreshMetricsLocked recomputes the gauge metrics from the current roster
// state. The caller must hold r.mu.
func (r *CutoverPeerRoster) refreshMetricsLocked() {
	r.metrics.SetGauge(metricLegacyPeersCurrent, float64(len(r.peers)))
	r.metrics.SetGauge(metricLegacyPeerRosterRevision, float64(r.rosterRevision))

	oldestFirstSeen, hasPeers := r.oldestFirstSeenBlockLocked()
	if !hasPeers || r.currentBlock < oldestFirstSeen {
		r.metrics.SetGauge(metricLegacyPeerOldestAgeBlocks, 0)
		return
	}
	r.metrics.SetGauge(
		metricLegacyPeerOldestAgeBlocks,
		float64(r.currentBlock-oldestFirstSeen),
	)
}

func (r *CutoverPeerRoster) oldestFirstSeenBlockLocked() (uint64, bool) {
	oldest := uint64(math.MaxUint64)
	found := false
	for _, entry := range r.peers {
		if entry.firstSeenBlock < oldest {
			oldest = entry.firstSeenBlock
			found = true
		}
	}
	return oldest, found
}

// logSnapshotIfRequired emits the periodic roster evidence line when a
// post-cutover legacy peer is retained or when operators have explicitly
// opened an evidence window. The latter includes an empty roster because
// "zero observed peers" is itself required go/no-go and rollback evidence.
func (r *CutoverPeerRoster) logSnapshotIfRequired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.peers) == 0 && !r.evidenceWindow.Active() {
		return
	}

	oldestFirstSeen, hasPeers := r.oldestFirstSeenBlockLocked()
	if !hasPeers {
		oldestFirstSeen = 0
	}
	rosterLogger.Infof(
		"protocol cutover peer roster snapshot [currentBlock=%d] "+
			"[clockAvailable=%t] [legacyPeers=%d] [oldestFirstSeenBlock=%d] "+
			"[rosterRevision=%d]",
		r.currentBlock,
		r.clockAvailable,
		len(r.peers),
		oldestFirstSeen,
		r.rosterRevision,
	)
}

// retentionThreshold returns lastSeenBlock+retentionBlocks, saturating at
// math.MaxUint64 so overflow never turns into a spurious early eviction.
func retentionThreshold(lastSeenBlock, retentionBlocks uint64) uint64 {
	threshold := lastSeenBlock + retentionBlocks
	if threshold < lastSeenBlock {
		return math.MaxUint64
	}
	return threshold
}

// normalizeOperatorAddress normalizes an operator address to lowercase "0x"
// followed by exactly 40 hexadecimal characters. It returns false if the input
// is not a valid 20-byte hex address.
func normalizeOperatorAddress(address chain.Address) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(address.String()))
	s = strings.TrimPrefix(s, "0x")

	if len(s) != 40 {
		return "", false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}

	return "0x" + s, true
}
