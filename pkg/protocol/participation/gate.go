package participation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipfs/go-log/v2"
	"golang.org/x/time/rate"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// Ceremony identifies a gated protocol ceremony class. The values are fixed:
// they name the per-ceremony refusal metrics and appear in logs and evidence.
type Ceremony string

// The complete, closed set of gated ceremonies.
const (
	TBTCDKG                Ceremony = "tbtc_dkg"
	TBTCWalletCoordination Ceremony = "tbtc_wallet_coordination"
	TBTCSigning            Ceremony = "tbtc_signing"
	TBTCHeartbeat          Ceremony = "tbtc_heartbeat"
	TBTCInactivityClaim    Ceremony = "tbtc_inactivity_claim"
	BeaconDKG              Ceremony = "beacon_dkg"
	BeaconRelaySigning     Ceremony = "beacon_relay_signing"
	BeaconRelayForwarding  Ceremony = "beacon_relay_forwarding"
	BeaconTimeoutReport    Ceremony = "beacon_timeout_report"
)

// AllCeremonies returns the fixed set of gated ceremonies in a stable order.
func AllCeremonies() []Ceremony {
	return []Ceremony{
		TBTCDKG,
		TBTCWalletCoordination,
		TBTCSigning,
		TBTCHeartbeat,
		TBTCInactivityClaim,
		BeaconDKG,
		BeaconRelaySigning,
		BeaconRelayForwarding,
		BeaconTimeoutReport,
	}
}

// CommitClass distinguishes the two commit fence classes: commits that
// complete work already performed and commits that create a new penalty.
type CommitClass uint8

const (
	// CompletionCommit is a terminal commit of already-performed work: signer
	// activation, DKG/relay result submission, or a Bitcoin broadcast. A
	// legacy permit may make completion commits after the cutover block while
	// its protocol validity lasts.
	CompletionCommit CommitClass = iota + 1
	// PenaltyCommit creates new penalty state: a heartbeat inactivity claim or
	// a beacon timeout report. Legacy permits must not create penalty commits
	// at or after the cutover block, and no permit may once quiescence begins.
	PenaltyCommit
)

// String returns the canonical string form of the commit class.
func (c CommitClass) String() string {
	switch c {
	case CompletionCommit:
		return "completion"
	case PenaltyCommit:
		return "penalty"
	default:
		return "unknown"
	}
}

// Gate refusal and fence sentinel errors. Callers distinguish a gate refusal
// from an ordinary protocol failure with errors.Is against these values.
var (
	// ErrInvalidAnchor means the supplied canonical start block is zero while
	// a cutover schedule is active, or is ahead of the current chain height.
	ErrInvalidAnchor = errors.New("invalid canonical ceremony anchor")
	// ErrClockUnavailable means a synchronous chain-clock read failed; the
	// gate refuses new work and has canceled all outstanding permits.
	ErrClockUnavailable = errors.New("chain clock unavailable")
	// ErrQuiescing means process quiescence began and no new permits are
	// issued.
	ErrQuiescing = errors.New("participation gate is quiescing")
	// ErrQuiesceDeadline means the process shutdown deadline arrived before
	// natural completion and the permit was force-canceled.
	ErrQuiesceDeadline = errors.New("participation quiesce deadline exceeded")
	// ErrResumeUnsupported means Resume was called for a ceremony class other
	// than the beacon relay restart path.
	ErrResumeUnsupported = errors.New(
		"resume is supported only for beacon relay signing",
	)
	// ErrPenaltySuppressed means a penalty commit was refused because the
	// permit is legacy at or after the cutover block, or because quiescence
	// began.
	ErrPenaltySuppressed = errors.New("penalty commit suppressed")
	// ErrCommitBeforeCutover means a security-v2 commit was attempted while
	// the current chain height is below the cutover block, e.g. after a deep
	// reorg.
	ErrCommitBeforeCutover = errors.New(
		"security-v2 commit refused below the cutover block",
	)
	// ErrPermitClosed means the permit was already closed by its owner.
	ErrPermitClosed = errors.New("participation permit is closed")
	// ErrInvalidPermitIdentity means a caller supplied an empty, malformed,
	// or ambiguous chain-work/local-permit identity.
	ErrInvalidPermitIdentity = errors.New(
		"invalid participation permit identity",
	)
	// ErrInvalidTerminalOutcome means a permit owner supplied a terminal
	// disposition or evidence shape that is not valid for its ceremony.
	ErrInvalidTerminalOutcome = errors.New(
		"invalid participation terminal outcome",
	)
	// ErrTerminalOutcomeAlreadyRecorded means a permit owner attempted to
	// replace its immutable terminal disposition.
	ErrTerminalOutcomeAlreadyRecorded = errors.New(
		"participation terminal outcome already recorded",
	)
	// ErrTerminalOutcomePersistence means the node-owned terminal journal
	// could not durably record the ceremony owner's outcome. The permit may
	// still close, but the offline rollback audit will fail closed.
	ErrTerminalOutcomePersistence = errors.New(
		"participation terminal outcome persistence failed",
	)
)

// IsGateRefusal reports whether the error is, or wraps, one of the gate's
// sentinel errors: the work was refused, canceled, or fenced off by the
// release gate rather than failing on its own protocol terms. Callers use it
// to keep gate decisions out of ordinary failure logs and metrics; it also
// matches a permit context's cancellation cause propagated through an error
// chain.
func IsGateRefusal(err error) bool {
	for _, sentinel := range []error{
		ErrInvalidAnchor,
		ErrClockUnavailable,
		ErrQuiescing,
		ErrQuiesceDeadline,
		ErrResumeUnsupported,
		ErrPenaltySuppressed,
		ErrCommitBeforeCutover,
		ErrPermitClosed,
		ErrInvalidPermitIdentity,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// CommitGuard is the narrow view of a Permit handed to terminal submission
// code: it can consult the commit fence immediately before an irreversible
// chain or broadcast call, but it cannot close or otherwise manage the permit.
type CommitGuard interface {
	// CheckCommit is the last-moment commit fence, called immediately before
	// activating newly generated key material, submitting results or claims,
	// or broadcasting Bitcoin transactions. It reads a fresh chain height and
	// enforces the per-mode fence rules; a returned error is a gate sentinel,
	// not a normal protocol timeout.
	CheckCommit(operation string, class CommitClass) error
}

// Permit authorizes local participation in one ceremony. Its ceremony,
// canonical start block, and protocol mode are immutable for its entire
// lifetime: crossing the cutover block never cancels a permit or mutates its
// mode. A permit is counted as active until its idempotent Close.
type Permit interface {
	CommitGuard

	// Context is canceled when the gate cancels the permit: on chain-clock
	// failure, at the quiesce deadline, or at Close. Ceremony work must stop
	// when it is done; the cancellation cause carries the gate sentinel.
	Context() context.Context
	// Ceremony returns the ceremony class this permit was issued for.
	Ceremony() Ceremony
	// CanonicalStartBlock returns the canonical chain anchor the mode was
	// pinned from.
	CanonicalStartBlock() uint64
	// Mode returns the immutable protocol mode of the ceremony.
	Mode() ProtocolMode
	// WorkID returns the immutable chain-native work identity supplied when
	// the permit was issued.
	WorkID() string
	// PermitID returns the immutable local membership/action identity supplied
	// when the permit was issued.
	PermitID() string
	// RecordTerminalOutcome records the real ceremony owner's final
	// disposition and the durable state or explicit no-threshold condition
	// behind it. If this permit was present at the quiescence transition, the
	// record is written into the encrypted node-authored terminal journal.
	// The first valid outcome is immutable.
	RecordTerminalOutcome(
		outcome TerminalOutcome,
		evidence TerminalEvidence,
	) error
	// Close releases the permit. It is idempotent.
	Close()
}

// Snapshot is a point-in-time observability view of the gate.
type Snapshot struct {
	State                      State
	CutoverBlock               uint64
	CurrentBlock               uint64
	ClockAvailable             bool
	Quiescing                  bool
	Allowed                    bool
	ActiveCeremonies           uint64
	ActiveLegacyCeremonies     uint64
	ActiveSecurityV2Ceremonies uint64
	ActivePermits              []PermitSnapshot
	// RecentTerminalOutcomes is the gate's own account of what became of the
	// permits it has already closed, oldest first and bounded. It is the same
	// record the quiescence journal carries, available while the node is still
	// running rather than only from a quiescence transition onward.
	RecentTerminalOutcomes []TerminalOutcomeRecord
}

// Gate issues per-ceremony participation permits with the protocol mode pinned
// from each ceremony's canonical chain anchor. It is the only component that
// derives protocol modes from the chain clock; cryptographic packages never
// query the clock themselves.
type Gate interface {
	// Begin issues a permit for a new ceremony. It reads the chain clock
	// synchronously, rejects a zero anchor while a cutover schedule is active,
	// rejects an anchor ahead of the current height, and derives the mode only
	// from the canonical start block. A production gate with quiescence
	// persistence also requires exactly one stable PermitIdentity. It returns
	// ErrInvalidAnchor, ErrInvalidPermitIdentity, ErrClockUnavailable, or
	// ErrQuiescing.
	Begin(
		ceremony Ceremony,
		canonicalStartBlock uint64,
		identity ...PermitIdentity,
	) (Permit, error)
	// Resume issues a permit for the beacon relay restart path only. The
	// caller must have verified on chain that the relay request is still live
	// and pass its on-chain start block; the mode pins from that block exactly
	// as in Begin. Any other ceremony class returns ErrResumeUnsupported.
	Resume(
		ceremony Ceremony,
		canonicalStartBlock uint64,
		identity ...PermitIdentity,
	) (Permit, error)
	// State returns a point-in-time observability snapshot.
	State() Snapshot
	// Quiesce atomically refuses all new permits, keeps existing permits
	// alive to natural completion, and refuses penalty commits from the
	// transition onward. It is idempotent and always returns the same channel,
	// which closes when the active permit count reaches zero or when Close
	// force-cancels the remainder.
	Quiesce(cause error) <-chan struct{}
	// Drained returns a channel that closes once the gate no longer issues
	// new permits — quiescence began or Close ran — and every issued permit
	// has been released by its owner. Unlike the quiesce channel, which Close
	// closes immediately, the drained channel stays open across a forced
	// cancellation until the canceled owners finish their cleanup — the
	// quarantine and audit writes included — and release their permits. It
	// always returns the same channel.
	Drained() <-chan struct{}
	// QuiescenceSnapshot returns the immutable node-authored inventory
	// captured at the first quiescence transition. The boolean is false
	// before that transition. Returned slices are defensive copies.
	QuiescenceSnapshot() (QuiescenceSnapshot, bool)
	// Close is the terminal shutdown: it force-cancels any remaining permits
	// with ErrQuiesceDeadline, closes the quiesce channel, and stops the
	// clock supervisor. Force-canceled permits remain counted until their
	// owners release them; the drained channel reports when that has
	// happened. Close is idempotent.
	Close()
}

// GateMetricsRecorder is the minimal metrics sink the gate needs. It is
// satisfied by the client-info performance metrics registry.
type GateMetricsRecorder interface {
	IncrementCounter(name string, value float64)
	SetGauge(name string, value float64)
}

type gateOptions struct {
	releaseVersion  string
	releaseRevision string
	recorder        QuiescenceSnapshotRecorder
	now             func() time.Time
}

// GateOption configures node-artifact identity and quiescence persistence
// without changing the required chain-clock and metrics inputs.
type GateOption func(*gateOptions) error

// WithArtifactIdentity binds the node-authored quiescence snapshot to the
// exact release version and source revision of the running process.
func WithArtifactIdentity(version string, revision string) GateOption {
	return func(options *gateOptions) error {
		if version == "" {
			return fmt.Errorf("release version is required")
		}
		if revision == "" {
			return fmt.Errorf("release revision is required")
		}
		options.releaseVersion = version
		options.releaseRevision = revision
		return nil
	}
}

// WithQuiescenceSnapshotRecorder persists the node-authored snapshot into
// storage as part of the first quiescence transition.
func WithQuiescenceSnapshotRecorder(
	recorder QuiescenceSnapshotRecorder,
) GateOption {
	return func(options *gateOptions) error {
		if recorder == nil {
			return fmt.Errorf("quiescence snapshot recorder is required")
		}
		options.recorder = recorder
		return nil
	}
}

func withGateTimeSource(now func() time.Time) GateOption {
	return func(options *gateOptions) error {
		if now == nil {
			return fmt.Errorf("gate time source is required")
		}
		options.now = now
		return nil
	}
}

var gateLogger = log.Logger("keep-participation")

// The gate reports through the client-info performance registry, which adds
// the "performance_" application prefix. Referencing the clientinfo constants
// keeps a single source of truth for the exact exported metric names.
const (
	metricGateState                  = clientinfo.MetricParticipationGateState
	metricCurrentBlock               = clientinfo.MetricParticipationCurrentBlock
	metricCutoverBlock               = clientinfo.MetricParticipationCutoverBlock
	metricAllowed                    = clientinfo.MetricParticipationAllowed
	metricActiveCeremonies           = clientinfo.MetricParticipationActiveCeremonies
	metricActiveLegacyCeremonies     = clientinfo.MetricParticipationActiveLegacyCeremonies
	metricActiveSecurityV2Ceremonies = clientinfo.MetricParticipationActiveSecurityV2Ceremonies
	metricModeLegacyTotal            = clientinfo.MetricParticipationModeLegacyTotal
	metricModeSecurityV2Total        = clientinfo.MetricParticipationModeSecurityV2Total
	metricLegacyCompletionsTotal     = clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal
	metricRefusalsTotal              = clientinfo.MetricParticipationRefusalsTotal
	metricCommitRefusalsTotal        = clientinfo.MetricParticipationCommitRefusalsTotal
	metricClockErrorsTotal           = clientinfo.MetricParticipationClockErrorsTotal
	metricClockAbortsTotal           = clientinfo.MetricParticipationClockAbortsTotal
	metricQuiesceTotal               = clientinfo.MetricParticipationQuiesceTotal
	metricQuiesceForcedAbortsTotal   = clientinfo.MetricParticipationQuiesceForcedAbortsTotal
	metricHeartbeatPenaltySuppressed = clientinfo.MetricHeartbeatPenaltySuppressedTotal
)

// gateSupervisorPollInterval is how often the clock supervisor synchronously
// polls the current chain height between authoritative per-operation reads.
const gateSupervisorPollInterval = 15 * time.Second

type permit struct {
	gate                *chainGate
	ceremony            Ceremony
	canonicalStartBlock uint64
	mode                ProtocolMode
	workID              string
	permitID            string
	identityBound       bool
	// operatedMembers is the issuance-time copy of the memberships this
	// permit's holder operates. It is written once, before the permit is
	// reachable by any other goroutine, and only ever read afterwards — every
	// reader receives a copy, so no holder of a snapshot can reach back into
	// the permit's own record.
	operatedMembers MemberIndexes

	ctx    context.Context
	cancel context.CancelCauseFunc

	closeOnce       sync.Once
	terminalOutcome *TerminalOutcomeRecord
}

func (p *permit) Context() context.Context    { return p.ctx }
func (p *permit) Ceremony() Ceremony          { return p.ceremony }
func (p *permit) CanonicalStartBlock() uint64 { return p.canonicalStartBlock }
func (p *permit) Mode() ProtocolMode          { return p.mode }
func (p *permit) WorkID() string              { return p.workID }
func (p *permit) PermitID() string            { return p.permitID }

// chainGate is the production Gate implementation, clocked exclusively by the
// shared Ethereum block counter.
type chainGate struct {
	schedule     Schedule
	blockCounter chain.BlockCounter
	metrics      GateMetricsRecorder

	ctx      context.Context
	cancel   context.CancelFunc
	loopDone chan struct{}

	// modeLogLimiter covers mode-selection and legacy-completion logs;
	// refusalLogLimiter covers refusal logs. Metrics retain every event.
	modeLogLimiter    *rate.Limiter
	refusalLogLimiter *rate.Limiter
	releaseVersion    string
	releaseRevision   string
	recorder          QuiescenceSnapshotRecorder
	now               func() time.Time

	closeOnce sync.Once

	// clockSeq issues the ordering tickets for synchronous clock reads. A
	// ticket is taken immediately before a read starts, so concurrently
	// completing reads apply in initiation order regardless of the order their
	// responses arrive in.
	clockSeq atomic.Uint64

	mu                 sync.Mutex
	lastClockTicket    uint64
	currentBlock       uint64
	clockAvailable     bool
	quiescing          bool
	closed             bool
	quiesceDone        chan struct{}
	quiesceDoneClosed  bool
	drained            chan struct{}
	drainedClosed      bool
	permits            map[*permit]struct{}
	activeLegacy       uint64
	activeSecurityV2   uint64
	lastState          State
	nextPermitID       uint64
	quiescenceSnapshot *QuiescenceSnapshot
	// terminalOutcomes retains what became of the permits this gate has
	// already closed, oldest first, bounded to the most recent
	// retainedTerminalOutcomes.
	//
	// The journal only exists from a quiescence transition onward, so before
	// one there is nothing node-authored saying what a permit came to — an
	// observer watching work cross the cutover has only its own word for it,
	// and a report about a ceremony is not evidence about a ceremony. This is
	// the gate's own account of the same records, kept while the node is still
	// running, so a permit that appeared in a live reading can be followed to
	// the outcome its owner recorded rather than to one claimed for it.
	terminalOutcomes []TerminalOutcomeRecord
}

// retainedTerminalOutcomes bounds the gate's in-memory account of closed
// permits. A node runs indefinitely, so the account has to forget: this holds
// well past the permit population of any one cutover while staying a fixed
// cost.
const retainedTerminalOutcomes = 512

// NewGate constructs the production gate from a resolved schedule and the
// shared chain block counter. It synchronously reads the current chain height
// — a clock error at startup is a construction error — arms the cutover-block
// waiter for eager transition telemetry, initializes all fixed metrics, and
// starts the clock supervisor. The supervisor loop is bound to the given
// context and to Close.
func NewGate(
	ctx context.Context,
	schedule Schedule,
	blockCounter chain.BlockCounter,
	metrics GateMetricsRecorder,
	options ...GateOption,
) (Gate, error) {
	return newGate(
		ctx,
		schedule,
		blockCounter,
		metrics,
		gateSupervisorPollInterval,
		options...,
	)
}

// newGate is the poll-interval-injecting constructor used by tests.
func newGate(
	ctx context.Context,
	schedule Schedule,
	blockCounter chain.BlockCounter,
	metrics GateMetricsRecorder,
	pollInterval time.Duration,
	optionFunctions ...GateOption,
) (*chainGate, error) {
	options := &gateOptions{now: time.Now}
	for _, option := range optionFunctions {
		if option == nil {
			return nil, fmt.Errorf("nil gate option")
		}
		if err := option(options); err != nil {
			return nil, fmt.Errorf("invalid gate option: [%w]", err)
		}
	}
	if options.recorder != nil &&
		(options.releaseVersion == "" || options.releaseRevision == "") {
		return nil, fmt.Errorf(
			"artifact identity is required when quiescence persistence is enabled",
		)
	}

	if blockCounter == nil {
		return nil, fmt.Errorf("block counter is required")
	}
	if metrics == nil {
		return nil, fmt.Errorf("metrics recorder is required")
	}
	if pollInterval <= 0 {
		return nil, fmt.Errorf("poll interval must be positive")
	}
	if err := validateMetricProjectable(schedule.CutoverBlock); err != nil {
		return nil, err
	}

	currentBlock, err := blockCounter.CurrentBlock()
	if err != nil {
		return nil, fmt.Errorf(
			"could not read the chain clock at gate construction: [%w]",
			err,
		)
	}
	// Every height the gate exports must project exactly onto the float64
	// metric surface; a chain reporting an unprojectable height is as unusable
	// as one reporting an error.
	if err := validateMetricProjectable(currentBlock); err != nil {
		return nil, fmt.Errorf(
			"could not accept the chain height at gate construction: [%w]",
			err,
		)
	}

	// The waiter exists only to make transition telemetry eager; every mode
	// selection and commit fence uses a synchronous read. The disabled
	// schedule has no transition to observe.
	var cutoverWaiter <-chan uint64
	if !schedule.Disabled() {
		cutoverWaiter, err = blockCounter.BlockHeightWaiter(
			schedule.CutoverBlock,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"could not arm the cutover block waiter: [%w]",
				err,
			)
		}
	}

	loopCtx, cancel := context.WithCancel(ctx)

	gate := &chainGate{
		schedule:          schedule,
		blockCounter:      blockCounter,
		metrics:           metrics,
		ctx:               loopCtx,
		cancel:            cancel,
		loopDone:          make(chan struct{}),
		modeLogLimiter:    rate.NewLimiter(rate.Every(30*time.Second), 5),
		refusalLogLimiter: rate.NewLimiter(rate.Every(30*time.Second), 5),
		releaseVersion:    options.releaseVersion,
		releaseRevision:   options.releaseRevision,
		recorder:          options.recorder,
		now:               options.now,
		quiesceDone:       make(chan struct{}),
		drained:           make(chan struct{}),
		permits:           make(map[*permit]struct{}),
		currentBlock:      currentBlock,
		clockAvailable:    true,
	}

	gate.initMetrics()

	gate.mu.Lock()
	gate.lastState = gate.stateLocked()
	gate.refreshMetricsLocked()
	gate.mu.Unlock()

	gateLogger.Infof(
		"protocol participation gate constructed [state=%s] "+
			"[currentBlock=%d] [cutoverBlock=%d] [epoch=%s]",
		gate.lastState,
		currentBlock,
		schedule.CutoverBlock,
		CompiledEpoch,
	)

	go gate.run(pollInterval, cutoverWaiter)

	return gate, nil
}

// initMetrics registers every fixed metric at its zero value so scrapers see a
// complete metric set from the start.
func (g *chainGate) initMetrics() {
	g.metrics.SetGauge(metricGateState, 0)
	g.metrics.SetGauge(metricCurrentBlock, 0)
	g.metrics.SetGauge(metricCutoverBlock, 0)
	g.metrics.SetGauge(metricAllowed, 0)
	g.metrics.SetGauge(metricActiveCeremonies, 0)
	g.metrics.SetGauge(metricActiveLegacyCeremonies, 0)
	g.metrics.SetGauge(metricActiveSecurityV2Ceremonies, 0)
	g.metrics.IncrementCounter(metricModeLegacyTotal, 0)
	g.metrics.IncrementCounter(metricModeSecurityV2Total, 0)
	g.metrics.IncrementCounter(metricLegacyCompletionsTotal, 0)
	g.metrics.IncrementCounter(metricRefusalsTotal, 0)
	g.metrics.IncrementCounter(metricCommitRefusalsTotal, 0)
	g.metrics.IncrementCounter(metricClockErrorsTotal, 0)
	g.metrics.IncrementCounter(metricClockAbortsTotal, 0)
	g.metrics.IncrementCounter(metricQuiesceTotal, 0)
	g.metrics.IncrementCounter(metricQuiesceForcedAbortsTotal, 0)
	g.metrics.IncrementCounter(metricHeartbeatPenaltySuppressed, 0)
	for _, ceremony := range AllCeremonies() {
		g.metrics.IncrementCounter(
			clientinfo.ParticipationRefusalMetricName(string(ceremony)),
			0,
		)
	}
}

// run is the clock supervisor: it polls the current height, watches the
// cutover-block waiter for an eager transition, and converts any clock error
// into the atomic clock-unavailable transition.
func (g *chainGate) run(
	pollInterval time.Duration,
	cutoverWaiter <-chan uint64,
) {
	defer close(g.loopDone)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.ctx.Done():
			return
		case _, ok := <-cutoverWaiter:
			// A nil channel (disabled schedule, or already handled) blocks
			// forever, which is the intended disarm.
			cutoverWaiter = nil
			if !ok {
				// The waiter closed before its target: a clock failure.
				g.mu.Lock()
				g.signalClockFailureLocked(
					"cutover_waiter",
					fmt.Errorf("cutover block waiter closed before target"),
				)
				g.mu.Unlock()
				continue
			}
			// The waiter exists only to make transition telemetry eager: it
			// requests an authoritative synchronous poll and never recovers or
			// advances gate state itself. A failing poll here is a clock
			// failure even though the waiter reported the target height.
			g.poll("cutover_waiter_poll")
		case <-ticker.C:
			g.poll("supervisor_poll")
		}
	}
}

// poll performs one ordered synchronous read of the chain clock. A newest
// failure cancels all permits; a newest success recomputes the current state,
// but previously canceled permits do not revive. A stale outcome is discarded.
func (g *chainGate) poll(operation string) {
	ticket, height, err := g.readClock()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.applyClockSampleLocked(ticket, height, operation, err)
}

// readClock performs one ordered synchronous read of the chain clock. The
// ordering ticket is taken immediately before the read starts, so concurrently
// completing reads apply in initiation order regardless of the order their
// responses arrive in. A height the float64 metrics projection cannot
// represent exactly is folded into the read's own error here, at read time:
// the owning operation then fails closed on it exactly like on an RPC error,
// even when a newer concurrent sample supersedes this one.
func (g *chainGate) readClock() (ticket uint64, height uint64, err error) {
	ticket = g.clockSeq.Add(1)
	height, err = g.blockCounter.CurrentBlock()
	if err == nil {
		err = validateMetricProjectable(height)
	}
	return ticket, height, err
}

// applyClockSampleLocked applies the outcome of one ordered synchronous clock
// read taken through readClock. A sample older than the newest applied one is
// discarded entirely: a stale success arriving after a newer failure can never
// reopen the gate, and a stale failure — an RPC error or an unprojectable
// height — arriving after a newer success cannot spuriously cancel permits.
// The caller must hold g.mu.
func (g *chainGate) applyClockSampleLocked(
	ticket uint64,
	height uint64,
	operation string,
	readErr error,
) {
	if ticket <= g.lastClockTicket {
		return
	}
	g.lastClockTicket = ticket

	if readErr != nil {
		g.clockFailureLocked(operation, readErr)
		return
	}

	g.clockAvailable = true
	g.currentBlock = height
	g.refreshMetricsLocked()
}

// signalClockFailureLocked records a clock failure that arrived as a lifecycle
// signal — the cutover waiter closing before its target — rather than as an
// ordered read outcome. It takes a fresh ticket at application time, so any
// read still in flight was initiated earlier, is stale on arrival, and cannot
// mask this failure; recovery requires a read initiated afterwards. The caller
// must hold g.mu.
func (g *chainGate) signalClockFailureLocked(operation string, err error) {
	g.lastClockTicket = g.clockSeq.Add(1)
	g.clockFailureLocked(operation, err)
}

// clockFailureLocked is the atomic clock-unavailable transition: it marks the
// clock unavailable and cancels every not-yet-canceled permit with
// ErrClockUnavailable. Canceled permits remain counted until their owners
// close them. The caller must hold g.mu.
func (g *chainGate) clockFailureLocked(operation string, err error) {
	g.clockAvailable = false
	g.metrics.IncrementCounter(metricClockErrorsTotal, 1)

	gateLogger.Warnf(
		"protocol participation chain clock unavailable [operation=%s] "+
			"[lastCurrentBlock=%d] [error=%s]",
		operation,
		g.currentBlock,
		err,
	)

	aborted := 0
	for p := range g.permits {
		if context.Cause(p.ctx) == nil {
			p.cancel(ErrClockUnavailable)
			aborted++
		}
	}
	if aborted > 0 {
		g.metrics.IncrementCounter(metricClockAbortsTotal, float64(aborted))
	}

	g.refreshMetricsLocked()
}

// stateLocked computes the externally visible process state. Quiescence is the
// dominant lifecycle condition, then clock failure, then the height-derived
// open state. The caller must hold g.mu.
func (g *chainGate) stateLocked() State {
	switch {
	case g.closed || g.quiescing:
		return StateQuiescing
	case !g.clockAvailable:
		return StateClockUnavailable
	default:
		return g.schedule.StateFor(g.currentBlock)
	}
}

// allowedLocked reports whether a new permit can be issued. The caller must
// hold g.mu.
func (g *chainGate) allowedLocked() bool {
	return !g.closed && !g.quiescing && g.clockAvailable
}

// refreshMetricsLocked recomputes all gauges and logs a state transition once
// per process transition. The caller must hold g.mu.
func (g *chainGate) refreshMetricsLocked() {
	state := g.stateLocked()
	if state != g.lastState {
		gateLogger.Infof(
			"protocol participation gate transitioned [from=%s] [to=%s] "+
				"[currentBlock=%d] [cutoverBlock=%d] [activeLegacy=%d] "+
				"[activeSecurityV2=%d]",
			g.lastState,
			state,
			g.currentBlock,
			g.schedule.CutoverBlock,
			g.activeLegacy,
			g.activeSecurityV2,
		)
		g.lastState = state
	}

	g.metrics.SetGauge(metricGateState, float64(state))
	g.metrics.SetGauge(metricCurrentBlock, float64(g.currentBlock))
	g.metrics.SetGauge(metricCutoverBlock, float64(g.schedule.CutoverBlock))
	allowed := float64(0)
	if g.allowedLocked() {
		allowed = 1
	}
	g.metrics.SetGauge(metricAllowed, allowed)
	g.metrics.SetGauge(
		metricActiveCeremonies,
		float64(g.activeLegacy+g.activeSecurityV2),
	)
	g.metrics.SetGauge(metricActiveLegacyCeremonies, float64(g.activeLegacy))
	g.metrics.SetGauge(
		metricActiveSecurityV2Ceremonies,
		float64(g.activeSecurityV2),
	)
}

// refuseLocked records a Begin/Resume refusal in metrics and the rate-limited
// refusal log and returns the sentinel wrapped with context. The caller must
// hold g.mu.
func (g *chainGate) refuseLocked(
	ceremony Ceremony,
	canonicalStartBlock uint64,
	reason string,
	sentinel error,
) error {
	g.metrics.IncrementCounter(metricRefusalsTotal, 1)
	g.metrics.IncrementCounter(
		clientinfo.ParticipationRefusalMetricName(string(ceremony)),
		1,
	)

	if g.refusalLogLimiter.Allow() {
		gateLogger.Infof(
			"protocol participation refused by release gate [ceremony=%s] "+
				"[reason=%s] [canonicalStartBlock=%d] [currentBlock=%d] "+
				"[cutoverBlock=%d]",
			ceremony,
			reason,
			canonicalStartBlock,
			g.currentBlock,
			g.schedule.CutoverBlock,
		)
	}

	return fmt.Errorf(
		"ceremony [%s] with canonical start block [%d] refused (%s): %w",
		ceremony,
		canonicalStartBlock,
		reason,
		sentinel,
	)
}

var knownCeremonies = func() map[Ceremony]struct{} {
	known := make(map[Ceremony]struct{})
	for _, ceremony := range AllCeremonies() {
		known[ceremony] = struct{}{}
	}
	return known
}()

// Begin implements Gate.
func (g *chainGate) Begin(
	ceremony Ceremony,
	canonicalStartBlock uint64,
	identity ...PermitIdentity,
) (Permit, error) {
	return g.issue(ceremony, canonicalStartBlock, false, identity...)
}

// Resume implements Gate.
func (g *chainGate) Resume(
	ceremony Ceremony,
	canonicalStartBlock uint64,
	identity ...PermitIdentity,
) (Permit, error) {
	return g.issue(ceremony, canonicalStartBlock, true, identity...)
}

func (g *chainGate) issue(
	ceremony Ceremony,
	canonicalStartBlock uint64,
	resume bool,
	identities ...PermitIdentity,
) (Permit, error) {
	if _, known := knownCeremonies[ceremony]; !known {
		return nil, fmt.Errorf("unknown ceremony [%s]", ceremony)
	}
	if len(identities) > 1 {
		return nil, fmt.Errorf(
			"ceremony [%s] supplied [%d] permit identities: %w",
			ceremony,
			len(identities),
			ErrInvalidPermitIdentity,
		)
	}
	if g.recorder != nil && len(identities) == 0 {
		return nil, fmt.Errorf(
			"ceremony [%s] did not supply the permit identity required by "+
				"the production quiescence recorder: %w",
			ceremony,
			ErrInvalidPermitIdentity,
		)
	}
	if len(identities) == 1 {
		if err := validatePermitIdentityForCeremony(
			ceremony,
			identities[0],
		); err != nil {
			return nil, fmt.Errorf(
				"ceremony [%s] permit identity rejected: [%v]: %w",
				ceremony,
				err,
				ErrInvalidPermitIdentity,
			)
		}
	}

	// The synchronous, authoritative chain read happens outside the lock so a
	// slow chain call never blocks fences, closes, or the supervisor. The
	// ticket taken before the read orders this sample against concurrent ones.
	ticket, height, clockErr := g.readClock()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.applyClockSampleLocked(ticket, height, "issue_permit", clockErr)

	if g.closed || g.quiescing {
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"quiescing",
			ErrQuiescing,
		)
	}

	// This operation fails closed on its own read error — an RPC failure or an
	// unprojectable height — even when a newer concurrent sample kept the gate
	// available, and equally when its own read succeeded but lost the race to
	// a newer applied failure.
	if clockErr != nil || !g.clockAvailable {
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"clock_unavailable",
			ErrClockUnavailable,
		)
	}

	// From here on, decisions use the newest applied height, which is this
	// read's own height unless a newer concurrent sample applied first.
	height = g.currentBlock

	if resume && ceremony != BeaconRelaySigning {
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"resume_unsupported",
			ErrResumeUnsupported,
		)
	}

	// A zero anchor is rejected whenever a cutover schedule is active: every
	// canonical anchor is an already validated chain event or window block.
	// The developer-only disabled schedule accepts zero (genesis) anchors.
	if !g.schedule.Disabled() && canonicalStartBlock == 0 {
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"zero_anchor",
			ErrInvalidAnchor,
		)
	}
	if canonicalStartBlock > height {
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"future_anchor",
			ErrInvalidAnchor,
		)
	}

	mode := g.schedule.ModeFor(canonicalStartBlock)
	g.nextPermitID++
	identity := PermitIdentity{
		WorkID: fmt.Sprintf(
			"unbound-%s-%d",
			ceremony,
			canonicalStartBlock,
		),
		PermitID: fmt.Sprintf("unbound-%d", g.nextPermitID),
	}
	identityBound := false
	if len(identities) == 1 {
		identity = identities[0]
		identityBound = true
	}
	for existing := range g.permits {
		if existing.ceremony == ceremony &&
			existing.canonicalStartBlock == canonicalStartBlock &&
			existing.workID == identity.WorkID &&
			existing.permitID == identity.PermitID {
			return nil, g.refuseLocked(
				ceremony,
				canonicalStartBlock,
				"duplicate_permit_identity",
				ErrInvalidPermitIdentity,
			)
		}
	}

	ctx, cancel := context.WithCancelCause(g.ctx)
	p := &permit{
		gate:                g,
		ceremony:            ceremony,
		canonicalStartBlock: canonicalStartBlock,
		mode:                mode,
		workID:              identity.WorkID,
		permitID:            identity.PermitID,
		identityBound:       identityBound,
		// Copied rather than aliased: the caller still holds the slice it
		// passed, and a permit whose operated seats can be rewritten after
		// issuance is not the immutable record every reading of it claims.
		operatedMembers: slices.Clone(identity.OperatedMembers),
		ctx:             ctx,
		cancel:          cancel,
	}

	g.permits[p] = struct{}{}
	switch mode {
	case ModeLegacy:
		g.activeLegacy++
		g.metrics.IncrementCounter(metricModeLegacyTotal, 1)
	case ModeSecurityV2:
		g.activeSecurityV2++
		g.metrics.IncrementCounter(metricModeSecurityV2Total, 1)
	}

	if g.modeLogLimiter.Allow() {
		gateLogger.Infof(
			"protocol participation mode selected [ceremony=%s] [mode=%s] "+
				"[canonicalStartBlock=%d] [currentBlock=%d] [cutoverBlock=%d]",
			ceremony,
			mode,
			canonicalStartBlock,
			height,
			g.schedule.CutoverBlock,
		)
	}

	g.refreshMetricsLocked()

	return p, nil
}

// CheckCommit implements the Permit commit fence.
func (p *permit) CheckCommit(operation string, class CommitClass) error {
	g := p.gate

	// The fence always uses its own fresh synchronous height, read outside
	// the lock and ordered against concurrent reads by its ticket.
	ticket, height, clockErr := g.readClock()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.applyClockSampleLocked(ticket, height, "commit_fence", clockErr)

	// The fence fails closed on its own read error — an RPC failure or an
	// unprojectable height — even when a newer concurrent sample kept the gate
	// available, and equally when its own read succeeded but lost the race to
	// a newer applied failure.
	if clockErr != nil || !g.clockAvailable {
		return g.refuseCommitLocked(
			p,
			operation,
			class,
			g.currentBlock,
			ErrClockUnavailable,
		)
	}

	// Fence decisions use the newest applied height, which is this read's own
	// height unless a newer concurrent sample applied first.
	height = g.currentBlock

	if cause := context.Cause(p.ctx); cause != nil {
		return g.refuseCommitLocked(p, operation, class, height, cause)
	}

	if g.closed {
		return g.refuseCommitLocked(
			p,
			operation,
			class,
			height,
			ErrQuiesceDeadline,
		)
	}

	if class == PenaltyCommit {
		// Penalty suppression protects the technical grace from turning into
		// punishment: it applies to legacy work at or after the cutover block
		// and to every permit once quiescence begins.
		afterCutoverLegacy := p.mode == ModeLegacy &&
			!g.schedule.Disabled() &&
			height >= g.schedule.CutoverBlock
		if afterCutoverLegacy || g.quiescing {
			return g.suppressPenaltyLocked(p, operation, height)
		}
	}

	if p.mode == ModeSecurityV2 &&
		(p.canonicalStartBlock < g.schedule.CutoverBlock ||
			height < g.schedule.CutoverBlock) {
		return g.refuseCommitLocked(
			p,
			operation,
			class,
			height,
			ErrCommitBeforeCutover,
		)
	}

	if p.mode == ModeLegacy &&
		class == CompletionCommit &&
		!g.schedule.Disabled() &&
		height >= g.schedule.CutoverBlock {
		g.metrics.IncrementCounter(metricLegacyCompletionsTotal, 1)
		if g.modeLogLimiter.Allow() {
			gateLogger.Infof(
				"protocol participation legacy completion after cutover "+
					"[ceremony=%s] [operation=%s] [canonicalStartBlock=%d] "+
					"[currentBlock=%d]",
				p.ceremony,
				operation,
				p.canonicalStartBlock,
				height,
			)
		}
	}

	return nil
}

// RecordTerminalOutcome implements Permit. Only the permit owner has this
// method, so an external evidence generator cannot author or replace the
// terminal disposition. The record is retained in memory before quiescence
// and persisted if the permit is captured by the quiescence transition.
func (p *permit) RecordTerminalOutcome(
	outcome TerminalOutcome,
	evidence TerminalEvidence,
) error {
	if err := ValidateTerminalOutcome(
		p.ceremony,
		p.workID,
		outcome,
		evidence,
	); err != nil {
		return fmt.Errorf(
			"terminal outcome for ceremony [%s] rejected: [%v]: %w",
			p.ceremony,
			err,
			ErrInvalidTerminalOutcome,
		)
	}
	// The seats the holder announced it was operating are read here, not in the
	// shared validator, because only the permit knows them. p.operatedMembers is
	// written once at issuance and never again, so it needs no lock.
	if err := ValidatePermitOperatedOwnership(
		p.ceremony,
		p.operatedMembers,
		outcome,
		evidence,
	); err != nil {
		return fmt.Errorf(
			"terminal outcome for ceremony [%s] rejected: [%v]: %w",
			p.ceremony,
			err,
			ErrInvalidTerminalOutcome,
		)
	}

	g := p.gate
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, active := g.permits[p]; !active {
		return fmt.Errorf(
			"terminal outcome for ceremony [%s] refused: %w",
			p.ceremony,
			ErrPermitClosed,
		)
	}
	if p.terminalOutcome != nil {
		if p.terminalOutcome.Outcome == outcome &&
			p.terminalOutcome.Evidence.Equal(evidence) {
			if g.quiescenceSnapshot != nil && g.recorder != nil {
				if err := g.recorder.RecordTerminalOutcome(
					*p.terminalOutcome,
				); err != nil {
					return fmt.Errorf(
						"cannot persist terminal outcome for ceremony [%s]: "+
							"[%v]: %w",
						p.ceremony,
						err,
						ErrTerminalOutcomePersistence,
					)
				}
			}

			return nil
		}

		return fmt.Errorf(
			"terminal outcome for ceremony [%s] is already [%s]: %w",
			p.ceremony,
			p.terminalOutcome.Outcome,
			ErrTerminalOutcomeAlreadyRecorded,
		)
	}

	record := &TerminalOutcomeRecord{
		RecordedAt: g.now().UTC(),
		Permit:     p.snapshot(),
		Outcome:    outcome,
		Evidence:   evidence,
	}
	// Retain the ceremony owner's immutable disposition before attempting
	// persistence. A transient journal failure can then be retried by an
	// identical call or by Close without replacing the real outcome with the
	// fail-closed unresolved marker.
	p.terminalOutcome = record

	if g.quiescenceSnapshot != nil && g.recorder != nil {
		if err := g.recorder.RecordTerminalOutcome(*record); err != nil {
			return fmt.Errorf(
				"cannot persist terminal outcome for ceremony [%s]: [%v]: %w",
				p.ceremony,
				err,
				ErrTerminalOutcomePersistence,
			)
		}
	}

	return nil
}

func (p *permit) snapshot() PermitSnapshot {
	return PermitSnapshot{
		Ceremony:            p.ceremony,
		Mode:                p.mode.String(),
		CanonicalStartBlock: p.canonicalStartBlock,
		WorkID:              p.workID,
		PermitID:            p.permitID,
		IdentityBound:       p.identityBound,
		// A snapshot outlives the call that took it — into a diagnostics
		// scrape, a quiescence inventory, a journal record — so it carries its
		// own copy rather than a window onto the permit's slice.
		OperatedMembers: slices.Clone(p.operatedMembers),
	}
}

// refuseCommitLocked records a failed commit fence and returns the sentinel
// wrapped with context. The caller must hold g.mu.
func (g *chainGate) refuseCommitLocked(
	p *permit,
	operation string,
	class CommitClass,
	height uint64,
	sentinel error,
) error {
	g.metrics.IncrementCounter(metricCommitRefusalsTotal, 1)

	gateLogger.Warnf(
		"protocol participation commit refused [ceremony=%s] [operation=%s] "+
			"[class=%s] [mode=%s] [state=%s] [currentBlock=%d]",
		p.ceremony,
		operation,
		class,
		p.mode,
		g.stateLocked(),
		height,
	)

	return fmt.Errorf(
		"%s commit [%s] for ceremony [%s] refused: %w",
		class,
		operation,
		p.ceremony,
		sentinel,
	)
}

// suppressPenaltyLocked records a suppressed penalty commit. The caller must
// hold g.mu.
func (g *chainGate) suppressPenaltyLocked(
	p *permit,
	operation string,
	height uint64,
) error {
	g.metrics.IncrementCounter(metricCommitRefusalsTotal, 1)
	if p.ceremony == TBTCHeartbeat || p.ceremony == TBTCInactivityClaim {
		g.metrics.IncrementCounter(metricHeartbeatPenaltySuppressed, 1)
	}

	gateLogger.Warnf(
		"protocol participation penalty suppressed [ceremony=%s] "+
			"[operation=%s] [mode=%s] [currentBlock=%d] [cutoverBlock=%d]",
		p.ceremony,
		operation,
		p.mode,
		height,
		g.schedule.CutoverBlock,
	)

	return fmt.Errorf(
		"penalty commit [%s] for ceremony [%s] suppressed: %w",
		operation,
		p.ceremony,
		ErrPenaltySuppressed,
	)
}

// Close implements the Permit release. It is idempotent; the permit stops
// being counted as active exactly once.
func (p *permit) Close() {
	p.closeOnce.Do(func() {
		p.cancel(ErrPermitClosed)

		g := p.gate
		g.mu.Lock()
		defer g.mu.Unlock()

		if _, active := g.permits[p]; !active {
			return
		}

		// A permit whose owner recorded nothing left no account of what its
		// ceremony came to. That is a disposition in itself and it is the one
		// the offline barrier refuses on, so it is written here rather than
		// left as a silent absence — under quiescence for the journal, and
		// always for the gate's own retained account.
		if p.terminalOutcome == nil {
			p.terminalOutcome = &TerminalOutcomeRecord{
				RecordedAt: g.now().UTC(),
				Permit:     p.snapshot(),
				Outcome:    terminalOutcomeUnresolved,
			}
		}
		g.retainTerminalOutcome(*p.terminalOutcome)

		if g.quiescenceSnapshot != nil && g.recorder != nil {
			if err := g.recorder.RecordTerminalOutcome(
				*p.terminalOutcome,
			); err != nil {
				gateLogger.Warnf(
					"protocol participation terminal outcome could not "+
						"be persisted [ceremony=%s] [outcome=%s] [error=%s]",
					p.ceremony,
					p.terminalOutcome.Outcome,
					err,
				)
			}
		}

		delete(g.permits, p)
		switch p.mode {
		case ModeLegacy:
			g.activeLegacy--
		case ModeSecurityV2:
			g.activeSecurityV2--
		}

		if g.quiescing &&
			g.activeLegacy+g.activeSecurityV2 == 0 &&
			!g.quiesceDoneClosed {
			g.quiesceDoneClosed = true
			close(g.quiesceDone)
		}
		g.maybeCloseDrainedLocked()

		g.refreshMetricsLocked()
	})
}

// maybeCloseDrainedLocked closes the drained channel once the gate no longer
// issues new permits — quiescence began or the gate closed — and the last
// counted permit has been released. A clock failure alone never drains the
// gate: it cancels permits but issuance resumes on clock recovery. The caller
// must hold g.mu.
func (g *chainGate) maybeCloseDrainedLocked() {
	if !g.quiescing && !g.closed {
		return
	}
	if g.activeLegacy+g.activeSecurityV2 > 0 {
		return
	}
	if !g.drainedClosed {
		g.drainedClosed = true
		close(g.drained)
	}
}

// State implements Gate.
func (g *chainGate) State() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()

	return Snapshot{
		State:                      g.stateLocked(),
		CutoverBlock:               g.schedule.CutoverBlock,
		CurrentBlock:               g.currentBlock,
		ClockAvailable:             g.clockAvailable,
		Quiescing:                  g.quiescing || g.closed,
		Allowed:                    g.allowedLocked(),
		ActiveCeremonies:           g.activeLegacy + g.activeSecurityV2,
		ActiveLegacyCeremonies:     g.activeLegacy,
		ActiveSecurityV2Ceremonies: g.activeSecurityV2,
		ActivePermits:              g.permitSnapshotsLocked(),
		RecentTerminalOutcomes:     g.terminalOutcomesLocked(),
	}
}

// retainTerminalOutcome adds a closed permit's disposition to the gate's own
// account of them, dropping the oldest once the account is full. The caller
// must hold g.mu.
func (g *chainGate) retainTerminalOutcome(record TerminalOutcomeRecord) {
	if len(g.terminalOutcomes) == retainedTerminalOutcomes {
		copy(g.terminalOutcomes, g.terminalOutcomes[1:])
		g.terminalOutcomes[len(g.terminalOutcomes)-1] = record
		return
	}

	g.terminalOutcomes = append(g.terminalOutcomes, record)
}

// terminalOutcomesLocked returns a copy of the gate's account of closed
// permits, oldest first. The caller must hold g.mu.
//
// The order is the order the permits closed in and is not re-sorted. What a
// reader joins on is the permit identity each record carries; the sequence is
// the one piece of information a re-sort would destroy, and it is what says
// which of two dispositions of neighbouring work came first.
func (g *chainGate) terminalOutcomesLocked() []TerminalOutcomeRecord {
	if len(g.terminalOutcomes) == 0 {
		return nil
	}

	records := make([]TerminalOutcomeRecord, 0, len(g.terminalOutcomes))
	for _, record := range g.terminalOutcomes {
		// The settlement hangs off the evidence by pointer, so a plain copy
		// would hand a reader the gate's own record to hold.
		if record.Evidence.ChainSettlement != nil {
			settlement := *record.Evidence.ChainSettlement
			record.Evidence.ChainSettlement = &settlement
		}
		// And the memberships travel by slice, which a plain copy shares for
		// the same reason.
		record.Permit.OperatedMembers = slices.Clone(
			record.Permit.OperatedMembers,
		)
		if record.Evidence.Contribution != nil {
			contribution := *record.Evidence.Contribution
			contribution.IncorporatedMembers = slices.Clone(
				contribution.IncorporatedMembers,
			)
			contribution.LocalMembers = slices.Clone(
				contribution.LocalMembers,
			)
			record.Evidence.Contribution = &contribution
		}
		records = append(records, record)
	}

	return records
}

// permitSnapshotsLocked returns a deterministic copy of the real live-permit
// registry. The caller must hold g.mu.
func (g *chainGate) permitSnapshotsLocked() []PermitSnapshot {
	snapshots := make([]PermitSnapshot, 0, len(g.permits))
	for permit := range g.permits {
		snapshots = append(snapshots, permit.snapshot())
	}

	sort.Slice(snapshots, func(i, j int) bool {
		left := snapshots[i]
		right := snapshots[j]
		if left.Ceremony != right.Ceremony {
			return left.Ceremony < right.Ceremony
		}
		if left.CanonicalStartBlock != right.CanonicalStartBlock {
			return left.CanonicalStartBlock < right.CanonicalStartBlock
		}
		if left.WorkID != right.WorkID {
			return left.WorkID < right.WorkID
		}
		return left.PermitID < right.PermitID
	})

	return snapshots
}

func cloneQuiescenceSnapshot(
	snapshot QuiescenceSnapshot,
) QuiescenceSnapshot {
	snapshot.ActivePermits = append(
		[]PermitSnapshot(nil),
		snapshot.ActivePermits...,
	)
	// Copying the list is not copying the permits: each one carries the
	// memberships its holder operates by slice, and the inventory this returns
	// is the immutable record of what the node was holding at the transition.
	for i := range snapshot.ActivePermits {
		snapshot.ActivePermits[i].OperatedMembers = slices.Clone(
			snapshot.ActivePermits[i].OperatedMembers,
		)
	}

	return snapshot
}

// QuiescenceSnapshot implements Gate.
func (g *chainGate) QuiescenceSnapshot() (QuiescenceSnapshot, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.quiescenceSnapshot == nil {
		return QuiescenceSnapshot{}, false
	}

	return cloneQuiescenceSnapshot(*g.quiescenceSnapshot), true
}

// Quiesce implements Gate.
func (g *chainGate) Quiesce(cause error) <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.quiescing && !g.closed {
		g.quiescing = true
		g.metrics.IncrementCounter(metricQuiesceTotal, 1)

		captured := QuiescenceSnapshot{
			SchemaVersion:              QuiescenceSnapshotSchemaVersion,
			CapturedAt:                 g.now().UTC(),
			ReleaseVersion:             g.releaseVersion,
			ReleaseRevision:            g.releaseRevision,
			ReleaseEpoch:               CompiledEpoch.String(),
			CutoverBlock:               g.schedule.CutoverBlock,
			CurrentBlock:               g.currentBlock,
			ClockAvailable:             g.clockAvailable,
			State:                      StateQuiescing.String(),
			QuiesceCause:               fmt.Sprint(cause),
			ActiveCeremonies:           g.activeLegacy + g.activeSecurityV2,
			ActiveLegacyCeremonies:     g.activeLegacy,
			ActiveSecurityV2Ceremonies: g.activeSecurityV2,
			ActivePermits:              g.permitSnapshotsLocked(),
		}
		g.quiescenceSnapshot = &captured

		if g.recorder != nil {
			if err := g.recorder.Record(
				cloneQuiescenceSnapshot(captured),
			); err != nil {
				// The transition remains one-way and fail-closed. The stopped
				// node's offline audit will refuse rollback when the required
				// node-authored record is absent or malformed.
				gateLogger.Warnf(
					"protocol participation quiescence snapshot could not "+
						"be persisted [error=%s]",
					err,
				)
			}
			for permit := range g.permits {
				if permit.terminalOutcome == nil {
					continue
				}
				if err := g.recorder.RecordTerminalOutcome(
					*permit.terminalOutcome,
				); err != nil {
					gateLogger.Warnf(
						"protocol participation terminal outcome could not "+
							"be persisted [ceremony=%s] [outcome=%s] [error=%s]",
						permit.ceremony,
						permit.terminalOutcome.Outcome,
						err,
					)
				}
			}
		}

		gateLogger.Warnf(
			"protocol participation quiescing [reason=%s] [currentBlock=%d] "+
				"[activeLegacy=%d] [activeSecurityV2=%d]",
			cause,
			g.currentBlock,
			g.activeLegacy,
			g.activeSecurityV2,
		)

		if g.activeLegacy+g.activeSecurityV2 == 0 && !g.quiesceDoneClosed {
			g.quiesceDoneClosed = true
			close(g.quiesceDone)
		}
		g.maybeCloseDrainedLocked()

		g.refreshMetricsLocked()
	}

	return g.quiesceDone
}

// Drained implements Gate. The channel is created once at construction and
// never replaced, so no lock is needed to hand it out.
func (g *chainGate) Drained() <-chan struct{} {
	return g.drained
}

// Close implements Gate.
func (g *chainGate) Close() {
	g.closeOnce.Do(func() {
		g.mu.Lock()

		g.closed = true

		for p := range g.permits {
			if context.Cause(p.ctx) == nil {
				p.cancel(ErrQuiesceDeadline)
				g.metrics.IncrementCounter(metricQuiesceForcedAbortsTotal, 1)

				gateLogger.Warnf(
					"protocol participation forced abort at quiesce deadline "+
						"[ceremony=%s] [mode=%s] [canonicalStartBlock=%d] "+
						"[currentBlock=%d]",
					p.ceremony,
					p.mode,
					p.canonicalStartBlock,
					g.currentBlock,
				)
			}
		}

		if !g.quiesceDoneClosed {
			g.quiesceDoneClosed = true
			close(g.quiesceDone)
		}
		g.maybeCloseDrainedLocked()

		g.refreshMetricsLocked()
		g.mu.Unlock()

		g.cancel()
		<-g.loopDone
	})
}
