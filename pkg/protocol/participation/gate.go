package participation

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
)

// Permit authorizes local participation in one ceremony. Its ceremony,
// canonical start block, and protocol mode are immutable for its entire
// lifetime: crossing the cutover block never cancels a permit or mutates its
// mode. A permit is counted as active until its idempotent Close.
type Permit interface {
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
	// CheckCommit is the last-moment commit fence, called immediately before
	// activating newly generated key material, submitting results or claims,
	// or broadcasting Bitcoin transactions. It reads a fresh chain height and
	// enforces the per-mode fence rules; a returned error is a gate sentinel,
	// not a normal protocol timeout.
	CheckCommit(operation string, class CommitClass) error
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
}

// Gate issues per-ceremony participation permits with the protocol mode pinned
// from each ceremony's canonical chain anchor. It is the only component that
// derives protocol modes from the chain clock; cryptographic packages never
// query the clock themselves.
type Gate interface {
	// Begin issues a permit for a new ceremony. It reads the chain clock
	// synchronously, rejects a zero anchor while a cutover schedule is active,
	// rejects an anchor ahead of the current height, and derives the mode only
	// from the canonical start block. It returns ErrInvalidAnchor,
	// ErrClockUnavailable, or ErrQuiescing.
	Begin(ceremony Ceremony, canonicalStartBlock uint64) (Permit, error)
	// Resume issues a permit for the beacon relay restart path only. The
	// caller must have verified on chain that the relay request is still live
	// and pass its on-chain start block; the mode pins from that block exactly
	// as in Begin. Any other ceremony class returns ErrResumeUnsupported.
	Resume(ceremony Ceremony, canonicalStartBlock uint64) (Permit, error)
	// State returns a point-in-time observability snapshot.
	State() Snapshot
	// Quiesce atomically refuses all new permits, keeps existing permits
	// alive to natural completion, and refuses penalty commits from the
	// transition onward. It is idempotent and always returns the same channel,
	// which closes when the active permit count reaches zero or when Close
	// force-cancels the remainder.
	Quiesce(cause error) <-chan struct{}
	// Close is the terminal shutdown: it force-cancels any remaining permits
	// with ErrQuiesceDeadline, closes the quiesce channel, and stops the
	// clock supervisor. It is idempotent.
	Close()
}

// GateMetricsRecorder is the minimal metrics sink the gate needs. It is
// satisfied by the client-info performance metrics registry.
type GateMetricsRecorder interface {
	IncrementCounter(name string, value float64)
	SetGauge(name string, value float64)
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

	ctx    context.Context
	cancel context.CancelCauseFunc

	closeOnce sync.Once
}

func (p *permit) Context() context.Context    { return p.ctx }
func (p *permit) Ceremony() Ceremony          { return p.ceremony }
func (p *permit) CanonicalStartBlock() uint64 { return p.canonicalStartBlock }
func (p *permit) Mode() ProtocolMode          { return p.mode }

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

	closeOnce sync.Once

	mu                sync.Mutex
	currentBlock      uint64
	clockAvailable    bool
	quiescing         bool
	closed            bool
	quiesceDone       chan struct{}
	quiesceDoneClosed bool
	permits           map[*permit]struct{}
	activeLegacy      uint64
	activeSecurityV2  uint64
	lastState         State
}

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
) (Gate, error) {
	return newGate(
		ctx,
		schedule,
		blockCounter,
		metrics,
		gateSupervisorPollInterval,
	)
}

// newGate is the poll-interval-injecting constructor used by tests.
func newGate(
	ctx context.Context,
	schedule Schedule,
	blockCounter chain.BlockCounter,
	metrics GateMetricsRecorder,
	pollInterval time.Duration,
) (*chainGate, error) {
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
		quiesceDone:       make(chan struct{}),
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
		case height, ok := <-cutoverWaiter:
			// A nil channel (disabled schedule, or already handled) blocks
			// forever, which is the intended disarm.
			cutoverWaiter = nil
			g.mu.Lock()
			if !ok {
				// The waiter closed before its target: a clock failure.
				g.clockFailureLocked(
					"cutover_waiter",
					fmt.Errorf("cutover block waiter closed before target"),
				)
			} else {
				g.clockAvailable = true
				if height > g.currentBlock {
					g.currentBlock = height
				}
				g.refreshMetricsLocked()
			}
			g.mu.Unlock()
		case <-ticker.C:
			g.poll()
		}
	}
}

// poll performs one supervisor read of the chain clock. A failure cancels all
// permits; a success recomputes the current state, but previously canceled
// permits do not revive.
func (g *chainGate) poll() {
	height, err := g.blockCounter.CurrentBlock()

	g.mu.Lock()
	defer g.mu.Unlock()

	if err != nil {
		g.clockFailureLocked("supervisor_poll", err)
		return
	}
	g.clockAvailable = true
	g.currentBlock = height
	g.refreshMetricsLocked()
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
) (Permit, error) {
	return g.issue(ceremony, canonicalStartBlock, false)
}

// Resume implements Gate.
func (g *chainGate) Resume(
	ceremony Ceremony,
	canonicalStartBlock uint64,
) (Permit, error) {
	return g.issue(ceremony, canonicalStartBlock, true)
}

func (g *chainGate) issue(
	ceremony Ceremony,
	canonicalStartBlock uint64,
	resume bool,
) (Permit, error) {
	if _, known := knownCeremonies[ceremony]; !known {
		return nil, fmt.Errorf("unknown ceremony [%s]", ceremony)
	}

	// The synchronous, authoritative chain read happens outside the lock so a
	// slow chain call never blocks fences, closes, or the supervisor.
	height, clockErr := g.blockCounter.CurrentBlock()

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed || g.quiescing {
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"quiescing",
			ErrQuiescing,
		)
	}

	if clockErr != nil {
		g.clockFailureLocked("issue_permit", clockErr)
		return nil, g.refuseLocked(
			ceremony,
			canonicalStartBlock,
			"clock_unavailable",
			ErrClockUnavailable,
		)
	}
	g.clockAvailable = true
	g.currentBlock = height

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

	ctx, cancel := context.WithCancelCause(g.ctx)
	p := &permit{
		gate:                g,
		ceremony:            ceremony,
		canonicalStartBlock: canonicalStartBlock,
		mode:                mode,
		ctx:                 ctx,
		cancel:              cancel,
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
	// the lock.
	height, clockErr := g.blockCounter.CurrentBlock()

	g.mu.Lock()
	defer g.mu.Unlock()

	if clockErr != nil {
		g.clockFailureLocked("commit_fence", clockErr)
		return g.refuseCommitLocked(
			p,
			operation,
			class,
			g.currentBlock,
			ErrClockUnavailable,
		)
	}
	g.clockAvailable = true
	g.currentBlock = height

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

		g.refreshMetricsLocked()
	})
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
	}
}

// Quiesce implements Gate.
func (g *chainGate) Quiesce(cause error) <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.quiescing && !g.closed {
		g.quiescing = true
		g.metrics.IncrementCounter(metricQuiesceTotal, 1)

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

		g.refreshMetricsLocked()
	}

	return g.quiesceDone
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

		g.refreshMetricsLocked()
		g.mu.Unlock()

		g.cancel()
		<-g.loopDone
	})
}
