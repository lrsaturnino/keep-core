package tbtc

import (
	"golang.org/x/time/rate"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// announcerMismatchMetrics is the minimal metrics sink used when handling an
// announcer session-ID mismatch. It is satisfied by the client-info performance
// metrics recorder.
type announcerMismatchMetrics interface {
	IncrementCounter(name string, value float64)
}

// announcerMismatchLogger is the minimal logging sink used when handling an
// announcer session-ID mismatch. It is satisfied by *zap.SugaredLogger.
type announcerMismatchLogger interface {
	Infof(format string, args ...interface{})
}

type participationGateStateReader interface {
	State() participation.Snapshot
}

func currentParticipationGateState(gate participationGateStateReader) string {
	if gate == nil {
		return "unknown"
	}

	return gate.State().State.String()
}

// handleAnnouncerSessionMismatch centralizes the node-local response to a
// membership-valid, protocol-matched announcement whose session ID differs from
// the local one. It is invoked once per mismatching sender per Announce call
// (the announcer deduplicates) and:
//
//   - increments the session-ID mismatch counter for every unequal ID, plus the
//     cross-format counter when the difference is legacy<->hardened;
//   - attributes the sighting to an operator address (mapping the 1-based sender
//     member index through operatorAddresses with an explicit bounds check) and
//     records it in the node-local cutover roster, which itself keeps only
//     genuine post-cutover legacy stragglers; and
//   - emits a rate-limited INFO log that carries only the classified formats,
//     never a raw session ID.
//
// Any of metrics, roster, logger, or logLimiter may be nil; each is guarded
// independently so the handler is safe on a client-info-disabled node.
func handleAnnouncerSessionMismatch(
	logger announcerMismatchLogger,
	logLimiter *rate.Limiter,
	metrics announcerMismatchMetrics,
	roster *participation.CutoverPeerRoster,
	currentMode participation.ProtocolMode,
	gateState string,
	operatorAddresses chain.Addresses,
	protocolID string,
	sender group.MemberIndex,
	expectedFormat announcer.SessionIDFormat,
	observedFormat announcer.SessionIDFormat,
) {
	// Every unequal, membership-valid announcement is a mismatch; only a
	// legacy<->hardened difference is a cross-format peer.
	if metrics != nil {
		metrics.IncrementCounter(clientinfo.MetricAnnouncerSessionIDMismatchTotal, 1)
		if announcer.IsCrossFormatMismatch(expectedFormat, observedFormat) {
			metrics.IncrementCounter(clientinfo.MetricAnnouncerCrossFormatPeerTotal, 1)
		}
	}

	// Attribute the sighting to an operator address and record it. The roster
	// itself filters to genuine post-cutover legacy stragglers (a security-v2
	// permit observing a legacy peer).
	if roster != nil && sender >= 1 && int(sender) <= len(operatorAddresses) {
		roster.ObserveLegacy(
			protocolID,
			sender,
			operatorAddresses[sender-1],
			currentMode,
			expectedFormat,
			observedFormat,
		)
	}

	if logger != nil && (logLimiter == nil || logLimiter.Allow()) {
		logger.Infof(
			"protocol announcement rejected: session ID mismatch "+
				"[protocol=%s] [member=%d] [expectedFormat=%s] "+
				"[observedFormat=%s] [permitMode=%s] [gateState=%s]",
			protocolID,
			sender,
			expectedFormat,
			observedFormat,
			currentMode,
			gateState,
		)
	}
}
