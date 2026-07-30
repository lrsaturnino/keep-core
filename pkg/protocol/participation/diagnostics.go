package participation

import (
	"encoding/json"
	"math/big"

	"github.com/ipfs/go-log"
)

var diagnosticsLogger = log.Logger("keep-participation")

const (
	// DiagnosticsSourceCutoverLegacyPeers is the diagnostics object carrying
	// the node-local cutover peer roster snapshot.
	DiagnosticsSourceCutoverLegacyPeers = "cutover_legacy_peers"
	// DiagnosticsSourceProtocolParticipation is the diagnostics object
	// carrying the gate's identity and live state.
	DiagnosticsSourceProtocolParticipation = "protocol_participation"
)

// DiagnosticsRegistry is the minimal diagnostics sink the participation
// sources need. It is satisfied by the client-info registry.
type DiagnosticsRegistry interface {
	RegisterDiagnosticSource(name string, source func() string)
}

// RosterSnapshotSource surfaces the node-local cutover peer roster.
type RosterSnapshotSource interface {
	Snapshot() CutoverPeerRosterSnapshot
}

// ChainIdentitySource surfaces the chain id of the endpoint this node is
// actually connected to.
//
// It is taken from the connected endpoint rather than from the configuration
// because a cutover block means nothing without the chain it counts on: a node
// armed with the right C against the wrong chain is exactly the
// misconfiguration a readiness scrape has to be able to see, and a configured
// value would only ever agree with itself.
type ChainIdentitySource interface {
	ChainID() *big.Int
}

// RegisterDiagnosticSources registers the cutover observability contract on
// the given diagnostics registry: the node-local legacy-peer roster, and the
// gate's identity and live state.
//
// Registration happens on the production startup path, so this function is the
// single definition of both the source names and the emitted field set — a
// scrape reads exactly what is registered here.
func RegisterDiagnosticSources(
	registry DiagnosticsRegistry,
	gate Gate,
	roster RosterSnapshotSource,
	chainIdentity ChainIdentitySource,
	cutoverBlockSource string,
) {
	// Expose the node-local cutover peer roster snapshot as a top-level
	// diagnostics object so port-enabled nodes surface which operators are
	// observed on the legacy release across the cutover.
	registry.RegisterDiagnosticSource(
		DiagnosticsSourceCutoverLegacyPeers,
		func() string {
			bytes, err := json.Marshal(roster.Snapshot())
			if err != nil {
				diagnosticsLogger.Errorf(
					"error on serializing cutover peer roster to JSON: [%v]",
					err,
				)
				return ""
			}
			return string(bytes)
		},
	)

	// Expose the gate's identity and live state so a diagnostics scrape
	// answers the readiness questions directly: which epoch this artifact is,
	// which chain it clocks itself against, which cutover block it compiled or
	// resolved, and what the gate is doing right now.
	registry.RegisterDiagnosticSource(
		DiagnosticsSourceProtocolParticipation,
		func() string {
			// The chain id is re-read per scrape from the connected endpoint
			// so the emitted value can never outlive the handle it describes.
			chainID := chainIdentity.ChainID()
			if chainID == nil {
				diagnosticsLogger.Errorf(
					"connected chain reported no chain id; " +
						"participation diagnostics cannot be composed",
				)
				return ""
			}

			snapshot := gate.State()
			// The permits themselves, and not only how many there are. A
			// count answers "this node holds two legacy ceremonies" and
			// nothing more, so an observer watching work cross the cutover
			// has to fall back on comparing fleet-wide totals — which any
			// two unrelated ceremonies moving in step will satisfy. The
			// identities let it name the permit that crossed instead. The
			// fields are the same stable public identities the quiescence
			// record carries; no key material or protocol input is exposed.
			permits := snapshot.ActivePermits
			if permits == nil {
				permits = []PermitSnapshot{}
			}
			// What became of the permits that are no longer here. A live
			// reading names the work a node is holding; without this, the
			// moment that work finishes it leaves nothing behind, and an
			// observer following work across the cutover has to take some
			// other party's word for how it ended. These are the node's own
			// records, written by each ceremony's owner, and they carry the
			// same permit identities the live list does — so a permit seen
			// held can be followed to the disposition its owner recorded for
			// it. Public identities only, exactly as the quiescence journal
			// that outlives them carries.
			terminalOutcomes := snapshot.RecentTerminalOutcomes
			if terminalOutcomes == nil {
				terminalOutcomes = []TerminalOutcomeRecord{}
			}
			// Whether the account above can be followed at all. It lives in
			// memory, so a reader joining a permit it saw held to the ending its
			// holder recorded has to be able to tell an account that never held
			// the record from one that held it and lost it — to a restart, or to
			// its own bound. Those are opposite answers: the first says this node
			// did not do that work, the second says nobody can say what it did,
			// and a reader that cannot distinguish them attributes the work to
			// whoever else was on the network.
			gateInstance := snapshot.GateInstance
			if gateInstance == "" {
				gateInstance = "unknown"
			}
			bytes, err := json.Marshal(map[string]interface{}{
				"protocol_epoch":                CompiledEpoch.String(),
				"ethereum_chain_id":             chainID.String(),
				"cutover_block":                 snapshot.CutoverBlock,
				"cutover_block_source":          cutoverBlockSource,
				"gate_state":                    snapshot.State.String(),
				"current_block":                 snapshot.CurrentBlock,
				"clock_available":               snapshot.ClockAvailable,
				"allowed":                       snapshot.Allowed,
				"quiescing":                     snapshot.Quiescing,
				"active_ceremonies":             snapshot.ActiveCeremonies,
				"active_legacy_ceremonies":      snapshot.ActiveLegacyCeremonies,
				"active_security_v2_ceremonies": snapshot.ActiveSecurityV2Ceremonies,
				"active_permits":                permits,
				"recent_terminal_outcomes":      terminalOutcomes,
				"gate_instance":                 gateInstance,
				"forgotten_terminal_outcomes": snapshot.
					ForgottenTerminalOutcomes,
			})
			if err != nil {
				diagnosticsLogger.Errorf(
					"error on serializing participation state to JSON: [%v]",
					err,
				)
				return ""
			}
			return string(bytes)
		},
	)
}
