package tbtc

import (
	"math/big"

	"github.com/ipfs/go-log/v2"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// recordPermitTerminalOutcome records the node-owned final disposition of a
// ceremony on its participation permit. Only the ceremony owner can author it,
// so this is the single place every tBTC ceremony reports what it durably left
// behind. A failure to record is logged and never propagated: the permit still
// closes and the gate falls back to the unresolved marker, which fails the
// offline rollback barrier closed rather than inventing an outcome.
func recordPermitTerminalOutcome(
	actionLogger log.StandardLogger,
	permit participation.Permit,
	outcome participation.TerminalOutcome,
	evidence participation.TerminalEvidence,
) {
	if permit == nil {
		return
	}

	if err := permit.RecordTerminalOutcome(outcome, evidence); err != nil {
		actionLogger.Warnf(
			"could not persist the node-authored terminal outcome "+
				"[ceremony=%s] [permit=%s] [outcome=%s]: [%v]",
			permit.Ceremony(),
			permit.PermitID(),
			outcome,
			err,
		)
	}
}

// recordPermitNoThreshold records that a ceremony ended without producing a
// threshold result or any durable state transition this node owns. It is the
// honest disposition for a ceremony that never got past its protocol steps,
// including one the release gate canceled: no key material, no signed
// transaction, and no chain submission was left behind.
func recordPermitNoThreshold(
	actionLogger log.StandardLogger,
	permit participation.Permit,
) {
	recordPermitTerminalOutcome(
		actionLogger,
		permit,
		participation.TerminalOutcomeExhausted,
		participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceNoThreshold,
		},
	)
}

// signatureComponentBytes returns the big-endian bytes of a tECDSA signature
// component. The signature type admits nil components — its own equality check
// compares them — so the terminal recorder, which runs deferred on the action's
// exit path, must not dereference one.
func signatureComponentBytes(component *big.Int) []byte {
	if component == nil {
		return nil
	}

	return component.Bytes()
}
