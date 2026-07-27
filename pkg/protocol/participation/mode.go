// Package participation implements the chain-clocked protocol cutover from
// the legacy cryptographic behavior to the hardened security-v2 behavior: the
// compiled release epoch, the one-value cutover schedule and its per-network
// resolver, the participation gate that issues per-ceremony permits with the
// protocol mode pinned from each ceremony's canonical chain anchor, and the
// node-local roster of post-cutover legacy peer sightings.
//
// The gate is the only component that derives protocol modes from the chain
// clock. There is no process-wide mutable mode: a pre-cutover legacy ceremony
// may still be completing while a post-cutover security-v2 ceremony begins,
// and each carries its own immutable permit.
package participation

// ProtocolMode identifies which cryptographic compatibility mode a ceremony
// participates in.
//
// A mode is selected by the gate from a ceremony's canonical chain anchor at
// permit issuance — legacy below the cutover block, security-v2 at or above
// it — and is pinned in that ceremony's permit for its entire lifetime.
// Components that receive a mode directly (test fixtures, strategy bundles)
// must treat it as immutable for the ceremony it was issued for.
type ProtocolMode uint8

const (
	// ModeLegacy is the production-compatible legacy cryptographic mode: the
	// session-ID, key-derivation, and hash-to-point behavior of the pre-hardening
	// releases.
	ModeLegacy ProtocolMode = iota + 1
	// ModeSecurityV2 is the hardened PR #4109 cryptographic mode.
	ModeSecurityV2
)

// String returns the canonical string form of the protocol mode: exactly
// "legacy" or "security_v2". Any other value renders as "unknown".
func (m ProtocolMode) String() string {
	switch m {
	case ModeLegacy:
		return "legacy"
	case ModeSecurityV2:
		return "security_v2"
	default:
		return "unknown"
	}
}
