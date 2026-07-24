// Package participation contains observability primitives used to track a
// coordinated protocol cutover from the legacy cryptographic behavior to the
// hardened security-v2 behavior.
//
// This package deliberately contains only the decoupled, self-contained pieces
// of the cutover observability contract: the process-scoped protocol mode and
// the node-local roster of post-cutover legacy peer sightings. The block-height
// cutover gate that would select the mode from a canonical chain anchor is
// intentionally NOT part of this package yet; it can adopt the ProtocolMode
// type below unchanged when it lands.
package participation

// ProtocolMode identifies which cryptographic compatibility mode a ceremony
// participates in.
//
// It is a small, self-contained, inert type. Nothing in this package selects a
// mode from a block height, configuration, or gate; callers supply the mode
// explicitly. The future cutover gate is expected to derive the mode from a
// ceremony's canonical chain anchor and pin it for the ceremony lifetime.
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
