package participation

// ReleaseEpoch identifies a compiled release artifact of the client with
// respect to the coordinated protocol cutover. It names the artifact, not the
// cryptographic mode of any particular ceremony: a single cutover-release
// process participates in legacy ceremonies before the cutover block and in
// security-v2 ceremonies canonically anchored at or after it.
type ReleaseEpoch uint8

const (
	// EpochSecurityV2Cutover identifies the single cutover release: one
	// compiled binary carrying both the production-compatible legacy protocol
	// behavior and the hardened security-v2 behavior, selecting between them
	// per ceremony from the ceremony's canonical chain anchor.
	EpochSecurityV2Cutover ReleaseEpoch = iota + 1
)

// CompiledEpoch is the release epoch of this artifact. It is changed only by a
// reviewed release commit and MUST NOT be selectable by an environment
// variable, configuration file, CLI flag, mutable image tag, or remote
// service. It is exported through client-info, diagnostics, and the startup
// log so fleet inventory can verify the exact artifact an instance runs.
const CompiledEpoch = EpochSecurityV2Cutover

// String returns the canonical string form of the release epoch: exactly
// "security_v2_cutover" for the cutover release. Any other value renders as
// "unknown".
func (e ReleaseEpoch) String() string {
	switch e {
	case EpochSecurityV2Cutover:
		return "security_v2_cutover"
	default:
		return "unknown"
	}
}

// MainnetCutoverBlock is the immutable mainnet cutover block C. A ceremony
// whose canonical chain anchor is below this Ethereum block participates with
// legacy cryptography for its entire lifetime; a ceremony anchored at or after
// it participates with security-v2 cryptography.
//
// The zero placeholder is a deliberate release blocker: mainnet schedule
// resolution fails until a reviewed release commit replaces it with the block
// height published in the operator notice. Like
// tbtc.DepositSweepEveryWindowActivationBlock, this is a release-baked
// constant that every operator must be running before the block is reached; on
// mainnet it cannot be overridden at runtime, and supplying an override at all
// is a startup error.
const MainnetCutoverBlock = uint64(0) // R1 release commit MUST replace
