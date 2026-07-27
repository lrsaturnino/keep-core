package participation

import (
	"fmt"

	commonEthereum "github.com/keep-network/keep-common/pkg/chain/ethereum"
)

// Schedule is the resolved one-value cutover schedule. The cutover block C is
// the only activation height: there is no drain block, stop block, or
// separately selected start block. Crossing C never cancels a permit, mutates
// its mode, or reinterprets persisted messages; it only changes the mode
// selected for ceremonies canonically anchored at or after it.
type Schedule struct {
	// CutoverBlock is the cutover block C. Zero means the developer-only
	// disabled schedule, in which every ceremony participates in legacy mode;
	// zero is rejected during resolution for every production network.
	CutoverBlock uint64
}

// State is the externally visible protocol participation state of the process.
// It is observability, not the mode selector for already-started work: the
// per-ceremony mode is pinned from the ceremony's canonical chain anchor at
// permit issuance and never changes afterwards.
type State uint8

// The State values double as the numeric gate-state metric mapping and must
// keep their exact order: 0=disabled, 1=open_legacy, 2=open_security_v2,
// 3=quiescing, 4=clock_unavailable.
const (
	// StateDisabled is the developer-only all-zero schedule: the gate issues
	// legacy permits unconditionally. It is never accepted as production
	// cutover evidence.
	StateDisabled State = iota
	// StateOpenLegacy means the current chain height is below the cutover
	// block: new ceremonies begin in legacy mode.
	StateOpenLegacy
	// StateOpenSecurityV2 means the current chain height is at or above the
	// cutover block: new ceremonies begin in security-v2 mode.
	StateOpenSecurityV2
	// StateQuiescing means process quiescence began: no new permits are
	// issued, existing permits run to natural completion, and penalty commits
	// are refused.
	StateQuiescing
	// StateClockUnavailable means a synchronous chain-clock read failed: the
	// gate refuses new work and has canceled all outstanding permits.
	StateClockUnavailable
)

// String returns the canonical string form of the participation state.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "disabled"
	case StateOpenLegacy:
		return "open_legacy"
	case StateOpenSecurityV2:
		return "open_security_v2"
	case StateQuiescing:
		return "quiescing"
	case StateClockUnavailable:
		return "clock_unavailable"
	default:
		return "unknown"
	}
}

// Disabled returns true for the developer-only all-zero schedule.
func (s Schedule) Disabled() bool {
	return s.CutoverBlock == 0
}

// ModeFor returns the protocol mode for a ceremony with the given canonical
// chain anchor: legacy below the cutover block, security-v2 at or above it.
// The disabled schedule always selects legacy. The result depends only on the
// anchor and the compiled schedule, never on the local current height, so a
// pre-cutover chain event confirmed or delivered after the cutover block still
// classifies as legacy.
func (s Schedule) ModeFor(canonicalStartBlock uint64) ProtocolMode {
	if s.Disabled() || canonicalStartBlock < s.CutoverBlock {
		return ModeLegacy
	}
	return ModeSecurityV2
}

// StateFor returns the open participation state derived from the given current
// chain height. Quiescence and clock failure are process conditions layered on
// top by the gate; they are not derivable from a height.
func (s Schedule) StateFor(currentBlock uint64) State {
	if s.Disabled() {
		return StateDisabled
	}
	if currentBlock < s.CutoverBlock {
		return StateOpenLegacy
	}
	return StateOpenSecurityV2
}

// Config is the protocol participation configuration surface. On mainnet the
// cutover block is exclusively the compiled MainnetCutoverBlock and supplying
// any override — including an explicit zero — is a startup error. Testnet
// release rehearsals must supply a nonzero cutover block. Developer mode may
// use zero for the disabled schedule.
type Config struct {
	// CutoverBlock is the non-mainnet cutover block override, supplied via the
	// [protocolParticipation] configuration section or the
	// --protocolParticipation.cutoverBlock flag.
	CutoverBlock uint64

	// CutoverBlockSet records whether the cutover block was explicitly
	// supplied at all, via flag or configuration file. Mainnet rejection is
	// keyed on this presence, not on the decoded numeric value, so an explicit
	// zero is rejected too. It is populated by command wiring from flag/key
	// presence and is deliberately not decodable from the configuration file
	// itself.
	CutoverBlockSet bool `mapstructure:"-"`
}

// ResolveAndValidate resolves the cutover schedule for the given Ethereum
// network from the compiled mainnet constant and the supplied configuration,
// enforcing the per-network validation rules. It performs configuration-only
// checks and is intended to run at the beginning of client start, before the
// Ethereum connection is established.
func ResolveAndValidate(
	network commonEthereum.Network,
	config Config,
) (Schedule, error) {
	return resolveAndValidate(network, config, MainnetCutoverBlock)
}

// resolveAndValidate is the compiled-constant-injecting resolver, split out so
// tests can exercise both the zero placeholder rejection and the reviewed
// nonzero release behavior without editing the constant.
func resolveAndValidate(
	network commonEthereum.Network,
	config Config,
	compiledMainnetCutoverBlock uint64,
) (Schedule, error) {
	switch network {
	case commonEthereum.Mainnet:
		if config.CutoverBlockSet {
			return Schedule{}, fmt.Errorf(
				"the [protocolParticipation.cutoverBlock] setting is not "+
					"allowed on mainnet: the cutover block is a compiled "+
					"release constant; remove the setting (supplied value: "+
					"[%d])",
				config.CutoverBlock,
			)
		}
		if compiledMainnetCutoverBlock == 0 {
			return Schedule{}, fmt.Errorf(
				"the compiled mainnet cutover block is the zero placeholder; " +
					"this artifact is not a reviewed cutover release and " +
					"must not participate on mainnet",
			)
		}
		if err := validateMetricProjectable(
			compiledMainnetCutoverBlock,
		); err != nil {
			return Schedule{}, err
		}
		return Schedule{CutoverBlock: compiledMainnetCutoverBlock}, nil
	case commonEthereum.Sepolia:
		if config.CutoverBlock == 0 {
			return Schedule{}, fmt.Errorf(
				"testnet requires a nonzero " +
					"[protocolParticipation.cutoverBlock]: release " +
					"rehearsals must supply the rehearsed cutover block",
			)
		}
		if err := validateMetricProjectable(config.CutoverBlock); err != nil {
			return Schedule{}, err
		}
		return Schedule{CutoverBlock: config.CutoverBlock}, nil
	case commonEthereum.Developer:
		if err := validateMetricProjectable(config.CutoverBlock); err != nil {
			return Schedule{}, err
		}
		return Schedule{CutoverBlock: config.CutoverBlock}, nil
	default:
		return Schedule{}, fmt.Errorf(
			"cannot resolve the protocol participation schedule for the "+
				"unrecognized Ethereum network [%v]",
			network,
		)
	}
}

// validateMetricProjectable rejects an Ethereum block height that cannot be
// represented exactly by the float64 metrics projection. Decisions always use
// uint64; this only guards the observability contract, under which every
// exported height gauge — the cutover block and the current block — must equal
// the decision value exactly.
func validateMetricProjectable(blockHeight uint64) error {
	if blockHeight > maxSafeMetricInteger {
		return fmt.Errorf(
			"block height [%d] exceeds the maximum precisely projectable "+
				"metric value [%d]",
			blockHeight,
			maxSafeMetricInteger,
		)
	}
	return nil
}
