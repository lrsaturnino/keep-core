package participation

import (
	"strings"
	"testing"

	commonEthereum "github.com/keep-network/keep-common/pkg/chain/ethereum"
)

func TestResolveAndValidate_MainnetRejectsOverride(t *testing.T) {
	for _, value := range []uint64{0, 1, 124000} {
		_, err := resolveAndValidate(
			commonEthereum.Mainnet,
			Config{CutoverBlock: value, CutoverBlockSet: true},
			999,
		)
		if err == nil {
			t.Fatalf(
				"expected mainnet to reject an explicit override of [%d]",
				value,
			)
		}
		if !strings.Contains(err.Error(), "protocolParticipation.cutoverBlock") {
			t.Errorf(
				"override rejection must name the offending key, got: [%v]",
				err,
			)
		}
	}
}

func TestResolveAndValidate_MainnetRejectsZeroCompiled(t *testing.T) {
	_, err := resolveAndValidate(commonEthereum.Mainnet, Config{}, 0)
	if err == nil {
		t.Fatal("expected the zero compiled placeholder to be rejected")
	}
}

func TestResolveAndValidate_MainnetPlaceholderIsStillZero(t *testing.T) {
	// The public resolver uses the compiled MainnetCutoverBlock. While the
	// placeholder is zero, mainnet resolution must fail; once the release
	// commit bakes a nonzero C, it must succeed with exactly that value.
	schedule, err := ResolveAndValidate(commonEthereum.Mainnet, Config{})
	if MainnetCutoverBlock == 0 {
		if err == nil {
			t.Fatal(
				"mainnet resolution must fail while the compiled cutover " +
					"block is the zero placeholder",
			)
		}
	} else {
		if err != nil {
			t.Fatalf("unexpected error: [%v]", err)
		}
		if schedule.CutoverBlock != MainnetCutoverBlock {
			t.Errorf(
				"expected schedule cutover block [%d], got [%d]",
				MainnetCutoverBlock,
				schedule.CutoverBlock,
			)
		}
	}
}

func TestResolveAndValidate_MainnetUsesCompiledConstant(t *testing.T) {
	schedule, err := resolveAndValidate(commonEthereum.Mainnet, Config{}, 12345)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if schedule.CutoverBlock != 12345 {
		t.Errorf(
			"expected cutover block [12345], got [%d]",
			schedule.CutoverBlock,
		)
	}
}

func TestResolveAndValidate_MainnetRejectsUnprojectableCompiled(t *testing.T) {
	_, err := resolveAndValidate(
		commonEthereum.Mainnet,
		Config{},
		maxSafeMetricInteger+1,
	)
	if err == nil {
		t.Fatal("expected an unprojectable compiled cutover block rejection")
	}
}

func TestResolveAndValidate_TestnetRejectsZero(t *testing.T) {
	for _, config := range []Config{
		{},
		{CutoverBlock: 0, CutoverBlockSet: true},
	} {
		_, err := resolveAndValidate(commonEthereum.Sepolia, config, 0)
		if err == nil {
			t.Fatal("expected testnet to reject a zero cutover block")
		}
	}
}

func TestResolveAndValidate_TestnetAcceptsNonzero(t *testing.T) {
	schedule, err := resolveAndValidate(
		commonEthereum.Sepolia,
		Config{CutoverBlock: 124000, CutoverBlockSet: true},
		0,
	)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if schedule.CutoverBlock != 124000 {
		t.Errorf(
			"expected cutover block [124000], got [%d]",
			schedule.CutoverBlock,
		)
	}
}

func TestResolveAndValidate_TestnetRejectsUnprojectable(t *testing.T) {
	_, err := resolveAndValidate(
		commonEthereum.Sepolia,
		Config{CutoverBlock: maxSafeMetricInteger + 1, CutoverBlockSet: true},
		0,
	)
	if err == nil {
		t.Fatal("expected an unprojectable cutover block rejection")
	}
}

func TestResolveAndValidate_DeveloperAcceptsZeroAndNonzero(t *testing.T) {
	schedule, err := resolveAndValidate(commonEthereum.Developer, Config{}, 0)
	if err != nil {
		t.Fatalf("unexpected error for developer zero: [%v]", err)
	}
	if !schedule.Disabled() {
		t.Error("expected the developer zero schedule to be disabled")
	}

	schedule, err = resolveAndValidate(
		commonEthereum.Developer,
		Config{CutoverBlock: 42, CutoverBlockSet: true},
		0,
	)
	if err != nil {
		t.Fatalf("unexpected error for developer nonzero: [%v]", err)
	}
	if schedule.CutoverBlock != 42 {
		t.Errorf(
			"expected cutover block [42], got [%d]",
			schedule.CutoverBlock,
		)
	}
}

func TestResolveAndValidate_RejectsUnknownNetwork(t *testing.T) {
	_, err := resolveAndValidate(commonEthereum.Unknown, Config{}, 999)
	if err == nil {
		t.Fatal("expected an unknown network rejection")
	}
}

func TestSchedule_ModeFor(t *testing.T) {
	schedule := Schedule{CutoverBlock: 1000}

	for anchor, expected := range map[uint64]ProtocolMode{
		0:    ModeLegacy,
		1:    ModeLegacy,
		999:  ModeLegacy,
		1000: ModeSecurityV2,
		1001: ModeSecurityV2,
	} {
		if mode := schedule.ModeFor(anchor); mode != expected {
			t.Errorf(
				"anchor [%d]: expected mode [%s], got [%s]",
				anchor,
				expected,
				mode,
			)
		}
	}

	disabled := Schedule{}
	for _, anchor := range []uint64{0, 1, 1000000} {
		if mode := disabled.ModeFor(anchor); mode != ModeLegacy {
			t.Errorf(
				"disabled schedule anchor [%d]: expected legacy, got [%s]",
				anchor,
				mode,
			)
		}
	}
}

func TestSchedule_StateFor(t *testing.T) {
	schedule := Schedule{CutoverBlock: 1000}

	for currentBlock, expected := range map[uint64]State{
		0:    StateOpenLegacy,
		999:  StateOpenLegacy,
		1000: StateOpenSecurityV2,
		1001: StateOpenSecurityV2,
	} {
		if state := schedule.StateFor(currentBlock); state != expected {
			t.Errorf(
				"current block [%d]: expected state [%s], got [%s]",
				currentBlock,
				expected,
				state,
			)
		}
	}

	if state := (Schedule{}).StateFor(1000000); state != StateDisabled {
		t.Errorf("disabled schedule: expected disabled state, got [%s]", state)
	}
}

func TestState_StringAndMetricMapping(t *testing.T) {
	// The numeric values are the gate-state metric contract:
	// 0=disabled, 1=open_legacy, 2=open_security_v2, 3=quiescing,
	// 4=clock_unavailable.
	expected := map[State]struct {
		text  string
		value uint8
	}{
		StateDisabled:         {"disabled", 0},
		StateOpenLegacy:       {"open_legacy", 1},
		StateOpenSecurityV2:   {"open_security_v2", 2},
		StateQuiescing:        {"quiescing", 3},
		StateClockUnavailable: {"clock_unavailable", 4},
	}

	for state, expectation := range expected {
		if state.String() != expectation.text {
			t.Errorf(
				"expected state string [%s], got [%s]",
				expectation.text,
				state.String(),
			)
		}
		if uint8(state) != expectation.value {
			t.Errorf(
				"state [%s]: expected metric value [%d], got [%d]",
				expectation.text,
				expectation.value,
				uint8(state),
			)
		}
	}

	if State(250).String() != "unknown" {
		t.Error("expected an out-of-range state to render as unknown")
	}
}

func TestReleaseEpoch_String(t *testing.T) {
	if CompiledEpoch.String() != "security_v2_cutover" {
		t.Errorf(
			"expected compiled epoch [security_v2_cutover], got [%s]",
			CompiledEpoch.String(),
		)
	}
	if ReleaseEpoch(0).String() != "unknown" {
		t.Error("expected an unrecognized epoch to render as unknown")
	}
}
