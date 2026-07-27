package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

const releaseManifestRepositoryPath = "../scripts/release/pr4109/release-manifest.json"

const releaseManifestDeployDirectory = "../scripts/release/pr4109/deploy"

// validReleaseManifestForTests builds a manifest that must pass validation:
// the derived termination grace under the reviewed default allowance,
// wrapped in the identity fields of the current artifact.
func validReleaseManifestForTests(t *testing.T) releaseManifest {
	t.Helper()

	grace, err := deriveTerminationGrace(defaultForcedCancellationAllowanceSeconds)
	if err != nil {
		t.Fatalf("unexpected derivation error: [%v]", err)
	}

	return releaseManifest{
		SchemaVersion:    releaseManifestSchemaVersion,
		GeneratedAt:      "2026-07-27T23:11:28Z",
		ProtocolEpoch:    participation.CompiledEpoch.String(),
		TerminationGrace: grace,
	}
}

// TestReleaseManifestDeriveMatchesCompiledBounds is the drift assertion for
// the manifest derivation: every number the manifest records is pinned to a
// reviewed literal, and the backstop and grace are re-checked against the
// documented arithmetic identity. It fails whenever a compiled bound moves
// without the manifest chain being deliberately re-reviewed.
func TestReleaseManifestDeriveMatchesCompiledBounds(t *testing.T) {
	grace, err := deriveTerminationGrace(defaultForcedCancellationAllowanceSeconds)
	if err != nil {
		t.Fatalf("unexpected derivation error: [%v]", err)
	}

	for _, assertion := range []struct {
		field    string
		got      uint64
		expected uint64
	}{
		{"tbtc_completion_blocks", grace.TBTCCompletionBlocks, 1200},
		{"beacon_completion_blocks", grace.BeaconCompletionBlocks, 136},
		{"beacon_inputs.group_size", grace.BeaconInputs.GroupSize, 64},
		{"beacon_inputs.result_publication_block_step", grace.BeaconInputs.ResultPublicationBlockStep, 1},
		{"beacon_inputs.relay_entry_timeout_blocks", grace.BeaconInputs.RelayEntryTimeoutBlocks, 64},
		{"maximum_legacy_completion_blocks", grace.MaximumLegacyCompletionBlocks, 1200},
		{"reviewed_margin_blocks", grace.ReviewedMarginBlocks, 100},
		{"upper_block_interval_seconds", grace.UpperBlockIntervalSeconds, 15},
		{"rpc_processing_allowance_seconds", grace.RPCProcessingAllowanceSeconds, 300},
		{"in_process_backstop_seconds", grace.InProcessBackstopSeconds, 19800},
		{"forced_cancellation_allowance_seconds", grace.ForcedCancellationAllowanceSeconds, 300},
		{"termination_grace_period_seconds", grace.TerminationGracePeriodSeconds, 20100},
	} {
		if assertion.got != assertion.expected {
			t.Errorf(
				"%s changed: expected [%d], got [%d]",
				assertion.field,
				assertion.expected,
				assertion.got,
			)
		}
	}

	backstopIdentity := (grace.MaximumLegacyCompletionBlocks+
		grace.ReviewedMarginBlocks)*grace.UpperBlockIntervalSeconds +
		grace.RPCProcessingAllowanceSeconds
	if grace.InProcessBackstopSeconds != backstopIdentity {
		t.Errorf(
			"backstop identity broken: (bound+margin)*interval+allowance is "+
				"[%d], recorded backstop is [%d]",
			backstopIdentity,
			grace.InProcessBackstopSeconds,
		)
	}

	backstopDuration, err := quiesceBackstopDeadline(
		grace.MaximumLegacyCompletionBlocks,
	)
	if err != nil {
		t.Fatalf("unexpected backstop error: [%v]", err)
	}
	if grace.InProcessBackstopSeconds != uint64(backstopDuration/time.Second) {
		t.Errorf(
			"manifest backstop [%d]s diverged from the runtime deadline [%s]",
			grace.InProcessBackstopSeconds,
			backstopDuration,
		)
	}

	graceIdentity := grace.InProcessBackstopSeconds +
		grace.ForcedCancellationAllowanceSeconds
	if grace.TerminationGracePeriodSeconds != graceIdentity {
		t.Errorf(
			"grace identity broken: backstop+allowance is [%d], recorded "+
				"grace is [%d]",
			graceIdentity,
			grace.TerminationGracePeriodSeconds,
		)
	}
	if grace.TerminationGracePeriodSeconds <= grace.InProcessBackstopSeconds {
		t.Errorf(
			"grace [%d]s must end strictly after the backstop [%d]s",
			grace.TerminationGracePeriodSeconds,
			grace.InProcessBackstopSeconds,
		)
	}
}

func TestReleaseManifestDeriveRejectsZeroAllowance(t *testing.T) {
	_, err := deriveTerminationGrace(0)
	if err == nil {
		t.Fatal("expected a zero allowance to be rejected")
	}
	if !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("unexpected rejection message: [%v]", err)
	}
}

// TestReleaseManifestFileMatchesCompiledDerivation pins the checked-in
// manifest to the compiled bounds: a stale manifest and a changed constant
// both fail here, forcing the regenerate-and-re-review step described in the
// manifest's own notes.
func TestReleaseManifestFileMatchesCompiledDerivation(t *testing.T) {
	manifest, err := loadReleaseManifest(releaseManifestRepositoryPath)
	if err != nil {
		t.Fatalf("cannot load the repository manifest: [%v]", err)
	}

	if err := validateReleaseManifest(manifest); err != nil {
		t.Errorf(
			"repository manifest rejected against the compiled bounds:\n%v",
			err,
		)
	}
}

// TestReleaseManifestDeploymentScaffoldMatchesManifest closes the chain from
// the compiled bounds through the manifest into the deployment scaffold: both
// scaffold files must carry exactly the manifest's termination grace, once,
// and the systemd drop-in must keep SIGTERM as the stop signal because that
// is the signal the lifecycle controller quiesces on.
func TestReleaseManifestDeploymentScaffoldMatchesManifest(t *testing.T) {
	manifest, err := loadReleaseManifest(releaseManifestRepositoryPath)
	if err != nil {
		t.Fatalf("cannot load the repository manifest: [%v]", err)
	}
	expected := manifest.TerminationGrace.TerminationGracePeriodSeconds

	scaffolds := []struct {
		file    string
		pattern *regexp.Regexp
	}{
		{
			"keep-client-termination-grace.k8s-patch.yaml",
			regexp.MustCompile(`(?m)^\s*terminationGracePeriodSeconds:\s*(\d+)\s*$`),
		},
		{
			"keep-client-termination-grace.systemd-dropin.conf",
			regexp.MustCompile(`(?m)^TimeoutStopSec=(\d+)$`),
		},
	}

	for _, scaffold := range scaffolds {
		path := filepath.Join(releaseManifestDeployDirectory, scaffold.file)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read the deployment scaffold: [%v]", err)
		}

		matches := scaffold.pattern.FindAllStringSubmatch(string(content), -1)
		if len(matches) != 1 {
			t.Errorf(
				"[%s] must configure the grace exactly once, found [%d] "+
					"occurrences",
				scaffold.file,
				len(matches),
			)
			continue
		}

		configured, err := strconv.ParseUint(matches[0][1], 10, 64)
		if err != nil {
			t.Errorf(
				"[%s] carries a non-integer grace [%s]",
				scaffold.file,
				matches[0][1],
			)
			continue
		}
		if configured != expected {
			t.Errorf(
				"[%s] configures a grace of [%d]s, the validated manifest "+
					"requires [%d]s",
				scaffold.file,
				configured,
				expected,
			)
		}
	}

	systemdPath := filepath.Join(
		releaseManifestDeployDirectory,
		"keep-client-termination-grace.systemd-dropin.conf",
	)
	systemdContent, err := os.ReadFile(systemdPath)
	if err != nil {
		t.Fatalf("cannot read the systemd drop-in: [%v]", err)
	}
	killSignal := regexp.MustCompile(`(?m)^KillSignal=(\S+)$`).
		FindAllStringSubmatch(string(systemdContent), -1)
	if len(killSignal) != 1 || killSignal[0][1] != "SIGTERM" {
		t.Errorf(
			"the systemd drop-in must keep KillSignal=SIGTERM exactly once, "+
				"got [%v]",
			killSignal,
		)
	}
}

func TestReleaseManifestValidateAcceptsDerived(t *testing.T) {
	if err := validateReleaseManifest(validReleaseManifestForTests(t)); err != nil {
		t.Errorf("derived manifest rejected: [%v]", err)
	}
}

// TestReleaseManifestValidateFailsClosed mutates every field of a valid
// manifest in turn and requires validation to name the exact violation, so
// no single stale number can survive a validate run.
func TestReleaseManifestValidateFailsClosed(t *testing.T) {
	tests := map[string]struct {
		mutate          func(*releaseManifest)
		expectedMessage string
	}{
		"wrong schema version": {
			func(m *releaseManifest) { m.SchemaVersion = 2 },
			"schema_version must be [1]",
		},
		"unparseable generation timestamp": {
			func(m *releaseManifest) { m.GeneratedAt = "yesterday" },
			"generated_at must be an RFC 3339 timestamp",
		},
		"wrong protocol epoch": {
			func(m *releaseManifest) { m.ProtocolEpoch = "legacy" },
			"protocol_epoch must be [security_v2_cutover]",
		},
		"stale tbtc bound": {
			func(m *releaseManifest) { m.TerminationGrace.TBTCCompletionBlocks++ },
			"tbtc_completion_blocks must be [1200]",
		},
		"stale beacon bound": {
			func(m *releaseManifest) { m.TerminationGrace.BeaconCompletionBlocks-- },
			"beacon_completion_blocks must be [136]",
		},
		"stale beacon group size": {
			func(m *releaseManifest) { m.TerminationGrace.BeaconInputs.GroupSize++ },
			"beacon_inputs.group_size must be [64]",
		},
		"stale beacon publication step": {
			func(m *releaseManifest) {
				m.TerminationGrace.BeaconInputs.ResultPublicationBlockStep++
			},
			"beacon_inputs.result_publication_block_step must be [1]",
		},
		"stale beacon relay entry timeout": {
			func(m *releaseManifest) {
				m.TerminationGrace.BeaconInputs.RelayEntryTimeoutBlocks++
			},
			"beacon_inputs.relay_entry_timeout_blocks must be [64]",
		},
		"stale combined bound": {
			func(m *releaseManifest) {
				m.TerminationGrace.MaximumLegacyCompletionBlocks++
			},
			"maximum_legacy_completion_blocks must be [1200]",
		},
		"stale reviewed margin": {
			func(m *releaseManifest) { m.TerminationGrace.ReviewedMarginBlocks++ },
			"reviewed_margin_blocks must be [100]",
		},
		"stale block interval": {
			func(m *releaseManifest) {
				m.TerminationGrace.UpperBlockIntervalSeconds++
			},
			"upper_block_interval_seconds must be [15]",
		},
		"stale rpc allowance": {
			func(m *releaseManifest) {
				m.TerminationGrace.RPCProcessingAllowanceSeconds++
			},
			"rpc_processing_allowance_seconds must be [300]",
		},
		"stale backstop": {
			func(m *releaseManifest) { m.TerminationGrace.InProcessBackstopSeconds++ },
			"in_process_backstop_seconds must be [19800]",
		},
		"zero forced-cancellation allowance": {
			func(m *releaseManifest) {
				m.TerminationGrace.ForcedCancellationAllowanceSeconds = 0
			},
			"must be positive",
		},
		"grace not equal to backstop plus allowance": {
			func(m *releaseManifest) {
				m.TerminationGrace.TerminationGracePeriodSeconds++
			},
			"termination_grace_period_seconds must be [20100]",
		},
		"grace truncated to the backstop": {
			func(m *releaseManifest) {
				m.TerminationGrace.TerminationGracePeriodSeconds =
					m.TerminationGrace.InProcessBackstopSeconds
			},
			"termination_grace_period_seconds must be [20100]",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			manifest := validReleaseManifestForTests(t)
			test.mutate(&manifest)

			err := validateReleaseManifest(manifest)
			if err == nil {
				t.Fatal("expected the mutated manifest to be rejected")
			}
			if !strings.Contains(err.Error(), test.expectedMessage) {
				t.Errorf(
					"rejection must name the violation [%s], got:\n%v",
					test.expectedMessage,
					err,
				)
			}
		})
	}
}

func TestReleaseManifestValidateReportsEveryViolation(t *testing.T) {
	manifest := validReleaseManifestForTests(t)
	manifest.SchemaVersion = 7
	manifest.TerminationGrace.ReviewedMarginBlocks++
	manifest.TerminationGrace.TerminationGracePeriodSeconds++

	err := validateReleaseManifest(manifest)
	if err == nil {
		t.Fatal("expected the mutated manifest to be rejected")
	}
	for _, expectedMessage := range []string{
		"schema_version must be [1]",
		"reviewed_margin_blocks must be [100]",
		"termination_grace_period_seconds must be [20100]",
	} {
		if !strings.Contains(err.Error(), expectedMessage) {
			t.Errorf(
				"rejection must accumulate the violation [%s], got:\n%v",
				expectedMessage,
				err,
			)
		}
	}
}

// TestReleaseManifestLoadFailsClosed drives the strict decoder: unknown
// fields, trailing content, and non-integer numbers are exactly the shapes a
// hand-edited manifest degrades into, and each must be rejected outright.
func TestReleaseManifestLoadFailsClosed(t *testing.T) {
	valid, err := json.Marshal(validReleaseManifestForTests(t))
	if err != nil {
		t.Fatalf("cannot encode the valid manifest: [%v]", err)
	}

	tests := map[string]struct {
		content         string
		expectedMessage string
	}{
		"unknown field": {
			strings.Replace(
				string(valid),
				`"schema_version"`,
				`"surprise_field":true,"schema_version"`,
				1,
			),
			"unknown field",
		},
		"trailing content": {
			string(valid) + "{}",
			"trailing content",
		},
		"fractional grace": {
			strings.Replace(
				string(valid),
				`"termination_grace_period_seconds":20100`,
				`"termination_grace_period_seconds":20100.5`,
				1,
			),
			"cannot decode",
		},
		"negative margin": {
			strings.Replace(
				string(valid),
				`"reviewed_margin_blocks":100`,
				`"reviewed_margin_blocks":-100`,
				1,
			),
			"cannot decode",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			// The replacement patterns above must actually hit, otherwise the
			// case silently degrades into loading a valid manifest.
			if test.content == string(valid) {
				t.Fatal("mutation did not change the manifest encoding")
			}

			path := filepath.Join(t.TempDir(), "release-manifest.json")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatalf("cannot write the manifest fixture: [%v]", err)
			}

			_, err := loadReleaseManifest(path)
			if err == nil {
				t.Fatal("expected the malformed manifest to be rejected")
			}
			if !strings.Contains(err.Error(), test.expectedMessage) {
				t.Errorf(
					"rejection must name the defect [%s], got: [%v]",
					test.expectedMessage,
					err,
				)
			}
		})
	}
}

func TestReleaseManifestLoadRejectsMissingFile(t *testing.T) {
	_, err := loadReleaseManifest(
		filepath.Join(t.TempDir(), "absent-manifest.json"),
	)
	if err == nil {
		t.Fatal("expected a missing manifest to be rejected")
	}
	if !strings.Contains(err.Error(), "cannot open") {
		t.Errorf("unexpected rejection message: [%v]", err)
	}
}
