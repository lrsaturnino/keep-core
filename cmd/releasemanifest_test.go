package cmd

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

const releaseManifestRepositoryPath = "../scripts/release/pr4109/release-manifest.json"

const releaseManifestDeployDirectory = "../scripts/release/pr4109/deploy"

const releaseManifestSchemaPath = "../scripts/release/pr4109/release-manifest.schema.json"

const rehearsalEvidenceSchemaPath = "../scripts/release/pr4109/rehearsal-evidence.schema.json"

// validReleaseManifestForTests builds a manifest that must pass validation:
// the derived termination grace under the reviewed default allowance,
// wrapped in the identity fields of the current artifact.
func validReleaseManifestForTests(t *testing.T) releaseManifest {
	t.Helper()

	grace, err := deriveTerminationGrace(compiledForcedCancellationAllowanceSeconds)
	if err != nil {
		t.Fatalf("unexpected derivation error: [%v]", err)
	}

	return releaseManifest{
		SchemaVersion:    releaseManifestSchemaVersion,
		GeneratedAt:      "2026-07-27T23:11:28Z",
		ProtocolEpoch:    participation.CompiledEpoch.String(),
		ReleaseIdentity:  deriveReleaseIdentity(),
		TerminationGrace: grace,
	}
}

// releaseReadyIdentityForTests is a fully recorded release identity: the
// compiled chain and cutover block plus the build outputs a release commit
// supplies. The cutover block is taken from the compiled constant rather than
// invented, so this helper states a complete identity for as long as that
// constant is a placeholder and keeps stating one after it is set.
func releaseReadyIdentityForTests() releaseIdentity {
	identity := deriveReleaseIdentity()
	identity.SourceCommit = "0123456789abcdef0123456789abcdef01234567"
	identity.Images = []releaseImage{
		{
			Platform: "linux/amd64",
			Reference: "gcr.io/keep-test/keep-client@sha256:" +
				strings.Repeat("a", 64),
			Digest: "sha256:" + strings.Repeat("a", 64),
		},
		{
			Platform: "linux/arm64",
			Reference: "gcr.io/keep-test/keep-client@sha256:" +
				strings.Repeat("b", 64),
			Digest: "sha256:" + strings.Repeat("b", 64),
		},
	}

	return identity
}

// TestReleaseManifestDeriveMatchesCompiledBounds is the drift assertion for
// the manifest derivation: every number the manifest records is pinned to a
// reviewed literal, and the backstop and grace are re-checked against the
// documented arithmetic identity. It fails whenever a compiled bound moves
// without the manifest chain being deliberately re-reviewed.
func TestReleaseManifestDeriveMatchesCompiledBounds(t *testing.T) {
	grace, err := deriveTerminationGrace(compiledForcedCancellationAllowanceSeconds)
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
		{"process_exit_headroom_seconds", grace.ProcessExitHeadroomSeconds, 60},
		{"termination_grace_period_seconds", grace.TerminationGracePeriodSeconds, 20160},
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
		grace.ForcedCancellationAllowanceSeconds +
		grace.ProcessExitHeadroomSeconds
	if grace.TerminationGracePeriodSeconds != graceIdentity {
		t.Errorf(
			"grace identity broken: backstop+allowance+headroom is [%d], "+
				"recorded grace is [%d]",
			graceIdentity,
			grace.TerminationGracePeriodSeconds,
		)
	}
	// The strict inequality is the entire point of the exit headroom: the
	// service manager counts its grace from signal delivery, so a grace that
	// merely equals the sum of the two in-process waits leaves controller
	// scheduling, the quiesce and close calls, logging, and teardown
	// unbudgeted and lets SIGKILL land inside them.
	internalWaits := grace.InProcessBackstopSeconds +
		grace.ForcedCancellationAllowanceSeconds
	if grace.TerminationGracePeriodSeconds <= internalWaits {
		t.Errorf(
			"grace [%d]s must end strictly after the complete internal wait "+
				"[%d]s (backstop plus cancellation allowance)",
			grace.TerminationGracePeriodSeconds,
			internalWaits,
		)
	}
	if grace.ProcessExitHeadroomSeconds == 0 {
		t.Error("the process-exit headroom must be positive")
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

func TestReleaseManifestDeriveRejectsOverflowingAllowance(t *testing.T) {
	_, err := deriveTerminationGrace(math.MaxUint64)
	if err == nil {
		t.Fatal("expected an overflowing allowance to be rejected")
	}
	if !strings.Contains(err.Error(), "termination grace overflows") {
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
// the compiled bounds through the manifest into the deployment scaffold:
// every scaffold file must carry exactly the manifest's termination grace at
// its expected number of sites — once per service-manager fragment, once per
// R1 rehearsal node — and the systemd drop-in must keep SIGTERM as the stop
// signal because that is the signal the lifecycle controller quiesces on.
func TestReleaseManifestDeploymentScaffoldMatchesManifest(t *testing.T) {
	manifest, err := loadReleaseManifest(releaseManifestRepositoryPath)
	if err != nil {
		t.Fatalf("cannot load the repository manifest: [%v]", err)
	}
	expected := manifest.TerminationGrace.TerminationGracePeriodSeconds

	scaffolds := []struct {
		path        string
		pattern     *regexp.Regexp
		occurrences int
	}{
		{
			filepath.Join(
				releaseManifestDeployDirectory,
				"keep-client-termination-grace.k8s-patch.yaml",
			),
			regexp.MustCompile(`(?m)^\s*terminationGracePeriodSeconds:\s*(\d+)\s*$`),
			1,
		},
		{
			filepath.Join(
				releaseManifestDeployDirectory,
				"keep-client-termination-grace.systemd-dropin.conf",
			),
			regexp.MustCompile(`(?m)^TimeoutStopSec=(\d+)$`),
			1,
		},
		{
			"../scripts/release/pr4109/compose.rehearsal.yaml",
			regexp.MustCompile(`(?m)^\s*stop_grace_period:\s*(\d+)s\s*$`),
			2,
		},
	}

	for _, scaffold := range scaffolds {
		content, err := os.ReadFile(scaffold.path)
		if err != nil {
			t.Fatalf("cannot read the deployment scaffold: [%v]", err)
		}

		matches := scaffold.pattern.FindAllStringSubmatch(string(content), -1)
		if len(matches) != scaffold.occurrences {
			t.Errorf(
				"[%s] must configure the grace at exactly [%d] site(s), "+
					"found [%d]",
				scaffold.path,
				scaffold.occurrences,
				len(matches),
			)
			continue
		}

		for _, match := range matches {
			configured, err := strconv.ParseUint(match[1], 10, 64)
			if err != nil {
				t.Errorf(
					"[%s] carries a non-integer grace [%s]",
					scaffold.path,
					match[1],
				)
				continue
			}
			if configured != expected {
				t.Errorf(
					"[%s] configures a grace of [%d]s, the validated "+
						"manifest requires [%d]s",
					scaffold.path,
					configured,
					expected,
				)
			}
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

// TestReleaseManifestSchemaMatchesTheDecodedDocument is the drift check for
// the published schema. The schema is a hand-written mirror of the types the
// client decodes, and nothing but this test holds the two together.
//
// Drift here is quiet and one-directional. The strict Go loader rejects a field
// the schema forgot, so a manifest is never accepted on a mismatch; what
// happens instead is that external tooling validating against the schema passes
// a document the release binary refuses, or — worse — reports a document
// complete while a required section it never learned about is missing from it.
func TestReleaseManifestSchemaMatchesTheDecodedDocument(t *testing.T) {
	content, err := os.ReadFile(releaseManifestSchemaPath)
	if err != nil {
		t.Fatalf("cannot read the manifest schema: [%v]", err)
	}

	// Decoded as an object graph rather than into a shape of its own: the check
	// walks the same nesting the manifest types have, and a schema that renamed
	// or moved a section must fail rather than decode into zero values.
	var schema map[string]any
	if err := json.Unmarshal(content, &schema); err != nil {
		t.Fatalf("cannot decode the manifest schema: [%v]", err)
	}

	if version := schemaObject(t, schema, "properties", "schema_version"); version != nil {
		if got, want := version["const"], float64(releaseManifestSchemaVersion); got != want {
			t.Errorf(
				"the schema pins schema_version to [%v], the binary accepts "+
					"only [%v]",
				got,
				want,
			)
		}
	}

	for _, section := range []struct {
		name     string
		path     []string
		recorded any
	}{
		{"the manifest", nil, releaseManifest{}},
		{
			"release_identity",
			[]string{"properties", "release_identity"},
			releaseIdentity{},
		},
		{
			"release_identity.images entries",
			[]string{
				"properties", "release_identity", "properties", "images",
				"items",
			},
			releaseImage{},
		},
		{
			"termination_grace",
			[]string{"properties", "termination_grace"},
			terminationGrace{},
		},
		{
			"termination_grace.beacon_inputs",
			[]string{
				"properties", "termination_grace", "properties",
				"beacon_inputs",
			},
			beaconCompletionInputs{},
		},
	} {
		object := schemaObject(t, schema, section.path...)
		if object == nil {
			t.Errorf("the schema defines no [%s] section", section.name)
			continue
		}

		// A schema that accepts unknown properties describes a laxer document
		// than the loader does, which is the direction that lets a hand-edited
		// manifest read as valid to everything except the binary.
		if closed, _ := object["additionalProperties"].(bool); closed {
			t.Errorf("[%s] must not accept additional properties", section.name)
		}

		declared := schemaObject(t, object, "properties")
		requiredList, _ := object["required"].([]any)
		required := make(map[string]struct{}, len(requiredList))
		for _, entry := range requiredList {
			name, _ := entry.(string)
			required[name] = struct{}{}
		}

		for field, optional := range jsonFields(section.recorded) {
			if _, present := declared[field]; !present {
				t.Errorf("[%s] must define [%s]", section.name, field)
			}
			// Optional exactly where the encoder may omit it. A required field
			// the schema left optional is a section a document may drop; an
			// optional one the schema required is a document the binary
			// produces and the schema rejects.
			if _, present := required[field]; present == optional {
				if optional {
					t.Errorf(
						"[%s] must not require [%s]: the client omits it when "+
							"it is empty",
						section.name,
						field,
					)
				} else {
					t.Errorf("[%s] must require [%s]", section.name, field)
				}
			}
		}

		for field := range declared {
			if _, recorded := jsonFields(section.recorded)[field]; !recorded {
				t.Errorf(
					"[%s] defines [%s], which the client does not decode",
					section.name,
					field,
				)
			}
		}
	}
}

// schemaObject walks a decoded schema to the object at the given path,
// reporting nil when the path does not lead to one.
func schemaObject(t *testing.T, schema map[string]any, path ...string) map[string]any {
	t.Helper()

	object := schema
	for _, step := range path {
		next, ok := object[step].(map[string]any)
		if !ok {
			return nil
		}
		object = next
	}

	return object
}

// jsonFields lists the JSON member names a manifest type encodes, saying of
// each whether the encoder may leave it out.
func jsonFields(recorded any) map[string]bool {
	fields := make(map[string]bool)

	structType := reflect.TypeOf(recorded)
	for index := range structType.NumField() {
		tag := structType.Field(index).Tag.Get("json")
		name, options, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		fields[name] = strings.Contains(options, "omitempty")
	}

	return fields
}

// TestRehearsalEvidenceSchemaRequiresManifestBinding pins the evidence
// schema's release-manifest binding: every accepted rehearsal record must
// name the hash of the reviewed manifest and the grace it ran under.
// Dropping the requirement from the schema would silently sever the link
// between the termination-grace record and the source SHA, image digests,
// and chain identity the record carries.
func TestRehearsalEvidenceSchemaRequiresManifestBinding(t *testing.T) {
	content, err := os.ReadFile(rehearsalEvidenceSchemaPath)
	if err != nil {
		t.Fatalf("cannot read the evidence schema: [%v]", err)
	}

	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			ReleaseManifest struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"release_manifest"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(content, &schema); err != nil {
		t.Fatalf("cannot decode the evidence schema: [%v]", err)
	}

	contains := func(list []string, want string) bool {
		for _, entry := range list {
			if entry == want {
				return true
			}
		}
		return false
	}

	if !contains(schema.Required, "release_manifest") {
		t.Error("the evidence schema must require the release_manifest binding")
	}
	for _, field := range []string{
		"sha256",
		"termination_grace_period_seconds",
	} {
		if !contains(schema.Properties.ReleaseManifest.Required, field) {
			t.Errorf("the release_manifest binding must require [%s]", field)
		}
		if _, present := schema.Properties.ReleaseManifest.Properties[field]; !present {
			t.Errorf("the release_manifest binding must define [%s]", field)
		}
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
			func(m *releaseManifest) { m.SchemaVersion = 1 },
			"schema_version must be [2]",
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
			"forced_cancellation_allowance_seconds must be [300]",
		},
		"stale forced-cancellation allowance": {
			func(m *releaseManifest) {
				m.TerminationGrace.ForcedCancellationAllowanceSeconds++
			},
			"forced_cancellation_allowance_seconds must be [300]",
		},
		"stale exit headroom": {
			func(m *releaseManifest) {
				m.TerminationGrace.ProcessExitHeadroomSeconds++
			},
			"process_exit_headroom_seconds must be [60]",
		},
		"exit headroom dropped": {
			func(m *releaseManifest) {
				m.TerminationGrace.ProcessExitHeadroomSeconds = 0
			},
			"process_exit_headroom_seconds must be [60]",
		},
		"grace not equal to the full internal sequence": {
			func(m *releaseManifest) {
				m.TerminationGrace.TerminationGracePeriodSeconds++
			},
			"termination_grace_period_seconds must be [20160]",
		},
		"grace truncated to the backstop": {
			func(m *releaseManifest) {
				m.TerminationGrace.TerminationGracePeriodSeconds =
					m.TerminationGrace.InProcessBackstopSeconds
			},
			"termination_grace_period_seconds must be [20160]",
		},
		"grace truncated to the two timed waits": {
			func(m *releaseManifest) {
				m.TerminationGrace.TerminationGracePeriodSeconds =
					m.TerminationGrace.InProcessBackstopSeconds +
						m.TerminationGrace.ForcedCancellationAllowanceSeconds
			},
			"termination_grace_period_seconds must be [20160]",
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

// TestReleaseManifestValidateRejectsCoherentlyChangedAllowance proves the
// allowance identity cannot be bypassed by a self-consistent edit: a manifest
// whose allowance, grace, and therefore scaffold-facing sum were all
// recomputed coherently around a different allowance still names a cleanup
// window the runtime does not wait, so validation must reject it against the
// compiled constant — never re-derive around the manifest's own value.
func TestReleaseManifestValidateRejectsCoherentlyChangedAllowance(t *testing.T) {
	tests := map[string]struct {
		allowanceSeconds  uint64
		expectedRejection []string
	}{
		"allowance lowered below the runtime cleanup wait": {
			120,
			[]string{
				"forced_cancellation_allowance_seconds must be [300] as " +
					"derived from the compiled bounds, got [120]",
				"termination_grace_period_seconds must be [20160] as " +
					"derived from the compiled bounds, got [19980]",
			},
		},
		"allowance raised above the runtime cleanup wait": {
			600,
			[]string{
				"forced_cancellation_allowance_seconds must be [300] as " +
					"derived from the compiled bounds, got [600]",
				"termination_grace_period_seconds must be [20160] as " +
					"derived from the compiled bounds, got [20460]",
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			manifest := validReleaseManifestForTests(t)
			grace := &manifest.TerminationGrace
			grace.ForcedCancellationAllowanceSeconds = test.allowanceSeconds
			// Recompute the grace exactly as a coherent hand-edit would, so
			// the only remaining inconsistency is with the compiled constant
			// the runtime waits.
			grace.TerminationGracePeriodSeconds = grace.InProcessBackstopSeconds +
				test.allowanceSeconds + grace.ProcessExitHeadroomSeconds

			err := validateReleaseManifest(manifest)
			if err == nil {
				t.Fatal("expected the coherently changed allowance to be rejected")
			}
			for _, expectedMessage := range test.expectedRejection {
				if !strings.Contains(err.Error(), expectedMessage) {
					t.Errorf(
						"rejection must name the violation [%s], got:\n%v",
						expectedMessage,
						err,
					)
				}
			}
		})
	}
}

func TestReleaseManifestValidateReportsEveryViolation(t *testing.T) {
	manifest := validReleaseManifestForTests(t)
	manifest.SchemaVersion = 7
	manifest.ReleaseIdentity.ChainID++
	manifest.TerminationGrace.ReviewedMarginBlocks++
	manifest.TerminationGrace.TerminationGracePeriodSeconds++

	err := validateReleaseManifest(manifest)
	if err == nil {
		t.Fatal("expected the mutated manifest to be rejected")
	}
	for _, expectedMessage := range []string{
		"schema_version must be [2]",
		"release_identity.chain_id must be [1]",
		"reviewed_margin_blocks must be [100]",
		"termination_grace_period_seconds must be [20160]",
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

// TestReleaseManifestValidateBindsIdentityToTheCompiledClient proves the
// recorded chain and cutover block cannot drift from what the binary compiles
// in, and that a recorded source commit or image reference has to name one
// immutable thing.
//
// The client reads no manifest at runtime: it resolves the mainnet schedule
// from its compiled constant. A document naming a different block would send
// operators to a cutover height no node observes, and a reference carrying a
// tag would let deployment pull whatever the registry resolves it to rather
// than the artifact the acceptance evidence describes.
func TestReleaseManifestValidateBindsIdentityToTheCompiledClient(t *testing.T) {
	tests := map[string]struct {
		mutate          func(*releaseIdentity)
		expectedMessage string
	}{
		"chain other than the one the compiled cutover block is for": {
			func(i *releaseIdentity) { i.ChainID = 11155111 },
			"release_identity.chain_id must be [1]",
		},
		"cutover block the client does not compile in": {
			func(i *releaseIdentity) {
				i.CutoverBlock = participation.MainnetCutoverBlock + 1
			},
			"release_identity.cutover_block must be [" + strconv.FormatUint(
				participation.MainnetCutoverBlock,
				10,
			) + "]",
		},
		"abbreviated source commit": {
			func(i *releaseIdentity) { i.SourceCommit = "0123456" },
			"release_identity.source_commit must be a full 40-character",
		},
		"source commit that is not hexadecimal": {
			func(i *releaseIdentity) {
				i.SourceCommit = strings.Repeat("z", 40)
			},
			"release_identity.source_commit must be a full 40-character",
		},
		"image digest under another algorithm": {
			func(i *releaseIdentity) {
				i.Images[0].Digest = "sha512:" + strings.Repeat("a", 64)
				i.Images[0].Reference = "gcr.io/keep-test/keep-client@" +
					i.Images[0].Digest
			},
			"release_identity.images[0].digest must be a sha256 content digest",
		},
		"image reference carrying a tag instead of its digest": {
			func(i *releaseIdentity) {
				i.Images[0].Reference = "gcr.io/keep-test/keep-client:v2.1.0"
			},
			"release_identity.images[0].reference must be pinned to its digest",
		},
		"image reference pinned to a different digest": {
			func(i *releaseIdentity) {
				i.Images[0].Reference = "gcr.io/keep-test/keep-client@sha256:" +
					strings.Repeat("c", 64)
			},
			"release_identity.images[0].reference must be pinned to its digest",
		},
		"image without a platform": {
			func(i *releaseIdentity) { i.Images[0].Platform = "" },
			"release_identity.images[0].platform must name the platform",
		},
		"two images for one platform": {
			func(i *releaseIdentity) {
				i.Images[1].Platform = i.Images[0].Platform
			},
			"release_identity.images[1] repeats platform [linux/amd64]",
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			manifest := validReleaseManifestForTests(t)
			manifest.ReleaseIdentity = releaseReadyIdentityForTests()
			test.mutate(&manifest.ReleaseIdentity)

			err := validateReleaseManifest(manifest)
			if err == nil {
				t.Fatal("expected the mutated identity to be rejected")
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

// TestReleaseManifestValidateAcceptsAFullyRecordedIdentity proves a complete
// identity passes, so the checks above reject what is wrong with a manifest
// rather than the act of recording one.
func TestReleaseManifestValidateAcceptsAFullyRecordedIdentity(t *testing.T) {
	manifest := validReleaseManifestForTests(t)
	manifest.ReleaseIdentity = releaseReadyIdentityForTests()

	if err := validateReleaseManifest(manifest); err != nil {
		t.Errorf("fully recorded manifest rejected: [%v]", err)
	}
	if violations := releaseReadyViolations(manifest); len(violations) > 0 &&
		participation.MainnetCutoverBlock != 0 {
		t.Errorf(
			"fully recorded manifest is not release-ready: %v",
			violations,
		)
	}
}

// TestReleaseManifestRepositoryFileIsNotReleaseReady is the standing statement
// of what release acceptance is still waiting for, checked rather than
// asserted in prose.
//
// The checked-in manifest is a valid document — every number in it matches the
// compiled bounds — and it is deliberately not a release-ready one. It is
// reviewed before the build it will name exists, and the cutover block it
// records is the compiled zero placeholder. This test fails the moment that
// stops being true in either direction: a manifest that stops validating, or
// one that starts passing release-readiness while its identity is still empty.
func TestReleaseManifestRepositoryFileIsNotReleaseReady(t *testing.T) {
	manifest, err := loadReleaseManifest(releaseManifestRepositoryPath)
	if err != nil {
		t.Fatalf("cannot load the repository manifest: [%v]", err)
	}

	if err := validateReleaseManifest(manifest); err != nil {
		t.Fatalf("the repository manifest must be a valid document: [%v]", err)
	}

	violations := releaseReadyViolations(manifest)
	if len(violations) == 0 {
		t.Fatal(
			"the repository manifest passed release-readiness: either the " +
				"release identity was recorded without this gate being " +
				"revisited, or the readiness check stopped checking",
		)
	}

	expected := []string{
		"release_identity.source_commit is unrecorded",
		"release_identity.images is empty",
	}
	// Named separately because it is the one blocker that lives in the client
	// rather than in the document: no edit to the manifest can clear it, only a
	// reviewed release commit setting C.
	if participation.MainnetCutoverBlock == 0 {
		expected = append(
			expected,
			"release_identity.cutover_block is the zero placeholder",
		)
	}

	joined := errors.Join(violations...).Error()
	for _, expectedMessage := range expected {
		if !strings.Contains(joined, expectedMessage) {
			t.Errorf(
				"release-readiness must still report [%s], got:\n%s",
				expectedMessage,
				joined,
			)
		}
	}
}

// TestReleaseManifestReleaseReadyIsSeparateFromValidity proves the two verdicts
// stay apart: a document can be entirely valid and still not be something an
// acceptance decision may be taken against.
func TestReleaseManifestReleaseReadyIsSeparateFromValidity(t *testing.T) {
	manifest := validReleaseManifestForTests(t)

	if err := validateReleaseManifest(manifest); err != nil {
		t.Fatalf("the derived manifest must be valid: [%v]", err)
	}

	violations := releaseReadyViolations(manifest)
	if len(violations) == 0 {
		t.Fatal(
			"a derived manifest records no build outputs and must not pass " +
				"release-readiness",
		)
	}

	// Recording the build outputs clears every blocker the document owns. What
	// remains, until a reviewed release commit sets C, is the compiled
	// placeholder — which is the point: release-readiness cannot be reached by
	// editing this file.
	manifest.ReleaseIdentity = releaseReadyIdentityForTests()
	remaining := releaseReadyViolations(manifest)

	if participation.MainnetCutoverBlock == 0 {
		if len(remaining) != 1 {
			t.Fatalf(
				"the compiled zero cutover block must be the only blocker "+
					"left, got: %v",
				remaining,
			)
		}
		if !strings.Contains(
			remaining[0].Error(),
			"release_identity.cutover_block is the zero placeholder",
		) {
			t.Errorf("unexpected remaining blocker: [%v]", remaining[0])
		}
		return
	}

	if len(remaining) != 0 {
		t.Errorf(
			"a fully recorded identity over a set cutover block must be "+
				"release-ready, got: %v",
			remaining,
		)
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
		// A stray closing delimiter is the shape a hand-edit most easily
		// leaves behind, and the one a More-style check waves through: More
		// only asks whether another value begins next, and a bare delimiter
		// does not.
		"trailing closing brace": {
			string(valid) + "}",
			"trailing content",
		},
		"trailing closing bracket": {
			string(valid) + "]",
			"trailing content",
		},
		"trailing number": {
			string(valid) + "\n7",
			"trailing content",
		},
		"trailing string": {
			string(valid) + ` "note"`,
			"trailing content",
		},
		"trailing boolean": {
			string(valid) + " true",
			"trailing content",
		},
		"fractional grace": {
			strings.Replace(
				string(valid),
				`"termination_grace_period_seconds":20160`,
				`"termination_grace_period_seconds":20160.5`,
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

// TestReleaseManifestLoadAcceptsTrailingWhitespace pins the boundary of the
// end-of-document check: insignificant whitespace after the manifest object —
// the newline every editor and generator appends — is not trailing content.
func TestReleaseManifestLoadAcceptsTrailingWhitespace(t *testing.T) {
	valid, err := json.Marshal(validReleaseManifestForTests(t))
	if err != nil {
		t.Fatalf("cannot encode the valid manifest: [%v]", err)
	}

	path := filepath.Join(t.TempDir(), "release-manifest.json")
	content := append(valid, " \t\r\n\n"...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("cannot write the manifest fixture: [%v]", err)
	}

	manifest, err := loadReleaseManifest(path)
	if err != nil {
		t.Fatalf("expected the whitespace-terminated manifest to load: [%v]", err)
	}
	if err := validateReleaseManifest(manifest); err != nil {
		t.Errorf("expected the loaded manifest to validate: [%v]", err)
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
