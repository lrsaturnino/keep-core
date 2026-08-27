// Package r00 exposes the machine-readable PR #4109 baseline inventory.
//
// The inventory is audit scaffolding, not a release gate. Valid JSON may
// truthfully describe missing evidence; consumers must inspect each case's
// evidence and release-gate state instead of treating successful decoding as
// approval.
package r00

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/keep-network/keep-core/audit/pr4109/internal/strictjson"
)

const (
	BaselineSourceCommit         = "1bc7edf9965cac43de3bd18060e07ba678670073"
	BaselineParentCommit         = "d2a95eed0b259805aa710e4184377180ade368bc"
	EvaluatedCandidateCommit     = "d7bf8c0753f3aac574f8d20d93c75268f350b389"
	EvaluatedCandidateBaseCommit = "a7ac8989b662d51d8a94fa28f1ac226058d5d6cc"
	CurrentTSSLibCommit          = "d847ce0030193ccf5dbec0097571dcce5a2a5cf6"
)

var (
	//go:embed frozen-inputs.json
	frozenInputsJSON []byte
	//go:embed reproduction-catalog.json
	reproductionCatalogJSON []byte
)

var (
	commitPattern         = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	moduleIdentityPattern = regexp.MustCompile(`^[^@\s]+@[^=\s]+=>[^\s]*$`)
)

// FrozenInput binds one audited dependency or source tree to an immutable
// identity. Verification describes identity resolution only; it never means a
// reproduction predicate passed.
type FrozenInput struct {
	Name         string  `json:"name"`
	Repository   string  `json:"repository"`
	Identity     string  `json:"identity"`
	Version      *string `json:"version"`
	Checksum     *string `json:"checksum"`
	Verification string  `json:"verification"`
	Purpose      string  `json:"purpose"`
}

// FrozenInputs separates the historical baseline from the candidate currently
// being evaluated for integration.
type FrozenInputs struct {
	Schema                   string        `json:"schema"`
	Version                  uint64        `json:"version"`
	CapturedAtUTC            string        `json:"captured_at_utc"`
	Repository               string        `json:"repository"`
	PullRequest              uint64        `json:"pull_request"`
	BaselineSourceCommit     string        `json:"baseline_source_commit"`
	BaselineParentCommit     string        `json:"baseline_parent_commit"`
	EvaluatedCandidateCommit string        `json:"evaluated_candidate_commit"`
	EvaluatedCandidateBase   string        `json:"evaluated_candidate_base"`
	Inputs                   []FrozenInput `json:"inputs"`
}

// SourceAnchor makes a source assertion resolvable without upgrading that
// assertion into evidence.
type SourceAnchor struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
	Symbol     string `json:"symbol"`
}

// Toolchain identifies the runtime that produced a retained control.
type Toolchain struct {
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

// EvidenceControl is one retained command result. A partial control must state
// exactly what it does not cover.
type EvidenceControl struct {
	Coverage             string    `json:"coverage"`
	Command              string    `json:"command"`
	WorkingDirectory     string    `json:"working_directory"`
	ExecutedSourceCommit string    `json:"executed_source_commit"`
	SourceTreeDigest     string    `json:"source_tree_digest"`
	ExitCode             int       `json:"exit_code"`
	StdoutPath           string    `json:"stdout_path"`
	StdoutSHA256         string    `json:"stdout_sha256"`
	StderrPath           string    `json:"stderr_path"`
	StderrSHA256         string    `json:"stderr_sha256"`
	Toolchain            Toolchain `json:"toolchain"`
	// ModuleSums keys are canonical path@version=>replacement identities. A
	// JSON object makes semantic identity uniqueness structural rather than an
	// array-level convention that JSON Schema cannot express.
	ModuleSums   map[string]string `json:"module_sums"`
	Covers       []string          `json:"covers"`
	DoesNotCover []string          `json:"does_not_cover"`
}

// BaselineEvidence distinguishes absent, partial, and predicate-complete
// evidence. A source-anchored assertion is always either not_run or partial.
type BaselineEvidence struct {
	Status   string            `json:"status"`
	Controls []EvidenceControl `json:"controls"`
	Blockers []string          `json:"blockers"`
}

// EvidenceReference identifies a current-head source or runtime basis.
type EvidenceReference struct {
	Commit string `json:"commit"`
	Path   string `json:"path"`
	Symbol string `json:"symbol"`
}

// HeadAssessment records whether the baseline weakness remains on the current
// integration base. Unknown is preferred to inference from incomplete tests.
type HeadAssessment struct {
	EvaluatedCommit string              `json:"evaluated_commit"`
	Status          string              `json:"status"`
	Basis           string              `json:"basis"`
	EvidenceRefs    []EvidenceReference `json:"evidence_refs"`
	Limitations     []string            `json:"limitations"`
}

// ReproductionCase is one named R00 predicate.
type ReproductionCase struct {
	ID               string           `json:"id"`
	Kind             string           `json:"kind"`
	Title            string           `json:"title"`
	Predicate        string           `json:"predicate"`
	SourceAnchors    []SourceAnchor   `json:"source_anchors"`
	BaselineEvidence BaselineEvidence `json:"baseline_evidence"`
	HeadAssessment   HeadAssessment   `json:"head_assessment"`
	ReleaseGate      string           `json:"release_gate"`
}

// ReproductionCatalog contains all 18 cases and an explicit root status.
type ReproductionCatalog struct {
	Schema                   string             `json:"schema"`
	Version                  uint64             `json:"version"`
	BaselineSourceCommit     string             `json:"baseline_source_commit"`
	EvaluatedCandidateCommit string             `json:"evaluated_candidate_commit"`
	Status                   string             `json:"status"`
	Cases                    []ReproductionCase `json:"cases"`
	Blockers                 []string           `json:"blockers"`
}

// Bundle contains the two R00 machine documents.
type Bundle struct {
	Inputs  FrozenInputs
	Catalog ReproductionCatalog
}

// Load performs strict decoding and cross-document validation.
func Load() (*Bundle, error) {
	var bundle Bundle
	if err := decodeStrict(frozenInputsJSON, &bundle.Inputs); err != nil {
		return nil, fmt.Errorf("frozen inputs: %w", err)
	}
	if err := decodeStrict(reproductionCatalogJSON, &bundle.Catalog); err != nil {
		return nil, fmt.Errorf("reproduction catalog: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return &bundle, nil
}

// Validate enforces the difference between a source assertion, a partial
// control, and predicate-complete evidence.
func (b *Bundle) Validate() error {
	if b.Inputs.Schema != "pr4109/r00-frozen-inputs/v1" || b.Inputs.Version != 1 {
		return errors.New("unsupported frozen-inputs schema")
	}
	if b.Catalog.Schema != "pr4109/r00-reproduction-catalog/v1" ||
		b.Catalog.Version != 1 {
		return errors.New("unsupported reproduction-catalog schema")
	}
	if b.Inputs.Repository != "threshold-network/keep-core" ||
		b.Inputs.PullRequest != 4109 {
		return errors.New("frozen inputs are not bound to keep-core PR #4109")
	}
	if b.Inputs.BaselineSourceCommit != BaselineSourceCommit ||
		b.Catalog.BaselineSourceCommit != BaselineSourceCommit {
		return errors.New("baseline source identity disagrees across R00 files")
	}
	if b.Inputs.EvaluatedCandidateCommit != EvaluatedCandidateCommit ||
		b.Catalog.EvaluatedCandidateCommit != EvaluatedCandidateCommit {
		return errors.New("evaluated candidate identity disagrees across R00 files")
	}
	if b.Inputs.BaselineParentCommit != BaselineParentCommit ||
		b.Inputs.EvaluatedCandidateBase != EvaluatedCandidateBaseCommit {
		return errors.New("baseline parent or evaluated candidate base is stale")
	}
	if _, err := time.Parse(time.RFC3339, b.Inputs.CapturedAtUTC); err != nil {
		return fmt.Errorf("invalid frozen-input capture time: %w", err)
	}
	for _, commit := range []string{
		b.Inputs.BaselineSourceCommit,
		b.Inputs.BaselineParentCommit,
		b.Inputs.EvaluatedCandidateCommit,
		b.Inputs.EvaluatedCandidateBase,
	} {
		if !commitPattern.MatchString(commit) {
			return fmt.Errorf("noncanonical commit identity %q", commit)
		}
	}
	type expectedInput struct {
		repository   string
		identity     string
		version      string
		checksum     string
		verification string
	}
	expectedInputs := map[string]expectedInput{
		"independently_tested_r1": {
			repository:   "threshold-network/keep-core",
			identity:     "2228ba0860455dc36672459565741b0a74697b13",
			verification: "local_git_object",
		},
		"prior_keep_core": {
			repository:   "threshold-network/keep-core",
			identity:     "66b187efdbe1cd567950de0efe9728de95886b13",
			version:      "v2.5.2",
			verification: "local_git_object_and_tag",
		},
		"candidate_tss_lib": {
			repository:   "threshold-network/tss-lib",
			identity:     CurrentTSSLibCommit,
			version:      "v0.0.0-20260729021955-d847ce003019",
			checksum:     "h1:EmD85fdfi20RKON39+Hho5zmB57gHj7EWd7pTYwsqRY=",
			verification: "go_mod_go_sum_and_upstream_commit",
		},
		"prior_tss_lib": {
			repository:   "threshold-network/tss-lib",
			identity:     "2e712689cfbeefede15f95a0ec7112227d86f702",
			version:      "v0.0.0-20230901144531-2e712689cfbe",
			checksum:     "h1:dOKhoYxZjXwFIyGnxgU+Sa1obZPMHRhu6e44oOLkzU4=",
			verification: "prior_keep_core_go_mod_go_sum_and_upstream_commit",
		},
		"candidate_keep_common": {
			repository:   "threshold-network/keep-common",
			identity:     "v1.7.1-tlabs.1",
			version:      "v1.7.1-tlabs.1",
			checksum:     "h1:GcaQUb/5TOdc1Vhs4ZsbLM5a1C0CXx7Nmqv4npNKTag=",
			verification: "go_mod_go_sum",
		},
		"tbtc_v2_lifecycle_reference": {
			repository:   "threshold-network/tbtc-v2",
			identity:     "280da5c4ca6aa066f0ea7291076e4c70085723a9",
			verification: "upstream_commit",
		},
		"external_do_harness_reference": {
			repository:   "tlabs-xyz/pr4109-do-infra",
			identity:     "7cbecdde357af30eecb25cfba767851da9ce3dd4",
			verification: "unverified_external_scope_reference",
		},
	}
	if len(b.Inputs.Inputs) != len(expectedInputs) {
		return fmt.Errorf("expected %d frozen inputs, got %d", len(expectedInputs), len(b.Inputs.Inputs))
	}
	seenInputs := make(map[string]struct{}, len(b.Inputs.Inputs))
	foundCurrentTSS := false
	for _, input := range b.Inputs.Inputs {
		if input.Name == "" || input.Repository == "" || input.Identity == "" ||
			input.Verification == "" || input.Purpose == "" {
			return errors.New("frozen input has an incomplete identity or purpose")
		}
		if _, duplicate := seenInputs[input.Name]; duplicate {
			return fmt.Errorf("duplicate frozen input %q", input.Name)
		}
		seenInputs[input.Name] = struct{}{}
		expectedInput, expected := expectedInputs[input.Name]
		if !expected || input.Identity != expectedInput.identity ||
			input.Repository != expectedInput.repository ||
			!optionalStringEquals(input.Version, expectedInput.version) ||
			!optionalStringEquals(input.Checksum, expectedInput.checksum) ||
			input.Verification != expectedInput.verification {
			return fmt.Errorf(
				"frozen input %q has an unreviewed identity tuple %q@%q",
				input.Name,
				input.Repository,
				input.Identity,
			)
		}
		if input.Name == "candidate_tss_lib" {
			foundCurrentTSS = input.Identity == CurrentTSSLibCommit &&
				input.Version != nil &&
				*input.Version == "v0.0.0-20260729021955-d847ce003019" &&
				input.Checksum != nil &&
				*input.Checksum == "h1:EmD85fdfi20RKON39+Hho5zmB57gHj7EWd7pTYwsqRY="
		}
	}
	if !foundCurrentTSS {
		return errors.New("candidate tss-lib identity is missing or stale")
	}

	if len(b.Catalog.Cases) != 18 {
		return fmt.Errorf("expected 18 reproduction cases, got %d", len(b.Catalog.Cases))
	}
	seen := make(map[string]struct{}, len(b.Catalog.Cases))
	positiveCount := 0
	for index, reproduction := range b.Catalog.Cases {
		wantID := fmt.Sprintf("R00-%02d", index+1)
		if reproduction.ID != wantID {
			return fmt.Errorf("case %d has ID %q, want %q", index, reproduction.ID, wantID)
		}
		if _, duplicate := seen[reproduction.ID]; duplicate {
			return fmt.Errorf("duplicate case %q", reproduction.ID)
		}
		seen[reproduction.ID] = struct{}{}
		if reproduction.Title == "" || reproduction.Predicate == "" ||
			len(reproduction.SourceAnchors) == 0 {
			return fmt.Errorf("case %q is missing its title, predicate, or source anchors", reproduction.ID)
		}
		switch reproduction.Kind {
		case "negative":
		case "positive":
			positiveCount++
		default:
			return fmt.Errorf("case %q has invalid kind %q", reproduction.ID, reproduction.Kind)
		}
		for _, anchor := range reproduction.SourceAnchors {
			if anchor.Repository == "" || !commitPattern.MatchString(anchor.Commit) ||
				anchor.Path == "" || anchor.Symbol == "" {
				return fmt.Errorf("case %q has an incomplete source anchor", reproduction.ID)
			}
		}
		if err := validateBaselineEvidence(reproduction.ID, reproduction.BaselineEvidence); err != nil {
			return err
		}
		if err := validateHeadAssessment(reproduction.ID, reproduction.HeadAssessment); err != nil {
			return err
		}
		if reproduction.ReleaseGate != "blocking" {
			return fmt.Errorf(
				"case %q uses release gate %q; R00 v1 is inventory-only",
				reproduction.ID,
				reproduction.ReleaseGate,
			)
		}
	}
	if positiveCount != 1 || b.Catalog.Cases[17].Kind != "positive" {
		return errors.New("R00 must contain 17 negatives and positive case R00-18")
	}
	if b.Catalog.Status != "blocked" {
		return fmt.Errorf(
			"R00 v1 is inventory-only and cannot claim root status %q",
			b.Catalog.Status,
		)
	}
	if len(b.Catalog.Blockers) == 0 {
		return errors.New("blocked R00 root has no blockers")
	}
	if err := requireNonemptyUniqueStrings("R00 root blockers", b.Catalog.Blockers); err != nil {
		return err
	}
	return nil
}

// ExitBlockers returns the explicit root blockers plus every incomplete case.
func (b *Bundle) ExitBlockers() []string {
	result := append([]string(nil), b.Catalog.Blockers...)
	for _, reproduction := range b.Catalog.Cases {
		if reproduction.BaselineEvidence.Status != "complete" {
			result = append(
				result,
				fmt.Sprintf(
					"%s baseline evidence is %s",
					reproduction.ID,
					reproduction.BaselineEvidence.Status,
				),
			)
		}
	}
	return result
}

func validateBaselineEvidence(id string, evidence BaselineEvidence) error {
	switch evidence.Status {
	case "not_run":
		if len(evidence.Controls) != 0 || len(evidence.Blockers) == 0 {
			return fmt.Errorf("case %q not_run evidence must have blockers and no controls", id)
		}
		if err := requireNonemptyUniqueStrings("case "+id+" blockers", evidence.Blockers); err != nil {
			return err
		}
	case "partial":
		if len(evidence.Controls) == 0 || len(evidence.Blockers) == 0 {
			return fmt.Errorf("case %q partial evidence must have controls and blockers", id)
		}
		for _, control := range evidence.Controls {
			if control.Coverage != "partial" || len(control.DoesNotCover) == 0 {
				return fmt.Errorf("case %q partial control hides its coverage gap", id)
			}
			if err := validateControlIdentity(id, control); err != nil {
				return err
			}
		}
		if err := requireNonemptyUniqueStrings("case "+id+" blockers", evidence.Blockers); err != nil {
			return err
		}
	case "complete":
		if len(evidence.Controls) == 0 || len(evidence.Blockers) != 0 {
			return fmt.Errorf("case %q complete evidence has no controls or still has blockers", id)
		}
		for _, control := range evidence.Controls {
			if control.Coverage != "complete" || len(control.DoesNotCover) != 0 {
				return fmt.Errorf("case %q complete control is not predicate-complete", id)
			}
			if control.ExitCode != 0 {
				return fmt.Errorf("case %q complete control has nonzero exit code", id)
			}
			if err := validateControlIdentity(id, control); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("case %q has invalid baseline evidence status %q", id, evidence.Status)
	}
	return nil
}

func validateControlIdentity(id string, control EvidenceControl) error {
	if control.Command == "" || control.WorkingDirectory == "" ||
		!commitPattern.MatchString(control.ExecutedSourceCommit) ||
		!sha256Pattern.MatchString(control.SourceTreeDigest) || control.StdoutPath == "" ||
		!sha256Pattern.MatchString(control.StdoutSHA256) || control.StderrPath == "" ||
		!sha256Pattern.MatchString(control.StderrSHA256) || control.Toolchain.GoVersion == "" ||
		control.Toolchain.GOOS == "" || control.Toolchain.GOARCH == "" ||
		len(control.ModuleSums) == 0 || len(control.Covers) == 0 {
		return fmt.Errorf("case %q has a control without complete provenance", id)
	}
	if err := requireNonemptyUniqueStrings("case "+id+" control coverage", control.Covers); err != nil {
		return err
	}
	if err := requireNonemptyUniqueStrings("case "+id+" control limitations", control.DoesNotCover); err != nil {
		return err
	}
	for identity, sum := range control.ModuleSums {
		if !moduleIdentityPattern.MatchString(identity) || sum == "" {
			return fmt.Errorf("case %q has an incomplete module sum", id)
		}
	}
	return nil
}

func validateHeadAssessment(id string, assessment HeadAssessment) error {
	if assessment.EvaluatedCommit != EvaluatedCandidateCommit {
		return fmt.Errorf("case %q evaluates the wrong candidate commit", id)
	}
	switch assessment.Status {
	case "present", "resolved", "partially_mitigated", "unknown":
	default:
		return fmt.Errorf("case %q has invalid head status %q", id, assessment.Status)
	}
	if len(assessment.Limitations) == 0 {
		return fmt.Errorf("case %q omits the limits of its current-head assessment", id)
	}
	if err := requireNonemptyUniqueStrings("case "+id+" assessment limitations", assessment.Limitations); err != nil {
		return err
	}
	switch assessment.Basis {
	case "runtime_test", "source_review":
		if len(assessment.EvidenceRefs) == 0 {
			return fmt.Errorf("case %q has an evidence basis without references", id)
		}
	case "none":
		if assessment.Status != "unknown" || len(assessment.EvidenceRefs) != 0 {
			return fmt.Errorf("case %q uses basis none for a non-unknown assessment", id)
		}
	default:
		return fmt.Errorf("case %q has invalid assessment basis %q", id, assessment.Basis)
	}
	for _, reference := range assessment.EvidenceRefs {
		if reference.Commit != EvaluatedCandidateCommit ||
			reference.Path == "" || reference.Symbol == "" {
			return fmt.Errorf("case %q has an invalid current-head evidence reference", id)
		}
	}
	return nil
}

func decodeStrict(data []byte, target any) error {
	return strictjson.Decode(data, target)
}

func optionalStringEquals(actual *string, expected string) bool {
	if expected == "" {
		return actual == nil
	}
	return actual != nil && *actual == expected
}

func requireNonemptyUniqueStrings(label string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value == "" {
			return fmt.Errorf("%s contains an empty value at index %d", label, index)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("%s contains duplicate value %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}
