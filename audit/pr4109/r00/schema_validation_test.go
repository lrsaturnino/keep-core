package r00

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	frozenInputsSchemaID = "https://threshold.network/schemas/pr4109/r00/frozen-inputs-v1.json"
	evidenceSchemaID     = "https://threshold.network/schemas/pr4109/r00/reproduction-evidence.schema.json"
	catalogSchemaID      = "https://threshold.network/schemas/pr4109/r00/reproduction-catalog-v1.json"
)

func TestR00SchemasCompileAndValidateEmbeddedDocuments(t *testing.T) {
	schemas := compileR00Schemas(t)
	validateJSONAgainstSchema(t, schemas[frozenInputsSchemaID], frozenInputsJSON)
	validateJSONAgainstSchema(t, schemas[catalogSchemaID], reproductionCatalogJSON)
}

func TestR00DocumentBytesArePinned(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "frozen inputs",
			data: frozenInputsJSON,
			want: "03cecccccb2dc1eb24e0fda9bb05f5403a6e7d962d46d836179b4db09cad5e8b",
		},
		{
			name: "reproduction catalog",
			data: reproductionCatalogJSON,
			want: "79dd86ea28b595de2da49033c5ce9ad0c0b95eaa2152b944d6045db8dba69f6e",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := fmt.Sprintf("%x", sha256.Sum256(test.data)); got != test.want {
				t.Fatalf("document bytes changed: SHA-256 is %s, want %s", got, test.want)
			}
		})
	}
}

func TestR00GoAndSchemasRejectAuthorityDrift(t *testing.T) {
	schemas := compileR00Schemas(t)

	tests := []struct {
		name         string
		mutateBundle func(*Bundle)
		mutateJSON   func(map[string]any)
	}{
		{
			name: "ready root",
			mutateBundle: func(bundle *Bundle) {
				bundle.Catalog.Status = "ready"
				bundle.Catalog.Blockers = nil
			},
			mutateJSON: func(document map[string]any) {
				document["status"] = "ready"
				document["blockers"] = []any{}
			},
		},
		{
			name: "satisfied release gate",
			mutateBundle: func(bundle *Bundle) {
				bundle.Catalog.Cases[0].ReleaseGate = "satisfied"
			},
			mutateJSON: func(document map[string]any) {
				cases := document["cases"].([]any)
				cases[0].(map[string]any)["release_gate"] = "satisfied"
			},
		},
		{
			name: "not-run without blocker",
			mutateBundle: func(bundle *Bundle) {
				bundle.Catalog.Cases[0].BaselineEvidence.Blockers = nil
			},
			mutateJSON: func(document map[string]any) {
				cases := document["cases"].([]any)
				evidence := cases[0].(map[string]any)["baseline_evidence"].(map[string]any)
				evidence["blockers"] = []any{}
			},
		},
		{
			name: "complete control with failed command",
			mutateBundle: func(bundle *Bundle) {
				bundle.Catalog.Cases[0].BaselineEvidence = completeEvidence(7)
			},
			mutateJSON: func(document map[string]any) {
				cases := document["cases"].([]any)
				evidenceBytes, err := json.Marshal(completeEvidence(7))
				if err != nil {
					t.Fatalf("could not encode evidence mutation: %v", err)
				}
				var evidence any
				if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
					t.Fatalf("could not decode evidence mutation: %v", err)
				}
				cases[0].(map[string]any)["baseline_evidence"] = evidence
			},
		},
		{
			name: "resolved assessment with no basis",
			mutateBundle: func(bundle *Bundle) {
				assessment := &bundle.Catalog.Cases[0].HeadAssessment
				assessment.Status = "resolved"
				assessment.Basis = "none"
				assessment.EvidenceRefs = nil
			},
			mutateJSON: func(document map[string]any) {
				cases := document["cases"].([]any)
				assessment := cases[0].(map[string]any)["head_assessment"].(map[string]any)
				assessment["status"] = "resolved"
				assessment["basis"] = "none"
				assessment["evidence_refs"] = []any{}
			},
		},
		{
			name: "duplicate case identity",
			mutateBundle: func(bundle *Bundle) {
				bundle.Catalog.Cases[1].ID = "R00-01"
			},
			mutateJSON: func(document map[string]any) {
				cases := document["cases"].([]any)
				cases[1].(map[string]any)["id"] = "R00-01"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle, err := Load()
			if err != nil {
				t.Fatalf("could not load R00 bundle: %v", err)
			}
			mutated := cloneBundleForSchemaTest(bundle)
			test.mutateBundle(mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("Go validation accepted adversarial catalog mutation")
			}

			document := decodeJSONObject(t, reproductionCatalogJSON)
			test.mutateJSON(document)
			if err := schemas[catalogSchemaID].Validate(document); err == nil {
				t.Fatal("compiled catalog schema accepted adversarial mutation")
			}
		})
	}
}

func TestR00GoAndSchemaRejectFrozenInputIdentityDrift(t *testing.T) {
	schemas := compileR00Schemas(t)
	bundle, err := Load()
	if err != nil {
		t.Fatalf("could not load R00 bundle: %v", err)
	}
	mutated := cloneBundleForSchemaTest(bundle)
	mutated.Inputs.Inputs[6].Repository = "lrsaturnino/pr4109-do-infra"
	if err := mutated.Validate(); err == nil {
		t.Fatal("Go validation accepted the wrong external harness owner")
	}

	document := decodeJSONObject(t, frozenInputsJSON)
	inputs := document["inputs"].([]any)
	inputs[6].(map[string]any)["repository"] = "lrsaturnino/pr4109-do-infra"
	if err := schemas[frozenInputsSchemaID].Validate(document); err == nil {
		t.Fatal("compiled frozen-input schema accepted the wrong external harness owner")
	}
}

func TestR00GoAndSchemaShareCanonicalModuleIdentity(t *testing.T) {
	schemas := compileR00Schemas(t)
	evidence := completeEvidence(0)
	evidence.Controls[0].ModuleSums = map[string]string{
		"ambiguous-module-identity": "h1:example",
	}

	bundle, err := Load()
	if err != nil {
		t.Fatalf("could not load R00 bundle: %v", err)
	}
	bundle.Catalog.Cases[0].BaselineEvidence = evidence
	if err := bundle.Validate(); err == nil {
		t.Fatal("Go validation accepted an ambiguous module identity")
	}

	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("could not encode evidence: %v", err)
	}
	var evidenceDocument any
	if err := decodeStrict(evidenceBytes, &evidenceDocument); err != nil {
		t.Fatalf("could not decode evidence: %v", err)
	}
	if err := schemas[evidenceSchemaID].Validate(evidenceDocument); err == nil {
		t.Fatal("compiled schema accepted an ambiguous module identity")
	}
}

func TestR00StrictDecoderRejectsDuplicateNames(t *testing.T) {
	duplicateRoot := bytes.Replace(
		reproductionCatalogJSON,
		[]byte(`"status": "blocked"`),
		[]byte(`"status": "blocked", "status": "ready"`),
		1,
	)
	var catalog ReproductionCatalog
	if err := decodeStrict(duplicateRoot, &catalog); err == nil ||
		!strings.Contains(err.Error(), "duplicate JSON object name") {
		t.Fatalf("catalog decoder error is %v, want duplicate-name rejection", err)
	}

	duplicateNested := bytes.Replace(
		frozenInputsJSON,
		[]byte(`"repository": "threshold-network/keep-core"`),
		[]byte(`"repository": "threshold-network/keep-core", "repository": "attacker/fork"`),
		1,
	)
	var inputs FrozenInputs
	if err := decodeStrict(duplicateNested, &inputs); err == nil ||
		!strings.Contains(err.Error(), "duplicate JSON object name") {
		t.Fatalf("frozen-input decoder error is %v, want duplicate-name rejection", err)
	}
}

func completeEvidence(exitCode int) BaselineEvidence {
	return BaselineEvidence{
		Status: "complete",
		Controls: []EvidenceControl{
			{
				Coverage:             "complete",
				Command:              "go test ./...",
				WorkingDirectory:     "/immutable/source",
				ExecutedSourceCommit: BaselineSourceCommit,
				SourceTreeDigest:     strings.Repeat("a", 64),
				ExitCode:             exitCode,
				StdoutPath:           "evidence/stdout.txt",
				StdoutSHA256:         strings.Repeat("b", 64),
				StderrPath:           "evidence/stderr.txt",
				StderrSHA256:         strings.Repeat("c", 64),
				Toolchain: Toolchain{
					GoVersion: "go1.25.10",
					GOOS:      "linux",
					GOARCH:    "amd64",
				},
				ModuleSums: map[string]string{
					"example.invalid/module@v1.0.0=>": "h1:example",
				},
				Covers:       []string{"entire predicate"},
				DoesNotCover: []string{},
			},
		},
		Blockers: []string{},
	}
}

func compileR00Schemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	resources := map[string]string{
		frozenInputsSchemaID: "frozen-inputs.schema.json",
		evidenceSchemaID:     "reproduction-evidence.schema.json",
		catalogSchemaID:      "reproduction-catalog.schema.json",
	}
	for id, name := range resources {
		data, err := os.ReadFile(filepath.Join("schemas", name))
		if err != nil {
			t.Fatalf("could not read schema %s: %v", name, err)
		}
		var document any
		if err := decodeStrict(data, &document); err != nil {
			t.Fatalf("could not decode schema %s: %v", name, err)
		}
		if err := compiler.AddResource(id, document); err != nil {
			t.Fatalf("could not register schema %s: %v", name, err)
		}
	}

	compiled := make(map[string]*jsonschema.Schema, len(resources))
	for id := range resources {
		schema, err := compiler.Compile(id)
		if err != nil {
			t.Fatalf("could not compile schema %s: %v", id, err)
		}
		compiled[id] = schema
	}
	return compiled
}

func validateJSONAgainstSchema(t *testing.T, schema *jsonschema.Schema, data []byte) {
	t.Helper()
	var document any
	if err := decodeStrict(data, &document); err != nil {
		t.Fatalf("could not decode JSON instance: %v", err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("checked-in JSON does not satisfy its compiled schema: %v", err)
	}
}

func decodeJSONObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("could not decode JSON object: %v", err)
	}
	return document
}

func cloneBundleForSchemaTest(source *Bundle) *Bundle {
	data, err := json.Marshal(source)
	if err != nil {
		panic(err)
	}
	var result Bundle
	if err := json.Unmarshal(data, &result); err != nil {
		panic(err)
	}
	return &result
}
