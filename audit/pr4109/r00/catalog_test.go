package r00

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogIsTruthfullyBlocked(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("could not load R00 bundle: %v", err)
	}

	if bundle.Catalog.Status != "blocked" {
		t.Fatalf("catalog status is %q, want blocked", bundle.Catalog.Status)
	}
	if len(bundle.Catalog.Blockers) == 0 {
		t.Fatal("blocked catalog has no root blocker")
	}
	for _, reproduction := range bundle.Catalog.Cases {
		if reproduction.BaselineEvidence.Status != "not_run" {
			t.Errorf(
				"%s baseline evidence is %q; this slice has no retained execution",
				reproduction.ID,
				reproduction.BaselineEvidence.Status,
			)
		}
		if len(reproduction.BaselineEvidence.Controls) != 0 {
			t.Errorf("%s claims controls in the no-evidence baseline", reproduction.ID)
		}
		if reproduction.ReleaseGate != "blocking" {
			t.Errorf("%s release gate is %q, want blocking", reproduction.ID, reproduction.ReleaseGate)
		}
	}

	wantHead := map[string]string{
		"R00-04": "resolved",
		"R00-05": "present",
		"R00-07": "present",
		"R00-15": "partially_mitigated",
	}
	for _, reproduction := range bundle.Catalog.Cases {
		want, classified := wantHead[reproduction.ID]
		if !classified {
			want = "unknown"
		}
		if reproduction.HeadAssessment.Status != want {
			t.Errorf(
				"%s head status is %q, want %q",
				reproduction.ID,
				reproduction.HeadAssessment.Status,
				want,
			)
		}
	}

	wantExitBlockers := len(bundle.Catalog.Blockers) + len(bundle.Catalog.Cases)
	if got := len(bundle.ExitBlockers()); got != wantExitBlockers {
		t.Fatalf("ExitBlockers returned %d entries, want %d", got, wantExitBlockers)
	}
}

func TestValidationRefusesUnsupportedReadinessClaims(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("could not load R00 bundle: %v", err)
	}

	ready := cloneBundle(bundle)
	ready.Catalog.Status = "ready"
	ready.Catalog.Blockers = nil
	if err := ready.Validate(); err == nil {
		t.Fatal("ready root accepted incomplete and blocked cases")
	}

	satisfied := cloneBundle(bundle)
	satisfied.Catalog.Cases[0].ReleaseGate = "satisfied"
	if err := satisfied.Validate(); err == nil {
		t.Fatal("satisfied gate accepted not_run baseline evidence")
	}

	partial := cloneBundle(bundle)
	partial.Catalog.Cases[0].BaselineEvidence.Status = "partial"
	if err := partial.Validate(); err == nil {
		t.Fatal("partial evidence accepted without a retained control")
	}
}

func TestEmbeddedDocumentsRejectUnknownFields(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		target func() any
		mutate func(map[string]any)
	}{
		{
			name:   "frozen inputs root",
			input:  frozenInputsJSON,
			target: func() any { return &FrozenInputs{} },
			mutate: func(document map[string]any) {
				document["unexpected"] = true
			},
		},
		{
			name:   "frozen input nested object",
			input:  frozenInputsJSON,
			target: func() any { return &FrozenInputs{} },
			mutate: func(document map[string]any) {
				inputs := document["inputs"].([]any)
				inputs[0].(map[string]any)["unexpected"] = true
			},
		},
		{
			name:   "catalog root",
			input:  reproductionCatalogJSON,
			target: func() any { return &ReproductionCatalog{} },
			mutate: func(document map[string]any) {
				document["unexpected"] = true
			},
		},
		{
			name:   "catalog nested object",
			input:  reproductionCatalogJSON,
			target: func() any { return &ReproductionCatalog{} },
			mutate: func(document map[string]any) {
				cases := document["cases"].([]any)
				cases[0].(map[string]any)["unexpected"] = true
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(test.input, &document); err != nil {
				t.Fatalf("could not prepare mutation: %v", err)
			}
			test.mutate(document)
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("could not encode mutation: %v", err)
			}
			if err := decodeStrict(mutated, test.target()); err == nil {
				t.Fatal("strict decoder accepted an unknown field")
			}
		})
	}
}

func TestKeepCoreSourceAnchorsResolveExactObjectAndSymbol(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("could not load R00 bundle: %v", err)
	}
	root := moduleRoot(t)
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		if os.IsNotExist(err) {
			t.Skip(
				"Git metadata is absent; the mandatory host-side source-anchor " +
					"step in the client CI job verifies history before Docker tests",
			)
		}
		t.Fatalf("could not inspect repository metadata: %v", err)
	}

	for _, reproduction := range bundle.Catalog.Cases {
		for _, anchor := range reproduction.SourceAnchors {
			if anchor.Repository != "threshold-network/keep-core" {
				continue
			}
			assertGitAnchor(
				t,
				root,
				reproduction.ID,
				anchor.Commit,
				anchor.Path,
				anchor.Symbol,
			)
		}
		for _, reference := range reproduction.HeadAssessment.EvidenceRefs {
			assertGitAnchor(
				t,
				root,
				reproduction.ID,
				reference.Commit,
				reference.Path,
				reference.Symbol,
			)
		}
	}
}

func TestTSSIdentityMatchesModuleAndOperatorDocs(t *testing.T) {
	root := moduleRoot(t)
	version := "v0.0.0-20260729021955-d847ce003019"
	checksum := "h1:EmD85fdfi20RKON39+Hho5zmB57gHj7EWd7pTYwsqRY="

	assertFileContains(t, filepath.Join(root, "go.mod"),
		"github.com/threshold-network/tss-lib "+version)
	assertFileContains(t, filepath.Join(root, "go.sum"),
		"github.com/threshold-network/tss-lib "+version+" "+checksum)
	for _, name := range []string{"CHANGELOG.md", "SECURITY-BREAKING-CHANGES.md"} {
		assertFileContains(t, filepath.Join(root, name), version)
		assertFileContains(t, filepath.Join(root, name), "d847ce003019")
	}
}

func TestR00SchemasCloseEveryDeclaredObject(t *testing.T) {
	for _, name := range []string{
		"frozen-inputs.schema.json",
		"reproduction-evidence.schema.json",
		"reproduction-catalog.schema.json",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("schemas", name))
			if err != nil {
				t.Fatalf("could not read schema: %v", err)
			}
			var schema any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatalf("invalid schema JSON: %v", err)
			}
			assertDeclaredObjectsClosed(t, schema, "$")
		})
	}
}

func cloneBundle(source *Bundle) *Bundle {
	result := *source
	result.Inputs.Inputs = append([]FrozenInput(nil), source.Inputs.Inputs...)
	result.Catalog.Cases = append([]ReproductionCase(nil), source.Catalog.Cases...)
	result.Catalog.Blockers = append([]string(nil), source.Catalog.Blockers...)
	return &result
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("could not resolve module root: %v", err)
	}
	return root
}

func assertGitAnchor(
	t *testing.T,
	root string,
	caseID string,
	commit string,
	path string,
	symbol string,
) {
	t.Helper()
	commitObject := exec.Command("git", "cat-file", "-e", commit+"^{commit}")
	commitObject.Dir = root
	if output, err := commitObject.CombinedOutput(); err != nil {
		t.Fatalf(
			"%s source commit %s is unavailable; immutable anchors fail closed: %v: %s",
			caseID,
			commit,
			err,
			output,
		)
	}

	anchoredBlob := exec.Command("git", "show", commit+":"+path)
	anchoredBlob.Dir = root
	contents, err := anchoredBlob.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"%s source anchor %s:%s does not resolve: %v: %s",
			caseID,
			commit,
			path,
			err,
			contents,
		)
	}
	if !strings.Contains(string(contents), symbol) {
		t.Fatalf(
			"%s source anchor %s:%s does not contain symbol %q",
			caseID,
			commit,
			path,
			symbol,
		)
	}
}

func assertFileContains(t *testing.T, path string, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	if !strings.Contains(string(data), want) {
		t.Errorf("%s does not contain %q", path, want)
	}
}

func assertDeclaredObjectsClosed(t *testing.T, node any, path string) {
	t.Helper()
	object, ok := node.(map[string]any)
	if !ok {
		if values, array := node.([]any); array {
			for index, value := range values {
				assertDeclaredObjectsClosed(t, value, fmt.Sprintf("%s[%d]", path, index))
			}
		}
		return
	}

	if object["type"] == "object" {
		closed, present := object["additionalProperties"].(bool)
		if !present || closed {
			t.Errorf("declared object at %s is not closed with additionalProperties:false", path)
		}
	}
	for key, value := range object {
		assertDeclaredObjectsClosed(t, value, path+"."+key)
	}
}
