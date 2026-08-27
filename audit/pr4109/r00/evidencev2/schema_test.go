package evidencev2

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSchemasCompileCloseEveryObjectAndValidateSyntheticRecords(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	entries, err := os.ReadDir("schemas")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("schemas", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("%s is invalid JSON: %v", entry.Name(), err)
		}
		id, ok := document["$id"].(string)
		if !ok {
			t.Fatalf("%s has no schema ID", entry.Name())
		}
		if err := compiler.AddResource(id, document); err != nil {
			t.Fatalf("add %s: %v", entry.Name(), err)
		}
		if entry.Name() == "records.schema.json" {
			assertSchemaObjectsClosed(t, document, "$")
		}
	}
	schemaIDs := map[string]string{
		BundleSchema:          "https://threshold.network/schemas/pr4109/r00/evidence-root-v2.json",
		BuildInfoSchema:       "https://threshold.network/schemas/pr4109/r00/tool-build-info-v2.json",
		CaseSchema:            "https://threshold.network/schemas/pr4109/r00/case-evidence-v2.json",
		ProofVectorSchema:     "https://threshold.network/schemas/pr4109/r00/proof-vector-v2.json",
		ProcessEventSchema:    "https://threshold.network/schemas/pr4109/r00/process-event-v2.json",
		WorkerEventSchema:     "https://threshold.network/schemas/pr4109/r00/worker-event-v2.json",
		ProofToolResultSchema: "https://threshold.network/schemas/pr4109/r00/proof-tool-result-v2.json",
	}
	compiled := make(map[string]*jsonschema.Schema, len(schemaIDs))
	for recordSchema, schemaID := range schemaIDs {
		schema, err := compiler.Compile(schemaID)
		if err != nil {
			t.Fatalf("compile %s: %v", schemaID, err)
		}
		compiled[recordSchema] = schema
	}

	fixture := newSyntheticFixture(t)
	rootData, err := os.ReadFile(filepath.Join(fixture.directory, RootFilename))
	if err != nil {
		t.Fatal(err)
	}
	validateSchemaRecord(t, compiled[BundleSchema], rootData)
	root := fixture.loadRoot(t)
	validated := map[string]int{BundleSchema: 1}
	for _, reference := range root.Files {
		if reference.MediaType != "application/json" && reference.MediaType != "text/plain" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(fixture.directory, filepath.FromSlash(reference.Path)))
		if err != nil {
			t.Fatal(err)
		}
		var header struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(data, &header); err != nil || header.Schema == "" {
			continue
		}
		schema, present := compiled[header.Schema]
		if !present {
			t.Fatalf("artifact %s has unregistered schema %q", reference.Role, header.Schema)
		}
		validateSchemaRecord(t, schema, data)
		validated[header.Schema]++
	}
	for recordSchema := range compiled {
		if validated[recordSchema] == 0 {
			t.Errorf("synthetic fixture did not exercise schema %s", recordSchema)
		}
	}
}

func validateSchemaRecord(t *testing.T, schema *jsonschema.Schema, data []byte) {
	t.Helper()
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}
}

func assertSchemaObjectsClosed(t *testing.T, value any, path string) {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		if value["type"] == "object" {
			closed, present := value["additionalProperties"]
			if !present || closed != false {
				t.Errorf("object schema %s is not closed", path)
			}
		}
		for name, child := range value {
			assertSchemaObjectsClosed(t, child, path+"."+name)
		}
	case []any:
		for _, child := range value {
			assertSchemaObjectsClosed(t, child, path+"[]")
		}
	}
}
