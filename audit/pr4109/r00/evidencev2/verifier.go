package evidencev2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/keep-network/keep-core/audit/pr4109/internal/strictjson"
	legacyr00 "github.com/keep-network/keep-core/audit/pr4109/r00"
)

const (
	maxRootBytes           int64  = 1 << 20
	maxJSONArtifactBytes   int64  = 8 << 20
	maxTextArtifactBytes   int64  = 16 << 20
	maxBinaryArtifactBytes int64  = 64 << 20
	maxBundleArtifactBytes uint64 = 512 << 20
)

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rolePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
)

type verifiedArtifact struct {
	reference FileReference
	data      []byte
}

type toolDigestEntry struct {
	Binding           ToolBinding `json:"binding"`
	ExecutableSHA256  string      `json:"executable_sha256"`
	BuildInfoSHA256   string      `json:"build_info_sha256"`
	ModuleGraphSHA256 string      `json:"module_graph_sha256"`
	SourceAssetSHA256 string      `json:"source_asset_sha256"`
	BuildInfo         BuildInfo   `json:"build_info"`
}

// VerifyBundle fail-closed verifies the internal consistency of a closed
// evidence-v2 bundle. Proof equations and signatures are evaluated from raw
// material; no runner verdict is consumed. It does not authenticate that the
// retained executables actually produced the retained records. Consequently,
// ExecutionProvenanceVerified and EvidenceAccepted are always false; external
// CI provenance and reproducible-build verification are required before an
// evidence consumer can make either determination.
func VerifyBundle(bundleDirectory string) (*Report, error) {
	rootData, err := readRegularFile(
		filepath.Join(bundleDirectory, RootFilename),
		maxRootBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("evidence root: %w", err)
	}
	rootDigest := sha256.Sum256(rootData)
	if err := validateBundleAddress(bundleDirectory, hex.EncodeToString(rootDigest[:])); err != nil {
		return nil, fmt.Errorf("evidence root: %w", err)
	}
	var root EvidenceRoot
	if err := strictjson.Decode(rootData, &root); err != nil {
		return nil, fmt.Errorf("evidence root: strict JSON: %w", err)
	}
	if err := validateRoot(&root); err != nil {
		return nil, fmt.Errorf("evidence root: %w", err)
	}
	if err := verifyLegacyV1(); err != nil {
		return nil, fmt.Errorf("legacy v1 binding: %w", err)
	}
	if err := verifyClosedLayout(bundleDirectory, root.Files); err != nil {
		return nil, fmt.Errorf("bundle layout: %w", err)
	}
	artifacts, err := verifyReferencedFiles(bundleDirectory, root.Files)
	if err != nil {
		return nil, err
	}

	bindings, inventoryDigest, consumed, err := verifyToolInventory(&root, artifacts)
	if err != nil {
		return nil, err
	}

	report := &Report{
		DiagnosticOnly:              root.Authority.DiagnosticOnly,
		ReleaseAuthority:            root.Authority.ReleaseAuthority,
		RootGate:                    root.Authority.RootGate,
		ExecutionProvenanceVerified: false,
		EvidenceAccepted:            false,
		Cases:                       make([]CaseOutcome, 0, len(requiredCaseIDs)),
	}
	for _, caseID := range requiredCaseIDs {
		caseRole := "case_" + strings.ToLower(caseID)
		artifact, err := consumeArtifact(
			artifacts,
			consumed,
			caseRole,
			"application/json",
		)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", caseID, err)
		}
		wantPath := "cases/" + caseID + ".json"
		if artifact.reference.Path != wantPath {
			return nil, fmt.Errorf(
				"%s: case artifact path is %q, want %q",
				caseID,
				artifact.reference.Path,
				wantPath,
			)
		}
		var evidence CaseEvidence
		if err := strictjson.Decode(artifact.data, &evidence); err != nil {
			return nil, fmt.Errorf("%s: strict JSON: %w", caseID, err)
		}
		if evidence.CaseID != caseID {
			return nil, fmt.Errorf("%s: record identifies %q", caseID, evidence.CaseID)
		}
		if evidence.ToolInventorySHA256 != inventoryDigest {
			return nil, fmt.Errorf("%s: tool inventory identity drift", caseID)
		}
		if err := validateCaseEvidence(
			&evidence,
			bindings,
			artifacts,
			consumed,
		); err != nil {
			return nil, fmt.Errorf("%s: %w", caseID, err)
		}
		report.Cases = append(report.Cases, CaseOutcome{
			CaseID:                    caseID,
			DerivedPredicateSatisfied: true,
		})
	}
	if len(consumed) != len(artifacts) {
		unused := make([]string, 0, len(artifacts)-len(consumed))
		for role := range artifacts {
			if _, used := consumed[role]; !used {
				unused = append(unused, role)
			}
		}
		sort.Strings(unused)
		return nil, fmt.Errorf("bundle contains unreferenced artifact roles %v", unused)
	}
	return report, nil
}

func validateRoot(root *EvidenceRoot) error {
	if root.Schema != BundleSchema || root.Version != 2 {
		return errors.New("unsupported bundle schema")
	}
	if root.Repository != "threshold-network/keep-core" || root.PullRequest != 4109 {
		return errors.New("repository or pull-request identity drift")
	}
	if err := validateSourceIdentity(root.BaselineSource); err != nil {
		return fmt.Errorf("baseline source: %w", err)
	}
	if root.BaselineSource.Repository != "threshold-network/keep-core" ||
		root.BaselineSource.Commit != BaselineSourceCommit ||
		root.BaselineSource.TreeSHA256 != BaselineTreeSHA256 {
		return errors.New("baseline source commit drift")
	}
	if err := validateSourceIdentity(root.PriorSource); err != nil {
		return fmt.Errorf("prior source: %w", err)
	}
	if root.PriorSource.Repository != "threshold-network/keep-core" ||
		root.PriorSource.Commit != PriorSourceCommit ||
		root.PriorSource.TreeSHA256 != PriorTreeSHA256 {
		return errors.New("prior source commit drift")
	}
	if err := validateSourceIdentity(root.RunnerSource); err != nil {
		return fmt.Errorf("runner source: %w", err)
	}
	if root.RunnerSource.Repository != "threshold-network/keep-core" ||
		root.RunnerSource.Commit == root.BaselineSource.Commit {
		return errors.New("runner source is missing or conflated with the frozen baseline")
	}
	if root.FixtureManifestSHA256 != FixtureManifestSHA256 {
		return errors.New("11-party keygen fixture manifest drift")
	}
	legacy := root.LegacyV1
	if legacy.ReproductionCatalogSHA256 != V1CatalogSHA256 ||
		legacy.FrozenInputsSHA256 != V1FrozenInputsSHA256 ||
		legacy.CatalogStatus != "blocked" || legacy.CaseCount != 18 ||
		legacy.BaselineEvidenceStatus != "not_run" {
		return errors.New("legacy v1 pin or blocked-state declaration drift")
	}
	if !slices.Equal(root.Scope, requiredCaseIDs[:]) {
		return fmt.Errorf("scope is %v, want exactly %v", root.Scope, requiredCaseIDs)
	}
	if !root.Authority.DiagnosticOnly || root.Authority.ReleaseAuthority ||
		root.Authority.RootGate != "blocked" {
		return errors.New("authority must be diagnostic-only with blocked root gate")
	}
	if err := validateToolBindings(root.Tools); err != nil {
		return err
	}
	_, err := indexFileReferences(root.Files)
	return err
}

func validateSourceIdentity(identity SourceIdentity) error {
	if identity.Repository == "" || !commitPattern.MatchString(identity.Commit) ||
		!sha256Pattern.MatchString(identity.TreeSHA256) {
		return errors.New("noncanonical repository, commit, or tree identity")
	}
	return nil
}

func expectedToolBindings() []ToolBinding {
	return []ToolBinding{
		{HistoricalProofTool, "proof", HistoricalImplementation, "tool_historical-proof_binary", "tool_historical-proof_buildinfo", "tool_historical-proof_modulegraph", "tool_historical-proof_source"},
		{CandidateProofTool, "proof", CandidateImplementation, "tool_candidate-proof_binary", "tool_candidate-proof_buildinfo", "tool_candidate-proof_modulegraph", "tool_candidate-proof_source"},
		{HistoricalWorker, "signing_worker", HistoricalImplementation, "tool_historical-worker_binary", "tool_historical-worker_buildinfo", "tool_historical-worker_modulegraph", "tool_historical-worker_source"},
		{CandidateWorker, "signing_worker", CandidateImplementation, "tool_candidate-worker_binary", "tool_candidate-worker_buildinfo", "tool_candidate-worker_modulegraph", "tool_candidate-worker_source"},
		{MixedCoordinator, "coordinator", HarnessImplementation, "tool_mixed-coordinator_binary", "tool_mixed-coordinator_buildinfo", "tool_mixed-coordinator_modulegraph", "tool_mixed-coordinator_source"},
		{EvidenceRunner, "runner", HarnessImplementation, "tool_evidence-runner_binary", "tool_evidence-runner_buildinfo", "tool_evidence-runner_modulegraph", "tool_evidence-runner_source"},
	}
}

func validateToolBindings(bindings []ToolBinding) error {
	want := expectedToolBindings()
	if len(bindings) != len(want) {
		return fmt.Errorf("tool inventory has %d bindings, want %d", len(bindings), len(want))
	}
	for index := range want {
		if bindings[index] != want[index] {
			return fmt.Errorf("tool binding %d drift", index)
		}
	}
	return nil
}

func indexFileReferences(references []FileReference) (map[string]FileReference, error) {
	if len(references) == 0 || len(references) > 512 {
		return nil, fmt.Errorf("unsafe file-reference count %d", len(references))
	}
	byRole := make(map[string]FileReference, len(references))
	seenPaths := make(map[string]struct{}, len(references))
	var aggregateSize uint64
	for _, reference := range references {
		if !rolePattern.MatchString(reference.Role) {
			return nil, fmt.Errorf("noncanonical file role %q", reference.Role)
		}
		if _, duplicate := byRole[reference.Role]; duplicate {
			return nil, fmt.Errorf("duplicate file role %q", reference.Role)
		}
		if err := validateSafeRelativePath(reference.Path); err != nil {
			return nil, fmt.Errorf("unsafe path %q: %w", reference.Path, err)
		}
		if _, duplicate := seenPaths[reference.Path]; duplicate {
			return nil, fmt.Errorf("duplicate file path %q", reference.Path)
		}
		mediaLimit, supported := artifactSizeLimit(reference.MediaType)
		if !supported {
			return nil, fmt.Errorf("unsupported media type %q", reference.MediaType)
		}
		if !sha256Pattern.MatchString(reference.SHA256) ||
			reference.Size > uint64(mediaLimit) ||
			(reference.Size == 0 && reference.MediaType != "text/plain") {
			return nil, fmt.Errorf("%s has unsafe hash or size", reference.Path)
		}
		if aggregateSize > maxBundleArtifactBytes ||
			reference.Size > maxBundleArtifactBytes-aggregateSize {
			return nil, fmt.Errorf(
				"aggregate artifact size exceeds %d-byte bundle limit",
				maxBundleArtifactBytes,
			)
		}
		aggregateSize += reference.Size
		byRole[reference.Role] = reference
		seenPaths[reference.Path] = struct{}{}
	}
	return byRole, nil
}

func artifactSizeLimit(mediaType string) (int64, bool) {
	switch mediaType {
	case "application/json":
		return maxJSONArtifactBytes, true
	case "text/plain":
		return maxTextArtifactBytes, true
	case "application/octet-stream":
		return maxBinaryArtifactBytes, true
	default:
		return 0, false
	}
}

func verifyToolInventory(
	root *EvidenceRoot,
	artifacts map[string]verifiedArtifact,
) (map[string]ToolBinding, string, map[string]struct{}, error) {
	bindings := make(map[string]ToolBinding, len(root.Tools))
	consumed := make(map[string]struct{})
	entries := make([]toolDigestEntry, 0, len(root.Tools))
	fixtureManifest, err := consumeArtifact(
		artifacts,
		consumed,
		"fixture_manifest",
		"text/plain",
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("fixture manifest: %w", err)
	}
	if fixtureManifest.reference.Path != "identity/keygen-fixtures.sha256" ||
		fixtureManifest.reference.SHA256 != FixtureManifestSHA256 {
		return nil, "", nil, errors.New("fixture manifest path or digest drift")
	}
	for _, binding := range root.Tools {
		executable, err := consumeArtifact(
			artifacts,
			consumed,
			binding.ExecutableRole,
			"application/octet-stream",
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("tool %s executable: %w", binding.ToolID, err)
		}
		buildArtifact, err := consumeArtifact(
			artifacts,
			consumed,
			binding.BuildInfoRole,
			"application/json",
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("tool %s build info: %w", binding.ToolID, err)
		}
		moduleGraph, err := consumeArtifact(
			artifacts,
			consumed,
			binding.ModuleGraphRole,
			"text/plain",
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("tool %s module graph: %w", binding.ToolID, err)
		}
		sourceAsset, err := consumeArtifact(
			artifacts,
			consumed,
			binding.SourceAssetRole,
			"text/plain",
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("tool %s source asset: %w", binding.ToolID, err)
		}
		if executable.reference.Path != "tools/"+binding.ToolID+"/tool.bin" ||
			buildArtifact.reference.Path != "tools/"+binding.ToolID+"/build-info.json" ||
			moduleGraph.reference.Path != "tools/"+binding.ToolID+"/module-graph.txt" ||
			sourceAsset.reference.Path != "tools/"+binding.ToolID+"/source-asset.txt" {
			return nil, "", nil, fmt.Errorf("tool %s artifact path drift", binding.ToolID)
		}
		var buildInfo BuildInfo
		if err := strictjson.Decode(buildArtifact.data, &buildInfo); err != nil {
			return nil, "", nil, fmt.Errorf("tool %s build info: strict JSON: %w", binding.ToolID, err)
		}
		if err := validateBuildInfo(
			&buildInfo,
			binding,
			root.BaselineSource,
			root.PriorSource,
			root.RunnerSource,
			executable.reference.SHA256,
			moduleGraph.reference.SHA256,
			sourceAsset.reference.SHA256,
		); err != nil {
			return nil, "", nil, fmt.Errorf("tool %s build info: %w", binding.ToolID, err)
		}
		if err := validateNormalizedModuleGraph(moduleGraph.data, buildInfo.Modules); err != nil {
			return nil, "", nil, fmt.Errorf("tool %s module graph: %w", binding.ToolID, err)
		}
		bindings[binding.ToolID] = binding
		entries = append(entries, toolDigestEntry{
			Binding:           binding,
			ExecutableSHA256:  executable.reference.SHA256,
			BuildInfoSHA256:   buildArtifact.reference.SHA256,
			ModuleGraphSHA256: moduleGraph.reference.SHA256,
			SourceAssetSHA256: sourceAsset.reference.SHA256,
			BuildInfo:         buildInfo,
		})
	}
	digest, err := digestToolInventory(entries)
	if err != nil {
		return nil, "", nil, err
	}
	return bindings, digest, consumed, nil
}

func digestToolInventory(entries []toolDigestEntry) (string, error) {
	encoded, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateBuildInfo(
	buildInfo *BuildInfo,
	binding ToolBinding,
	baseline SourceIdentity,
	prior SourceIdentity,
	runner SourceIdentity,
	executableSHA256 string,
	moduleGraphSHA256 string,
	sourceAssetSHA256 string,
) error {
	if buildInfo.Schema != BuildInfoSchema || buildInfo.Version != 2 {
		return errors.New("unsupported schema")
	}
	if buildInfo.ToolID != binding.ToolID || buildInfo.ToolRole != binding.Role ||
		buildInfo.Implementation != binding.Implementation ||
		buildInfo.ExecutableSHA256 != executableSHA256 {
		return errors.New("tool or executable identity drift")
	}
	if buildInfo.BaselineSource != baseline || buildInfo.PriorSource != prior ||
		buildInfo.RunnerSource != runner {
		return errors.New("baseline, prior, or runner source identity drift")
	}
	wantCompileSource := runner
	if binding.Implementation == HistoricalImplementation {
		wantCompileSource = prior
	} else if binding.Implementation == CandidateImplementation {
		wantCompileSource = baseline
	}
	if buildInfo.CompileSource != wantCompileSource {
		return errors.New("per-tool compile source identity drift")
	}
	if buildInfo.FixtureManifestSHA256 != FixtureManifestSHA256 ||
		buildInfo.InjectedSourceSHA256 != sourceAssetSHA256 {
		return errors.New("fixture manifest or injected source-asset identity drift")
	}
	if buildInfo.MainModule.Path != "github.com/keep-network/keep-core" ||
		buildInfo.MainModule.Version != "(devel)" || buildInfo.MainModule.Sum != "" {
		return errors.New("main module identity drift")
	}
	for name, digest := range map[string]string{
		"go.mod":       buildInfo.GoModSHA256,
		"go.sum":       buildInfo.GoSumSHA256,
		"module graph": buildInfo.ModuleGraphSHA256,
	} {
		if !sha256Pattern.MatchString(digest) {
			return fmt.Errorf("%s identity is not canonical SHA-256", name)
		}
	}
	if buildInfo.ModuleGraphSHA256 != moduleGraphSHA256 {
		return errors.New("retained normalized module graph digest drift")
	}
	switch binding.Implementation {
	case HistoricalImplementation:
		if buildInfo.GoModSHA256 != PriorGoModSHA256 ||
			buildInfo.GoSumSHA256 != PriorGoSumSHA256 {
			return errors.New("PRIOR go.mod or go.sum identity drift")
		}
	case CandidateImplementation:
		if buildInfo.GoModSHA256 != BaselineGoModSHA256 ||
			buildInfo.GoSumSHA256 != BaselineGoSumSHA256 {
			return errors.New("baseline go.mod or go.sum identity drift")
		}
	}
	if buildInfo.Toolchain != (ToolchainIdentity{
		GoVersion: "go1.25.10", GOOS: "linux", GOARCH: "amd64",
		CGOEnabled: false, GOTOOLCHAIN: "local", GOWORK: "off", ModuleMode: "readonly",
	}) {
		return errors.New("toolchain identity drift")
	}
	if buildInfo.VCSModified {
		return errors.New("tool was built from a modified runner tree")
	}
	return validateModuleInventory(buildInfo.Modules, binding.Implementation)
}

func validateBundleAddress(bundleDirectory, rootDigest string) error {
	absolute, err := filepath.Abs(bundleDirectory)
	if err != nil {
		return err
	}
	if filepath.Base(filepath.Dir(absolute)) != "sha256" ||
		filepath.Base(absolute) != rootDigest {
		return errors.New("bundle path must be sha256/<SHA-256(evidence-root.json)>")
	}
	return nil
}

func validateModuleInventory(modules []ModuleIdentity, implementation string) error {
	if len(modules) != 1 {
		return fmt.Errorf("module inventory has %d entries, want the exact TSS tuple", len(modules))
	}
	module := modules[0]
	if module.RequestedPath != "github.com/bnb-chain/tss-lib" ||
		module.RequestedVersion != "v1.3.5" || module.RequestedSum != "" ||
		module.ReplacementPath != "github.com/threshold-network/tss-lib" {
		return errors.New("requested TSS module or replacement path drift")
	}
	wantVersion, wantSum := CandidateTSSVersion, CandidateTSSSum
	if implementation == HistoricalImplementation {
		wantVersion, wantSum = HistoricalTSSVersion, HistoricalTSSSum
	}
	if module.ReplacementVersion != wantVersion || module.ReplacementSum != wantSum {
		return errors.New("TSS replacement version or sum drift")
	}
	return nil
}

func validateNormalizedModuleGraph(data []byte, modules []ModuleIdentity) error {
	var expected strings.Builder
	for _, module := range modules {
		fmt.Fprintf(
			&expected,
			"%s@%s => %s@%s %s\n",
			module.RequestedPath,
			module.RequestedVersion,
			module.ReplacementPath,
			module.ReplacementVersion,
			module.ReplacementSum,
		)
	}
	if string(data) != expected.String() {
		return errors.New("artifact is not the exact normalized requested-to-replacement inventory")
	}
	return nil
}

func verifyLegacyV1() error {
	digests := legacyr00.DocumentDigests()
	if digests.FrozenInputsSHA256 != V1FrozenInputsSHA256 ||
		digests.ReproductionCatalogSHA256 != V1CatalogSHA256 {
		return errors.New("embedded v1 document digest drift")
	}
	bundle, err := legacyr00.Load()
	if err != nil {
		return fmt.Errorf("could not validate embedded documents: %w", err)
	}
	if bundle.Catalog.Status != "blocked" || len(bundle.Catalog.Cases) != 18 {
		return errors.New("catalog is not blocked with exactly 18 cases")
	}
	for _, reproduction := range bundle.Catalog.Cases {
		if reproduction.BaselineEvidence.Status != "not_run" ||
			len(reproduction.BaselineEvidence.Controls) != 0 ||
			reproduction.ReleaseGate != "blocking" {
			return fmt.Errorf("%s no longer has not_run evidence and a blocking gate", reproduction.ID)
		}
	}
	return nil
}

func consumeArtifact(
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
	role string,
	mediaType string,
) (verifiedArtifact, error) {
	artifact, present := artifacts[role]
	if !present {
		return verifiedArtifact{}, fmt.Errorf("missing artifact role %q", role)
	}
	if _, duplicate := consumed[role]; duplicate {
		return verifiedArtifact{}, fmt.Errorf("artifact role %q is referenced more than once", role)
	}
	if artifact.reference.MediaType != mediaType {
		return verifiedArtifact{}, fmt.Errorf("artifact role %q has wrong media type", role)
	}
	consumed[role] = struct{}{}
	return artifact, nil
}

func validateSafeRelativePath(name string) error {
	if name == "" || !utf8.ValidString(name) || strings.Contains(name, `\`) ||
		path.IsAbs(name) || path.Clean(name) != name || name == "." || name == ".." ||
		strings.HasPrefix(name, "../") {
		return errors.New("path is not canonical relative slash form")
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("path contains unsafe component")
		}
	}
	return nil
}

func verifyClosedLayout(bundleDirectory string, references []FileReference) error {
	root, err := filepath.Abs(bundleDirectory)
	if err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("bundle root is not a real directory")
	}
	expectedFiles := map[string]struct{}{RootFilename: {}}
	expectedDirectories := make(map[string]struct{})
	for _, reference := range references {
		expectedFiles[reference.Path] = struct{}{}
		for directory := path.Dir(reference.Path); directory != "."; directory = path.Dir(directory) {
			expectedDirectories[directory] = struct{}{}
			if !strings.Contains(directory, "/") {
				break
			}
		}
	}
	return filepath.WalkDir(root, func(entryPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entryPath == root {
			return nil
		}
		relative, err := filepath.Rel(root, entryPath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", relative)
		}
		if entry.IsDir() {
			if _, expected := expectedDirectories[relative]; !expected {
				return fmt.Errorf("unexpected directory %s", relative)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", relative)
		}
		if _, expected := expectedFiles[relative]; !expected {
			return fmt.Errorf("unexpected file %s", relative)
		}
		return nil
	})
}

func verifyReferencedFiles(
	bundleDirectory string,
	references []FileReference,
) (map[string]verifiedArtifact, error) {
	result := make(map[string]verifiedArtifact, len(references))
	for _, reference := range references {
		limit, supported := artifactSizeLimit(reference.MediaType)
		if !supported {
			return nil, fmt.Errorf("artifact %s: unsupported media type", reference.Path)
		}
		data, err := readRegularFile(
			filepath.Join(bundleDirectory, filepath.FromSlash(reference.Path)),
			limit,
		)
		if err != nil {
			return nil, fmt.Errorf("artifact %s: %w", reference.Path, err)
		}
		if uint64(len(data)) != reference.Size {
			return nil, fmt.Errorf("artifact %s: size mismatch", reference.Path)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != reference.SHA256 {
			return nil, fmt.Errorf("artifact %s: SHA-256 mismatch", reference.Path)
		}
		result[reference.Role] = verifiedArtifact{reference, data}
	}
	return result, nil
}

func readRegularFile(name string, limit int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular, nonsymlink file")
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("file size %d exceeds limit %d", info.Size(), limit)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("file changed while being read")
	}
	return data, nil
}
