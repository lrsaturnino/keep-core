// Package evidencev2 defines and fail-closed verifies the self-consistency of
// diagnostic evidence records for the first three PR #4109 R00 reproduction
// cases.
//
// It is additive scaffolding. It neither replaces the blocked R00 v1 catalog
// nor executes a reproduction runner or grants release authority. It also
// cannot authenticate that a retained executable actually produced a retained
// transcript; evidence acceptance requires external execution provenance and
// reproducible-build verification.
package evidencev2

const (
	RootFilename = "evidence-root.json"

	BundleSchema          = "pr4109/r00-reproduction-evidence-bundle/v2"
	BuildInfoSchema       = "pr4109/r00-tool-build-info/v2"
	CaseSchema            = "pr4109/r00-case-evidence/v2"
	ProofVectorSchema     = "pr4109/r00-proof-vector/v2"
	ProcessEventSchema    = "pr4109/r00-process-event/v2"
	WorkerEventSchema     = "pr4109/r00-worker-event/v2"
	ProofToolResultSchema = "pr4109/r00-proof-tool-result/v2"

	BaselineSourceCommit  = "1bc7edf9965cac43de3bd18060e07ba678670073"
	BaselineTreeSHA256    = "6b1dd8926674c13e81e259cdbaa0d575317faba81b8a19467c9f52694210dcc1"
	PriorSourceCommit     = "66b187efdbe1cd567950de0efe9728de95886b13"
	PriorTreeSHA256       = "1cffb3cb5eeda2a00e0ffc00edff0a90a822aa5bc1658473b762b8f0185ff924"
	BaselineGoModSHA256   = "73362df2edfea4014951ce8e73a9ce8aba81d0c33f57ef406f0803ece5762b42"
	BaselineGoSumSHA256   = "c83f7573d66b6e4ec4eed90f6b0d46858f2f111f53bc9b11de0e9b7bd2d727cc"
	PriorGoModSHA256      = "aa1840ee1dcf01296c4854e7c35018d6bbef41f230a2c1346b648612eac12012"
	PriorGoSumSHA256      = "0f950b3c40aafdc27bacfddc4e1e4fc742efc4e1fe6d13d2e05dbc08c9377b0e"
	V1CatalogSHA256       = "79dd86ea28b595de2da49033c5ce9ad0c0b95eaa2152b944d6045db8dba69f6e"
	V1FrozenInputsSHA256  = "03cecccccb2dc1eb24e0fda9bb05f5403a6e7d962d46d836179b4db09cad5e8b"
	FixtureManifestSHA256 = "7b934fd6db3a109e1c3c70ec2be50aab3af3f955951d02f18841331eb988c42c"

	HistoricalImplementation = "tss-lib@2e712689cfbeefede15f95a0ec7112227d86f702"
	CandidateImplementation  = "tss-lib@d847ce0030193ccf5dbec0097571dcce5a2a5cf6"
	HarnessImplementation    = "keep-core-r00-evidence-v2"

	HistoricalTSSVersion = "v0.0.0-20230901144531-2e712689cfbe"
	HistoricalTSSSum     = "h1:dOKhoYxZjXwFIyGnxgU+Sa1obZPMHRhu6e44oOLkzU4="
	CandidateTSSVersion  = "v0.0.0-20260729021955-d847ce003019"
	CandidateTSSSum      = "h1:EmD85fdfi20RKON39+Hho5zmB57gHj7EWd7pTYwsqRY="

	HistoricalProofTool = "historical-proof"
	CandidateProofTool  = "candidate-proof"
	HistoricalWorker    = "historical-worker"
	CandidateWorker     = "candidate-worker"
	MixedCoordinator    = "mixed-coordinator"
	EvidenceRunner      = "evidence-runner"

	FixturePublicKeyX = "0x03472891167c868800271158e7ed01dcb46595a39479909b398a2d2e0cd02812"
	FixturePublicKeyY = "0x6a91b933c2498f8845218d114e91fa0d60dd897b826f962c4187d46397951740"
	FixtureMessageHex = "0x000000000000000000000000000000000000000000000000000000000000002a"
)

var requiredCaseIDs = [...]string{"R00-01", "R00-02", "R00-03"}

type Authority struct {
	DiagnosticOnly   bool   `json:"diagnostic_only"`
	ReleaseAuthority bool   `json:"release_authority"`
	RootGate         string `json:"root_gate"`
}

type LegacyV1Binding struct {
	ReproductionCatalogSHA256 string `json:"reproduction_catalog_sha256"`
	FrozenInputsSHA256        string `json:"frozen_inputs_sha256"`
	CatalogStatus             string `json:"catalog_status"`
	CaseCount                 uint64 `json:"case_count"`
	BaselineEvidenceStatus    string `json:"baseline_evidence_status"`
}

// SourceIdentity keeps the frozen system-under-test separate from the later
// evidence-runner implementation that captures it. TreeSHA256 is the digest
// of the canonical tree-content manifest, not a Git SHA-1 tree object ID.
type SourceIdentity struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	TreeSHA256 string `json:"tree_sha256"`
}

type ToolchainIdentity struct {
	GoVersion   string `json:"go_version"`
	GOOS        string `json:"goos"`
	GOARCH      string `json:"goarch"`
	CGOEnabled  bool   `json:"cgo_enabled"`
	GOTOOLCHAIN string `json:"gotoolchain"`
	GOWORK      string `json:"gowork"`
	ModuleMode  string `json:"module_mode"`
}

// FileReference is one member of the bundle's closed, content-addressed,
// regular-file allowlist. evidence-root.json is necessarily implicit.
type FileReference struct {
	Path      string `json:"path"`
	Role      string `json:"role"`
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	Size      uint64 `json:"size"`
}

type ToolBinding struct {
	ToolID          string `json:"tool_id"`
	Role            string `json:"role"`
	Implementation  string `json:"implementation"`
	ExecutableRole  string `json:"executable_role"`
	BuildInfoRole   string `json:"build_info_role"`
	ModuleGraphRole string `json:"module_graph_role"`
	SourceAssetRole string `json:"source_asset_role"`
}

type EvidenceRoot struct {
	Schema                string          `json:"schema"`
	Version               uint64          `json:"version"`
	Repository            string          `json:"repository"`
	PullRequest           uint64          `json:"pull_request"`
	BaselineSource        SourceIdentity  `json:"baseline_source"`
	PriorSource           SourceIdentity  `json:"prior_source"`
	RunnerSource          SourceIdentity  `json:"runner_source"`
	FixtureManifestSHA256 string          `json:"fixture_manifest_sha256"`
	LegacyV1              LegacyV1Binding `json:"legacy_v1"`
	Scope                 []string        `json:"scope"`
	Authority             Authority       `json:"authority"`
	Tools                 []ToolBinding   `json:"tools"`
	Files                 []FileReference `json:"files"`
}

type MainModuleIdentity struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

// ModuleIdentity retains an exact requested-to-replacement tuple. A closed
// array plus Go validation makes requested identities duplicate-free.
type ModuleIdentity struct {
	RequestedPath      string `json:"requested_path"`
	RequestedVersion   string `json:"requested_version"`
	RequestedSum       string `json:"requested_sum"`
	ReplacementPath    string `json:"replacement_path"`
	ReplacementVersion string `json:"replacement_version"`
	ReplacementSum     string `json:"replacement_sum"`
}

type BuildInfo struct {
	Schema                string             `json:"schema"`
	Version               uint64             `json:"version"`
	ToolID                string             `json:"tool_id"`
	ToolRole              string             `json:"tool_role"`
	Implementation        string             `json:"implementation"`
	ExecutableSHA256      string             `json:"executable_sha256"`
	BaselineSource        SourceIdentity     `json:"baseline_source"`
	PriorSource           SourceIdentity     `json:"prior_source"`
	RunnerSource          SourceIdentity     `json:"runner_source"`
	CompileSource         SourceIdentity     `json:"compile_source"`
	FixtureManifestSHA256 string             `json:"fixture_manifest_sha256"`
	InjectedSourceSHA256  string             `json:"injected_source_sha256"`
	MainModule            MainModuleIdentity `json:"main_module"`
	GoModSHA256           string             `json:"go_mod_sha256"`
	GoSumSHA256           string             `json:"go_sum_sha256"`
	ModuleGraphSHA256     string             `json:"module_graph_sha256"`
	Modules               []ModuleIdentity   `json:"modules"`
	Toolchain             ToolchainIdentity  `json:"toolchain"`
	VCSModified           bool               `json:"vcs_modified"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ToolExecution struct {
	Purpose   string `json:"purpose"`
	ToolID    string `json:"tool_id"`
	EventRole string `json:"event_role"`
}

// ProcessEvent is a raw, separately hashed execution record. Case documents
// point to it instead of supplying trusted timeout/exit/drain summaries.
type ProcessEvent struct {
	Schema           string   `json:"schema"`
	Version          uint64   `json:"version"`
	Purpose          string   `json:"purpose"`
	ToolID           string   `json:"tool_id"`
	Argv             []string `json:"argv"`
	Environment      []EnvVar `json:"environment"`
	WorkingDirectory string   `json:"working_directory"`
	InputRoles       []string `json:"input_roles"`
	PID              uint64   `json:"pid"`
	Started          bool     `json:"started"`
	StdinClosed      bool     `json:"stdin_closed"`
	StdoutDrained    bool     `json:"stdout_drained"`
	StderrDrained    bool     `json:"stderr_drained"`
	Waited           bool     `json:"waited"`
	ExitCode         int      `json:"exit_code"`
	Signal           string   `json:"signal"`
	TimedOut         bool     `json:"timed_out"`
	PanicDetected    bool     `json:"panic_detected"`
	StdoutRole       string   `json:"stdout_role"`
	StderrRole       string   `json:"stderr_role"`
}

type CurvePoint struct {
	XHex string `json:"x_hex"`
	YHex string `json:"y_hex"`
}

type CurveDefinition struct {
	Name      string     `json:"name"`
	PrimeHex  string     `json:"prime_hex"`
	OrderHex  string     `json:"order_hex"`
	Generator CurvePoint `json:"generator"`
}

// ProofVector is raw secp256k1 material. It has no decoded or verified booleans;
// the independent verifier parses it and evaluates both equations itself.
type ProofVector struct {
	Schema             string          `json:"schema"`
	Version            uint64          `json:"version"`
	VectorID           string          `json:"vector_id"`
	ProducerToolID     string          `json:"producer_tool_id"`
	Kind               string          `json:"kind"`
	Curve              CurveDefinition `json:"curve"`
	SessionHex         string          `json:"session_hex"`
	CandidateDomainHex string          `json:"candidate_domain_hex"`
	CandidateEquation  string          `json:"candidate_equation"`
	HistoricalEquation string          `json:"historical_equation"`
	Public             CurvePoint      `json:"public"`
	Auxiliary          *CurvePoint     `json:"auxiliary"`
	Alpha              CurvePoint      `json:"alpha"`
	THex               string          `json:"t_hex"`
	UHex               *string         `json:"u_hex"`
}

type ProofEvidence struct {
	VectorRole               string          `json:"vector_role"`
	ProducerToolID           string          `json:"producer_tool_id"`
	HistoricalVerifierToolID string          `json:"historical_verifier_tool_id"`
	CandidateVerifierToolID  string          `json:"candidate_verifier_tool_id"`
	Executions               []ToolExecution `json:"executions"`
}

// ProofToolResult is retained exact-binary output. Accepted is never trusted:
// the verifier compares it with the equation derived from the raw vector.
type ProofToolResult struct {
	Schema       string `json:"schema"`
	Version      uint64 `json:"version"`
	Operation    string `json:"operation"`
	VectorSHA256 string `json:"vector_sha256"`
	Decoded      bool   `json:"decoded"`
	Accepted     bool   `json:"accepted"`
	ToolID       string `json:"tool_id"`
}

type SigningTopology struct {
	Parties              uint64 `json:"parties"`
	Threshold            uint64 `json:"threshold"`
	HistoricalParties    uint64 `json:"historical_parties"`
	NominalLegacyParties uint64 `json:"nominal_legacy_parties"`
}

// SignatureData mirrors the library's raw SignatureData bytes. SignatureHex
// must be exactly RHex||SHex, S must be canonical low-S, and validity is
// derived rather than read from an observation.
type SignatureData struct {
	SignatureHex        string     `json:"signature_hex"`
	RecoveryHex         string     `json:"signature_recovery_hex"`
	RHex                string     `json:"r_hex"`
	SHex                string     `json:"s_hex"`
	MHex                string     `json:"m_hex"`
	RequestedMessageHex string     `json:"requested_message_hex"`
	PublicKey           CurvePoint `json:"public_key"`
}

// TypedRefusal preserves the raw tss.Error fields and binds a round-3 refusal
// to the final received round-2 delivery that triggered the transition.
type TypedRefusal struct {
	Task              string   `json:"task"`
	Round             uint64   `json:"round"`
	Cause             string   `json:"cause"`
	TriggerDeliveryID string   `json:"trigger_delivery_id"`
	Victim            uint64   `json:"victim"`
	Culprits          []uint64 `json:"culprits"`
}

type ProtocolEvent struct {
	Sequence      uint64         `json:"sequence"`
	Direction     string         `json:"direction"`
	DeliveryID    string         `json:"delivery_id"`
	MessageType   string         `json:"message_type"`
	PeerOrdinal   *uint64        `json:"peer_ordinal"`
	PayloadSHA256 string         `json:"payload_sha256"`
	Signature     *SignatureData `json:"signature"`
	Refusal       *TypedRefusal  `json:"refusal"`
}

// WorkerEvent is a raw, separately hashed worker transcript record.
type WorkerEvent struct {
	Schema        string          `json:"schema"`
	Version       uint64          `json:"version"`
	RunID         string          `json:"run_id"`
	Ordinal       uint64          `json:"ordinal"`
	ToolID        string          `json:"tool_id"`
	TerminalState string          `json:"terminal_state"`
	Process       ProcessEvent    `json:"process"`
	Events        []ProtocolEvent `json:"events"`
}

type SigningObservation struct {
	RunID            string          `json:"run_id"`
	Coordinator      ToolExecution   `json:"coordinator"`
	Topology         SigningTopology `json:"topology"`
	WorkerEventRoles []string        `json:"worker_event_roles"`
}

type CaseEvidence struct {
	Schema              string               `json:"schema"`
	Version             uint64               `json:"version"`
	CaseID              string               `json:"case_id"`
	ToolInventorySHA256 string               `json:"tool_inventory_sha256"`
	RunnerExecution     ToolExecution        `json:"runner_execution"`
	Proofs              []ProofEvidence      `json:"proofs"`
	SigningRuns         []SigningObservation `json:"signing_runs"`
}

// CaseOutcome reports only a predicate derived from retained bundle bytes.
// It is not a statement about execution provenance or evidence acceptance.
type CaseOutcome struct {
	CaseID                    string
	DerivedPredicateSatisfied bool
}

// Report separates fail-closed self-consistency from external provenance and
// acceptance decisions. VerifyBundle always leaves the latter two false.
type Report struct {
	DiagnosticOnly              bool
	ReleaseAuthority            bool
	RootGate                    string
	ExecutionProvenanceVerified bool
	EvidenceAccepted            bool
	Cases                       []CaseOutcome
}
