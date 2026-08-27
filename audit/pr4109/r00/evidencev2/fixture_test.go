package evidencev2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const fixtureManifestText = "" +
	"d9de3a0fbd8ae8f11c7d194c71be7d40b3a9581e1b2064f1b5be10ea2c2cef5e  keygen_data_0.json\n" +
	"22c591a6caaf2f5a04c80ca88596dd07358313627898e26c602214b10a043629  keygen_data_1.json\n" +
	"f0aa21f8c623f0b5c6b11c9b3fcb44575c7a63363e3b3a5fedf49cdfb08d280d  keygen_data_2.json\n" +
	"c1e5cf0b018e01158a848e1876868c7fa8d1e78cd2681252c12fe9b7fad8b60f  keygen_data_3.json\n" +
	"063cf0037012af03d7e828ea15b42ca458e7f9c68bb7b280a4f5069a2e848c76  keygen_data_4.json\n" +
	"bf224ff4e349e473f55b231552ce546377706ce890d7e6b753ce2aca82271c07  keygen_data_5.json\n" +
	"7202c32c618598ad068a3ae21953f4248411cecfa73d56496bbb4f00cb6c572d  keygen_data_6.json\n" +
	"e15a9310011d33a22a0ea157f4b0fa28b7358191642bf222496776a493854e26  keygen_data_7.json\n" +
	"fcd080036c2d0c5a634bb892f88a376713a1c07d37545bdc52a85f55f66533ec  keygen_data_8.json\n" +
	"7fdedc15ed24175e30100b655c102cf23eb9f77de24d9a35645454a1dd71da17  keygen_data_9.json\n" +
	"9b6d48b9242f0002d65ce1b6810cac558a50642e542566be7393ba24399bbc37  keygen_data_10.json\n"

type syntheticFixture struct {
	directory string
}

type fixtureBuilder struct {
	t          *testing.T
	directory  string
	references []FileReference
	roles      map[string]struct{}
	nextPID    uint64
	baseline   SourceIdentity
	prior      SourceIdentity
	runner     SourceIdentity
}

func newSyntheticFixture(t *testing.T) *syntheticFixture {
	t.Helper()
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	builder := &fixtureBuilder{
		t:         t,
		directory: staging,
		roles:     make(map[string]struct{}),
		nextPID:   1000,
		baseline: SourceIdentity{
			Repository: "threshold-network/keep-core",
			Commit:     BaselineSourceCommit,
			TreeSHA256: BaselineTreeSHA256,
		},
		prior: SourceIdentity{
			Repository: "threshold-network/keep-core",
			Commit:     PriorSourceCommit,
			TreeSHA256: PriorTreeSHA256,
		},
		runner: SourceIdentity{
			Repository: "threshold-network/keep-core",
			Commit:     "1775696e87d5feca58c22ece23dc63a225440f46",
			TreeSHA256: strings.Repeat("c", 64),
		},
	}
	manifestReference := builder.add(
		"fixture_manifest",
		"identity/keygen-fixtures.sha256",
		"text/plain",
		[]byte(fixtureManifestText),
	)
	if manifestReference.SHA256 != FixtureManifestSHA256 {
		t.Fatalf("fixture manifest digest is %s", manifestReference.SHA256)
	}

	bindings := expectedToolBindings()
	entries := make([]toolDigestEntry, 0, len(bindings))
	for _, binding := range bindings {
		executable := builder.add(
			binding.ExecutableRole,
			"tools/"+binding.ToolID+"/tool.bin",
			"application/octet-stream",
			[]byte("synthetic executable for "+binding.ToolID+"\n"),
		)
		module := moduleForImplementation(binding.Implementation)
		moduleGraphData := []byte(fmt.Sprintf(
			"%s@%s => %s@%s %s\n",
			module.RequestedPath,
			module.RequestedVersion,
			module.ReplacementPath,
			module.ReplacementVersion,
			module.ReplacementSum,
		))
		moduleGraph := builder.add(
			binding.ModuleGraphRole,
			"tools/"+binding.ToolID+"/module-graph.txt",
			"text/plain",
			moduleGraphData,
		)
		sourceAsset := builder.add(
			binding.SourceAssetRole,
			"tools/"+binding.ToolID+"/source-asset.txt",
			"text/plain",
			[]byte("canonical injected source for "+binding.ToolID+"\n"),
		)
		compileSource := builder.runner
		goMod, goSum := hashText("runner go.mod"), hashText("runner go.sum")
		if binding.Implementation == HistoricalImplementation {
			compileSource = builder.prior
			goMod, goSum = PriorGoModSHA256, PriorGoSumSHA256
		} else if binding.Implementation == CandidateImplementation {
			compileSource = builder.baseline
			goMod, goSum = BaselineGoModSHA256, BaselineGoSumSHA256
		}
		buildInfo := BuildInfo{
			Schema:                BuildInfoSchema,
			Version:               2,
			ToolID:                binding.ToolID,
			ToolRole:              binding.Role,
			Implementation:        binding.Implementation,
			ExecutableSHA256:      executable.SHA256,
			BaselineSource:        builder.baseline,
			PriorSource:           builder.prior,
			RunnerSource:          builder.runner,
			CompileSource:         compileSource,
			FixtureManifestSHA256: FixtureManifestSHA256,
			InjectedSourceSHA256:  sourceAsset.SHA256,
			MainModule: MainModuleIdentity{
				Path: "github.com/keep-network/keep-core", Version: "(devel)", Sum: "",
			},
			GoModSHA256:       goMod,
			GoSumSHA256:       goSum,
			ModuleGraphSHA256: moduleGraph.SHA256,
			Modules:           []ModuleIdentity{module},
			Toolchain: ToolchainIdentity{
				GoVersion: "go1.25.10", GOOS: "linux", GOARCH: "amd64",
				CGOEnabled: false, GOTOOLCHAIN: "local", GOWORK: "off", ModuleMode: "readonly",
			},
			VCSModified: false,
		}
		buildReference := builder.addJSON(
			binding.BuildInfoRole,
			"tools/"+binding.ToolID+"/build-info.json",
			buildInfo,
		)
		entries = append(entries, toolDigestEntry{
			Binding:           binding,
			ExecutableSHA256:  executable.SHA256,
			BuildInfoSHA256:   buildReference.SHA256,
			ModuleGraphSHA256: moduleGraph.SHA256,
			SourceAssetSHA256: sourceAsset.SHA256,
			BuildInfo:         buildInfo,
		})
	}
	inventoryDigest, err := digestToolInventory(entries)
	if err != nil {
		t.Fatal(err)
	}

	for _, caseID := range requiredCaseIDs {
		caseRecord := builder.makeCase(caseID, inventoryDigest)
		builder.addJSON(
			"case_"+strings.ToLower(caseID),
			"cases/"+caseID+".json",
			caseRecord,
		)
	}
	root := EvidenceRoot{
		Schema:                BundleSchema,
		Version:               2,
		Repository:            "threshold-network/keep-core",
		PullRequest:           4109,
		BaselineSource:        builder.baseline,
		PriorSource:           builder.prior,
		RunnerSource:          builder.runner,
		FixtureManifestSHA256: FixtureManifestSHA256,
		LegacyV1: LegacyV1Binding{
			ReproductionCatalogSHA256: V1CatalogSHA256,
			FrozenInputsSHA256:        V1FrozenInputsSHA256,
			CatalogStatus:             "blocked",
			CaseCount:                 18,
			BaselineEvidenceStatus:    "not_run",
		},
		Scope:     append([]string(nil), requiredCaseIDs[:]...),
		Authority: Authority{true, false, "blocked"},
		Tools:     bindings,
		Files:     builder.references,
	}
	rootData := marshalJSON(t, root)
	if err := os.WriteFile(filepath.Join(staging, RootFilename), rootData, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootData)
	final := filepath.Join(base, "sha256", hex.EncodeToString(digest[:]))
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staging, final); err != nil {
		t.Fatal(err)
	}
	return &syntheticFixture{directory: final}
}

func (builder *fixtureBuilder) makeCase(caseID, inventoryDigest string) CaseEvidence {
	runner := builder.addExecution(
		"process_runner_"+strings.ToLower(caseID),
		"case_recorder",
		EvidenceRunner,
		[]string{toolArgv0(EvidenceRunner), "record", "--case", caseID},
		[]string{},
	)
	record := CaseEvidence{
		Schema: CaseSchema, Version: 2, CaseID: caseID,
		ToolInventorySHA256: inventoryDigest,
		RunnerExecution:     runner,
		Proofs:              []ProofEvidence{},
		SigningRuns:         []SigningObservation{},
	}
	type proofSpec struct{ id, kind, producer string }
	specs := map[string][]proofSpec{
		"R00-01": {{"r00-01-candidate-zk", "zk", CandidateProofTool}},
		"R00-02": {{"r00-02-historical-zk", "zk", HistoricalProofTool}},
		"R00-03": {
			{"r00-03-historical-zkv", "zkv", HistoricalProofTool},
			{"r00-03-candidate-zkv", "zkv", CandidateProofTool},
		},
	}
	for index, spec := range specs[caseID] {
		vector := makeProofVector(builder.t, spec.id, spec.kind, spec.producer, int64(11+index*7))
		vectorRole := "vector_" + spec.id
		vectorReference := builder.addJSON(vectorRole, "vectors/"+spec.id+".json", vector)
		historical, candidate, err := evaluateProofEquations(&vector)
		if err != nil {
			builder.t.Fatal(err)
		}
		producerAccepted := candidate
		if spec.producer == HistoricalProofTool {
			producerAccepted = historical
		}
		proofOutput := func(operation, toolID string, accepted bool) []byte {
			return marshalJSON(builder.t, ProofToolResult{
				Schema: ProofToolResultSchema, Version: 2, Operation: operation,
				VectorSHA256: vectorReference.SHA256, Decoded: true,
				Accepted: accepted, ToolID: toolID,
			})
		}
		record.Proofs = append(record.Proofs, ProofEvidence{
			VectorRole: vectorRole, ProducerToolID: spec.producer,
			HistoricalVerifierToolID: HistoricalProofTool,
			CandidateVerifierToolID:  CandidateProofTool,
			Executions: []ToolExecution{
				builder.addExecutionOutput(
					"process_"+spec.id+"_produce", "produce", spec.producer,
					[]string{toolArgv0(spec.producer), "generate", "--kind", spec.kind, "--output-role", vectorRole},
					[]string{},
					proofOutput("produce", spec.producer, producerAccepted),
				),
				builder.addExecutionOutput(
					"process_"+spec.id+"_historical", "historical_verify", HistoricalProofTool,
					[]string{toolArgv0(HistoricalProofTool), "verify", "--vector-role", vectorRole},
					[]string{vectorRole},
					proofOutput("verify", HistoricalProofTool, historical),
				),
				builder.addExecutionOutput(
					"process_"+spec.id+"_candidate", "candidate_verify", CandidateProofTool,
					[]string{toolArgv0(CandidateProofTool), "verify", "--vector-role", vectorRole},
					[]string{vectorRole},
					proofOutput("verify", CandidateProofTool, candidate),
				),
			},
		})
	}
	if caseID == "R00-03" {
		record.SigningRuns = []SigningObservation{
			builder.makeSigningRun("signing-historical-homogeneous", 11, false),
			builder.makeSigningRun("signing-candidate-homogeneous", 0, false),
			builder.makeSigningRun("signing-mixed-5-historical-6-candidate", 5, true),
		}
	}
	return record
}

func (builder *fixtureBuilder) makeSigningRun(
	runID string,
	historicalParties uint64,
	mixed bool,
) SigningObservation {
	topology := SigningTopology{11, 10, historicalParties, 11 - historicalParties}
	coordinatorInputs := sortedRoles([]string{
		"tool_historical-worker_binary", "tool_candidate-worker_binary", "fixture_manifest",
	})
	coordinator := builder.addExecution(
		"process_"+runID+"_coordinator", "coordinate", MixedCoordinator,
		[]string{
			toolArgv0(MixedCoordinator), "coordinate", "--run", runID,
			"--parties", "11", "--threshold", "10", "--historical",
			strconv.FormatUint(historicalParties, 10),
		},
		coordinatorInputs,
	)

	events := make([][]ProtocolEvent, 11)
	prefix := strings.ReplaceAll(runID, "signing-", "")
	if mixed {
		for typeIndex, messageType := range mixedRequiredMessageTypes {
			for from := uint64(0); from < 11; from++ {
				for to := uint64(0); to < 11; to++ {
					if from == to {
						continue
					}
					id := fmt.Sprintf(
						"d_%s_%d_%02d_%02d",
						strings.ReplaceAll(prefix, "-", "_"), typeIndex, from, to,
					)
					payloadSeed := id
					if messageType == mixedRequiredMessageTypes[1] {
						payloadSeed = fmt.Sprintf("broadcast_%s_%02d", prefix, from)
					}
					appendFixtureDelivery(events, from, to, id, messageType, payloadSeed)
				}
			}
		}
	} else {
		for delivery := 0; delivery < 1100; delivery++ {
			from := uint64(delivery % 11)
			to := (from + 1 + uint64((delivery/11)%10)) % 11
			id := fmt.Sprintf("d_%s_%04d", strings.ReplaceAll(prefix, "-", "_"), delivery)
			appendFixtureDelivery(events, from, to, id, "round_message", id)
		}
	}

	var commonSignature *SignatureData
	if !mixed {
		implementation := CandidateImplementation
		if historicalParties == 11 {
			implementation = HistoricalImplementation
		}
		signature := makeFixtureSignature(builder.t, implementation)
		commonSignature = &signature
	}
	roles := make([]string, 0, 11)
	for ordinal := 0; ordinal < 11; ordinal++ {
		terminalState := "completed"
		if mixed {
			if ordinal == 7 {
				terminalState = "rejected"
				triggerDeliveryID := ""
				for index := len(events[ordinal]) - 1; index >= 0; index-- {
					if events[ordinal][index].Direction == "received" &&
						events[ordinal][index].MessageType == mixedRequiredMessageTypes[2] {
						triggerDeliveryID = events[ordinal][index].DeliveryID
						break
					}
				}
				if triggerDeliveryID == "" {
					builder.t.Fatal("mixed fixture has no round-2 trigger delivery")
				}
				refusal := &TypedRefusal{
					Task: "signing", Round: 3,
					Cause:             "failed to calculate Alice_end or Alice_end_wc",
					TriggerDeliveryID: triggerDeliveryID,
					Victim:            7,
					Culprits:          []uint64{4, 0, 0, 3, 4, 3, 1, 2, 1, 2},
				}
				events[ordinal] = append(events[ordinal], ProtocolEvent{
					Direction: "refusal", DeliveryID: "", MessageType: "tss_error",
					PayloadSHA256: hashJSON(*refusal), Refusal: refusal,
				})
			} else {
				terminalState = "quiesced_no_result"
				events[ordinal] = append(events[ordinal], ProtocolEvent{
					Direction: "quiesced", DeliveryID: "", MessageType: "no_result",
					PayloadSHA256: hashJSON(struct {
						State string `json:"state"`
					}{"quiesced_no_result"}),
				})
			}
		} else {
			signature := *commonSignature
			events[ordinal] = append(events[ordinal], ProtocolEvent{
				Direction: "signature", DeliveryID: "", MessageType: "signature_data",
				PayloadSHA256: hashJSON(signature), Signature: &signature,
			})
		}
		events[ordinal] = append(events[ordinal], ProtocolEvent{
			Direction: "stopped", DeliveryID: "", MessageType: "eof_after_terminal",
			PayloadSHA256: hashJSON(struct {
				Waited  bool `json:"waited"`
				Drained bool `json:"drained"`
			}{true, true}),
		})
		for index := range events[ordinal] {
			events[ordinal][index].Sequence = uint64(index)
		}
		stdout := encodeJSONL(builder.t, events[ordinal])
		toolID := CandidateWorker
		if uint64(ordinal) < historicalParties {
			toolID = HistoricalWorker
		}
		workerRole := fmt.Sprintf("worker_%s_%02d", strings.ReplaceAll(prefix, "-", "_"), ordinal)
		process := builder.makeProcess(
			workerRole,
			"signing_worker",
			toolID,
			[]string{toolArgv0(toolID), "serve", "--run", runID, "--ordinal", strconv.Itoa(ordinal)},
			[]string{"fixture_manifest"},
			stdout,
		)
		worker := WorkerEvent{
			Schema: WorkerEventSchema, Version: 2, RunID: runID,
			Ordinal: uint64(ordinal), ToolID: toolID, TerminalState: terminalState,
			Process: process, Events: events[ordinal],
		}
		builder.addJSON(workerRole, "workers/"+workerRole+".json", worker)
		roles = append(roles, workerRole)
	}
	return SigningObservation{
		RunID: runID, Coordinator: coordinator, Topology: topology,
		WorkerEventRoles: roles,
	}
}

func appendFixtureDelivery(
	events [][]ProtocolEvent,
	from, to uint64,
	id, messageType, payloadSeed string,
) {
	payload := hashText(payloadSeed)
	fromCopy, toCopy := from, to
	events[from] = append(events[from], ProtocolEvent{
		Direction: "emitted", DeliveryID: id, MessageType: messageType,
		PeerOrdinal: &toCopy, PayloadSHA256: payload,
	})
	events[to] = append(events[to], ProtocolEvent{
		Direction: "received", DeliveryID: id, MessageType: messageType,
		PeerOrdinal: &fromCopy, PayloadSHA256: payload,
	})
}

func (builder *fixtureBuilder) addExecution(
	role, purpose, toolID string,
	argv, inputs []string,
) ToolExecution {
	return builder.addExecutionOutput(
		role, purpose, toolID, argv, inputs, []byte("completed\n"),
	)
}

func (builder *fixtureBuilder) addExecutionOutput(
	role, purpose, toolID string,
	argv, inputs []string,
	stdout []byte,
) ToolExecution {
	process := builder.makeProcess(role, purpose, toolID, argv, inputs, stdout)
	builder.addJSON(role, "events/"+role+".json", process)
	return ToolExecution{Purpose: purpose, ToolID: toolID, EventRole: role}
}

func (builder *fixtureBuilder) makeProcess(
	role, purpose, toolID string,
	argv, inputs []string,
	stdout []byte,
) ProcessEvent {
	stdoutRole, stderrRole := role+"_stdout", role+"_stderr"
	builder.add(stdoutRole, "logs/"+role+".stdout.log", "text/plain", stdout)
	builder.add(stderrRole, "logs/"+role+".stderr.log", "text/plain", []byte{})
	process := ProcessEvent{
		Schema: ProcessEventSchema, Version: 2, Purpose: purpose, ToolID: toolID,
		Argv: argv, Environment: append([]EnvVar(nil), exactExecutionEnvironment...),
		WorkingDirectory: "workspace", InputRoles: inputs,
		PID: builder.nextPID, Started: true, StdinClosed: true,
		StdoutDrained: true, StderrDrained: true, Waited: true,
		ExitCode: 0, Signal: "", TimedOut: false, PanicDetected: false,
		StdoutRole: stdoutRole, StderrRole: stderrRole,
	}
	builder.nextPID++
	return process
}

func (builder *fixtureBuilder) addJSON(role, path string, value any) FileReference {
	return builder.add(role, path, "application/json", marshalJSON(builder.t, value))
}

func (builder *fixtureBuilder) add(
	role, relativePath, mediaType string,
	data []byte,
) FileReference {
	builder.t.Helper()
	if _, duplicate := builder.roles[role]; duplicate {
		builder.t.Fatalf("duplicate fixture role %s", role)
	}
	builder.roles[role] = struct{}{}
	fullPath := filepath.Join(builder.directory, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		builder.t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		builder.t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	reference := FileReference{
		Path: relativePath, Role: role, MediaType: mediaType,
		SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(data)),
	}
	builder.references = append(builder.references, reference)
	return reference
}

func moduleForImplementation(implementation string) ModuleIdentity {
	version, sum := CandidateTSSVersion, CandidateTSSSum
	if implementation == HistoricalImplementation {
		version, sum = HistoricalTSSVersion, HistoricalTSSSum
	}
	return ModuleIdentity{
		RequestedPath: "github.com/bnb-chain/tss-lib", RequestedVersion: "v1.3.5",
		RequestedSum: "", ReplacementPath: "github.com/threshold-network/tss-lib",
		ReplacementVersion: version, ReplacementSum: sum,
	}
}

func makeProofVector(
	t *testing.T,
	id, kind, producer string,
	nonce int64,
) ProofVector {
	t.Helper()
	curve := btcec.S256()
	order := curve.Params().N
	vector := ProofVector{
		Schema: ProofVectorSchema, Version: 2, VectorID: id,
		ProducerToolID: producer, Kind: kind,
		Curve: CurveDefinition{
			Name: "secp256k1", PrimeHex: secp256k1Prime, OrderHex: secp256k1Order,
			Generator: CurvePoint{secp256k1GX, secp256k1GY},
		},
		SessionHex:         "0x",
		CandidateEquation:  "sha512_256i_tagged_mod_n/v1",
		HistoricalEquation: "hash_to_n_sha512_256_3block/v1",
	}
	a := big.NewInt(nonce)
	alphaX, alphaY := curve.ScalarBaseMult(a.Bytes())
	vector.Alpha = encodePoint(alphaX, alphaY)
	var inputs []*big.Int
	if kind == "zk" {
		x := big.NewInt(7)
		publicX, publicY := curve.ScalarBaseMult(x.Bytes())
		vector.Public = encodePoint(publicX, publicY)
		vector.CandidateDomainHex = hexBytes([]byte("tss-lib.threshold.schnorr.zk|"))
		inputs = []*big.Int{publicX, publicY, curve.Params().Gx, curve.Params().Gy, alphaX, alphaY}
		challenge := challengeForProducer(producer, vector.CandidateDomainHex, order, inputs)
		response := new(big.Int).Add(a, new(big.Int).Mul(challenge, x))
		response.Mod(response, order)
		vector.THex = fixedHex(response)
		vector.Auxiliary = nil
		vector.UHex = nil
	} else {
		r, s, l, b := big.NewInt(3), big.NewInt(5), big.NewInt(7), big.NewInt(nonce+2)
		rX, rY := curve.ScalarBaseMult(r.Bytes())
		publicScalar := new(big.Int).Add(new(big.Int).Mul(s, r), l)
		publicX, publicY := curve.ScalarBaseMult(publicScalar.Bytes())
		alphaScalar := new(big.Int).Add(new(big.Int).Mul(a, r), b)
		alphaX, alphaY = curve.ScalarBaseMult(alphaScalar.Bytes())
		vector.Alpha = encodePoint(alphaX, alphaY)
		auxiliary := encodePoint(rX, rY)
		vector.Auxiliary = &auxiliary
		vector.Public = encodePoint(publicX, publicY)
		vector.CandidateDomainHex = hexBytes([]byte("tss-lib.threshold.schnorr.zkv|"))
		inputs = []*big.Int{
			publicX, publicY, rX, rY, curve.Params().Gx, curve.Params().Gy, alphaX, alphaY,
		}
		challenge := challengeForProducer(producer, vector.CandidateDomainHex, order, inputs)
		tResponse := new(big.Int).Add(a, new(big.Int).Mul(challenge, s))
		tResponse.Mod(tResponse, order)
		uResponse := new(big.Int).Add(b, new(big.Int).Mul(challenge, l))
		uResponse.Mod(uResponse, order)
		vector.THex = fixedHex(tResponse)
		uHex := fixedHex(uResponse)
		vector.UHex = &uHex
	}
	if err := verifyProofVector(&vector, producer); err != nil {
		t.Fatalf("synthetic proof vector %s is invalid: %v", id, err)
	}
	return vector
}

func challengeForProducer(
	producer, domain string,
	order *big.Int,
	inputs []*big.Int,
) *big.Int {
	if producer == HistoricalProofTool {
		return historicalHashToN(order, inputs...)
	}
	tag, _ := parseHexBytes(domain)
	return candidateTaggedChallenge(order, tag, inputs...)
}

func makeFixtureSignature(t *testing.T, implementation string) SignatureData {
	t.Helper()
	secret, _ := new(big.Int).SetString(
		"9eff9a23589e483cc761a244aa13847c03c270721a2b8e88e4343cca35928d89",
		16,
	)
	curve := btcec.S256()
	publicX, publicY := curve.ScalarBaseMult(secret.Bytes())
	if fixedHex(publicX) != FixturePublicKeyX || fixedHex(publicY) != FixturePublicKeyY {
		t.Fatal("reconstructed public fixture key drift")
	}
	m := []byte{42}
	mHex := "0x2a"
	if implementation != HistoricalImplementation {
		m = make([]byte, 32)
		m[31] = 42
		mHex = FixtureMessageHex
	}
	private := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: publicX, Y: publicY},
		D:         secret,
	}
	r, s, err := ecdsa.Sign(rand.Reader, private, m)
	if err != nil {
		t.Fatal(err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(curve.Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curve.Params().N, s)
	}
	recovery := byte(255)
	for candidate := byte(0); candidate < 4; candidate++ {
		compact := make([]byte, 65)
		compact[0] = 27 + candidate + 4
		r.FillBytes(compact[1:33])
		s.FillBytes(compact[33:65])
		recovered, _, err := btcecdsa.RecoverCompact(compact, m)
		if err == nil && recovered.X().Cmp(publicX) == 0 && recovered.Y().Cmp(publicY) == 0 {
			recovery = candidate
			break
		}
	}
	if recovery == 255 {
		t.Fatal("could not derive signature recovery byte")
	}
	rHex, sHex := fixedHex(r), fixedHex(s)
	result := SignatureData{
		SignatureHex: "0x" + rHex[2:] + sHex[2:],
		RecoveryHex:  fmt.Sprintf("0x%02x", recovery),
		RHex:         rHex, SHex: sHex, MHex: mHex,
		RequestedMessageHex: FixtureMessageHex,
		PublicKey:           CurvePoint{FixturePublicKeyX, FixturePublicKeyY},
	}
	if err := verifySignature(&result, implementation); err != nil {
		t.Fatalf("synthetic signature is invalid: %v", err)
	}
	return result
}

func encodePoint(x, y *big.Int) CurvePoint {
	return CurvePoint{XHex: fixedHex(x), YHex: fixedHex(y)}
}

func fixedHex(value *big.Int) string {
	return fmt.Sprintf("0x%064x", value)
}

func encodeJSONL(t *testing.T, events []ProtocolEvent) []byte {
	t.Helper()
	var result []byte
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, data...)
		result = append(result, '\n')
	}
	return result
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func hashText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
