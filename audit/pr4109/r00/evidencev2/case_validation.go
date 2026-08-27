package evidencev2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/keep-network/keep-core/audit/pr4109/internal/strictjson"
)

var exactExecutionEnvironment = []EnvVar{
	{Name: "CGO_ENABLED", Value: "0"},
	{Name: "GOARCH", Value: "amd64"},
	{Name: "GOENV", Value: "off"},
	{Name: "GOFLAGS", Value: "-mod=readonly"},
	{Name: "GOOS", Value: "linux"},
	{Name: "GOPROXY", Value: "off"},
	{Name: "GOSUMDB", Value: "off"},
	{Name: "GOTOOLCHAIN", Value: "local"},
	{Name: "GOWORK", Value: "off"},
}

var mixedRequiredMessageTypes = [...]string{
	"binance.tsslib.ecdsa.signing.SignRound1Message1",
	"binance.tsslib.ecdsa.signing.SignRound1Message2",
	"binance.tsslib.ecdsa.signing.SignRound2Message",
}

func validateCaseEvidence(
	evidence *CaseEvidence,
	bindings map[string]ToolBinding,
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
) error {
	if evidence.Schema != CaseSchema || evidence.Version != 2 {
		return errors.New("unsupported case schema")
	}
	if !sha256Pattern.MatchString(evidence.ToolInventorySHA256) {
		return errors.New("noncanonical tool-inventory digest")
	}
	runnerArgv := []string{
		toolArgv0(EvidenceRunner), "record", "--case", evidence.CaseID,
	}
	if _, err := validateToolExecution(
		evidence.RunnerExecution,
		"case_recorder",
		EvidenceRunner,
		runnerArgv,
		[]string{},
		bindings,
		artifacts,
		consumed,
	); err != nil {
		return fmt.Errorf("runner execution: %w", err)
	}

	expectedProofs := map[string][]struct {
		vectorID string
		kind     string
		producer string
	}{
		"R00-01": {{"r00-01-candidate-zk", "zk", CandidateProofTool}},
		"R00-02": {{"r00-02-historical-zk", "zk", HistoricalProofTool}},
		"R00-03": {
			{"r00-03-historical-zkv", "zkv", HistoricalProofTool},
			{"r00-03-candidate-zkv", "zkv", CandidateProofTool},
		},
	}
	wantProofs, present := expectedProofs[evidence.CaseID]
	if !present {
		return fmt.Errorf("unsupported case ID %q", evidence.CaseID)
	}
	if len(evidence.Proofs) != len(wantProofs) {
		return fmt.Errorf("got %d proof vectors, want %d", len(evidence.Proofs), len(wantProofs))
	}
	for index, expected := range wantProofs {
		if err := validateProofEvidence(
			evidence.Proofs[index],
			expected.vectorID,
			expected.kind,
			expected.producer,
			bindings,
			artifacts,
			consumed,
		); err != nil {
			return fmt.Errorf("proof %s: %w", expected.vectorID, err)
		}
	}

	if evidence.CaseID != "R00-03" {
		if len(evidence.SigningRuns) != 0 {
			return errors.New("unexpected signing runs outside R00-03")
		}
		return nil
	}
	return validateSigningRuns(evidence.SigningRuns, bindings, artifacts, consumed)
}

func validateProofEvidence(
	evidence ProofEvidence,
	wantVectorID string,
	wantKind string,
	wantProducer string,
	bindings map[string]ToolBinding,
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
) error {
	if evidence.VectorRole != "vector_"+wantVectorID ||
		evidence.ProducerToolID != wantProducer ||
		evidence.HistoricalVerifierToolID != HistoricalProofTool ||
		evidence.CandidateVerifierToolID != CandidateProofTool {
		return errors.New("direction or tool identity drift")
	}
	vectorArtifact, err := consumeArtifact(
		artifacts,
		consumed,
		evidence.VectorRole,
		"application/json",
	)
	if err != nil {
		return err
	}
	if vectorArtifact.reference.Path != "vectors/"+wantVectorID+".json" {
		return errors.New("vector path drift")
	}
	var vector ProofVector
	if err := strictjson.Decode(vectorArtifact.data, &vector); err != nil {
		return fmt.Errorf("strict vector JSON: %w", err)
	}
	if vector.VectorID != wantVectorID || vector.Kind != wantKind {
		return errors.New("vector identity or kind drift")
	}
	if len(evidence.Executions) != 3 {
		return fmt.Errorf("got %d proof executions, want 3", len(evidence.Executions))
	}
	expectedExecutions := []struct {
		purpose string
		toolID  string
		argv    []string
		inputs  []string
	}{
		{
			"produce", wantProducer,
			[]string{toolArgv0(wantProducer), "generate", "--kind", wantKind, "--output-role", evidence.VectorRole},
			[]string{},
		},
		{
			"historical_verify", HistoricalProofTool,
			[]string{toolArgv0(HistoricalProofTool), "verify", "--vector-role", evidence.VectorRole},
			[]string{evidence.VectorRole},
		},
		{
			"candidate_verify", CandidateProofTool,
			[]string{toolArgv0(CandidateProofTool), "verify", "--vector-role", evidence.VectorRole},
			[]string{evidence.VectorRole},
		},
	}
	processes := make([]*ProcessEvent, 0, len(expectedExecutions))
	for index, want := range expectedExecutions {
		process, err := validateToolExecution(
			evidence.Executions[index],
			want.purpose,
			want.toolID,
			want.argv,
			want.inputs,
			bindings,
			artifacts,
			consumed,
		)
		if err != nil {
			return err
		}
		processes = append(processes, process)
	}
	if err := verifyProofVector(&vector, wantProducer); err != nil {
		return err
	}
	historical, candidate, err := evaluateProofEquations(&vector)
	if err != nil {
		return err
	}
	producerAccepted := candidate
	if wantProducer == HistoricalProofTool {
		producerAccepted = historical
	}
	wantResults := []struct {
		operation string
		accepted  bool
		toolID    string
	}{
		{"produce", producerAccepted, wantProducer},
		{"verify", historical, HistoricalProofTool},
		{"verify", candidate, CandidateProofTool},
	}
	for index, want := range wantResults {
		if err := validateProofToolResult(
			artifacts[processes[index].StdoutRole].data,
			want.operation,
			want.accepted,
			want.toolID,
			vectorArtifact.reference.SHA256,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateProofToolResult(
	stdout []byte,
	wantOperation string,
	wantAccepted bool,
	wantToolID string,
	wantVectorSHA256 string,
) error {
	var result ProofToolResult
	if err := strictjson.Decode(stdout, &result); err != nil {
		return fmt.Errorf("proof tool stdout: strict JSON: %w", err)
	}
	if result.Schema != ProofToolResultSchema || result.Version != 2 ||
		result.Operation != wantOperation || result.ToolID != wantToolID ||
		result.VectorSHA256 != wantVectorSHA256 || !result.Decoded ||
		result.Accepted != wantAccepted {
		return errors.New("proof tool output disagrees with independently derived vector result")
	}
	return nil
}

func validateToolExecution(
	execution ToolExecution,
	wantPurpose string,
	wantToolID string,
	wantArgv []string,
	wantInputs []string,
	bindings map[string]ToolBinding,
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
) (*ProcessEvent, error) {
	if execution.Purpose != wantPurpose || execution.ToolID != wantToolID {
		return nil, errors.New("execution purpose or tool identity drift")
	}
	if _, present := bindings[wantToolID]; !present {
		return nil, fmt.Errorf("unknown tool %q", wantToolID)
	}
	artifact, err := consumeArtifact(
		artifacts,
		consumed,
		execution.EventRole,
		"application/json",
	)
	if err != nil {
		return nil, err
	}
	if artifact.reference.Path != "events/"+execution.EventRole+".json" {
		return nil, errors.New("process-event path drift")
	}
	var process ProcessEvent
	if err := strictjson.Decode(artifact.data, &process); err != nil {
		return nil, fmt.Errorf("strict process-event JSON: %w", err)
	}
	if process.Purpose != wantPurpose || process.ToolID != wantToolID {
		return nil, errors.New("raw process event disagrees with execution reference")
	}
	if err := validateProcessEvent(
		&process,
		wantArgv,
		wantInputs,
		artifacts,
		consumed,
	); err != nil {
		return nil, err
	}
	return &process, nil
}

func validateProcessEvent(
	process *ProcessEvent,
	wantArgv []string,
	wantInputs []string,
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
) error {
	if process.Schema != ProcessEventSchema || process.Version != 2 {
		return errors.New("unsupported process-event schema")
	}
	if !slices.Equal(process.Argv, wantArgv) {
		return fmt.Errorf("argv is %v, want %v", process.Argv, wantArgv)
	}
	if !slices.Equal(process.Environment, exactExecutionEnvironment) {
		return errors.New("effective environment identity drift or unsorted environment")
	}
	if process.WorkingDirectory != "workspace" ||
		!slices.Equal(process.InputRoles, wantInputs) {
		return errors.New("working directory or input-role identity drift")
	}
	for _, role := range process.InputRoles {
		if _, present := artifacts[role]; !present {
			return fmt.Errorf("unknown input role %q", role)
		}
	}
	if process.PID == 0 || !process.Started || !process.StdinClosed ||
		!process.StdoutDrained || !process.StderrDrained || !process.Waited ||
		process.ExitCode != 0 || process.Signal != "" || process.TimedOut ||
		process.PanicDetected {
		return errors.New("process did not start, drain, and exit cleanly")
	}
	stdout, err := consumeArtifact(
		artifacts,
		consumed,
		process.StdoutRole,
		"text/plain",
	)
	if err != nil {
		return fmt.Errorf("stdout: %w", err)
	}
	stderr, err := consumeArtifact(
		artifacts,
		consumed,
		process.StderrRole,
		"text/plain",
	)
	if err != nil {
		return fmt.Errorf("stderr: %w", err)
	}
	if !utf8.Valid(stdout.data) || !utf8.Valid(stderr.data) {
		return errors.New("process log is not valid UTF-8")
	}
	combined := strings.ToLower(string(stdout.data) + "\n" + string(stderr.data))
	for _, marker := range []string{"panic:", "fatal error:", "deadline exceeded", "timed out"} {
		if strings.Contains(combined, marker) {
			return fmt.Errorf("process logs contain forbidden marker %q", marker)
		}
	}
	return nil
}

func validateSigningRuns(
	runs []SigningObservation,
	bindings map[string]ToolBinding,
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
) error {
	type expectedRun struct {
		topology SigningTopology
		mixed    bool
	}
	expected := map[string]expectedRun{
		"signing-historical-homogeneous":         {SigningTopology{11, 10, 11, 0}, false},
		"signing-candidate-homogeneous":          {SigningTopology{11, 10, 0, 11}, false},
		"signing-mixed-5-historical-6-candidate": {SigningTopology{11, 10, 5, 6}, true},
	}
	if len(runs) != 3 {
		return fmt.Errorf("got %d signing runs, want 3", len(runs))
	}
	seen := make(map[string]struct{}, 3)
	for _, run := range runs {
		want, present := expected[run.RunID]
		if !present {
			return fmt.Errorf("unexpected signing run %q", run.RunID)
		}
		if _, duplicate := seen[run.RunID]; duplicate {
			return fmt.Errorf("duplicate signing run %q", run.RunID)
		}
		seen[run.RunID] = struct{}{}
		if run.Topology != want.topology {
			return fmt.Errorf("signing run %q topology drift", run.RunID)
		}
		coordinatorArgv := []string{
			toolArgv0(MixedCoordinator), "coordinate", "--run", run.RunID,
			"--parties", "11", "--threshold", "10", "--historical",
			strconv.FormatUint(run.Topology.HistoricalParties, 10),
		}
		coordinator, err := validateToolExecution(
			run.Coordinator,
			"coordinate",
			MixedCoordinator,
			coordinatorArgv,
			sortedRoles([]string{
				"tool_historical-worker_binary",
				"tool_candidate-worker_binary",
				"fixture_manifest",
			}),
			bindings,
			artifacts,
			consumed,
		)
		if err != nil {
			return fmt.Errorf("signing run %q coordinator: %w", run.RunID, err)
		}
		if err := validateWorkerEvents(
			run,
			want.mixed,
			coordinator.PID,
			artifacts,
			consumed,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkerEvents(
	run SigningObservation,
	mixed bool,
	coordinatorPID uint64,
	artifacts map[string]verifiedArtifact,
	consumed map[string]struct{},
) error {
	if len(run.WorkerEventRoles) != 11 {
		return fmt.Errorf("signing run %q has %d workers, want 11", run.RunID, len(run.WorkerEventRoles))
	}
	pids := map[uint64]struct{}{coordinatorPID: {}}
	ordinals := make(map[uint64]struct{}, 11)
	totalReceived, totalSignatures, refusals := 0, 0, 0
	allEmitted := make(map[string]deliveryRecord)
	allReceived := make(map[string]deliveryRecord)
	commonSignature := ""
	for index, role := range run.WorkerEventRoles {
		artifact, err := consumeArtifact(artifacts, consumed, role, "application/json")
		if err != nil {
			return fmt.Errorf("signing run %q worker %d: %w", run.RunID, index, err)
		}
		if artifact.reference.Path != "workers/"+role+".json" {
			return fmt.Errorf("signing run %q worker path drift", run.RunID)
		}
		var worker WorkerEvent
		if err := strictjson.Decode(artifact.data, &worker); err != nil {
			return fmt.Errorf("signing run %q worker: strict JSON: %w", run.RunID, err)
		}
		if worker.Schema != WorkerEventSchema || worker.Version != 2 ||
			worker.RunID != run.RunID || worker.Ordinal != uint64(index) {
			return fmt.Errorf("signing run %q worker identity drift", run.RunID)
		}
		if _, duplicate := ordinals[worker.Ordinal]; duplicate {
			return fmt.Errorf("signing run %q duplicates worker ordinal", run.RunID)
		}
		ordinals[worker.Ordinal] = struct{}{}
		wantTool := CandidateWorker
		if worker.Ordinal < run.Topology.HistoricalParties {
			wantTool = HistoricalWorker
		}
		if worker.ToolID != wantTool || worker.Process.ToolID != wantTool ||
			worker.Process.Purpose != "signing_worker" {
			return fmt.Errorf("signing run %q worker tool placement drift", run.RunID)
		}
		workerArgv := []string{
			toolArgv0(wantTool), "serve", "--run", run.RunID,
			"--ordinal", strconv.Itoa(index),
		}
		if err := validateProcessEvent(
			&worker.Process,
			workerArgv,
			[]string{"fixture_manifest"},
			artifacts,
			consumed,
		); err != nil {
			return fmt.Errorf("signing run %q worker %d process: %w", run.RunID, index, err)
		}
		if _, duplicate := pids[worker.Process.PID]; duplicate {
			return fmt.Errorf("signing run %q reuses a process PID", run.RunID)
		}
		pids[worker.Process.PID] = struct{}{}
		protocol, err := validateProtocolEvents(
			&worker,
			artifacts[worker.Process.StdoutRole].data,
		)
		if err != nil {
			return fmt.Errorf("signing run %q worker %d: %w", run.RunID, index, err)
		}
		if err := mergeDeliveries(allEmitted, protocol.emitted); err != nil {
			return fmt.Errorf("signing run %q emitted ledger: %w", run.RunID, err)
		}
		if err := mergeDeliveries(allReceived, protocol.received); err != nil {
			return fmt.Errorf("signing run %q received ledger: %w", run.RunID, err)
		}
		totalReceived += len(protocol.received)
		if protocol.signature != nil {
			totalSignatures++
		}
		if protocol.refusal != nil {
			refusals++
		}
		if !mixed {
			if worker.TerminalState != "completed" || protocol.signature == nil ||
				protocol.refusal != nil || protocol.terminal != "signature" {
				return fmt.Errorf("signing run %q has invalid homogeneous terminal result", run.RunID)
			}
			implementation := CandidateImplementation
			if wantTool == HistoricalWorker {
				implementation = HistoricalImplementation
			}
			if err := verifySignature(protocol.signature, implementation); err != nil {
				return fmt.Errorf("signing run %q worker signature: %w", run.RunID, err)
			}
			digest := signatureDigest(*protocol.signature)
			if commonSignature == "" {
				commonSignature = digest
			} else if commonSignature != digest {
				return fmt.Errorf("signing run %q has mismatched homogeneous signatures", run.RunID)
			}
		} else if err := validateMixedWorker(
			&worker,
			protocol.signature,
			protocol.refusal,
			protocol.terminal,
		); err != nil {
			return fmt.Errorf("signing run %q worker %d: %w", run.RunID, index, err)
		}
	}
	if !reflect.DeepEqual(allEmitted, allReceived) {
		return fmt.Errorf("signing run %q has unmatched or unacknowledged deliveries", run.RunID)
	}
	if !mixed && totalReceived != 1100 {
		return fmt.Errorf("signing run %q has invalid retained delivery count %d", run.RunID, totalReceived)
	}
	if mixed {
		if err := validateMixedDeliveryProgression(allReceived); err != nil {
			return fmt.Errorf("signing run %q: %w", run.RunID, err)
		}
		if totalSignatures != 0 || refusals < 1 {
			return fmt.Errorf("signing run %q must have zero signatures and at least one typed refusal", run.RunID)
		}
	} else if totalSignatures != 11 || refusals != 0 {
		return fmt.Errorf("signing run %q must have 11 signatures and no refusals", run.RunID)
	}
	return nil
}

func validateMixedDeliveryProgression(deliveries map[string]deliveryRecord) error {
	const parties = 11
	wantCount := len(mixedRequiredMessageTypes) * parties * (parties - 1)
	if len(deliveries) != wantCount {
		return fmt.Errorf(
			"mixed delivery progression has %d deliveries, want %d",
			len(deliveries),
			wantCount,
		)
	}

	allowed := make(map[string]struct{}, len(mixedRequiredMessageTypes))
	for _, messageType := range mixedRequiredMessageTypes {
		allowed[messageType] = struct{}{}
	}
	type progressionCell struct {
		messageType string
		from        uint64
		to          uint64
	}
	seen := make(map[progressionCell]struct{}, wantCount)
	round1Message2Broadcasts := make(map[uint64]string, parties)
	for _, delivery := range deliveries {
		if _, present := allowed[delivery.MessageType]; !present {
			return fmt.Errorf("mixed delivery progression contains unknown type %q", delivery.MessageType)
		}
		cell := progressionCell{delivery.MessageType, delivery.From, delivery.To}
		if _, duplicate := seen[cell]; duplicate {
			return fmt.Errorf(
				"mixed delivery progression duplicates type/pair %q %d->%d",
				delivery.MessageType,
				delivery.From,
				delivery.To,
			)
		}
		seen[cell] = struct{}{}
		if delivery.MessageType == mixedRequiredMessageTypes[1] {
			if payloadHash, present := round1Message2Broadcasts[delivery.From]; present &&
				payloadHash != delivery.PayloadHash {
				return fmt.Errorf(
					"round-1 message-2 broadcast sender %d has divergent payload hashes",
					delivery.From,
				)
			}
			round1Message2Broadcasts[delivery.From] = delivery.PayloadHash
		}
	}
	for _, messageType := range mixedRequiredMessageTypes {
		for from := uint64(0); from < parties; from++ {
			for to := uint64(0); to < parties; to++ {
				if from == to {
					continue
				}
				cell := progressionCell{messageType, from, to}
				if _, present := seen[cell]; !present {
					return fmt.Errorf(
						"mixed delivery progression is missing type/pair %q %d->%d",
						messageType,
						from,
						to,
					)
				}
			}
		}
	}
	return nil
}

type deliveryRecord struct {
	ID          string
	From        uint64
	To          uint64
	MessageType string
	PayloadHash string
}

type protocolResult struct {
	received  map[string]deliveryRecord
	emitted   map[string]deliveryRecord
	signature *SignatureData
	refusal   *TypedRefusal
	terminal  string
}

func validateProtocolEvents(worker *WorkerEvent, stdout []byte) (*protocolResult, error) {
	if len(worker.Events) < 2 {
		return nil, errors.New("worker event sequence lacks terminal result and stop")
	}
	if err := compareWorkerJSONL(stdout, worker.Events); err != nil {
		return nil, err
	}
	penultimate := worker.Events[len(worker.Events)-2].Direction
	if penultimate != "signature" && penultimate != "refusal" && penultimate != "quiesced" {
		return nil, errors.New("terminal protocol result must be the penultimate event")
	}
	if worker.Events[len(worker.Events)-1].Direction != "stopped" {
		return nil, errors.New("stopped acknowledgement must be the final event")
	}
	result := &protocolResult{
		received: make(map[string]deliveryRecord),
		emitted:  make(map[string]deliveryRecord),
	}
	emittedCount, terminalCount, stopped := 0, 0, 0
	for index, event := range worker.Events {
		if event.Sequence != uint64(index) || !sha256Pattern.MatchString(event.PayloadSHA256) {
			return nil, errors.New("noncontiguous event sequence or invalid payload hash")
		}
		switch event.Direction {
		case "received", "emitted":
			if index >= len(worker.Events)-2 {
				return nil, errors.New("protocol traffic appears after terminal result")
			}
			if !rolePattern.MatchString(event.DeliveryID) || event.MessageType == "" ||
				event.Signature != nil || event.Refusal != nil || event.PeerOrdinal == nil ||
				*event.PeerOrdinal >= 11 || *event.PeerOrdinal == worker.Ordinal {
				return nil, errors.New("invalid protocol delivery event")
			}
			record := deliveryRecord{
				ID: event.DeliveryID, MessageType: event.MessageType,
				PayloadHash: event.PayloadSHA256,
			}
			if event.Direction == "received" {
				record.From, record.To = *event.PeerOrdinal, worker.Ordinal
				if _, duplicate := result.received[record.ID]; duplicate {
					return nil, errors.New("duplicate received delivery ID")
				}
				result.received[record.ID] = record
			} else {
				record.From, record.To = worker.Ordinal, *event.PeerOrdinal
				if _, duplicate := result.emitted[record.ID]; duplicate {
					return nil, errors.New("duplicate emitted delivery ID")
				}
				result.emitted[record.ID] = record
				emittedCount++
			}
		case "signature":
			if index != len(worker.Events)-2 {
				return nil, errors.New("terminal protocol result must be the penultimate event")
			}
			if event.DeliveryID != "" || event.MessageType != "signature_data" ||
				event.PeerOrdinal != nil || event.Signature == nil || event.Refusal != nil ||
				event.PayloadSHA256 != hashJSON(*event.Signature) {
				return nil, errors.New("signature event does not bind raw SignatureData")
			}
			result.signature = event.Signature
			result.terminal = "signature"
			terminalCount++
		case "refusal":
			if index != len(worker.Events)-2 {
				return nil, errors.New("terminal protocol result must be the penultimate event")
			}
			if event.DeliveryID != "" || event.MessageType != "tss_error" ||
				event.PeerOrdinal != nil || event.Signature != nil || event.Refusal == nil ||
				event.PayloadSHA256 != hashJSON(*event.Refusal) {
				return nil, errors.New("refusal event does not bind raw tss error")
			}
			result.refusal = event.Refusal
			result.terminal = "refusal"
			terminalCount++
		case "quiesced":
			if index != len(worker.Events)-2 {
				return nil, errors.New("terminal protocol result must be the penultimate event")
			}
			if event.DeliveryID != "" || event.MessageType != "no_result" ||
				event.PeerOrdinal != nil || event.Signature != nil || event.Refusal != nil ||
				event.PayloadSHA256 != hashJSON(struct {
					State string `json:"state"`
				}{"quiesced_no_result"}) {
				return nil, errors.New("invalid quiescence event")
			}
			result.terminal = "quiesced"
			terminalCount++
		case "stopped":
			if event.DeliveryID != "" || event.MessageType != "eof_after_terminal" ||
				event.PeerOrdinal != nil || event.Signature != nil || event.Refusal != nil ||
				event.PayloadSHA256 != hashJSON(struct {
					Waited  bool `json:"waited"`
					Drained bool `json:"drained"`
				}{true, true}) || index != len(worker.Events)-1 {
				return nil, errors.New("invalid terminal stop/EOF acknowledgement")
			}
			stopped++
		default:
			return nil, fmt.Errorf("unknown protocol event direction %q", event.Direction)
		}
	}
	if emittedCount == 0 {
		return nil, errors.New("worker retained no emitted protocol event")
	}
	if terminalCount != 1 || stopped != 1 {
		return nil, errors.New("worker has ambiguous terminal or stop event sequence")
	}
	return result, nil
}

func compareWorkerJSONL(stdout []byte, events []ProtocolEvent) error {
	lines := bytes.Split(stdout, []byte("\n"))
	if len(lines) != len(events)+1 || len(lines[len(lines)-1]) != 0 {
		return errors.New("worker stdout is not one complete JSON event per line")
	}
	for index := range events {
		var decoded ProtocolEvent
		if err := strictjson.Decode(lines[index], &decoded); err != nil {
			return fmt.Errorf("worker stdout line %d: %w", index+1, err)
		}
		if !reflect.DeepEqual(decoded, events[index]) {
			return fmt.Errorf("worker stdout line %d disagrees with event record", index+1)
		}
	}
	return nil
}

func mergeDeliveries(destination, source map[string]deliveryRecord) error {
	for id, record := range source {
		if _, duplicate := destination[id]; duplicate {
			return fmt.Errorf("duplicate global delivery ID %q", id)
		}
		destination[id] = record
	}
	return nil
}

func validateMixedWorker(
	worker *WorkerEvent,
	signature *SignatureData,
	refusal *TypedRefusal,
	terminal string,
) error {
	if signature != nil {
		return errors.New("mixed worker produced SignatureData")
	}
	if err := validateMixedWorkerProgression(worker); err != nil {
		return err
	}
	switch worker.TerminalState {
	case "rejected":
		if refusal == nil || terminal != "refusal" {
			return errors.New("rejected worker lacks one raw typed refusal")
		}
		if worker.Ordinal < 5 || worker.Ordinal > 10 {
			return errors.New("typed refusal victim is not a candidate worker")
		}
		if refusal.Task != "signing" || refusal.Round != 3 ||
			refusal.Cause != "failed to calculate Alice_end or Alice_end_wc" ||
			refusal.Victim != worker.Ordinal {
			return errors.New("wrong task/round/cause/victim in typed refusal")
		}
		triggerDeliveryID := ""
		triggerIndex := -1
		for index := len(worker.Events) - 1; index >= 0; index-- {
			event := worker.Events[index]
			if event.Direction == "received" &&
				event.MessageType == mixedRequiredMessageTypes[2] {
				triggerDeliveryID = event.DeliveryID
				triggerIndex = index
				break
			}
		}
		if triggerDeliveryID == "" || refusal.TriggerDeliveryID != triggerDeliveryID ||
			triggerIndex != len(worker.Events)-3 {
			return errors.New("typed refusal does not bind the final round-2 trigger delivery")
		}
		gotCulprits := slices.Clone(refusal.Culprits)
		sort.Slice(gotCulprits, func(left, right int) bool {
			return gotCulprits[left] < gotCulprits[right]
		})
		wantCulprits := []uint64{0, 0, 1, 1, 2, 2, 3, 3, 4, 4}
		if !slices.Equal(gotCulprits, wantCulprits) {
			return errors.New("typed refusal has wrong culprit multiset")
		}
	case "quiesced_no_result":
		if refusal != nil || terminal != "quiesced" {
			return errors.New("quiesced worker contains a refusal")
		}
	default:
		return fmt.Errorf("nonterminal or unsupported mixed state %q", worker.TerminalState)
	}
	return nil
}

func validateMixedWorkerProgression(worker *WorkerEvent) error {
	type directionCounts struct {
		emitted  int
		received int
	}
	counts := make(map[string]*directionCounts, len(mixedRequiredMessageTypes))
	for _, messageType := range mixedRequiredMessageTypes {
		counts[messageType] = &directionCounts{}
	}
	round1Received, round2Received := 0, 0
	for _, event := range worker.Events {
		switch event.Direction {
		case "received", "emitted":
			count, present := counts[event.MessageType]
			if !present {
				return fmt.Errorf("mixed worker contains unknown message type %q", event.MessageType)
			}
			if event.MessageType == mixedRequiredMessageTypes[2] &&
				event.Direction == "emitted" && round1Received != 20 {
				return errors.New("round-2 emit precedes all 20 round-1 receives")
			}
			if event.Direction == "emitted" {
				count.emitted++
			} else {
				count.received++
				if event.MessageType == mixedRequiredMessageTypes[0] ||
					event.MessageType == mixedRequiredMessageTypes[1] {
					round1Received++
				} else {
					round2Received++
				}
			}
		case "refusal":
			if round2Received != 10 {
				return errors.New("round-3 refusal precedes all 10 round-2 receives")
			}
		}
	}
	for _, messageType := range mixedRequiredMessageTypes {
		count := counts[messageType]
		if count.emitted != 10 || count.received != 10 {
			return fmt.Errorf(
				"mixed worker must retain 10 emitted and 10 received %q messages; got %d/%d",
				messageType,
				count.emitted,
				count.received,
			)
		}
	}
	return nil
}

func toolArgv0(toolID string) string {
	return "tools/" + toolID + "/tool.bin"
}

func hashJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func sortedRoles(values []string) []string {
	result := slices.Clone(values)
	sort.Strings(result)
	return result
}
