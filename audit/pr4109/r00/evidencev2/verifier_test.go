package evidencev2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	legacyr00 "github.com/keep-network/keep-core/audit/pr4109/r00"
)

func TestVerifySyntheticBundleDerivesDiagnosticCases(t *testing.T) {
	fixture := newSyntheticFixture(t)
	report, err := VerifyBundle(fixture.directory)
	if err != nil {
		t.Fatalf("valid synthetic evidence bundle failed: %v", err)
	}
	if !report.DiagnosticOnly || report.ReleaseAuthority || report.RootGate != "blocked" ||
		report.ExecutionProvenanceVerified || report.EvidenceAccepted {
		t.Fatalf("authority drift in report: %+v", report)
	}
	if len(report.Cases) != 3 {
		t.Fatalf("got %d case outcomes, want 3", len(report.Cases))
	}
	for index, outcome := range report.Cases {
		if outcome.CaseID != requiredCaseIDs[index] || !outcome.DerivedPredicateSatisfied {
			t.Errorf("unexpected derived outcome %+v", outcome)
		}
	}
}

func TestFileReferenceSizeBudgetsFailClosed(t *testing.T) {
	validReference := func(index int, mediaType string, size uint64) FileReference {
		return FileReference{
			Path:      fmt.Sprintf("objects/%03d", index),
			Role:      fmt.Sprintf("object_%03d", index),
			MediaType: mediaType,
			SHA256:    strings.Repeat("a", 64),
			Size:      size,
		}
	}

	t.Run("per-media", func(t *testing.T) {
		for _, test := range []struct {
			mediaType string
			limit     int64
		}{
			{"application/json", maxJSONArtifactBytes},
			{"text/plain", maxTextArtifactBytes},
			{"application/octet-stream", maxBinaryArtifactBytes},
		} {
			_, err := indexFileReferences([]FileReference{
				validReference(0, test.mediaType, uint64(test.limit)+1),
			})
			if err == nil || !strings.Contains(err.Error(), "unsafe hash or size") {
				t.Fatalf("%s over-limit error is %v", test.mediaType, err)
			}
		}
	})

	t.Run("aggregate", func(t *testing.T) {
		references := make([]FileReference, 0, 9)
		for index := 0; index < 9; index++ {
			references = append(
				references,
				validReference(index, "application/octet-stream", uint64(maxBinaryArtifactBytes)),
			)
		}
		_, err := indexFileReferences(references)
		if err == nil || !strings.Contains(err.Error(), "aggregate artifact size") {
			t.Fatalf("aggregate over-limit error is %v", err)
		}
	})
}

func TestStrictJSONRejectsUnknownAndDuplicateFields(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		fixture := newSyntheticFixture(t)
		fixture.mutateJSONObject(t, "case_r00-01", func(document map[string]any) {
			document["unexpected"] = true
		})
		assertVerifyFails(t, fixture, "unknown field")
	})
	t.Run("duplicate", func(t *testing.T) {
		fixture := newSyntheticFixture(t)
		data := fixture.readRole(t, "case_r00-01")
		data = bytes.Replace(
			data,
			[]byte(`"case_id": "R00-01"`),
			[]byte(`"case_id": "R00-01", "case_id": "R00-02"`),
			1,
		)
		fixture.rewriteArtifacts(t, map[string][]byte{"case_r00-01": data})
		assertVerifyFails(t, fixture, "duplicate JSON object name")
	})
}

func TestIdentityArtifactAndLayoutMutationsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *syntheticFixture)
		want   string
	}{
		{
			"toolchain identity drift",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "tool_candidate-proof_buildinfo", func(document map[string]any) {
					document["toolchain"].(map[string]any)["goos"] = "darwin"
				})
			},
			"toolchain identity drift",
		},
		{
			"artifact hash",
			func(t *testing.T, fixture *syntheticFixture) {
				path := fixture.pathForRole(t, "case_r00-01")
				if err := os.WriteFile(path, append(fixture.readRole(t, "case_r00-01"), '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			"size mismatch",
		},
		{
			"path traversal",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateRoot(t, func(root *EvidenceRoot) {
					root.Files[0].Path = "../escape"
				})
			},
			"unsafe path",
		},
		{
			"unexpected file",
			func(t *testing.T, fixture *syntheticFixture) {
				if err := os.WriteFile(filepath.Join(fixture.directory, "extra.txt"), []byte("extra"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			"unexpected file",
		},
		{
			"symlink",
			func(t *testing.T, fixture *syntheticFixture) {
				path := fixture.pathForRole(t, "case_r00-01")
				target := filepath.Join(t.TempDir(), "case.json")
				if err := os.WriteFile(target, fixture.readRole(t, "case_r00-01"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
			"symlink",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSyntheticFixture(t)
			test.mutate(t, fixture)
			assertVerifyFails(t, fixture, test.want)
		})
	}
}

func TestContentAddressedRootCannotBeReplacedInPlace(t *testing.T) {
	fixture := newSyntheticFixture(t)
	wrong := filepath.Join(filepath.Dir(fixture.directory), strings.Repeat("0", 64))
	if err := os.Rename(fixture.directory, wrong); err != nil {
		t.Fatal(err)
	}
	fixture.directory = wrong
	assertVerifyFails(t, fixture, "bundle path must be sha256")
}

func TestR0001And02DirectionDecodeTimeoutPanicAndResultMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *syntheticFixture)
		want   string
	}{
		{
			"R00-01 direction",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "case_r00-01", func(document map[string]any) {
					proof := document["proofs"].([]any)[0].(map[string]any)
					proof["producer_tool_id"] = HistoricalProofTool
				})
			},
			"direction or tool identity drift",
		},
		{
			"R00-02 direction",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "case_r00-02", func(document map[string]any) {
					proof := document["proofs"].([]any)[0].(map[string]any)
					proof["candidate_verifier_tool_id"] = HistoricalProofTool
				})
			},
			"direction or tool identity drift",
		},
		{
			"R00-01 decode",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "vector_r00-01-candidate-zk", func(document map[string]any) {
					document["t_hex"] = "0x01"
				})
			},
			"fixed-width",
		},
		{
			"R00-02 timeout",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "process_r00-02-historical-zk_candidate", func(document map[string]any) {
					document["timed_out"] = true
				})
			},
			"did not start, drain, and exit cleanly",
		},
		{
			"R00-01 panic",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "process_r00-01-candidate-zk_historical", func(document map[string]any) {
					document["panic_detected"] = true
				})
			},
			"did not start, drain, and exit cleanly",
		},
		{
			"derived result",
			func(t *testing.T, fixture *syntheticFixture) {
				role := "process_r00-01-candidate-zk_historical_stdout"
				var result ProofToolResult
				if err := json.Unmarshal(fixture.readRole(t, role), &result); err != nil {
					t.Fatal(err)
				}
				result.Accepted = true
				fixture.rewriteArtifacts(t, map[string][]byte{role: marshalJSON(t, result)})
			},
			"disagrees with independently derived",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSyntheticFixture(t)
			test.mutate(t, fixture)
			assertVerifyFails(t, fixture, test.want)
		})
	}
}

func TestR0003ProofSigningAndLifecycleMutationsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *syntheticFixture)
		want   string
	}{
		{
			"missing proof direction",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "case_r00-03", func(document map[string]any) {
					proofs := document["proofs"].([]any)
					document["proofs"] = proofs[:1]
				})
			},
			"proof vectors, want 2",
		},
		{
			"invalid homogeneous signature",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_historical_homogeneous_00", func(worker *WorkerEvent) {
					event := terminalProtocolEvent(worker)
					event.Signature.SHex = "0x" + strings.Repeat("0", 64)
					event.Signature.SignatureHex = "0x" + event.Signature.RHex[2:] + event.Signature.SHex[2:]
					event.PayloadSHA256 = hashJSON(*event.Signature)
				})
			},
			"signature S",
		},
		{
			"mismatched homogeneous signatures",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_candidate_homogeneous_00", func(worker *WorkerEvent) {
					event := terminalProtocolEvent(worker)
					signature := makeFixtureSignature(t, CandidateImplementation)
					event.Signature = &signature
					event.PayloadSHA256 = hashJSON(signature)
				})
			},
			"mismatched homogeneous signatures",
		},
		{
			"high-S homogeneous signature",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_candidate_homogeneous_00", func(worker *WorkerEvent) {
					event := terminalProtocolEvent(worker)
					s, ok := new(big.Int).SetString(event.Signature.SHex[2:], 16)
					if !ok {
						t.Fatal("invalid fixture S")
					}
					s.Sub(btcecOrder(t), s)
					event.Signature.SHex = fixedHex(s)
					event.Signature.SignatureHex = "0x" +
						event.Signature.RHex[2:] + event.Signature.SHex[2:]
					recovery, err := hex.DecodeString(event.Signature.RecoveryHex[2:])
					if err != nil || len(recovery) != 1 {
						t.Fatalf("invalid fixture recovery byte: %v", err)
					}
					event.Signature.RecoveryHex = fmt.Sprintf("0x%02x", recovery[0]^1)
					event.PayloadSHA256 = hashJSON(*event.Signature)
				})
			},
			"canonical low-S",
		},
		{
			"mixed signature",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					signature := makeFixtureSignature(t, HistoricalImplementation)
					event := terminalProtocolEvent(worker)
					event.Direction = "signature"
					event.MessageType = "signature_data"
					event.Signature = &signature
					event.Refusal = nil
					event.PayloadSHA256 = hashJSON(signature)
					worker.TerminalState = "completed"
				})
			},
			"mixed worker produced SignatureData",
		},
		{
			"generic refusal",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_07", func(worker *WorkerEvent) {
					event := terminalProtocolEvent(worker)
					event.Refusal.Cause = "generic error"
					event.PayloadSHA256 = hashJSON(*event.Refusal)
				})
			},
			"wrong task/round/cause/victim",
		},
		{
			"short mixed worker progression",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					for index, event := range worker.Events {
						if event.Direction == "received" || event.Direction == "emitted" {
							worker.Events = append(worker.Events[:index], worker.Events[index+1:]...)
							break
						}
					}
					resequenceEvents(worker.Events)
				})
			},
			"must retain 10 emitted and 10 received",
		},
		{
			"unknown mixed message",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					for index := range worker.Events {
						if worker.Events[index].Direction == "received" {
							worker.Events[index].MessageType = "round_message"
							break
						}
					}
				})
			},
			"unknown message type",
		},
		{
			"early round-2 emit",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					for index, event := range worker.Events {
						if event.Direction == "emitted" &&
							event.MessageType == mixedRequiredMessageTypes[2] {
							reordered := make([]ProtocolEvent, 0, len(worker.Events))
							reordered = append(reordered, event)
							reordered = append(reordered, worker.Events[:index]...)
							reordered = append(reordered, worker.Events[index+1:]...)
							worker.Events = reordered
							break
						}
					}
					resequenceEvents(worker.Events)
				})
			},
			"round-2 emit precedes all 20 round-1 receives",
		},
		{
			"early round-3 refusal",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_07", func(worker *WorkerEvent) {
					for index, event := range worker.Events {
						if event.Direction == "received" &&
							event.MessageType == mixedRequiredMessageTypes[2] {
							worker.Events = append(worker.Events[:index], worker.Events[index+1:]...)
							break
						}
					}
					resequenceEvents(worker.Events)
				})
			},
			"round-3 refusal precedes all 10 round-2 receives",
		},
		{
			"historical refusal victim",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_04", func(worker *WorkerEvent) {
					triggerDeliveryID := ""
					for index := len(worker.Events) - 1; index >= 0; index-- {
						if worker.Events[index].Direction == "received" &&
							worker.Events[index].MessageType == mixedRequiredMessageTypes[2] {
							triggerDeliveryID = worker.Events[index].DeliveryID
							break
						}
					}
					refusal := &TypedRefusal{
						Task: "signing", Round: 3,
						Cause:             "failed to calculate Alice_end or Alice_end_wc",
						TriggerDeliveryID: triggerDeliveryID,
						Victim:            4,
						Culprits:          []uint64{4, 0, 0, 3, 4, 3, 1, 2, 1, 2},
					}
					event := terminalProtocolEvent(worker)
					event.Direction = "refusal"
					event.MessageType = "tss_error"
					event.Refusal = refusal
					event.PayloadSHA256 = hashJSON(*refusal)
					worker.TerminalState = "rejected"
				})
			},
			"typed refusal victim is not a candidate worker",
		},
		{
			"wrong culprit multiset",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_07", func(worker *WorkerEvent) {
					event := terminalProtocolEvent(worker)
					event.Refusal.Culprits[len(event.Refusal.Culprits)-1] = 5
					event.PayloadSHA256 = hashJSON(*event.Refusal)
				})
			},
			"wrong culprit multiset",
		},
		{
			"wrong refusal trigger delivery",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_07", func(worker *WorkerEvent) {
					event := terminalProtocolEvent(worker)
					event.Refusal.TriggerDeliveryID = "d_wrong_round_2_trigger"
					event.PayloadSHA256 = hashJSON(*event.Refusal)
				})
			},
			"does not bind the final round-2 trigger delivery",
		},
		{
			"topology",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateJSONObject(t, "case_r00-03", func(document map[string]any) {
					run := document["signing_runs"].([]any)[2].(map[string]any)
					run["topology"].(map[string]any)["threshold"] = float64(9)
				})
			},
			"topology drift",
		},
		{
			"nonterminal worker",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					worker.TerminalState = "running"
				})
			},
			"nonterminal or unsupported mixed state",
		},
		{
			"undrained worker",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					worker.Process.StdoutDrained = false
				})
			},
			"did not start, drain, and exit cleanly",
		},
		{
			"unmatched delivery",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					for index := range worker.Events {
						if worker.Events[index].Direction == "emitted" {
							worker.Events[index].PayloadSHA256 = strings.Repeat("f", 64)
							break
						}
					}
				})
			},
			"unmatched or unacknowledged",
		},
		{
			"post-terminal traffic",
			func(t *testing.T, fixture *syntheticFixture) {
				fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_00", func(worker *WorkerEvent) {
					var traffic ProtocolEvent
					for _, event := range worker.Events {
						if event.Direction == "received" || event.Direction == "emitted" {
							traffic = event
							break
						}
					}
					traffic.DeliveryID = "post_terminal_traffic"
					last := len(worker.Events) - 1
					worker.Events = append(worker.Events, ProtocolEvent{})
					copy(worker.Events[last+1:], worker.Events[last:])
					worker.Events[last] = traffic
					for index := range worker.Events {
						worker.Events[index].Sequence = uint64(index)
					}
				})
			},
			"terminal protocol result must be the penultimate event",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSyntheticFixture(t)
			test.mutate(t, fixture)
			assertVerifyFails(t, fixture, test.want)
		})
	}
}

func TestMixedDeliveryProgressionMutationsFailClosed(t *testing.T) {
	canonical := func() map[string]deliveryRecord {
		result := make(map[string]deliveryRecord, 330)
		for typeIndex, messageType := range mixedRequiredMessageTypes {
			for from := uint64(0); from < 11; from++ {
				for to := uint64(0); to < 11; to++ {
					if from == to {
						continue
					}
					id := fmt.Sprintf("d_%d_%02d_%02d", typeIndex, from, to)
					payloadHash := hashText(id)
					if messageType == mixedRequiredMessageTypes[1] {
						payloadHash = hashText(fmt.Sprintf("broadcast_%02d", from))
					}
					result[id] = deliveryRecord{
						ID: id, From: from, To: to, MessageType: messageType,
						PayloadHash: payloadHash,
					}
				}
			}
		}
		return result
	}

	t.Run("short generic transcript", func(t *testing.T) {
		deliveries := canonical()
		for id, delivery := range deliveries {
			if delivery.MessageType != mixedRequiredMessageTypes[0] {
				delete(deliveries, id)
			} else {
				delivery.MessageType = "round_message"
				deliveries[id] = delivery
			}
		}
		if err := validateMixedDeliveryProgression(deliveries); err == nil ||
			!strings.Contains(err.Error(), "110 deliveries, want 330") {
			t.Fatalf("short generic progression error is %v", err)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		deliveries := canonical()
		record := deliveries["d_0_00_01"]
		record.MessageType = "round_message"
		deliveries["d_0_00_01"] = record
		if err := validateMixedDeliveryProgression(deliveries); err == nil ||
			!strings.Contains(err.Error(), "unknown type") {
			t.Fatalf("unknown-type progression error is %v", err)
		}
	})

	t.Run("missing and duplicate type pair", func(t *testing.T) {
		deliveries := canonical()
		record := deliveries["d_2_00_01"]
		record.MessageType = mixedRequiredMessageTypes[0]
		deliveries["d_2_00_01"] = record
		if err := validateMixedDeliveryProgression(deliveries); err == nil ||
			!strings.Contains(err.Error(), "duplicates type/pair") {
			t.Fatalf("duplicate-pair progression error is %v", err)
		}
	})

	t.Run("divergent broadcast expansion", func(t *testing.T) {
		deliveries := canonical()
		record := deliveries["d_1_00_01"]
		record.PayloadHash = strings.Repeat("f", 64)
		deliveries["d_1_00_01"] = record
		if err := validateMixedDeliveryProgression(deliveries); err == nil ||
			!strings.Contains(err.Error(), "divergent payload hashes") {
			t.Fatalf("broadcast-expansion progression error is %v", err)
		}
	})
}

func TestMixedCulpritOrderIsRetainedButNotPinned(t *testing.T) {
	fixture := newSyntheticFixture(t)
	fixture.mutateWorker(t, "worker_mixed_5_historical_6_candidate_07", func(worker *WorkerEvent) {
		event := terminalProtocolEvent(worker)
		for left, right := 0, len(event.Refusal.Culprits)-1; left < right; left, right = left+1, right-1 {
			event.Refusal.Culprits[left], event.Refusal.Culprits[right] =
				event.Refusal.Culprits[right], event.Refusal.Culprits[left]
		}
		event.PayloadSHA256 = hashJSON(*event.Refusal)
	})
	if _, err := VerifyBundle(fixture.directory); err != nil {
		t.Fatalf("culprit-order permutation was rejected: %v", err)
	}
}

func btcecOrder(t *testing.T) *big.Int {
	t.Helper()
	order, ok := new(big.Int).SetString(secp256k1Order[2:], 16)
	if !ok {
		t.Fatal("invalid secp256k1 order constant")
	}
	return order
}

func TestLegacyV1RemainsBlockedAndNotRun(t *testing.T) {
	digests := legacyr00.DocumentDigests()
	if digests.FrozenInputsSHA256 != V1FrozenInputsSHA256 ||
		digests.ReproductionCatalogSHA256 != V1CatalogSHA256 {
		t.Fatalf("v1 embedded document digest drift: %+v", digests)
	}
	bundle, err := legacyr00.Load()
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Catalog.Status != "blocked" || len(bundle.Catalog.Cases) != 18 {
		t.Fatalf("v1 root is %q with %d cases", bundle.Catalog.Status, len(bundle.Catalog.Cases))
	}
	for _, reproduction := range bundle.Catalog.Cases {
		if reproduction.BaselineEvidence.Status != "not_run" ||
			len(reproduction.BaselineEvidence.Controls) != 0 ||
			reproduction.ReleaseGate != "blocking" {
			t.Fatalf("v1 case %s authority drift", reproduction.ID)
		}
	}
}

func terminalProtocolEvent(worker *WorkerEvent) *ProtocolEvent {
	return &worker.Events[len(worker.Events)-2]
}

func resequenceEvents(events []ProtocolEvent) {
	for index := range events {
		events[index].Sequence = uint64(index)
	}
}

func assertVerifyFails(t *testing.T, fixture *syntheticFixture, want string) {
	t.Helper()
	_, err := VerifyBundle(fixture.directory)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("VerifyBundle error is %v, want substring %q", err, want)
	}
}

func (fixture *syntheticFixture) mutateWorker(
	t *testing.T,
	role string,
	mutate func(*WorkerEvent),
) {
	t.Helper()
	var worker WorkerEvent
	if err := json.Unmarshal(fixture.readRole(t, role), &worker); err != nil {
		t.Fatal(err)
	}
	mutate(&worker)
	fixture.rewriteArtifacts(t, map[string][]byte{
		role:                      marshalJSON(t, worker),
		worker.Process.StdoutRole: encodeJSONL(t, worker.Events),
	})
}

func (fixture *syntheticFixture) mutateJSONObject(
	t *testing.T,
	role string,
	mutate func(map[string]any),
) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(fixture.readRole(t, role), &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	fixture.rewriteArtifacts(t, map[string][]byte{role: marshalJSON(t, document)})
}

func (fixture *syntheticFixture) mutateRoot(
	t *testing.T,
	mutate func(*EvidenceRoot),
) {
	t.Helper()
	root := fixture.loadRoot(t)
	mutate(&root)
	fixture.writeRootAndReaddress(t, root)
}

func (fixture *syntheticFixture) rewriteArtifacts(t *testing.T, updates map[string][]byte) {
	t.Helper()
	root := fixture.loadRoot(t)
	for role, data := range updates {
		found := false
		for index := range root.Files {
			if root.Files[index].Role != role {
				continue
			}
			found = true
			path := filepath.Join(fixture.directory, filepath.FromSlash(root.Files[index].Path))
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			root.Files[index].SHA256 = hex.EncodeToString(digest[:])
			root.Files[index].Size = uint64(len(data))
			break
		}
		if !found {
			t.Fatalf("unknown artifact role %s", role)
		}
	}
	fixture.writeRootAndReaddress(t, root)
}

func (fixture *syntheticFixture) writeRootAndReaddress(t *testing.T, root EvidenceRoot) {
	t.Helper()
	data := marshalJSON(t, root)
	if err := os.WriteFile(filepath.Join(fixture.directory, RootFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	newDirectory := filepath.Join(filepath.Dir(fixture.directory), hex.EncodeToString(digest[:]))
	if newDirectory != fixture.directory {
		if err := os.Rename(fixture.directory, newDirectory); err != nil {
			t.Fatal(err)
		}
		fixture.directory = newDirectory
	}
}

func (fixture *syntheticFixture) loadRoot(t *testing.T) EvidenceRoot {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.directory, RootFilename))
	if err != nil {
		t.Fatal(err)
	}
	var root EvidenceRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func (fixture *syntheticFixture) readRole(t *testing.T, role string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixture.pathForRole(t, role))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (fixture *syntheticFixture) pathForRole(t *testing.T, role string) string {
	t.Helper()
	root := fixture.loadRoot(t)
	for _, reference := range root.Files {
		if reference.Role == role {
			return filepath.Join(fixture.directory, filepath.FromSlash(reference.Path))
		}
	}
	t.Fatalf("unknown artifact role %s", role)
	return ""
}
