package cutoverroster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseServiceDiscovery proves the Prometheus file_sd target file (keep-sd.json)
// is parsed into an operator→scrape-URL map keyed by the __meta_chain_address
// label, skipping rows without a canonical chain address.
func TestParseServiceDiscovery(t *testing.T) {
	op := "0xabcdef0000000000000000000000000000000001"
	raw := fmt.Sprintf(`[
		{"targets": ["10.0.0.5:9601"], "labels": {"__meta_chain_address": "%s", "__meta_network_id": "1"}},
		{"targets": ["10.0.0.6:9601"], "labels": {"__meta_chain_address": "not-an-address"}},
		{"targets": [], "labels": {"__meta_chain_address": "0x1111111111111111111111111111111111111111"}}
	]`, strings.ToUpper(op))

	sd, err := ParseServiceDiscovery([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sd.Len() != 1 {
		t.Fatalf("expected 1 usable discovery entry, got %d", sd.Len())
	}
	if !sd.Has(op) {
		t.Errorf("expected operator %s present (case-insensitive)", op)
	}
	if got := sd.MetricsURL(op); got != "http://10.0.0.5:9601/metrics" {
		t.Errorf("metrics URL = %q", got)
	}
	if got := sd.DiagnosticsURL(op); got != "http://10.0.0.5:9601/diagnostics" {
		t.Errorf("diagnostics URL = %q", got)
	}
}

// TestReconcileWithDiscovery proves an eligible instance whose operator is absent
// from service discovery is flagged DisappearedFromDiscovery, while a discovered
// operator is not.
func TestReconcileWithDiscovery(t *testing.T) {
	present := "0xabcdef0000000000000000000000000000000001"
	absent := "0xabcdef0000000000000000000000000000000002"
	raw := fmt.Sprintf(
		`[{"targets": ["h:9601"], "labels": {"__meta_chain_address": "%s"}}]`, present,
	)
	sd, err := ParseServiceDiscovery([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	inventory := []InventoryInstance{
		{InstanceID: "i1", OperatorAddress: present, CeremonyEligible: true},
		{InstanceID: "i2", OperatorAddress: absent, CeremonyEligible: true},
	}
	out := ReconcileWithDiscovery(inventory, sd)
	if out[0].DisappearedFromDiscovery {
		t.Error("discovered operator must not be flagged disappeared")
	}
	if !out[1].DisappearedFromDiscovery {
		t.Error("operator absent from discovery must be flagged disappeared")
	}

	// A nil discovery feed leaves the inventory untouched.
	untouched := ReconcileWithDiscovery(
		[]InventoryInstance{{InstanceID: "i1", OperatorAddress: absent, CeremonyEligible: true}},
		nil,
	)
	if untouched[0].DisappearedFromDiscovery {
		t.Error("nil discovery feed must not flag anything")
	}
}

// TestParseClientInfoLabels proves the client_info metric labels are extracted
// from a Prometheus text exposition and that longer names do not falsely match.
func TestParseClientInfoLabels(t *testing.T) {
	text := `# HELP client_info Client info
# TYPE client_info gauge
client_info_extra{version="x"} 1
client_info{version="v2.0.0",revision="abc123",protocol_epoch="security_v2_cutover"} 1
`
	labels := parseClientInfoLabels(text)
	if labels == nil {
		t.Fatal("expected client_info labels")
	}
	if labels["version"] != "v2.0.0" || labels["revision"] != "abc123" ||
		labels["protocol_epoch"] != "security_v2_cutover" {
		t.Errorf("unexpected labels: %+v", labels)
	}

	if parseClientInfoLabels("performance_signing_operations_total 0\n") != nil {
		t.Error("absent client_info must return nil")
	}
}

// TestMetricsReportSource_Fetch proves the adapter builds a report from the
// node's real /metrics and /diagnostics endpoints, taking the revision from
// diagnostics when the client_info metric carries only the version (the current
// build), and folding in the externally-attested digest and epoch.
func TestMetricsReportSource_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			// Current build: client_info carries only version.
			_, _ = io.WriteString(w, "client_info{version=\"v2.0.0\"} 1\n")
		case "/diagnostics":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"client_info": map[string]string{
					"version":  "v2.0.0",
					"revision": "abc123def456",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	source := NewMetricsReportSource(srv.Client(), &MapAttestationSource{
		Digests: map[string]string{"i1": "sha256:deadbeef"},
		Epochs:  map[string]string{"i1": ExpectedEpochSecurityV2Cutover},
	})

	inv := InventoryInstance{
		InstanceID:          "i1",
		OperatorAddress:     "0xabcdef0000000000000000000000000000000001",
		TrustedReportTarget: srv.URL,
	}
	report, err := source.Fetch(context.Background(), inv)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if report.Revision != "abc123def456" {
		t.Errorf("revision from diagnostics = %q", report.Revision)
	}
	if report.Epoch != ExpectedEpochSecurityV2Cutover {
		t.Errorf("epoch from attestation = %q", report.Epoch)
	}
	if report.ImageDigest != "sha256:deadbeef" {
		t.Errorf("digest from attestation = %q", report.ImageDigest)
	}
	if report.ReporterRevision == 0 {
		t.Error("reporter revision must advance from zero")
	}
	if report.AttestedAt.IsZero() {
		t.Error("attested time must be stamped")
	}

	// A second scrape advances the reporter revision (monotonic).
	report2, err := source.Fetch(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if report2.ReporterRevision <= report.ReporterRevision {
		t.Errorf("reporter revision must be monotonic: %d then %d", report.ReporterRevision, report2.ReporterRevision)
	}
}

// TestEthCallIdentityVerifier proves the verifier ABI-encodes the
// operatorToStakingProvider(address) call and decodes the returned address.
func TestEthCallIdentityVerifier(t *testing.T) {
	operator := "0xabcdef0000000000000000000000000000000001"
	stakingProvider := "0x1111111111111111111111111111111111111111"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode rpc: %v", err)
		}
		// The call object must target the contract and carry the selector.
		var call struct {
			To   string `json:"to"`
			Data string `json:"data"`
		}
		_ = json.Unmarshal(req.Params[0], &call)
		if !strings.HasPrefix(call.Data, "0x") || len(call.Data) != 2+8+64 {
			t.Errorf("unexpected calldata length: %q", call.Data)
		}
		// Return the staking provider right-aligned in a 32-byte word.
		padded := "000000000000000000000000" + strings.TrimPrefix(stakingProvider, "0x")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "result": "0x" + padded,
		})
	}))
	defer srv.Close()

	verifier, err := NewEthCallIdentityVerifier(
		srv.URL, "0x2222222222222222222222222222222222222222", srv.Client(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	got, err := verifier.OperatorStakingProviderAtBlock(operator, 12345)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != stakingProvider {
		t.Errorf("staking provider = %q, want %q", got, stakingProvider)
	}

	// A non-canonical contract address is rejected at construction.
	if _, err := NewEthCallIdentityVerifier(srv.URL, "not-an-address", srv.Client()); err == nil {
		t.Error("expected rejection of a non-canonical contract address")
	}
}
