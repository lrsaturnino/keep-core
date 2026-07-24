package main

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/monitoring/cutoverroster"
)

// TestLoadInventory_ReadsTrustedReportTarget proves the inventory loader ingests
// the trusted report target from the explicit JSON key. This is the regression
// guard for the bug where the target — being `json:"-"` on InventoryInstance —
// was silently dropped on input, leaving every instance untargeted.
func TestLoadInventory_ReadsTrustedReportTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	content := `[
	  {
	    "instance_id": "i1",
	    "operator_address": "0xabc",
	    "staking_provider": "sp-1",
	    "ceremony_eligible": true,
	    "expected_revision": "abc123",
	    "expected_epoch": "security_v2_cutover",
	    "expected_image_digest": "sha256:deadbeef",
	    "trusted_report_target": "https://reports.example/i1"
	  }
	]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write inventory file: %v", err)
	}

	inventory, err := loadInventory(path)
	if err != nil {
		t.Fatalf("loadInventory failed: %v", err)
	}
	if len(inventory) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(inventory))
	}
	inv := inventory[0]
	if inv.TrustedReportTarget != "https://reports.example/i1" {
		t.Errorf("trusted report target not ingested: %q", inv.TrustedReportTarget)
	}
	if !inv.CeremonyEligible {
		t.Errorf("ceremony_eligible not ingested")
	}
	if inv.ExpectedImageDigest != "sha256:deadbeef" {
		t.Errorf("expected image digest not ingested: %q", inv.ExpectedImageDigest)
	}
}

// TestLoadInventory_EmptyPath returns no inventory without error.
func TestLoadInventory_EmptyPath(t *testing.T) {
	inventory, err := loadInventory("")
	if err != nil {
		t.Fatalf("expected no error for empty path, got %v", err)
	}
	if inventory != nil {
		t.Errorf("expected nil inventory for empty path, got %v", inventory)
	}
}

// TestLoadQuarantineEvidence_ReadsEntries proves independently-verified evidence
// is loaded from its separate trusted file.
func TestLoadQuarantineEvidence_ReadsEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	content := `[
	  {"instance_id": "i1", "operator_address": "0xabc", "evidence_ref": "evidence://verified/1"}
	]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write evidence file: %v", err)
	}

	entries, err := loadQuarantineEvidence(path)
	if err != nil {
		t.Fatalf("loadQuarantineEvidence failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 evidence entry, got %d", len(entries))
	}
	if entries[0].EvidenceRef != "evidence://verified/1" {
		t.Errorf("evidence ref not ingested: %q", entries[0].EvidenceRef)
	}
}

// TestChainIDMatches proves the configured chain ID (decimal or 0x-hex) is
// compared numerically against the RPC-returned hex eth_chainId, so a block
// height read from the wrong chain is rejected rather than certifying readiness.
func TestChainIDMatches(t *testing.T) {
	cases := []struct {
		configured, rpcHex string
		want               bool
	}{
		{"1", "0x1", true},
		{"0x1", "0x1", true},
		{"11155111", "0xaa36a7", true}, // sepolia, decimal vs hex
		{"1", "0x2", false},
		{"", "0x1", false},
		{"1", "", false},
		{"abc", "0x1", false},
		{"1", "0xzz", false},
	}
	for _, c := range cases {
		if got := chainIDMatches(c.configured, c.rpcHex); got != c.want {
			t.Errorf(
				"chainIDMatches(%q, %q) = %v, want %v",
				c.configured, c.rpcHex, got, c.want,
			)
		}
	}
}

// TestParseHexUint64 proves the JSON-RPC hex parser fails closed: it rejects a
// missing prefix, an empty body, an invalid digit, and — critically — a value
// that overflows uint64. An oversized eth_blockNumber/eth_chainId result must
// error rather than silently wrap and certify readiness from a bogus height.
func TestParseHexUint64(t *testing.T) {
	maxHex := "0x" + strings.Repeat("f", 16) // exactly math.MaxUint64

	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"0x0", 0, false},
		{"0x1", 1, false},
		{"0xaa36a7", 0xaa36a7, false},
		{maxHex, math.MaxUint64, false},
		{"0x" + strings.Repeat("f", 17), 0, true},  // 17 nibbles overflows uint64
		{"0x1" + strings.Repeat("0", 16), 0, true}, // 2^64 overflows uint64
		{"", 0, true},                              // missing prefix
		{"1", 0, true},                             // missing prefix
		{"0x", 0, true},                            // empty body
		{"0xzz", 0, true},                          // invalid digit
	}
	for _, c := range cases {
		got, err := parseHexUint64(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseHexUint64(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseHexUint64(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseHexUint64(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestCollectOnce_InventoryUnavailableFailsClosed proves the collection loop
// fails readiness closed when its authoritative inventory cannot be read: rather
// than returning early and leaving a prior snapshot standing, it drives the
// collector to an incomplete snapshot carrying a nonzero unreconciled signal.
func TestCollectOnce_InventoryUnavailableFailsClosed(t *testing.T) {
	store, err := cutoverroster.OpenStore(filepath.Join(t.TempDir(), "roster.db"))
	if err != nil {
		t.Fatalf("cannot open store: %v", err)
	}
	defer func() { _ = store.Close() }()

	collector, err := cutoverroster.NewCollector(
		cutoverroster.CollectorConfig{
			ExpectedEpoch:      cutoverroster.ExpectedEpochSecurityV2Cutover,
			CollectionInterval: time.Minute,
			MissedThreshold:    2,
			SuccessThreshold:   3,
		},
		store,
		cutoverroster.NewPrometheusMetrics(),
	)
	if err != nil {
		t.Fatalf("cannot construct collector: %v", err)
	}

	// A non-empty path to a file that does not exist forces the inventory load to
	// fail (an empty path is a valid "no inventory" input and would not error).
	opts := options{
		inventoryFile: filepath.Join(t.TempDir(), "does-not-exist.json"),
	}

	collectOnce(context.Background(), opts, collector)

	snap := collector.Snapshot()
	if snap.Complete {
		t.Errorf("an unreadable inventory must not leave readiness certified complete")
	}
	if snap.Inventory.Unreconciled < 1 {
		t.Errorf(
			"an unreadable inventory must drive a nonzero unreconciled signal, got %d",
			snap.Inventory.Unreconciled,
		)
	}
}
