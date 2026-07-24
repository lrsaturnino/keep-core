package main

import (
	"os"
	"path/filepath"
	"testing"
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
