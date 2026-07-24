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
