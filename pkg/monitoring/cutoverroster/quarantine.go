package cutoverroster

import "strings"

// VerifiedQuarantineEntry is one independently-verified quarantine/removal
// evidence record. It is a separate trusted input from the authoritative
// inventory, so an operator self-report placed in the inventory cannot fabricate
// quarantine on its own — the evidence reference must also appear here, having
// been independently verified out of band.
type VerifiedQuarantineEntry struct {
	InstanceID      string `json:"instance_id"`
	OperatorAddress string `json:"operator_address"`
	EvidenceRef     string `json:"evidence_ref"`
}

// AllowlistQuarantineVerifier verifies quarantine evidence against a fixed set
// of independently-verified entries. It satisfies QuarantineVerifier.
type AllowlistQuarantineVerifier struct {
	verified map[string]struct{}
}

// NewAllowlistQuarantineVerifier builds a verifier from the given
// independently-verified entries.
func NewAllowlistQuarantineVerifier(
	entries []VerifiedQuarantineEntry,
) *AllowlistQuarantineVerifier {
	verified := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.EvidenceRef) == "" {
			continue
		}
		verified[quarantineKey(e.InstanceID, e.OperatorAddress, e.EvidenceRef)] = struct{}{}
	}
	return &AllowlistQuarantineVerifier{verified: verified}
}

// Verify reports whether the (instance, operator, evidence) triple is present in
// the independently-verified allowlist. An empty evidence reference never
// verifies.
func (v *AllowlistQuarantineVerifier) Verify(
	instanceID, operatorAddress, evidenceRef string,
) bool {
	if strings.TrimSpace(evidenceRef) == "" {
		return false
	}
	_, ok := v.verified[quarantineKey(instanceID, operatorAddress, evidenceRef)]
	return ok
}

func quarantineKey(instanceID, operatorAddress, evidenceRef string) string {
	return strings.ToLower(strings.TrimSpace(instanceID)) + "|" +
		normalizeAddress(operatorAddress) + "|" +
		strings.TrimSpace(evidenceRef)
}
