package cutoverroster

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The production Prometheus consumes a file-based service-discovery target file
// (keep-sd.json) in the standard Prometheus file_sd format and attaches the
// operator's on-chain address under the __meta_chain_address label
// (infrastructure/kube/keep-prd/monitoring/prometheus/config/config.yaml). The
// discovered targets expose /metrics over http. This parser reads exactly that
// file so the collector reconciles against the same authoritative discovery input
// Prometheus scrapes, rather than an inventory-only view.
const (
	// metaChainAddressLabel is the Prometheus meta-label carrying the operator's
	// on-chain address in the keep-sd.json target file.
	metaChainAddressLabel = "__meta_chain_address"
	// discoveryScheme is the scrape scheme the production Prometheus config uses
	// for discovered nodes.
	discoveryScheme = "http"
	// metricsPath and diagnosticsPath are the endpoints a discovered node exposes.
	metricsPath     = "/metrics"
	diagnosticsPath = "/diagnostics"
)

// fileSDEntry is one entry of the Prometheus file_sd target file: a set of
// scrape targets plus the meta-labels attached to them.
type fileSDEntry struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// ServiceDiscovery is the parsed production service-discovery target set, keyed by
// normalized operator (chain) address, joining each operator to its discovered
// scrape base URL.
type ServiceDiscovery struct {
	baseURLByOperator map[string]string
}

// ParseServiceDiscovery parses the Prometheus file_sd target file (keep-sd.json)
// that production Prometheus consumes. For every target it reads the
// __meta_chain_address label (the operator address) and the target host:port, and
// records the operator's http scrape base URL. Entries without a canonical
// chain-address label or without a target are skipped as unusable discovery rows.
func ParseServiceDiscovery(data []byte) (*ServiceDiscovery, error) {
	var entries []fileSDEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("cannot decode service-discovery target file: %w", err)
	}

	sd := &ServiceDiscovery{baseURLByOperator: map[string]string{}}
	for _, entry := range entries {
		operator := normalizeAddress(entry.Labels[metaChainAddressLabel])
		if !isCanonicalAddress(operator) {
			continue
		}
		for _, target := range entry.Targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}
			// First usable target wins for an operator; a single operator maps to
			// a single scrape base URL.
			if _, exists := sd.baseURLByOperator[operator]; !exists {
				sd.baseURLByOperator[operator] = discoveryScheme + "://" + target
			}
			break
		}
	}
	return sd, nil
}

// Has reports whether the operator is present in the service-discovery target set.
func (s *ServiceDiscovery) Has(operatorAddress string) bool {
	_, ok := s.baseURLByOperator[normalizeAddress(operatorAddress)]
	return ok
}

// MetricsURL returns the discovered /metrics scrape URL for the operator, or "".
func (s *ServiceDiscovery) MetricsURL(operatorAddress string) string {
	base, ok := s.baseURLByOperator[normalizeAddress(operatorAddress)]
	if !ok {
		return ""
	}
	return base + metricsPath
}

// DiagnosticsURL returns the discovered /diagnostics URL for the operator, or "".
func (s *ServiceDiscovery) DiagnosticsURL(operatorAddress string) string {
	base, ok := s.baseURLByOperator[normalizeAddress(operatorAddress)]
	if !ok {
		return ""
	}
	return base + diagnosticsPath
}

// Len returns the number of operators present in service discovery.
func (s *ServiceDiscovery) Len() int {
	return len(s.baseURLByOperator)
}

// ReconcileWithDiscovery annotates the authoritative inventory against the
// production service-discovery target set. An eligible instance whose operator is
// absent from discovery is flagged DisappearedFromDiscovery (reconciliation rule
// 2: disappearance from service discovery is offline_unknown). It returns the
// inventory with the flags applied. A nil ServiceDiscovery leaves the inventory
// unchanged (no discovery feed configured).
func ReconcileWithDiscovery(
	inventory []InventoryInstance,
	sd *ServiceDiscovery,
) []InventoryInstance {
	if sd == nil {
		return inventory
	}
	for i := range inventory {
		if !inventory[i].CeremonyEligible {
			continue
		}
		if !sd.Has(inventory[i].OperatorAddress) {
			inventory[i].DisappearedFromDiscovery = true
		}
	}
	return inventory
}
