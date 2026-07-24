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
	// metaNetworkIDLabel is the Prometheus meta-label carrying the node's libp2p
	// network ID in the keep-sd.json target file. It is the per-instance
	// disambiguator: two instances of one operator carry the same chain address
	// but distinct network IDs.
	metaNetworkIDLabel = "__meta_network_id"
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

// discoveredTarget is one instance's discovered scrape base URL together with
// the operator it belongs to, so a per-instance lookup can confirm the operator
// matches before handing back a target.
type discoveredTarget struct {
	operator string
	baseURL  string
}

// ServiceDiscovery is the parsed production service-discovery target set. It is
// keyed by node network ID (the per-instance disambiguator) so multiple
// instances of one operator resolve to distinct discovered targets rather than
// collapsing onto a single operator-level URL, and it separately records which
// operators appear anywhere in discovery for reconciliation rule 2.
type ServiceDiscovery struct {
	byNetworkID      map[string]discoveredTarget
	operatorsPresent map[string]bool
}

// ParseServiceDiscovery parses the Prometheus file_sd target file (keep-sd.json)
// that production Prometheus consumes. For every target it reads the
// __meta_chain_address label (the operator address), the __meta_network_id label
// (the per-instance network ID), and the target host:port, and records the
// instance's http scrape base URL keyed by network ID. Entries without a
// canonical chain-address label or without a target are skipped as unusable
// discovery rows; an entry without a network ID still marks the operator present
// (for rule 2) but yields no per-instance target.
func ParseServiceDiscovery(data []byte) (*ServiceDiscovery, error) {
	var entries []fileSDEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("cannot decode service-discovery target file: %w", err)
	}

	sd := &ServiceDiscovery{
		byNetworkID:      map[string]discoveredTarget{},
		operatorsPresent: map[string]bool{},
	}
	for _, entry := range entries {
		operator := normalizeAddress(entry.Labels[metaChainAddressLabel])
		if !isCanonicalAddress(operator) {
			continue
		}
		var base string
		for _, target := range entry.Targets {
			target = strings.TrimSpace(target)
			if target != "" {
				base = discoveryScheme + "://" + target
				break
			}
		}
		if base == "" {
			continue
		}
		// The operator is present in discovery regardless of whether the entry
		// carries a per-instance network ID.
		sd.operatorsPresent[operator] = true

		networkID := strings.TrimSpace(entry.Labels[metaNetworkIDLabel])
		if networkID == "" {
			continue
		}
		// First usable target wins for a given network ID: one instance maps to a
		// single scrape base URL.
		if _, exists := sd.byNetworkID[networkID]; !exists {
			sd.byNetworkID[networkID] = discoveredTarget{operator: operator, baseURL: base}
		}
	}
	return sd, nil
}

// Has reports whether the operator is present anywhere in the service-discovery
// target set.
func (s *ServiceDiscovery) Has(operatorAddress string) bool {
	return s.operatorsPresent[normalizeAddress(operatorAddress)]
}

// instanceBaseURL returns the discovered scrape base URL for the specific
// instance identified by (operatorAddress, networkID), or "". It requires the
// network ID (the per-instance key) and confirms the discovered target belongs
// to the claimed operator.
func (s *ServiceDiscovery) instanceBaseURL(operatorAddress, networkID string) string {
	networkID = strings.TrimSpace(networkID)
	if networkID == "" {
		return ""
	}
	target, ok := s.byNetworkID[networkID]
	if !ok {
		return ""
	}
	if target.operator != normalizeAddress(operatorAddress) {
		return ""
	}
	return target.baseURL
}

// MetricsURLForInstance returns the discovered /metrics scrape URL for the
// specific instance identified by (operatorAddress, networkID), or "".
func (s *ServiceDiscovery) MetricsURLForInstance(operatorAddress, networkID string) string {
	base := s.instanceBaseURL(operatorAddress, networkID)
	if base == "" {
		return ""
	}
	return base + metricsPath
}

// DiagnosticsURLForInstance returns the discovered /diagnostics URL for the
// specific instance identified by (operatorAddress, networkID), or "".
func (s *ServiceDiscovery) DiagnosticsURLForInstance(operatorAddress, networkID string) string {
	base := s.instanceBaseURL(operatorAddress, networkID)
	if base == "" {
		return ""
	}
	return base + diagnosticsPath
}

// Len returns the number of operators present in service discovery.
func (s *ServiceDiscovery) Len() int {
	return len(s.operatorsPresent)
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
