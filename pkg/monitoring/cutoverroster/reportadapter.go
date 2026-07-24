package cutoverroster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// clientInfoMetricName is the Prometheus metric the node exposes carrying its
// build labels (pkg/clientinfo/metrics.go). In the current build it carries only
// `version`; once the cutover release adds `revision` and `protocol_epoch` to
// this metric (Part A's observability change), the adapter picks them up from the
// same place with no change here.
const clientInfoMetricName = "client_info"

// AttestationSource supplies the externally-attested image digest and, until the
// node itself emits it, the release epoch for an instance. The running binary
// does not know its own container image digest, so the digest is always external
// inventory (per the spec, "the container digest remains external inventory
// because the binary does not know it"). A nil source attests nothing, which
// keeps a report that cannot prove its digest/epoch blocking (fail closed).
type AttestationSource interface {
	// AttestedDigest returns the independently-attested image digest for the
	// instance, and whether one exists.
	AttestedDigest(instanceID string) (string, bool)
	// AttestedEpoch returns the independently-attested release epoch for the
	// instance, and whether one exists. It is consulted only when the node does
	// not itself report the epoch via client_info.
	AttestedEpoch(instanceID string) (string, bool)
}

// MapAttestationSource is a fixed map-backed AttestationSource.
type MapAttestationSource struct {
	Digests map[string]string
	Epochs  map[string]string
}

// AttestedDigest implements AttestationSource.
func (m *MapAttestationSource) AttestedDigest(instanceID string) (string, bool) {
	d, ok := m.Digests[instanceID]
	return d, ok
}

// AttestedEpoch implements AttestationSource.
func (m *MapAttestationSource) AttestedEpoch(instanceID string) (string, bool) {
	e, ok := m.Epochs[instanceID]
	return e, ok
}

// MetricsReportSource builds an InstanceReport from a node's real exposed
// endpoints — /metrics (the client_info metric labels) and /diagnostics (the
// client_info JSON, which carries the exact revision) — rather than a bespoke
// JSON attestation contract. The image digest, and the release epoch until the
// node emits it, come from the independent AttestationSource.
type MetricsReportSource struct {
	client      *http.Client
	attestation AttestationSource
	clock       func() time.Time
}

// NewMetricsReportSource constructs a MetricsReportSource. A nil attestation
// source attests no digest/epoch (fail closed). A nil client uses a default with
// a 10s timeout.
func NewMetricsReportSource(
	client *http.Client,
	attestation AttestationSource,
) *MetricsReportSource {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &MetricsReportSource{
		client:      client,
		attestation: attestation,
		clock:       time.Now,
	}
}

// diagnosticsPayload is the subset of the /diagnostics JSON the adapter reads.
// The /diagnostics endpoint returns a JSON object keyed by diagnostic source
// name; the "client_info" source carries the exact version and revision plus the
// node's self-attested chain address and network ID (pkg/clientinfo/diagnostics.go).
type diagnosticsPayload struct {
	ClientInfo struct {
		Version      string `json:"version"`
		Revision     string `json:"revision"`
		ChainAddress string `json:"chain_address"`
		NetworkID    string `json:"network_id"`
	} `json:"client_info"`
}

// Fetch scrapes the instance's /metrics and /diagnostics endpoints (derived from
// its trusted report base URL) and assembles an InstanceReport. The report's
// revision comes from the node's own diagnostics/metrics, its epoch from the
// node's client_info metric when present or otherwise from external attestation,
// and its image digest from external attestation. A missing endpoint or an
// unparseable body is an error (treated by the collector as a missed collection).
//
// The responding node's identity is validated against its OWN diagnostics
// payload rather than copied from inventory: the report's operator address is
// taken from the node's self-attested chain_address, and it must match the
// inventory operator address the target answers for. When the inventory carries
// the instance's network ID, the node's self-attested network_id must match it
// too. A mismatch means the responding target is not the trusted instance, and
// the fetch fails (a missed collection) rather than certifying a foreign report.
func (s *MetricsReportSource) Fetch(
	ctx context.Context,
	inv InventoryInstance,
) (InstanceReport, error) {
	report := InstanceReport{
		InstanceID: inv.InstanceID,
	}

	base := strings.TrimSuffix(strings.TrimSpace(inv.TrustedReportTarget), "/")
	base = strings.TrimSuffix(base, metricsPath)
	base = strings.TrimSuffix(base, diagnosticsPath)
	if base == "" {
		return report, fmt.Errorf("no report target for instance %s", inv.InstanceID)
	}

	// /metrics: confirm the node is up and read the client_info labels (version,
	// and revision/protocol_epoch once the release adds them there).
	metricsBody, err := s.get(ctx, base+metricsPath)
	if err != nil {
		return report, err
	}
	labels := parseClientInfoLabels(metricsBody)
	if labels == nil {
		return report, fmt.Errorf("client_info metric absent from %s", inv.InstanceID)
	}
	report.Revision = labels["revision"]
	report.Epoch = labels["protocol_epoch"]

	// /diagnostics: read the exact revision (which the current build exposes here
	// rather than in the client_info metric) and the node's self-attested identity.
	diagBody, err := s.get(ctx, base+diagnosticsPath)
	if err != nil {
		return report, err
	}
	var diag diagnosticsPayload
	if err := json.Unmarshal([]byte(diagBody), &diag); err != nil {
		return report, fmt.Errorf("cannot decode diagnostics from %s: %w", inv.InstanceID, err)
	}
	if report.Revision == "" {
		report.Revision = strings.TrimSpace(diag.ClientInfo.Revision)
	}

	// Validate the responding node's self-attested identity instead of copying it
	// from inventory. The chain address it reports for itself must be canonical and
	// must equal the operator address the inventory says this target answers for.
	observedOperator := normalizeAddress(diag.ClientInfo.ChainAddress)
	if !isCanonicalAddress(observedOperator) {
		return report, fmt.Errorf(
			"diagnostics chain address is not a canonical operator address for %s",
			inv.InstanceID,
		)
	}
	if observedOperator != normalizeAddress(inv.OperatorAddress) {
		return report, fmt.Errorf(
			"responding node operator identity mismatch for %s", inv.InstanceID,
		)
	}
	// The report's operator address comes from the node's own attestation.
	report.OperatorAddress = observedOperator
	// When inventory pins the instance's network ID, the node's self-attested
	// network_id must match it, so one operator's responding target cannot stand
	// in for a different instance of the same operator.
	if strings.TrimSpace(inv.NetworkID) != "" {
		if strings.TrimSpace(diag.ClientInfo.NetworkID) != strings.TrimSpace(inv.NetworkID) {
			return report, fmt.Errorf(
				"responding node network identity mismatch for %s", inv.InstanceID,
			)
		}
	}

	// The image digest is always external attestation; the release epoch is taken
	// from attestation only when the node did not report it via client_info.
	if s.attestation != nil {
		if digest, ok := s.attestation.AttestedDigest(inv.InstanceID); ok {
			report.ImageDigest = digest
		}
		if report.Epoch == "" {
			if epoch, ok := s.attestation.AttestedEpoch(inv.InstanceID); ok {
				report.Epoch = epoch
			}
		}
	}

	report.AttestedAt = s.clock()
	// ReporterRevision is derived from the attestation timestamp (wall-clock
	// nanoseconds) rather than a process-local counter, so the collector's
	// replay/downgrade high-water-mark guard keeps accepting reports immediately
	// after a collector restart. A resettable in-memory sequence would start below
	// the persisted high-water mark and reject every report for as many cycles as
	// the previous process had run.
	report.ReporterRevision = uint64(report.AttestedAt.UnixNano())

	return report, nil
}

func (s *MetricsReportSource) get(ctx context.Context, url string) (string, error) {
	// #nosec G107 -- the URL is derived from operator-supplied trusted service
	// discovery / inventory for the monitoring tool.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// Sanitize: do not surface the raw transport error, which embeds the
		// requested URL (host/IP) that must not appear in logs.
		return "", fmt.Errorf("request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, io.LimitReader(resp.Body, maxReportBodyBytes)); err != nil {
		return "", fmt.Errorf("cannot read response body")
	}
	return buf.String(), nil
}

// maxReportBodyBytes caps how much of a report endpoint response is read, so a
// misbehaving or hostile target cannot exhaust memory.
const maxReportBodyBytes = 8 << 20 // 8 MiB

// parseClientInfoLabels extracts the label set of the client_info metric from a
// Prometheus text exposition. It returns nil if the metric line is absent. Only
// the first client_info series is read; HELP/TYPE comment lines are ignored.
func parseClientInfoLabels(promText string) map[string]string {
	for _, line := range strings.Split(promText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, clientInfoMetricName) ||
			len(line) == len(clientInfoMetricName) {
			continue
		}
		// The metric name must be followed by a label brace or whitespace before
		// the value, so a longer name such as client_info_extra does not match.
		next := line[len(clientInfoMetricName)]
		if next != '{' && next != ' ' && next != '\t' {
			continue
		}
		open := strings.IndexByte(line, '{')
		if open < 0 {
			// client_info with no labels.
			return map[string]string{}
		}
		closeIdx := strings.IndexByte(line, '}')
		if closeIdx < open {
			continue
		}
		return parseMetricLabels(line[open+1 : closeIdx])
	}
	return nil
}

// parseMetricLabels parses a Prometheus label list body (the text between the
// braces) into a map. It handles simple double-quoted values without escape
// sequences, which is sufficient for the build-info labels the node emits.
func parseMetricLabels(body string) map[string]string {
	labels := map[string]string{}
	for _, pair := range strings.Split(body, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:eq])
		value := strings.TrimSpace(pair[eq+1:])
		value = strings.Trim(value, `"`)
		labels[key] = value
	}
	return labels
}
