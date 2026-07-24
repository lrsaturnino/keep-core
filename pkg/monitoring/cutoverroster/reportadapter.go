package cutoverroster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
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
	seq         atomic.Uint64
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
// name; the "client_info" source carries the exact version and revision
// (pkg/clientinfo/diagnostics.go).
type diagnosticsPayload struct {
	ClientInfo struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	} `json:"client_info"`
}

// Fetch scrapes the instance's /metrics and /diagnostics endpoints (derived from
// its trusted report base URL) and assembles an InstanceReport. The report's
// revision comes from the node's own diagnostics/metrics, its epoch from the
// node's client_info metric when present or otherwise from external attestation,
// and its image digest from external attestation. A missing endpoint or an
// unparseable body is an error (treated by the collector as a missed collection).
func (s *MetricsReportSource) Fetch(
	ctx context.Context,
	inv InventoryInstance,
) (InstanceReport, error) {
	report := InstanceReport{
		InstanceID:      inv.InstanceID,
		OperatorAddress: inv.OperatorAddress,
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

	// /diagnostics: read the exact revision, which the current build exposes here
	// rather than in the client_info metric.
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
	// ReporterRevision is a monotonically increasing per-source scrape sequence.
	// The node does not emit its own reporter revision in this build, so the
	// collector's replay/downgrade guard is fed a value that genuinely advances
	// each successful scrape rather than a fabricated constant.
	report.ReporterRevision = s.seq.Add(1)

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
