// Command cutover-roster is the authoritative fleet aggregation service for a
// coordinated protocol cutover. It periodically polls each ceremony-eligible
// instance's trusted report target for its exact revision/epoch/image-digest
// attestation, folds in post-cutover node-local legacy sightings, reconciles
// each operator to a fleet status, persists the central state in bbolt, and
// serves a deterministic GET /api/v1/cutover-readiness endpoint plus Prometheus
// metrics on a monitoring-only address.
//
// The --expectedEpoch and --cutoverBlock values are plain operator-supplied
// configuration. They become meaningful once the real cutover release ships;
// this tool does not derive them from any compiled gate constant.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-core/pkg/monitoring/cutoverroster"
)

var logger = log.Logger("keep-cutover-roster")

type options struct {
	expectedRevision       string
	expectedEpoch          string
	expectedImageDigest    string
	cutoverBlock           uint64
	chainID                string
	collectionInterval     time.Duration
	missedThreshold        uint
	successThreshold       uint
	dbPath                 string
	apiAddr                string
	inventoryFile          string
	sightingsFile          string
	quarantineEvidenceFile string
	ethereumRPC            string
}

func parseOptions() options {
	var opts options

	flag.StringVar(&opts.expectedRevision, "expectedRevision", "",
		"Exact git revision (short SHA) the cutover release must report.")
	flag.StringVar(&opts.expectedEpoch, "expectedEpoch",
		cutoverroster.ExpectedEpochSecurityV2Cutover,
		"Expected release epoch. Meaningful once the real cutover release ships.")
	flag.StringVar(&opts.expectedImageDigest, "expectedImageDigest", "",
		"Exact runtime image digest the cutover release must report.")
	flag.Uint64Var(&opts.cutoverBlock, "cutoverBlock", 0,
		"Cutover block C (metadata). Meaningful once the real cutover release ships.")
	flag.StringVar(&opts.chainID, "chainID", "", "Chain ID of the monitored network.")
	flag.DurationVar(&opts.collectionInterval, "collectionInterval", time.Minute,
		"Interval between collection cycles.")
	flag.UintVar(&opts.missedThreshold, "missedThreshold", 2,
		"Consecutive missed collections before an instance is offline_unknown.")
	flag.UintVar(&opts.successThreshold, "successThreshold", 3,
		"Consecutive exact reports required before an operator is resolved_current.")
	flag.StringVar(&opts.dbPath, "dbPath", "/var/lib/cutover-roster/roster.db",
		"bbolt database path for persisted central state.")
	flag.StringVar(&opts.apiAddr, "apiAddr", "127.0.0.1:9701",
		"Monitoring-only bind address for the readiness API and /metrics. Do not expose publicly.")
	flag.StringVar(&opts.inventoryFile, "inventoryFile", "",
		"Path to the authoritative ceremony-eligible inventory JSON file.")
	flag.StringVar(&opts.sightingsFile, "sightingsFile", "",
		"Optional path to a JSON file of aggregated post-cutover legacy sightings.")
	flag.StringVar(&opts.quarantineEvidenceFile, "quarantineEvidenceFile", "",
		"Optional path to a JSON file of independently-verified quarantine/removal "+
			"evidence. Without it, no quarantine evidence is accepted (fail closed).")
	flag.StringVar(&opts.ethereumRPC, "ethereumRPC", "",
		"Optional Ethereum JSON-RPC URL used to read the current block height.")

	flag.Parse()

	return opts
}

func main() {
	opts := parseOptions()

	if err := run(opts); err != nil {
		logger.Errorf("cutover-roster exited with error: %v", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	store, err := cutoverroster.OpenStore(opts.dbPath)
	if err != nil {
		return fmt.Errorf("cannot open store: %w", err)
	}
	defer func() { _ = store.Close() }()

	metrics := cutoverroster.NewPrometheusMetrics()

	collector, err := cutoverroster.NewCollector(
		cutoverroster.CollectorConfig{
			ExpectedRevision:    opts.expectedRevision,
			ExpectedEpoch:       opts.expectedEpoch,
			ExpectedImageDigest: opts.expectedImageDigest,
			CutoverBlock:        opts.cutoverBlock,
			ChainID:             opts.chainID,
			CollectionInterval:  opts.collectionInterval,
			MissedThreshold:     opts.missedThreshold,
			SuccessThreshold:    opts.successThreshold,
		},
		store,
		metrics,
	)
	if err != nil {
		return fmt.Errorf("cannot construct collector: %w", err)
	}

	// Install the independent quarantine-evidence verifier. Absent one, the
	// collector accepts no quarantine evidence (fail closed).
	if opts.quarantineEvidenceFile != "" {
		entries, verifierErr := loadQuarantineEvidence(opts.quarantineEvidenceFile)
		if verifierErr != nil {
			return fmt.Errorf("cannot load quarantine evidence: %w", verifierErr)
		}
		collector.SetQuarantineVerifier(
			cutoverroster.NewAllowlistQuarantineVerifier(entries),
		)
		logger.Infof(
			"loaded %d independently-verified quarantine evidence entries",
			len(entries),
		)
	}

	server, err := cutoverroster.NewServer(opts.apiAddr, collector, metrics)
	if err != nil {
		return fmt.Errorf("cannot start API server: %w", err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	go func() {
		if serveErr := server.Serve(); serveErr != nil {
			logger.Errorf("readiness API server error: %v", serveErr)
		}
	}()
	logger.Infof(
		"cutover-roster serving readiness API on %s (monitoring-only)",
		server.Addr(),
	)

	runCollectionLoop(ctx, opts, collector)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Close(shutdownCtx)
}

func runCollectionLoop(
	ctx context.Context,
	opts options,
	collector *cutoverroster.Collector,
) {
	ticker := time.NewTicker(opts.collectionInterval)
	defer ticker.Stop()

	collectOnce(ctx, opts, collector)

	for {
		select {
		case <-ctx.Done():
			logger.Infof("shutdown requested; stopping collection loop")
			return
		case <-ticker.C:
			collectOnce(ctx, opts, collector)
		}
	}
}

func collectOnce(
	ctx context.Context,
	opts options,
	collector *cutoverroster.Collector,
) {
	// Read the chain height first so it can stamp even a failed-closed snapshot;
	// it is independent of the authoritative inputs read below.
	currentBlock := readCurrentBlock(ctx, opts.ethereumRPC, opts.chainID)

	// An unreadable authoritative input must fail readiness closed for this cycle
	// rather than leave a previous "complete=true" snapshot standing. Returning
	// early would keep certifying readiness while the inventory or sightings
	// evidence is missing.
	inventory, err := loadInventory(opts.inventoryFile)
	if err != nil {
		logger.Errorf(
			"cannot load authoritative inventory; failing readiness closed "+
				"for this cycle: %v", err,
		)
		collector.RecordInputUnavailable(currentBlock)
		return
	}

	sightings, err := loadSightings(opts.sightingsFile)
	if err != nil {
		logger.Errorf(
			"cannot load legacy sightings; failing readiness closed for this "+
				"cycle: %v", err,
		)
		collector.RecordInputUnavailable(currentBlock)
		return
	}

	reports := pollReports(ctx, inventory)

	if _, err := collector.Collect(inventory, reports, sightings, currentBlock); err != nil {
		logger.Errorf("collection cycle failed: %v", err)
	}
}

func loadInventory(path string) ([]cutoverroster.InventoryInstance, error) {
	if path == "" {
		return nil, nil
	}
	// #nosec G304 -- operator-supplied inventory path for the monitoring tool.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Decode into the input form, which carries trusted_report_target under an
	// explicit JSON key; InventoryInstance itself never serializes that field.
	var inputs []cutoverroster.InventoryInstanceInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil, fmt.Errorf("cannot decode inventory: %w", err)
	}
	inventory := make([]cutoverroster.InventoryInstance, 0, len(inputs))
	for _, in := range inputs {
		inventory = append(inventory, in.ToInventoryInstance())
	}
	return inventory, nil
}

func loadQuarantineEvidence(
	path string,
) ([]cutoverroster.VerifiedQuarantineEntry, error) {
	// #nosec G304 -- operator-supplied evidence path for the monitoring tool.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []cutoverroster.VerifiedQuarantineEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("cannot decode quarantine evidence: %w", err)
	}
	return entries, nil
}

func loadSightings(path string) ([]cutoverroster.LegacySighting, error) {
	if path == "" {
		return nil, nil
	}
	// #nosec G304 -- operator-supplied sightings path for the monitoring tool.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sightings []cutoverroster.LegacySighting
	if err := json.Unmarshal(data, &sightings); err != nil {
		return nil, fmt.Errorf("cannot decode sightings: %w", err)
	}
	return sightings, nil
}

// pollReports fetches each eligible instance's report from its trusted target.
// A target that is unreachable or returns a malformed body is simply omitted,
// which the collector treats as a missed collection.
func pollReports(
	ctx context.Context,
	inventory []cutoverroster.InventoryInstance,
) map[string]cutoverroster.InstanceReport {
	reports := make(map[string]cutoverroster.InstanceReport)
	client := &http.Client{Timeout: 10 * time.Second}

	for _, inv := range inventory {
		if !inv.CeremonyEligible || inv.TrustedReportTarget == "" {
			continue
		}
		report, err := fetchReport(ctx, client, inv)
		if err != nil {
			logger.Debugf("no report from instance %s: %v", inv.InstanceID, err)
			continue
		}
		reports[inv.InstanceID] = report
	}

	return reports
}

func fetchReport(
	ctx context.Context,
	client *http.Client,
	inv cutoverroster.InventoryInstance,
) (cutoverroster.InstanceReport, error) {
	var report cutoverroster.InstanceReport

	// #nosec G107 -- the report target is operator-supplied trusted inventory.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, inv.TrustedReportTarget, nil)
	if err != nil {
		return report, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return report, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return report, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return report, fmt.Errorf("cannot decode report: %w", err)
	}

	// Do not fabricate the report's identity or attestation time from inventory
	// or the local clock. The collector validates the instance's own attested
	// identity, freshness, and reporter revision and rejects anything missing or
	// mismatched, so a fabricated field could mask a stale or foreign report.
	return report, nil
}

// readCurrentBlock reads the current block height via eth_blockNumber. When a
// chain ID is configured it first verifies, via eth_chainId, that the RPC
// endpoint actually serves the expected chain. It returns 0 when no RPC URL is
// configured, on any error, or on a chain-ID mismatch — a block height read from
// the wrong chain must never be allowed to certify readiness.
func readCurrentBlock(ctx context.Context, rpcURL, expectedChainID string) uint64 {
	if rpcURL == "" {
		return 0
	}

	if expectedChainID != "" {
		actual, err := ethRPCResult(ctx, rpcURL, "eth_chainId")
		if err != nil {
			logger.Errorf("cannot verify chain ID via RPC: %v", err)
			return 0
		}
		if !chainIDMatches(expectedChainID, actual) {
			logger.Errorf(
				"configured chain ID %q does not match RPC eth_chainId %q; "+
					"refusing to use a block height from the wrong chain",
				expectedChainID, actual,
			)
			return 0
		}
	}

	result, err := ethRPCResult(ctx, rpcURL, "eth_blockNumber")
	if err != nil {
		logger.Debugf("cannot read current block: %v", err)
		return 0
	}
	block, err := parseHexUint64(result)
	if err != nil {
		logger.Debugf("cannot parse block number %q: %v", result, err)
		return 0
	}
	return block
}

// ethRPCResult performs a single parameter-less JSON-RPC call and returns the
// string "result" field, surfacing any transport, HTTP, or JSON-RPC error.
func ethRPCResult(ctx context.Context, rpcURL, method string) (string, error) {
	body := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":%q,"params":[]}`, method,
	))
	// #nosec G107 -- the RPC URL is operator-supplied configuration.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var rpcResponse struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResponse); err != nil {
		return "", err
	}
	if rpcResponse.Error != nil {
		return "", fmt.Errorf("rpc error: %s", rpcResponse.Error.Message)
	}
	return rpcResponse.Result, nil
}

// chainIDMatches reports whether the configured chain ID (decimal or 0x-hex)
// numerically equals the RPC-returned eth_chainId (hex).
func chainIDMatches(configured, rpcHex string) bool {
	rpcVal, err := parseHexUint64(rpcHex)
	if err != nil {
		return false
	}
	cfgVal, err := parseUint64Flexible(configured)
	if err != nil {
		return false
	}
	return cfgVal == rpcVal
}

// parseUint64Flexible parses an unsigned integer that may be decimal or
// 0x-prefixed hexadecimal.
func parseUint64Flexible(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

func parseHexUint64(s string) (uint64, error) {
	if len(s) < 2 || s[:2] != "0x" {
		return 0, errors.New("missing 0x prefix")
	}
	// Delegate digit parsing to strconv, which rejects an empty body, an invalid
	// digit, and — critically — a value that overflows uint64. A hand-rolled
	// value*16+digit loop wraps silently on an oversized eth_blockNumber or
	// eth_chainId result, which would then certify readiness from a bogus height;
	// ParseUint fails closed instead.
	return strconv.ParseUint(s[2:], 16, 64)
}
