package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/maintainer/spv"
)

// TestMaintainerCommandExposesClientInfoFlags verifies that, after ClientInfo is
// added to config.MaintainerCategories, the maintainer command exposes the
// client-info opt-in flag so metrics can be enabled for the process that runs
// the SPV maintainer.
func TestMaintainerCommandExposesClientInfoFlags(t *testing.T) {
	hasClientInfo := false
	for _, category := range config.MaintainerCategories {
		if category == config.ClientInfo {
			hasClientInfo = true
			break
		}
	}
	if !hasClientInfo {
		t.Fatal("expected config.MaintainerCategories to include ClientInfo")
	}

	if flag := MaintainerCommand.Flags().Lookup("clientInfo.port"); flag == nil {
		t.Fatal("expected maintainer command to expose the clientInfo.port flag")
	}
}

// TestWireMaintainerMetricsDisabled verifies that a client-info port of 0 leaves
// metrics disabled: no PerformanceMetrics is created and the production wiring
// helper leaves the SPV recorder unset, so proof submission is unaffected.
func TestWireMaintainerMetricsDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start from a clean recorder so the assertion reflects this call only.
	spv.SetMetricsRecorder(nil)
	defer spv.SetMetricsRecorder(nil)

	cfg := &config.Config{}
	cfg.ClientInfo.Port = 0

	// The initializer creates no recorder when the endpoint is disabled...
	if pm := initializeMaintainerClientInfo(ctx, cfg, nil); pm != nil {
		t.Fatal("expected no performance metrics when client-info port is 0")
	}

	// ...and the production wiring helper therefore leaves the SPV recorder nil.
	stop := wireMaintainerMetrics(ctx, cfg, nil)
	defer stop()
	if spv.MetricsRecorder() != nil {
		t.Fatal("expected the SPV metrics recorder to stay nil when port is 0")
	}
}

// TestWireMaintainerMetricsEnabled verifies that a configured client-info port
// drives the exact production wiring helper (wireMaintainerMetrics in
// cmd/maintainer.go, the same call the maintainer startup path uses before
// maintainer.Initialize), that the helper actually wires the recorder into the
// SPV maintainer, and that the three SPV redemption-proof series are present at
// zero when the /metrics endpoint is scraped so Prometheus sees them from
// startup.
//
// Driving wireMaintainerMetrics rather than calling spv.SetMetricsRecorder here
// means this test fails if production stops wiring the recorder - the gap the
// previous version could not catch.
//
// This is the single enabled-port test in the cmd package: keep-common's
// EnableServer registers "/metrics" on the global http.DefaultServeMux, which
// panics on a second registration, so all enabled-endpoint assertions live here.
func TestWireMaintainerMetricsEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start from a clean recorder and guarantee it is reset even if an
	// assertion below fails before the cleanup runs.
	spv.SetMetricsRecorder(nil)
	defer spv.SetMetricsRecorder(nil)

	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.ClientInfo.Port = port

	// Drive the production wiring helper, exactly as the maintainer startup path
	// does before maintainer.Initialize.
	stop := wireMaintainerMetrics(
		ctx,
		cfg,
		&stubBitcoinChain{latestBlockHeight: 100},
	)
	defer stop()

	// Production wiring must have installed the recorder into the SPV maintainer.
	if spv.MetricsRecorder() == nil {
		t.Fatal(
			"expected wireMaintainerMetrics to wire the SPV metrics recorder",
		)
	}

	// The three SPV redemption-proof series must be scrapeable at zero from
	// startup so operators never see a gap before the first submission.
	redemptionProofSeries := []string{
		"performance_" + clientinfo.MetricRedemptionProofSubmissionsTotal,
		"performance_" + clientinfo.MetricRedemptionProofSubmissionsSuccessTotal,
		"performance_" + clientinfo.MetricRedemptionProofSubmissionsFailedTotal,
	}

	metrics := scrapeMetricsEndpoint(t, port)
	for _, series := range redemptionProofSeries {
		value, ok := metricValue(metrics, series)
		if !ok {
			t.Errorf("expected series [%s] to be exposed at /metrics", series)
			continue
		}
		if value != "0" {
			t.Errorf(
				"expected series [%s] to be zero at startup, got [%s]",
				series,
				value,
			)
		}
	}

	// The cutover participation family must be scrapeable at zero from the
	// same startup. These series are the evidence the exact-image rehearsal
	// reads off a running node, and a recorder that only creates a series on
	// first use publishes nothing until the event it is meant to warn about
	// has already happened. Asserting them here is what proves the production
	// registry exports them: the recorder's own getters answer for a name it
	// was never asked to register, so only the exposition settles it.
	for _, name := range participationSeriesExposedAtZero {
		series := "performance_" + name
		value, ok := metricValue(metrics, series)
		if !ok {
			t.Errorf("expected series [%s] to be exposed at /metrics", series)
			continue
		}
		if value != "0" {
			t.Errorf(
				"expected series [%s] to be zero at startup, got [%s]",
				series,
				value,
			)
		}
	}
}

// participationSeriesExposedAtZero is the cutover observability contract as an
// operator scraping a node sees it. It mirrors the rehearsal's
// PARTICIPATION_METRICS list; the quarantined-signer count is included because
// it is registered with the rest of the fixed family, so a node exposes it from
// startup whether or not it ever quarantines an output.
var participationSeriesExposedAtZero = []string{
	clientinfo.MetricParticipationGateState,
	clientinfo.MetricParticipationCurrentBlock,
	clientinfo.MetricParticipationCutoverBlock,
	clientinfo.MetricParticipationAllowed,
	clientinfo.MetricParticipationActiveCeremonies,
	clientinfo.MetricParticipationActiveLegacyCeremonies,
	clientinfo.MetricParticipationActiveSecurityV2Ceremonies,
	clientinfo.MetricParticipationModeLegacyTotal,
	clientinfo.MetricParticipationModeSecurityV2Total,
	clientinfo.MetricParticipationLegacyCompletionsAfterCutoverTotal,
	clientinfo.MetricParticipationRefusalsTotal,
	clientinfo.MetricParticipationCommitRefusalsTotal,
	clientinfo.MetricParticipationClockErrorsTotal,
	clientinfo.MetricParticipationClockAbortsTotal,
	clientinfo.MetricParticipationQuiesceTotal,
	clientinfo.MetricParticipationQuiesceForcedAbortsTotal,
	clientinfo.MetricParticipationQuarantinedTBTCSigners,
}

// scrapeMetricsEndpoint fetches the /metrics body from the client-info endpoint,
// retrying briefly while the server goroutine started by EnableServer comes up.
func scrapeMetricsEndpoint(t *testing.T, port int) string {
	t.Helper()

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)

	var lastErr error
	for attempt := 0; attempt < 50; attempt++ {
		resp, err := http.Get(url) //nolint:gosec // fixed loopback test URL
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("could not read /metrics response: %v", err)
		}
		return string(body)
	}

	t.Fatalf("could not scrape /metrics on port %d: %v", port, lastErr)
	return ""
}

// metricValue extracts the value of a non-labelled metric series from the
// exposed text. Lines are formatted as "<name> <value> <timestamp>".
func metricValue(metrics, series string) (string, bool) {
	for _, line := range strings.Split(metrics, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == series {
			return fields[1], true
		}
	}
	return "", false
}

// freeTCPPort asks the OS for an unused TCP port.
func freeTCPPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// stubBitcoinChain is a minimal bitcoin.Chain for the client-info wiring test.
// Only GetLatestBlockHeight is used by the connectivity observer; every other
// method panics to catch unexpected use.
type stubBitcoinChain struct {
	latestBlockHeight uint
}

func (s *stubBitcoinChain) GetLatestBlockHeight() (uint, error) {
	return s.latestBlockHeight, nil
}

func (s *stubBitcoinChain) GetTransaction(bitcoin.Hash) (*bitcoin.Transaction, error) {
	panic("unexpected GetTransaction call")
}

func (s *stubBitcoinChain) GetTransactionConfirmations(
	context.Context,
	bitcoin.Hash,
) (uint, error) {
	panic("unexpected GetTransactionConfirmations call")
}

func (s *stubBitcoinChain) BroadcastTransaction(*bitcoin.Transaction) error {
	panic("unexpected BroadcastTransaction call")
}

func (s *stubBitcoinChain) GetBlockHeader(uint) (*bitcoin.BlockHeader, error) {
	panic("unexpected GetBlockHeader call")
}

func (s *stubBitcoinChain) GetTransactionMerkleProof(
	bitcoin.Hash,
	uint,
) (*bitcoin.TransactionMerkleProof, error) {
	panic("unexpected GetTransactionMerkleProof call")
}

func (s *stubBitcoinChain) GetTransactionsForPublicKeyHash(
	[20]byte,
	int,
) ([]*bitcoin.Transaction, error) {
	panic("unexpected GetTransactionsForPublicKeyHash call")
}

func (s *stubBitcoinChain) GetTxHashesForPublicKeyHash(
	[20]byte,
) ([]bitcoin.Hash, error) {
	panic("unexpected GetTxHashesForPublicKeyHash call")
}

func (s *stubBitcoinChain) GetMempoolForPublicKeyHash(
	[20]byte,
) ([]*bitcoin.Transaction, error) {
	panic("unexpected GetMempoolForPublicKeyHash call")
}

func (s *stubBitcoinChain) GetUtxosForPublicKeyHash(
	[20]byte,
) ([]*bitcoin.UnspentTransactionOutput, error) {
	panic("unexpected GetUtxosForPublicKeyHash call")
}

func (s *stubBitcoinChain) GetMempoolUtxosForPublicKeyHash(
	[20]byte,
) ([]*bitcoin.UnspentTransactionOutput, error) {
	panic("unexpected GetMempoolUtxosForPublicKeyHash call")
}

func (s *stubBitcoinChain) EstimateSatPerVByteFee(uint32) (int64, error) {
	panic("unexpected EstimateSatPerVByteFee call")
}

func (s *stubBitcoinChain) GetCoinbaseTxHash(uint) (bitcoin.Hash, error) {
	panic("unexpected GetCoinbaseTxHash call")
}
