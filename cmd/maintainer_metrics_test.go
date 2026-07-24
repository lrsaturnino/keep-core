package cmd

import (
	"context"
	"net"
	"testing"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/bitcoin"
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

// TestInitializeMaintainerClientInfoDisabled verifies that a client-info port of
// 0 leaves metrics disabled: no PerformanceMetrics is created, so the SPV
// recorder is never wired and proof submission is unaffected.
func TestInitializeMaintainerClientInfoDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{}
	cfg.ClientInfo.Port = 0

	performanceMetrics := initializeMaintainerClientInfo(ctx, cfg, nil)
	if performanceMetrics != nil {
		t.Fatal("expected no performance metrics when client-info port is 0")
	}
}

// TestInitializeMaintainerClientInfoEnabled verifies that a configured
// client-info port creates a PerformanceMetrics recorder the maintainer can wire
// into the SPV maintainer before maintainer.Initialize.
func TestInitializeMaintainerClientInfoEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.ClientInfo.Port = port

	performanceMetrics := initializeMaintainerClientInfo(
		ctx,
		cfg,
		&stubBitcoinChain{latestBlockHeight: 100},
	)
	if performanceMetrics == nil {
		t.Fatal("expected performance metrics when a client-info port is set")
	}
	performanceMetrics.Stop()
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

func (s *stubBitcoinChain) GetTransactionConfirmations(bitcoin.Hash) (uint, error) {
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
