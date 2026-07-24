package spv

import (
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/clientinfo"
)

// fakeMetricsRecorder records counter increments so tests can assert that the
// SPV redemption-proof metrics fire through the production recorder path.
type fakeMetricsRecorder struct {
	mutex    sync.Mutex
	counters map[string]float64
}

func newFakeMetricsRecorder() *fakeMetricsRecorder {
	return &fakeMetricsRecorder{counters: make(map[string]float64)}
}

func (f *fakeMetricsRecorder) IncrementCounter(name string, value float64) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.counters[name] += value
}

func (f *fakeMetricsRecorder) value(name string) float64 {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.counters[name]
}

// TestSubmitRedemptionProofRecordsMetrics installs a fake recorder through the
// production SetMetricsRecorder/getGlobalMetricsRecorder path and asserts that a
// successful submission records total+success while a failing submission records
// total+failed.
func TestSubmitRedemptionProofRecordsMetrics(t *testing.T) {
	bytesFromHex := func(str string) []byte {
		value, err := hex.DecodeString(str)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	txFromHex := func(str string) *bitcoin.Transaction {
		transaction := new(bitcoin.Transaction)
		if err := transaction.Deserialize(bytesFromHex(str)); err != nil {
			t.Fatal(err)
		}
		return transaction
	}

	requiredConfirmations := uint(6)

	// The same arbitrary redemption transaction and its input used by
	// TestSubmitRedemptionProof.
	redemptionTransaction := txFromHex("0100000000010189a128bbd1fd4626f752aa9036a118b2f4b2363ef409f5b527c69d048214d3130000000000ffffffff039ef9e92e0000000016001403b74d6893ad46dfdd01b9e0e3b3385f4fce2d1e6eed10000000000017a91486884e6be1525dab5ae0b451bd2c72cee67dcf4187791411000000000017a914538e4cc700d6510c8cae5e8b688d65276771e6088702483045022100b2e7fc655e0ddadbfef49201fb5f7046a40b36848c08f17ef2e4483bffb7a29e022024616909a96f8c901572d6a9e19d29d6aee6a835b409d4383a463fe1b338a2940121028ed84936be6a9f594a2dcc636d4bebf132713da3ce4dac5c61afbf8bbb47d6f700000000")
	redemptionInputTransaction := txFromHex("01000000000101db7aad9f51cffa7cebf5a3b41dc3552e1151d2550d8919a8e13d6bb00e046d5b0000000000ffffffff0333fc0b2f0000000016001403b74d6893ad46dfdd01b9e0e3b3385f4fce2d1e182612000000000017a914538e4cc700d6510c8cae5e8b688d65276771e60887aa9f10000000000017a91486884e6be1525dab5ae0b451bd2c72cee67dcf418702483045022100dded6eeacf49830de6f6b590a56f9b8ba3c2fda0b24e7f51884226a5ee78b5c2022024b1fbf3406716c9f9c5bfe241cfc0766af8209ecf8eb5f3318b407fd41c59ec0121028ed84936be6a9f594a2dcc636d4bebf132713da3ce4dac5c61afbf8bbb47d6f700000000")

	proof := &bitcoin.SpvProof{
		MerkleProof:    []byte{0x01},
		TxIndexInBlock: 2,
		BitcoinHeaders: []byte{0x03},
	}

	t.Run("successful submission records total and success", func(t *testing.T) {
		recorder := newFakeMetricsRecorder()
		SetMetricsRecorder(recorder)
		defer SetMetricsRecorder(nil)

		btcChain := newLocalBitcoinChain()
		spvChain := newLocalChain()
		if err := btcChain.BroadcastTransaction(redemptionTransaction); err != nil {
			t.Fatal(err)
		}
		if err := btcChain.BroadcastTransaction(redemptionInputTransaction); err != nil {
			t.Fatal(err)
		}

		assembler := func(
			bitcoin.Hash,
			uint,
			bitcoin.Chain,
		) (*bitcoin.Transaction, *bitcoin.SpvProof, error) {
			return redemptionTransaction, proof, nil
		}

		err := submitRedemptionProof(
			redemptionTransaction.Hash(),
			requiredConfirmations,
			btcChain,
			spvChain,
			assembler,
			getGlobalMetricsRecorder(),
		)
		if err != nil {
			t.Fatal(err)
		}

		if got := recorder.value(clientinfo.MetricRedemptionProofSubmissionsTotal); got != 1 {
			t.Errorf("expected total 1, got %v", got)
		}
		if got := recorder.value(clientinfo.MetricRedemptionProofSubmissionsSuccessTotal); got != 1 {
			t.Errorf("expected success 1, got %v", got)
		}
		if got := recorder.value(clientinfo.MetricRedemptionProofSubmissionsFailedTotal); got != 0 {
			t.Errorf("expected failed 0, got %v", got)
		}
	})

	t.Run("assembler error records total and failed", func(t *testing.T) {
		recorder := newFakeMetricsRecorder()
		SetMetricsRecorder(recorder)
		defer SetMetricsRecorder(nil)

		btcChain := newLocalBitcoinChain()
		spvChain := newLocalChain()

		assembler := func(
			bitcoin.Hash,
			uint,
			bitcoin.Chain,
		) (*bitcoin.Transaction, *bitcoin.SpvProof, error) {
			return nil, nil, fmt.Errorf("assembler failure")
		}

		err := submitRedemptionProof(
			redemptionTransaction.Hash(),
			requiredConfirmations,
			btcChain,
			spvChain,
			assembler,
			getGlobalMetricsRecorder(),
		)
		if err == nil {
			t.Fatal("expected an error from the failing assembler")
		}

		if got := recorder.value(clientinfo.MetricRedemptionProofSubmissionsTotal); got != 1 {
			t.Errorf("expected total 1, got %v", got)
		}
		if got := recorder.value(clientinfo.MetricRedemptionProofSubmissionsFailedTotal); got != 1 {
			t.Errorf("expected failed 1, got %v", got)
		}
		if got := recorder.value(clientinfo.MetricRedemptionProofSubmissionsSuccessTotal); got != 0 {
			t.Errorf("expected success 0, got %v", got)
		}
	})
}
