package spv

import (
	"testing"

	"github.com/keep-network/keep-core/pkg/bitcoin"
)

// These tests are regression coverage for the security-audit OOB cluster
// (F-003/004/006/007): an output index taken from a candidate transaction's
// input outpoint is used to index a separately-fetched previous transaction's
// Outputs slice. A malicious or MITM Electrum backend can return a
// valid-but-shorter transaction for the requested hash, so the index can be
// out of range. Before the fix each site panicked (index out of range), and a
// panic on the SPV-maintainer goroutine crashes the whole client. After the
// fix each site returns an error instead.
//
// Each test wires the shared localBitcoinChain mock to return a previous
// transaction with a single output, then references it from a candidate
// transaction with an out-of-range output index, and asserts an error rather
// than a panic.

// oobPreviousTransaction is a minimal previous transaction with exactly one
// output (index 0 is the only valid index).
func oobPreviousTransaction() *bitcoin.Transaction {
	return &bitcoin.Transaction{
		Version: 1,
		Inputs: []*bitcoin.TransactionInput{
			{
				Outpoint: &bitcoin.TransactionOutpoint{
					TransactionHash: bitcoin.Hash{},
					OutputIndex:     0,
				},
				SignatureScript: []byte{0x00},
			},
		},
		Outputs: []*bitcoin.TransactionOutput{
			{Value: 1000, PublicKeyScript: []byte{0x00, 0x14, 0x01}},
		},
		Locktime: 0,
	}
}

const oobOutOfRangeIndex = uint32(5) // the previous tx has only 1 output

func TestIsInputCurrentWalletsMainUTXO_OutOfRangeIndex(t *testing.T) {
	btcChain := newLocalBitcoinChain()
	localChain := newLocalChain()

	prevTx := oobPreviousTransaction()
	if err := btcChain.BroadcastTransaction(prevTx); err != nil {
		t.Fatal(err)
	}

	walletPublicKeyHash := [20]byte{}

	_, err := isInputCurrentWalletsMainUTXO(
		prevTx.Hash(),
		oobOutOfRangeIndex,
		walletPublicKeyHash,
		btcChain,
		localChain,
	)
	if err == nil {
		t.Fatal("expected an out-of-range error, got nil (the unguarded code panics here)")
	}
}

func TestParseDepositSweepTransactionInputs_OutOfRangeIndex(t *testing.T) {
	btcChain := newLocalBitcoinChain()
	localChain := newLocalChain()

	prevTx := oobPreviousTransaction()
	if err := btcChain.BroadcastTransaction(prevTx); err != nil {
		t.Fatal(err)
	}

	// A deposit sweep transaction must have exactly one output.
	candidate := &bitcoin.Transaction{
		Version: 1,
		Inputs: []*bitcoin.TransactionInput{
			{
				Outpoint: &bitcoin.TransactionOutpoint{
					TransactionHash: prevTx.Hash(),
					OutputIndex:     oobOutOfRangeIndex,
				},
				SignatureScript: []byte{0x00},
			},
		},
		Outputs: []*bitcoin.TransactionOutput{
			{Value: 900, PublicKeyScript: []byte{0x00, 0x14, 0x02}},
		},
	}

	_, _, err := parseDepositSweepTransactionInputs(btcChain, localChain, candidate)
	if err == nil {
		t.Fatal("expected an out-of-range error, got nil (the unguarded code panics here)")
	}
}

func TestParseMovingFundsTransactionInput_OutOfRangeIndex(t *testing.T) {
	btcChain := newLocalBitcoinChain()

	prevTx := oobPreviousTransaction()
	if err := btcChain.BroadcastTransaction(prevTx); err != nil {
		t.Fatal(err)
	}

	// A moving funds transaction must have exactly one input.
	candidate := &bitcoin.Transaction{
		Version: 1,
		Inputs: []*bitcoin.TransactionInput{
			{
				Outpoint: &bitcoin.TransactionOutpoint{
					TransactionHash: prevTx.Hash(),
					OutputIndex:     oobOutOfRangeIndex,
				},
				SignatureScript: []byte{0x00},
			},
		},
		Outputs: []*bitcoin.TransactionOutput{
			{Value: 900, PublicKeyScript: []byte{0x00, 0x14, 0x03}},
		},
	}

	_, _, err := parseMovingFundsTransactionInput(btcChain, candidate)
	if err == nil {
		t.Fatal("expected an out-of-range error, got nil (the unguarded code panics here)")
	}
}

func TestParseMovedFundsSweepTransactionInputs_OutOfRangeIndex(t *testing.T) {
	btcChain := newLocalBitcoinChain()

	prevTx := oobPreviousTransaction()
	if err := btcChain.BroadcastTransaction(prevTx); err != nil {
		t.Fatal(err)
	}

	// A moved funds sweep transaction with two inputs uses Inputs[1] (the
	// wallet's main UTXO) for the output lookup.
	candidate := &bitcoin.Transaction{
		Version: 1,
		Inputs: []*bitcoin.TransactionInput{
			{
				Outpoint: &bitcoin.TransactionOutpoint{
					TransactionHash: bitcoin.Hash{},
					OutputIndex:     0,
				},
				SignatureScript: []byte{0x00},
			},
			{
				Outpoint: &bitcoin.TransactionOutpoint{
					TransactionHash: prevTx.Hash(),
					OutputIndex:     oobOutOfRangeIndex,
				},
				SignatureScript: []byte{0x00},
			},
		},
		Outputs: []*bitcoin.TransactionOutput{
			{Value: 900, PublicKeyScript: []byte{0x00, 0x14, 0x04}},
		},
	}

	_, err := parseMovedFundsSweepTransactionInputs(btcChain, candidate)
	if err == nil {
		t.Fatal("expected an out-of-range error, got nil (the unguarded code panics here)")
	}
}
