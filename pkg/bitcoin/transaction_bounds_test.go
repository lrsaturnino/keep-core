package bitcoin

import "testing"

// These tests cover the bounds-checked accessors that guard against
// out-of-range panics when an index originates from untrusted or
// separately-fetched transaction data. See the security audit OOB cluster
// (F-002/003/004/006/007/012).

func TestTransaction_OutputAt(t *testing.T) {
	transaction := &Transaction{
		Outputs: []*TransactionOutput{
			{Value: 100, PublicKeyScript: []byte{0x01}},
			{Value: 200, PublicKeyScript: []byte{0x02}},
		},
	}

	for _, index := range []uint32{0, 1} {
		output, err := transaction.OutputAt(index)
		if err != nil {
			t.Fatalf("unexpected error for in-range index [%d]: [%v]", index, err)
		}
		if output != transaction.Outputs[index] {
			t.Errorf("OutputAt(%d) returned the wrong output", index)
		}
	}

	// Out-of-range indices must return an error, never panic.
	for _, index := range []uint32{2, 3, 1 << 31} {
		output, err := transaction.OutputAt(index)
		if err == nil {
			t.Errorf("expected an out-of-range error for index [%d], got nil", index)
		}
		if output != nil {
			t.Errorf("expected a nil output for out-of-range index [%d]", index)
		}
	}
}

func TestTransaction_OutputAt_NoOutputs(t *testing.T) {
	transaction := &Transaction{}
	if _, err := transaction.OutputAt(0); err == nil {
		t.Error("expected an error indexing a transaction that has no outputs")
	}
}

func TestTransaction_InputAt(t *testing.T) {
	transaction := &Transaction{
		Inputs: []*TransactionInput{
			{Outpoint: &TransactionOutpoint{OutputIndex: 0}},
		},
	}

	input, err := transaction.InputAt(0)
	if err != nil {
		t.Fatalf("unexpected error for in-range index: [%v]", err)
	}
	if input != transaction.Inputs[0] {
		t.Error("InputAt(0) returned the wrong input")
	}

	for _, index := range []uint32{1, 5} {
		if _, err := transaction.InputAt(index); err == nil {
			t.Errorf("expected an out-of-range error for index [%d], got nil", index)
		}
	}
}

// TestTransaction_InputAt_NoInputs covers the F-012 case directly: indexing
// Inputs[0] on a zero-input transaction (a malicious Electrum backend can
// decode a segwit-flagged zero-input tx) must return an error, not panic.
func TestTransaction_InputAt_NoInputs(t *testing.T) {
	transaction := &Transaction{}
	if _, err := transaction.InputAt(0); err == nil {
		t.Error("expected an error indexing a transaction that has no inputs")
	}
}
