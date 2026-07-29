package electrum

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/checksum0/go-electrum/electrum"
	"github.com/keep-network/keep-core/pkg/bitcoin"
)

// decodeTransaction deserializes a transaction from the hexadecimal serialized
// string to a btcd message format.
func decodeTransaction(rawTx string) (tx *wire.MsgTx, err error) {
	headerBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode a hex string: [%w]", err)
	}

	// The Electrum server is untrusted and the deserialization below panics
	// on transactions holding more script data than any consensus-valid
	// transaction can carry.
	if len(headerBytes) > bitcoin.MaxTransactionByteLength {
		return nil, fmt.Errorf(
			"transaction byte length [%v] exceeds the maximum of [%v]",
			len(headerBytes),
			bitcoin.MaxTransactionByteLength,
		)
	}

	// The length guard above does not fully close the underlying btcd
	// decoder's panic: a transaction whose real wire length is far below
	// that guard can still trigger it (see the MaxTransactionByteLength
	// doc comment in the bitcoin package). Recover from any such panic and
	// return it as a plain error so a malicious or malformed response from
	// the untrusted Electrum server cannot crash the process.
	defer func() {
		if r := recover(); r != nil {
			tx = nil
			err = fmt.Errorf(
				"recovered from a panic while deserializing a transaction: [%v]",
				r,
			)
		}
	}()

	buf := bytes.NewBuffer(headerBytes)

	var t wire.MsgTx
	if err := t.Deserialize(buf); err != nil {
		return nil, fmt.Errorf("failed to deserialize a transaction: [%w]", err)
	}

	return &t, nil
}

// convertRawTransaction transforms a transaction provided in the hexadecimal serialized
// string to the format expected by the bitcoin.Chain interface.
func convertRawTransaction(rawTx string) (*bitcoin.Transaction, error) {
	t, err := decodeTransaction(rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode a transaction: [%w]", err)
	}

	result := &bitcoin.Transaction{
		Version:  int32(t.Version),
		Locktime: t.LockTime,
	}

	for _, vin := range t.TxIn {
		input := &bitcoin.TransactionInput{
			Outpoint: &bitcoin.TransactionOutpoint{
				TransactionHash: bitcoin.Hash(vin.PreviousOutPoint.Hash),
				OutputIndex:     vin.PreviousOutPoint.Index,
			},
			SignatureScript: vin.SignatureScript,
			Witness:         vin.Witness,
			Sequence:        vin.Sequence,
		}

		result.Inputs = append(result.Inputs, input)
	}

	for _, vout := range t.TxOut {
		output := &bitcoin.TransactionOutput{
			Value:           vout.Value,
			PublicKeyScript: vout.PkScript,
		}

		result.Outputs = append(result.Outputs, output)
	}

	return result, nil
}

// convertMerkleProof transforms a MerkleProof returned from Electrum protocol
// to the format expected by the bitcoin.Chain interface.
func convertMerkleProof(
	electrumResult *electrum.GetMerkleProofResult,
) *bitcoin.TransactionMerkleProof {
	return &bitcoin.TransactionMerkleProof{
		BlockHeight: uint(electrumResult.Height),
		MerkleNodes: electrumResult.Merkle,
		Position:    uint(electrumResult.Position),
	}
}
