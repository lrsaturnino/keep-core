package tbtc

// Coverage-guided fuzz targets for the NETWORK/coordination protobuf
// unmarshalers in marshaling.go. Each asserts that Unmarshal never panics on
// arbitrary bytes: malformed input must return an error, not crash. The
// signer unmarshaler is intentionally excluded (local key material, not
// untrusted network input).

import "testing"

func FuzzSigningDoneMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&signingDoneMessage{}).Unmarshal(data)
	})
}

func FuzzCoordinationMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&coordinationMessage{}).Unmarshal(data)
	})
}

func FuzzNoopProposalUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&NoopProposal{}).Unmarshal(data)
	})
}

func FuzzHeartbeatProposalUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&HeartbeatProposal{}).Unmarshal(data)
	})
}

func FuzzDepositSweepProposalUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&DepositSweepProposal{}).Unmarshal(data)
	})
}

func FuzzRedemptionProposalUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&RedemptionProposal{}).Unmarshal(data)
	})
}

func FuzzMovingFundsProposalUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&MovingFundsProposal{}).Unmarshal(data)
	})
}

func FuzzMovedFundsSweepProposalUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&MovedFundsSweepProposal{}).Unmarshal(data)
	})
}
