package gjkr

// Fuzz targets for the network-message protobuf unmarshalers in this package.
// Each asserts that Unmarshal never panics on arbitrary bytes: malformed input
// must return an error, not crash.

import "testing"

func FuzzEphemeralPublicKeyMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&EphemeralPublicKeyMessage{}).Unmarshal(data)
	})
}

func FuzzMemberCommitmentsMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&MemberCommitmentsMessage{}).Unmarshal(data)
	})
}

func FuzzPeerSharesMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&PeerSharesMessage{}).Unmarshal(data)
	})
}

func FuzzSecretSharesAccusationsMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&SecretSharesAccusationsMessage{}).Unmarshal(data)
	})
}

func FuzzMemberPublicKeySharePointsMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&MemberPublicKeySharePointsMessage{}).Unmarshal(data)
	})
}

func FuzzPointsAccusationsMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&PointsAccusationsMessage{}).Unmarshal(data)
	})
}

func FuzzMisbehavedEphemeralKeysMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&MisbehavedEphemeralKeysMessage{}).Unmarshal(data)
	})
}
