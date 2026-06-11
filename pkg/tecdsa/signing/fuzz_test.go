package signing

// Coverage-guided fuzz targets for the network-message protobuf unmarshalers.
// Each asserts that Unmarshal never panics on arbitrary input bytes.

import "testing"

func FuzzEphemeralPublicKeyMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&ephemeralPublicKeyMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundOneMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundOneMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundTwoMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundTwoMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundThreeMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundThreeMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundFourMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundFourMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundFiveMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundFiveMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundSixMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundSixMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundSevenMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundSevenMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundEightMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundEightMessage{}).Unmarshal(data)
	})
}

func FuzzTssRoundNineMessageUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&tssRoundNineMessage{}).Unmarshal(data)
	})
}
