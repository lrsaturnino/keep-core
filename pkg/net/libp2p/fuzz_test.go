package libp2p

// This fuzz target exercises identity.Unmarshal, which parses the
// message.Sender bytes of broadcast-channel envelopes. The parse runs
// BEFORE sender verification in processContainerMessage, so the input
// is fully attacker-controlled: proto unmarshaling, public-key
// unmarshaling, and peer-ID derivation all see raw peer bytes. The
// invariant under test is that Unmarshal never panics on arbitrary
// input: malformed bytes must return an error, not crash the process.

import (
	"crypto/rand"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

func FuzzIdentityUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x0a, 0x01})

	// A well-formed identity as a seed so coverage starts past the
	// proto envelope and into key/peer-ID parsing.
	privateKey, _, err := libp2pcrypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	validIdentity, err := createIdentity(privateKey)
	if err != nil {
		f.Fatal(err)
	}
	validBytes, err := validIdentity.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic on arbitrary input; an error return is correct.
		_ = (&identity{}).Unmarshal(data)
	})
}
