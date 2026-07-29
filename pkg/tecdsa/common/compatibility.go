package common

import (
	"github.com/bnb-chain/tss-lib/tss"

	"github.com/keep-network/keep-core/pkg/crypto/ephemeral"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// CompatibilityStrategies is the narrow view of the per-ceremony protocol
// compatibility bundle the tECDSA protocols require: the ECDH symmetric-key
// derivation and the proof-transcript configuration of the local TSS
// parties, pinned together to one protocol mode for the ceremony's entire
// lifetime. Every DKG and signing member construction takes the bundle
// explicitly — there is no default — so a ceremony can never mix modes or
// fall back to an implicit transcript. The production bundle is provided by
// the pkg/protocol/compatibility package; passing anything else is reserved
// for tests.
type CompatibilityStrategies interface {
	// Mode returns the protocol mode this bundle implements.
	Mode() participation.ProtocolMode

	// ECDH derives the symmetric key for the given key pair. The info label
	// provides the security-v2 protocol/peer domain separation; the legacy
	// derivation has no domain separation by design and ignores it.
	ECDH(
		privateKey *ephemeral.PrivateKey,
		publicKey *ephemeral.PublicKey,
		info []byte,
	) *ephemeral.SymmetricEcdhKey

	// ConfigureTSSParameters applies the bundle's proof-transcript decision
	// to the given TSS parameters before any local party is constructed from
	// them.
	ConfigureTSSParameters(parameters *tss.Parameters, sessionID string) error
}
