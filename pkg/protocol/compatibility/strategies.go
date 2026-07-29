// Package compatibility bundles the per-ceremony cryptographic compatibility
// strategies of the coordinated protocol cutover. A ceremony participates
// with exactly one bundle — legacy or security-v2 — selected from its
// participation permit's pinned protocol mode, and every wire- and
// transcript-sensitive decision travels together inside that bundle: the
// announcement session-ID formats, the ECDH symmetric-key derivation, the
// G1 hash-to-point mapping, and the tECDSA proof-transcript configuration.
// Selecting these decisions individually is forbidden: switching only one of
// them would produce a partially legacy ceremony that interoperates with
// neither release.
//
// The bundles are stateless values and therefore immutable: nothing can
// mutate a bundle after selection, and nothing in this package reads the
// chain clock, a configuration file, or any global mode. Legacy strategies
// reproduce, byte for byte, the behavior of the pre-hardening production
// releases; security-v2 strategies reproduce the hardened behavior.
package compatibility

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/tss"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/pkg/altbn128"
	"github.com/keep-network/keep-core/pkg/crypto/ephemeral"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// minTSSSessionIDBytes mirrors the pinned tss-lib fork's minimum session-ID
// length: the fork hashes the session ID into the GG20 proof-binding nonce
// and panics below 16 bytes (128 bits), the birthday-bound minimum for
// collision resistance. The bundle validates the length up front so a
// malformed session ID surfaces as an error, not a panic inside the party.
const minTSSSessionIDBytes = 16

// Strategies is the immutable per-ceremony compatibility strategy bundle. All
// methods are pure functions of their inputs and the bundle's mode; a bundle
// carries no other state.
type Strategies interface {
	// Mode returns the protocol mode this bundle implements.
	Mode() participation.ProtocolMode

	// DKGSessionID returns the announcement/protocol session ID for one DKG
	// attempt over the given seed.
	DKGSessionID(seed *big.Int, attemptNumber uint) string

	// SigningSessionID returns the announcement/protocol session ID for one
	// signing attempt over the given message. The legacy format carries no
	// attempt start block; the parameter participates only in the security-v2
	// format.
	SigningSessionID(
		message *big.Int,
		attemptStartBlock uint64,
		attemptNumber uint,
	) string

	// ECDH derives the symmetric key for the given key pair. The info label
	// provides the security-v2 protocol/peer domain separation; the legacy
	// derivation has no domain separation by design and ignores it.
	ECDH(
		privateKey *ephemeral.PrivateKey,
		publicKey *ephemeral.PublicKey,
		info []byte,
	) *ephemeral.SymmetricEcdhKey

	// G1HashToPoint maps the given message onto a G1 point.
	G1HashToPoint(message []byte) *bn256.G1

	// ConfigureTSSParameters applies this bundle's tECDSA proof-transcript
	// decision to the given TSS parameters before any local party is
	// constructed from them. The security-v2 configuration binds the GG20
	// proof challenges to the ceremony's session ID; the legacy configuration
	// selects the historical untagged proof transcript. The applied setting is
	// immutable for the party's lifetime.
	ConfigureTSSParameters(parameters *tss.Parameters, sessionID string) error
}

// StrategiesFor returns the immutable strategy bundle for the given protocol
// mode. There is no default bundle: a mode that is not explicitly legacy or
// security-v2 is a programming error, because an implicit mode could silently
// produce a partially incompatible ceremony.
func StrategiesFor(mode participation.ProtocolMode) (Strategies, error) {
	switch mode {
	case participation.ModeLegacy:
		return legacyStrategies{}, nil
	case participation.ModeSecurityV2:
		return securityV2Strategies{}, nil
	default:
		return nil, fmt.Errorf(
			"no compatibility strategies for protocol mode [%v]: the mode "+
				"must be selected explicitly from a participation permit",
			mode,
		)
	}
}

// Legacy returns the legacy strategy bundle. It is a deliberate, explicit
// selection — never a fallback for an unset mode.
func Legacy() Strategies {
	return legacyStrategies{}
}

// SecurityV2 returns the security-v2 strategy bundle. It is a deliberate,
// explicit selection — never a fallback for an unset mode.
func SecurityV2() Strategies {
	return securityV2Strategies{}
}

// legacyStrategies reproduces, byte for byte, the wire- and
// transcript-sensitive behavior of the pre-hardening production releases.
type legacyStrategies struct{}

func (legacyStrategies) Mode() participation.ProtocolMode {
	return participation.ModeLegacy
}

func (legacyStrategies) DKGSessionID(
	seed *big.Int,
	attemptNumber uint,
) string {
	return fmt.Sprintf("%v-%v", seed.Text(16), attemptNumber)
}

func (legacyStrategies) SigningSessionID(
	message *big.Int,
	_ uint64,
	attemptNumber uint,
) string {
	return fmt.Sprintf("%v-%v", message.Text(16), attemptNumber)
}

func (legacyStrategies) ECDH(
	privateKey *ephemeral.PrivateKey,
	publicKey *ephemeral.PublicKey,
	_ []byte,
) *ephemeral.SymmetricEcdhKey {
	return privateKey.EcdhLegacy(publicKey)
}

func (legacyStrategies) G1HashToPoint(message []byte) *bn256.G1 {
	return altbn128.G1HashToPointLegacy(message)
}

func (legacyStrategies) ConfigureTSSParameters(
	parameters *tss.Parameters,
	_ string,
) error {
	if parameters == nil {
		return fmt.Errorf(
			"cannot configure TSS parameters: no parameters provided",
		)
	}

	parameters.SetProtocolMode(tss.ProtocolModeLegacy)
	return nil
}

// securityV2Strategies reproduces the hardened behavior of the security
// release.
type securityV2Strategies struct{}

func (securityV2Strategies) Mode() participation.ProtocolMode {
	return participation.ModeSecurityV2
}

func (securityV2Strategies) DKGSessionID(
	seed *big.Int,
	attemptNumber uint,
) string {
	return fmt.Sprintf("dkg-%v-%016x", seed.Text(16), attemptNumber)
}

func (securityV2Strategies) SigningSessionID(
	message *big.Int,
	attemptStartBlock uint64,
	attemptNumber uint,
) string {
	return fmt.Sprintf(
		"signing-%v-%016x-%016x",
		message.Text(16),
		attemptStartBlock,
		attemptNumber,
	)
}

func (securityV2Strategies) ECDH(
	privateKey *ephemeral.PrivateKey,
	publicKey *ephemeral.PublicKey,
	info []byte,
) *ephemeral.SymmetricEcdhKey {
	return privateKey.Ecdh(publicKey, info)
}

func (securityV2Strategies) G1HashToPoint(message []byte) *bn256.G1 {
	return altbn128.G1HashToPoint(message)
}

func (securityV2Strategies) ConfigureTSSParameters(
	parameters *tss.Parameters,
	sessionID string,
) error {
	if parameters == nil {
		return fmt.Errorf(
			"cannot configure TSS parameters: no parameters provided",
		)
	}
	if len(sessionID) < minTSSSessionIDBytes {
		return fmt.Errorf(
			"cannot bind GG20 proof challenges to session ID of [%d] bytes: "+
				"at least [%d] bytes are required",
			len(sessionID),
			minTSSSessionIDBytes,
		)
	}
	// Bind GG20 proof challenges to the existing protocol session.
	parameters.SetProtocolMode(tss.ProtocolModeSecurityV2)
	parameters.SetSessionNonceBytes([]byte(sessionID))
	return nil
}
