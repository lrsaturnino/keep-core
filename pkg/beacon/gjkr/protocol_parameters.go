package gjkr

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
)

// protocolParameters holds all cryptographic parameters that must be the same
// for all members in the group.
type protocolParameters struct {
	// `H = G*a` is a custom generator where `a` is unknown. It is used to
	// produce Pedersen commitments.
	H *bn256.G1
}

// newProtocolParameters creates a new instance of protocolParameters from the
// provided seed value which can be the previous random beacon's result.
// The seed is used to evaluate `H` parameter so that the discrete logarithm of
// `H` is unknown.
//
// The hash-to-point mapping deriving `H` is wire-sensitive: every member of a
// group must derive an identical `H`, so the mapping comes from the ceremony's
// compatibility strategy bundle and is fixed for the ceremony lifetime.
func newProtocolParameters(
	seed *big.Int,
	strategies compatibility.Strategies,
) *protocolParameters {
	return &protocolParameters{
		H: strategies.G1HashToPoint(seed.Bytes()),
	}
}
