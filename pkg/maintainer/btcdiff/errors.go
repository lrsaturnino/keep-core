package btcdiff

import "errors"

// ErrUniformPreRetargetDifficulty is returned when Bitcoin headers on the
// pre-retarget side of a relay proof disagree with the epoch anchor nBits.
// Honest proofs are impossible on unmodified LightRelay for some testnets (e.g.
// minimum-difficulty blocks inside a window).
var ErrUniformPreRetargetDifficulty = errors.New(
	"bitcoin pre-retarget headers do not match epoch anchor nBits",
)
