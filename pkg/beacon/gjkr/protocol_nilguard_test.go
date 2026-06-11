package gjkr

import (
	"math/big"
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// TestComputeGroupPublicKeyShares_MissingRevealedShare is regression coverage
// for the security-audit finding F-008. ComputeGroupPublicKeyShares runs in an
// unrecovered goroutine; when it falls into the reconstructed-share branch it
// computed ScalarBaseMult(shares.peerSharesS[operatingMemberID]) directly. If
// that map entry were missing, the *big.Int would be nil and ScalarBaseMult
// would panic, taking the whole beacon node down.
//
// The DKG disqualification invariants are expected to make this branch
// unreachable (a member that did not validly reveal its shares is evicted
// before this phase), so this is a DEFENSIVE guard, not a confirmed-reachable
// bug. The test only asserts the goroutine does not panic and completes (it
// does NOT assert the resulting share is correct -- a missing share cannot
// produce a correct share). Against the unpatched code the goroutine panics
// and crashes the test binary.
func TestComputeGroupPublicKeyShares_MissingRevealedShare(t *testing.T) {
	dishonestThreshold := 1
	groupSize := 3

	members, err := initializeCombiningMembersGroup(dishonestThreshold, groupSize)
	if err != nil {
		t.Fatal(err)
	}

	member := members[0]

	member.publicKeySharePoints = []*bn256.G2{
		new(bn256.G2).ScalarBaseMult(big.NewInt(10)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(11)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(12)),
	}

	member.receivedValidPeerPublicKeySharePoints[2] = []*bn256.G2{
		new(bn256.G2).ScalarBaseMult(big.NewInt(20)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(21)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(22)),
	}

	// Member 3 became inactive and its shares were revealed in phase 11, but
	// the revealed shares are MISSING the entry for operating member 2. This
	// drives ComputeGroupPublicKeyShares into the reconstructed-share branch
	// with shares.peerSharesS[2] == nil.
	member.group.MarkMemberAsInactive(3)
	delete(member.receivedValidPeerPublicKeySharePoints, 3)
	member.revealedMisbehavedMembersShares = []*misbehavedShares{{
		misbehavedMemberID: 3,
		peerSharesS:        map[group.MemberIndex]*big.Int{
			// intentionally empty: no entry for operating member 2
		},
	}}

	member.ComputeGroupPublicKeyShares()

	// The goroutine must complete and deliver a result rather than panicking.
	groupPublicKeyShares := <-member.groupPublicKeySharesChannel
	if groupPublicKeyShares == nil {
		t.Fatal("expected a (possibly incomplete) result, got nil")
	}
}
