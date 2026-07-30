package tbtc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

// A wallet action takes one permit covering every seat this node holds in the
// wallet, so unlike a per-seat DKG or relay permit it cannot carry the seat in
// its identity. These tests cover the reader that supplies them instead, because
// a reader that under-reports leaves a seat outside the fleet's ownership map —
// and a seat outside that map is attributed to whatever other release is on the
// network.

// TestWalletSigningGroupSeats_NamesEverySeatTheRegistryHolds covers the case a
// per-seat identity cannot express: one node operating several seats of one
// wallet under one permit.
func TestWalletSigningGroupSeats_NamesEverySeatTheRegistryHolds(t *testing.T) {
	registry, walletPublicKey := newSeatTestRegistry(t, 9, 2, 5)
	node := &node{walletRegistry: registry}

	assertSeats(
		t,
		"the seats of a wallet this node holds three memberships in",
		node.walletSigningGroupSeats(walletPublicKey),
		[]group.MemberIndex{2, 5, 9},
	)
}

// TestWalletSigningGroupSeats_NamesNoSeatOfAnUnheldWallet is the honest empty
// answer, and it has to be empty rather than absent: a permit is still issued
// for the action, and a reader has to be able to tell "this node operated no
// seat here" from "this node was never asked".
func TestWalletSigningGroupSeats_NamesNoSeatOfAnUnheldWallet(t *testing.T) {
	registry, _ := newSeatTestRegistry(t, 1)
	node := &node{walletRegistry: registry}

	// A genuinely different wallet. The key-share fixtures are all shares of one
	// wallet key, so a second fixture would ask about the same wallet under
	// another name.
	otherKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := &otherKey.PublicKey

	if seats := node.walletSigningGroupSeats(other); len(seats) != 0 {
		t.Fatalf("a wallet this node holds no membership in named %v", seats)
	}
}

// TestWalletPermitIdentity_CarriesTheOperatedSeats holds the wiring itself: the
// seats have to reach the permit identity the gate validates, not merely be
// readable from the registry.
func TestWalletPermitIdentity_CarriesTheOperatedSeats(t *testing.T) {
	registry, walletPublicKey := newSeatTestRegistry(t, 4, 1)
	node := &node{walletRegistry: registry}

	identity := walletPermitIdentity(
		"wallet-action-1",
		walletPublicKey,
		1_000,
		node.walletSigningGroupSeats(walletPublicKey),
	)

	assertSeats(
		t,
		"the seats a wallet permit identity carries",
		identity.OperatedMembers,
		[]group.MemberIndex{1, 4},
	)
}

// newSeatTestRegistry returns a registry holding one wallet with the given
// signing group seats, registered as a node controlling all of them would.
func newSeatTestRegistry(
	t *testing.T,
	seats ...group.MemberIndex,
) (*walletRegistry, *ecdsa.PublicKey) {
	t.Helper()

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		t.Fatalf("failed to load test data: [%v]", err)
	}
	privateKeyShare := tecdsa.NewPrivateKeyShare(testData[0])

	registry, err := newWalletRegistry(
		&mockPersistenceHandle{},
		func(publicKey *ecdsa.PublicKey) ([32]byte, error) {
			return [32]byte{0x5c}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, seat := range seats {
		if err := registry.registerSigner(&signer{
			wallet: wallet{
				publicKey: privateKeyShare.PublicKey(),
				signingGroupOperators: []chain.Address{
					"address-1",
					"address-2",
					"address-3",
				},
			},
			signingGroupMemberIndex: seat,
			privateKeyShare:         privateKeyShare,
		}); err != nil {
			t.Fatalf("failed to register the signer of seat [%v]: [%v]", seat, err)
		}
	}

	return registry, privateKeyShare.PublicKey()
}

func assertSeats(
	t *testing.T,
	subject string,
	actual []group.MemberIndex,
	expected []group.MemberIndex,
) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Fatalf("%s are %v, expected %v", subject, actual, expected)
	}
	for i, seat := range expected {
		if actual[i] != seat {
			t.Fatalf("%s are %v, expected %v", subject, actual, expected)
		}
	}
}
