package tbtc

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/keep-network/keep-common/pkg/cache"
)

const (
	testDKGSeedCachePeriod       = 1 * time.Second
	testDKGResultHashCachePeriod = 1 * time.Second
	testWalletClosedCachePeriod  = 1 * time.Second
)

func TestNotifyDKGStarted(t *testing.T) {
	deduplicator := deduplicator{
		dkgSeedCache: cache.NewTimeCache(testDKGSeedCachePeriod),
	}

	seed1 := big.NewInt(100)
	seed2 := big.NewInt(200)

	// Add the first seed.
	canJoinDKG := deduplicator.notifyDKGStarted(seed1)
	if !canJoinDKG {
		t.Fatal("should be allowed to join DKG")
	}

	// Add the second seed.
	canJoinDKG = deduplicator.notifyDKGStarted(seed2)
	if !canJoinDKG {
		t.Fatal("should be allowed to join DKG")
	}

	// Add the first seed before caching period elapses.
	canJoinDKG = deduplicator.notifyDKGStarted(seed1)
	if canJoinDKG {
		t.Fatal("should not be allowed to join DKG")
	}

	// Wait until caching period elapses.
	time.Sleep(testDKGSeedCachePeriod)

	// Add the first seed again.
	canJoinDKG = deduplicator.notifyDKGStarted(seed1)
	if !canJoinDKG {
		t.Fatal("should be allowed to join DKG")
	}
}

func TestNotifyDKGResultSubmitted(t *testing.T) {
	deduplicator := deduplicator{
		dkgResultHashCache: cache.NewTimeCache(testDKGResultHashCachePeriod),
		inProgress:         make(map[string]bool),
	}

	hash1Bytes, err := hex.DecodeString("92327ddff69a2b8c7ae787c5d590a2f14586089e6339e942d56e82aa42052cd9")
	if err != nil {
		t.Fatal(err)
	}
	var hash1 [32]byte
	copy(hash1[:], hash1Bytes)

	hash2Bytes, err := hex.DecodeString("23c0062913c4614bdff07f94475ceb4c585df53f71611776c3521ed8f8785913")
	if err != nil {
		t.Fatal(err)
	}
	var hash2 [32]byte
	copy(hash2[:], hash2Bytes)

	// Claim and confirm the original parameters.
	canProcess := deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 500)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}
	deduplicator.confirmDKGResultSubmitted(big.NewInt(100), hash1, 500)

	// Different seed, different result hash, different result block, and
	// all-different parameters must be treated as independent events.
	for _, tc := range []struct {
		seed  *big.Int
		hash  [32]byte
		block uint64
	}{
		{big.NewInt(101), hash1, 500},
		{big.NewInt(100), hash2, 500},
		{big.NewInt(100), hash1, 501},
		{big.NewInt(101), hash2, 501},
	} {
		if !deduplicator.notifyDKGResultSubmitted(tc.seed, tc.hash, tc.block) {
			t.Fatalf("should be allowed to process seed [%v]", tc.seed)
		}
		deduplicator.confirmDKGResultSubmitted(tc.seed, tc.hash, tc.block)
	}

	// The original parameters are now a confirmed duplicate before the caching
	// period elapses.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 500)
	if canProcess {
		t.Fatal("should not be allowed to process")
	}

	// Wait until caching period elapses.
	time.Sleep(testDKGResultHashCachePeriod)

	// The original parameters can be processed again after expiry.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 500)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}
}

// TestNotifyDKGResultSubmitted_RetryOpenAfterAbort verifies that a DKG result
// submission whose handling did not complete (aborted) can be retried on a
// later redelivery, and that a confirmed one is dropped as a duplicate.
func TestNotifyDKGResultSubmitted_RetryOpenAfterAbort(t *testing.T) {
	deduplicator := deduplicator{
		dkgResultHashCache: cache.NewTimeCache(testDKGResultHashCachePeriod),
		inProgress:         make(map[string]bool),
	}

	var hash [32]byte
	seed := big.NewInt(100)
	block := uint64(500)

	// Claim the event for handling.
	if !deduplicator.notifyDKGResultSubmitted(seed, hash, block) {
		t.Fatal("first claim should be allowed to process")
	}

	// While the claim is in progress, a concurrent duplicate delivery must be
	// ignored.
	if deduplicator.notifyDKGResultSubmitted(seed, hash, block) {
		t.Fatal("in-progress event should not be claimable again")
	}

	// Handling failed, so the claim is released.
	deduplicator.abortDKGResultSubmitted(seed, hash, block)

	// A later redelivery of the same event must be allowed to retry, rather
	// than being dropped as an already-processed duplicate.
	if !deduplicator.notifyDKGResultSubmitted(seed, hash, block) {
		t.Fatal("event should be claimable again after an aborted attempt")
	}

	// Once handling completes successfully, further deliveries are duplicates.
	deduplicator.confirmDKGResultSubmitted(seed, hash, block)
	if deduplicator.notifyDKGResultSubmitted(seed, hash, block) {
		t.Fatal("confirmed event should not be claimable again")
	}
}

func TestNotifyWalletClosed(t *testing.T) {
	deduplicator := deduplicator{
		walletClosedCache: cache.NewTimeCache(testWalletClosedCachePeriod),
	}

	wallet1 := [32]byte{1}
	wallet2 := [32]byte{2}

	// Add the first wallet ID.
	canProcess := deduplicator.notifyWalletClosed(wallet1)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add the second wallet ID.
	canProcess = deduplicator.notifyWalletClosed(wallet2)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add the first wallet ID before caching period elapses.
	canProcess = deduplicator.notifyWalletClosed(wallet1)
	if canProcess {
		t.Fatal("should not be allowed to process")
	}

	// Wait until caching period elapses.
	time.Sleep(testWalletClosedCachePeriod)

	// Add the first wallet ID again.
	canProcess = deduplicator.notifyWalletClosed(wallet1)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}
}
