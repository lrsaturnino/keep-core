package tbtc

import (
	"encoding/hex"
	"math/big"
	"sync"
	"sync/atomic"
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

	// Add the original parameters.
	canProcess := deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 500)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add with different seed.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(101), hash1, 500)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add with different result hash.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash2, 500)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add with different result block.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 501)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add with all different parameters.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(101), hash2, 501)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}

	// Add the original parameters before caching period elapses.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 500)
	if canProcess {
		t.Fatal("should not be allowed to process")
	}

	// Wait until caching period elapses.
	time.Sleep(testDKGResultHashCachePeriod)

	// Add the original parameters again.
	canProcess = deduplicator.notifyDKGResultSubmitted(big.NewInt(100), hash1, 500)
	if !canProcess {
		t.Fatal("should be allowed to process")
	}
}

// TestNotifyDKGStartedConcurrent is the F-13 TOCTOU regression test.
// Before F-13, notify*() did a Has()+Add() pair and two goroutines racing on
// the same key could both see Has() return false and both Add() the key,
// returning true from both calls. The fix relies on cache.TimeCache.Add()
// being mutex-serialized and returning true only for the first inserter.
// This test launches many goroutines that all race on the same key behind a
// barrier and asserts exactly one wins.
func TestNotifyDKGStartedConcurrent(t *testing.T) {
	const callers = 100

	dedup := deduplicator{
		dkgSeedCache: cache.NewTimeCache(testDKGSeedCachePeriod),
	}
	seed := big.NewInt(42)

	var wins int32
	var ready, start sync.WaitGroup
	ready.Add(callers)
	start.Add(1)

	results := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready.Done()
			start.Wait()
			results <- dedup.notifyDKGStarted(seed)
		}()
	}
	ready.Wait()
	start.Done()

	for i := 0; i < callers; i++ {
		if <-results {
			atomic.AddInt32(&wins, 1)
		}
	}
	if got := atomic.LoadInt32(&wins); got != 1 {
		t.Fatalf("F-13 regression: %d/%d concurrent notifyDKGStarted "+
			"calls returned true; want exactly 1", got, callers)
	}
}

func TestNotifyDKGResultSubmittedConcurrent(t *testing.T) {
	const callers = 100

	dedup := deduplicator{
		dkgResultHashCache: cache.NewTimeCache(testDKGResultHashCachePeriod),
	}
	hashBytes, err := hex.DecodeString(
		"92327ddff69a2b8c7ae787c5d590a2f14586089e6339e942d56e82aa42052cd9",
	)
	if err != nil {
		t.Fatal(err)
	}
	var hash [32]byte
	copy(hash[:], hashBytes)

	var wins int32
	var ready, start sync.WaitGroup
	ready.Add(callers)
	start.Add(1)

	results := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready.Done()
			start.Wait()
			results <- dedup.notifyDKGResultSubmitted(big.NewInt(100), hash, 500)
		}()
	}
	ready.Wait()
	start.Done()

	for i := 0; i < callers; i++ {
		if <-results {
			atomic.AddInt32(&wins, 1)
		}
	}
	if got := atomic.LoadInt32(&wins); got != 1 {
		t.Fatalf("F-13 regression: %d/%d concurrent notifyDKGResultSubmitted "+
			"calls returned true; want exactly 1", got, callers)
	}
}

func TestNotifyWalletClosedConcurrent(t *testing.T) {
	const callers = 100

	dedup := deduplicator{
		walletClosedCache: cache.NewTimeCache(testWalletClosedCachePeriod),
	}
	wallet := [32]byte{0x77}

	var wins int32
	var ready, start sync.WaitGroup
	ready.Add(callers)
	start.Add(1)

	results := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready.Done()
			start.Wait()
			results <- dedup.notifyWalletClosed(wallet)
		}()
	}
	ready.Wait()
	start.Done()

	for i := 0; i < callers; i++ {
		if <-results {
			atomic.AddInt32(&wins, 1)
		}
	}
	if got := atomic.LoadInt32(&wins); got != 1 {
		t.Fatalf("F-13 regression: %d/%d concurrent notifyWalletClosed "+
			"calls returned true; want exactly 1", got, callers)
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
