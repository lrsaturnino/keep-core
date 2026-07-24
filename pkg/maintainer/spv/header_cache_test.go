package spv

import (
	"math/big"
	"testing"

	"github.com/keep-network/keep-core/pkg/bitcoin"
)

func TestBlockHeaderCache(t *testing.T) {
	header := func(h uint) *bitcoin.BlockHeader {
		return &bitcoin.BlockHeader{Bits: uint32(0x1d000000 + h)}
	}

	t.Run("repeated successful lookup hits the backend once", func(t *testing.T) {
		getter := newCountingHeaderGetter(
			func(h uint) (*bitcoin.BlockHeader, error) {
				return header(h), nil
			},
		)
		cache := newBlockHeaderCache(getter.get)

		first, err := cache.getBlockHeader(100)
		if err != nil {
			t.Fatal(err)
		}
		second, err := cache.getBlockHeader(100)
		if err != nil {
			t.Fatal(err)
		}

		if got := getter.totalCalls(); got != 1 {
			t.Fatalf("expected 1 backend call, got [%d]", got)
		}
		if first != second {
			t.Fatal("expected the same cached header value on repeated lookup")
		}
	})

	t.Run("distinct heights hit the backend once each", func(t *testing.T) {
		getter := newCountingHeaderGetter(
			func(h uint) (*bitcoin.BlockHeader, error) {
				return header(h), nil
			},
		)
		cache := newBlockHeaderCache(getter.get)

		if _, err := cache.getBlockHeader(100); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.getBlockHeader(101); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.getBlockHeader(100); err != nil {
			t.Fatal(err)
		}

		if got := getter.totalCalls(); got != 2 {
			t.Fatalf(
				"expected 2 backend calls for 2 distinct heights, got [%d]",
				got,
			)
		}
		if got := getter.callsAt(100); got != 1 {
			t.Fatalf("expected height 100 fetched once, got [%d]", got)
		}
		if got := getter.callsAt(101); got != 1 {
			t.Fatalf("expected height 101 fetched once, got [%d]", got)
		}
	})

	t.Run("errors are not cached", func(t *testing.T) {
		getter := newCountingHeaderGetter(
			func(h uint) (*bitcoin.BlockHeader, error) {
				return header(h), nil
			},
		)
		getter.failNext(100, 1)
		cache := newBlockHeaderCache(getter.get)

		if _, err := cache.getBlockHeader(100); err == nil {
			t.Fatal("expected an error on the first lookup")
		}
		got, err := cache.getBlockHeader(100)
		if err != nil {
			t.Fatalf("expected success on retry, got [%v]", err)
		}
		if got == nil {
			t.Fatal("expected a header on retry")
		}

		if calls := getter.callsAt(100); calls != 2 {
			t.Fatalf(
				"expected 2 backend calls (error not cached), got [%d]",
				calls,
			)
		}
	})
}

// TestGetProofInfoUsesPassHeaderCache proves that a single pass-scoped cache
// shared across transactions with overlapping proof windows fetches each
// distinct height from the backend exactly once, and that a fresh cache on the
// next pass refetches. It also pins that the cache imposes no proof-length cap:
// walks proceed unchanged, only their backend reads are deduplicated.
func TestGetProofInfoUsesPassHeaderCache(t *testing.T) {
	const proofStart = 790270

	txA, err := bitcoin.NewHashFromString(
		"44c568bc0eac07a2a9c2b46829be5b5d46e7d00e17bfb613f506a75ccf86a473",
		bitcoin.InternalByteOrder,
	)
	if err != nil {
		t.Fatal(err)
	}
	txB, err := bitcoin.NewHashFromString(
		"1111111111111111111111111111111111111111111111111111111111111111",
		bitcoin.InternalByteOrder,
	)
	if err != nil {
		t.Fatal(err)
	}

	localChain := newLocalChain()
	localChain.setTxProofDifficultyFactor(big.NewInt(6))
	localChain.setCurrentEpoch(392)
	localChain.setCurrentAndPrevEpochDifficulty(big.NewInt(32), big.NewInt(16))

	btcChain := newLocalBitcoinChain()
	// 20 headers of difficulty 32, so both transactions bind to the current
	// epoch and each needs 6 headers (6*32 = 192).
	if err := populateBlockHeaders(
		btcChain,
		proofStart,
		proofStart+19,
		func(uint) *big.Int { return big.NewInt(32) },
	); err != nil {
		t.Fatal(err)
	}
	// latestBlockHeight = proofStart+19 = 790289.
	// txA: 20 confirmations -> walks 790270..790275.
	// txB: 18 confirmations -> walks 790272..790277 (overlaps 790272..790275).
	// Distinct heights across both walks: 790270..790277 = 8.
	btcChain.addTransactionConfirmations(txA, 20)
	btcChain.addTransactionConfirmations(txB, 18)

	getter := newCountingHeaderGetter(btcChain.GetBlockHeader)

	proveWith := func(cache *blockHeaderCache, txHash bitcoin.Hash) {
		withinRange, _, required, err := getProofInfo(
			txHash,
			btcChain,
			localChain,
			localChain,
			cache,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !withinRange {
			t.Fatal("expected transaction proof within relay range")
		}
		if required != 6 {
			t.Fatalf("expected required confirmations 6, got [%d]", required)
		}
	}

	// One pass: both transactions share a single cache. The backend is hit once
	// per distinct height across the two overlapping walks.
	passCache := newBlockHeaderCache(getter.get)
	proveWith(passCache, txA)
	proveWith(passCache, txB)

	if got := getter.totalCalls(); got != 8 {
		t.Fatalf(
			"expected 8 backend calls for 8 distinct heights in one pass, "+
				"got [%d]",
			got,
		)
	}
	for h := uint(proofStart); h <= proofStart+7; h++ {
		if got := getter.callsAt(h); got != 1 {
			t.Fatalf(
				"expected height [%d] fetched once in the pass, got [%d]",
				h,
				got,
			)
		}
	}

	// A new pass uses a fresh cache and refetches the overlapping heights.
	nextPassCache := newBlockHeaderCache(getter.get)
	proveWith(nextPassCache, txA)

	if got := getter.totalCalls(); got != 14 {
		t.Fatalf(
			"expected 14 total backend calls after a second-pass refetch, "+
				"got [%d]",
			got,
		)
	}
	if got := getter.callsAt(proofStart); got != 2 {
		t.Fatalf(
			"expected height [%d] fetched once per pass (2 total), got [%d]",
			uint(proofStart),
			got,
		)
	}
	if got := getter.callsAt(proofStart + 7); got != 1 {
		t.Fatalf(
			"expected height [%d] fetched only in the first pass, got [%d]",
			uint(proofStart+7),
			got,
		)
	}
}

// TestProveTransactionsSharesHeaderCacheAcrossProofTypes proves that the single
// pass-scoped cache maintainSpv creates above the proofTypes loop
// (spv.go: newBlockHeaderCache before `for action, v := range proofTypes`) is
// shared across every proof type in a pass, not just across transactions within
// one proof type. It drives sm.proveTransactions once per simulated proof type
// with the same cache - exactly as maintainSpv does - and asserts each distinct
// height is fetched from the backend once across all proof types, then that the
// next pass's fresh cache refetches.
func TestProveTransactionsSharesHeaderCacheAcrossProofTypes(t *testing.T) {
	const proofStart = 790270

	// Two transactions with distinct hashes and overlapping proof windows, each
	// surfaced by a different proof type.
	depositSweepTx := &bitcoin.Transaction{Version: 1}
	redemptionTx := &bitcoin.Transaction{Version: 2}
	if depositSweepTx.Hash() == redemptionTx.Hash() {
		t.Fatal("expected the two fixtures to have distinct hashes")
	}

	localChain := newLocalChain()
	localChain.setTxProofDifficultyFactor(big.NewInt(6))
	localChain.setCurrentEpoch(392)
	localChain.setCurrentAndPrevEpochDifficulty(big.NewInt(32), big.NewInt(16))

	btcChain := newLocalBitcoinChain()
	if err := populateBlockHeaders(
		btcChain,
		proofStart,
		proofStart+19,
		func(uint) *big.Int { return big.NewInt(32) },
	); err != nil {
		t.Fatal(err)
	}
	// latestBlockHeight = 790289. depositSweepTx: 20 confirmations -> walks
	// 790270..790275; redemptionTx: 18 confirmations -> walks 790272..790277.
	// Distinct heights across both proof types: 790270..790277 = 8.
	btcChain.addTransactionConfirmations(depositSweepTx.Hash(), 20)
	btcChain.addTransactionConfirmations(redemptionTx.Hash(), 18)

	getter := newCountingHeaderGetter(btcChain.GetBlockHeader)

	sm := &spvMaintainer{
		config:       Config{HistoryDepth: 100, TransactionLimit: 10},
		spvChain:     localChain,
		btcDiffChain: localChain,
		btcChain:     btcChain,
	}

	// A getter standing in for one proof type's unproven-transactions source.
	proofTypeGetter := func(tx *bitcoin.Transaction) unprovenTransactionsGetter {
		return func(
			uint64,
			int,
			bitcoin.Chain,
			Chain,
		) ([]*bitcoin.Transaction, error) {
			return []*bitcoin.Transaction{tx}, nil
		}
	}
	noopSubmitter := func(
		bitcoin.Hash,
		uint,
		bitcoin.Chain,
		Chain,
	) error {
		return nil
	}

	runPass := func(cache *blockHeaderCache) {
		// Two proof types, one shared cache - the maintainSpv structure.
		if err := sm.proveTransactions(
			proofTypeGetter(depositSweepTx),
			noopSubmitter,
			cache,
		); err != nil {
			t.Fatalf("deposit-sweep proof type failed: %v", err)
		}
		if err := sm.proveTransactions(
			proofTypeGetter(redemptionTx),
			noopSubmitter,
			cache,
		); err != nil {
			t.Fatalf("redemption proof type failed: %v", err)
		}
	}

	passCache := newBlockHeaderCache(getter.get)
	runPass(passCache)

	if got := getter.totalCalls(); got != 8 {
		t.Fatalf(
			"expected 8 backend calls for 8 distinct heights shared across "+
				"proof types in one pass, got [%d]",
			got,
		)
	}
	for h := uint(proofStart); h <= proofStart+7; h++ {
		if got := getter.callsAt(h); got != 1 {
			t.Fatalf(
				"expected height [%d] fetched once across all proof types in "+
					"the pass, got [%d]",
				h,
				got,
			)
		}
	}

	// A new pass uses a fresh cache and refetches the shared heights.
	runPass(newBlockHeaderCache(getter.get))

	if got := getter.totalCalls(); got != 16 {
		t.Fatalf(
			"expected 16 total backend calls after the second pass refetch, "+
				"got [%d]",
			got,
		)
	}
}
