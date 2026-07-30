package tbtc

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-common/pkg/chain/ethereum"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// coordinationWatchRecordingChain records every reach for the chain clock the
// coordination layer watches windows on.
//
// The block counter is the first thing runCoordinationLayer asks the chain for,
// and nothing earlier in tBTC startup asks for it, so a read of it is the mark
// that the layer started.
type coordinationWatchRecordingChain struct {
	Chain

	blockCounterReads atomic.Int32
}

func (c *coordinationWatchRecordingChain) BlockCounter() (
	chain.BlockCounter,
	error,
) {
	c.blockCounterReads.Add(1)

	return c.Chain.BlockCounter()
}

// TestInitialize_UnreadableQuarantineStopsStartupBeforeCoordination proves a
// quarantine namespace that cannot be enumerated stops tBTC startup before the
// coordination layer installs a single block watcher.
//
// Failing closed after that layer is running is not failing closed. It watches
// coordination windows and launches coordination procedures, so a permit can be
// issued — and a ceremony begun — during a startup that has already established
// it must not proceed, on a host whose preserved key material nobody can count.
//
// The namespace also has to be read whether or not the client-info endpoint is
// configured: an unreadable quarantine is a fault in its own right, and a node
// that only notices it when metrics happen to be enabled starts over material
// nobody can account for. This startup is given no client-info registry for
// exactly that reason.
func TestInitialize_UnreadableQuarantineStopsStartupBeforeCoordination(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	localChain := Connect()
	blockCounter, err := localChain.BlockCounter()
	if err != nil {
		t.Fatal(err)
	}

	retention, err := CutoverPeerRosterRetentionBlocks()
	if err != nil {
		t.Fatal(err)
	}
	roster, err := participation.NewCutoverPeerRoster(
		ctx,
		blockCounter,
		retention,
		testGateMetrics{},
	)
	if err != nil {
		t.Fatal(err)
	}

	watchedChain := &coordinationWatchRecordingChain{Chain: localChain}

	err = Initialize(
		ctx,
		watchedChain,
		newLocalBitcoinChain(),
		local.Connect(),
		&mockPersistenceHandle{},
		&unreadableHandle{},
		&mockPersistenceHandle{},
		newTestScheduler(t),
		&mockCoordinationProposalGenerator{},
		Config{PreParamsPoolSize: 1, PreParamsGenerationTimeout: time.Hour},
		nil,
		nil,
		ethereum.Developer,
		newTestGate(t, blockCounter),
		roster,
	)
	if err == nil {
		t.Fatal(
			"an unreadable quarantine namespace must stop tBTC startup, not " +
				"leave the registered zero standing as the count",
		)
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("expected the underlying read error, got [%v]", err)
	}

	if reads := watchedChain.blockCounterReads.Load(); reads != 0 {
		t.Errorf(
			"a startup that failed closed still started the coordination "+
				"layer: [%d] block-counter reads",
			reads,
		)
	}
}
