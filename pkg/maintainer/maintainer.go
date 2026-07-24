package maintainer

import (
	"context"
	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/maintainer/btcdiff"
	"github.com/keep-network/keep-core/pkg/maintainer/spv"
)

var logger = log.Logger("keep-maintainer")

func Initialize(
	ctx context.Context,
	config Config,
	btcChain bitcoin.Chain,
	btcDiffChain btcdiff.Chain,
	spvChain spv.Chain,
) {
	// If none of the maintainers was specified in the config (i.e. no option was
	// provided to the `maintainer` command), all maintainers should be launched.
	launchAll := !config.BitcoinDifficulty.Enabled &&
		!config.Spv.Enabled

	if launchAll {
		logger.Info("initializing all maintainer modules...")
	}

	if config.BitcoinDifficulty.Enabled || launchAll {
		btcdiff.Initialize(
			ctx,
			config.BitcoinDifficulty,
			btcChain,
			btcDiffChain,
		)
	}

	if config.Spv.Enabled || launchAll {
		spv.Initialize(
			ctx,
			config.Spv,
			spvChain,
			btcDiffChain,
			btcChain,
		)
	}

	// The blast radius of a panic here is this dedicated `keep-client
	// maintainer` process, which hosts the co-resident SPV and
	// Bitcoin-difficulty maintainers - not the separate `keep-client start`
	// beacon/tBTC operator. The SPV maintainer recovers panics per iteration
	// and restarts after a backoff (see spvMaintainer.runMaintainSpv), so a
	// panic in a single SPV iteration no longer terminates this process.
	//
	// TODO: Allow for launching multiple maintainers here. Every flag
	//       indicating a maintainer task should launch a separate maintainer.
	//       A panic in a maintainer without its own recovery boundary still
	//       terminates this process; extend per-iteration recovery to the
	//       other maintainers. Consider cancelling all maintainers if one
	//       maintainer cannot be launched due to a configuration error.
}
