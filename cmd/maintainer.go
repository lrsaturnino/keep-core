package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keep-network/keep-core/build"
	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/bitcoin/electrum"
	"github.com/keep-network/keep-core/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/maintainer"
	"github.com/keep-network/keep-core/pkg/maintainer/spv"
)

// MaintainerCommand contains the definition of the maintainer command-line
// subcommand.
var MaintainerCommand = &cobra.Command{
	Use:   "maintainer",
	Short: `(experimental) Starts maintainers`,
	Long:  `(experimental) The maintainer command starts maintainers`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if err := clientConfig.ReadConfig(
			configFilePath,
			cmd.Flags(),
			config.MaintainerCategories...,
		); err != nil {
			logger.Fatalf("error reading config: %v", err)
		}
	},
	RunE: maintainers,
}

func init() {
	initFlags(
		MaintainerCommand,
		&configFilePath,
		clientConfig,
		config.MaintainerCategories...,
	)
}

// maintainers initializes maintainer tasks specified by flags passed to the
// maintainer command.
func maintainers(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	btcChain, err := electrum.Connect(ctx, clientConfig.Bitcoin.Electrum)
	if err != nil {
		return fmt.Errorf("could not connect to Electrum chain: [%v]", err)
	}

	btcDiffChain, err := ethereum.ConnectBitcoinDifficulty(
		ctx,
		clientConfig.Ethereum,
		clientConfig.Maintainer,
	)
	if err != nil {
		return fmt.Errorf(
			"could not connect to Bitcoin difficulty chain: [%v]",
			err,
		)
	}

	_, tbtcChain, _, _, _, err := ethereum.Connect(
		ctx,
		clientConfig.Ethereum,
	)
	if err != nil {
		return fmt.Errorf(
			"could not connect to tBTC chain: [%v]",
			err,
		)
	}

	// Wire client-info metrics when the client-info endpoint is enabled (opt-in
	// via [clientInfo] Port / --clientInfo.port). The SPV maintainer records its
	// redemption-proof counters through the global recorder set here. When the
	// port is 0 the endpoint stays disabled and the recorder stays nil, so proof
	// submission is unaffected.
	if performanceMetrics := initializeMaintainerClientInfo(
		ctx,
		clientConfig,
		btcChain,
	); performanceMetrics != nil {
		spv.SetMetricsRecorder(performanceMetrics)
		defer func() {
			spv.SetMetricsRecorder(nil)
			performanceMetrics.Stop()
		}()
	}

	maintainer.Initialize(
		ctx,
		clientConfig.Maintainer,
		btcChain,
		btcDiffChain,
		tbtcChain,
	)

	<-ctx.Done()
	return fmt.Errorf("unexpected context cancellation")
}

// initializeMaintainerClientInfo enables the client-info metrics endpoint for
// the maintainer process when a client-info port is configured, and returns a
// PerformanceMetrics recorder wired into that endpoint. It registers the static
// client version information and Bitcoin connectivity that the maintainer has
// the dependencies for; the network/Ethereum peer sources wired by the start
// command are not applicable here. It returns nil when the endpoint is not
// configured (port 0), leaving metrics disabled and proof submission
// unaffected.
func initializeMaintainerClientInfo(
	ctx context.Context,
	config *config.Config,
	btcChain bitcoin.Chain,
) *clientinfo.PerformanceMetrics {
	registry, isConfigured := clientinfo.Initialize(ctx, config.ClientInfo.Port)
	if !isConfigured {
		logger.Infof("client info endpoint not configured")
		return nil
	}

	registry.RegisterMetricClientInfo(build.Version)

	registry.ObserveBtcConnectivity(
		btcChain,
		config.ClientInfo.BitcoinMetricsTick,
	)
	registry.RegisterBtcChainInfoSource(btcChain)

	performanceMetrics := clientinfo.NewPerformanceMetrics(ctx, registry)

	logger.Infof(
		"enabled client info endpoint on port [%v]",
		config.ClientInfo.Port,
	)

	return performanceMetrics
}
