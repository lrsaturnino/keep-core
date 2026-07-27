package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/keep-network/keep-core/pkg/tbtcpg"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/build"
	"github.com/keep-network/keep-core/pkg/bitcoin/electrum"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/storage"

	"github.com/spf13/cobra"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/beacon"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/firewall"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/net/libp2p"
	"github.com/keep-network/keep-core/pkg/net/retransmission"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tbtc"
)

// StartCommand contains the definition of the start command-line subcommand.
var StartCommand = &cobra.Command{
	Use:   "start",
	Short: "Starts the Keep Client",
	Long:  "Starts the Keep Client in the foreground",
	PreRun: func(cmd *cobra.Command, args []string) {
		if err := clientConfig.ReadConfig(configFilePath, cmd.Flags(), config.StartCmdCategories...); err != nil {
			logger.Fatalf("error reading config: %v", err)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := start(cmd); err != nil {
			logger.Fatal(err)
		}
	},
}

func init() {
	initFlags(StartCommand, &configFilePath, clientConfig, config.StartCmdCategories...)

	StartCommand.SetUsageTemplate(
		fmt.Sprintf(`%s
Environment variables:
    %s    Password for Keep operator account keyfile decryption.
    %s                 Space-delimited set of log level directives; set to "help" for help.
`,
			StartCommand.UsageString(),
			config.EthereumPasswordEnvVariable,
			config.LogLevelEnvVariable,
		),
	)
}

// start starts a node
func start(cmd *cobra.Command) error {
	// Two-context lifecycle: the gate and the cutover roster live on the root
	// context and are closed explicitly, while every protocol component
	// receives runCtx, which the signal controller cancels only after
	// quiescence has run its course. Handing protocol code an
	// already-canceled signal context would defeat graceful completion.
	ctx := context.Background()
	runCtx, cancelRunCtx := context.WithCancel(ctx)
	defer cancelRunCtx()

	// Resolve the protocol participation schedule before connecting anywhere:
	// these are configuration-only checks, and a misconfigured cutover block
	// must terminate startup before any component can send protocol traffic.
	participationSchedule, err := participation.ResolveAndValidate(
		clientConfig.Ethereum.Network,
		clientConfig.ProtocolParticipation,
	)
	if err != nil {
		return fmt.Errorf(
			"protocol participation schedule rejected: [%v]",
			err,
		)
	}

	cutoverBlockSource := "release_baked"
	if clientConfig.ProtocolParticipation.CutoverBlockSet {
		cutoverBlockSource = "non_mainnet_override"
	}
	logger.Infof(
		"protocol participation schedule resolved [version=%s] "+
			"[revision=%s] [epoch=%s] [cutoverBlock=%d] [source=%s] "+
			"[disabled=%t]",
		build.Version,
		build.Revision,
		participation.CompiledEpoch,
		participationSchedule.CutoverBlock,
		cutoverBlockSource,
		participationSchedule.Disabled(),
	)

	beaconChain, tbtcChain, blockCounter, signing, operatorPrivateKey, err :=
		ethereum.Connect(ctx, clientConfig.Ethereum)
	if err != nil {
		return fmt.Errorf("error connecting to Ethereum node: [%v]", err)
	}

	// The client-info registry and its chain-bound observers start first: the
	// participation gate and cutover roster constructed below need a real
	// metrics sink before the network provider exists. The network-bound
	// observers attach right after the network initializes.
	clientInfoRegistry := initializeClientInfo(runCtx, clientConfig, blockCounter)

	var perfMetrics *clientinfo.PerformanceMetrics
	if clientInfoRegistry != nil {
		perfMetrics = clientinfo.NewPerformanceMetrics(runCtx, clientInfoRegistry)

		// Wire performance metrics into firewall validation so live on-chain
		// IsRecognized calls are counted. The recorder is a package-level sink
		// read at validation time, so setting it before the network provider
		// is constructed loses no events.
		firewall.SetMetricsRecorder(perfMetrics)
	}

	// Construct the production participation gate and the cutover peer roster
	// from the shared block counter immediately after the Ethereum connection
	// and before the network provider, beacon, or tBTC can send protocol
	// traffic. The gate performs its first synchronous chain-clock read here
	// and a clock error refuses startup. With client-info disabled both record
	// to a no-op sink so their logs and state machines still function.
	var gateMetrics participation.GateMetricsRecorder
	if perfMetrics != nil {
		gateMetrics = perfMetrics
	} else {
		gateMetrics = &clientinfo.NoOpPerformanceMetrics{}
	}
	participationGate, err := participation.NewGate(
		ctx,
		participationSchedule,
		blockCounter,
		gateMetrics,
	)
	if err != nil {
		return fmt.Errorf("cannot construct the participation gate: [%v]", err)
	}
	defer participationGate.Close()

	rosterRetentionBlocks, err := tbtc.CutoverPeerRosterRetentionBlocks()
	if err != nil {
		return fmt.Errorf(
			"cannot derive cutover peer roster retention: [%v]",
			err,
		)
	}
	var rosterMetrics participation.CutoverRosterMetricsRecorder
	if perfMetrics != nil {
		rosterMetrics = perfMetrics
	} else {
		rosterMetrics = &clientinfo.NoOpPerformanceMetrics{}
	}
	cutoverRoster, err := participation.NewCutoverPeerRoster(
		ctx,
		blockCounter,
		rosterRetentionBlocks,
		rosterMetrics,
	)
	if err != nil {
		return fmt.Errorf("cannot create cutover peer roster: [%v]", err)
	}
	defer cutoverRoster.Close()

	if clientInfoRegistry != nil {
		// Expose the node-local cutover peer roster snapshot as a top-level
		// diagnostics object so port-enabled nodes surface which operators
		// are observed on the legacy release across the cutover.
		clientInfoRegistry.RegisterDiagnosticSource(
			"cutover_legacy_peers",
			func() string {
				snapshot := cutoverRoster.Snapshot()
				bytes, err := json.Marshal(snapshot)
				if err != nil {
					logger.Errorf(
						"error on serializing cutover peer roster to JSON: [%v]",
						err,
					)
					return ""
				}
				return string(bytes)
			},
		)
	}

	beaconCompletionBound, err := beacon.MaximumLegacyCompletionBlocks(
		beaconChain.GetConfig(),
	)
	if err != nil {
		return fmt.Errorf("cannot derive the beacon completion bound: [%v]", err)
	}
	maximumCompletionBound := tbtc.MaximumLegacyCompletionBlocks()
	if beaconCompletionBound > maximumCompletionBound {
		maximumCompletionBound = beaconCompletionBound
	}

	gateSnapshot := participationGate.State()
	logger.Infof(
		"protocol participation gate started [state=%s] [currentBlock=%d] "+
			"[cutoverBlock=%d] [revision=%s] [epoch=%s] "+
			"[maximumLegacyCompletionBlocks=%d] [source=%s]",
		gateSnapshot.State,
		gateSnapshot.CurrentBlock,
		gateSnapshot.CutoverBlock,
		build.Revision,
		participation.CompiledEpoch,
		maximumCompletionBound,
		cutoverBlockSource,
	)

	netProvider, err := initializeNetwork(
		runCtx,
		[]firewall.Application{beaconChain, tbtcChain},
		operatorPrivateKey,
		blockCounter,
	)
	if err != nil {
		return fmt.Errorf("cannot initialize network: [%v]", err)
	}

	registerNetworkClientInfo(clientConfig, clientInfoRegistry, netProvider, signing)

	if perfMetrics != nil {
		// Type assert to libp2p provider to set metrics recorder
		// The provider struct is not exported, so we use interface assertion
		if setter, ok := netProvider.(interface {
			SetMetricsRecorder(recorder interface {
				IncrementCounter(name string, value float64)
				SetGauge(name string, value float64)
				RecordDuration(name string, duration time.Duration)
			})
		}); ok {
			setter.SetMetricsRecorder(perfMetrics)
		}
	}

	// Initialize beacon and tbtc only for non-bootstrap nodes.
	// Skip initialization for bootstrap nodes as they are only used for network
	// discovery.
	if !isBootstrap() {
		btcChain, err := electrum.Connect(runCtx, clientConfig.Bitcoin.Electrum)
		if err != nil {
			return fmt.Errorf("could not connect to Electrum chain: [%v]", err)
		}

		beaconKeyStorePersistence,
			tbtcKeyStorePersistence,
			tbtcDataPersistence,
			err := initializePersistence()
		if err != nil {
			return fmt.Errorf("cannot initialize persistence: [%w]", err)
		}

		scheduler := generator.StartScheduler()

		if clientInfoRegistry != nil {
			clientInfoRegistry.ObserveBtcConnectivity(
				btcChain,
				clientConfig.ClientInfo.BitcoinMetricsTick,
			)

			clientInfoRegistry.RegisterBtcChainInfoSource(btcChain)

			rpcHealthChecker := clientinfo.NewRPCHealthChecker(
				clientInfoRegistry,
				blockCounter,
				btcChain,
				clientConfig.ClientInfo.RPCHealthCheckInterval,
			)
			rpcHealthChecker.Start(runCtx)
		}

		err = beacon.Initialize(
			runCtx,
			beaconChain,
			netProvider,
			beaconKeyStorePersistence,
			scheduler,
			participationGate,
		)
		if err != nil {
			return fmt.Errorf("error initializing beacon: [%v]", err)
		}

		proposalGenerator := tbtcpg.NewProposalGenerator(
			tbtcChain,
			btcChain,
		)

		err = tbtc.Initialize(
			runCtx,
			tbtcChain,
			btcChain,
			netProvider,
			tbtcKeyStorePersistence,
			tbtcDataPersistence,
			scheduler,
			proposalGenerator,
			clientConfig.Tbtc,
			clientInfoRegistry,
			perfMetrics, // Pass the existing performance metrics instance to avoid duplicate registrations
			clientConfig.Ethereum.Network,
			participationGate,
			cutoverRoster,
		)
		if err != nil {
			return fmt.Errorf("error initializing TBTC: [%v]", err)
		}
	}

	nodeHeader(
		netProvider.ConnectionManager().AddrStrings(),
		beaconChain.Signing().Address().String(),
		clientConfig.LibP2P.Port,
		clientConfig.Ethereum,
	)

	// The signal controller: on the first SIGTERM/SIGINT the gate refuses new
	// permits and existing ceremonies run to natural completion; the run
	// context is canceled only afterwards, so in-flight protocol work keeps
	// its network, chain, and persistence access for the whole drain. A
	// second signal or the in-process backstop deadline forces the remainder
	// through the gate's audited forced-cancellation path.
	signalChan := make(chan os.Signal, 2)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signalChan)

	select {
	case receivedSignal := <-signalChan:
		quiesceCause := fmt.Errorf("received signal [%v]", receivedSignal)
		quiesceDone := participationGate.Quiesce(quiesceCause)

		reason := awaitQuiesce(
			quiesceDone,
			signalChan,
			quiesceBackstopDeadline(maximumCompletionBound),
		)
		logger.Infof(
			"protocol participation quiescence ended [reason=%s] "+
				"[signal=%v]",
			reason,
			receivedSignal,
		)

		// Close force-cancels any permit that outlived the drain and stops
		// the clock supervisor; only then may the run context be canceled.
		participationGate.Close()
		cancelRunCtx()

		return fmt.Errorf(
			"shutting down the node after signal [%v]",
			receivedSignal,
		)
	case <-runCtx.Done():
		return fmt.Errorf("shutting down the node because its context has ended")
	}
}

// quiesceUpperBlockIntervalSeconds is the conservative upper bound on the
// Ethereum block interval used to convert the block-clock completion bound
// into the in-process wall-clock backstop. The release manifest derives the
// authoritative external termination grace from reviewed production evidence;
// this value only sizes the last-resort in-process deadline.
const quiesceUpperBlockIntervalSeconds = 15

// quiesceBackstopMargin absorbs RPC and processing skew on top of the
// block-derived backstop.
const quiesceBackstopMargin = 5 * time.Minute

// quiesceBackstopDeadline converts the maximum legacy completion bound into
// the in-process wall-clock backstop for the quiesce drain. The service
// manager's configured termination grace, derived in the release manifest,
// remains the authoritative external deadline; this backstop only guarantees
// the audited forced-cancellation path runs even if no second signal ever
// arrives.
func quiesceBackstopDeadline(completionBoundBlocks uint64) time.Duration {
	return time.Duration(completionBoundBlocks)*
		quiesceUpperBlockIntervalSeconds*time.Second +
		quiesceBackstopMargin
}

// awaitQuiesce waits for the quiesce drain to end and reports why: natural
// completion of every active permit, a second operator signal forcing
// shutdown, or the in-process backstop deadline.
func awaitQuiesce(
	quiesceDone <-chan struct{},
	signals <-chan os.Signal,
	backstop time.Duration,
) string {
	backstopTimer := time.NewTimer(backstop)
	defer backstopTimer.Stop()

	select {
	case <-quiesceDone:
		return "completed"
	case <-signals:
		return "forced_by_signal"
	case <-backstopTimer.C:
		return "backstop_deadline"
	}
}

func isBootstrap() bool {
	if clientConfig.LibP2P.Bootstrap {
		logger.Warnf("--network.bootstrap is deprecated and will be removed in a future release")
	}
	return clientConfig.LibP2P.Bootstrap
}

func initializeNetwork(
	ctx context.Context,
	applications []firewall.Application,
	operatorPrivateKey *operator.PrivateKey,
	blockCounter chain.BlockCounter,
) (net.Provider, error) {
	firewall := firewall.AnyApplicationPolicy(
		applications,
		firewall.EmptyAllowList(),
	)

	netProvider, err := libp2p.Connect(
		ctx,
		clientConfig.LibP2P,
		operatorPrivateKey,
		firewall,
		retransmission.NewTicker(blockCounter.WatchBlocks(ctx)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed while creating the network provider: [%v]", err)
	}

	return netProvider, nil
}

// initializeClientInfo starts the client-info registry and attaches the
// chain-bound observers. It runs before the network provider exists because
// the participation gate and cutover roster need its metrics sink from the
// first chain-clock read; the network-bound observers attach later through
// registerNetworkClientInfo.
func initializeClientInfo(
	ctx context.Context,
	config *config.Config,
	blockCounter chain.BlockCounter,
) *clientinfo.Registry {
	registry, isConfigured := clientinfo.Initialize(ctx, config.ClientInfo.Port)
	if !isConfigured {
		logger.Infof("client info endpoint not configured")
		return nil
	}

	registry.ObserveEthConnectivity(
		blockCounter,
		config.ClientInfo.EthereumMetricsTick,
	)

	registry.RegisterMetricClientInfo(build.Version)

	registry.RegisterEthChainInfoSource(blockCounter)

	logger.Infof(
		"enabled client info endpoint on port [%v]",
		config.ClientInfo.Port,
	)

	return registry
}

// registerNetworkClientInfo attaches the network-bound client-info observers
// once the network provider exists. It is a no-op when the client-info
// endpoint is not configured.
func registerNetworkClientInfo(
	config *config.Config,
	registry *clientinfo.Registry,
	netProvider net.Provider,
	signing chain.Signing,
) {
	if registry == nil {
		return
	}

	registry.ObserveConnectedPeersCount(
		netProvider,
		config.ClientInfo.NetworkMetricsTick,
	)

	registry.ObserveConnectedWellknownPeersCount(
		netProvider,
		config.LibP2P.Peers,
		config.ClientInfo.NetworkMetricsTick,
	)

	registry.RegisterConnectedPeersSource(netProvider, signing)

	registry.RegisterClientInfoSource(
		netProvider,
		signing,
		build.Version,
		build.Revision,
	)
}

func initializePersistence() (
	beaconKeyStorePersistence persistence.ProtectedHandle,
	tbtcKeyStorePersistence persistence.ProtectedHandle,
	tbtcDataPersistence persistence.BasicHandle,
	err error,
) {
	storage, err := storage.Initialize(
		clientConfig.Storage,
		clientConfig.Ethereum.KeyFilePassword,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot initialize storage: [%w]", err)
	}

	beaconKeyStorePersistence, err = storage.InitializeKeyStorePersistence(
		"beacon",
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"cannot initialize beacon keystore persistence: [%w]",
			err,
		)
	}

	tbtcKeyStorePersistence, err = storage.InitializeKeyStorePersistence(
		"tbtc",
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"cannot initialize tbtc keystore persistence: [%w]",
			err,
		)
	}

	tbtcDataPersistence, err = storage.InitializeWorkPersistence("tbtc")
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"cannot initialize tbtc data persistence: [%w]",
			err,
		)
	}

	return
}
