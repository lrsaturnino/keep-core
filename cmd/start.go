package cmd

import (
	"context"
	"fmt"
	"math"
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

	// Signal capture is installed before anything else so that no window of
	// the startup sequence is left to the default signal action: a signal
	// arriving before the participation gate exists is held in the buffered
	// channel and acted on the moment the lifecycle controller starts,
	// immediately after the gate is constructed.
	signalChan := make(chan os.Signal, 2)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signalChan)

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

	// The gate's quiescence capture is persisted in its own encrypted work
	// namespace. Initialize it before constructing the gate so even a signal
	// received during the rest of startup produces a node-authored inventory
	// in the storage snapshot later handed to the rollback audit.
	participationPersistence, err := initializeParticipationPersistence()
	if err != nil {
		return fmt.Errorf(
			"cannot initialize participation persistence: [%w]",
			err,
		)
	}
	quiescenceRecorder, err :=
		participation.NewPersistenceQuiescenceSnapshotRecorder(
			participationPersistence,
		)
	if err != nil {
		return fmt.Errorf(
			"cannot construct the quiescence snapshot recorder: [%w]",
			err,
		)
	}

	participationGate, err := participation.NewGate(
		ctx,
		participationSchedule,
		blockCounter,
		gateMetrics,
		participation.WithArtifactIdentity(build.Version, build.Revision),
		participation.WithQuiescenceSnapshotRecorder(quiescenceRecorder),
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
		participation.WithCutoverSchedule(participationSchedule),
	)
	if err != nil {
		return fmt.Errorf("cannot create cutover peer roster: [%v]", err)
	}
	defer cutoverRoster.Close()

	if clientInfoRegistry != nil {
		// The chain identity handed to the diagnostics contract is the
		// connected beacon chain itself, so every scrape reports the chain
		// this node actually reached rather than the one it was configured to
		// reach.
		participation.RegisterDiagnosticSources(
			clientInfoRegistry,
			participationGate,
			cutoverRoster,
			beaconChain,
			cutoverBlockSource,
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

	// The quiesce backstop is derived at startup with checked arithmetic: an
	// overflowing deadline calculation refuses startup instead of producing a
	// silently truncated grace period at shutdown time.
	quiesceBackstop, err := quiesceBackstopDeadline(maximumCompletionBound)
	if err != nil {
		return fmt.Errorf("cannot derive the quiesce backstop: [%v]", err)
	}

	// The lifecycle controller arms while only the gate and roster exist —
	// before the network provider, beacon, or tBTC can begin protocol work —
	// so a termination signal received at any later point of startup quiesces
	// the gate immediately instead of waiting for initialization to finish.
	shutdownChan := startSignalLifecycleController(
		runCtx,
		cancelRunCtx,
		participationGate,
		signalChan,
		quiesceBackstop,
		forcedCancellationAllowance(),
	)

	gateSnapshot := participationGate.State()
	logger.Infof(
		"protocol participation gate started [state=%s] [currentBlock=%d] "+
			"[cutoverBlock=%d] [revision=%s] [epoch=%s] "+
			"[maximumLegacyCompletionBlocks=%d] [quiesceMarginBlocks=%d] "+
			"[quiesceUpperBlockIntervalSeconds=%d] [quiesceBackstop=%s] "+
			"[source=%s]",
		gateSnapshot.State,
		gateSnapshot.CurrentBlock,
		gateSnapshot.CutoverBlock,
		build.Revision,
		participation.CompiledEpoch,
		maximumCompletionBound,
		quiesceReviewedMarginBlocks,
		quiesceUpperBlockIntervalSeconds,
		quiesceBackstop,
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
			beaconQuarantinePersistence,
			tbtcKeyStorePersistence,
			tbtcQuarantinePersistence,
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
			beaconQuarantinePersistence,
			scheduler,
			participationGate,
			gateMetrics,
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
			tbtcQuarantinePersistence,
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

	// The lifecycle controller has been driving signals since right after the
	// gate was constructed; from here the main goroutine only waits for its
	// shutdown report or for the run context to end for another reason.
	select {
	case err := <-shutdownChan:
		return err
	case <-runCtx.Done():
		// The controller sends its shutdown report before it cancels the run
		// context, so a pending report is always preferred over the bare
		// context end.
		select {
		case err := <-shutdownChan:
			return err
		default:
		}
		return fmt.Errorf("shutting down the node because its context has ended")
	}
}

// startSignalLifecycleController launches the signal-driven shutdown
// controller. It must be started as soon as the participation gate exists,
// before the network provider or either application can begin protocol work:
// the first SIGTERM/SIGINT — including one that arrives while startup is
// still initializing components — immediately quiesces the gate, so no new
// permit is issued from that moment on, while existing ceremonies run to
// natural completion. A second signal or the in-process backstop deadline
// forces the remainder through the gate's audited forced-cancellation path.
// That path is two-phase: Close cancels the permits that outlived the drain,
// and the controller then keeps the run context alive until their owners
// finish the cancellation cleanup — the quarantine and audit writes included
// — and release them, bounded by the reviewed forced-cancellation allowance.
// Only then is the shutdown cause reported and the run context canceled, so
// in-flight protocol work and its cleanup keep network, chain, and
// persistence access for the whole shutdown. The returned channel reports
// the shutdown cause once the drive completes.
func startSignalLifecycleController(
	runCtx context.Context,
	cancelRunCtx context.CancelFunc,
	gate participation.Gate,
	signals <-chan os.Signal,
	backstop time.Duration,
	cancellationAllowance time.Duration,
) <-chan error {
	shutdown := make(chan error, 1)

	go func() {
		select {
		case receivedSignal := <-signals:
			quiesceCause := fmt.Errorf("received signal [%v]", receivedSignal)
			quiesceDone := gate.Quiesce(quiesceCause)

			reason := awaitQuiesce(quiesceDone, signals, backstop)
			logger.Infof(
				"protocol participation quiescence ended [reason=%s] "+
					"[signal=%v]",
				reason,
				receivedSignal,
			)

			// Close force-cancels any permit that outlived the drain and
			// stops the clock supervisor. The canceled permits stay counted
			// until their owners finish the cancellation cleanup and release
			// them, and the gate reports that through its drained channel.
			gate.Close()

			// Phase two of the forced cancellation: join the owners of the
			// canceled permits before letting the process exit, so quarantine
			// and audit writes are never cut off mid-flight. The wait is
			// bounded by the reviewed forced-cancellation allowance — the
			// same wall-clock room the release manifest grants the service
			// manager between the in-process deadline and SIGKILL. After
			// natural completion the drained channel is already closed and
			// the wait returns immediately.
			cleanupReason := awaitForcedCancellationCleanup(
				gate.Drained(),
				cancellationAllowance,
			)
			if cleanupReason == cleanupReasonAllowanceExceeded {
				logger.Warnf(
					"protocol participation forced-cancellation cleanup did "+
						"not finish within the [%s] allowance; shutting down "+
						"with permits still held [signal=%v]",
					cancellationAllowance,
					receivedSignal,
				)
			} else {
				logger.Infof(
					"protocol participation forced-cancellation cleanup "+
						"ended [reason=%s] [signal=%v]",
					cleanupReason,
					receivedSignal,
				)
			}

			// The shutdown report is sent before the run context is canceled
			// so the report is already pending whenever the main goroutine
			// observes the context end.
			shutdown <- fmt.Errorf(
				"shutting down the node after signal [%v]",
				receivedSignal,
			)
			cancelRunCtx()
		case <-runCtx.Done():
			// The process is ending for another reason; there is no drain to
			// drive.
		}
	}()

	return shutdown
}

// quiesceUpperBlockIntervalSeconds is the conservative upper bound on the
// Ethereum block interval used to convert the block-clock completion bound
// into the in-process wall-clock backstop. The release manifest derives the
// authoritative external termination grace from reviewed production evidence;
// this value only sizes the last-resort in-process deadline.
const quiesceUpperBlockIntervalSeconds = 15

// quiesceReviewedMarginBlocks is the reviewed block margin added on top of the
// maximum legacy completion bound before the conversion to wall time: it
// absorbs chain-clock jitter and late block delivery around the completion
// bound so a ceremony finishing exactly at its protocol deadline is not
// force-canceled by the backstop. The release manifest records this margin
// beside the completion bound and the block-interval bound as the inputs of
// the external termination grace.
const quiesceReviewedMarginBlocks = uint64(100)

// quiesceBackstopMargin absorbs RPC and processing skew on top of the
// block-derived backstop.
const quiesceBackstopMargin = 5 * time.Minute

// quiesceBackstopDeadline converts the maximum legacy completion bound plus
// the reviewed block margin into the in-process wall-clock backstop for the
// quiesce drain, with every step overflow-checked. The service manager's
// configured termination grace, derived in the release manifest from the same
// inputs, remains the authoritative external deadline; this backstop only
// guarantees the audited forced-cancellation path runs even if no second
// signal ever arrives.
func quiesceBackstopDeadline(completionBoundBlocks uint64) (time.Duration, error) {
	totalBlocks := completionBoundBlocks + quiesceReviewedMarginBlocks
	if totalBlocks < completionBoundBlocks {
		return 0, fmt.Errorf(
			"quiesce backstop block bound overflows: completion bound [%d] "+
				"plus margin [%d]",
			completionBoundBlocks,
			quiesceReviewedMarginBlocks,
		)
	}

	totalSeconds := totalBlocks * quiesceUpperBlockIntervalSeconds
	if totalSeconds/quiesceUpperBlockIntervalSeconds != totalBlocks {
		return 0, fmt.Errorf(
			"quiesce backstop seconds overflow: [%d] blocks at [%d] "+
				"seconds per block",
			totalBlocks,
			quiesceUpperBlockIntervalSeconds,
		)
	}

	if totalSeconds > uint64(math.MaxInt64/time.Second) {
		return 0, fmt.Errorf(
			"quiesce backstop duration overflows: [%d] seconds",
			totalSeconds,
		)
	}
	backstop := time.Duration(totalSeconds) * time.Second

	if backstop > math.MaxInt64-quiesceBackstopMargin {
		return 0, fmt.Errorf(
			"quiesce backstop duration overflows with the [%s] margin",
			quiesceBackstopMargin,
		)
	}

	return backstop + quiesceBackstopMargin, nil
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

// The two ways the forced-cancellation cleanup wait can end: every canceled
// permit was released by its owner, or the reviewed allowance elapsed first.
const (
	cleanupReasonDrained           = "drained"
	cleanupReasonAllowanceExceeded = "allowance_exceeded"
)

// forcedCancellationAllowance is the wall-clock bound on the second phase of
// a forced shutdown: the time the controller keeps the process alive after
// canceling the remaining permits so their owners can finish quarantine and
// audit writes. It is the same compiled allowance the release manifest adds
// on top of the in-process backstop when deriving the service manager's
// termination grace — together with the compiled process-exit headroom that
// budgets the controller scheduling, quiesce and close calls, shutdown
// logging, and teardown running outside both in-process timers — so the
// external SIGKILL deadline, counted from signal delivery, always ends
// strictly after this wait does. Manifest validation rejects a manifest
// recording any other allowance, so a reviewed grace always budgets exactly
// this wait. Deliberately not a signal-escapable wait: an operator hammering
// the terminal must not be able to cut off key-material persistence.
func forcedCancellationAllowance() time.Duration {
	return time.Duration(compiledForcedCancellationAllowanceSeconds) *
		time.Second
}

// awaitForcedCancellationCleanup waits for the owners of force-canceled
// permits to finish their cancellation cleanup and release them, bounded by
// the reviewed forced-cancellation allowance, and reports which of the two
// ended the wait.
func awaitForcedCancellationCleanup(
	drained <-chan struct{},
	allowance time.Duration,
) string {
	allowanceTimer := time.NewTimer(allowance)
	defer allowanceTimer.Stop()

	select {
	case <-drained:
		return cleanupReasonDrained
	case <-allowanceTimer.C:
		return cleanupReasonAllowanceExceeded
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

	registry.RegisterMetricClientInfo(
		build.Version,
		build.Revision,
		participation.CompiledEpoch.String(),
	)

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
	beaconQuarantinePersistence persistence.ProtectedHandle,
	tbtcKeyStorePersistence persistence.ProtectedHandle,
	tbtcQuarantinePersistence persistence.ProtectedHandle,
	tbtcDataPersistence persistence.BasicHandle,
	err error,
) {
	storage, err := storage.Initialize(
		clientConfig.Storage,
		clientConfig.Ethereum.KeyFilePassword,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"cannot initialize storage: [%w]",
			err,
		)
	}

	beaconKeyStorePersistence, err = storage.InitializeKeyStorePersistence(
		"beacon",
	)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"cannot initialize beacon keystore persistence: [%w]",
			err,
		)
	}

	// The quarantine namespace is a sibling of the active beacon keystore, so
	// no release's active-group scan — which reads only the "beacon" directory
	// — can load a quarantined signer output as an active signer.
	beaconQuarantinePersistence, err = storage.InitializeKeyStorePersistence(
		"beacon-quarantine",
	)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"cannot initialize beacon quarantine persistence: [%w]",
			err,
		)
	}

	tbtcKeyStorePersistence, err = storage.InitializeKeyStorePersistence(
		"tbtc",
	)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"cannot initialize tbtc keystore persistence: [%w]",
			err,
		)
	}

	// The quarantine namespace is a sibling of the active tbtc keystore, so
	// no release's active-wallet scan — which reads only the "tbtc" directory
	// — can load a quarantined signer output as an active signer.
	tbtcQuarantinePersistence, err = storage.InitializeKeyStorePersistence(
		"tbtc-quarantine",
	)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"cannot initialize tbtc quarantine persistence: [%w]",
			err,
		)
	}

	tbtcDataPersistence, err = storage.InitializeWorkPersistence("tbtc")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"cannot initialize tbtc data persistence: [%w]",
			err,
		)
	}

	return
}

func initializeParticipationPersistence() (
	persistence.BasicHandle,
	error,
) {
	diskStorage, err := storage.Initialize(
		clientConfig.Storage,
		clientConfig.Ethereum.KeyFilePassword,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot initialize storage: [%w]",
			err,
		)
	}

	participationPersistence, err :=
		diskStorage.InitializeWorkPersistence("participation")
	if err != nil {
		return nil, fmt.Errorf(
			"cannot initialize participation work persistence: [%w]",
			err,
		)
	}

	return participationPersistence, nil
}
