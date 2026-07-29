package tbtc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync/atomic"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/time/rate"

	"go.uber.org/zap"

	"github.com/ipfs/go-log/v2"
	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/clientinfo"
	"github.com/keep-network/keep-core/pkg/generator"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/announcer"
	"github.com/keep-network/keep-core/pkg/protocol/compatibility"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa/dkg"
)

const (
	// dkgStartedConfirmationBlocks determines the block length of the
	// confirmation period that is preserved after a DKG start. Once the period
	// elapses, the DKG state is checked to confirm the protocol can be started.
	dkgStartedConfirmationBlocks = 20
	// dkgResultSubmissionDelayStep determines the delay step in blocks that
	// is used to calculate the submission delay period that should be respected
	// by the given member to avoid all members submitting the same DKG result
	// at the same time.
	dkgResultSubmissionDelayStepBlocks = 3
	// dkgResultApprovalDelayStepBlocks determines the delay step in blocks
	// that is used to calculate the approval delay period that should be
	// respected by the given member to avoid all members approving the same
	// DKG result at the same time.
	dkgResultApprovalDelayStepBlocks = 15
	// dkgResultChallengeConfirmationBlocks determines the block length of
	// the confirmation period that is preserved after a DKG result challenge
	// submission. Once the period elapses, the DKG state is checked to confirm
	// the challenge was accepted successfully.
	dkgResultChallengeConfirmationBlocks = 20
	// dkgAttemptsLimit determines the maximum number of attempts to execute
	// the DKG protocol. If the limit is reached, the protocol execution is
	// aborted.
	dkgAttemptsLimit = 1
)

// dkgExecutor is a component responsible for the full execution of ECDSA
// Distributed Key Generation: determining members selected to the signing
// group, executing off-chain protocol, and publishing the result to the chain.
type dkgExecutor struct {
	groupParameters *GroupParameters

	operatorIDFn    func() (chain.OperatorID, error)
	operatorAddress chain.Address

	chain          Chain
	netProvider    net.Provider
	walletRegistry *walletRegistry
	protocolLatch  *generator.ProtocolLatch

	// waitForBlockFn is a function used to wait for the given block.
	waitForBlockFn waitForBlockFn

	tecdsaExecutor *dkg.Executor

	// metricsRecorder is optional and used for recording performance metrics
	metricsRecorder interface {
		IncrementCounter(name string, value float64)
		SetGauge(name string, value float64)
		RecordDuration(name string, duration time.Duration)
	}

	// cutoverPeerRoster is optional and, when set, records post-cutover legacy
	// peer sightings observed by the DKG announcer.
	cutoverPeerRoster *participation.CutoverPeerRoster

	// participationGate issues the per-member DKG participation permits that
	// pin the ceremony's protocol mode from its canonical chain anchor. It is
	// wired once during initialization, before any DKG event subscription
	// exists; joining DKG without it is refused fail-closed.
	participationGate participation.Gate

	// signerQuarantine preserves signer outputs whose activation the gate
	// refused before the wallet's on-chain registration was proven. Joining
	// DKG without it is refused fail-closed: a gate interruption after key
	// generation would otherwise have to drop the generated share.
	signerQuarantine *signerQuarantine

	// announcerMismatchLogLimiter bounds the volume of session-ID mismatch INFO
	// logs to a burst of 5 with one line every 30 seconds, matching the
	// observability contract. Metrics retain every event.
	announcerMismatchLogLimiter *rate.Limiter
}

func tbtcDKGPermitIdentity(
	seed *big.Int,
	memberIndex group.MemberIndex,
) participation.PermitIdentity {
	seedHash := sha256.Sum256(seed.Bytes())
	return participation.PermitIdentity{
		WorkID:   hex.EncodeToString(seedHash[:]),
		PermitID: fmt.Sprint(memberIndex),
	}
}

// newDkgExecutor creates a new instance of dkgExecutor struct. There should
// be only one instance of dkgExecutor.
func newDkgExecutor(
	groupParameters *GroupParameters,
	operatorIDFn func() (chain.OperatorID, error),
	operatorAddress chain.Address,
	chain Chain,
	netProvider net.Provider,
	walletRegistry *walletRegistry,
	protocolLatch *generator.ProtocolLatch,
	config Config,
	workPersistence persistence.BasicHandle,
	scheduler *generator.Scheduler,
	waitForBlockFn waitForBlockFn,
) *dkgExecutor {
	tecdsaExecutor := dkg.NewExecutor(
		logger,
		scheduler,
		workPersistence,
		config.PreParamsPoolSize,
		config.PreParamsGenerationTimeout,
		config.PreParamsGenerationDelay,
		config.PreParamsGenerationConcurrency,
		config.KeyGenerationConcurrency,
	)

	return &dkgExecutor{
		groupParameters:             groupParameters,
		operatorIDFn:                operatorIDFn,
		operatorAddress:             operatorAddress,
		chain:                       chain,
		netProvider:                 netProvider,
		walletRegistry:              walletRegistry,
		protocolLatch:               protocolLatch,
		tecdsaExecutor:              tecdsaExecutor,
		waitForBlockFn:              waitForBlockFn,
		announcerMismatchLogLimiter: rate.NewLimiter(rate.Every(30*time.Second), 5),
	}
}

// setMetricsRecorder sets the metrics recorder for the DKG executor.
func (de *dkgExecutor) setMetricsRecorder(recorder interface {
	IncrementCounter(name string, value float64)
	SetGauge(name string, value float64)
	RecordDuration(name string, duration time.Duration)
}) {
	de.metricsRecorder = recorder
}

// setCutoverPeerRoster sets the node-local cutover peer roster for the DKG
// executor.
func (de *dkgExecutor) setCutoverPeerRoster(roster *participation.CutoverPeerRoster) {
	de.cutoverPeerRoster = roster
}

// preParamsCount returns the current count of the ECDSA DKG pre-parameters.
func (de *dkgExecutor) preParamsCount() int {
	return de.tecdsaExecutor.PreParamsCount()
}

// executeDkgIfEligible is the main function of dkgExecutor. It performs the
// full execution of ECDSA Distributed Key Generation: determining members
// selected to the signing group, executing off-chain protocol, and publishing
// the result to the chain. The execution can be delayed by an arbitrary number
// of blocks using the delayBlocks argument. This allows confirming the state
// on-chain - e.g. wait for the required number of confirming blocks - before
// executing the off-chain action.
func (de *dkgExecutor) executeDkgIfEligible(
	seed *big.Int,
	startBlock uint64,
	delayBlocks uint64,
) {
	dkgLogger := logger.With(
		zap.String("seed", fmt.Sprintf("0x%x", seed)),
	)

	dkgLogger.Info("checking eligibility for DKG")
	memberIndexes, groupSelectionResult, err := de.checkEligibility(
		dkgLogger,
	)
	if err != nil {
		dkgLogger.Errorf("could not check eligibility for DKG: [%v]", err)
		return
	}

	if membersCount := len(memberIndexes); membersCount > 0 {
		if preParamsCount := de.tecdsaExecutor.PreParamsCount(); membersCount > preParamsCount {
			dkgLogger.Infof(
				"cannot join DKG as pre-parameters pool size is "+
					"too small; [%v] pre-parameters are required but "+
					"only [%v] available",
				membersCount,
				preParamsCount,
			)
			return
		}

		dkgLogger.Infof(
			"joining DKG and controlling [%v] group members",
			membersCount,
		)

		if de.metricsRecorder != nil {
			de.metricsRecorder.IncrementCounter(clientinfo.MetricDKGJoinedTotal, float64(membersCount))
		}

		de.generateSigningGroup(
			dkgLogger,
			seed,
			memberIndexes,
			groupSelectionResult,
			startBlock,
			delayBlocks,
		)
	} else {
		dkgLogger.Infof("not eligible for DKG")
	}
}

// checkEligibility performs on-chain group selection and returns two pieces
// of information:
//   - Indexes of members selected to the signing group and controlled by this
//     operator. The indexes are in range [1, `groupSize`]. The slice is nil if
//     none of the selected signing group members is controlled by this operator.
//   - Group selection result holding chain.OperatorID and chain.Address for
//     operators selected to the signing group. There are always `groupSize`
//     selected operators.
func (de *dkgExecutor) checkEligibility(
	dkgLogger log.StandardLogger,
) ([]uint8, *GroupSelectionResult, error) {
	groupSelectionResult, err := de.chain.SelectGroup()
	if err != nil {
		return nil, nil, fmt.Errorf("selecting group not possible: [%v]", err)
	}

	dkgLogger.Infof(
		"selected group members (seats) for DKG: [%s]",
		groupSelectionResult.OperatorsAddresses,
	)

	dkgLogger.Infof(
		"distinct operators participating in DKG: [%s]",
		maps.Keys(groupSelectionResult.OperatorsAddresses.Set()),
	)

	if len(groupSelectionResult.OperatorsAddresses) > de.groupParameters.GroupSize {
		return nil, nil, fmt.Errorf(
			"group size larger than supported: [%v]",
			len(groupSelectionResult.OperatorsAddresses),
		)
	}

	indexes := make([]uint8, 0)
	for index, operator := range groupSelectionResult.OperatorsAddresses {
		// See if we are amongst those chosen
		if operator == de.operatorAddress {
			// The group member index should be in range [1, groupSize] so we
			// need to add 1.
			indexes = append(indexes, uint8(index)+1)
		}
	}

	return indexes, groupSelectionResult, nil
}

// setupBroadcastChannel creates and initializes broadcast channel for the
// current DKG execution. It is a temporary channel named after the seed and
// the protocol name.
func (de *dkgExecutor) setupBroadcastChannel(
	seed *big.Int,
	membershipValidator *group.MembershipValidator,
) (net.BroadcastChannel, error) {
	// Create temporary broadcast channel name for DKG using the
	// group selection seed with the protocol name as prefix.
	channelName := fmt.Sprintf("%s-%s", ProtocolName, seed.Text(16))

	broadcastChannel, err := de.netProvider.BroadcastChannelFor(channelName)
	if err != nil {
		return nil, fmt.Errorf("failed to get broadcast channel: [%v]", err)
	}

	dkg.RegisterUnmarshallers(broadcastChannel)
	announcer.RegisterUnmarshaller(broadcastChannel)

	err = broadcastChannel.SetFilter(membershipValidator.IsInGroup)
	if err != nil {
		return nil, fmt.Errorf(
			"could not set filter for channel [%v]: [%v]",
			broadcastChannel.Name(),
			err,
		)
	}

	return broadcastChannel, nil
}

// generateSigningGroup executes off-chain protocol for each member controlled
// by the current operator and upon successful execution of the protocol
// publishes the result to the chain. The execution can be delayed by an
// arbitrary number of blocks using the delayBlocks argument. This allows
// confirming the state on-chain - e.g. wait for the required number of
// confirming blocks - before executing the off-chain action. Note that the
// startBlock represents the block at which DKG started on-chain. This is
// important for the result submission.
func (de *dkgExecutor) generateSigningGroup(
	dkgLogger *zap.SugaredLogger,
	seed *big.Int,
	memberIndexes []uint8,
	groupSelectionResult *GroupSelectionResult,
	startBlock uint64,
	delayBlocks uint64,
) {
	if de.participationGate == nil {
		// Without the gate no permit can pin the ceremony's protocol mode.
		// Fail closed.
		dkgLogger.Errorf("no participation gate; refusing to join DKG")
		return
	}
	if de.signerQuarantine == nil {
		// Without a quarantine store a gate interruption after key generation
		// would have to drop the generated share. Fail closed.
		dkgLogger.Errorf("no signer quarantine store; refusing to join DKG")
		return
	}

	membershipValidator := group.NewMembershipValidator(
		dkgLogger,
		groupSelectionResult.OperatorsAddresses,
		de.chain.Signing(),
	)

	broadcastChannel, err := de.setupBroadcastChannel(seed, membershipValidator)
	if err != nil {
		dkgLogger.Errorf("could not set up a broadcast channel: [%v]", err)
		return
	}

	dkgParameters, err := de.chain.DKGParameters()
	if err != nil {
		dkgLogger.Errorf("cannot get DKG parameters: [%v]", err)
		return
	}

	dkgTimeoutBlock := startBlock + dkgParameters.SubmissionTimeoutBlocks

	for _, index := range memberIndexes {
		// Capture the member index for the goroutine.
		memberIndex := index

		// One participation permit per locally controlled member, issued
		// immediately before the member goroutine. The permit pins the
		// protocol mode from the ceremony's canonical chain anchor — the DKG
		// started event block — for the ceremony's entire lifetime, including
		// every retry attempt. A refusal is a gate decision, not an ordinary
		// DKG failure.
		permit, err := de.participationGate.Begin(
			participation.TBTCDKG,
			startBlock,
			tbtcDKGPermitIdentity(seed, memberIndex),
		)
		if err != nil {
			dkgLogger.Warnf(
				"[member:%v] refused by the participation gate: [%v]",
				memberIndex,
				err,
			)
			continue
		}

		go func() {
			defer permit.Close()

			dkgStartTime := time.Now()
			de.protocolLatch.Lock()
			defer de.protocolLatch.Unlock()

			ctx, cancelCtx := withCancelOnBlock(
				permit.Context(),
				dkgTimeoutBlock,
				de.waitForBlockFn,
			)
			defer cancelCtx()

			// resultSubmitted records that a DKG result for this ceremony
			// reached the chain — submitted by this member or any other —
			// before the subscription canceled the publication context.
			// Activating the generated signer is conditioned on it: a
			// publication context that ends without a submitted result must
			// not leave an active signer behind.
			var resultSubmitted atomic.Bool

			// TODO: This subscription has to be updated once we implement
			//       re-submitting DKG result to the chain after a challenge.
			//       See https://github.com/keep-network/keep-core/issues/3450
			subscription := de.chain.OnDKGResultSubmitted(
				func(event *DKGResultSubmittedEvent) {
					resultSubmitted.Store(true)
					defer cancelCtx()

					dkgLogger.Infof(
						"[member:%v] DKG result with group public "+
							"key [0x%x] and result hash [0x%x] submitted "+
							"at block [%v] by member [%v]",
						memberIndex,
						event.Result.GroupPublicKey,
						event.ResultHash,
						event.BlockNumber,
						event.Result.SubmitterMemberIndex,
					)
				})
			defer subscription.Unsubscribe()

			// currentMode is the local node's protocol mode for this ceremony,
			// pinned in the participation permit. It classifies our own
			// announcement so the mismatch observer can tell legacy peers
			// apart from hardened ones during a coordinated cutover.
			currentMode := permit.Mode()
			// The compatibility strategy bundle carries the permit's mode
			// into every tECDSA party this ceremony constructs; each retry
			// attempt reuses it unchanged.
			strategies, err := compatibility.StrategiesFor(currentMode)
			if err != nil {
				dkgLogger.Errorf(
					"[member:%v] cannot select compatibility strategies: [%v]",
					memberIndex,
					err,
				)
				return
			}
			// operatorAddresses maps a sender's group member index (1-based) to
			// its operator address so a mismatch can be attributed to an
			// operator in the node-local cutover roster.
			operatorAddresses := groupSelectionResult.OperatorsAddresses
			sessionMismatchObserver := func(
				protocolID string,
				sender group.MemberIndex,
				expectedFormat announcer.SessionIDFormat,
				observedFormat announcer.SessionIDFormat,
			) {
				handleAnnouncerSessionMismatch(
					dkgLogger,
					de.announcerMismatchLogLimiter,
					de.metricsRecorder,
					de.cutoverPeerRoster,
					currentMode,
					operatorAddresses,
					protocolID,
					sender,
					expectedFormat,
					observedFormat,
				)
			}

			announcer := announcer.New(
				fmt.Sprintf("%v-%v", ProtocolName, "dkg"),
				broadcastChannel,
				membershipValidator,
				announcer.WithSessionMismatchObserver(sessionMismatchObserver),
			)

			retryLoop := newDkgRetryLoop(
				dkgLogger,
				seed,
				permit.Mode(),
				startBlock+delayBlocks,
				memberIndex,
				groupSelectionResult.OperatorsAddresses,
				de.groupParameters,
				announcer,
				dkgAttemptsLimit,
			)

			result, err := retryLoop.start(
				ctx,
				de.waitForBlockFn,
				func(attempt *dkgAttemptParams) (*dkg.Result, error) {
					dkgAttemptLogger := dkgLogger.With(
						zap.Uint("attempt", attempt.number),
						zap.Uint64("attemptStartBlock", attempt.startBlock),
						zap.Uint64("attemptTimeoutBlock", attempt.timeoutBlock),
					)

					dkgAttemptLogger.Infof(
						"[member:%v] scheduled dkg attempt "+
							"with [%v] group members (excluded: [%v])",
						memberIndex,
						de.groupParameters.GroupSize-len(attempt.excludedMembersIndexes),
						attempt.excludedMembersIndexes,
					)

					// Set up the attempt timeout signal.
					attemptCtx, _ := withCancelOnBlock(
						ctx,
						attempt.timeoutBlock,
						de.waitForBlockFn,
					)

					result, err := de.tecdsaExecutor.Execute(
						attemptCtx,
						dkgAttemptLogger,
						seed,
						attempt.sessionID,
						memberIndex,
						de.groupParameters.GroupSize,
						de.groupParameters.DishonestThreshold(),
						attempt.excludedMembersIndexes,
						broadcastChannel,
						membershipValidator,
						strategies,
					)
					if err != nil {
						dkgAttemptLogger.Errorf(
							"[member:%v] dkg attempt failed: [%v]",
							memberIndex,
							err,
						)

						return nil, err
					}

					return result, nil
				},
			)
			if err != nil {
				// A gate decision — clock failure, forced quiescence, or a
				// closed permit — is not an ordinary DKG failure and must not
				// increment the ordinary failure metrics.
				if cause := context.Cause(ctx); participation.IsGateRefusal(cause) {
					dkgLogger.Warnf(
						"[member:%v] DKG canceled by the participation "+
							"gate: [%v]",
						memberIndex,
						cause,
					)
					return
				}

				if de.metricsRecorder != nil {
					de.metricsRecorder.IncrementCounter(clientinfo.MetricDKGFailedTotal, 1)
					de.metricsRecorder.RecordDuration(clientinfo.MetricDKGDurationSeconds, time.Since(dkgStartTime))
				}
				if errors.Is(err, context.Canceled) {
					dkgLogger.Infof(
						"[member:%v] DKG is no longer awaiting the result; "+
							"aborting DKG protocol execution",
						memberIndex,
					)
					return
				}

				dkgLogger.Errorf(
					"[member:%v] failed to execute DKG: [%v]",
					memberIndex,
					err,
				)
				return
			}

			activated := de.completeDkgCeremony(
				ctx,
				dkgLogger,
				permit,
				seed,
				result,
				memberIndex,
				groupSelectionResult,
				resultSubmitted.Load,
				func(publishCtx context.Context) error {
					return de.publishDkgResult(
						publishCtx,
						dkgLogger,
						seed,
						memberIndex,
						broadcastChannel,
						membershipValidator,
						result,
						groupSelectionResult,
						startBlock,
						permit,
					)
				},
			)
			if activated && de.metricsRecorder != nil {
				// The ceremony completed end to end: result published,
				// activation fenced, signer active.
				de.metricsRecorder.RecordDuration(clientinfo.MetricDKGDurationSeconds, time.Since(dkgStartTime))
			}
		}()
	}
}

// completeDkgCeremony finalizes one member's DKG after key generation.
// Publication precedes activation: the generated share stays out of the
// active namespace and the wallet cache until the DKG result demonstrably
// reached the chain and the activation fence passed. A clock failure, forced
// quiescence, or a publication window that closes without a submitted result
// therefore never leaves an active signer for an unpublished result; every
// such outcome preserves the share through the interrupted-signer path
// instead of dropping or activating it. publishResultFn performs the result
// publication bound to the given context; resultSubmittedFn reports whether a
// submitted DKG result was observed on chain for this ceremony. It returns
// true only when the signer was activated.
func (de *dkgExecutor) completeDkgCeremony(
	ctx context.Context,
	dkgLogger log.StandardLogger,
	permit participation.Permit,
	seed *big.Int,
	result *dkg.Result,
	memberIndex group.MemberIndex,
	groupSelectionResult *GroupSelectionResult,
	resultSubmittedFn func() bool,
	publishResultFn func(context.Context) error,
) bool {
	err := publishResultFn(ctx)
	if err != nil {
		// The submission fence returns its sentinel as an ordinary error; a
		// permit cancellation surfaces as a plain context cancellation whose
		// gate cause is only in the context.
		refusal := err
		if !participation.IsGateRefusal(refusal) {
			refusal = context.Cause(ctx)
		}
		switch {
		case participation.IsGateRefusal(refusal):
			dkgLogger.Warnf(
				"[member:%v] DKG result publication refused by the release "+
					"gate; preserving the generated signer without "+
					"activation: [%v]",
				memberIndex,
				err,
			)
			de.preserveInterruptedSigner(
				dkgLogger,
				permit,
				seed,
				result,
				memberIndex,
				groupSelectionResult,
				"tbtc_dkg_result_publication",
				refusal,
			)
			return false
		case errors.Is(err, context.Canceled) && resultSubmittedFn():
			// The submission subscription observed the result on chain and
			// ended the publication; the ceremony completed and the signer
			// proceeds to activation.
			dkgLogger.Infof(
				"[member:%v] DKG result submitted by another member; "+
					"proceeding to signer activation",
				memberIndex,
			)
		default:
			// The publication window closed without an observed submitted
			// result, or publication failed outright. The wallet may never
			// appear on chain, so the share is preserved without activation
			// for the offline state audit to reconcile.
			dkgLogger.Errorf(
				"[member:%v] DKG result publication ended without a "+
					"submitted result; preserving the generated signer "+
					"without activation: [%v]",
				memberIndex,
				err,
			)
			de.preserveInterruptedSigner(
				dkgLogger,
				permit,
				seed,
				result,
				memberIndex,
				groupSelectionResult,
				"tbtc_dkg_result_publication",
				err,
			)
			return false
		}
	}

	// The last-moment fence before activating the newly generated key
	// material, consulted only after the result publication concluded. A
	// refusal — clock failure or process quiescence — preserves the share
	// without activating it: in the protected quarantine namespace normally,
	// or as a durable non-activated save when the wallet is already
	// registered on chain.
	if fenceErr := permit.CheckCommit(
		"tbtc_dkg_signer_activation",
		participation.CompletionCommit,
	); fenceErr != nil {
		de.preserveInterruptedSigner(
			dkgLogger,
			permit,
			seed,
			result,
			memberIndex,
			groupSelectionResult,
			"tbtc_dkg_signer_activation",
			fenceErr,
		)
		return false
	}

	signer, err := de.registerSigner(
		result,
		memberIndex,
		groupSelectionResult.OperatorsAddresses,
	)
	if err != nil {
		dkgLogger.Errorf(
			"[member:%v] failed to register signing group member; "+
				"preserving the generated signer without activation: [%v]",
			memberIndex,
			err,
		)
		de.preserveInterruptedSigner(
			dkgLogger,
			permit,
			seed,
			result,
			memberIndex,
			groupSelectionResult,
			"tbtc_dkg_signer_registration",
			err,
		)
		return false
	}

	dkgLogger.Infof("registered %s", signer)
	de.recordPermitTerminalOutcome(
		dkgLogger,
		permit,
		participation.TerminalOutcomeCompleted,
		participation.TerminalEvidence{
			Kind: participation.TerminalEvidencePersistedTBTCSinger,
			Reference: getWalletStorageKey(
				signer.wallet.publicKey,
			),
			MembershipIndex: signer.signingGroupMemberIndex,
		},
	)

	return true
}

// buildFinalSigner determines the final signing group shape and constructs
// the signer holding the generated key share. Note that the final group
// members may differ from the ones returned by the sortition pool if there
// was any misbehavior or inactivities during the key generation.
func (de *dkgExecutor) buildFinalSigner(
	result *dkg.Result,
	memberIndex group.MemberIndex,
	selectedSigningGroupOperators chain.Addresses,
) (*signer, error) {
	// Final signing group may differ from the original DKG
	// group outputted by the sortition protocol. One need to
	// determine the final signing group based on the selected
	// group members who behaved correctly during DKG protocol.
	operatingMemberIndexes := result.Group.OperatingMemberIndexes()
	finalSigningGroupOperators, finalSigningGroupMembersIndexes, err :=
		finalSigningGroup(
			selectedSigningGroupOperators,
			operatingMemberIndexes,
			de.groupParameters,
		)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve final signing group members")
	}

	// Just like the final and original group may differ, the
	// member index used during the DKG protocol may differ
	// from the final signing group member index as well.
	// We need to remap it.
	finalSigningGroupMemberIndex, ok :=
		finalSigningGroupMembersIndexes[memberIndex]
	if !ok {
		return nil, fmt.Errorf("failed to resolve final signing " +
			"group member index",
		)
	}

	return newSigner(
		result.PrivateKeyShare.PublicKey(),
		finalSigningGroupOperators,
		finalSigningGroupMemberIndex,
		result.PrivateKeyShare,
	), nil
}

// registerSigner determines the final signing group shape and persists the
// generated signer with a unique key share, activating it in the wallet
// cache.
func (de *dkgExecutor) registerSigner(
	result *dkg.Result,
	memberIndex group.MemberIndex,
	selectedSigningGroupOperators chain.Addresses,
) (*signer, error) {
	signer, err := de.buildFinalSigner(
		result,
		memberIndex,
		selectedSigningGroupOperators,
	)
	if err != nil {
		return nil, err
	}

	err = de.walletRegistry.registerSigner(signer)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to register %s: [%v]",
			signer,
			err,
		)
	}

	return signer, nil
}

// preserveInterruptedSigner durably preserves generated key material the
// release gate or a failed ceremony step kept from activating — a clock
// failure, process quiescence, or a publication that ended without a
// submitted result raced with the completing DKG. The share is never dropped
// and never activated by this process: when the wallet is already registered
// on chain the signer is saved to the active namespace without cache
// activation, so a restart's reconciliation can pick it up; otherwise it goes
// to the protected quarantine namespace that no release's active-wallet scan
// reads, for the offline state audit to reconcile. The operation names the
// ceremony step that was refused in the quarantine metadata.
func (de *dkgExecutor) preserveInterruptedSigner(
	dkgLogger log.StandardLogger,
	permit participation.Permit,
	seed *big.Int,
	result *dkg.Result,
	memberIndex group.MemberIndex,
	groupSelectionResult *GroupSelectionResult,
	operation string,
	fenceErr error,
) {
	signer, err := de.buildFinalSigner(
		result,
		memberIndex,
		groupSelectionResult.OperatorsAddresses,
	)
	if err != nil {
		dkgLogger.Errorf(
			"[member:%v] cannot build the interrupted signer; the generated "+
				"share is only in memory: [%v]",
			memberIndex,
			err,
		)
		return
	}

	walletRegistered := false
	walletID, err := de.chain.CalculateWalletID(signer.wallet.publicKey)
	if err == nil {
		walletRegistered, err = de.chain.IsWalletRegistered(walletID)
		if err != nil {
			// An unverifiable registration state is treated as unregistered:
			// quarantine preserves the share without exposing it to any
			// release's active scan.
			walletRegistered = false
		}
	}

	if walletRegistered {
		dkgLogger.Warnf(
			"[member:%v] signer activation withheld at [%s] but the wallet "+
				"is registered on chain; saving the signer without "+
				"activation: [%v]",
			memberIndex,
			operation,
			fenceErr,
		)
		if saveErr := de.walletRegistry.saveSigner(signer); saveErr != nil {
			dkgLogger.Errorf(
				"[member:%v] failed to save the interrupted signer; the "+
					"share is only in memory: [%v]",
				memberIndex,
				saveErr,
			)
		} else {
			de.recordPermitTerminalOutcome(
				dkgLogger,
				permit,
				participation.TerminalOutcomeCompleted,
				participation.TerminalEvidence{
					Kind: participation.TerminalEvidencePersistedTBTCSinger,
					Reference: getWalletStorageKey(
						signer.wallet.publicKey,
					),
					MembershipIndex: signer.signingGroupMemberIndex,
				},
			)
		}
		return
	}

	seedHash := sha256.Sum256(seed.Bytes())
	snapshot := de.participationGate.State()

	walletIDHex := ""
	if err == nil {
		walletIDHex = hex.EncodeToString(walletID[:])
	}

	dkgLogger.Warnf(
		"[member:%v] signer activation withheld at [%s]; quarantining the "+
			"generated signer: [%v]",
		memberIndex,
		operation,
		fenceErr,
	)

	if quarantineErr := de.signerQuarantine.preserve(
		signer,
		QuarantinedSignerMetadata{
			ReleaseEpoch:        participation.CompiledEpoch.String(),
			ProtocolMode:        permit.Mode().String(),
			CutoverBlock:        snapshot.CutoverBlock,
			CanonicalStartBlock: permit.CanonicalStartBlock(),
			Ceremony:            string(permit.Ceremony()),
			SeedHash:            hex.EncodeToString(seedHash[:]),
			WalletID:            walletIDHex,
			FailedOperation:     operation,
			LastObservedBlock:   snapshot.CurrentBlock,
		},
	); quarantineErr != nil {
		dkgLogger.Errorf(
			"[member:%v] failed to quarantine the interrupted signer; the "+
				"generated share is only in memory: [%v]",
			memberIndex,
			quarantineErr,
		)
	} else {
		de.recordPermitTerminalOutcome(
			dkgLogger,
			permit,
			participation.TerminalOutcomeQuarantined,
			participation.TerminalEvidence{
				Kind: participation.TerminalEvidenceQuarantinedTBTCSinger,
			},
		)
	}
}

func (de *dkgExecutor) recordPermitTerminalOutcome(
	dkgLogger log.StandardLogger,
	permit participation.Permit,
	outcome participation.TerminalOutcome,
	evidence participation.TerminalEvidence,
) {
	if err := permit.RecordTerminalOutcome(outcome, evidence); err != nil {
		dkgLogger.Warnf(
			"could not persist the node-authored DKG terminal outcome "+
				"[member=%s] [outcome=%s]: [%v]",
			permit.PermitID(),
			outcome,
			err,
		)
	}
}

// publishDkgResult performs the DKG result publication process. The commit
// guard fences the terminal on-chain submission.
func (de *dkgExecutor) publishDkgResult(
	ctx context.Context,
	dkgLogger log.StandardLogger,
	seed *big.Int,
	memberIndex group.MemberIndex,
	broadcastChannel net.BroadcastChannel,
	membershipValidator *group.MembershipValidator,
	dkgResult *dkg.Result,
	groupSelectionResult *GroupSelectionResult,
	startBlock uint64,
	commitGuard participation.CommitGuard,
) error {
	return dkg.Publish(
		ctx,
		dkgLogger,
		seed.Text(16),
		memberIndex,
		broadcastChannel,
		membershipValidator,
		newDkgResultSigner(de.chain, startBlock),
		newDkgResultSubmitter(
			dkgLogger,
			de.chain,
			de.groupParameters,
			groupSelectionResult,
			de.waitForBlockFn,
			commitGuard,
		),
		dkgResult,
	)
}

// executeDkgValidation performs the submitted DKG result validation process.
// If the result is not valid, this function submits an on-chain result
// challenge. If the result is valid and the given node was involved in the DKG,
// this function schedules an on-chain approve that is submitted once the
// challenge period elapses.
func (de *dkgExecutor) executeDkgValidation(
	seed *big.Int,
	submissionBlock uint64,
	result *DKGChainResult,
	resultHash [32]byte,
) {
	dkgLogger := logger.With(
		zap.String("seed", fmt.Sprintf("0x%x", seed)),
		zap.String("groupPublicKey", fmt.Sprintf("0x%x", result.GroupPublicKey)),
		zap.String("resultHash", fmt.Sprintf("0x%x", resultHash)),
	)

	dkgLogger.Infof("starting DKG result validation")

	if de.metricsRecorder != nil {
		de.metricsRecorder.IncrementCounter(clientinfo.MetricDKGValidationTotal, 1)
	}

	isValid, err := de.chain.IsDKGResultValid(result)
	if err != nil {
		dkgLogger.Errorf("cannot validate DKG result: [%v]", err)
		return
	}

	if !isValid {
		dkgLogger.Infof("DKG result is invalid")

		i := uint64(0)

		// Challenges are done along with DKG state confirmations. This is
		// needed to handle chain reorgs that may wipe out the block holding
		// the challenge transaction. The state check done upon the confirmation
		// block makes sure the submitted challenge changed the DKG state
		// as expected. If the DKG state was not changed, the challenge is
		// re-submitted.
		for {
			i++

			err = de.chain.ChallengeDKGResult(result)
			if err != nil {
				dkgLogger.Errorf(
					"cannot challenge invalid DKG result: [%v]",
					err,
				)
				return
			}

			if de.metricsRecorder != nil {
				de.metricsRecorder.IncrementCounter(clientinfo.MetricDKGChallengesSubmittedTotal, 1)
			}

			confirmationBlock := submissionBlock +
				(i * dkgResultChallengeConfirmationBlocks)

			dkgLogger.Infof(
				"challenging invalid DKG result; waiting for "+
					"block [%v] to confirm DKG state",
				confirmationBlock,
			)

			err := de.waitForBlockFn(context.Background(), confirmationBlock)
			if err != nil {
				dkgLogger.Errorf(
					"error while waiting for challenge confirmation: [%v]",
					err,
				)
				return
			}

			state, err := de.chain.GetDKGState()
			if err != nil {
				dkgLogger.Errorf("cannot check DKG state: [%v]", err)
				return
			}

			if state != Challenge {
				dkgLogger.Infof(
					"invalid DKG result challenged successfully",
				)
				return
			}

			dkgLogger.Infof(
				"invalid DKG result still not challenged; retrying",
			)
		}
	}

	dkgLogger.Infof("DKG result is valid")

	operatorID, err := de.operatorIDFn()
	if err != nil {
		dkgLogger.Errorf("cannot get node's operator ID: [%v]", err)
		return
	}

	// Determine the member indexes controlled by this node's operator.
	memberIndexes := make([]group.MemberIndex, 0)
	for index, memberOperatorID := range result.Members {
		if memberOperatorID == operatorID {
			// The group member index should be in range [1, groupSize] so we
			// need to add 1.
			memberIndexes = append(memberIndexes, group.MemberIndex(index+1))
		}
	}

	if len(memberIndexes) == 0 {
		dkgLogger.Infof(
			"not eligible for DKG result approval; my operator "+
				"ID [%v] is not among DKG participants [%v]",
			operatorID,
			result.Members,
		)
		return
	}

	dkgLogger.Infof("scheduling DKG result approval")

	parameters, err := de.chain.DKGParameters()
	if err != nil {
		dkgLogger.Errorf("cannot get current DKG parameters: [%v]", err)
		return
	}

	// The challenge period starts at the result submission block and lasts
	// for challengePeriodBlocks.
	challengePeriodEndBlock := submissionBlock + parameters.ChallengePeriodBlocks
	// The approval is possible one block after the challenge period end.
	// The result submitter has precedence for approvePrecedencePeriodBlocks.
	approvePrecedencePeriodStartBlock := challengePeriodEndBlock + 1
	// Everyone else can approve once the precedence period ends.
	approvePeriodStartBlock := approvePrecedencePeriodStartBlock +
		parameters.ApprovePrecedencePeriodBlocks

	for _, currentMemberIndex := range memberIndexes {
		go func(memberIndex group.MemberIndex) {
			var approveBlock uint64

			if memberIndex == result.SubmitterMemberIndex {
				// The submitter can approve earlier, during the precedence
				// period.
				approveBlock = approvePrecedencePeriodStartBlock
			} else {
				// Everyone else must approve after the precedence period ends.
				// Each member preserves a delay according to their index
				// to avoid simultaneous approval.
				delayBlocks := uint64(memberIndex-1) * dkgResultApprovalDelayStepBlocks
				approveBlock = approvePeriodStartBlock + delayBlocks
			}

			dkgLogger.Infof(
				"[member:%v] waiting for block [%v] to approve DKG result",
				memberIndex,
				approveBlock,
			)

			ctx, cancelCtx := context.WithCancel(context.Background())
			defer cancelCtx()

			subscription := de.chain.OnDKGResultApproved(
				func(event *DKGResultApprovedEvent) {
					cancelCtx()
				},
			)
			defer subscription.Unsubscribe()

			err := de.waitForBlockFn(ctx, approveBlock)
			if err != nil {
				dkgLogger.Errorf(
					"[member:%v] error while waiting for DKG result "+
						"approve block: [%v]",
					memberIndex,
					err,
				)
				return
			}

			// If the context got cancelled that means the result was approved
			// by someone else.
			if ctx.Err() != nil {
				dkgLogger.Infof(
					"[member:%v] DKG result approved by someone else",
					memberIndex,
				)
				return
			}

			err = de.chain.ApproveDKGResult(result)
			if err != nil {
				dkgLogger.Errorf(
					"[member:%v] cannot approve DKG result: [%v]",
					memberIndex,
					err,
				)
				return
			}

			if de.metricsRecorder != nil {
				de.metricsRecorder.IncrementCounter(clientinfo.MetricDKGApprovalsSubmittedTotal, 1)
			}

			dkgLogger.Infof("[member:%v] approving DKG result", memberIndex)
		}(currentMemberIndex)
	}
}

// finalSigningGroup takes three parameters:
//   - selectedOperators: Contains addresses of all selected operators. Slice
//     length equals to the groupSize. Each element with index N corresponds
//     to the group member with ID N+1.
//   - operatingMembersIndexes: Contains group members indexes that were neither
//     disqualified nor marked as inactive. Slice length is lesser than or equal
//     to the groupSize.
//   - chainConfig: The tBTC chain's configuration
//
// Using those parameters, this function transforms the selectedOperators
// slice into another slice that contains addresses of all operators
// that were neither disqualified nor marked as inactive. This way, the
// resulting slice has only addresses of properly operating operators
// who form the resulting group.
//
// Apart from that, this function returns a map that holds the final signing
// group members indexes that should be used by particular members who behaved
// correctly during the DKG protocol execution. The key of this map is the
// member index used during DKG protocol and the value is the new member
// index that should be used in the context of the final signing group.
//
// Example:
// selectedOperators: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
// operatingMembersIndexes: [5, 1, 3]
// finalOperators: [0xAA, 0xCC, 0xEE]
// finalMembersIndexes: [1:1, 3:2, 5:3]
//
// Please see docs of IdentityConverter from pkg/tecdsa/common for more
// information about shifting indexes.
func finalSigningGroup(
	selectedOperators []chain.Address,
	operatingMembersIndexes []group.MemberIndex,
	groupParameters *GroupParameters,
) (
	[]chain.Address,
	map[group.MemberIndex]group.MemberIndex,
	error,
) {
	if len(selectedOperators) != groupParameters.GroupSize ||
		len(operatingMembersIndexes) < groupParameters.GroupQuorum {
		return nil, nil, fmt.Errorf("invalid input parameters")
	}

	sort.Slice(operatingMembersIndexes, func(i, j int) bool {
		return operatingMembersIndexes[i] < operatingMembersIndexes[j]
	})

	finalOperators := make(
		[]chain.Address,
		len(operatingMembersIndexes),
	)
	finalMembersIndexes := make(
		map[group.MemberIndex]group.MemberIndex,
		len(operatingMembersIndexes),
	)

	for i, operatingMemberID := range operatingMembersIndexes {
		finalOperators[i] = selectedOperators[operatingMemberID-1]
		finalMembersIndexes[operatingMemberID] = group.MemberIndex(i + 1)
	}

	return finalOperators, finalMembersIndexes, nil
}
