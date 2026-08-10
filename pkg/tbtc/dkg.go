package tbtc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"sync"
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

	// quarantineReportMutex serializes recounting the quarantine namespace and
	// publishing the count, so concurrently preserving members cannot leave an
	// older, lower count as the published one. It also guards the four fields
	// below.
	quarantineReportMutex sync.Mutex

	// preservedOutputFloor names the key material this process wrote to the
	// quarantine namespace itself and no successful scan has ruled on yet. The
	// namespace is the authority on how much preserved material a rollback has
	// to account for, but a scan that fails cannot take away what this process
	// knows it persisted, and the published count must never fall below that.
	// A scan that does succeed settles every entry — it enumerated the namespace
	// after each was written — so it empties this, and what the namespace still
	// held is carried by lastScannedOutputs instead.
	preservedOutputFloor map[quarantinedSigner]struct{}

	// lastScannedOutputs names what the last successful enumeration found. A
	// quarantined output outlives the process that wrote it, so the material
	// this process inherited is not its own to remember any other way, and
	// dropping it the moment a scan fails would leave everything an earlier
	// process preserved out of the count exactly when the namespace can no
	// longer be asked about it.
	lastScannedOutputs map[quarantinedSigner]struct{}

	// lastPublishedQuarantineCount is the count that currently stands, so a
	// failed recount can tell whether what it does know is already covered by
	// the published number.
	lastPublishedQuarantineCount int

	// incompleteQuarantineOutputs names preservation attempts that exhausted
	// their write-grace rounds and are still holding an output whose key
	// material and audit record are not both durable. It is guarded by
	// quarantineReportMutex and drives the live incomplete-output gauge. The
	// map key deduplicates repeated notifications for the same wallet seat.
	incompleteQuarantineOutputs map[quarantinedSigner]struct{}

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
		// The one DKG seat this permit runs. It is the ceremony's own index
		// space, not the final signing group's: the final group is not known
		// until the result is built, and the seats a reader needs in order to
		// tell which node was operating this ceremony are the ones it was
		// operating while it ran.
		OperatedMembers: participation.MemberIndexes{memberIndex},
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

			// resultSubmitted holds the DKG result this ceremony was seen to
			// settle on chain — submitted by this member or any other — before
			// the subscription canceled the publication context. Activating the
			// generated signer is conditioned on it: a publication context that
			// ends without a submitted result must not leave an active signer
			// behind.
			//
			// The event itself is kept rather than the fact that one arrived.
			// The key material about to be activated is this member's own, and
			// a result that settled for some other ceremony, or for some other
			// group, says nothing about it — so what settled has to be readable
			// where the generated result is, which is only after key generation
			// returns.
			var resultSubmitted atomic.Pointer[DKGResultSubmittedEvent]

			// TODO: This subscription has to be updated once we implement
			//       re-submitting DKG result to the chain after a challenge.
			//       See https://github.com/threshold-network/keep-core/issues/3450
			subscription := de.chain.OnDKGResultSubmitted(
				func(event *DKGResultSubmittedEvent) {
					resultSubmitted.Store(event)
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
					currentParticipationGateState(de.participationGate),
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
				func() bool {
					return dkgResultSettledLocalCeremony(
						dkgLogger,
						memberIndex,
						seed,
						result,
						resultSubmitted.Load(),
					)
				},
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

// dkgResultSettledLocalCeremony reports whether the DKG result observed to
// settle on chain is the one this member generated.
//
// Activation persists key material and enters it into the wallet cache under
// the final signing group the local result describes. Reading the subscription
// as nothing but "something settled" makes that a claim about a chain state
// nobody checked: an event for a different ceremony, or for a group rebuilt
// from a different membership, satisfies it equally, and the node then holds an
// active signer whose seat and whose wallet the chain does not agree with. That
// disagreement is exactly what the offline audit exists to find, and finding it
// afterwards is worse than not activating in the first place — so a mismatch
// falls through to the interrupted-signer path, which preserves the share
// without activating it and leaves the audit a record to reconcile.
//
// The three fields compared are the ones the wallet identity and the final
// group are derived from: the ceremony this result answers, the key it produced,
// and the members removed from the group that produced it.
func dkgResultSettledLocalCeremony(
	dkgLogger log.StandardLogger,
	memberIndex group.MemberIndex,
	seed *big.Int,
	result *dkg.Result,
	submitted *DKGResultSubmittedEvent,
) bool {
	if submitted == nil || submitted.Result == nil {
		return false
	}

	if seed == nil || submitted.Seed == nil ||
		seed.Cmp(submitted.Seed) != 0 {
		dkgLogger.Warnf(
			"[member:%v] observed a DKG result for seed [0x%x] while running "+
				"the ceremony for seed [0x%x]; not activating the generated "+
				"signer against another ceremony's result",
			memberIndex,
			submitted.Seed,
			seed,
		)
		return false
	}

	localGroupPublicKey, err := result.GroupPublicKeyBytes()
	if err != nil {
		dkgLogger.Errorf(
			"[member:%v] cannot read the generated group public key to "+
				"compare it with the submitted DKG result: [%v]",
			memberIndex,
			err,
		)
		return false
	}
	if !sameChainGroupPublicKey(
		localGroupPublicKey,
		submitted.Result.GroupPublicKey,
	) {
		dkgLogger.Warnf(
			"[member:%v] the DKG result submitted for this ceremony carries "+
				"group public key [0x%x] while this member generated [0x%x]; "+
				"not activating a signer for a wallet the chain does not have",
			memberIndex,
			submitted.Result.GroupPublicKey,
			localGroupPublicKey,
		)
		return false
	}

	localMisbehaved := result.MisbehavedMembersIndexes()
	if !slices.Equal(localMisbehaved, submitted.Result.MisbehavedMembersIndexes) {
		dkgLogger.Warnf(
			"[member:%v] the DKG result submitted for this ceremony removes "+
				"members %v while this member removed %v; the two describe "+
				"different final signing groups, so the generated signer is "+
				"not activated",
			memberIndex,
			submitted.Result.MisbehavedMembersIndexes,
			localMisbehaved,
		)
		return false
	}

	return true
}

// sameChainGroupPublicKey reports whether a locally marshaled group public key
// and one carried by a submitted DKG result are the same key.
//
// The Chain interface does not pin the encoding of the submitted key, and its
// implementations differ: the on-chain binding carries the 64-byte X||Y pair the
// registry stores, while the in-process chain carries the 65-byte uncompressed
// marshaling the local key produces. Both name one point, so the comparison is
// made on the coordinates the two share rather than on whichever prefix each
// happens to include.
func sameChainGroupPublicKey(local []byte, submitted []byte) bool {
	uncompressed := func(key []byte) []byte {
		if len(key) == 65 && key[0] == 4 {
			return key[1:]
		}
		return key
	}

	return bytes.Equal(uncompressed(local), uncompressed(submitted))
}

// completeDkgCeremony finalizes one member's DKG after key generation.
// Publication precedes activation: the generated share stays out of the
// active namespace and the wallet cache until the DKG result demonstrably
// reached the chain and the activation fence passed. A clock failure, forced
// quiescence, a publication window that closes without a submitted result, or
// a submitted result that is not the one this member generated therefore never
// leaves an active signer; every such outcome preserves the share through the
// interrupted-signer path instead of dropping or activating it.
// publishResultFn performs the result publication bound to the given context;
// resultSubmittedFn reports whether the result observed to settle on chain for
// this ceremony is this member's own. It returns true only when the signer was
// activated.
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
			Contribution:    dkgTranscriptContribution(signer, result),
		},
	)

	return true
}

// dkgTranscriptContribution renders the memberships that produced a DKG result,
// in the final signing group's own index space.
//
// The final signing group is built from exactly the DKG members this node saw
// operating: a member whose round messages did not arrive, or arrived without a
// valid membership behind them, was marked inactive and is absent from the final
// group. Every final membership therefore stands for a member whose
// contributions this node authenticated and combined into the key material it
// persisted — which is the local view of the transcript, and the only thing that
// distinguishes a key generated together with other parties from a persisted
// share whose provenance is one party's word.
//
// The index space is the final group's rather than the DKG's because the
// persisted membership this evidence names is a final index, and a transcript
// that mixed the two would join a result produced in one ceremony to a signer
// persisted from another.
//
// Because the permits for this ceremony are in the DKG's space, the transcript
// also carries the seat each final membership was rebuilt from. That mapping is
// the accepted result's own operating members, ascending, which is precisely the
// list finalSigningGroup positions the final group by — so entry i of it is the
// DKG seat that became final seat i+1.
func dkgTranscriptContribution(
	persistedSigner *signer,
	result *dkg.Result,
) *participation.TranscriptContribution {
	operatingMembers := result.Group.OperatingMemberIndexes()
	sort.Slice(operatingMembers, func(i, j int) bool {
		return operatingMembers[i] < operatingMembers[j]
	})

	finalGroupSize := len(persistedSigner.wallet.signingGroupOperators)

	incorporated := make(participation.MemberIndexes, 0, finalGroupSize)
	for seat := 1; seat <= finalGroupSize; seat++ {
		incorporated = append(incorporated, group.MemberIndex(seat))
	}

	return &participation.TranscriptContribution{
		IncorporatedMembers: incorporated,
		LocalMembers: participation.MemberIndexes{
			persistedSigner.signingGroupMemberIndex,
		},
		PermitSpaceMembers: participation.MemberIndexes(operatingMembers),
	}
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
		saveErr := de.walletRegistry.saveSigner(signer)
		if saveErr == nil {
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
					Contribution:    dkgTranscriptContribution(signer, result),
				},
			)
			return
		}

		// The active namespace refused the share, so the quarantine namespace is
		// tried rather than the share being dropped: it is a separate namespace
		// with its own failure modes, and a preserved share the audit reports as
		// unexpected is recoverable where a lost one is not. The recorded
		// operation says the active save was refused, so the audit reads the
		// record as what it is — a registered wallet's share that did not reach
		// the namespace a restart would load it from — rather than as an
		// ordinary pre-registration quarantine.
		dkgLogger.Errorf(
			"[member:%v] failed to save the interrupted signer for a "+
				"registered wallet; preserving it in the quarantine namespace "+
				"instead: [%v]",
			memberIndex,
			saveErr,
		)
		operation += "_after_refused_active_save"
	}

	seedHash := sha256.Sum256(seed.Bytes())
	snapshot := de.participationGate.State()

	walletIDHex := ""
	if err == nil {
		walletIDHex = hex.EncodeToString(walletID[:])
	}
	quarantineOutput := quarantinedSigner{
		walletStorageKey: getWalletStorageKey(signer.wallet.publicKey),
		memberIndex:      signer.signingGroupMemberIndex,
	}

	dkgLogger.Warnf(
		"[member:%v] signer activation withheld at [%s]; quarantining the "+
			"generated signer: [%v]",
		memberIndex,
		operation,
		fenceErr,
	)

	quarantineState, quarantineErr := de.signerQuarantine.preserve(
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
		quarantineObserver{
			// The published count follows the key material alone: a share the
			// namespace holds is material a rollback has to account for even
			// when the record explaining it did not land, and a share that
			// never reached the namespace is not quarantined however much was
			// written about it.
			//
			// It is taken here, at the moment the namespace accepts the share,
			// rather than from what preserve returns. A preservation whose
			// other half keeps being refused runs until the process ends, so
			// the return is not a moment this count can wait for.
			//
			// What runs here is only what this handoff can afford. The audit
			// record is written next, in this same round, and enumerating the
			// namespace between the two writes would put a namespace-wide read
			// on the path of the one write that turns preserved material into
			// explained material.
			keyMaterialPreserved: func() {
				de.accountForPreservedKeyMaterial(signer)
			},
			// Preservation keeps running behind this. It fires once the
			// namespace has refused a half for longer than a passing fault
			// would last, so the node stops taking new work while it is still
			// holding an output the namespace does not fully have.
			stillIncomplete: func(state quarantineState, cause error) {
				de.markIncompleteQuarantine(quarantineOutput)
				de.blockOnIncompleteQuarantine(
					dkgLogger,
					memberIndex,
					state,
					cause,
				)
			},
		},
	)

	// The observer above normally reports an incomplete output while Preserve
	// is still retrying. A failure before the retry loop begins — for example,
	// serialization failure — has no grace callback, and a process lifetime
	// that ends before grace can return without one too, so account for both
	// here. A completed retry removes the output from the live gauge; the
	// cumulative failure counter remains as history.
	if quarantineState.complete() {
		de.resolveIncompleteQuarantine(quarantineOutput)
	} else {
		de.markIncompleteQuarantine(quarantineOutput)
	}

	// The preservation is over, so the namespace can be read without holding a
	// write up behind it. What the write-time accounting published is a floor —
	// what this process can vouch for — and this is where it is reconciled
	// against what the namespace actually holds, which is the only reading that
	// can bring the count back down once a seat has been activated or an
	// operator has cleared a record.
	if quarantineState.keyMaterialPersisted() {
		de.reportQuarantinedSigners(dkgLogger)
	}

	// The terminal outcome, unlike the count, needs the whole output. The
	// audit record is what names the mode, canonical anchor, ceremony, seat, and
	// refused operation of the preserved share; without it the offline audit
	// cannot reconcile the material against the chain, so calling the permit
	// resolved would hand the rollback decision a quarantine nothing explains.
	// Either form the namespace took it whole in settles this — the record pair
	// or the single handoff carrying both. Anything less leaves the permit
	// unresolved, and the offline barrier keeps blocking on it until an operator
	// repairs the namespace.
	if !quarantineState.complete() {
		de.blockOnIncompleteQuarantine(
			dkgLogger,
			memberIndex,
			quarantineState,
			quarantineErr,
		)
		return
	}

	de.recordPermitTerminalOutcome(
		dkgLogger,
		permit,
		participation.TerminalOutcomeQuarantined,
		participation.TerminalEvidence{
			Kind: participation.TerminalEvidenceQuarantinedTBTCSinger,
		},
	)
}

// accountForPreservedKeyMaterial adds key material this process durably wrote
// to the count a rollback reads. It is called once the quarantine namespace is
// known to hold the share, which is the only condition it may be called under.
//
// The audit metadata may still be missing. The count is of preserved shares,
// and a share the namespace holds is one whether or not the record explaining
// it landed — leaving it out until the pair completes would under-report exactly
// the material a rollback most needs to find.
//
// The namespace is not enumerated here. This runs between the two writes of one
// preservation round, and a scan that hangs there would hold up the audit record
// the share still needs — the half whose absence leaves preserved material
// unexplained. What it publishes instead is the floor this process can vouch
// for without asking anyone: everything the last successful scan found plus
// everything written since. That floor is never above the truth, so the reading
// it leaves standing until the post-preservation recount cannot be an
// all-clear.
func (de *dkgExecutor) accountForPreservedKeyMaterial(signer *signer) {
	de.quarantineReportMutex.Lock()
	defer de.quarantineReportMutex.Unlock()

	if de.preservedOutputFloor == nil {
		de.preservedOutputFloor = make(map[quarantinedSigner]struct{})
	}
	// Keyed by wallet and seat, so preserving the same output twice — a retry,
	// a second interruption of the same seat — names it once rather than
	// counting the same share as two.
	de.preservedOutputFloor[quarantinedSigner{
		walletStorageKey: getWalletStorageKey(signer.wallet.publicKey),
		memberIndex:      signer.signingGroupMemberIndex,
	}] = struct{}{}

	de.publishKnownFloorLocked()
}

// markIncompleteQuarantine publishes a newly observed incomplete preservation.
// The normal call is the live grace-exhaustion observer; the return-time call
// covers failures that reached no observer. The counter records the first
// grace-exhaustion notification for an output while that output remains
// unresolved; repeated notifications for the same wallet seat coalesce in the
// live gauge. Resolution removes the seat, so a later incomplete episode for
// it is counted again. The gauge remains nonzero for as long as the output lacks
// either key material or its audit record.
func (de *dkgExecutor) markIncompleteQuarantine(
	output quarantinedSigner,
) {
	de.quarantineReportMutex.Lock()
	defer de.quarantineReportMutex.Unlock()

	if de.incompleteQuarantineOutputs == nil {
		de.incompleteQuarantineOutputs =
			make(map[quarantinedSigner]struct{})
	}
	if _, exists := de.incompleteQuarantineOutputs[output]; exists {
		return
	}

	de.incompleteQuarantineOutputs[output] = struct{}{}
	if de.metricsRecorder == nil {
		return
	}

	de.metricsRecorder.IncrementCounter(
		clientinfo.MetricParticipationTBTCQuarantinePreservationFailuresTotal,
		1,
	)
	de.metricsRecorder.SetGauge(
		clientinfo.MetricParticipationTBTCQuarantineIncompleteOutputs,
		float64(len(de.incompleteQuarantineOutputs)),
	)
}

// resolveIncompleteQuarantine clears the live incomplete-output signal only
// after preservation has made the whole output durable. An output still
// incomplete when the process lifetime ends deliberately remains nonzero in
// the last readable sample; the cumulative counter is never decremented.
func (de *dkgExecutor) resolveIncompleteQuarantine(
	output quarantinedSigner,
) {
	de.quarantineReportMutex.Lock()
	defer de.quarantineReportMutex.Unlock()

	if _, exists := de.incompleteQuarantineOutputs[output]; !exists {
		return
	}

	delete(de.incompleteQuarantineOutputs, output)
	if de.metricsRecorder != nil {
		de.metricsRecorder.SetGauge(
			clientinfo.MetricParticipationTBTCQuarantineIncompleteOutputs,
			float64(len(de.incompleteQuarantineOutputs)),
		)
	}
}

// blockOnIncompleteQuarantine stops this node from beginning new ceremonies
// while a preserved output is missing a half the namespace was supposed to hold.
//
// Either half missing leaves an inventory a rollback cannot reconcile. A share
// that reached no namespace exists only in the goroutine that generated it and
// nothing an operator or the offline audit can read accounts for it. A share
// preserved without its audit metadata is on disk but unexplained: the mode,
// canonical anchor, ceremony, seat, and refused operation that would let the
// audit match it against the chain are exactly what did not land. Taking on more
// work in either state builds further state on a host whose inventory is already
// known to be incomplete.
//
// Quiescence is the blocking state rather than a new one of its own: it refuses
// every new permit, it is already what the gate-state gauge and the quiesce
// counter report, and it lets the permits still running finish normally. It is
// one-way by design — an operator restarts the node once the namespace is
// repaired — which is also why the preservation behind it is given a grace
// budget first, so a namespace that clears on its own does not cost the fleet a
// node. No terminal outcome is recorded, so this permit closes unresolved and
// blocks the offline barrier on its own.
//
// The returned channel is deliberately ignored. This caller holds a permit of
// its own, so waiting for the active permit count to reach zero here would be
// waiting for itself.
func (de *dkgExecutor) blockOnIncompleteQuarantine(
	dkgLogger log.StandardLogger,
	memberIndex group.MemberIndex,
	state quarantineState,
	cause error,
) {
	if state.keyMaterialPersisted() {
		dkgLogger.Errorf(
			"[member:%v] the quarantined signer has no audit record "+
				"explaining it; the share is preserved but a rollback cannot "+
				"reconcile it without the record; refusing new ceremonies on "+
				"this node until an operator repairs the quarantine "+
				"namespace: [%v]",
			memberIndex,
			cause,
		)
	} else {
		dkgLogger.Errorf(
			"[member:%v] generated key material reached no namespace; the "+
				"share is only in memory [auditMetadataPreserved=%v]; "+
				"refusing new ceremonies on this node until an operator "+
				"resolves the quarantine namespace: [%v]",
			memberIndex,
			state.metadataPersisted,
			cause,
		)
	}

	if de.participationGate == nil {
		return
	}

	de.participationGate.Quiesce(fmt.Errorf(
		"tbtc key material could not be preserved with its audit record: [%w]",
		cause,
	))
}

// reportQuarantinedSigners publishes how many preserved signer outputs this
// process is holding without having activated them.
//
// The value is recounted from the namespace on every call rather than tracked as
// this process's own tally of preservations. A quarantined output outlives the
// process that wrote it: the count a rollback decision needs is of everything
// preserved on this host, and a tally that starts at zero every restart reports
// none of what an earlier one left behind. Recounting also keeps the comparison
// honest in the other direction — an output whose seat this process did activate
// from the active namespace stops being counted, which a tally could not
// express.
//
// Recount and publication are serialized. Concurrent members of the same
// ceremony quarantine independently, and two interleaved scans could otherwise
// publish out of order, leaving the older, lower count as the last word — the
// direction that reads as an all-clear.
func (de *dkgExecutor) reportQuarantinedSigners(dkgLogger log.StandardLogger) {
	if err := de.publishQuarantinedSignerCount(); err != nil {
		// The last published count stands. Publishing a zero here would say the
		// namespace is empty, which is precisely what could not be established.
		dkgLogger.Errorf(
			"cannot count the quarantined signer outputs; the reported count "+
				"stays as last published: [%v]",
			err,
		)
	}
}

// reportInitialQuarantinedSigners publishes the count this process starts with
// and refuses to start when the namespace cannot be enumerated.
//
// Keeping the last published count is the right answer at runtime because there
// is one: a scan that fails after an earlier scan succeeded leaves a number
// somebody published. At startup there is none. The gauge is registered at zero
// with the rest of the fixed family, so a startup scan that gives up quietly
// leaves that zero as this process's first and only word on the subject, and a
// rollback decision reads it as nothing left to account for — the one answer
// the count must never invent.
//
// So the failure is raised to the caller rather than logged. A node that will
// not start is a visible fault an operator resolves against a namespace whose
// contents are still on disk; a node that starts and reports an empty
// quarantine is an invisible one.
func (de *dkgExecutor) reportInitialQuarantinedSigners() error {
	if err := de.publishQuarantinedSignerCount(); err != nil {
		return fmt.Errorf(
			"cannot count the quarantined signer outputs this process "+
				"starts with: [%w]",
			err,
		)
	}

	return nil
}

// publishQuarantinedSignerCount recounts the namespace and publishes how many
// preserved outputs this process holds without having activated them. How the
// caller treats a namespace it cannot enumerate is what tells a startup apart
// from a later recount, so that failure is returned rather than decided here.
//
// A failed scan still publishes when this process knows more than the standing
// count does. The namespace is the authority on the total, but what a scan
// already found and what this process wrote itself are not in doubt: a share
// held and not activated stays held whatever the namespace can be read to say.
// Without that floor, a startup that published zero followed by a first
// post-write scan that failed would leave the zero standing over a namespace
// holding key material — the one answer the count must never invent.
//
// The namespace is enumerated whether or not a recorder is configured. An
// unreadable quarantine is a fault in its own right, and a node that only
// notices it when the client-info endpoint happens to be enabled would start
// over preserved material nobody can account for.
func (de *dkgExecutor) publishQuarantinedSignerCount() error {
	if de.signerQuarantine == nil {
		return nil
	}

	de.quarantineReportMutex.Lock()
	defer de.quarantineReportMutex.Unlock()

	outputs, err := de.signerQuarantine.preservedOutputs()
	if err != nil {
		de.publishKnownFloorLocked()

		return err
	}

	de.lastScannedOutputs = make(map[quarantinedSigner]struct{}, len(outputs))
	for _, output := range outputs {
		de.lastScannedOutputs[output] = struct{}{}
	}

	// The floor exists to name what this process wrote and no scan has ruled on
	// yet. This scan ruled on all of it: every entry was added after the
	// namespace had taken the record, and this enumeration ran later still,
	// under the same lock, so the namespace was asked about every one of them.
	// Whatever it did not answer for — a seat an operator activated, a record
	// they cleared — is gone, and keeping the identity would let the next failed
	// scan union it back in and raise the count over an output that no longer
	// exists.
	de.preservedOutputFloor = nil

	de.publishQuarantineCountLocked(de.withheldCount(outputs))

	return nil
}

// publishKnownFloorLocked publishes what this process can still account for
// without reading the namespace, when the namespace is what it could not read.
// The caller must hold quarantineReportMutex.
//
// It only ever raises the count. A floor is a lower bound — the namespace may
// hold outputs neither the last scan nor this process saw — so letting it lower
// a higher standing count would turn what could not be established into a
// smaller number somebody reads as progress.
func (de *dkgExecutor) publishKnownFloorLocked() {
	if floor := de.withheldCount(
		de.knownOutputsLocked(),
	); floor > de.lastPublishedQuarantineCount {
		de.publishQuarantineCountLocked(floor)
	}
}

// withheldCount counts the preserved outputs whose seat this process has not
// activated from the active namespace. An activated seat stopped being withheld
// material the moment it became a working signer.
func (de *dkgExecutor) withheldCount(outputs []quarantinedSigner) int {
	withheld := 0
	for _, output := range outputs {
		if de.walletRegistry.isSignerActive(
			output.walletStorageKey,
			output.memberIndex,
		) {
			continue
		}
		withheld++
	}

	return withheld
}

// knownOutputsLocked lists the preserved outputs this process can name without
// reading the namespace: everything the last successful scan found together
// with everything this process has persisted since. The caller must hold
// quarantineReportMutex.
//
// Both are needed and neither is enough. The scan is the only account of what
// earlier processes on this host left behind, and it says nothing about a share
// written after it; this process's own writes say nothing about what it
// inherited. Reporting either alone leaves out material that is on disk.
//
// The two overlap freely — a scan taken after a write finds that write — so
// they are merged as identities rather than added as counts, and an output
// named by both is one output.
//
// Only writes a successful scan has not already ruled on survive in the floor,
// so this can name an output the namespace has since let go of only for as long
// as no scan has succeeded to say otherwise.
func (de *dkgExecutor) knownOutputsLocked() []quarantinedSigner {
	known := make(
		map[quarantinedSigner]struct{},
		len(de.lastScannedOutputs)+len(de.preservedOutputFloor),
	)
	for output := range de.lastScannedOutputs {
		known[output] = struct{}{}
	}
	for output := range de.preservedOutputFloor {
		known[output] = struct{}{}
	}

	outputs := make([]quarantinedSigner, 0, len(known))
	for output := range known {
		outputs = append(outputs, output)
	}

	return outputs
}

// publishQuarantineCountLocked publishes the count and remembers it as the one
// that stands. The caller must hold quarantineReportMutex.
//
// Nothing is remembered when there is no recorder to publish to. The remembered
// value is what a failed recount compares its floor against, and a number that
// never reached a gauge would hold that comparison up against a reading nobody
// can see.
func (de *dkgExecutor) publishQuarantineCountLocked(count int) {
	if de.metricsRecorder == nil {
		return
	}

	de.lastPublishedQuarantineCount = count

	de.metricsRecorder.SetGauge(
		clientinfo.MetricParticipationQuarantinedTBTCSigners,
		float64(count),
	)
}

func (de *dkgExecutor) recordPermitTerminalOutcome(
	dkgLogger log.StandardLogger,
	permit participation.Permit,
	outcome participation.TerminalOutcome,
	evidence participation.TerminalEvidence,
) {
	recordPermitTerminalOutcome(dkgLogger, permit, outcome, evidence)
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
