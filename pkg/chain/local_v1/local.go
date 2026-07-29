package local_v1

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"sync"

	"github.com/ipfs/go-log"

	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/beacon/event"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/subscription"
	"golang.org/x/crypto/sha3"
)

var logger = log.Logger("keep-chainlocal")

var seedGroupPublicKey = []byte("seed to group public key")
var groupActiveTime = uint64(10)
var relayRequestTimeout = uint64(8)

type localGroup struct {
	groupPublicKey          []byte
	registrationBlockHeight uint64
}

type localChain struct {
	relayConfig *beaconchain.Config

	groups []localGroup

	lastSubmittedDKGResult           *beaconchain.DKGResult
	lastSubmittedDKGResultSignatures map[beaconchain.GroupMemberIndex][]byte
	lastSubmittedRelayEntry          []byte

	handlerMutex             sync.Mutex
	relayEntryHandlers       map[int]func(entry *event.RelayEntrySubmitted)
	relayRequestHandlers     map[int]func(request *event.RelayEntryRequested)
	groupRegisteredHandlers  map[int]func(groupRegistration *event.GroupRegistration)
	dkgStartedHandlers       map[int]func(submission *event.DKGStarted)
	resultSubmissionHandlers map[int]func(submission *event.DKGResultSubmission)

	// resultSubmissionRegisteredSignal, when non-nil, receives an empty value
	// after each DKG result submission handler is installed via
	// OnDKGResultSubmitted. It is test-only instrumentation that lets a test
	// deterministically wait until a member has installed its result submission
	// subscription before triggering a competing submission, eliminating the
	// race between a result submission and a concurrent subscription setup.
	// Access is guarded by handlerMutex.
	resultSubmissionRegisteredSignal chan<- struct{}

	simulatedHeight uint64
	blockCounter    chain.BlockCounter

	relayEntryTimeoutReportsMutex sync.Mutex
	relayEntryTimeoutReports      []uint64

	operatorPrivateKey *operator.PrivateKey
}

func (c *localChain) BlockCounter() (chain.BlockCounter, error) {
	return c.blockCounter, nil
}

func (c *localChain) Signing() chain.Signing {
	return NewSigner(c.operatorPrivateKey)
}

func (c *localChain) OperatorKeyPair() (*operator.PrivateKey, *operator.PublicKey, error) {
	return c.operatorPrivateKey, &c.operatorPrivateKey.PublicKey, nil
}

func (c *localChain) GetConfig() *beaconchain.Config {
	return c.relayConfig
}

func (c *localChain) SubmitRelayEntry(newEntry []byte) error {
	currentBlock, err := c.blockCounter.CurrentBlock()
	if err != nil {
		return fmt.Errorf("cannot read current block: [%v]", err)
	}

	entry := &event.RelayEntrySubmitted{
		BlockNumber: currentBlock,
	}

	c.handlerMutex.Lock()
	// Record the last submitted entry under the same lock that guards it in
	// GetLastRelayEntry so concurrent submissions/reads do not race.
	c.lastSubmittedRelayEntry = newEntry
	for _, handler := range c.relayEntryHandlers {
		go func(handler func(entry *event.RelayEntrySubmitted), entry *event.RelayEntrySubmitted) {
			handler(entry)
		}(handler, entry)
	}
	c.handlerMutex.Unlock()

	return nil
}

func (c *localChain) OnRelayEntrySubmitted(
	handler func(entry *event.RelayEntrySubmitted),
) subscription.EventSubscription {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	handlerID := GenerateHandlerID()
	c.relayEntryHandlers[handlerID] = handler

	return subscription.NewEventSubscription(func() {
		c.handlerMutex.Lock()
		defer c.handlerMutex.Unlock()

		delete(c.relayEntryHandlers, handlerID)
	})
}

func (c *localChain) GetLastRelayEntry() []byte {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	return c.lastSubmittedRelayEntry
}

func (c *localChain) OnRelayEntryRequested(
	handler func(request *event.RelayEntryRequested),
) subscription.EventSubscription {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	handlerID := GenerateHandlerID()
	c.relayRequestHandlers[handlerID] = handler

	return subscription.NewEventSubscription(func() {
		c.handlerMutex.Lock()
		defer c.handlerMutex.Unlock()

		delete(c.relayRequestHandlers, handlerID)
	})
}

func (c *localChain) SelectGroup(seed *big.Int) (chain.Addresses, error) {
	panic("not implemented")
}

func (c *localChain) OnGroupRegistered(
	handler func(groupRegistration *event.GroupRegistration),
) subscription.EventSubscription {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	handlerID := GenerateHandlerID()

	c.groupRegisteredHandlers[handlerID] = handler

	return subscription.NewEventSubscription(func() {
		c.handlerMutex.Lock()
		defer c.handlerMutex.Unlock()

		delete(c.groupRegisteredHandlers, handlerID)
	})
}

// Connect initializes a local stub implementation of the chain
// interfaces for testing. It uses auto-generated operator key.
func Connect(
	groupSize int,
	honestThreshold int,
) *localChain {
	operatorPrivateKey, _, err := operator.GenerateKeyPair(DefaultCurve)
	if err != nil {
		panic(err)
	}

	return ConnectWithKey(groupSize, honestThreshold, operatorPrivateKey)
}

// ConnectWithKey initializes a local stub implementation of the chain
// interfaces for testing.
func ConnectWithKey(
	groupSize int,
	honestThreshold int,
	operatorPrivateKey *operator.PrivateKey,
) *localChain {
	bc, _ := BlockCounter()

	currentBlock, _ := bc.CurrentBlock()
	group := localGroup{
		groupPublicKey:          seedGroupPublicKey,
		registrationBlockHeight: currentBlock,
	}

	resultPublicationBlockStep := uint64(3)

	return &localChain{
		relayConfig: &beaconchain.Config{
			GroupSize:                  groupSize,
			HonestThreshold:            honestThreshold,
			ResultPublicationBlockStep: resultPublicationBlockStep,
			RelayEntryTimeout:          resultPublicationBlockStep * uint64(groupSize),
		},
		relayEntryHandlers:       make(map[int]func(request *event.RelayEntrySubmitted)),
		relayRequestHandlers:     make(map[int]func(request *event.RelayEntryRequested)),
		groupRegisteredHandlers:  make(map[int]func(groupRegistration *event.GroupRegistration)),
		dkgStartedHandlers:       make(map[int]func(submission *event.DKGStarted)),
		resultSubmissionHandlers: make(map[int]func(submission *event.DKGResultSubmission)),
		blockCounter:             bc,
		groups:                   []localGroup{group},
		operatorPrivateKey:       operatorPrivateKey,
	}
}

func selectGroup(entry *big.Int, numberOfGroups int) int {
	if numberOfGroups == 0 {
		return 0
	}

	return int(new(big.Int).Mod(entry, big.NewInt(int64(numberOfGroups))).Int64())
}

func (c *localChain) IsStaleGroup(groupPublicKey []byte) (bool, error) {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	bc, _ := BlockCounter()

	err := bc.WaitForBlockHeight(c.simulatedHeight)
	if err != nil {
		logger.Errorf("could not wait for block height: [%v]", err)
	}

	currentBlock, err := bc.CurrentBlock()

	if err != nil {
		return false, fmt.Errorf("could not determine current block: [%v]", err)
	}

	for _, group := range c.groups {
		if bytes.Equal(group.groupPublicKey, groupPublicKey) {
			return group.registrationBlockHeight+groupActiveTime+relayRequestTimeout < currentBlock, nil
		}
	}

	return true, nil
}

func (c *localChain) IsGroupRegistered(groupPublicKey []byte) (bool, error) {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	for _, group := range c.groups {
		if bytes.Equal(group.groupPublicKey, groupPublicKey) {
			return true, nil
		}
	}
	return false, nil
}

// SubmitDKGResult submits the result to a chain.
func (c *localChain) SubmitDKGResult(
	participantIndex beaconchain.GroupMemberIndex,
	resultToPublish *beaconchain.DKGResult,
	signatures map[beaconchain.GroupMemberIndex][]byte,
) error {
	if len(signatures) < c.relayConfig.HonestThreshold {
		return fmt.Errorf(
			"failed to submit result with [%v] signatures for honest threshold [%v]",
			len(signatures),
			c.relayConfig.HonestThreshold,
		)
	}

	currentBlock, err := c.blockCounter.CurrentBlock()
	if err != nil {
		return fmt.Errorf("cannot read current block: [%v]", err)
	}

	dkgResultPublicationEvent := &event.DKGResultSubmission{
		MemberIndex:    uint32(participantIndex),
		GroupPublicKey: resultToPublish.GroupPublicKey[:],
		Misbehaved:     resultToPublish.Misbehaved,
		BlockNumber:    currentBlock,
	}

	myGroup := localGroup{
		groupPublicKey:          resultToPublish.GroupPublicKey,
		registrationBlockHeight: currentBlock,
	}

	groupRegistrationEvent := &event.GroupRegistration{
		GroupPublicKey: resultToPublish.GroupPublicKey[:],
		BlockNumber:    currentBlock,
	}

	c.handlerMutex.Lock()
	// Register the group and record the last submitted result under the same
	// lock that guards these fields in IsGroupRegistered, IsStaleGroup, and
	// GetLastDKGResult. Concurrent DKG result publications by multiple members
	// would otherwise race on the groups slice.
	c.groups = append(c.groups, myGroup)
	c.lastSubmittedDKGResult = resultToPublish
	c.lastSubmittedDKGResultSignatures = signatures

	for _, handler := range c.resultSubmissionHandlers {
		go func(handler func(*event.DKGResultSubmission), dkgResultPublication *event.DKGResultSubmission) {
			handler(dkgResultPublicationEvent)
		}(handler, dkgResultPublicationEvent)
	}

	for _, handler := range c.groupRegisteredHandlers {
		go func(handler func(*event.GroupRegistration), groupRegistration *event.GroupRegistration) {
			handler(groupRegistrationEvent)
		}(handler, groupRegistrationEvent)
	}
	c.handlerMutex.Unlock()

	return nil
}

func (c *localChain) OnDKGStarted(
	handler func(event *event.DKGStarted),
) subscription.EventSubscription {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	handlerID := GenerateHandlerID()
	c.dkgStartedHandlers[handlerID] = handler

	return subscription.NewEventSubscription(func() {
		c.handlerMutex.Lock()
		defer c.handlerMutex.Unlock()

		delete(c.dkgStartedHandlers, handlerID)
	})
}

func (c *localChain) OnDKGResultSubmitted(
	handler func(dkgResultPublication *event.DKGResultSubmission),
) subscription.EventSubscription {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	handlerID := GenerateHandlerID()
	c.resultSubmissionHandlers[handlerID] = handler

	// Notify any test synchronization listener that a result submission handler
	// has been installed. The send is non-blocking so chain operation is never
	// blocked; a sufficiently buffered listener channel guarantees delivery.
	if c.resultSubmissionRegisteredSignal != nil {
		select {
		case c.resultSubmissionRegisteredSignal <- struct{}{}:
		default:
		}
	}

	return subscription.NewEventSubscription(func() {
		c.handlerMutex.Lock()
		defer c.handlerMutex.Unlock()

		delete(c.resultSubmissionHandlers, handlerID)
	})
}

// SetResultSubmissionRegisteredSignal installs a test-only signal channel that
// receives an empty value after each DKG result submission handler is registered
// via OnDKGResultSubmitted. It lets tests synchronize on subscription
// installation without relying on timing, for example to guarantee a member has
// installed its subscription before a competing member submits a result. The
// provided channel should be buffered so signals are never dropped; pass nil to
// disable notifications.
func (c *localChain) SetResultSubmissionRegisteredSignal(signal chan<- struct{}) {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	c.resultSubmissionRegisteredSignal = signal
}

func (c *localChain) GetLastDKGResult() (
	*beaconchain.DKGResult,
	map[beaconchain.GroupMemberIndex][]byte,
) {
	c.handlerMutex.Lock()
	defer c.handlerMutex.Unlock()

	// Read these fields under the same lock SubmitDKGResult holds while writing
	// them. The deferred unlock runs only after the return values are evaluated,
	// so the field reads happen inside the critical section and establish the
	// happens-before edge the race detector requires. SubmitDKGResult only ever
	// reassigns lastSubmittedDKGResult and lastSubmittedDKGResultSignatures (it
	// never mutates the pointed-to result or the signatures map in place), so the
	// references returned here remain a stable snapshot after the lock is
	// released.
	return c.lastSubmittedDKGResult, c.lastSubmittedDKGResultSignatures
}

func (c *localChain) ReportRelayEntryTimeout() error {
	c.relayEntryTimeoutReportsMutex.Lock()
	defer c.relayEntryTimeoutReportsMutex.Unlock()

	currentBlock, err := c.blockCounter.CurrentBlock()
	if err != nil {
		return err
	}

	c.relayEntryTimeoutReports = append(c.relayEntryTimeoutReports, currentBlock)
	return nil
}

// errNoRelayRequestState reports that this chain keeps no relay request
// lifecycle. It is returned rather than panicked because the relay entry
// timeout monitor reconciles a filed report against these reads on every run;
// an error tells the monitor it cannot confirm the report and leaves the
// penalty unclaimed, which is the honest reading. Answering "no request is in
// progress" would be vacuously true here and would let a local run claim a
// penalty no chain ever confirmed.
var errNoRelayRequestState = fmt.Errorf(
	"the local chain keeps no relay request state",
)

func (c *localChain) IsEntryInProgress() (bool, error) {
	return false, errNoRelayRequestState
}

func (c *localChain) CurrentRequestStartBlock() (*big.Int, error) {
	return nil, errNoRelayRequestState
}

func (c *localChain) CurrentRequestPreviousEntry() ([]byte, error) {
	return nil, errNoRelayRequestState
}

func (c *localChain) CurrentRequestGroupPublicKey() ([]byte, error) {
	panic("not implemented")
}

func (c *localChain) RelayEntryTimeoutSettlement(
	uint64,
	[]byte,
) (*event.RelayEntryTimeoutSettlement, error) {
	return nil, errNoRelayRequestState
}

func (c *localChain) GetRelayEntryTimeoutReports() []uint64 {
	c.relayEntryTimeoutReportsMutex.Lock()
	defer c.relayEntryTimeoutReportsMutex.Unlock()

	// Return a snapshot copy so callers can read the reports without racing a
	// concurrent ReportRelayEntryTimeout append.
	reports := make([]uint64, len(c.relayEntryTimeoutReports))
	copy(reports, c.relayEntryTimeoutReports)
	return reports
}

// CalculateDKGResultHash calculates a 256-bit hash of the DKG result.
func (c *localChain) CalculateDKGResultHash(
	dkgResult *beaconchain.DKGResult,
) (beaconchain.DKGResultHash, error) {
	encodedDKGResult := fmt.Sprint(dkgResult)
	dkgResultHash := beaconchain.DKGResultHash(
		sha3.Sum256([]byte(encodedDKGResult)),
	)

	return dkgResultHash, nil
}

func (c *localChain) OperatorToStakingProvider() (chain.Address, bool, error) {
	panic("unsupported")
}

func (c *localChain) EligibleStake(stakingProvider chain.Address) (*big.Int, error) {
	panic("unsupported")
}

func (c *localChain) IsPoolLocked() (bool, error) {
	panic("unsupported")
}

func (c *localChain) IsOperatorInPool() (bool, error) {
	panic("unsupported")
}

func (c *localChain) IsOperatorUpToDate() (bool, error) {
	panic("unsupported")
}

func (c *localChain) JoinSortitionPool() error {
	panic("unsupported")
}

func (c *localChain) UpdateOperatorStatus() error {
	panic("unsupported")
}

func (c *localChain) IsEligibleForRewards() (bool, error) {
	panic("unsupported")
}

func (c *localChain) CanRestoreRewardEligibility() (bool, error) {
	panic("unsupported")
}

func (c *localChain) RestoreRewardEligibility() error {
	panic("unsupported")
}

func (c *localChain) IsChaosnetActive() (bool, error) {
	panic("unsupported")
}

func (c *localChain) IsBetaOperator() (bool, error) {
	panic("unsupported")
}

func (c *localChain) GetOperatorID(
	operatorAddress chain.Address,
) (chain.OperatorID, error) {
	panic("unsupported")
}

func GenerateHandlerID() int {
	// #nosec G404 (insecure random number source (rand))
	// Local chain implementation doesn't require secure randomness.
	return rand.Int()
}
