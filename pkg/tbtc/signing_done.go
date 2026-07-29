package tbtc

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/signing"
)

// signingDoneReceiveBuffer is a buffer for messages received from the broadcast
// channel needed when the signing done's consumer is temporarily too slow to
// handle them. Keep in mind that although we expect only 51 done messages,
// it may happen that the check receives retransmissions of messages from
// the signing protocol and before they are filtered out as not interesting for
// the done check, they are buffered in the channel.
const signingDoneReceiveBuffer = 512

// signingDoneCheckInterval determines a frequency of checking if all conditions
// to consider the signing as done are met, in waitUntilAllDone.
const signingDoneCheckInterval = 100 * time.Millisecond

// errWaitDoneTimedOut is returned by waitUntilAllDone if it did not receive
// valid done checks from all members on time.
var errWaitDoneTimedOut = fmt.Errorf("cannot receive signing done messages on time")

// signingDoneMessage is a message used to signal a successful signature
// calculation across all signing group members.
type signingDoneMessage struct {
	senderID      group.MemberIndex
	message       *big.Int
	attemptNumber uint64
	signature     *tecdsa.Signature
	endBlock      uint64
}

func (sdm *signingDoneMessage) Type() string {
	return "tbtc/signing_done_message"
}

// signingDoneCheck is a component that is responsible for signaling a
// successful signature calculation across all signing group members.
type signingDoneCheck struct {
	groupSize           int
	broadcastChannel    net.BroadcastChannel
	membershipValidator *group.MembershipValidator

	// receiveCtx, cancelReceiveCtx and attempt hold the state of the attempt
	// this check is currently working on. They are written by listen and read
	// by waitUntilAllDone, which the retry loop calls one after the other on
	// its own goroutine; no other goroutine touches them.
	receiveCtx       context.Context
	cancelReceiveCtx context.CancelFunc
	attempt          *signingDoneAttempt
}

// signingDoneAttempt is the done-check state of a single signing attempt: the
// memberships the attempt selected and the done messages received from them.
//
// It is owned by the listen call that created it, and that call's listener
// goroutine closes over it, because an attempt's listener is stopped by
// cancelling its context and the next attempt does not wait for it to notice.
// A listener still draining buffered messages from the previous attempt would
// otherwise write into state the current attempt installed — filling a fresh
// map with a finished attempt's messages, and validating them against the
// wrong attempt's party set.
type signingDoneAttempt struct {
	// members are the memberships the attempt selected to sign, and the only
	// senders whose done messages describe its transcript. Immutable once the
	// attempt is constructed, so it needs no lock.
	members []group.MemberIndex

	doneSigners      map[group.MemberIndex]*signingDoneMessage
	doneSignersMutex sync.Mutex
}

// recordDoneSigner stores a validated done message under its sender.
func (sda *signingDoneAttempt) recordDoneSigner(doneMessage *signingDoneMessage) {
	sda.doneSignersMutex.Lock()
	defer sda.doneSignersMutex.Unlock()

	sda.doneSigners[doneMessage.senderID] = doneMessage
}

// isDoneSigner reports whether a done message from the given sender was
// already accepted for this attempt.
func (sda *signingDoneAttempt) isDoneSigner(senderID group.MemberIndex) bool {
	sda.doneSignersMutex.Lock()
	defer sda.doneSignersMutex.Unlock()

	_, done := sda.doneSigners[senderID]
	return done
}

func newSigningDoneCheck(
	groupSize int,
	broadcastChannel net.BroadcastChannel,
	membershipValidator *group.MembershipValidator,
) *signingDoneCheck {
	return &signingDoneCheck{
		groupSize:           groupSize,
		broadcastChannel:    broadcastChannel,
		membershipValidator: membershipValidator,
	}
}

// listen runs the signing done check listening routine. This function listens
// for incoming signing done checks from the members the given signing attempt
// selected. Messages are filtered out based on the sending membership, the
// attempt number, and the attempt's own protocol window. Only one message for
// the given attempt can be sent by the given signing group member. This
// function should be called before the signing attempt starts to ensure signing
// done messages are getting received as early as possible. This is especially
// important when the current member is the slowest one with executing the
// signing.
func (sdc *signingDoneCheck) listen(
	ctx context.Context,
	message *big.Int,
	attemptNumber uint64,
	attemptStartBlock uint64,
	attemptTimeoutBlock uint64,
	attemptMembersIndexes []group.MemberIndex,
) {
	// Use a separate context for the message receiver as the receiver and the
	// consuming goroutine are closed when the `waitUntilAllDone` completes its
	// work. Leaving a dangling receiver without the message processing loop
	// causes warnings on the channel level.
	receiveCtx, cancelReceiveCtx := context.WithCancel(ctx)
	sdc.receiveCtx, sdc.cancelReceiveCtx = receiveCtx, cancelReceiveCtx

	messagesChan := make(chan net.Message, signingDoneReceiveBuffer)
	sdc.broadcastChannel.Recv(receiveCtx, func(message net.Message) {
		messagesChan <- message
	})

	attempt := &signingDoneAttempt{
		members:     slices.Clone(attemptMembersIndexes),
		doneSigners: make(map[group.MemberIndex]*signingDoneMessage),
	}
	sdc.attempt = attempt

	// The goroutine works on the attempt and context it was started with rather
	// than on the check's fields, which the next attempt's listen replaces.
	go func() {
		for {
			select {
			case netMessage := <-messagesChan:
				doneMessage, ok := netMessage.Payload().(*signingDoneMessage)
				if !ok {
					continue
				}

				if !sdc.isValidDoneMessage(
					attempt,
					doneMessage,
					netMessage.SenderPublicKey(),
					message,
					attemptNumber,
					attemptStartBlock,
					attemptTimeoutBlock,
				) {
					continue
				}

				attempt.recordDoneSigner(doneMessage)

			case <-receiveCtx.Done():
				return
			}
		}
	}()
}

// signalDone broadcasts the signing done check along with information necessary
// to attribute the result to the given signing attempt.
func (sdc *signingDoneCheck) signalDone(
	ctx context.Context,
	memberIndex group.MemberIndex,
	message *big.Int,
	attemptNumber uint64,
	result *signing.Result,
	endBlock uint64,
) error {
	return sdc.broadcastChannel.Send(ctx, &signingDoneMessage{
		senderID:      memberIndex,
		message:       message,
		attemptNumber: attemptNumber,
		signature:     result.Signature,
		endBlock:      endBlock,
	}, net.BackoffRetransmissionStrategy)
}

// waitUntilAllDone blocks until it receives all the required done checks from
// members or until the passed context is done. In the first case, it returns
// the signature computed by the signing members, the memberships whose done
// checks carried it, and the block at which the slowest signer completed the
// signature computation process. If the expected done checks are not received
// on time, the function returns an error. If at least one signature is
// different from others, the function returns an error.
//
// The returned memberships are the local view of who produced the signature,
// and the only one this node has. Every done check counted here was
// authenticated against the wallet's on-chain signing group, sent by a
// membership this attempt selected, ended inside this attempt's own protocol
// window, and carried a signature equal to every other — so a membership in that
// list confirmed this exact result under an identity the chain accounts for, and
// a membership absent from it confirmed nothing about it. That distinction is
// what a reader otherwise has to take from whichever party wrote the report: a
// completed ceremony reads identically whether its shares came from several
// parties or one party recovered the common result alone.
//
// It is an attestation by each named membership rather than a proof that it
// computed a share, and the difference is bounded by what the wire carries. A
// done message names the message, the attempt number, the signature, and the
// block its sender finished at; nothing in it is derived from this attempt's
// protocol transcript. The window check is therefore what separates the runs: it
// refuses the earlier run's messages, whose end blocks lie outside this attempt's
// window, whether they were honestly retransmitted or replayed by anybody who
// captured them. A selected membership choosing to assert an in-window end block
// over an output it did not compute is not separated by it, and separating it
// would mean binding the message to a session the prior release does not
// compute — the wire change a compatibility release cannot make.
func (sdc *signingDoneCheck) waitUntilAllDone(ctx context.Context) (
	*signing.Result,
	participation.MemberIndexes,
	uint64,
	error,
) {
	defer sdc.cancelReceiveCtx()

	attempt := sdc.attempt

	ticker := time.NewTicker(signingDoneCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, nil, 0, errWaitDoneTimedOut

		case <-ticker.C:
			result, signers, endBlock, done, err := func() (
				*signing.Result,
				participation.MemberIndexes,
				uint64,
				bool,
				error,
			) {
				attempt.doneSignersMutex.Lock()
				defer attempt.doneSignersMutex.Unlock()

				if len(attempt.members) != len(attempt.doneSigners) {
					return nil, nil, 0, false, nil
				}

				var signature *tecdsa.Signature
				var latestEndBlock uint64
				signers := make(
					participation.MemberIndexes,
					0,
					len(attempt.doneSigners),
				)

				for senderID, doneMessage := range attempt.doneSigners {
					if signature == nil {
						signature = doneMessage.signature
					} else {
						if !signature.Equals(doneMessage.signature) {
							return nil, nil, 0, true, fmt.Errorf(
								"not matching signatures detected: [%v] and [%v]",
								signature,
								doneMessage.signature,
							)
						}
					}

					if doneMessage.endBlock > latestEndBlock {
						latestEndBlock = doneMessage.endBlock
					}

					signers = append(signers, senderID)
				}

				// Map iteration order is random, and this list identifies a
				// transcript in a record two nodes have to agree on. Sorting
				// gives one population exactly one rendering.
				slices.Sort(signers)

				return &signing.Result{Signature: signature},
					signers,
					latestEndBlock,
					true,
					nil
			}()

			if done {
				return result, signers, endBlock, err
			}
		}
	}
}

// isValidDoneMessage validates the given signingDoneMessage in the context
// of the given signing attempt.
func (sdc *signingDoneCheck) isValidDoneMessage(
	attempt *signingDoneAttempt,
	doneMessage *signingDoneMessage,
	senderPublicKey []byte,
	message *big.Int,
	attemptNumber uint64,
	attemptStartBlock uint64,
	attemptTimeoutBlock uint64,
) bool {
	if attempt.isDoneSigner(doneMessage.senderID) {
		// only one done message allowed
		return false
	}

	if !sdc.membershipValidator.IsValidMembership(
		doneMessage.senderID,
		senderPublicKey,
	) {
		return false
	}

	// A valid wallet membership is not necessarily one of this attempt's
	// signers. The members the attempt excluded compute nothing and signal
	// nothing, so a done message from one of them attests to a transcript that
	// never existed — and the count check in waitUntilAllDone cannot tell the
	// difference, because an excluded member's message standing in for a lost
	// message from a selected one reaches the expected total over the wrong
	// population. The attempt would then conclude on a signature it never
	// gathered from its own signers and name a membership that never signed as
	// having produced it.
	if !slices.Contains(attempt.members, doneMessage.senderID) {
		return false
	}

	if doneMessage.message.Cmp(message) != 0 {
		return false
	}

	if doneMessage.attemptNumber != attemptNumber {
		return false
	}

	// The end block says when the sender finished computing, and the attempt's
	// protocol window says when finishing this attempt was possible. The
	// message and attempt number do not identify an attempt on their own: the
	// same wallet can be asked to sign the same message again under a later
	// canonical anchor, and its attempt numbering restarts from zero. A done
	// message left over from such an earlier run — retransmitted past its own
	// window, or replayed — describes that run's transcript, and its end block
	// lies below the block this attempt's protocol started at.
	if doneMessage.endBlock < attemptStartBlock ||
		doneMessage.endBlock > attemptTimeoutBlock {
		return false
	}

	if doneMessage.signature == nil {
		return false
	}

	return true
}
