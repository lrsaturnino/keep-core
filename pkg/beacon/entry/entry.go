package entry

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/keep-network/keep-core/pkg/beacon/event"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/ipfs/go-log/v2"
	beaconchain "github.com/keep-network/keep-core/pkg/beacon/chain"
	"github.com/keep-network/keep-core/pkg/beacon/dkg"
	"github.com/keep-network/keep-core/pkg/bls"
	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

// RegisterUnmarshallers initializes the given broadcast channel to be able to
// perform relay entry signing protocol interactions by registering all the
// required protocol message unmarshallers.
// The channel has to be initialized before the SignAndSubmit is called.
func RegisterUnmarshallers(channel net.BroadcastChannel) {
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &SignatureShareMessage{}
	})
}

// SignAndSubmit triggers the threshold signature process for the
// previous relay entry and publishes the signature to the chain as
// a new relay entry.
//
// It returns the marshaled relay entry this member recovered, or nil when the
// local ceremony ended before reaching the honest threshold — because another
// member submitted the entry first, the request timed out, or the permit was
// canceled. A relay entry is deterministic for a given previous entry, so the
// returned value is the ceremony's durable result and stays reconcilable
// against the chain even if the submission below did not go through.
//
// Beside it, the memberships whose signature shares were combined into that
// entry, and nil wherever no entry was recovered. Every one of them was
// authenticated against the group public key share the DKG published for that
// membership and against this exact previous entry, so a membership named there
// held the private share behind its seat and put it into this result. That is
// the local view of the transcript, and the only fact separating a threshold
// entry several parties produced from one this node recovered among its own
// kind: a completed relay ceremony reads identically either way, so a reader
// holding only the completion has to take the population from whichever party
// reported it.
//
// The context bounds the execution and must be the ceremony permit's context:
// canceling it aborts the share exchange and the submission. The commit guard
// is consulted immediately before the terminal on-chain entry submission.
func SignAndSubmit(
	ctx context.Context,
	logger log.StandardLogger,
	blockCounter chain.BlockCounter,
	channel net.BroadcastChannel,
	beaconChain beaconchain.Interface,
	previousEntryBytes []byte,
	honestThreshold int,
	signer *dkg.ThresholdSigner,
	startBlockHeight uint64,
	commitGuard participation.CommitGuard,
) ([]byte, participation.MemberIndexes, error) {
	if commitGuard == nil {
		// Submitting without a fence would publish an entry the release gate
		// never authorized; there is no implicit default.
		return nil, nil, fmt.Errorf(
			"a commit guard is required to sign a relay entry",
		)
	}

	ctx, cancelCtx := context.WithCancel(ctx)
	defer cancelCtx()

	// The buffer lets an in-flight event callback complete after the consumer
	// returned on cancellation or timeout, instead of blocking forever.
	relayEntrySubmittedChannel := make(chan uint64, 1)
	subscription := beaconChain.OnRelayEntrySubmitted(
		func(event *event.RelayEntrySubmitted) {
			relayEntrySubmittedChannel <- event.BlockNumber
		},
	)
	defer subscription.Unsubscribe()

	chainConfig := beaconChain.GetConfig()

	relayEntryTimeoutChannel, err := blockCounter.BlockHeightWaiter(
		startBlockHeight + chainConfig.RelayEntryTimeout,
	)
	if err != nil {
		return nil, nil, err
	}

	previousEntry := new(bn256.G1)
	_, err = previousEntry.Unmarshal(previousEntryBytes)
	if err != nil {
		return nil, nil, err
	}

	selfShare := signer.CalculateSignatureShare(previousEntry)

	// Marshal the local signature share once, on this goroutine, before the
	// share is used by both the broadcast goroutine and the signature-recovery
	// path. bn256.G1.Marshal normalizes the point in place (MakeAffine), so
	// letting broadcastShare marshal the same *bn256.G1 concurrently with
	// completeSignature reading it via ScalarMult is a data race. Marshaling
	// here and handing broadcastShare only the resulting bytes confines all
	// access to the point to this goroutine. Normalizing to affine does not
	// change the point's value, so signature recovery is unaffected.
	selfShareBytes := selfShare.Marshal()

	sessionID := shareSessionID(previousEntryBytes)

	go broadcastShare(ctx, logger, signer.MemberID(), selfShareBytes, channel, sessionID)

	receiveChannel := make(chan net.Message, 64)
	channel.Recv(ctx, func(netMessage net.Message) {
		receiveChannel <- netMessage
	})

	receivedValidShares := map[group.MemberIndex]*bn256.G1{
		signer.MemberID(): selfShare,
	}

	// Run the message loop until the number of received and valid signature
	// shares is equal to the honest threshold. Message loop will be also
	// terminated if an other member submits the result or the relay entry
	// timeout block is reached.
	for len(receivedValidShares) < honestThreshold {
		select {
		case netMessage := <-receiveChannel:
			message, ok := netMessage.Payload().(*SignatureShareMessage)
			if !ok ||
				signer.MemberID() == message.SenderID() ||
				message.sessionID != sessionID {
				continue
			}

			share, err := extractAndValidateShare(
				message,
				signer.GroupPublicKeyShares(),
				previousEntry,
			)
			if err != nil {
				logger.Warnf(
					"[member:%v] rejecting signature share from "+
						"member [%v]: [%v]",
					signer.MemberID(),
					message.senderID,
					err,
				)
				continue
			}

			logger.Debugf(
				"[member:%v] accepting signature share from member [%v]",
				signer.MemberID(),
				message.senderID,
			)

			receivedValidShares[message.senderID] = share
		case blockNumber := <-relayEntrySubmittedChannel:
			logger.Infof(
				"[member:%v] leaving message loop; "+
					"relay entry submitted by other member at block [%v]",
				signer.MemberID(),
				blockNumber,
			)
			return nil, nil, nil
		case blockNumber := <-relayEntryTimeoutChannel:
			return nil, nil, fmt.Errorf(
				"relay entry timed out at block [%v]; received [%v] valid signature shares",
				blockNumber,
				len(receivedValidShares),
			)
		case <-ctx.Done():
			return nil, nil, fmt.Errorf(
				"relay entry signing canceled: [%w]",
				context.Cause(ctx),
			)
		}
	}

	signature, err := completeSignature(logger, signer, receivedValidShares, honestThreshold)
	if err != nil {
		return nil, nil, err
	}

	// Read before anything else can add to the map. The loop above exits at
	// exactly the honest threshold and every share it holds went into the
	// recovery, so this is the population behind the entry rather than a
	// population that merely spoke on the channel.
	incorporated := incorporatedMemberships(receivedValidShares)

	entryBytes := signature.Marshal()

	submitter := &relayEntrySubmitter{
		logger:       logger,
		chain:        beaconChain,
		blockCounter: blockCounter,
		index:        signer.MemberID(),
	}

	// relayEntrySubmittedChannel and relayEntryTimeoutChannel are passed to
	// the submitter. This should be done because no entry submission or
	// timeout signal appeared while executing the message loop. There is
	// still a possibility those signals appear in the future so the submitter
	// must be aware of them and break the execution if they occur.
	// The recovered entry is returned whatever the submission does: the local
	// ceremony already reached its threshold result, and a submission refused
	// by the release gate or won by another member does not undo it.
	return entryBytes, incorporated, submitter.submitRelayEntry(
		ctx,
		entryBytes,
		signer.GroupPublicKeyBytes(),
		startBlockHeight,
		relayEntrySubmittedChannel,
		relayEntryTimeoutChannel,
		commitGuard,
	)
}

// incorporatedMemberships renders the memberships whose shares were combined
// into a recovered entry, ascending. The ordering is what gives one population
// exactly one rendering, so two members' records of the same relay compare
// equal and a reader cannot be shown a seat twice.
func incorporatedMemberships(
	shares map[group.MemberIndex]*bn256.G1,
) participation.MemberIndexes {
	memberships := make(participation.MemberIndexes, 0, len(shares))
	for memberID := range shares {
		memberships = append(memberships, memberID)
	}
	slices.Sort(memberships)

	return memberships
}

// shareSessionID renders the broadcast session a signature share belongs to.
//
// It is the previous entry and nothing else, and it cannot become anything else
// while a release deriving it this way is on the network: the session ID travels
// on the wire, and both sides of a mixed-release group have to arrive at the same
// string for the same request or each silently filters the other's shares out as
// belonging to some other session.
//
// So a session identifies the value being signed rather than the request that
// asked for it, and the difference is visible in one place. A relay entry is
// deterministic in the previous entry, so a request following one that timed out
// without a submission carries the same previous entry as the request before it —
// and a share produced for the earlier request is then indistinguishable from one
// produced for the later one: same signing key share, same point, same session.
//
// Accepting it is sound, because the entry recovered from it is the same value
// either way. What it means is that the population behind a recovered entry
// attributes seats to that entry and not to the request an audit joined it to: a
// seat in it held the private share behind its membership and put it into this
// result, and a reader taking it for an account of which parties were live at a
// given relay request start block is reading more than the wire carries. Binding
// a share to its request would mean putting the request anchor in the message,
// which is exactly the wire change a compatibility release cannot make.
func shareSessionID(previousEntryBytes []byte) string {
	return hex.EncodeToString(previousEntryBytes)
}

func broadcastShare(
	ctx context.Context,
	logger log.StandardLogger,
	memberID group.MemberIndex,
	shareBytes []byte,
	channel net.BroadcastChannel,
	sessionID string,
) {
	message := &SignatureShareMessage{
		memberID,
		shareBytes,
		sessionID,
	}

	if err := channel.Send(ctx, message); err != nil {
		logger.Errorf(
			"[member:%v] could not send signature share: [%v]",
			memberID,
			err,
		)
	}
}

func extractAndValidateShare(
	message *SignatureShareMessage,
	groupPublicKeyShares map[group.MemberIndex]*bn256.G2,
	previousEntry *bn256.G1,
) (*bn256.G1, error) {
	share := new(bn256.G1)
	_, err := share.Unmarshal(message.shareBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"could not unmarshal signature share: [%v]",
			err,
		)
	}

	publicKeyShare, ok := groupPublicKeyShares[message.senderID]
	if !ok {
		return nil, fmt.Errorf(
			"could not validate signature share; " +
				"group public key share for sender not found",
		)
	}

	if !bls.VerifyG1(publicKeyShare, previousEntry, share) {
		return nil, fmt.Errorf("invalid signature share")
	}

	return share, nil
}

func completeSignature(
	logger log.StandardLogger,
	signer *dkg.ThresholdSigner,
	shares map[group.MemberIndex]*bn256.G1,
	honestThreshold int,
) (*bn256.G1, error) {
	signatureShares := make([]*bls.SignatureShare, 0)
	for memberID, share := range shares {
		signatureShare := &bls.SignatureShare{I: int(memberID), V: share}
		signatureShares = append(signatureShares, signatureShare)
	}

	logger.Infof(
		"[member:%v] restoring signature from [%v] shares",
		signer.MemberID(),
		len(signatureShares),
	)

	signature, err := signer.CompleteSignature(
		signatureShares,
		honestThreshold,
	)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
