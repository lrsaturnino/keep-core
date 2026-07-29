package entry

import (
	"context"
	"encoding/hex"
	"fmt"

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
) ([]byte, error) {
	if commitGuard == nil {
		// Submitting without a fence would publish an entry the release gate
		// never authorized; there is no implicit default.
		return nil, fmt.Errorf(
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
		return nil, err
	}

	previousEntry := new(bn256.G1)
	_, err = previousEntry.Unmarshal(previousEntryBytes)
	if err != nil {
		return nil, err
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

	sessionID := hex.EncodeToString(previousEntryBytes)

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
			return nil, nil
		case blockNumber := <-relayEntryTimeoutChannel:
			return nil, fmt.Errorf(
				"relay entry timed out at block [%v]; received [%v] valid signature shares",
				blockNumber,
				len(receivedValidShares),
			)
		case <-ctx.Done():
			return nil, fmt.Errorf(
				"relay entry signing canceled: [%w]",
				context.Cause(ctx),
			)
		}
	}

	signature, err := completeSignature(logger, signer, receivedValidShares, honestThreshold)
	if err != nil {
		return nil, err
	}

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
	return entryBytes, submitter.submitRelayEntry(
		ctx,
		entryBytes,
		signer.GroupPublicKeyBytes(),
		startBlockHeight,
		relayEntrySubmittedChannel,
		relayEntryTimeoutChannel,
		commitGuard,
	)
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
