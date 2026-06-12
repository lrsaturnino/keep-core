// Package signingtest provides a full-roundtrip tECDSA signing test engine,
// the signing analogue of dkgtest. All members run signing.Execute against a
// single shared local broadcast channel; an optional interception.Strategy
// lets a test inject Byzantine behavior (drop / mutate / duplicate / inject).
//
// It is the first whole-signing-protocol harness in the tree - the per-round
// unit tests in pkg/tecdsa/signing stress phases individually and the file's
// own TODO asks for an integration test of the whole protocol. Member private
// key shares come from the committed tECDSA fixtures
// (tecdsatest.LoadPrivateKeyShareTestFixtures), so no expensive tECDSA DKG runs
// per test.
//
// Unlike dkgtest (block-driven SyncMachine, ~37.5s/run), signing uses the
// message-driven AsyncMachine, so an honest roundtrip completes in seconds.
package signingtest

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/keep-network/keep-core/internal/testutils"

	"github.com/keep-network/keep-core/pkg/chain"
	"github.com/keep-network/keep-core/pkg/chain/local_v1"
	"github.com/keep-network/keep-core/pkg/internal/interception"
	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	netLocal "github.com/keep-network/keep-core/pkg/net/local"
	"github.com/keep-network/keep-core/pkg/operator"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/signing"

	"context"
	"time"
)

// maxFixtures is the number of committed private-key-share fixtures
// (private_key_share_data_0..4.json), and thus the maximum group size.
const maxFixtures = 5

// Result of a signing test execution. signatures holds the signature produced
// by each member that completed; memberFailures holds the error from each
// member that did not.
type Result struct {
	signatures     []*tecdsa.Signature
	memberFailures []error
}

// GetSignatures returns the signatures produced by members that completed the
// protocol. Order is nondeterministic (members complete concurrently).
func (r *Result) GetSignatures() []*tecdsa.Signature {
	return r.signatures
}

// GetMemberFailures returns the errors from members that did not complete.
func (r *Result) GetMemberFailures() []error {
	return r.memberFailures
}

// RunTest executes the full tECDSA signing protocol for the given message over
// a group of groupSize members (loaded from key-share fixtures), applying the
// provided interception.Strategy to the shared broadcast channel. Pass
// interception.PassThrough for an honest run. Uses a 60s execution bound; an
// honest run finishes in seconds and never approaches it.
func RunTest(
	message *big.Int,
	groupSize int,
	dishonestThreshold int,
	strategy interception.Strategy,
) (*Result, error) {
	return RunTestWithTimeout(message, groupSize, dishonestThreshold, 60*time.Second, strategy)
}

// RunTestWithTimeout is RunTest with an explicit execution bound. Use a short
// timeout for Byzantine scenarios where a withheld or corrupted message leaves
// peers waiting (they cannot complete and block until the bound fires); the
// timeout bounds how long that denial-of-service takes to observe.
func RunTestWithTimeout(
	message *big.Int,
	groupSize int,
	dishonestThreshold int,
	timeout time.Duration,
	strategy interception.Strategy,
) (*Result, error) {
	if groupSize < 1 || groupSize > maxFixtures {
		return nil, fmt.Errorf(
			"groupSize %d out of range [1,%d] (available key-share fixtures)",
			groupSize, maxFixtures,
		)
	}

	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(groupSize)
	if err != nil {
		return nil, fmt.Errorf("failed to load key-share fixtures: [%v]", err)
	}

	operatorPrivateKey, operatorPublicKey, err := operator.GenerateKeyPair(local_v1.DefaultCurve)
	if err != nil {
		return nil, err
	}

	network := interception.NewNetworkWithStrategy(
		netLocal.ConnectWithKey(operatorPublicKey),
		strategy,
	)

	// The local chain is used only for its Signing() (public-key-to-address
	// conversion) so the membership validator can be built. signing.Execute
	// itself takes no chain - it is driven entirely by the broadcast channel.
	localChain := local_v1.ConnectWithKey(
		groupSize,
		groupSize-dishonestThreshold,
		operatorPrivateKey,
	)

	address, err := localChain.Signing().PublicKeyToAddress(operatorPublicKey)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot convert operator public key to chain address: [%v]",
			err,
		)
	}

	selectedOperators := make([]chain.Address, groupSize)
	for i := range selectedOperators {
		selectedOperators[i] = address
	}

	broadcastChannel, err := network.BroadcastChannelFor(
		fmt.Sprintf("signing-test-%v", message),
	)
	if err != nil {
		return nil, err
	}
	signing.RegisterUnmarshallers(broadcastChannel)

	membershipValidator := group.NewMembershipValidator(
		&testutils.MockLogger{},
		selectedOperators,
		localChain.Signing(),
	)

	sessionID := message.Text(16)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var mutex sync.Mutex
	var signatures []*tecdsa.Signature
	var memberFailures []error

	var wg sync.WaitGroup
	wg.Add(groupSize)
	for i := 0; i < groupSize; i++ {
		memberIndex := group.MemberIndex(i + 1)
		privateKeyShare := tecdsa.NewPrivateKeyShare(testData[i])
		go func() {
			defer wg.Done()
			result, err := signing.Execute(
				ctx,
				&testutils.MockLogger{},
				message,
				sessionID,
				memberIndex,
				privateKeyShare,
				groupSize,
				dishonestThreshold,
				[]group.MemberIndex{}, // no statically-excluded members
				broadcastChannel,
				membershipValidator,
			)

			mutex.Lock()
			defer mutex.Unlock()
			if result != nil {
				signatures = append(signatures, result.Signature)
			}
			if err != nil {
				memberFailures = append(memberFailures, err)
			}
		}()
	}
	wg.Wait()

	return &Result{signatures: signatures, memberFailures: memberFailures}, nil
}

// GroupPublicKey returns the ECDSA public key the fixture key shares correspond
// to, for verifying produced signatures. It loads the first fixture only.
func GroupPublicKey() (*tecdsa.PrivateKeyShare, error) {
	testData, err := tecdsatest.LoadPrivateKeyShareTestFixtures(1)
	if err != nil {
		return nil, err
	}
	return tecdsa.NewPrivateKeyShare(testData[0]), nil
}
