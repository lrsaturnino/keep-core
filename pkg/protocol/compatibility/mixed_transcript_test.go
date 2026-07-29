package compatibility

import (
	"encoding/hex"
	"math/big"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	tsslibcommon "github.com/bnb-chain/tss-lib/common"
	tsslibkeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslibsigning "github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"

	"github.com/keep-network/keep-core/pkg/internal/tecdsatest"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tecdsa"
)

// mixedTranscriptSettleTimeout bounds a ceremony expected never to finish.
// Failing closed can mean a party rejecting a proof or a party never receiving
// one it can accept, and the second ending produces no error to wait on.
const mixedTranscriptSettleTimeout = 60 * time.Second

// TestMixedTranscriptSigningCeremonyFailsClosed asserts a tECDSA signing
// ceremony whose members were configured by different compatibility bundles
// produces no signature.
//
// The two bundles exist so a fleet can cross from one release to the other, and
// the crossing is only worth anything if it is all-or-nothing. A legacy party
// omits the session binding a security-v2 party's GG20 proofs are built on, so
// a ceremony that tolerated a mixture would let one member strip the binding
// off a signature the rest of the group believed carried it — a downgrade
// obtained by joining a ceremony rather than by attacking it. Nothing in the
// bundle-selection tests says anything about that: they check which transcript
// each bundle configures, not what happens when two of them meet.
//
// The property belongs to the pinned tss-lib revision rather than to this
// repository, which is exactly why it is asserted here. `go.mod` resolves one
// revision, this test drives that revision through the bundles that own its
// transcript configuration, and a replacement revision that quietly tolerated a
// mixture would fail here rather than in a rehearsal.
//
// The homogeneous cases are not decoration. A harness that never completes any
// ceremony would pass every mixed case for the wrong reason, so the same driver
// has to produce a real signature when the transcripts agree.
func TestMixedTranscriptSigningCeremonyFailsClosed(t *testing.T) {
	tests := map[string]struct {
		modeAt          func(index int) participation.ProtocolMode
		expectSignature bool
	}{
		"every member on the security-v2 transcript": {
			modeAt: func(int) participation.ProtocolMode {
				return participation.ModeSecurityV2
			},
			expectSignature: true,
		},
		"every member on the legacy transcript": {
			modeAt: func(int) participation.ProtocolMode {
				return participation.ModeLegacy
			},
			expectSignature: true,
		},
		// The downgrade attempt: one member that has not crossed joins a
		// ceremony the rest are running on the hardened transcript.
		"one legacy member among security-v2 members": {
			modeAt: func(index int) participation.ProtocolMode {
				if index == 0 {
					return participation.ModeLegacy
				}
				return participation.ModeSecurityV2
			},
		},
		// The mirror: the member that has crossed must refuse to sign with a
		// group that has not.
		"one security-v2 member among legacy members": {
			modeAt: func(index int) participation.ProtocolMode {
				if index == 0 {
					return participation.ModeSecurityV2
				}
				return participation.ModeLegacy
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			signatures, members, refusals, terminal :=
				runMixedTranscriptSigningCeremony(t, test.modeAt)

			assertMixedTranscriptOutcome(
				t,
				"signature",
				test.expectSignature,
				signatures,
				members,
				refusals,
				terminal,
			)
		})
	}
}

// assertMixedTranscriptOutcome holds a ceremony to the only two endings the
// crossing allows: every member outputs, or no member does.
//
// A partial count is its own failure and neither assertion would catch it. It
// would mean some members finished a ceremony others refused, which is the
// split state the all-or-nothing crossing exists to prevent — a group holding
// key material or a signature that only part of it agrees was produced.
//
// A ceremony that never reached its terminal state decides nothing either way.
// The refusal claim is that no member *will* output, and a group still holding
// live workers has not been shown that; the count in hand is what had appeared
// by the time the drive gave up.
func assertMixedTranscriptOutcome(
	t *testing.T,
	output string,
	expectOutput bool,
	outputs int,
	members int,
	refusals int,
	terminal bool,
) {
	t.Helper()

	if !terminal {
		t.Fatalf(
			"the ceremony was still running after %s with %d/%d %ss and %d "+
				"refusal(s); nothing was observed to terminal completion",
			mixedTranscriptSettleTimeout,
			outputs,
			members,
			output,
			refusals,
		)
	}

	if expectOutput {
		if outputs != members {
			t.Fatalf(
				"a ceremony whose members agree on the transcript produced "+
					"%d/%d %ss; %d member(s) refused",
				outputs,
				members,
				output,
				refusals,
			)
		}
		return
	}

	if outputs != 0 {
		t.Fatalf(
			"a ceremony mixing proof transcripts produced %d/%d %ss",
			outputs,
			members,
			output,
		)
	}
	if refusals == 0 {
		t.Logf(
			"the mixed ceremony produced no %s and no member reported a "+
				"refusal within the settle timeout",
			output,
		)
	}
}

// TestMixedTranscriptKeygenCeremonyFailsClosed asserts a tECDSA key-generation
// ceremony whose members were configured by different compatibility bundles
// produces no key share.
//
// Keygen is the half of the crossing that leaves something behind. A refused
// signing ceremony costs an attempt; a keygen ceremony that tolerated a mixture
// would mint a wallet whose members disagree about which transcript its shares
// were proved under, and that wallet then signs for as long as it exists. The
// legacy party's Paillier and DLN proofs carry no session tag, the security-v2
// party's carry one derived from the ceremony's SSID, and each verifies the
// other's under its own rule — so a revision that let those meet would be
// caught here rather than at the first wallet that could not be trusted.
//
// The homogeneous cases carry the same weight as in signing: a harness that
// never completed a ceremony would pass the mixed cases for the wrong reason.
func TestMixedTranscriptKeygenCeremonyFailsClosed(t *testing.T) {
	tests := map[string]struct {
		modeAt         func(index int) participation.ProtocolMode
		expectKeyShare bool
	}{
		"every member on the security-v2 transcript": {
			modeAt: func(int) participation.ProtocolMode {
				return participation.ModeSecurityV2
			},
			expectKeyShare: true,
		},
		"every member on the legacy transcript": {
			modeAt: func(int) participation.ProtocolMode {
				return participation.ModeLegacy
			},
			expectKeyShare: true,
		},
		// A member that has not crossed joining a wallet the rest are
		// generating on the hardened transcript.
		"one legacy member among security-v2 members": {
			modeAt: func(index int) participation.ProtocolMode {
				if index == 0 {
					return participation.ModeLegacy
				}
				return participation.ModeSecurityV2
			},
		},
		// The mirror: the member that has crossed must refuse to help mint a
		// wallet with a group that has not.
		"one security-v2 member among legacy members": {
			modeAt: func(index int) participation.ProtocolMode {
				if index == 0 {
					return participation.ModeSecurityV2
				}
				return participation.ModeLegacy
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			shares, members, refusals, terminal :=
				runMixedTranscriptKeygenCeremony(t, test.modeAt)

			assertMixedTranscriptOutcome(
				t,
				"key share",
				test.expectKeyShare,
				shares,
				members,
				refusals,
				terminal,
			)
		})
	}
}

// runMixedTranscriptKeygenCeremony drives a real tss-lib key-generation
// ceremony, configuring each party's transcript through the compatibility
// bundle the given mode selects. It reports how many parties produced a key
// share, how many were in the group, and how many refused.
func runMixedTranscriptKeygenCeremony(
	t *testing.T,
	modeAt func(index int) participation.ProtocolMode,
) (shares int, members int, refusals int, terminal bool) {
	t.Helper()

	// Keygen is quadratic in the group and dominated by Paillier work, so the
	// group is the smallest one that still has a member to disagree with.
	const keygenGroupSize = 3
	const tssThreshold = keygenGroupSize - 1

	// The key-share fixtures were themselves produced by a keygen ceremony and
	// carry the pre-parameters each party used. Reusing them is what keeps this
	// test to the protocol under examination: generating fresh safe primes here
	// would add minutes of work that says nothing about proof transcripts.
	fixtures, err := tecdsatest.LoadPrivateKeyShareTestFixtures(keygenGroupSize)
	if err != nil {
		t.Fatalf("failed to load key-share fixtures: [%v]", err)
	}

	partyIDs := make(tss.UnSortedPartyIDs, len(fixtures))
	for i := range fixtures {
		moniker := big.NewInt(int64(i + 1)).String()
		partyIDs[i] = tss.NewPartyID(
			moniker,
			moniker,
			big.NewInt(int64(i+1)),
		)
	}
	sortedPartyIDs := tss.SortPartyIDs(partyIDs)
	peerContext := tss.NewPeerContext(sortedPartyIDs)

	errChan := make(chan *tss.Error, len(sortedPartyIDs)*len(sortedPartyIDs))
	outgoingChan := make(
		chan tss.Message,
		len(sortedPartyIDs)*len(sortedPartyIDs),
	)
	resultChan := make(
		chan tsslibkeygen.LocalPartySaveData,
		len(sortedPartyIDs),
	)

	parties := make([]tss.Party, 0, len(sortedPartyIDs))
	for i := range sortedPartyIDs {
		strategies, err := StrategiesFor(modeAt(i))
		if err != nil {
			t.Fatalf("failed to resolve the compatibility bundle: [%v]", err)
		}

		parameters := tss.NewParameters(
			tecdsa.Curve,
			peerContext,
			sortedPartyIDs[i],
			len(sortedPartyIDs),
			tssThreshold,
		)
		// The session ID is the ceremony's, not the member's: a mixed group
		// disagrees about the transcript, never about which ceremony it is in.
		if err := strategies.ConfigureTSSParameters(
			parameters,
			mixedTranscriptDKGSessionID,
		); err != nil {
			t.Fatalf("failed to configure the TSS parameters: [%v]", err)
		}

		parties = append(parties, tsslibkeygen.NewLocalParty(
			parameters,
			outgoingChan,
			resultChan,
			fixtures[i].LocalPreParams,
		))
	}

	shares, refusals, terminal = driveTSSCeremony(
		parties,
		outgoingChan,
		resultChan,
		errChan,
	)
	return shares, len(parties), refusals, terminal
}

// mixedTranscriptDKGSessionID is a ceremony session identifier long enough to
// clear the security-v2 bundle's proof-binding floor.
const mixedTranscriptDKGSessionID = "dkg-64757a1f-0000000000000001"

// runMixedTranscriptSigningCeremony drives a real tss-lib signing ceremony over
// the tECDSA key-share fixtures, configuring each party's transcript through the
// compatibility bundle the given mode selects. It reports how many parties
// produced a signature, how many were in the group, and how many refused.
func runMixedTranscriptSigningCeremony(
	t *testing.T,
	modeAt func(index int) participation.ProtocolMode,
) (signatures int, members int, refusals int, terminal bool) {
	t.Helper()

	// The fixtures are a 3-of-5 group, so three members carry the signing
	// threshold. Fewer parties is a faster ceremony and the same transcript.
	const signingGroupSize = 3
	const tssThreshold = signingGroupSize - 1

	shares, err := tecdsatest.LoadPrivateKeyShareTestFixtures(signingGroupSize)
	if err != nil {
		t.Fatalf("failed to load key-share fixtures: [%v]", err)
	}

	// tss-lib identifies a party by its key share's identifier and expects the
	// peer context sorted by it, so the shares are ordered the same way before
	// they are handed to the parties that hold them.
	sort.Slice(shares, func(i, j int) bool {
		return shares[i].ShareID.Cmp(shares[j].ShareID) < 0
	})
	partyIDs := make(tss.UnSortedPartyIDs, len(shares))
	for i, share := range shares {
		moniker := big.NewInt(int64(i + 1)).String()
		partyIDs[i] = tss.NewPartyID(moniker, moniker, share.ShareID)
	}
	sortedPartyIDs := tss.SortPartyIDs(partyIDs)
	peerContext := tss.NewPeerContext(sortedPartyIDs)

	messageBytes, err := hex.DecodeString(
		"00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5",
	)
	if err != nil {
		t.Fatal(err)
	}
	message := new(big.Int).SetBytes(messageBytes)

	// A refusing party can be reported once per peer that keeps delivering to
	// it, so the channels are sized past one per party to keep the routing
	// goroutines from blocking once the ceremony is decided.
	errChan := make(chan *tss.Error, len(sortedPartyIDs)*len(sortedPartyIDs))
	outgoingChan := make(
		chan tss.Message,
		len(sortedPartyIDs)*len(sortedPartyIDs),
	)
	resultChan := make(chan tsslibcommon.SignatureData, len(sortedPartyIDs))

	parties := make([]tss.Party, 0, len(sortedPartyIDs))
	for i := range sortedPartyIDs {
		strategies, err := StrategiesFor(modeAt(i))
		if err != nil {
			t.Fatalf("failed to resolve the compatibility bundle: [%v]", err)
		}

		parameters := tss.NewParameters(
			tecdsa.Curve,
			peerContext,
			sortedPartyIDs[i],
			len(sortedPartyIDs),
			tssThreshold,
		)
		// The session ID is the ceremony's, not the member's: a mixed group
		// disagrees about the transcript, never about which ceremony it is in.
		if err := strategies.ConfigureTSSParameters(
			parameters,
			mixedTranscriptSessionID,
		); err != nil {
			t.Fatalf("failed to configure the TSS parameters: [%v]", err)
		}

		fullBytesLen := (tecdsa.Curve.Params().N.BitLen() + 7) / 8
		parties = append(parties, tsslibsigning.NewLocalParty(
			message,
			parameters,
			shares[i],
			outgoingChan,
			resultChan,
			fullBytesLen,
		))
	}

	signatures, refusals, terminal = driveTSSCeremony(
		parties,
		outgoingChan,
		resultChan,
		errChan,
	)
	return signatures, len(parties), refusals, terminal
}

// mixedTranscriptSessionID is a ceremony session identifier long enough to
// clear the security-v2 bundle's proof-binding floor.
const mixedTranscriptSessionID = "signing-64757a1f-0000000000000001"

// driveTSSCeremony starts every party and routes messages between them until
// the ceremony can produce nothing further. It reports how many parties output
// a result, how many refusals were seen, and whether the ceremony was watched
// all the way to that terminal state.
//
// The terminal state is the point of this function. A tss-lib party emits its
// messages and its save data from inside Start and UpdateFromBytes — every
// goroutine a round spawns is joined before the round returns — so a ceremony
// with no Start and no delivery still running, and nothing left queued to
// deliver, has no path left by which a signature or a key share could appear.
// That is a state this function can join and observe. A stretch of silence is
// not: it says the ceremony has produced nothing *yet*, which is what a slow
// round also looks like, and a caller asserting that nothing was output would
// be asserting it of a group still holding workers that could output.
//
// A refusal therefore does not end the drive either. What is under test is that
// a mixed group produces nothing, and stopping at the first error would only
// establish that one party complained — a group that reported a refusal and
// then went on to output a signature anyway would look identical. Routing
// continues, the result channel keeps being watched, and the count the caller
// asserts on is the number of outputs observed over the whole ceremony.
//
// The settle timeout bounds a party that hangs inside tss-lib rather than
// returning. It is reported as a failure to reach the terminal state rather
// than folded into the counts, because a ceremony still running proves nothing
// about what it will not produce.
//
// It is generic over the result type because keygen and signing deliver
// different save data over otherwise identical plumbing, and the property being
// asserted is about how many results appear, not what is in them.
func driveTSSCeremony[R any](
	parties []tss.Party,
	outgoingChan <-chan tss.Message,
	resultChan <-chan R,
	errChan chan *tss.Error,
) (outputs int, refusals int, terminal bool) {
	// Everything that can still put something on one of the channels below:
	// each party's Start, and each delivery into a party. Only the loop below
	// adds to it, and it does so before releasing the worker, so a count of
	// zero read there means no party code is executing anywhere.
	var running atomic.Int64
	// Coalescing and never blocking, because its only job is to wake the loop
	// so it re-reads the count. A worker that could block here would be a
	// worker the count never releases.
	woken := make(chan struct{}, 1)
	run := func(work func()) {
		running.Add(1)
		go func() {
			defer func() {
				running.Add(-1)
				select {
				case woken <- struct{}{}:
				default:
				}
			}()
			work()
		}()
	}

	// A refusing party keeps refusing every later delivery, so reports can
	// outnumber the channel long after the ceremony is decided. Dropping the
	// surplus is what keeps a delivery from blocking on a full channel, which
	// would leave a worker the count never releases; the first report already
	// carries everything the caller reads.
	report := func(err *tss.Error) {
		select {
		case errChan <- err:
		default:
		}
	}

	deliver := func(to tss.Party, message tss.Message) {
		run(func() {
			bytes, routingInfo, err := message.WireBytes()
			if err != nil {
				report(to.WrapError(err))
				return
			}
			if _, err := to.UpdateFromBytes(
				bytes,
				routingInfo.From,
				routingInfo.IsBroadcast,
			); err != nil {
				report(err)
			}
		})
	}

	route := func(message tss.Message) {
		destinations := message.GetTo()
		if destinations == nil {
			for _, party := range parties {
				if party.PartyID().Index == message.GetFrom().Index {
					continue
				}
				deliver(party, message)
			}
			return
		}
		for _, destination := range destinations {
			deliver(parties[destination.Index], message)
		}
	}

	// A party that cannot start emits nothing, so its error is the only thing
	// that says the ceremony went anywhere.
	for _, party := range parties {
		run(func() {
			if err := party.Start(); err != nil {
				report(err)
			}
		})
	}

	settled := time.After(mixedTranscriptSettleTimeout)

	for {
		if running.Load() == 0 {
			// Nothing is executing, so nothing can be added to these channels
			// any more and whatever is already on them is all there will ever
			// be. Taking it here rather than declaring the ceremony over keeps
			// a result that landed in the same instant as the last worker
			// returned counted against the caller's claim.
			select {
			case <-errChan:
				refusals++
			case <-resultChan:
				outputs++
			case message := <-outgoingChan:
				route(message)
			default:
				return outputs, refusals, true
			}
			continue
		}

		select {
		case <-errChan:
			refusals++

		case message := <-outgoingChan:
			route(message)

		case <-resultChan:
			outputs++

		case <-woken:

		case <-settled:
			return outputs, refusals, false
		}
	}
}
