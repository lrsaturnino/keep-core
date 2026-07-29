package compatibility

import (
	"encoding/hex"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	tsslibcommon "github.com/bnb-chain/tss-lib/common"
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

// TestMixedTranscriptCeremonyFailsClosed asserts a tECDSA signing ceremony
// whose members were configured by different compatibility bundles produces no
// signature.
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
func TestMixedTranscriptCeremonyFailsClosed(t *testing.T) {
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
			signed, refusals := runMixedTranscriptCeremony(t, test.modeAt)

			if test.expectSignature {
				if !signed {
					t.Fatalf(
						"a ceremony whose members agree on the transcript "+
							"produced no signature; %d member(s) refused",
						refusals,
					)
				}
				return
			}

			if signed {
				t.Fatal(
					"a ceremony mixing proof transcripts produced a signature",
				)
			}
			if refusals == 0 {
				t.Log(
					"the mixed ceremony produced no signature and no member " +
						"reported a refusal within the settle timeout",
				)
			}
		})
	}
}

// runMixedTranscriptCeremony drives a real tss-lib signing ceremony over the
// tECDSA key-share fixtures, configuring each party's transcript through the
// compatibility bundle the given mode selects. It reports whether the group
// produced a signature and how many parties refused.
func runMixedTranscriptCeremony(
	t *testing.T,
	modeAt func(index int) participation.ProtocolMode,
) (bool, int) {
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

	for _, party := range parties {
		go func(party tss.Party) {
			if err := party.Start(); err != nil {
				errChan <- err
			}
		}(party)
	}

	return driveTSSCeremony(parties, outgoingChan, resultChan, errChan)
}

// mixedTranscriptSessionID is a ceremony session identifier long enough to
// clear the security-v2 bundle's proof-binding floor.
const mixedTranscriptSessionID = "signing-64757a1f-0000000000000001"

// driveTSSCeremony routes messages between parties until the group signs, one
// party refuses, or the ceremony has had long enough to do either.
func driveTSSCeremony(
	parties []tss.Party,
	outgoingChan <-chan tss.Message,
	resultChan <-chan tsslibcommon.SignatureData,
	errChan chan *tss.Error,
) (bool, int) {
	var routing sync.WaitGroup
	defer routing.Wait()

	// A refusing party keeps refusing every later delivery, so reports can
	// outnumber the channel long after the ceremony is decided. Dropping the
	// surplus is what lets this function return: a routing goroutine still
	// blocked on a full channel would hold the wait below forever, and the
	// first report already carries everything the caller reads.
	report := func(err *tss.Error) {
		select {
		case errChan <- err:
		default:
		}
	}

	deliver := func(to tss.Party, message tss.Message) {
		routing.Add(1)
		go func() {
			defer routing.Done()

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
		}()
	}

	completed := 0
	refusals := 0
	settled := time.After(mixedTranscriptSettleTimeout)

	for {
		select {
		case <-errChan:
			// One refusal already decides it: signing needs every selected
			// member, so a member that stopped is a ceremony that cannot
			// produce a signature.
			return false, refusals + 1

		case message := <-outgoingChan:
			destinations := message.GetTo()
			if destinations == nil {
				for _, party := range parties {
					if party.PartyID().Index ==
						message.GetFrom().Index {
						continue
					}
					deliver(party, message)
				}
				continue
			}
			for _, destination := range destinations {
				deliver(parties[destination.Index], message)
			}

		case <-resultChan:
			completed++
			if completed == len(parties) {
				return true, refusals
			}

		case <-settled:
			return false, refusals
		}
	}
}
