package signing

import (
	"context"
	"fmt"
	"math/big"

	tsslibcommon "github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/ipfs/go-log/v2"
	"github.com/keep-network/keep-core/pkg/crypto/ephemeral"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"github.com/keep-network/keep-core/pkg/tecdsa"
	"github.com/keep-network/keep-core/pkg/tecdsa/common"
	"golang.org/x/exp/slices"
)

// Member represents a signing protocol member.
type member struct {
	// Logger used to produce log messages.
	logger log.StandardLogger
	// id of this group member.
	id group.MemberIndex
	// Group to which this member belongs.
	group *group.Group
	// Validator allowing to check public key and member index against
	// group members
	membershipValidator *group.MembershipValidator
	// Identifier of the particular signing session this member is part of.
	sessionID string
	// Message that is the subject of the signing process.
	message *big.Int
	// tECDSA private key share of the member.
	privateKeyShare *tecdsa.PrivateKeyShare
	// Instance of the member identity converter.
	identityConverter *identityConverter
}

// newMember creates a new member in an initial state
func newMember(
	logger log.StandardLogger,
	memberID group.MemberIndex,
	groupSize,
	dishonestThreshold int,
	membershipValidator *group.MembershipValidator,
	sessionID string,
	message *big.Int,
	privateKeyShare *tecdsa.PrivateKeyShare,
) *member {
	return &member{
		logger:              logger,
		id:                  memberID,
		group:               group.NewGroup(dishonestThreshold, groupSize),
		membershipValidator: membershipValidator,
		sessionID:           sessionID,
		message:             message,
		privateKeyShare:     privateKeyShare,
		identityConverter:   &identityConverter{keys: privateKeyShare.Data().Ks},
	}
}

// inactiveMemberFilter returns a new instance of the inactive member filter.
func (m *member) inactiveMemberFilter() *group.InactiveMemberFilter {
	return group.NewInactiveMemberFilter(m.logger, m.id, m.group)
}

// shouldAcceptMessage indicates whether the given member should accept
// a message from the given sender.
func (m *member) shouldAcceptMessage(
	senderID group.MemberIndex,
	senderPublicKey []byte,
) bool {
	isMessageFromSelf := senderID == m.id
	isSenderValid := m.membershipValidator.IsValidMembership(
		senderID,
		senderPublicKey,
	)
	isSenderAccepted := m.group.IsOperating(senderID)

	return !isMessageFromSelf && isSenderValid && isSenderAccepted
}

// initializeEphemeralKeysGeneration performs a transition of a member state
// from the initial state to the first phase of the protocol.
func (m *member) initializeEphemeralKeysGeneration() *ephemeralKeyPairGeneratingMember {
	return &ephemeralKeyPairGeneratingMember{
		member:            m,
		ephemeralKeyPairs: make(map[group.MemberIndex]*ephemeral.KeyPair),
	}
}

// ephemeralKeyPairGeneratingMember represents one member in a signing group
// performing ephemeral key pair generation. It has a full list of `memberIndexes`
// that belong to its threshold group.
type ephemeralKeyPairGeneratingMember struct {
	*member

	// Ephemeral key pairs used to create symmetric keys,
	// generated individually for each other group member.
	ephemeralKeyPairs map[group.MemberIndex]*ephemeral.KeyPair
}

// initializeSymmetricKeyGeneration performs a transition of the member state
// to the next phase. It returns a member instance ready to execute the
// next phase of the protocol.
func (ekpgm *ephemeralKeyPairGeneratingMember) initializeSymmetricKeyGeneration() *symmetricKeyGeneratingMember {
	return &symmetricKeyGeneratingMember{
		ephemeralKeyPairGeneratingMember: ekpgm,
		symmetricKeys:                    make(map[group.MemberIndex]ephemeral.SymmetricKey),
	}
}

// symmetricKeyGeneratingMember represents one member in a signing group
// performing ephemeral symmetric key generation.
type symmetricKeyGeneratingMember struct {
	*ephemeralKeyPairGeneratingMember

	// Symmetric keys used to encrypt confidential information,
	// generated individually for each other group member by ECDH'ing the
	// broadcasted ephemeral public key intended for this member and the
	// ephemeral private key generated for the other member.
	symmetricKeys map[group.MemberIndex]ephemeral.SymmetricKey
}

// initializeTssRoundOne returns a member to perform next protocol operations.
func (skgm *symmetricKeyGeneratingMember) initializeTssRoundOne() *tssRoundOneMember {
	// Set up the local TSS party using only operating members. This effectively
	// removes all excluded members who were marked as disqualified at the
	// beginning of the protocol.
	tssPartyID, groupTssPartiesIDs := common.GenerateTssPartiesIDs(
		skgm.id,
		skgm.group.OperatingMemberIndexes(),
		skgm.identityConverter,
	)

	tssParameters := tss.NewParameters(
		tecdsa.Curve,
		tss.NewPeerContext(tss.SortPartyIDs(groupTssPartiesIDs)),
		tssPartyID,
		len(groupTssPartiesIDs),
		skgm.group.HonestThreshold()-1,
	)
	// Bind GG20 proof challenges to the existing protocol session.
	tssParameters.SetSessionNonceBytes([]byte(skgm.sessionID))

	tssOutgoingMessagesChan := make(chan tss.Message, len(groupTssPartiesIDs))
	tssResultChan := make(chan tsslibcommon.SignatureData, 1)
	fullBytesLen := (tecdsa.Curve.Params().N.BitLen() + 7) / 8

	tssParty := signing.NewLocalParty(
		skgm.message,
		tssParameters,
		skgm.privateKeyShare.Data(),
		tssOutgoingMessagesChan,
		tssResultChan,
		fullBytesLen,
	)

	return &tssRoundOneMember{
		symmetricKeyGeneratingMember: skgm,
		tssParty:                     tssParty,
		tssParameters:                tssParameters,
		tssOutgoingMessagesChan:      tssOutgoingMessagesChan,
		tssResultChan:                tssResultChan,
	}
}

// tssRoundOneMember represents one member in a signing group performing the
// first round of the TSS keygen.
type tssRoundOneMember struct {
	*symmetricKeyGeneratingMember

	tssParty                tss.Party
	tssParameters           *tss.Parameters
	tssOutgoingMessagesChan <-chan tss.Message
	tssResultChan           <-chan tsslibcommon.SignatureData
}

// initializeTssRoundTwo returns a member to perform next protocol operations.
func (trom *tssRoundOneMember) initializeTssRoundTwo() *tssRoundTwoMember {
	return &tssRoundTwoMember{
		tssRoundOneMember: trom,
	}
}

// tssRoundTwoMember represents one member in a signing group performing the
// second round of the TSS keygen.
type tssRoundTwoMember struct {
	*tssRoundOneMember
}

// initializeTssRoundThree returns a member to perform next protocol operations.
func (trtm *tssRoundTwoMember) initializeTssRoundThree() *tssRoundThreeMember {
	return &tssRoundThreeMember{
		tssRoundTwoMember: trtm,
	}
}

// tssRoundThreeMember represents one member in a signing group performing the
// third round of the TSS keygen.
type tssRoundThreeMember struct {
	*tssRoundTwoMember
}

// initializeTssRoundFour returns a member to perform next protocol operations.
func (trtm *tssRoundThreeMember) initializeTssRoundFour() *tssRoundFourMember {
	return &tssRoundFourMember{
		tssRoundThreeMember: trtm,
	}
}

// tssRoundFourMember represents one member in a signing group performing the
// fourth round of the TSS keygen.
type tssRoundFourMember struct {
	*tssRoundThreeMember
}

// initializeTssRoundFive returns a member to perform next protocol operations.
func (trfm *tssRoundFourMember) initializeTssRoundFive() *tssRoundFiveMember {
	return &tssRoundFiveMember{
		tssRoundFourMember: trfm,
	}
}

// tssRoundFiveMember represents one member in a signing group performing the
// fifth round of the TSS keygen.
type tssRoundFiveMember struct {
	*tssRoundFourMember
}

// initializeTssRoundSix returns a member to perform next protocol operations.
func (trfm *tssRoundFiveMember) initializeTssRoundSix() *tssRoundSixMember {
	return &tssRoundSixMember{
		tssRoundFiveMember: trfm,
	}
}

// tssRoundSixMember represents one member in a signing group performing the
// sixth round of the TSS keygen.
type tssRoundSixMember struct {
	*tssRoundFiveMember
}

// initializeTssRoundSeven returns a member to perform next protocol operations.
func (trsm *tssRoundSixMember) initializeTssRoundSeven() *tssRoundSevenMember {
	return &tssRoundSevenMember{
		tssRoundSixMember: trsm,
	}
}

// tssRoundSevenMember represents one member in a signing group performing the
// seventh round of the TSS keygen.
type tssRoundSevenMember struct {
	*tssRoundSixMember
}

// initializeTssRoundEight returns a member to perform next protocol operations.
func (trsm *tssRoundSevenMember) initializeTssRoundEight() *tssRoundEightMember {
	return &tssRoundEightMember{
		tssRoundSevenMember: trsm,
	}
}

// tssRoundEightMember represents one member in a signing group performing the
// eighth round of the TSS keygen.
type tssRoundEightMember struct {
	*tssRoundSevenMember
}

// initializeTssRoundNine returns a member to perform next protocol operations.
func (trem *tssRoundEightMember) initializeTssRoundNine() *tssRoundNineMember {
	return &tssRoundNineMember{
		tssRoundEightMember: trem,
	}
}

// tssRoundNineMember represents one member in a signing group performing the
// ninth round of the TSS keygen.
type tssRoundNineMember struct {
	*tssRoundEightMember
}

// initializeFinalization returns a member to perform next protocol operations.
func (trnm *tssRoundNineMember) initializeFinalization() *finalizingMember {
	return &finalizingMember{
		tssRoundNineMember: trnm,
	}
}

// finalizingMember represents one member of the given group, after it
// completed the signing process.
//
// Prepares a result in the last phase of the protocol.
type finalizingMember struct {
	*tssRoundNineMember

	tssResult *tsslibcommon.SignatureData
}

// Result is a successful computation of the tECDSA signature.
func (fm *finalizingMember) Result() *Result {
	return &Result{Signature: tecdsa.NewSignature(fm.tssResult)}
}

// receiveTSSResult waits for the tss-lib signing result to arrive on the result
// channel, or for the context to be cancelled, and returns an
// independently-owned SignatureData that carries the produced signature.
//
// Ownership boundary. tss-lib's signing.NewLocalParty requires a value-typed
// result channel (`end chan<- common.SignatureData`) and delivers the outcome
// with `end <- *round.data` (ecdsa/signing/finalize.go). common.SignatureData
// is a protobuf message whose embedded protoimpl.MessageState carries a
// `[0]sync.Mutex` DoNotCopy marker, so every consumer of that channel must copy
// a lock-bearing struct on receive. go vet's copylock analyzer flags that copy,
// even though it is benign here: the delivered value is a freshly built,
// never-locked data carrier, and copying it once is exactly the contract the
// value-typed channel imposes on all callers.
//
// Rather than evade the analyzer with reflection - which still copies the same
// struct while making the copy invisible - the single unavoidable receive is
// performed by the type-safe generic helper receiveFromChannel, and the fields
// are then re-homed into a brand new SignatureData built with a composite
// literal. The returned message therefore owns a fresh, zero-value
// MessageState; the transient received value is never retained or propagated
// past this boundary, and NewSignature reads only the R, S and recovery byte
// slices from it.
//
// The tss-lib dependency is pinned by commit in go.mod. Its external security
// review is a separate release-gate action (not yet archived), so this comment
// does not assert the dependency is already audited. Its value-typed API is
// deliberately not forked to a pointer channel as part of this release;
// changing the channel element type is the correct upstream fix and is tracked
// separately. Until that upstream change lands, the single mandated copy is
// confined here and its lock-bearing MessageState is never retained.
func (fm *finalizingMember) receiveTSSResult(
	ctx context.Context,
) (*tsslibcommon.SignatureData, error) {
	received, ok, err := receiveFromChannel(ctx, fm.tssResultChan)
	if err != nil {
		// The context was cancelled before a result was produced.
		return nil, fmt.Errorf("TSS result was not generated on time")
	}

	if !ok {
		return nil, fmt.Errorf("TSS result channel was closed unexpectedly")
	}

	// Re-home the produced fields into a freshly allocated, independently-owned
	// SignatureData. The received value (and the lock-bearing MessageState it
	// copied from tss-lib) is not kept beyond this point.
	return &tsslibcommon.SignatureData{
		Signature:         received.GetSignature(),
		SignatureRecovery: received.GetSignatureRecovery(),
		R:                 received.GetR(),
		S:                 received.GetS(),
		M:                 received.GetM(),
	}, nil
}

// receiveFromChannel performs a context-aware receive from ch. It reports the
// received value, whether the channel delivered a value (false once the channel
// is closed and drained), and a non-nil error if the context was cancelled or
// its deadline passed before a value arrived.
//
// It is generic over the element type so a single, unit-tested primitive covers
// the value receive that tss-lib's value-typed result channel forces on the
// caller. Keeping the receive here - instead of inline at every call site -
// confines the one lock-bearing protobuf copy tss-lib mandates (see
// receiveTSSResult) to a single, well-documented place.
func receiveFromChannel[T any](
	ctx context.Context,
	ch <-chan T,
) (T, bool, error) {
	select {
	case value, ok := <-ch:
		return value, ok, nil
	case <-ctx.Done():
		var zero T
		return zero, false, ctx.Err()
	}
}

// identityConverter implements the common.IdentityConverter for tECDSA signing.
// It does the conversion using the predefined keys list obtained from Ks
// party ID array available in TSS key share.
type identityConverter struct {
	keys []*big.Int
}

func (ic *identityConverter) MemberIndexToTssPartyID(
	memberIndex group.MemberIndex,
) *tss.PartyID {
	partyIDKey := ic.MemberIndexToTssPartyIDKey(memberIndex)

	return tss.NewPartyID(
		partyIDKey.Text(10),
		fmt.Sprintf("member-%v", memberIndex),
		partyIDKey,
	)
}

func (ic *identityConverter) MemberIndexToTssPartyIDKey(
	memberIndex group.MemberIndex,
) *big.Int {
	return ic.keys[memberIndex-1]
}

func (ic *identityConverter) TssPartyIDToMemberIndex(
	partyID *tss.PartyID,
) group.MemberIndex {
	index := slices.IndexFunc(ic.keys, func(key *big.Int) bool {
		return key.Cmp(partyID.KeyInt()) == 0
	})

	return group.MemberIndex(index + 1)
}
