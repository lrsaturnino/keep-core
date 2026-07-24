// Package announcer contains an implementation of a generic protocol announcer
// that can be used to determine live participants of an interactive protocol
// before executing the given protocol session.
package announcer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/keep-network/keep-core/pkg/net"
	"github.com/keep-network/keep-core/pkg/protocol/announcer/gen/pb"
	"github.com/keep-network/keep-core/pkg/protocol/group"
	"google.golang.org/protobuf/proto"
)

// announceReceiveBuffer is a buffer for messages received from the broadcast
// channel needed when the announcer's consumer is temporarily too slow to
// handle them. Keep in mind that although we expect only 51 announce messages,
// it may happen that the announcer receives retransmissions of messages from
// the previous signing protocol and before they are filtered out as not
// interesting for the announcer, they are buffered in the channel.
const announceReceiveBuffer = 512

// announcementMessage represents a message that is used to announce
// member's participation in the given session of the protocol.
type announcementMessage struct {
	senderID   group.MemberIndex
	protocolID string
	sessionID  string
}

func (am *announcementMessage) Marshal() ([]byte, error) {
	return proto.Marshal(&pb.AnnouncementMessage{
		SenderID:   uint32(am.senderID),
		ProtocolID: am.protocolID,
		SessionID:  am.sessionID,
	})
}

func (am *announcementMessage) Unmarshal(bytes []byte) error {
	pbMessage := pb.AnnouncementMessage{}
	if err := proto.Unmarshal(bytes, &pbMessage); err != nil {
		return fmt.Errorf(
			"failed to unmarshal AnnouncementMessage: [%v]",
			err,
		)
	}

	if senderID := pbMessage.SenderID; senderID > group.MaxMemberIndex {
		return fmt.Errorf("invalid member index value: [%v]", senderID)
	} else {
		am.senderID = group.MemberIndex(senderID)
	}

	am.protocolID = pbMessage.ProtocolID
	am.sessionID = pbMessage.SessionID

	return nil
}

func (am *announcementMessage) Type() string {
	return "protocol_announcer/announcement_message"
}

// SessionIDFormat classifies the wire format of an announcement session ID
// without exposing the raw identifier. It is used to distinguish legacy peers
// from hardened (security-v2) peers during a coordinated cutover.
type SessionIDFormat uint8

const (
	// SessionIDFormatUnknown denotes a session ID that matches neither the
	// legacy nor a hardened format.
	SessionIDFormatUnknown SessionIDFormat = iota
	// SessionIDFormatLegacy denotes the pre-hardening form: one lowercase
	// hexadecimal seed/message component and one unsigned decimal attempt
	// component, separated by a single hyphen (e.g. "abc123-4").
	SessionIDFormatLegacy
	// SessionIDFormatHardenedDKG denotes the hardened tECDSA DKG form
	// "dkg-<hex>-<16 hex digits>".
	SessionIDFormatHardenedDKG
	// SessionIDFormatHardenedSigning denotes the hardened tECDSA signing form
	// "signing-<hex>-<16 hex digits>-<16 hex digits>".
	SessionIDFormatHardenedSigning
)

// String returns a stable, log-safe label for the session ID format.
func (f SessionIDFormat) String() string {
	switch f {
	case SessionIDFormatLegacy:
		return "legacy"
	case SessionIDFormatHardenedDKG:
		return "hardened_dkg"
	case SessionIDFormatHardenedSigning:
		return "hardened_signing"
	default:
		return "unknown"
	}
}

// IsHardened reports whether the format is one of the hardened (security-v2)
// forms.
func (f SessionIDFormat) IsHardened() bool {
	return f == SessionIDFormatHardenedDKG || f == SessionIDFormatHardenedSigning
}

// ClassifySessionIDFormat classifies a session ID into one of the known formats
// without retaining or exposing the raw identifier. The classification is
// purely structural and mirrors the exact formats produced by the tBTC DKG and
// signing loops:
//
//   - hardened DKG:     "dkg-<hex>-<16 hex digits>"
//   - hardened signing: "signing-<hex>-<16 hex digits>-<16 hex digits>"
//   - legacy:           "<lowercase hex>-<unsigned decimal>"
//   - otherwise:        unknown
func ClassifySessionIDFormat(sessionID string) SessionIDFormat {
	parts := strings.Split(sessionID, "-")

	switch {
	case len(parts) == 3 &&
		parts[0] == "dkg" &&
		isLowerHex(parts[1]) &&
		isFixedWidthLowerHex(parts[2], 16):
		return SessionIDFormatHardenedDKG
	case len(parts) == 4 &&
		parts[0] == "signing" &&
		isLowerHex(parts[1]) &&
		isFixedWidthLowerHex(parts[2], 16) &&
		isFixedWidthLowerHex(parts[3], 16):
		return SessionIDFormatHardenedSigning
	case len(parts) == 2 &&
		isLowerHex(parts[0]) &&
		isDecimal(parts[1]):
		return SessionIDFormatLegacy
	default:
		return SessionIDFormatUnknown
	}
}

// IsCrossFormatMismatch reports whether two session ID formats represent a
// legacy-versus-hardened mismatch (as opposed to two differing formats on the
// same side of the cutover). Only cross-format mismatches indicate a peer on
// the opposite side of the cutover.
func IsCrossFormatMismatch(a, b SessionIDFormat) bool {
	return (a == SessionIDFormatLegacy && b.IsHardened()) ||
		(b == SessionIDFormatLegacy && a.IsHardened())
}

// isLowerHex reports whether s is a non-empty string of lowercase hexadecimal
// digits.
func isLowerHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isFixedWidthLowerHex reports whether s is exactly width lowercase hexadecimal
// digits.
func isFixedWidthLowerHex(s string, width int) bool {
	return len(s) == width && isLowerHex(s)
}

// isDecimal reports whether s is a non-empty string of decimal digits.
func isDecimal(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SessionMismatchObserver is invoked once per membership-valid, protocol-matched
// sender per Announce call whose announced session ID differs from the local
// session ID. It receives only the protocol ID, the sender's group member
// index, and the classified expected/observed formats — never the raw session
// IDs — so it is safe to log or aggregate. expectedFormat is the format of the
// local node's own session ID; observedFormat is the sender's.
type SessionMismatchObserver func(
	protocolID string,
	sender group.MemberIndex,
	expectedFormat SessionIDFormat,
	observedFormat SessionIDFormat,
)

// Option configures optional Announcer behavior. It is source-compatible: the
// existing three-argument New calls continue to compile unchanged.
type Option func(*Announcer)

// WithSessionMismatchObserver installs an observer that is invoked when a
// membership-valid, protocol-matched announcement carries a session ID that
// differs from the local session ID. The observer is called at most once per
// sender per Announce call. A nil observer is equivalent to not setting one.
func WithSessionMismatchObserver(observer SessionMismatchObserver) Option {
	return func(a *Announcer) {
		a.sessionMismatchObserver = observer
	}
}

// Announcer is an implementation of the protocol announcer that performs the
// readiness announcement over the provided broadcast channel.
type Announcer struct {
	protocolID              string
	broadcastChannel        net.BroadcastChannel
	membershipValidator     *group.MembershipValidator
	sessionMismatchObserver SessionMismatchObserver
}

// RegisterUnmarshaller initializes the given broadcast channel to be able to
// handle announcement messages by registering the required unmarshaller.
func RegisterUnmarshaller(channel net.BroadcastChannel) {
	channel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &announcementMessage{}
	})
}

// New creates a new instance of the Announcer. It expects a unique protocol
// identifier, a broadcast channel configured to mediate between group members,
// and a membership validator configured to validate the group membership of
// announcements senders.
func New(
	protocolID string,
	broadcastChannel net.BroadcastChannel,
	membershipValidator *group.MembershipValidator,
	options ...Option,
) *Announcer {
	announcer := &Announcer{
		protocolID:          protocolID,
		broadcastChannel:    broadcastChannel,
		membershipValidator: membershipValidator,
	}

	for _, option := range options {
		option(announcer)
	}

	return announcer
}

// Announce sends the member's readiness announcement for the given protocol
// session and listens for announcements from other group members. It returns a
// list of unique members indexes that are ready for the given attempt,
// including the executing member's index. The list is sorted in ascending order.
// This function blocks until the ctx passed as argument is done.
func (a *Announcer) Announce(
	ctx context.Context,
	memberIndex group.MemberIndex,
	sessionID string,
) (
	[]group.MemberIndex,
	error,
) {
	messagesChan := make(chan net.Message, announceReceiveBuffer)

	a.broadcastChannel.Recv(ctx, func(message net.Message) {
		messagesChan <- message
	})

	err := a.broadcastChannel.Send(ctx, &announcementMessage{
		senderID:   memberIndex,
		protocolID: a.protocolID,
		sessionID:  sessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot send announcement message: [%w]", err)
	}

	readyMembersIndexesSet := make(map[group.MemberIndex]bool)
	// Mark itself as ready.
	readyMembersIndexesSet[memberIndex] = true

	// Tracks senders already reported to the session mismatch observer during
	// this Announce call so each mismatching sender is counted at most once.
	mismatchObservedSenders := make(map[group.MemberIndex]bool)

loop:
	for {
		select {
		case netMessage := <-messagesChan:
			announcement, ok := netMessage.Payload().(*announcementMessage)
			if !ok {
				continue
			}

			if announcement.senderID == memberIndex {
				continue
			}

			if !a.membershipValidator.IsValidMembership(
				announcement.senderID,
				netMessage.SenderPublicKey(),
			) {
				continue
			}

			if announcement.protocolID != a.protocolID {
				continue
			}

			if announcement.sessionID != sessionID {
				// The sender is a valid group member announcing for this
				// protocol but with a different session ID. During a
				// coordinated cutover this is how a peer on the opposite side
				// of the boundary is observed. Report it to the optional
				// observer, once per sender per call, before discarding the
				// announcement. Only structural formats are exposed, never the
				// raw session IDs.
				if a.sessionMismatchObserver != nil &&
					!mismatchObservedSenders[announcement.senderID] {
					mismatchObservedSenders[announcement.senderID] = true
					a.sessionMismatchObserver(
						announcement.protocolID,
						announcement.senderID,
						ClassifySessionIDFormat(sessionID),
						ClassifySessionIDFormat(announcement.sessionID),
					)
				}
				continue
			}

			readyMembersIndexesSet[announcement.senderID] = true
		case <-ctx.Done():
			break loop
		}
	}

	readyMembersIndexes := make([]group.MemberIndex, 0)
	for memberIndex := range readyMembersIndexesSet {
		readyMembersIndexes = append(readyMembersIndexes, memberIndex)
	}

	sort.Slice(readyMembersIndexes, func(i, j int) bool {
		return readyMembersIndexes[i] < readyMembersIndexes[j]
	})

	return readyMembersIndexes, nil
}

// UnreadyMembers returns a list of member indexes that turned out to be unready
// during the announcement. The list is sorted in ascending order.
func UnreadyMembers(
	readyMembers []group.MemberIndex,
	groupSize int,
) []group.MemberIndex {
	if len(readyMembers) == groupSize {
		return []group.MemberIndex{}
	}

	readyMembersSet := make(map[group.MemberIndex]bool)
	for _, memberIndex := range readyMembers {
		readyMembersSet[memberIndex] = true
	}

	unreadyMembers := make([]group.MemberIndex, 0)

	for i := 0; i < groupSize; i++ {
		memberIndex := group.MemberIndex(i + 1)

		if _, isReady := readyMembersSet[memberIndex]; !isReady {
			unreadyMembers = append(unreadyMembers, memberIndex)
		}
	}

	sort.Slice(unreadyMembers, func(i, j int) bool {
		return unreadyMembers[i] < unreadyMembers[j]
	})

	return unreadyMembers
}
