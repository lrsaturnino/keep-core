package registry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ipfs/go-log"

	"github.com/keep-network/keep-common/pkg/persistence"
)

// QuarantineSchemaVersion versions the quarantined-signer metadata document
// for the offline state-audit tooling.
const QuarantineSchemaVersion uint32 = 1

// QuarantinedSignerMetadata describes one quarantined signer output for the
// offline state audit, without any private material: the key share itself
// stays only inside the encrypted membership record it accompanies.
type QuarantinedSignerMetadata struct {
	SchemaVersion       uint32    `json:"schema_version"`
	ReleaseEpoch        string    `json:"release_epoch"`
	ProtocolMode        string    `json:"protocol_mode"`
	CutoverBlock        uint64    `json:"cutover_block"`
	CanonicalStartBlock uint64    `json:"canonical_start_block"`
	Ceremony            string    `json:"ceremony"`
	SeedHash            string    `json:"seed_hash"`
	MemberIndex         uint8     `json:"member_index"`
	GroupPublicKey      string    `json:"group_public_key"`
	FailedOperation     string    `json:"failed_operation"`
	LastObservedBlock   uint64    `json:"last_observed_block"`
	PreservedAt         time.Time `json:"preserved_at"`
}

// Quarantine preserves signer outputs whose completion the participation gate
// interrupted — clock failure, forced quiescence, or a refused commit fence —
// before an accepted on-chain publication was observed. The handle MUST be
// rooted in a dedicated protected namespace that no release's active-group
// scan reads: quarantined records use the same membership encoding as active
// ones, so placing them beside active membership files would make a prior
// binary load them as active signers, which is not rollback-safe. Quarantined
// material is recovery evidence for the offline state audit; it is never
// activated by the running process.
type Quarantine struct {
	logger log.StandardLogger
	handle persistence.ProtectedHandle

	// lifetime bounds how long a preservation keeps trying to write the output
	// it is holding. It is the process lifetime rather than the ceremony's:
	// the ceremony context is normally already canceled by the very refusal
	// that sent the share here, and until the process itself is going away the
	// generated key material is still this node's to write down. It is held on
	// the store because the choke points that preserve run several call levels
	// below the startup that knows the process context.
	lifetime context.Context

	// graceAttempts, retryDelay, and maxRetryDelay shape the retry, and wait
	// pauses between rounds unless the lifetime ends first. They are fields so
	// a test does not have to spend the real delays.
	graceAttempts int
	retryDelay    time.Duration
	maxRetryDelay time.Duration
	wait          func(context.Context, time.Duration) bool
}

// quarantineGraceAttempts bounds how many rounds a preservation makes before
// the node is told it is holding key material the namespace does not have, and
// quarantineRetryDelay and quarantineMaxRetryDelay bound the wait between
// rounds.
//
// The grace budget is not a deadline. A refused write is often transient — a
// namespace being remounted, a disk an operator is draining — so the first
// rounds pass without disturbing the fleet; what follows is a node that stops
// taking new work while it keeps trying, not a node that gives the share up.
// The material on this path cannot be generated again, so the retry ends only
// with the process, and the backoff grows to keep a namespace that is down for
// an operator's whole repair from being hammered.
const (
	quarantineGraceAttempts = 3
	quarantineRetryDelay    = 100 * time.Millisecond
	quarantineMaxRetryDelay = 30 * time.Second
)

// NewQuarantine creates a quarantine store over the given protected handle,
// preserving outputs for as long as the given process lifetime lasts.
func NewQuarantine(
	lifetime context.Context,
	logger log.StandardLogger,
	handle persistence.ProtectedHandle,
) *Quarantine {
	return &Quarantine{
		logger:        logger,
		handle:        handle,
		lifetime:      lifetime,
		graceAttempts: quarantineGraceAttempts,
		retryDelay:    quarantineRetryDelay,
		maxRetryDelay: quarantineMaxRetryDelay,
		wait:          waitWithinLifetime,
	}
}

// waitWithinLifetime pauses between preservation rounds, reporting whether the
// process is still around to make another one.
func waitWithinLifetime(lifetime context.Context, delay time.Duration) bool {
	if lifetime == nil {
		time.Sleep(delay)
		return true
	}

	// Checked before the wait so a lifetime that has already ended stops the
	// retry rather than racing the timer for it.
	if lifetime.Err() != nil {
		return false
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-lifetime.Done():
		return false
	case <-timer.C:
		return true
	}
}

// QuarantineState reports which halves of a preserved output reached the
// namespace. A caller cannot infer this from the error alone, and the two
// halves mean different things: the membership is the key material a rollback
// has to account for, while the metadata is the audit record explaining it.
// Reporting the wrong one is how an operator log, a published count, and the
// offline audit come to disagree about the same directory.
type QuarantineState struct {
	// MembershipPersisted reports whether the key material reached the
	// namespace.
	MembershipPersisted bool
	// MetadataPersisted reports whether the audit record reached the
	// namespace.
	MetadataPersisted bool
}

// Preserve durably saves the membership and its audit metadata under the
// quarantine namespace. It keeps ownership of the generated output until both
// halves are durable, retrying for as long as the process lives, and returns
// early only when the process is going away with a half still missing.
//
// Both records are attempted in every round and what actually landed is
// returned beside the error, because the two halves mean different things and a
// caller cannot infer either from the error alone. A membership without
// metadata is unexplained key material; metadata without a membership is a
// share that was lost. What must not happen is the node reporting a state the
// namespace contradicts.
//
// The membership is attempted first so that a process killed between the two
// writes leaves the key material behind rather than only the note describing
// it: an unexplained share is recoverable, a lost one is not.
//
// notifyIncomplete is called once, after graceAttempts rounds have left a half
// unwritten, with what the namespace holds so far. It exists so the node can
// stop taking new work while it is still holding an output no namespace fully
// has — not to end the attempt, which continues behind it until the pair is
// durable or the process ends.
func (q *Quarantine) Preserve(
	membership *Membership,
	metadata QuarantinedSignerMetadata,
	notifyIncomplete func(QuarantineState, error),
) (QuarantineState, error) {
	var state QuarantineState

	membershipBytes, err := membership.Marshal()
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantined membership: [%v]",
			err,
		)
	}

	metadata.SchemaVersion = QuarantineSchemaVersion
	metadata.GroupPublicKey = hex.EncodeToString(
		membership.Signer.GroupPublicKeyBytesCompressed(),
	)
	metadata.MemberIndex = uint8(membership.Signer.MemberID())
	metadata.PreservedAt = time.Now().UTC()

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantine metadata: [%v]",
			err,
		)
	}

	directory := metadata.GroupPublicKey
	memberSuffix := fmt.Sprint(membership.Signer.MemberID())

	// One line names the output and what the namespace holds of it, so the
	// operator record and the namespace cannot drift apart. An incomplete pair
	// is a finding the offline audit will raise, so it reads as an error rather
	// than like an ordinary quarantine.
	report := func(rounds int, complete bool) {
		logQuarantine := q.logger.Warnf
		if !complete {
			logQuarantine = q.logger.Errorf
		}
		logQuarantine(
			"quarantined a beacon signer output [group=0x%v] [member=%v] "+
				"[mode=%s] [canonicalStartBlock=%d] [failedOperation=%s] "+
				"[lastObservedBlock=%d] [keyMaterialPreserved=%v] "+
				"[auditMetadataPreserved=%v] [rounds=%d]",
			metadata.GroupPublicKey,
			membership.Signer.MemberID(),
			metadata.ProtocolMode,
			metadata.CanonicalStartBlock,
			metadata.FailedOperation,
			metadata.LastObservedBlock,
			state.MembershipPersisted,
			state.MetadataPersisted,
			rounds,
		)
	}

	rounds, lastErr := q.persistPair(
		&state,
		directory,
		memberSuffix,
		membershipBytes,
		metadataBytes,
		notifyIncomplete,
	)
	if lastErr == nil {
		report(rounds, true)
		return state, nil
	}

	report(rounds, false)

	return state, fmt.Errorf(
		"could not preserve the quarantined beacon signer output in %d rounds "+
			"before the process ended [keyMaterialPreserved=%v] "+
			"[auditMetadataPreserved=%v]: %w",
		rounds,
		state.MembershipPersisted,
		state.MetadataPersisted,
		lastErr,
	)
}

// persistPair writes whichever halves of a preserved output the namespace has
// not taken yet, round after round, until it holds both or the process ends.
// It reports how many rounds were spent and the last round's failure, which is
// nil exactly when both halves are durable.
//
// The state is updated in place as each half lands so that a caller reading it
// after an interrupted preservation sees what the namespace actually has, and
// so a half that succeeded is never rewritten by a later round.
func (q *Quarantine) persistPair(
	state *QuarantineState,
	directory string,
	memberSuffix string,
	membershipBytes []byte,
	metadataBytes []byte,
	notifyIncomplete func(QuarantineState, error),
) (int, error) {
	graceAttempts := q.graceAttempts
	if graceAttempts < 1 {
		graceAttempts = 1
	}
	wait := q.wait
	if wait == nil {
		wait = waitWithinLifetime
	}
	delay := q.retryDelay

	notified := false
	var lastErr error

	for round := 1; ; round++ {
		var roundErrs []error

		if !state.MembershipPersisted {
			if err := q.handle.Save(
				membershipBytes,
				directory,
				"/membership_"+memberSuffix,
			); err != nil {
				roundErrs = append(roundErrs, fmt.Errorf(
					"could not persist the quarantined membership: [%v]",
					err,
				))
			} else {
				state.MembershipPersisted = true
			}
		}

		if !state.MetadataPersisted {
			if err := q.handle.Save(
				metadataBytes,
				directory,
				"/metadata_"+memberSuffix,
			); err != nil {
				roundErrs = append(roundErrs, fmt.Errorf(
					"could not persist the quarantine metadata: [%v]",
					err,
				))
			} else {
				state.MetadataPersisted = true
			}
		}

		if len(roundErrs) == 0 {
			return round, nil
		}

		lastErr = errors.Join(roundErrs...)

		// The node is told once the grace rounds are spent, so a namespace that
		// clears on its own does not take the node out of the fleet, and one
		// that does not stops it from building further state it cannot account
		// for. Preservation does not end here: the share is still in hand and
		// the retry keeps running behind the notification.
		if !notified && round >= graceAttempts {
			notified = true
			if notifyIncomplete != nil {
				notifyIncomplete(*state, lastErr)
			}
		}

		if !wait(q.lifetime, delay) {
			return round, lastErr
		}

		if delay *= 2; delay > q.maxRetryDelay {
			delay = q.maxRetryDelay
		}
	}
}
