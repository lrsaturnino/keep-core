package tbtc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-log/v2"

	"github.com/keep-network/keep-common/pkg/persistence"
	"github.com/keep-network/keep-core/pkg/bitcoin"
	"github.com/keep-network/keep-core/pkg/protocol/group"
)

// QuarantineSchemaVersion versions the quarantined-signer metadata document
// for the offline state-audit tooling.
const QuarantineSchemaVersion uint32 = 1

// QuarantinedSignerMetadata describes one quarantined tBTC signer output for
// the offline state audit, without any private material: the key share itself
// stays only inside the encrypted membership record it accompanies. The seed
// is recorded as a hash, never raw.
type QuarantinedSignerMetadata struct {
	SchemaVersion       uint32    `json:"schema_version"`
	ReleaseEpoch        string    `json:"release_epoch"`
	ProtocolMode        string    `json:"protocol_mode"`
	CutoverBlock        uint64    `json:"cutover_block"`
	CanonicalStartBlock uint64    `json:"canonical_start_block"`
	Ceremony            string    `json:"ceremony"`
	SeedHash            string    `json:"seed_hash"`
	MemberIndex         uint8     `json:"member_index"`
	WalletID            string    `json:"wallet_id"`
	WalletPublicKeyHash string    `json:"wallet_public_key_hash"`
	FailedOperation     string    `json:"failed_operation"`
	LastObservedBlock   uint64    `json:"last_observed_block"`
	PreservedAt         time.Time `json:"preserved_at"`
}

// signerQuarantine preserves tBTC signer outputs whose activation the
// participation gate refused — clock failure, forced quiescence, or a refused
// commit fence — before the wallet's on-chain registration was proven. The
// handle MUST be rooted in a dedicated protected namespace that no release's
// active-wallet scan reads: quarantined records use the same membership
// encoding as active ones, so placing them beside active membership files
// would make a prior binary load them as active signers, which is not
// rollback-safe. Quarantined material is recovery evidence for the offline
// state audit; it is never activated by the running process.
type signerQuarantine struct {
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

// newSignerQuarantine creates a quarantine store over the given protected
// handle, preserving outputs for as long as the given process lifetime lasts.
func newSignerQuarantine(
	lifetime context.Context,
	logger log.StandardLogger,
	handle persistence.ProtectedHandle,
) *signerQuarantine {
	return &signerQuarantine{
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

// quarantineState reports which halves of a preserved output reached the
// namespace. A caller cannot infer this from the error alone, and the two
// halves mean different things: the membership is the key material a rollback
// has to account for, while the metadata is the audit record explaining it.
// Reporting the wrong one is how an operator log, a published count, and the
// offline audit come to disagree about the same directory.
type quarantineState struct {
	membershipPersisted bool
	metadataPersisted   bool
}

// quarantineObserver receives what a preservation learns while it is still
// holding the output, for the things a caller must not wait for the return
// value to know. Both callbacks run on the preserving goroutine.
type quarantineObserver struct {
	// keyMaterialPreserved is called the moment the namespace takes the key
	// material, whether or not the audit record beside it has landed.
	//
	// The count of preserved shares follows the material alone, and the
	// preservation still waiting on the other half can run for the rest of the
	// process. A caller that learned this from the return value would leave a
	// share the namespace already holds unreported for exactly as long as the
	// metadata keeps being refused — the stale all-clear the count exists to
	// prevent.
	//
	// It runs between the two writes of the round the material landed in, so
	// it must do only what belongs on that path. Anything slow here — a
	// namespace-wide read above all — delays the audit record that turns the
	// preserved share into an explained one, and delays it for as long as
	// whatever it waited on takes. Reconciliation that can wait belongs after
	// preserve returns.
	keyMaterialPreserved func()

	// stillIncomplete is called once, after graceAttempts rounds have left a
	// half unwritten, with what the namespace holds so far. It exists so the
	// node can stop taking new work while it is still holding an output no
	// namespace fully has — not to end the attempt, which continues behind it
	// until the pair is durable or the process ends.
	//
	// It is one-shot on purpose: quiescence is one-way, so saying it twice
	// changes nothing, and key material that lands in a later round is
	// reported by keyMaterialPreserved rather than by a second notification
	// here.
	stillIncomplete func(quarantineState, error)
}

// preserve durably saves the signer membership and its audit metadata under
// the quarantine namespace, mirroring the active storage layout so the same
// decoding path can interpret both. It keeps ownership of the generated output
// until both halves are durable, retrying for as long as the process lives, and
// returns early only when the process is going away with a half still missing.
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
// The observer is told what the namespace takes while the preservation is still
// running, because a caller that only reads the returned state learns nothing
// until an attempt that may outlast the process is over.
func (q *signerQuarantine) preserve(
	signer *signer,
	metadata QuarantinedSignerMetadata,
	observer quarantineObserver,
) (quarantineState, error) {
	var state quarantineState

	signerBytes, err := signer.Marshal()
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantined signer: [%v]",
			err,
		)
	}

	walletPublicKeyHash := bitcoin.PublicKeyHash(signer.wallet.publicKey)

	metadata.SchemaVersion = QuarantineSchemaVersion
	metadata.MemberIndex = uint8(signer.signingGroupMemberIndex)
	metadata.WalletPublicKeyHash = hex.EncodeToString(walletPublicKeyHash[:])
	metadata.PreservedAt = time.Now().UTC()

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantine metadata: [%v]",
			err,
		)
	}

	directory := getWalletStorageKey(signer.wallet.publicKey)
	memberSuffix := fmt.Sprint(signer.signingGroupMemberIndex)

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
			"quarantined a tbtc signer output [walletPKH=0x%s] [member=%v] "+
				"[mode=%s] [canonicalStartBlock=%d] [failedOperation=%s] "+
				"[lastObservedBlock=%d] [keyMaterialPreserved=%v] "+
				"[auditMetadataPreserved=%v] [rounds=%d]",
			metadata.WalletPublicKeyHash,
			signer.signingGroupMemberIndex,
			metadata.ProtocolMode,
			metadata.CanonicalStartBlock,
			metadata.FailedOperation,
			metadata.LastObservedBlock,
			state.membershipPersisted,
			state.metadataPersisted,
			rounds,
		)
	}

	rounds, lastErr := q.persistPair(
		&state,
		directory,
		memberSuffix,
		signerBytes,
		metadataBytes,
		observer,
	)
	if lastErr == nil {
		report(rounds, true)
		return state, nil
	}

	report(rounds, false)

	return state, fmt.Errorf(
		"could not preserve the quarantined tbtc signer output in %d rounds "+
			"before the process ended [keyMaterialPreserved=%v] "+
			"[auditMetadataPreserved=%v]: %w",
		rounds,
		state.membershipPersisted,
		state.metadataPersisted,
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
func (q *signerQuarantine) persistPair(
	state *quarantineState,
	directory string,
	memberSuffix string,
	signerBytes []byte,
	metadataBytes []byte,
	observer quarantineObserver,
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

	// announcedLostMaterial remembers that the operator record says this share
	// reached no namespace. It is what makes a later write worth a line of its
	// own: until one is written, the standing account of this output is an error
	// saying the material is only in memory, over a namespace that now holds it.
	announcedLostMaterial := false

	var lastErr error

	for round := 1; ; round++ {
		var roundErrs []error

		if !state.membershipPersisted {
			if err := q.handle.Save(
				signerBytes,
				directory,
				"/membership_"+memberSuffix,
			); err != nil {
				roundErrs = append(roundErrs, fmt.Errorf(
					"could not persist the quarantined signer: [%v]",
					err,
				))
			} else {
				// Reported from inside the round rather than from the return,
				// because the round the metadata lands in may never come: this
				// is the only moment the material is known to be held that a
				// caller is guaranteed to see.
				state.membershipPersisted = true

				if announcedLostMaterial {
					announcedLostMaterial = false
					// Named by the directory the record lives under rather
					// than by the wallet hash the other quarantine lines
					// carry: an operator reading this is going to the
					// namespace to confirm the material is there.
					q.logger.Warnf(
						"the quarantine namespace took the tbtc key material "+
							"it had been refusing [walletStorageKey=%s] "+
							"[member=%s] [round=%d]; the share this node "+
							"reported as only in memory is on disk",
						directory,
						memberSuffix,
						round,
					)
				}

				if observer.keyMaterialPreserved != nil {
					observer.keyMaterialPreserved()
				}
			}
		}

		if !state.metadataPersisted {
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
				state.metadataPersisted = true
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
			announcedLostMaterial = !state.membershipPersisted
			if observer.stillIncomplete != nil {
				observer.stillIncomplete(*state, lastErr)
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

// quarantinedSigner names one preserved signer output by the wallet it belongs
// to and the seat it was generated for — the pair an active signer is also
// identified by, so the two namespaces can be compared without decoding either
// side's key material.
type quarantinedSigner struct {
	walletStorageKey string
	memberIndex      group.MemberIndex
}

// preservedOutputs lists the signer outputs currently held in the quarantine
// namespace.
//
// Only the membership records are counted. Each preserved output writes a
// membership beside its audit metadata, and counting both would report every
// output twice; the membership is the output itself, so it is the one that
// decides. Nothing here reads a record's content: the pair identifying an
// output is carried by the wallet directory and the membership name, and the
// share inside stays encrypted and unread.
//
// A namespace that cannot be enumerated returns an error rather than a short
// list. The count exists to say how much preserved material a rollback still
// has to account for, and a truncated one reads as an all-clear — the single
// answer this must never invent.
func (q *signerQuarantine) preservedOutputs() ([]quarantinedSigner, error) {
	descriptorsChan, errorsChan := q.handle.ReadAll()

	// The descriptor and error channels are unbuffered and written to in an
	// order this side cannot predict, so both are drained concurrently. This
	// mirrors the active wallet storage scan.
	var wg sync.WaitGroup
	wg.Add(2)

	var outputs []quarantinedSigner
	go func() {
		defer wg.Done()
		for descriptor := range descriptorsChan {
			memberIndex, ok := quarantinedMemberIndex(descriptor.Name())
			if !ok {
				continue
			}
			outputs = append(outputs, quarantinedSigner{
				walletStorageKey: descriptor.Directory(),
				memberIndex:      memberIndex,
			})
		}
	}()

	var readErrs []error
	go func() {
		defer wg.Done()
		for err := range errorsChan {
			readErrs = append(readErrs, err)
		}
	}()

	wg.Wait()

	if len(readErrs) > 0 {
		return nil, fmt.Errorf(
			"could not enumerate the signer quarantine namespace: %w",
			errors.Join(readErrs...),
		)
	}

	return outputs, nil
}

// quarantinedMemberIndex reads the seat a preserved membership record was
// written for out of its name, reporting whether the name is one at all.
//
// The name is this package's own: preserve writes "membership_<seat>" beside
// "metadata_<seat>". Anything else in the namespace — the metadata documents, a
// name a later schema adds, an operator's stray file — is not a signer output
// and is not counted as one.
//
// A leading separator is tolerated because the name is written with one and not
// every handle hands it back the same way: the disk implementation joins it into
// a path and enumerates the bare file name, while a handle that keeps what it
// was given returns the name as this package wrote it. Both spell the same
// record, so neither is allowed to decide whether it counts.
func quarantinedMemberIndex(name string) (group.MemberIndex, bool) {
	const prefix = "membership_"

	suffix, found := strings.CutPrefix(strings.TrimPrefix(name, "/"), prefix)
	if !found {
		return 0, false
	}

	seat, err := strconv.ParseUint(suffix, 10, 8)
	if err != nil || seat == 0 {
		return 0, false
	}

	return group.MemberIndex(seat), true
}
