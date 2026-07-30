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

// QuarantineHandoffSchemaVersion versions the combined handoff document for the
// offline state-audit tooling.
const QuarantineHandoffSchemaVersion uint32 = 1

// QuarantinedSignerHandoff carries one quarantined signer output whole: the key
// material and the audit record that explains it, in a single document written
// with a single save.
//
// The membership and metadata records preservation prefers are two independent
// writes, and a namespace that takes one but refuses the other leaves the output
// split. One of those halves cannot be split off harmlessly: a refused
// membership write leaves an audit record describing a share that reached no
// disk, and the share is the half no ceremony can generate again. This document
// is the form that cannot reach a reader in halves — every field an audit needs
// travels with the material it explains, and a document a crash left half
// written fails the encrypted handle's authentication rather than decoding as
// the part that got through — and it is written under a name of its own, so a
// name the namespace refuses does not decide whether the output survives.
type QuarantinedSignerHandoff struct {
	SchemaVersion uint32                    `json:"schema_version"`
	Metadata      QuarantinedSignerMetadata `json:"metadata"`
	// Signer is the marshaled signer, byte for byte what the membership record
	// holds, so a reader decodes either form the same way.
	Signer []byte `json:"signer"`
}

// DecodeQuarantinedSignerHandoff reads a combined handoff record back into the
// halves it carries, for a later process and for the offline state audit.
//
// A document naming a schema this binary does not know is refused rather than
// read past. The handoff is the only account of an output preserved this way,
// so a reader that guessed at unknown fields would be inventing the evidence a
// rollback decision is made on.
func DecodeQuarantinedSignerHandoff(
	recordBytes []byte,
) (*QuarantinedSignerHandoff, error) {
	handoff := &QuarantinedSignerHandoff{}
	if err := json.Unmarshal(recordBytes, handoff); err != nil {
		return nil, fmt.Errorf(
			"could not decode the quarantine handoff: [%v]",
			err,
		)
	}

	if handoff.SchemaVersion != QuarantineHandoffSchemaVersion {
		return nil, fmt.Errorf(
			"quarantine handoff has schema version [%d], expected [%d]",
			handoff.SchemaVersion,
			QuarantineHandoffSchemaVersion,
		)
	}

	if len(handoff.Signer) == 0 {
		return nil, fmt.Errorf(
			"quarantine handoff carries no key material",
		)
	}

	return handoff, nil
}

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
	// handoffPersisted reports whether the namespace holds the combined record
	// carrying both halves at once. It is written only when the pair could not
	// be completed, and once it lands the output is whole whatever the pair is
	// still missing.
	handoffPersisted bool
}

// keyMaterialPersisted reports whether the namespace holds the generated share
// in either of the forms preservation writes it in. This is what the count of
// preserved material follows: a share on disk is material a rollback has to
// account for however it got written down.
func (s quarantineState) keyMaterialPersisted() bool {
	return s.membershipPersisted || s.handoffPersisted
}

// complete reports whether the namespace holds the whole output — the key
// material and the audit record explaining it. The pair says so when both its
// halves landed, and the combined record says so on its own, since it carries
// both.
func (s quarantineState) complete() bool {
	return (s.membershipPersisted && s.metadataPersisted) || s.handoffPersisted
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
// A round that cannot complete the pair falls back on the combined handoff
// record, which carries both halves in one write under a name of its own. It is
// what keeps a namespace refusing one particular record from costing the node a
// share it can never generate again, and once it lands the output is whole
// however little of the pair the namespace took.
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

	handoffBytes, err := json.Marshal(QuarantinedSignerHandoff{
		SchemaVersion: QuarantineHandoffSchemaVersion,
		Metadata:      metadata,
		Signer:        signerBytes,
	})
	if err != nil {
		return state, fmt.Errorf(
			"could not marshal the quarantine handoff: [%v]",
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
				"[auditMetadataPreserved=%v] [preservedAsOneRecord=%v] "+
				"[rounds=%d]",
			metadata.WalletPublicKeyHash,
			signer.signingGroupMemberIndex,
			metadata.ProtocolMode,
			metadata.CanonicalStartBlock,
			metadata.FailedOperation,
			metadata.LastObservedBlock,
			state.keyMaterialPersisted(),
			state.metadataPersisted || state.handoffPersisted,
			state.handoffPersisted,
			rounds,
		)
	}

	rounds, lastErr := q.persistOutput(
		&state,
		directory,
		memberSuffix,
		signerBytes,
		metadataBytes,
		handoffBytes,
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
		state.keyMaterialPersisted(),
		state.metadataPersisted || state.handoffPersisted,
		lastErr,
	)
}

// persistOutput writes whichever records of a preserved output the namespace
// has not taken yet, round after round, until it holds the whole output or the
// process ends. It reports how many rounds were spent and the last round's
// failure, which is nil exactly when the output is durable.
//
// The preferred form is the pair — a membership record beside its metadata —
// because it is the layout the active namespace uses and the one every reader
// already understands. A round that cannot complete the pair falls back on the
// combined handoff record, which carries both halves under a name of its own, so
// no namespace that refuses one particular record can leave key material with
// nowhere to go. A landed handoff ends the attempt, since there is nothing left
// the namespace does not hold.
//
// A record counts as landed on the namespace's word that it took the write, not
// on a reader's. The disk persistence behind this handle creates the file,
// writes the document, and syncs it, with no temporary record renamed into
// place, so a write a crash interrupts leaves a truncated document behind — and
// confirming each write by enumerating the namespace would put a share this node
// is still holding behind a directory listing that may never return, which is
// the more expensive way to lose it. What a torn write leaves is caught on the
// way out instead: the document fails the encrypted handle's authentication, so
// the offline audit reads it as an unreadable record and blocks on it rather
// than any reader taking it for a preserved output.
//
// The state is updated in place as each record lands so that a caller reading it
// after an interrupted preservation sees what the namespace actually has, and
// so a record that succeeded is never rewritten by a later round.
func (q *signerQuarantine) persistOutput(
	state *quarantineState,
	directory string,
	memberSuffix string,
	signerBytes []byte,
	metadataBytes []byte,
	handoffBytes []byte,
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

	// materialAccountedFor keeps the observer's count of preserved shares to one
	// notification per output. The material can reach the namespace as the
	// membership record or inside the handoff, and it is the same share either
	// way.
	materialAccountedFor := false
	accountForMaterial := func(round int) {
		if announcedLostMaterial {
			announcedLostMaterial = false
			// Named by the directory the record lives under rather than by the
			// wallet hash the other quarantine lines carry: an operator reading
			// this is going to the namespace to confirm the material is there.
			q.logger.Warnf(
				"the quarantine namespace took the tbtc key material it had "+
					"been refusing [walletStorageKey=%s] [member=%s] "+
					"[round=%d]; the share this node reported as only in "+
					"memory is on disk",
				directory,
				memberSuffix,
				round,
			)
		}

		if materialAccountedFor {
			return
		}
		materialAccountedFor = true

		if observer.keyMaterialPreserved != nil {
			observer.keyMaterialPreserved()
		}
	}

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

				accountForMaterial(round)
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

		// The pair is what this round could not finish, so the output is
		// offered whole under a name of its own. A namespace refusing one
		// particular record — a leftover file nothing can overwrite, a name an
		// operator's repair left behind — still has somewhere to put a share
		// that cannot be generated a second time.
		//
		// When the half that did land was the membership, the namespace ends up
		// holding the material twice. That is the cheaper mistake: both copies
		// are the same encrypted bytes under the same handle, readers count the
		// seat once, and the alternative is choosing which refusals are worth
		// leaving an output incomplete for.
		if len(roundErrs) > 0 && !state.handoffPersisted {
			if err := q.handle.Save(
				handoffBytes,
				directory,
				"/handoff_"+memberSuffix,
			); err != nil {
				roundErrs = append(roundErrs, fmt.Errorf(
					"could not persist the quarantine handoff: [%v]",
					err,
				))
			} else {
				state.handoffPersisted = true

				q.logger.Warnf(
					"preserved a tbtc signer output as a single handoff record "+
						"[walletStorageKey=%s] [member=%s] [round=%d]; the "+
						"namespace would not take the record pair, and the key "+
						"material and its audit record are held together "+
						"instead",
					directory,
					memberSuffix,
					round,
				)

				accountForMaterial(round)
			}
		}

		if state.complete() {
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
			announcedLostMaterial = !state.keyMaterialPersisted()
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
// Only the records carrying key material are counted. A preserved output is
// written either as a membership beside its audit metadata or as a single
// handoff carrying both, and in each form exactly one record holds the share;
// counting the metadata beside it would report the same output twice. Nothing
// here reads a record's content: the pair identifying an output is carried by
// the wallet directory and the record name, and the share inside stays
// encrypted and unread.
//
// The same seat can be named by both forms — a preservation that wrote the
// membership, was refused the metadata, and fell back on the handoff leaves
// both on disk — so outputs are collected as identities rather than counted per
// record. One seat of one wallet is one share whatever it took to write it
// down.
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

	found := make(map[quarantinedSigner]struct{})
	go func() {
		defer wg.Done()
		for descriptor := range descriptorsChan {
			memberIndex, ok := quarantinedMemberIndex(descriptor.Name())
			if !ok {
				continue
			}
			found[quarantinedSigner{
				walletStorageKey: descriptor.Directory(),
				memberIndex:      memberIndex,
			}] = struct{}{}
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

	outputs := make([]quarantinedSigner, 0, len(found))
	for output := range found {
		outputs = append(outputs, output)
	}

	return outputs, nil
}

// quarantinedMemberIndex reads the seat a preserved record was written for out
// of its name, reporting whether the name belongs to a record holding key
// material at all.
//
// The names are this package's own: preserve writes "membership_<seat>" beside
// "metadata_<seat>", and falls back on "handoff_<seat>" carrying both. The two
// that hold the share count; anything else in the namespace — the metadata
// documents, a name a later schema adds, an operator's stray file — is not a
// signer output and is not counted as one.
//
// A leading separator is tolerated because the name is written with one and not
// every handle hands it back the same way: the disk implementation joins it into
// a path and enumerates the bare file name, while a handle that keeps what it
// was given returns the name as this package wrote it. Both spell the same
// record, so neither is allowed to decide whether it counts.
func quarantinedMemberIndex(name string) (group.MemberIndex, bool) {
	bare := strings.TrimPrefix(name, "/")

	var suffix string
	for _, prefix := range []string{"membership_", "handoff_"} {
		if cut, found := strings.CutPrefix(bare, prefix); found {
			suffix = cut
			break
		}
	}
	if suffix == "" {
		return 0, false
	}

	seat, err := strconv.ParseUint(suffix, 10, 8)
	if err != nil || seat == 0 {
		return 0, false
	}

	return group.MemberIndex(seat), true
}
