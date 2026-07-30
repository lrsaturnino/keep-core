package tbtc

import (
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

	// saveAttempts and saveRetryDelay bound the retry budget spent on each half
	// of a preserved output, and sleep waits between attempts. They are fields
	// so a test does not have to spend the real delay.
	saveAttempts   int
	saveRetryDelay time.Duration
	sleep          func(time.Duration)
}

// quarantineSaveAttempts bounds how many times each half of a preserved output
// is written before its failure stands, and quarantineSaveRetryDelay is the wait
// between attempts.
//
// A refused write is often transient — a namespace being remounted, a disk an
// operator is draining — and the key material this path is holding cannot be
// regenerated, so a single attempt is not enough to conclude it is unwritable.
// The budget stays small because the process is normally already quiescing
// behind this write and its shutdown drain waits for it to finish.
const (
	quarantineSaveAttempts   = 3
	quarantineSaveRetryDelay = 100 * time.Millisecond
)

// newSignerQuarantine creates a quarantine store over the given protected
// handle.
func newSignerQuarantine(
	logger log.StandardLogger,
	handle persistence.ProtectedHandle,
) *signerQuarantine {
	return &signerQuarantine{
		logger:         logger,
		handle:         handle,
		saveAttempts:   quarantineSaveAttempts,
		saveRetryDelay: quarantineSaveRetryDelay,
		sleep:          time.Sleep,
	}
}

// save writes one half of a preserved output, retrying a refused write within
// the attempt budget and returning the last error if the budget runs out.
func (q *signerQuarantine) save(
	content []byte,
	directory string,
	name string,
) error {
	// A store assembled without a budget still gets one attempt, and one
	// without a wait still waits: a zero budget would report a write that never
	// happened as a success, which is the single outcome this path exists to
	// prevent.
	attempts := q.saveAttempts
	if attempts < 1 {
		attempts = 1
	}
	sleep := q.sleep
	if sleep == nil {
		sleep = time.Sleep
	}

	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			sleep(q.saveRetryDelay)
		}
		if err = q.handle.Save(content, directory, name); err == nil {
			return nil
		}
	}

	return err
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

// preserve durably saves the signer membership and its audit metadata under
// the quarantine namespace, mirroring the active storage layout so the same
// decoding path can interpret both. Preservation failure is surfaced to the
// caller: losing generated key material is a protocol violation, so the
// caller must log it unsuppressed.
//
// Both records are attempted even when the first fails, and what actually
// landed is returned beside the error. A half that could have been written is
// evidence the offline audit would otherwise not have, and the audit already
// reads either orphan as a finding — a membership without metadata is
// unexplained key material, metadata without a membership is a share that was
// lost. What must not happen is the node reporting a state the namespace
// contradicts, so the caller is told which of the two it is.
//
// The membership is attempted first so that a process killed between the two
// writes leaves the key material behind rather than only the note describing
// it: an unexplained share is recoverable, a lost one is not. Each half is
// retried within a bounded budget before its failure stands, because a namespace
// that refuses one write often accepts the next and the material being written
// cannot be generated again.
func (q *signerQuarantine) preserve(
	signer *signer,
	metadata QuarantinedSignerMetadata,
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

	var writeErrs []error

	if err := q.save(
		signerBytes,
		directory,
		"/membership_"+memberSuffix,
	); err != nil {
		writeErrs = append(writeErrs, fmt.Errorf(
			"could not persist the quarantined signer in %d attempts: [%v]",
			q.saveAttempts,
			err,
		))
	} else {
		state.membershipPersisted = true
	}

	if err := q.save(
		metadataBytes,
		directory,
		"/metadata_"+memberSuffix,
	); err != nil {
		writeErrs = append(writeErrs, fmt.Errorf(
			"could not persist the quarantine metadata in %d attempts: [%v]",
			q.saveAttempts,
			err,
		))
	} else {
		state.metadataPersisted = true
	}

	// One line names the output and what the namespace now holds of it, so the
	// operator record and the namespace cannot drift apart. An incomplete pair
	// is a finding the offline audit will raise, so it is logged as an error
	// here rather than left to read like an ordinary quarantine.
	logQuarantine := q.logger.Warnf
	if len(writeErrs) > 0 {
		logQuarantine = q.logger.Errorf
	}
	logQuarantine(
		"quarantined a tbtc signer output [walletPKH=0x%s] [member=%v] "+
			"[mode=%s] [canonicalStartBlock=%d] [failedOperation=%s] "+
			"[lastObservedBlock=%d] [keyMaterialPreserved=%v] "+
			"[auditMetadataPreserved=%v]",
		metadata.WalletPublicKeyHash,
		signer.signingGroupMemberIndex,
		metadata.ProtocolMode,
		metadata.CanonicalStartBlock,
		metadata.FailedOperation,
		metadata.LastObservedBlock,
		state.membershipPersisted,
		state.metadataPersisted,
	)

	if len(writeErrs) > 0 {
		return state, errors.Join(writeErrs...)
	}

	return state, nil
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
