package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	commonEthereum "github.com/keep-network/keep-common/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/pkg/beacon"
	"github.com/keep-network/keep-core/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tbtc"
)

// releaseManifestSchemaVersion is the only release manifest schema this
// binary understands. A manifest carrying any other version is rejected
// instead of being partially interpreted. Version 2 added the release identity
// section: a manifest that only binds the termination grace can no longer be
// read as a complete reviewed record.
const releaseManifestSchemaVersion = uint64(2)

// compiledForcedCancellationAllowanceSeconds is the reviewed wall-clock
// allowance between the in-process quiesce backstop firing and the service
// manager escalating to SIGKILL. It covers the audited forced-cancellation
// path that runs after the backstop: canceling the permits that outlived the
// drain, persisting their audit records, closing the gate, and letting the
// process exit. It deliberately mirrors the RPC/processing margin used inside
// the backstop itself; both absorb the same order of local skew. The runtime
// cleanup wait consumes exactly this constant (forcedCancellationAllowance in
// start.go), and manifest validation rejects a manifest recording any other
// allowance, so no reviewed document can promise the service manager a
// cleanup window the running process does not observe.
const compiledForcedCancellationAllowanceSeconds = uint64(300)

// processExitHeadroomSeconds is the reviewed headroom the external
// termination grace adds on top of the two in-process waits. The service
// manager counts its grace from signal delivery, but the backstop timer arms
// only after the lifecycle controller has been scheduled and has quiesced
// the gate, the cancellation-allowance timer arms only after the gate has
// closed, and the shutdown logging, run-context teardown, and process exit
// run after both. This headroom budgets that overhead — purely local work
// with no chain or network waits, sized far above what such work needs even
// under heavy load — so the external SIGKILL deadline ends strictly after
// the complete internal shutdown sequence instead of exactly at the sum of
// the two timed waits.
const processExitHeadroomSeconds = uint64(60)

// sourceCommitPattern is the shape of a full git commit hash. An abbreviated
// hash is rejected because it names a prefix rather than a commit: prefixes
// collide, and the whole point of recording the source here is that a reviewer
// can fetch exactly what was built.
var sourceCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// imageDigestPattern is the shape of an OCI content digest. The algorithm is
// pinned to sha256 rather than accepted from the document: the digest is what
// makes the reference immutable, so the manifest does not get to name the
// function it is immutable under.
var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// releaseImage names one runtime image the release publishes.
//
// The reference is what a deployment scaffold actually pulls, and it has to
// carry the digest. A tag is a name a registry can repoint at any time, so a
// manifest recording a digest beside a tagged reference documents one artifact
// while deployment runs whatever the tag resolves to at pull time — and the
// acceptance evidence, which is stated against the digest, would describe an
// image no node is necessarily running.
type releaseImage struct {
	Platform  string `json:"platform"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// releaseIdentity names the chain and block the reviewed cutover happens at.
//
// The termination grace binds this document to the compiled bounds of the
// binary validating it. That establishes the numbers are right for some build
// of this source; it does not establish which chain and block the cutover it
// describes is for. Every statement made about this release afterwards —
// smoke-gate evidence, the fleet inventory's per-instance digest attestation, a
// rollback decision taken against a block height — is stated against those
// identities, so the reviewed record carries them and validation holds them
// against what the binary compiles in.
//
// What the release was built into is deliberately absent. The commit finally
// built and the immutable image digests are outputs of a build over this
// document's own bytes, so a manifest recording them would have to contain a
// hash of the tree containing it: writing the value changes the commit the
// value names. Those two live in the detached release provenance instead — a
// document produced after the source commit and the images exist, bound back to
// this one by its hash. See releaseProvenance.
type releaseIdentity struct {
	ChainID      uint64 `json:"chain_id"`
	CutoverBlock uint64 `json:"cutover_block"`
	Notes        string `json:"notes,omitempty"`
}

// relocatedIdentityFields are the release-identity keys that used to live in
// the manifest and now live in the detached provenance. Strict decoding already
// rejects a manifest carrying them, but it rejects them as misspellings; naming
// them here is what turns that into the one instruction a reviewer holding a
// pre-relocation manifest needs.
var relocatedIdentityFields = []string{"source_commit", "images"}

// releaseProvenance is the detached record of what the reviewed release was
// actually built into: the commit it was built from, and the immutable image
// digests the fleet runs.
//
// It exists separately from the manifest because those values cannot be inside
// the tree they describe. A reviewed manifest is part of the commit it would
// have to name, so filling the field changes the answer — which is why the
// manifest carries only what is reviewable ahead of the build, and this
// document, generated afterwards and never committed to the tree it describes,
// carries the rest.
//
// ManifestSHA256 is what keeps the two one record. Provenance naming a source
// commit and a set of images says nothing on its own about which reviewed
// bounds those artifacts were built under; hashing the manifest bytes into it
// means acceptance can refuse provenance produced against some other reviewed
// document, and refuse a manifest edited after provenance was taken over it.
type releaseProvenance struct {
	SchemaVersion  uint64         `json:"schema_version"`
	GeneratedAt    string         `json:"generated_at"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	SourceCommit   string         `json:"source_commit"`
	Images         []releaseImage `json:"images"`
	Notes          string         `json:"notes,omitempty"`
}

// releaseProvenanceSchemaVersion is the only provenance schema this binary
// understands.
const releaseProvenanceSchemaVersion = uint64(1)

// manifestDigestPattern is the shape of the manifest hash provenance binds
// itself to: the lowercase hexadecimal sha256 the release scripts compute over
// the manifest bytes, bare rather than algorithm-prefixed because it names a
// file rather than a registry object.
var manifestDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// beaconCompletionInputs records the beacon chain configuration from which
// the beacon completion bound was derived, so a manifest reviewer can retrace
// the arithmetic without reading the adapter source.
type beaconCompletionInputs struct {
	GroupSize                  uint64 `json:"group_size"`
	ResultPublicationBlockStep uint64 `json:"result_publication_block_step"`
	RelayEntryTimeoutBlocks    uint64 `json:"relay_entry_timeout_blocks"`
}

// terminationGrace is the manifest section binding the service manager's
// external termination grace to the in-process quiesce deadline. Every field
// is derived from this binary's compiled protocol bounds — the allowance is
// the compiled constant the runtime cleanup wait consumes, recorded here so
// the reviewed document names it — and the grace period is the checked sum
// of the backstop, the allowance, and the compiled process-exit headroom.
type terminationGrace struct {
	TBTCCompletionBlocks               uint64                 `json:"tbtc_completion_blocks"`
	BeaconCompletionBlocks             uint64                 `json:"beacon_completion_blocks"`
	BeaconInputs                       beaconCompletionInputs `json:"beacon_inputs"`
	MaximumLegacyCompletionBlocks      uint64                 `json:"maximum_legacy_completion_blocks"`
	ReviewedMarginBlocks               uint64                 `json:"reviewed_margin_blocks"`
	UpperBlockIntervalSeconds          uint64                 `json:"upper_block_interval_seconds"`
	RPCProcessingAllowanceSeconds      uint64                 `json:"rpc_processing_allowance_seconds"`
	InProcessBackstopSeconds           uint64                 `json:"in_process_backstop_seconds"`
	ForcedCancellationAllowanceSeconds uint64                 `json:"forced_cancellation_allowance_seconds"`
	ProcessExitHeadroomSeconds         uint64                 `json:"process_exit_headroom_seconds"`
	TerminationGracePeriodSeconds      uint64                 `json:"termination_grace_period_seconds"`
	Notes                              string                 `json:"notes,omitempty"`
}

// releaseManifest is the reviewed record from which deployment scaffolds take
// the authoritative service-manager termination grace. The client never reads
// it at runtime: its protocol bounds are compiled in, and this manifest exists
// so the external SIGKILL deadline is derived from those same bounds instead
// of being configured by hand.
type releaseManifest struct {
	SchemaVersion    uint64           `json:"schema_version"`
	GeneratedAt      string           `json:"generated_at"`
	ProtocolEpoch    string           `json:"protocol_epoch"`
	ReleaseIdentity  releaseIdentity  `json:"release_identity"`
	TerminationGrace terminationGrace `json:"termination_grace"`
}

// deriveReleaseIdentity returns the release identity this binary states on its
// own: the mainnet chain the compiled cutover constant is for, and the cutover
// block compiled into it.
//
// Both are compiled values, which is the whole of what the manifest records.
// The source commit and the published image digests are outputs of the build
// rather than values inside it — a binary cannot honestly name the tree it was
// produced from or the registry content addresses it was packaged into — so
// they are recorded by the detached provenance and checked there.
func deriveReleaseIdentity() releaseIdentity {
	return releaseIdentity{
		ChainID:      uint64(commonEthereum.Mainnet.ChainID()),
		CutoverBlock: participation.MainnetCutoverBlock,
	}
}

// deriveTerminationGrace computes the termination grace section from this
// binary's compiled protocol bounds: the tBTC and beacon completion bounds,
// the reviewed quiesce margin, the upper block interval, the RPC/processing
// allowance, and the in-process backstop produced by the same checked
// arithmetic the node uses at startup. Every production caller passes the
// compiled forced-cancellation allowance — the very value the runtime
// cleanup wait consumes — and validation separately requires a manifest to
// record exactly that value. A zero allowance is rejected because the
// external grace must end strictly after the in-process backstop for the
// audited forced-cancellation path to run before SIGKILL.
func deriveTerminationGrace(
	forcedCancellationAllowanceSeconds uint64,
) (terminationGrace, error) {
	if forcedCancellationAllowanceSeconds == 0 {
		return terminationGrace{}, fmt.Errorf(
			"forced-cancellation allowance must be positive: the external " +
				"termination grace must end strictly after the in-process " +
				"backstop",
		)
	}

	beaconConfig := (&ethereum.BeaconChain{}).GetConfig()
	beaconBound, err := beacon.MaximumLegacyCompletionBlocks(beaconConfig)
	if err != nil {
		return terminationGrace{}, fmt.Errorf(
			"cannot derive the beacon completion bound: [%v]",
			err,
		)
	}

	tbtcBound := tbtc.MaximumLegacyCompletionBlocks()
	maximumBound := tbtcBound
	if beaconBound > maximumBound {
		maximumBound = beaconBound
	}

	// The backstop is produced by the exact function the node runs at
	// startup, so the manifest can never encode a deadline the client would
	// not actually arm.
	backstop, err := quiesceBackstopDeadline(maximumBound)
	if err != nil {
		return terminationGrace{}, fmt.Errorf(
			"cannot derive the in-process backstop: [%v]",
			err,
		)
	}
	backstopSeconds := uint64(backstop / time.Second)

	if forcedCancellationAllowanceSeconds >
		math.MaxUint64-processExitHeadroomSeconds {
		return terminationGrace{}, fmt.Errorf(
			"termination grace overflows: allowance [%d]s plus exit "+
				"headroom [%d]s",
			forcedCancellationAllowanceSeconds,
			processExitHeadroomSeconds,
		)
	}
	graceBeyondBackstop := forcedCancellationAllowanceSeconds +
		processExitHeadroomSeconds
	if backstopSeconds > math.MaxUint64-graceBeyondBackstop {
		return terminationGrace{}, fmt.Errorf(
			"termination grace overflows: backstop [%d]s plus allowance "+
				"[%d]s plus exit headroom [%d]s",
			backstopSeconds,
			forcedCancellationAllowanceSeconds,
			processExitHeadroomSeconds,
		)
	}

	return terminationGrace{
		TBTCCompletionBlocks:   tbtcBound,
		BeaconCompletionBlocks: beaconBound,
		BeaconInputs: beaconCompletionInputs{
			GroupSize:                  uint64(beaconConfig.GroupSize),
			ResultPublicationBlockStep: beaconConfig.ResultPublicationBlockStep,
			RelayEntryTimeoutBlocks:    beaconConfig.RelayEntryTimeout,
		},
		MaximumLegacyCompletionBlocks:      maximumBound,
		ReviewedMarginBlocks:               quiesceReviewedMarginBlocks,
		UpperBlockIntervalSeconds:          uint64(quiesceUpperBlockIntervalSeconds),
		RPCProcessingAllowanceSeconds:      uint64(quiesceBackstopMargin / time.Second),
		InProcessBackstopSeconds:           backstopSeconds,
		ForcedCancellationAllowanceSeconds: forcedCancellationAllowanceSeconds,
		ProcessExitHeadroomSeconds:         processExitHeadroomSeconds,
		TerminationGracePeriodSeconds:      backstopSeconds + graceBeyondBackstop,
	}, nil
}

// loadReleaseManifest reads and strictly decodes a release manifest: unknown
// fields, trailing content, and non-integer numbers are all rejected so a
// misspelled or hand-mangled input cannot pass as a reviewed manifest.
func loadReleaseManifest(path string) (releaseManifest, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied manifest path
	if err != nil {
		return releaseManifest{}, fmt.Errorf(
			"cannot open the release manifest: [%v]",
			err,
		)
	}
	defer func() {
		_ = file.Close()
	}()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var manifest releaseManifest
	if err := decoder.Decode(&manifest); err != nil {
		// A manifest predating the provenance split fails here as a set of
		// unknown fields, which reads as a typo rather than as the one thing it
		// is. Say what actually happened, and where those values went.
		if relocated := relocatedIdentityKeys(path); len(relocated) > 0 {
			return releaseManifest{}, fmt.Errorf(
				"release manifest [%s] records release_identity.%s, which the "+
					"manifest no longer carries: the commit built and the "+
					"image digests are outputs of the build over this "+
					"document's own bytes, so they moved to the detached "+
					"release provenance generated after the build. Remove "+
					"them here and record them there; "+
					"`release-manifest verify-provenance` checks that "+
					"document against this one. Decoding reported: [%v]",
				path,
				strings.Join(relocated, ", release_identity."),
				err,
			)
		}
		return releaseManifest{}, fmt.Errorf(
			"cannot decode the release manifest [%s]: [%v]",
			path,
			err,
		)
	}
	// The end-of-document check must ask for the next token, not use More:
	// More only reports whether another value begins next, so a stray closing
	// delimiter after the manifest object would pass it. Token consumes
	// whatever actually follows — a value, a delimiter, or malformed bytes —
	// and only clean EOF is an intact single-document manifest.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return releaseManifest{}, fmt.Errorf(
			"release manifest [%s] carries trailing content after the "+
				"manifest object",
			path,
		)
	}

	return manifest, nil
}

// relocatedIdentityKeys reports which of the keys that moved to the detached
// provenance a document still carries under release_identity. It is diagnostic
// only — the caller has already refused the document — so an unreadable or
// unparseable file simply reports nothing rather than masking the real error
// with one about reading it a second time.
func relocatedIdentityKeys(path string) []string {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil
	}

	var document struct {
		ReleaseIdentity map[string]json.RawMessage `json:"release_identity"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil
	}

	var found []string
	for _, field := range relocatedIdentityFields {
		if _, present := document.ReleaseIdentity[field]; present {
			found = append(found, field)
		}
	}
	return found
}

// hashReleaseManifest returns the sha256 the release scripts bind records to:
// the digest of the exact manifest bytes, lowercase hexadecimal. Hashing the
// bytes rather than a re-encoding of the decoded document is deliberate — the
// binding has to be to the file a reviewer read and a record names, not to this
// binary's idea of how that file should be formatted.
func hashReleaseManifest(path string) (string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return "", fmt.Errorf(
			"cannot read the release manifest [%s] to hash it: [%v]",
			path,
			err,
		)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

// loadReleaseProvenance reads and strictly decodes a detached provenance
// document, on the same terms as the manifest: unknown fields, trailing
// content, and non-integer numbers are all rejected.
func loadReleaseProvenance(path string) (releaseProvenance, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return releaseProvenance{}, fmt.Errorf(
			"cannot open the release provenance: [%v]",
			err,
		)
	}
	defer func() {
		_ = file.Close()
	}()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var provenance releaseProvenance
	if err := decoder.Decode(&provenance); err != nil {
		return releaseProvenance{}, fmt.Errorf(
			"cannot decode the release provenance [%s]: [%v]",
			path,
			err,
		)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return releaseProvenance{}, fmt.Errorf(
			"release provenance [%s] carries trailing content after the "+
				"provenance object",
			path,
		)
	}

	return provenance, nil
}

// validateReleaseManifest checks a manifest against this binary's compiled
// bounds and reports every violation, not only the first: a reviewer fixing a
// stale manifest sees the complete distance to the current code in one run.
// The manifest is authoritative only when this returns nil.
func validateReleaseManifest(manifest releaseManifest) error {
	var violations []error

	if manifest.SchemaVersion != releaseManifestSchemaVersion {
		violations = append(violations, fmt.Errorf(
			"schema_version must be [%d], got [%d]",
			releaseManifestSchemaVersion,
			manifest.SchemaVersion,
		))
	}

	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err != nil {
		violations = append(violations, fmt.Errorf(
			"generated_at must be an RFC 3339 timestamp: [%v]",
			err,
		))
	}

	expectedEpoch := participation.CompiledEpoch.String()
	if manifest.ProtocolEpoch != expectedEpoch {
		violations = append(violations, fmt.Errorf(
			"protocol_epoch must be [%s], got [%s]",
			expectedEpoch,
			manifest.ProtocolEpoch,
		))
	}

	violations = append(
		violations,
		releaseIdentityViolations(manifest.ReleaseIdentity)...,
	)

	// Derivation must consume the compiled allowance, never the manifest's
	// own recorded value: the runtime cleanup wait is bound to the compiled
	// constant, so a manifest carrying any other allowance — even one whose
	// grace and scaffold values were recomputed coherently around it — would
	// grant the service manager a SIGKILL deadline the running process does
	// not honor. The recorded allowance is checked like every other number,
	// against the compiled value.
	derived, err := deriveTerminationGrace(
		compiledForcedCancellationAllowanceSeconds,
	)
	if err != nil {
		violations = append(violations, err)
		return errors.Join(violations...)
	}

	recorded := manifest.TerminationGrace
	// Notes are the only free-form field; every number must equal the value
	// derived from the compiled bounds so neither a stale manifest nor a
	// changed constant can pass unnoticed.
	recordedNumbers, derivedNumbers := recorded, derived
	recordedNumbers.Notes, derivedNumbers.Notes = "", ""
	if recordedNumbers != derivedNumbers {
		for _, mismatch := range []struct {
			field    string
			recorded uint64
			derived  uint64
		}{
			{"tbtc_completion_blocks", recorded.TBTCCompletionBlocks, derived.TBTCCompletionBlocks},
			{"beacon_completion_blocks", recorded.BeaconCompletionBlocks, derived.BeaconCompletionBlocks},
			{"beacon_inputs.group_size", recorded.BeaconInputs.GroupSize, derived.BeaconInputs.GroupSize},
			{"beacon_inputs.result_publication_block_step", recorded.BeaconInputs.ResultPublicationBlockStep, derived.BeaconInputs.ResultPublicationBlockStep},
			{"beacon_inputs.relay_entry_timeout_blocks", recorded.BeaconInputs.RelayEntryTimeoutBlocks, derived.BeaconInputs.RelayEntryTimeoutBlocks},
			{"maximum_legacy_completion_blocks", recorded.MaximumLegacyCompletionBlocks, derived.MaximumLegacyCompletionBlocks},
			{"reviewed_margin_blocks", recorded.ReviewedMarginBlocks, derived.ReviewedMarginBlocks},
			{"upper_block_interval_seconds", recorded.UpperBlockIntervalSeconds, derived.UpperBlockIntervalSeconds},
			{"rpc_processing_allowance_seconds", recorded.RPCProcessingAllowanceSeconds, derived.RPCProcessingAllowanceSeconds},
			{"in_process_backstop_seconds", recorded.InProcessBackstopSeconds, derived.InProcessBackstopSeconds},
			{"forced_cancellation_allowance_seconds", recorded.ForcedCancellationAllowanceSeconds, derived.ForcedCancellationAllowanceSeconds},
			{"process_exit_headroom_seconds", recorded.ProcessExitHeadroomSeconds, derived.ProcessExitHeadroomSeconds},
			{"termination_grace_period_seconds", recorded.TerminationGracePeriodSeconds, derived.TerminationGracePeriodSeconds},
		} {
			if mismatch.recorded != mismatch.derived {
				violations = append(violations, fmt.Errorf(
					"%s must be [%d] as derived from the compiled bounds, "+
						"got [%d]",
					mismatch.field,
					mismatch.derived,
					mismatch.recorded,
				))
			}
		}
	}

	return errors.Join(violations...)
}

// releaseIdentityViolations holds the recorded identity against what this
// binary compiles in.
//
// Both fields are compiled values, so both are checked outright rather than
// merely when present: unlike the build outputs that moved to the detached
// provenance, neither has a legitimate unrecorded state.
func releaseIdentityViolations(identity releaseIdentity) []error {
	var violations []error

	derived := deriveReleaseIdentity()

	if identity.ChainID != derived.ChainID {
		violations = append(violations, fmt.Errorf(
			"release_identity.chain_id must be [%d], the mainnet chain the "+
				"compiled cutover block is for, got [%d]",
			derived.ChainID,
			identity.ChainID,
		))
	}

	// Held against the compiled constant rather than merely required to be
	// present: the client resolves the mainnet schedule from what it compiles
	// in and reads no manifest at runtime, so a document naming a different
	// block would send operators to a cutover height no node observes.
	if identity.CutoverBlock != derived.CutoverBlock {
		violations = append(violations, fmt.Errorf(
			"release_identity.cutover_block must be [%d] as compiled into "+
				"this binary, got [%d]",
			derived.CutoverBlock,
			identity.CutoverBlock,
		))
	}

	return violations
}

// releaseImageViolations checks a recorded image list against the shape a
// reference has to have to name one immutable artifact. The field name is
// passed in because the same list is checked in the detached provenance, and a
// violation has to tell the reviewer which document to go edit.
func releaseImageViolations(field string, images []releaseImage) []error {
	var violations []error

	platforms := make(map[string]struct{}, len(images))
	for index, image := range images {
		if image.Platform == "" {
			violations = append(violations, fmt.Errorf(
				"%s[%d].platform must name the platform the image was built "+
					"for, as the architecture[/variant] the registry manifest "+
					"lists it under",
				field,
				index,
			))
		} else if _, duplicate := platforms[image.Platform]; duplicate {
			// One platform cannot have two images in one release: a scaffold
			// choosing between them would be choosing between artifacts, which
			// is the decision this document exists to have already made.
			violations = append(violations, fmt.Errorf(
				"%s[%d] repeats platform [%s]",
				field,
				index,
				image.Platform,
			))
		} else {
			platforms[image.Platform] = struct{}{}
		}

		if !imageDigestPattern.MatchString(image.Digest) {
			violations = append(violations, fmt.Errorf(
				"%s[%d].digest must be a sha256 content digest, got [%s]",
				field,
				index,
				image.Digest,
			))
			// The reference check below is a comparison against this digest,
			// so a malformed digest has nothing to check the reference against.
			continue
		}

		// A tag is a name the registry may repoint at any time. A reference
		// carrying one pulls whatever it resolves to at deployment time, which
		// is not necessarily the artifact this document — or the acceptance
		// evidence stated against its digest — describes.
		if !strings.HasSuffix(image.Reference, "@"+image.Digest) {
			violations = append(violations, fmt.Errorf(
				"%s[%d].reference must be pinned to its digest as "+
					"[repository]@%s, got [%s]",
				field,
				index,
				image.Digest,
				image.Reference,
			))
		}
	}

	return violations
}

// releaseReadyViolations reports what still stands between a manifest that is
// internally valid and one a release-acceptance decision may be taken against.
//
// The two are deliberately separate checks. Validity is a property of the
// document and the binary reading it, and it holds throughout development;
// readiness is a property of the release, and it cannot hold until the block
// the cutover happens at — a value that does not exist during development — has
// been reviewed and compiled in. Answering them with one verdict would either
// fail every development run or let a placeholder manifest pass as accepted.
//
// Readiness is the whole of what the manifest can answer. It says the reviewed
// document names a real cutover; it cannot say which artifact runs it, because
// the artifact does not exist when this document is reviewed. That half is the
// detached provenance's, and validateReleaseProvenance is where it is asked.
func releaseReadyViolations(manifest releaseManifest) []error {
	var violations []error

	if manifest.ReleaseIdentity.CutoverBlock == 0 {
		violations = append(violations, fmt.Errorf(
			"release_identity.cutover_block is the zero placeholder: a "+
				"reviewed release commit must set the mainnet cutover block "+
				"in the client before a manifest can be release-ready",
		))
	}

	return violations
}

// validateReleaseProvenance checks a detached provenance document against the
// reviewed manifest whose bytes hash to manifestSHA256, reporting every
// violation rather than only the first.
//
// Unlike the manifest, provenance has no valid half-recorded state. It is
// generated after the build it describes, so a document missing the commit or
// the images is not an early draft — it is a claim about a release whose
// artifacts its author did not have.
func validateReleaseProvenance(
	provenance releaseProvenance,
	manifestSHA256 string,
) error {
	var violations []error

	if provenance.SchemaVersion != releaseProvenanceSchemaVersion {
		violations = append(violations, fmt.Errorf(
			"schema_version must be [%d], got [%d]",
			releaseProvenanceSchemaVersion,
			provenance.SchemaVersion,
		))
	}

	if _, err := time.Parse(time.RFC3339, provenance.GeneratedAt); err != nil {
		violations = append(violations, fmt.Errorf(
			"generated_at must be an RFC 3339 timestamp: [%v]",
			err,
		))
	}

	// Both halves of the binding, separately reported. A malformed hash is a
	// document that never named a manifest; a well-formed one naming another
	// manifest is provenance for a release reviewed under different bounds, and
	// telling those two apart is what tells the operator which file to fix.
	switch {
	case !manifestDigestPattern.MatchString(provenance.ManifestSHA256):
		violations = append(violations, fmt.Errorf(
			"manifest_sha256 must be a 64-character lowercase hexadecimal "+
				"sha256 over the reviewed manifest bytes, got [%s]",
			provenance.ManifestSHA256,
		))
	case provenance.ManifestSHA256 != manifestSHA256:
		violations = append(violations, fmt.Errorf(
			"manifest_sha256 is [%s], but the reviewed manifest hashes to "+
				"[%s]; this provenance was taken over a different reviewed "+
				"document, or the manifest was edited after it was taken",
			provenance.ManifestSHA256,
			manifestSHA256,
		))
	}

	if !sourceCommitPattern.MatchString(provenance.SourceCommit) {
		violations = append(violations, fmt.Errorf(
			"source_commit must be a full 40-character lowercase hexadecimal "+
				"commit naming the tree the release was built from, got [%s]",
			provenance.SourceCommit,
		))
	}

	if len(provenance.Images) == 0 {
		violations = append(violations, fmt.Errorf(
			"images is empty: provenance must record the immutable image " +
				"digests the fleet runs and the acceptance evidence is " +
				"collected against",
		))
	}
	violations = append(
		violations,
		releaseImageViolations("images", provenance.Images)...,
	)

	return errors.Join(violations...)
}

// ReleaseManifestCommand contains the definition of the release-manifest
// command-line subcommand and its own subcommands.
var ReleaseManifestCommand = &cobra.Command{
	Use:   "release-manifest",
	Short: "Derive and validate the release manifest termination grace",
	Long: "The release-manifest command derives the service-manager " +
		"termination grace from this binary's compiled protocol bounds and " +
		"validates a reviewed release manifest against them. The external " +
		"grace must end strictly after the complete in-process shutdown " +
		"sequence — the quiesce backstop, the forced-cancellation cleanup " +
		"allowance, and the process teardown budgeted by the compiled exit " +
		"headroom — so the audited forced-cancellation path and its writes " +
		"always finish before the service manager escalates to SIGKILL.",
}

var releaseManifestPath string

// releaseManifestRequireReleaseReady turns validate into the release-acceptance
// check. It is off by default so the same command stays usable throughout
// development, where the identity a release records cannot yet exist.
var releaseManifestRequireReleaseReady bool

// The derive subcommand deliberately takes no allowance flag: the runtime
// cleanup wait consumes the compiled allowance, so the only manifest worth
// deriving — and the only one validation accepts — is the one recording
// exactly that constant.
var releaseManifestDeriveCommand = &cobra.Command{
	Use:   "derive",
	Short: "Print the release manifest derived from the compiled bounds",
	RunE: func(cmd *cobra.Command, args []string) error {
		grace, err := deriveTerminationGrace(
			compiledForcedCancellationAllowanceSeconds,
		)
		if err != nil {
			return err
		}

		// The identity is entirely compiled values. What the build produced is
		// not derived here and is not recorded here at all: it belongs to the
		// detached provenance, generated once the build this document is
		// reviewed ahead of has actually happened.
		manifest := releaseManifest{
			SchemaVersion:    releaseManifestSchemaVersion,
			GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
			ProtocolEpoch:    participation.CompiledEpoch.String(),
			ReleaseIdentity:  deriveReleaseIdentity(),
			TerminationGrace: grace,
		}

		encoded, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("cannot encode the derived manifest: [%v]", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
		return nil
	},
}

var releaseManifestValidateCommand = &cobra.Command{
	Use:   "validate",
	Short: "Validate a release manifest against the compiled bounds",
	RunE: func(cmd *cobra.Command, args []string) error {
		manifest, err := loadReleaseManifest(releaseManifestPath)
		if err != nil {
			return err
		}

		if err := validateReleaseManifest(manifest); err != nil {
			return fmt.Errorf(
				"release manifest [%s] rejected:\n%v",
				releaseManifestPath,
				err,
			)
		}

		if releaseManifestRequireReleaseReady {
			if violations := releaseReadyViolations(
				manifest,
			); len(violations) > 0 {
				return fmt.Errorf(
					"release manifest [%s] is valid but not release-ready:\n%v",
					releaseManifestPath,
					errors.Join(violations...),
				)
			}
		}

		fmt.Fprintf(
			cmd.OutOrStdout(),
			"release manifest [%s] validated against the compiled bounds\n"+
				"protocol epoch:                  %s\n"+
				"chain id:                        %d\n"+
				"cutover block:                   %d\n"+
				"in-process backstop:             %ds\n"+
				"service-manager termination grace: %ds\n",
			releaseManifestPath,
			manifest.ProtocolEpoch,
			manifest.ReleaseIdentity.ChainID,
			manifest.ReleaseIdentity.CutoverBlock,
			manifest.TerminationGrace.InProcessBackstopSeconds,
			manifest.TerminationGrace.TerminationGracePeriodSeconds,
		)
		return nil
	},
}

var releaseProvenancePath string

// verify-provenance is the release-acceptance half the manifest cannot answer.
// validate --release-ready says the reviewed document names a real cutover;
// this says which artifact runs it, and that the artifact was built under those
// same reviewed bounds.
var releaseManifestVerifyProvenanceCommand = &cobra.Command{
	Use:   "verify-provenance",
	Short: "Verify detached release provenance against a reviewed manifest",
	Long: "The verify-provenance command checks the detached provenance " +
		"document — the commit the release was built from and the immutable " +
		"image digests it publishes — against the reviewed release manifest " +
		"it was taken over. Those values are outputs of a build over the " +
		"manifest's own bytes, so they cannot live inside it: writing the " +
		"commit into the tree changes the commit. Provenance is therefore " +
		"generated after the build, never committed to the tree it describes, " +
		"and bound back to the reviewed document by its hash.",
	RunE: func(cmd *cobra.Command, args []string) error {
		manifest, err := loadReleaseManifest(releaseManifestPath)
		if err != nil {
			return err
		}

		// Provenance for a manifest this binary rejects is provenance for a
		// release that would not pass its own validation, so the reviewed
		// document is held to the compiled bounds first — and to readiness,
		// because provenance exists only for a release being accepted.
		if err := validateReleaseManifest(manifest); err != nil {
			return fmt.Errorf(
				"release manifest [%s] rejected:\n%v",
				releaseManifestPath,
				err,
			)
		}
		if violations := releaseReadyViolations(manifest); len(violations) > 0 {
			return fmt.Errorf(
				"release manifest [%s] is valid but not release-ready, so no "+
					"provenance can be verified against it:\n%v",
				releaseManifestPath,
				errors.Join(violations...),
			)
		}

		manifestSHA256, err := hashReleaseManifest(releaseManifestPath)
		if err != nil {
			return err
		}

		provenance, err := loadReleaseProvenance(releaseProvenancePath)
		if err != nil {
			return err
		}
		if err := validateReleaseProvenance(
			provenance,
			manifestSHA256,
		); err != nil {
			return fmt.Errorf(
				"release provenance [%s] rejected:\n%v",
				releaseProvenancePath,
				err,
			)
		}

		fmt.Fprintf(
			cmd.OutOrStdout(),
			"release provenance [%s] verified against [%s]\n"+
				"reviewed manifest sha256: %s\n"+
				"source commit:            %s\n"+
				"cutover block:            %d\n",
			releaseProvenancePath,
			releaseManifestPath,
			manifestSHA256,
			provenance.SourceCommit,
			manifest.ReleaseIdentity.CutoverBlock,
		)
		for _, image := range provenance.Images {
			fmt.Fprintf(
				cmd.OutOrStdout(),
				"image %-16s %s\n",
				image.Platform,
				image.Reference,
			)
		}
		return nil
	},
}

func init() {
	releaseManifestValidateCommand.Flags().StringVar(
		&releaseManifestPath,
		"manifest",
		"",
		"Path to the release manifest JSON document.",
	)
	releaseManifestValidateCommand.Flags().BoolVar(
		&releaseManifestRequireReleaseReady,
		"release-ready",
		false,
		"Additionally require the reviewed cutover block to be the nonzero "+
			"block compiled into this binary. What the release was built "+
			"into is checked separately, by verify-provenance.",
	)
	if err := releaseManifestValidateCommand.MarkFlagRequired("manifest"); err != nil {
		logger.Fatalf("cannot mark the manifest flag required: [%v]", err)
	}

	releaseManifestVerifyProvenanceCommand.Flags().StringVar(
		&releaseManifestPath,
		"manifest",
		"",
		"Path to the reviewed release manifest JSON document.",
	)
	releaseManifestVerifyProvenanceCommand.Flags().StringVar(
		&releaseProvenancePath,
		"provenance",
		"",
		"Path to the detached release provenance JSON document, generated "+
			"after the build and never committed to the tree it describes.",
	)
	for _, flag := range []string{"manifest", "provenance"} {
		if err := releaseManifestVerifyProvenanceCommand.MarkFlagRequired(
			flag,
		); err != nil {
			logger.Fatalf("cannot mark the %s flag required: [%v]", flag, err)
		}
	}

	ReleaseManifestCommand.AddCommand(
		releaseManifestDeriveCommand,
		releaseManifestValidateCommand,
		releaseManifestVerifyProvenanceCommand,
	)
}
