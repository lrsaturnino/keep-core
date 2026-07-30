package cmd

import (
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

// releaseIdentity names what the reviewed release is — the source it was built
// from and the images it publishes — and the chain and block its cutover
// happens at.
//
// The termination grace binds this document to the compiled bounds of the
// binary validating it. That establishes the numbers are right for some build
// of this source; it does not establish which build the fleet runs, nor which
// chain and block the cutover it describes is for. Every statement made about
// this release afterwards — smoke-gate evidence, the fleet inventory's
// per-instance digest attestation, a rollback decision taken against a block
// height — is stated against those identities, so the reviewed record carries
// them and validation holds them against what the binary compiles in.
type releaseIdentity struct {
	SourceCommit string         `json:"source_commit"`
	ChainID      uint64         `json:"chain_id"`
	CutoverBlock uint64         `json:"cutover_block"`
	Images       []releaseImage `json:"images"`
	Notes        string         `json:"notes,omitempty"`
}

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

// deriveReleaseIdentity returns the part of the release identity this binary
// can state on its own: the mainnet chain the compiled cutover constant is for,
// and the cutover block compiled into it.
//
// The source commit and the published image digests are outputs of the build
// rather than values inside it — a binary cannot honestly name the tree it was
// produced from or the registry content addresses it was packaged into — so
// they are recorded by the release commit and checked here rather than derived.
func deriveReleaseIdentity() releaseIdentity {
	return releaseIdentity{
		ChainID:      uint64(commonEthereum.Mainnet.ChainID()),
		CutoverBlock: participation.MainnetCutoverBlock,
		// An empty list rather than none, so the derived document says "no
		// images recorded yet" in the same shape the filled-in one uses.
		Images: []releaseImage{},
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
// binary compiles in, and against the shape a reference has to have to name one
// immutable artifact.
//
// It does not require the identity to be filled in. A manifest is derived and
// reviewed before the build it will name exists, so an unrecorded source commit
// or an empty image list is a manifest that is not release-ready yet rather
// than one contradicting the binary — the difference releaseReadyViolations
// exists to state. What is recorded, however, has to be right.
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

	if identity.SourceCommit != "" &&
		!sourceCommitPattern.MatchString(identity.SourceCommit) {
		violations = append(violations, fmt.Errorf(
			"release_identity.source_commit must be a full 40-character "+
				"lowercase hexadecimal commit, got [%s]",
			identity.SourceCommit,
		))
	}

	platforms := make(map[string]struct{}, len(identity.Images))
	for index, image := range identity.Images {
		if image.Platform == "" {
			violations = append(violations, fmt.Errorf(
				"release_identity.images[%d].platform must name the platform "+
					"the image was built for",
				index,
			))
		} else if _, duplicate := platforms[image.Platform]; duplicate {
			// One platform cannot have two images in one release: a scaffold
			// choosing between them would be choosing between artifacts, which
			// is the decision this document exists to have already made.
			violations = append(violations, fmt.Errorf(
				"release_identity.images[%d] repeats platform [%s]",
				index,
				image.Platform,
			))
		} else {
			platforms[image.Platform] = struct{}{}
		}

		if !imageDigestPattern.MatchString(image.Digest) {
			violations = append(violations, fmt.Errorf(
				"release_identity.images[%d].digest must be a sha256 content "+
					"digest, got [%s]",
				index,
				image.Digest,
			))
			// The reference check below is a comparison against this digest,
			// so a malformed digest has nothing to check the reference against.
			continue
		}

		// A tag is a name the registry may repoint at any time. A reference
		// carrying one pulls whatever it resolves to at deployment time, which
		// is not necessarily the artifact this manifest — or the acceptance
		// evidence stated against its digest — describes.
		if !strings.HasSuffix(image.Reference, "@"+image.Digest) {
			violations = append(violations, fmt.Errorf(
				"release_identity.images[%d].reference must be pinned to its "+
					"digest as [repository]@%s, got [%s]",
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
// readiness is a property of the release, and it cannot hold until values that
// do not exist during development — the block the cutover happens at, the
// commit finally built, the digests acceptance actually ran against — have been
// reviewed and recorded. Answering them with one verdict would either fail
// every development run or let a manifest with none of them pass as accepted.
func releaseReadyViolations(manifest releaseManifest) []error {
	var violations []error

	identity := manifest.ReleaseIdentity

	if identity.CutoverBlock == 0 {
		violations = append(violations, fmt.Errorf(
			"release_identity.cutover_block is the zero placeholder: a "+
				"reviewed release commit must set the mainnet cutover block "+
				"in the client before a manifest can be release-ready",
		))
	}

	if identity.SourceCommit == "" {
		violations = append(violations, fmt.Errorf(
			"release_identity.source_commit is unrecorded: the manifest must "+
				"name the exact commit the accepted release was built from",
		))
	}

	if len(identity.Images) == 0 {
		violations = append(violations, fmt.Errorf(
			"release_identity.images is empty: the manifest must record the "+
				"immutable image digests the acceptance evidence was "+
				"collected against",
		))
	}

	return violations
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

		// The identity is derived only as far as the binary can speak for it.
		// The source commit and image digests come out empty, which is what a
		// document generated before its own build has to say about them, and
		// is exactly what release-readiness then refuses to accept.
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
		"Additionally require the release identity to be fully recorded: a "+
			"nonzero compiled cutover block, the source commit built, and the "+
			"immutable image digests acceptance ran against.",
	)
	if err := releaseManifestValidateCommand.MarkFlagRequired("manifest"); err != nil {
		logger.Fatalf("cannot mark the manifest flag required: [%v]", err)
	}

	ReleaseManifestCommand.AddCommand(
		releaseManifestDeriveCommand,
		releaseManifestValidateCommand,
	)
}
