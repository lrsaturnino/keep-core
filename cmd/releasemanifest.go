package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keep-network/keep-core/pkg/beacon"
	"github.com/keep-network/keep-core/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
	"github.com/keep-network/keep-core/pkg/tbtc"
)

// releaseManifestSchemaVersion is the only release manifest schema this
// binary understands. A manifest carrying any other version is rejected
// instead of being partially interpreted.
const releaseManifestSchemaVersion = uint64(1)

// defaultForcedCancellationAllowanceSeconds is the reviewed wall-clock
// allowance between the in-process quiesce backstop firing and the service
// manager escalating to SIGKILL. It covers the audited forced-cancellation
// path that runs after the backstop: canceling the permits that outlived the
// drain, persisting their audit records, closing the gate, and letting the
// process exit. It deliberately mirrors the RPC/processing margin used inside
// the backstop itself; both absorb the same order of local skew.
const defaultForcedCancellationAllowanceSeconds = uint64(300)

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
// except the forced-cancellation allowance is derived from this binary's
// compiled protocol bounds; the allowance is the one reviewed input recorded
// only here, and the grace period is the checked sum of the backstop, the
// allowance, and the compiled process-exit headroom.
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
	TerminationGrace terminationGrace `json:"termination_grace"`
}

// deriveTerminationGrace computes the termination grace section from this
// binary's compiled protocol bounds: the tBTC and beacon completion bounds,
// the reviewed quiesce margin, the upper block interval, the RPC/processing
// allowance, and the in-process backstop produced by the same checked
// arithmetic the node uses at startup. The forced-cancellation allowance is
// the one reviewed input that is not compiled in; a zero allowance is
// rejected because the external grace must end strictly after the in-process
// backstop for the audited forced-cancellation path to run before SIGKILL.
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

	derived, err := deriveTerminationGrace(
		manifest.TerminationGrace.ForcedCancellationAllowanceSeconds,
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
var releaseManifestAllowanceSeconds uint64

var releaseManifestDeriveCommand = &cobra.Command{
	Use:   "derive",
	Short: "Print the release manifest derived from the compiled bounds",
	RunE: func(cmd *cobra.Command, args []string) error {
		grace, err := deriveTerminationGrace(releaseManifestAllowanceSeconds)
		if err != nil {
			return err
		}

		manifest := releaseManifest{
			SchemaVersion:    releaseManifestSchemaVersion,
			GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
			ProtocolEpoch:    participation.CompiledEpoch.String(),
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

		fmt.Fprintf(
			cmd.OutOrStdout(),
			"release manifest [%s] validated against the compiled bounds\n"+
				"protocol epoch:                  %s\n"+
				"in-process backstop:             %ds\n"+
				"service-manager termination grace: %ds\n",
			releaseManifestPath,
			manifest.ProtocolEpoch,
			manifest.TerminationGrace.InProcessBackstopSeconds,
			manifest.TerminationGrace.TerminationGracePeriodSeconds,
		)
		return nil
	},
}

func init() {
	releaseManifestDeriveCommand.Flags().Uint64Var(
		&releaseManifestAllowanceSeconds,
		"forcedCancellationAllowanceSeconds",
		defaultForcedCancellationAllowanceSeconds,
		"Reviewed allowance between the in-process backstop and SIGKILL.",
	)

	releaseManifestValidateCommand.Flags().StringVar(
		&releaseManifestPath,
		"manifest",
		"",
		"Path to the release manifest JSON document.",
	)
	if err := releaseManifestValidateCommand.MarkFlagRequired("manifest"); err != nil {
		logger.Fatalf("cannot mark the manifest flag required: [%v]", err)
	}

	ReleaseManifestCommand.AddCommand(
		releaseManifestDeriveCommand,
		releaseManifestValidateCommand,
	)
}
