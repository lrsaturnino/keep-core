package clientinfo

import (
	"context"
	"fmt"
	"testing"

	keepclientinfo "github.com/keep-network/keep-common/pkg/clientinfo"
)

// TestCutoverMetrics_ExactExportedNames pins the exact metric names exposed on
// the /metrics endpoint. The performance registry prepends the "performance_"
// application prefix (see ObserveApplicationSource), so the exported name is
// "performance_" + the internal constant. This guards against the regression
// where the internal constant itself carried a "performance_" prefix and the
// metric was exposed as performance_performance_* (or, being unregistered, not
// at all).
func TestCutoverMetrics_ExactExportedNames(t *testing.T) {
	cases := []struct {
		internal string
		exported string
	}{
		{MetricAnnouncerSessionIDMismatchTotal, "performance_announcer_session_id_mismatch_total"},
		{MetricAnnouncerCrossFormatPeerTotal, "performance_announcer_cross_format_peer_total"},
		{MetricAnnouncerLegacyPeersCurrent, "performance_announcer_legacy_peers_current"},
		{MetricAnnouncerLegacyPeerOldestAgeBlocks, "performance_announcer_legacy_peer_oldest_age_blocks"},
		{MetricAnnouncerLegacyPeerRosterRevision, "performance_announcer_legacy_peer_roster_revision"},
		{MetricAnnouncerLegacyPeerAdditionsTotal, "performance_announcer_legacy_peer_additions_total"},
		{MetricAnnouncerLegacyPeerEvictionsTotal, "performance_announcer_legacy_peer_evictions_total"},
		{MetricParticipationTBTCQuarantinePreservationFailuresTotal, "performance_participation_tbtc_quarantine_preservation_failures_total"},
		{MetricParticipationBeaconQuarantinePreservationFailuresTotal, "performance_participation_beacon_quarantine_preservation_failures_total"},
		{MetricParticipationTBTCQuarantineIncompleteOutputs, "performance_participation_tbtc_quarantine_incomplete_outputs"},
		{MetricParticipationBeaconQuarantineIncompleteOutputs, "performance_participation_beacon_quarantine_incomplete_outputs"},
	}

	for _, c := range cases {
		got := fmt.Sprintf("performance_%s", c.internal)
		if got != c.exported {
			t.Errorf(
				"internal metric %q exposes as %q, want %q",
				c.internal,
				got,
				c.exported,
			)
		}
	}
}

// TestCutoverMetrics_RegisteredAtZeroAndRecordable proves that the seven cutover
// observability metrics are registered at zero by registerAllMetrics (so they
// appear on /metrics before any event) and that they record through the
// production PerformanceMetrics recorder used by the tBTC announcer wiring and
// the node-local cutover roster.
func TestCutoverMetrics_RegisteredAtZeroAndRecordable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &Registry{keepclientinfo.NewRegistry(), ctx}
	pm := NewPerformanceMetrics(ctx, registry)

	counters := []string{
		MetricAnnouncerSessionIDMismatchTotal,
		MetricAnnouncerCrossFormatPeerTotal,
		MetricAnnouncerLegacyPeerAdditionsTotal,
		MetricAnnouncerLegacyPeerEvictionsTotal,
	}
	gauges := []string{
		MetricAnnouncerLegacyPeersCurrent,
		MetricAnnouncerLegacyPeerOldestAgeBlocks,
		MetricAnnouncerLegacyPeerRosterRevision,
	}

	for _, name := range counters {
		if got := pm.GetCounterValue(name); got != 0 {
			t.Errorf("counter %q should be registered at zero, got %v", name, got)
		}
	}
	for _, name := range gauges {
		if got := pm.GetGaugeValue(name); got != 0 {
			t.Errorf("gauge %q should be registered at zero, got %v", name, got)
		}
	}

	// Record like the production announcer/roster path does.
	pm.IncrementCounter(MetricAnnouncerSessionIDMismatchTotal, 1)
	pm.IncrementCounter(MetricAnnouncerSessionIDMismatchTotal, 1)
	pm.IncrementCounter(MetricAnnouncerCrossFormatPeerTotal, 1)
	pm.SetGauge(MetricAnnouncerLegacyPeersCurrent, 3)
	pm.SetGauge(MetricAnnouncerLegacyPeerRosterRevision, 7)

	if got := pm.GetCounterValue(MetricAnnouncerSessionIDMismatchTotal); got != 2 {
		t.Errorf("mismatch counter = %v, want 2", got)
	}
	if got := pm.GetCounterValue(MetricAnnouncerCrossFormatPeerTotal); got != 1 {
		t.Errorf("cross-format counter = %v, want 1", got)
	}
	if got := pm.GetGaugeValue(MetricAnnouncerLegacyPeersCurrent); got != 3 {
		t.Errorf("legacy peers gauge = %v, want 3", got)
	}
	if got := pm.GetGaugeValue(MetricAnnouncerLegacyPeerRosterRevision); got != 7 {
		t.Errorf("roster revision gauge = %v, want 7", got)
	}
}

// participationMetricFamily is the observability contract of the cutover gate:
// every series the rehearsal's evidence steps snapshot by name. It is the
// pre-image of the PARTICIPATION_METRICS list the exact-image rehearsal reads
// off a running node, so a series missing from the production registration
// fails here rather than at rehearsal time.
var participationMetricFamily = []string{
	MetricParticipationGateState,
	MetricParticipationCurrentBlock,
	MetricParticipationCutoverBlock,
	MetricParticipationAllowed,
	MetricParticipationActiveCeremonies,
	MetricParticipationActiveLegacyCeremonies,
	MetricParticipationActiveSecurityV2Ceremonies,
	MetricParticipationModeLegacyTotal,
	MetricParticipationModeSecurityV2Total,
	MetricParticipationLegacyCompletionsAfterCutoverTotal,
	MetricParticipationRefusalsTotal,
	MetricParticipationCommitRefusalsTotal,
	MetricParticipationClockErrorsTotal,
	MetricParticipationClockAbortsTotal,
	MetricParticipationQuiesceTotal,
	MetricParticipationQuiesceForcedAbortsTotal,
	MetricParticipationTBTCQuarantinePreservationFailuresTotal,
	MetricParticipationBeaconQuarantinePreservationFailuresTotal,
	MetricParticipationTBTCQuarantineIncompleteOutputs,
	MetricParticipationBeaconQuarantineIncompleteOutputs,
	MetricParticipationQuarantinedTBTCSigners,
}

// TestParticipationMetrics_RegisteredWithTheExposingRegistry proves every
// participation series is registered with the client-info registry that backs
// /metrics, not merely readable back through the recorder.
//
// The distinction is the whole point. GetGaugeValue and GetCounterValue read
// the recorder's own maps, and SetGauge inserts into those maps for a name it
// was never asked to register — so a series omitted from registerAllMetrics
// reads back correctly through the recorder while being absent from the
// exposition entirely. Membership is asserted by re-registering the exported
// name: the registry refuses a name it already holds, which is exactly the set
// the exposition enumerates.
func TestParticipationMetrics_RegisteredWithTheExposingRegistry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &Registry{keepclientinfo.NewRegistry(), ctx}
	NewPerformanceMetrics(ctx, registry)

	for _, name := range participationMetricFamily {
		exported := fmt.Sprintf("performance_%s", name)
		if _, err := registry.NewMetricGauge(exported); err == nil {
			t.Errorf(
				"metric %q is not registered with the registry, so it is "+
					"absent from /metrics until something records it",
				exported,
			)
		}
	}

	// A name nothing registered must register cleanly, otherwise the loop
	// above would pass against any registry that refuses everything.
	if _, err := registry.NewMetricGauge(
		"performance_participation_absent_control",
	); err != nil {
		t.Fatalf(
			"an unregistered name must be registrable, otherwise the "+
				"membership assertion above is vacuous: %v",
			err,
		)
	}
}

// TestParticipationMetrics_QuarantinedSignersRegisteredAtZero proves the
// quarantined-signer gauge is pre-registered at zero rather than created on
// first use by SetGauge, and that it then records through the production
// recorder the tBTC quarantine reporter holds.
//
// Pre-registration is what makes an empty quarantine distinguishable from an
// unreported one: a node that never quarantines anything must still publish a
// zero, or a rollback decision cannot tell "nothing preserved" from "nothing
// said".
func TestParticipationMetrics_QuarantinedSignersRegisteredAtZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &Registry{keepclientinfo.NewRegistry(), ctx}
	pm := NewPerformanceMetrics(ctx, registry)

	pm.gaugesMutex.RLock()
	_, preRegistered := pm.gauges[MetricParticipationQuarantinedTBTCSigners]
	pm.gaugesMutex.RUnlock()

	if !preRegistered {
		t.Fatal(
			"the quarantined-signer gauge must be registered before any " +
				"quarantine occurs, not created by the first SetGauge",
		)
	}

	if got := pm.GetGaugeValue(
		MetricParticipationQuarantinedTBTCSigners,
	); got != 0 {
		t.Errorf("quarantined-signer gauge = %v at startup, want 0", got)
	}

	pm.SetGauge(MetricParticipationQuarantinedTBTCSigners, 2)

	if got := pm.GetGaugeValue(
		MetricParticipationQuarantinedTBTCSigners,
	); got != 2 {
		t.Errorf("quarantined-signer gauge = %v after update, want 2", got)
	}
}

// TestParticipationMetrics_QuarantinePreservationFailuresRegisteredAtZero
// proves both protocol-specific failure counters are present before a
// quarantine attempt. Zero must be a published reading rather than an absent
// series: the rollback gate distinguishes "no preservation failed" from "this
// node never reported whether preservation failed".
func TestParticipationMetrics_QuarantinePreservationFailuresRegisteredAtZero(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &Registry{keepclientinfo.NewRegistry(), ctx}
	pm := NewPerformanceMetrics(ctx, registry)

	for _, name := range []string{
		MetricParticipationTBTCQuarantinePreservationFailuresTotal,
		MetricParticipationBeaconQuarantinePreservationFailuresTotal,
	} {
		if got := pm.GetCounterValue(name); got != 0 {
			t.Errorf("quarantine-preservation counter %q = %v at startup, want 0", name, got)
		}

		pm.IncrementCounter(name, 1)
		if got := pm.GetCounterValue(name); got != 1 {
			t.Errorf("quarantine-preservation counter %q = %v after increment, want 1", name, got)
		}
	}
}

// TestParticipationMetrics_QuarantineIncompleteOutputsRegisteredAtZero proves
// both live incomplete-output gauges are present before any quarantine attempt.
// A rollback sampler must be able to distinguish a running node reporting zero
// incomplete outputs from one that never exposed the signal.
func TestParticipationMetrics_QuarantineIncompleteOutputsRegisteredAtZero(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &Registry{keepclientinfo.NewRegistry(), ctx}
	pm := NewPerformanceMetrics(ctx, registry)

	for _, name := range []string{
		MetricParticipationTBTCQuarantineIncompleteOutputs,
		MetricParticipationBeaconQuarantineIncompleteOutputs,
	} {
		pm.gaugesMutex.RLock()
		_, preRegistered := pm.gauges[name]
		pm.gaugesMutex.RUnlock()
		if !preRegistered {
			t.Errorf(
				"quarantine-incomplete gauge %q must be registered before "+
					"preservation starts",
				name,
			)
			continue
		}

		if got := pm.GetGaugeValue(name); got != 0 {
			t.Errorf(
				"quarantine-incomplete gauge %q = %v at startup, want 0",
				name,
				got,
			)
		}

		pm.SetGauge(name, 2)
		if got := pm.GetGaugeValue(name); got != 2 {
			t.Errorf(
				"quarantine-incomplete gauge %q = %v after update, want 2",
				name,
				got,
			)
		}
	}
}
