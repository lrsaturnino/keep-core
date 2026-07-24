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
