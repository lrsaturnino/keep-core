package cutoverroster

import (
	"fmt"
	"strings"
)

// AlertRule is a single Prometheus alerting rule for the fleet collector.
type AlertRule struct {
	Alert       string
	Expr        string
	For         string
	Labels      map[string]string
	Annotations map[string]string
}

// CutoverRosterJob is the Prometheus scrape job that collects the fleet metrics
// (infrastructure/kube/keep-prd/monitoring/prometheus/config/config.yaml). The
// collector-down alert keys on it: if the collector dies, every
// performance_cutover_* series vanishes, so a value-threshold alert on those
// series would itself evaluate absent and never fire. An up/absent() alert on the
// scrape target catches that hole.
const CutoverRosterJob = "cutover-roster"

// AlertRules returns the required fleet-readiness alerts. All fire only after two
// consecutive one-minute evaluations and are routed to the Release and Operator
// Coordination teams via routing labels.
func AlertRules() []AlertRule {
	routing := func(severity string) map[string]string {
		return map[string]string{
			"severity": severity,
			"team":     "release",
			"route_to": "release,operator-coordination",
		}
	}

	return []AlertRule{
		{
			Alert: "CutoverBlockingOperatorsPresent",
			Expr:  fmt.Sprintf("%s > 0", MetricFleetBlockingOperators),
			// Two consecutive one-minute evaluations.
			For:    "2m",
			Labels: routing("critical"),
			Annotations: map[string]string{
				"summary": "Cutover-eligible operators remain in a blocking status.",
				"description": "One or more authoritative operators are not exact-R1 " +
					"or independently quarantined. Cutover readiness is not met.",
			},
		},
		{
			Alert: "CutoverRosterIncomplete",
			Expr: fmt.Sprintf(
				"%s > 0 or %s > 0 or %s > 0",
				MetricFleetBlockingOperators,
				MetricReportersStale,
				MetricInventoryUnreconciled,
			),
			For:    "2m",
			Labels: routing("warning"),
			Annotations: map[string]string{
				"summary": "Cutover fleet roster is incomplete.",
				"description": "Blocking operators, stale reporters, or unreconciled " +
					"inventory are present. The go/no-go completeness criteria are not met.",
			},
		},
		{
			// A dead or unscraped collector makes every performance_cutover_* series
			// vanish, so the two alerts above would evaluate absent and never fire.
			// This alert fires when the collector scrape target is down (up == 0) OR
			// has disappeared entirely from the scrape config (absent), so a missing
			// collector can never leave both roster alerts silently absent.
			Alert: "CutoverRosterCollectorDown",
			Expr: fmt.Sprintf(
				"up{job=%q} == 0 or absent(up{job=%q})",
				CutoverRosterJob, CutoverRosterJob,
			),
			For:    "2m",
			Labels: routing("critical"),
			Annotations: map[string]string{
				"summary": "Cutover-roster collector scrape target is down or absent.",
				"description": "Prometheus cannot scrape the cutover-roster collector " +
					"(job cutover-roster): the target is down or has disappeared from the " +
					"scrape config. Every performance_cutover_* series is therefore stale " +
					"or absent, so the other roster alerts can be silently absent. Cutover " +
					"readiness cannot be evaluated until the collector is restored.",
			},
		},
	}
}

// RenderAlertRulesYAML renders the alert rules as a Prometheus rule-file group.
func RenderAlertRulesYAML() string {
	var b strings.Builder
	b.WriteString("groups:\n")
	b.WriteString("  - name: cutover-roster\n")
	b.WriteString("    rules:\n")
	for _, rule := range AlertRules() {
		fmt.Fprintf(&b, "      - alert: %s\n", rule.Alert)
		fmt.Fprintf(&b, "        expr: %s\n", rule.Expr)
		fmt.Fprintf(&b, "        for: %s\n", rule.For)
		b.WriteString("        labels:\n")
		for _, key := range sortedKeys(rule.Labels) {
			fmt.Fprintf(&b, "          %s: %q\n", key, rule.Labels[key])
		}
		b.WriteString("        annotations:\n")
		for _, key := range sortedKeys(rule.Annotations) {
			fmt.Fprintf(&b, "          %s: %q\n", key, rule.Annotations[key])
		}
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Small maps; simple insertion sort keeps output deterministic without a
	// sort import churn.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
