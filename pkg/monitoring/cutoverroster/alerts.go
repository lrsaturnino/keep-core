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

// AlertRules returns the two required fleet-readiness alerts. Both fire only
// after two consecutive one-minute evaluations and are routed to the Release and
// Operator Coordination teams via routing labels.
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
