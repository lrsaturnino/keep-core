package cutoverroster

import (
	"strings"
	"testing"
)

func TestAlertRules_NamesForAndRouting(t *testing.T) {
	rules := AlertRules()

	byName := map[string]AlertRule{}
	for _, rule := range rules {
		byName[rule.Alert] = rule
	}

	for _, name := range []string{
		"CutoverBlockingOperatorsPresent",
		"CutoverRosterIncomplete",
	} {
		rule, ok := byName[name]
		if !ok {
			t.Fatalf("expected alert %q to be defined", name)
		}
		// Two consecutive one-minute evaluations.
		if rule.For != "2m" {
			t.Errorf("alert %q: expected for=2m, got %q", name, rule.For)
		}
		// Routed to Release and Operator Coordination.
		route := rule.Labels["route_to"]
		if !strings.Contains(route, "release") ||
			!strings.Contains(route, "operator-coordination") {
			t.Errorf("alert %q: expected routing to release and operator-coordination, got %q", name, route)
		}
		if rule.Expr == "" {
			t.Errorf("alert %q: expected a non-empty expression", name)
		}
	}
}

func TestRenderAlertRulesYAML(t *testing.T) {
	yaml := RenderAlertRulesYAML()

	for _, want := range []string{
		"groups:",
		"name: cutover-roster",
		"alert: CutoverBlockingOperatorsPresent",
		"alert: CutoverRosterIncomplete",
		MetricFleetBlockingOperators,
		"for: 2m",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("rendered rules missing %q:\n%s", want, yaml)
		}
	}
}
