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

// TestAlertRules_CollectorDownAlert proves the up/absent() alert exists so a dead
// collector — which makes every performance_cutover_* series vanish — cannot leave
// both roster alerts silently absent.
func TestAlertRules_CollectorDownAlert(t *testing.T) {
	var found bool
	for _, r := range AlertRules() {
		if r.Alert != "CutoverRosterCollectorDown" {
			continue
		}
		found = true
		if !strings.Contains(r.Expr, `up{job="cutover-roster"}`) {
			t.Errorf("collector-down alert must key on the cutover-roster scrape job: %q", r.Expr)
		}
		if !strings.Contains(r.Expr, "absent(") {
			t.Errorf("collector-down alert must use absent() so a vanished target fires: %q", r.Expr)
		}
		if r.For != "2m" {
			t.Errorf("collector-down alert for=%q, want 2m", r.For)
		}
		if route := r.Labels["route_to"]; !strings.Contains(route, "release") {
			t.Errorf("collector-down alert must route to release, got %q", route)
		}
	}
	if !found {
		t.Fatal("expected a CutoverRosterCollectorDown alert to be defined")
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
