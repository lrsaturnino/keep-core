package cutoverroster

import (
	"github.com/prometheus/client_golang/prometheus"
)

// operatorLabels are the label names on the per-operator gauges.
var operatorLabels = []string{"operator_address", "staking_provider", "status"}

// PrometheusMetrics is a Prometheus-backed MetricsSink for the fleet collector.
type PrometheusMetrics struct {
	registry *prometheus.Registry

	fleetGauges    map[string]prometheus.Gauge
	operatorGauges map[string]*prometheus.GaugeVec
}

// NewPrometheusMetrics constructs and registers all fleet and operator metrics
// in a dedicated registry.
func NewPrometheusMetrics() *PrometheusMetrics {
	registry := prometheus.NewRegistry()

	fleetGauges := map[string]prometheus.Gauge{}
	for name, help := range map[string]string{
		MetricFleetBlockingOperators: "Distinct nonquarantined operators in any blocking status",
		MetricFleetObservedLegacy:    "Operators with retained post-cutover legacy wire evidence",
		MetricReportersStale:         "Eligible instances without a fresh accepted report",
		MetricInventoryUnreconciled:  "Identity/target/inventory reconciliation failures",
	} {
		gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
		registry.MustRegister(gauge)
		fleetGauges[name] = gauge
	}

	operatorGauges := map[string]*prometheus.GaugeVec{}
	for name, help := range map[string]string{
		MetricOperatorInfo:           "Bounded central-inventory operator status",
		MetricOperatorFirstSeenBlock: "First relevant evidence block for the operator",
		MetricOperatorLastSeenBlock:  "Last wire/report evidence block for the operator",
	} {
		vec := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, operatorLabels)
		registry.MustRegister(vec)
		operatorGauges[name] = vec
	}

	return &PrometheusMetrics{
		registry:       registry,
		fleetGauges:    fleetGauges,
		operatorGauges: operatorGauges,
	}
}

// Registry returns the underlying Prometheus registry for exposition.
func (m *PrometheusMetrics) Registry() *prometheus.Registry {
	return m.registry
}

// SetGauge implements MetricsSink for the label-less fleet gauges.
func (m *PrometheusMetrics) SetGauge(name string, value float64) {
	if gauge, ok := m.fleetGauges[name]; ok {
		gauge.Set(value)
	}
}

// SetOperatorGauge implements MetricsSink for the per-operator labeled gauges.
func (m *PrometheusMetrics) SetOperatorGauge(
	name, operatorAddress, stakingProvider, status string,
	value float64,
) {
	if vec, ok := m.operatorGauges[name]; ok {
		vec.WithLabelValues(operatorAddress, stakingProvider, status).Set(value)
	}
}

// ResetOperatorGauges clears every per-operator labeled series so stale label
// sets do not linger between cycles.
func (m *PrometheusMetrics) ResetOperatorGauges() {
	for _, vec := range m.operatorGauges {
		vec.Reset()
	}
}
