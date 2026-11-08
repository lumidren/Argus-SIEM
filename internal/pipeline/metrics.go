package pipeline

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the pipeline's Prometheus collectors. A nil *Metrics is valid
// and records nothing, which keeps tests free of registry setup.
type Metrics struct {
	Events       *prometheus.CounterVec
	ParseSeconds *prometheus.HistogramVec
	ParsePanics  *prometheus.CounterVec
	Duplicates   *prometheus.CounterVec
	Conflicts    *prometheus.CounterVec
	Invalid      prometheus.Counter
	Batches      prometheus.Counter
	BatchEvents  prometheus.Histogram
}

// NewMetrics registers the collectors on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_pipeline_events_total", Help: "Events produced by parsers, by tenant, parser and parse status.",
		}, []string{"tenant", "parser", "status"}),
		ParseSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "argus_parser_duration_seconds", Help: "Time spent parsing one record.",
			Buckets: []float64{1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 5e-3, 1e-2, 5e-2},
		}, []string{"parser"}),
		ParsePanics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_parser_panics_total", Help: "Recovered parser panics.",
		}, []string{"parser"}),
		Duplicates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_pipeline_duplicates_total", Help: "Events dropped as duplicates before indexing.",
		}, []string{"tenant"}),
		Conflicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_sink_conflicts_total", Help: "Index writes that hit an existing _id.",
		}, []string{"tenant"}),
		Invalid: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "argus_pipeline_invalid_envelopes_total", Help: "Raw messages that were not valid envelopes.",
		}),
		Batches: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "argus_pipeline_batches_total", Help: "Successfully committed batches.",
		}),
		BatchEvents: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "argus_pipeline_batch_events", Help: "Events per committed batch.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 14),
		}),
	}
	if reg != nil {
		reg.MustRegister(m.Events, m.ParseSeconds, m.ParsePanics, m.Duplicates, m.Conflicts, m.Invalid, m.Batches, m.BatchEvents)
	}
	return m
}

func (m *Metrics) parsed(tenant, parser, status string, d time.Duration, panicked bool) {
	if m == nil {
		return
	}
	m.Events.WithLabelValues(tenant, parser, status).Inc()
	m.ParseSeconds.WithLabelValues(parser).Observe(d.Seconds())
	if panicked {
		m.ParsePanics.WithLabelValues(parser).Inc()
	}
}

func (m *Metrics) duplicate(tenant string) {
	if m != nil {
		m.Duplicates.WithLabelValues(tenant).Inc()
	}
}

func (m *Metrics) sinkConflict(tenant string) {
	if m != nil {
		m.Conflicts.WithLabelValues(tenant).Inc()
	}
}

func (m *Metrics) invalid() {
	if m != nil {
		m.Invalid.Inc()
	}
}

func (m *Metrics) batch(r BatchResult) {
	if m != nil {
		m.Batches.Inc()
		m.BatchEvents.Observe(float64(r.Events))
	}
}
