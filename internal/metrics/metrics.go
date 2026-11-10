package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics contains API and scan-worker Prometheus collectors.
type Metrics struct {
	registry        *prometheus.Registry
	httpRequests    *prometheus.CounterVec
	httpDuration    *prometheus.HistogramVec
	httpInFlight    *prometheus.GaugeVec
	scanJobOutcomes *prometheus.CounterVec
	nmapDuration    prometheus.Histogram
}

// New creates an isolated registry so application metrics do not depend on global registration.
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP application requests.",
		}, []string{"method", "route", "status_code"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP application request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route", "status_code"}),
		httpInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "Current HTTP application requests being served.",
		}, []string{"method", "route"}),
		scanJobOutcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scan_jobs_total",
			Help: "Scan jobs that reached a persisted terminal outcome.",
		}, []string{"outcome"}),
		nmapDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "nmap_execution_duration_seconds",
			Help:    "Time spent executing the Nmap process, excluding parsing and persistence.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120},
		}),
	}
	m.registry.MustRegister(m.httpRequests, m.httpDuration, m.httpInFlight, m.scanJobOutcomes, m.nmapDuration)
	return m
}

// RecordNmapExecution observes only the duration of the Nmap process invocation.
func (m *Metrics) RecordNmapExecution(duration time.Duration) {
	m.nmapDuration.Observe(duration.Seconds())
}

// RecordScanJobOutcomes adds persisted terminal outcomes. Retries and requeued jobs are not passed here.
func (m *Metrics) RecordScanJobOutcomes(outcome string, count int64) {
	if count <= 0 {
		return
	}
	switch outcome {
	case "completed", "failed", "timed_out":
		m.scanJobOutcomes.WithLabelValues(outcome).Add(float64(count))
	}
}

// Handler returns the Prometheus exposition handler for this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// HTTPHandler exposes /metrics separately and instruments the existing application handler.
// Metrics scrapes themselves are excluded from application request metrics.
func (m *Metrics) HTTPHandler(application http.Handler) http.Handler {
	metricsHandler := m.Handler()
	instrumentedApplication := m.instrument(application)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			metricsHandler.ServeHTTP(w, r)
			return
		}
		instrumentedApplication.ServeHTTP(w, r)
	})
}

func (m *Metrics) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := normalizeMethod(r.Method)
		route := normalizeRoute(r.URL.Path)
		m.httpInFlight.WithLabelValues(method, route).Inc()
		defer m.httpInFlight.WithLabelValues(method, route).Dec()

		started := time.Now()
		writer := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		if writer.status == 0 {
			writer.status = http.StatusOK
		}

		labels := []string{method, route, strconv.Itoa(writer.status)}
		m.httpRequests.WithLabelValues(labels...).Inc()
		m.httpDuration.WithLabelValues(labels...).Observe(time.Since(started).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func normalizeRoute(path string) string {
	switch path {
	case "/api/v1/scans":
		return path
	case "/api/v1/targets/":
		return "unmatched"
	}
	const prefix = "/api/v1/targets/"
	if strings.HasPrefix(path, prefix) {
		parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
		if len(parts) == 2 && parts[0] != "" {
			switch parts[1] {
			case "scans":
				return "/api/v1/targets/{target}/scans"
			case "changes":
				return "/api/v1/targets/{target}/changes"
			}
		}
	}
	return "unmatched"
}
