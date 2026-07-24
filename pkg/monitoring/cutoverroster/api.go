package cutoverroster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// readinessPath is the single authoritative readiness endpoint.
const readinessPath = "/api/v1/cutover-readiness"

// snapshotSource is the minimal collector view the API needs.
type snapshotSource interface {
	Snapshot() FleetSnapshot
}

// NewHandler builds the HTTP handler exposing the deterministic readiness
// endpoint and, when a Prometheus registry is supplied, a /metrics endpoint.
// The TrustedReportTarget inventory field is never serialized (it is
// `json:"-"`), so it cannot leak through the API.
func NewHandler(source snapshotSource, metrics *PrometheusMetrics) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(readinessPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		snapshot := source.Snapshot()

		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(snapshot); err != nil {
			http.Error(w, "cannot encode snapshot", http.StatusInternalServerError)
			return
		}
	})

	if metrics != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(
			metrics.Registry(),
			promhttp.HandlerOpts{},
		))
	}

	return mux
}

// Server serves the readiness API. It MUST be bound only to a monitoring
// network address; the readiness data is authoritative but not public.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
}

// NewServer binds a TCP listener on addr and prepares an HTTP server for the
// readiness API. Bind addr to the monitoring interface only.
func NewServer(
	addr string,
	source snapshotSource,
	metrics *PrometheusMetrics,
) (*Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot bind cutover-roster API on [%s]: %w", addr, err)
	}

	return &Server{
		httpServer: &http.Server{
			Handler:           NewHandler(source, metrics),
			ReadHeaderTimeout: 10 * time.Second,
		},
		listener: listener,
	}, nil
}

// Addr returns the actual bound address (useful when addr requested port 0).
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Serve blocks serving requests until the server is closed.
func (s *Server) Serve() error {
	err := s.httpServer.Serve(s.listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Close gracefully shuts the server down.
func (s *Server) Close(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
