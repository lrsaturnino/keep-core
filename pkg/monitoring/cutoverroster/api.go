package cutoverroster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// readinessPath is the single authoritative readiness endpoint.
const readinessPath = "/api/v1/cutover-readiness"

// healthzPath is an unauthenticated liveness/readiness endpoint for the process
// itself. It is deliberately served OUTSIDE the CIDR allowlist because Kubernetes
// kubelet probes originate from the node IP, which is not on the monitoring pod
// network and is not loopback — an allowlisted probe would return 403 and leave
// the pod permanently unready. It exposes no fleet data (only "ok"), so serving
// it openly is safe; the authoritative readiness data and /metrics stay behind
// the allowlist.
const healthzPath = "/healthz"

// CIDRAllowlist is the monitoring-network trust boundary for the readiness API.
// When configured, only clients whose source IP is loopback or within one of the
// allowed networks are served; every other client is denied. It is a defensive
// application-level control that complements (does not replace) network-level
// firewalling.
type CIDRAllowlist struct {
	nets []*net.IPNet
}

// ParseCIDRAllowlist parses a comma-separated list of CIDR networks. An empty
// string returns a nil allowlist, meaning "no application-level boundary
// configured" (the caller's loopback bind default is then the only mitigation).
func ParseCIDRAllowlist(csv string) (*CIDRAllowlist, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
		}
		nets = append(nets, ipNet)
	}
	if len(nets) == 0 {
		return nil, nil
	}
	return &CIDRAllowlist{nets: nets}, nil
}

// Allowed reports whether a request from remoteAddr (host or host:port) is within
// the trust boundary. Loopback is always allowed so a local operator/health check
// works; every other source must fall within an allowed network.
func (a *CIDRAllowlist) Allowed(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// bindIsLoopbackOnly reports whether addr binds only the loopback interface. An
// empty host, "0.0.0.0", "::", or a hostname it cannot classify are treated as
// non-loopback (routable) so the safe default is to demand an allowlist.
func bindIsLoopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		// No host = all interfaces.
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname we cannot resolve to an IP here; do not assume it is loopback.
		return false
	}
	return ip.IsLoopback()
}

// healthzHandler serves the unauthenticated liveness/readiness endpoint. It
// always returns 200 with a tiny body once the HTTP server is accepting
// connections, which is exactly what a kubelet probe needs to mark the pod ready
// so Prometheus and Grafana can reach it. It intentionally reflects only that the
// process is serving, not fleet readiness, and exposes no fleet data.
func healthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
}

// withAllowlist wraps next so a request from outside the monitoring trust
// boundary is denied with 403 before reaching the readiness data. A nil
// allowlist means no application-level boundary is configured and next is served
// unchanged (the server's loopback bind default is then the mitigation).
func withAllowlist(allowlist *CIDRAllowlist, next http.Handler) http.Handler {
	if allowlist == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowlist.Allowed(r.RemoteAddr) {
			http.Error(w, "forbidden: not on the monitoring network", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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
// readiness API. Bind addr to the monitoring interface only. When allowlist is
// non-nil, it enforces the monitoring-network trust boundary: only loopback and
// allowed-CIDR clients are served, everything else is denied with 403.
//
// A non-loopback bind with no allowlist is refused: exposing the authoritative
// readiness data on a routable interface without an application-level trust
// boundary is a misconfiguration, so it fails closed at startup rather than
// silently serving every client.
func NewServer(
	addr string,
	source snapshotSource,
	metrics *PrometheusMetrics,
	allowlist *CIDRAllowlist,
) (*Server, error) {
	if allowlist == nil && !bindIsLoopbackOnly(addr) {
		return nil, fmt.Errorf(
			"refusing to bind the readiness API to non-loopback address [%s] without "+
				"an allowlist; set --allowedCIDRs to define the monitoring trust boundary "+
				"or bind to loopback",
			addr,
		)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot bind cutover-roster API on [%s]: %w", addr, err)
	}

	return &Server{
		httpServer: &http.Server{
			Handler:           serverHandler(allowlist, source, metrics),
			ReadHeaderTimeout: 10 * time.Second,
		},
		listener: listener,
	}, nil
}

// serverHandler builds the top-level HTTP handler. /healthz is routed OUTSIDE the
// CIDR allowlist so kubelet liveness/readiness probes from the node IP succeed,
// while the authoritative readiness data and /metrics stay behind the allowlist.
func serverHandler(
	allowlist *CIDRAllowlist,
	source snapshotSource,
	metrics *PrometheusMetrics,
) http.Handler {
	top := http.NewServeMux()
	top.Handle(healthzPath, healthzHandler())
	top.Handle("/", withAllowlist(allowlist, NewHandler(source, metrics)))
	return top
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
