package cutoverroster

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCIDRAllowlist_EnforcesMonitoringBoundary proves the monitoring-network
// trust boundary: with an allowlist configured, a request from an untrusted
// source IP is denied with 403, while loopback and an allowed-CIDR client are
// served. A nil allowlist serves everyone (no application-level boundary).
func TestCIDRAllowlist_EnforcesMonitoringBoundary(t *testing.T) {
	allowlist, err := ParseCIDRAllowlist("10.1.0.0/16")
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	if allowlist == nil {
		t.Fatal("expected a non-nil allowlist")
	}

	// The wrapped handler just writes 200 so we can observe allow vs deny.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := withAllowlist(allowlist, inner)

	for _, tt := range []struct {
		name       string
		remoteAddr string
		wantStatus int
	}{
		{"untrusted public IP denied", "203.0.113.7:5555", http.StatusForbidden},
		{"outside allowed CIDR denied", "10.2.0.4:5555", http.StatusForbidden},
		{"allowed CIDR served", "10.1.2.3:5555", http.StatusOK},
		{"loopback always served", "127.0.0.1:5555", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, readinessPath, nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("remote %s: got %d, want %d", tt.remoteAddr, rec.Code, tt.wantStatus)
			}
		})
	}

	// A nil allowlist imposes no application-level boundary.
	served := withAllowlist(nil, inner)
	req := httptest.NewRequest(http.MethodGet, readinessPath, nil)
	req.RemoteAddr = "203.0.113.7:5555"
	rec := httptest.NewRecorder()
	served.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("nil allowlist must serve everyone, got %d", rec.Code)
	}
}

// TestParseCIDRAllowlist_Validation proves an empty allowlist parses to nil and
// an invalid CIDR is rejected.
func TestParseCIDRAllowlist_Validation(t *testing.T) {
	if a, err := ParseCIDRAllowlist("  "); err != nil || a != nil {
		t.Errorf("empty allowlist must parse to (nil, nil), got (%v, %v)", a, err)
	}
	if _, err := ParseCIDRAllowlist("not-a-cidr"); err == nil {
		t.Error("expected an error for an invalid CIDR")
	}
}

// TestNewServer_RequiresAllowlistForNonLoopbackBind proves a non-loopback bind
// without an allowlist is refused at startup (fail closed), while a loopback bind
// or a non-loopback bind with an allowlist is accepted.
func TestNewServer_RequiresAllowlistForNonLoopbackBind(t *testing.T) {
	allowlist, err := ParseCIDRAllowlist("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}

	// Non-loopback bind, no allowlist: refused.
	if s, err := NewServer("0.0.0.0:0", nil, nil, nil); err == nil {
		t.Error("a non-loopback bind without an allowlist must be refused")
		if s != nil {
			_ = s.Close(context.Background())
		}
	}

	// Loopback bind, no allowlist: accepted (loopback is the mitigation).
	loopback, err := NewServer("127.0.0.1:0", nil, nil, nil)
	if err != nil {
		t.Errorf("a loopback bind without an allowlist must be accepted: %v", err)
	} else {
		_ = loopback.Close(context.Background())
	}

	// Non-loopback bind WITH an allowlist: accepted.
	guarded, err := NewServer("0.0.0.0:0", nil, nil, allowlist)
	if err != nil {
		t.Errorf("a non-loopback bind with an allowlist must be accepted: %v", err)
	} else {
		_ = guarded.Close(context.Background())
	}
}
