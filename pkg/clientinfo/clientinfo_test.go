package clientinfo

import (
	"context"
	"testing"

	keepclientinfo "github.com/keep-network/keep-common/pkg/clientinfo"
)

func TestInitialize_PortZeroDisablesServer(t *testing.T) {
	registry, isConfigured := Initialize(context.Background(), 0)

	if isConfigured {
		t.Fatal("expected port 0 to disable the client info server")
	}

	if registry != nil {
		t.Fatal("expected no registry when client info server is disabled")
	}
}

func TestInitialize_NonZeroPortEnablesServer(t *testing.T) {
	registry, isConfigured := Initialize(context.Background(), 9601)

	if !isConfigured {
		t.Fatal("expected non-zero port to enable the client info server")
	}

	if registry == nil {
		t.Fatal("expected a registry when client info server is enabled")
	}
}

// TestRegisterMetricClientInfo_RegistersArtifactIdentity proves the identity
// metric is registered under the exact exported name: a subsequent
// registration attempt for client_info must be refused as a duplicate. The
// version, revision, and protocol-epoch labels travel in that single
// registration.
func TestRegisterMetricClientInfo_RegistersArtifactIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &Registry{keepclientinfo.NewRegistry(), ctx}

	registry.RegisterMetricClientInfo(
		"v2.2.0",
		"33808cba",
		"security_v2_cutover",
	)

	if _, err := registry.NewMetricInfo(
		ClientInfoMetricName,
		[]keepclientinfo.Label{keepclientinfo.NewLabel("version", "other")},
	); err == nil {
		t.Fatal(
			"expected the client_info metric to already be registered with " +
				"the artifact identity labels",
		)
	}
}
