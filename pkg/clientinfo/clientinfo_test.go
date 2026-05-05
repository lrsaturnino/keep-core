package clientinfo

import (
	"context"
	"testing"
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
