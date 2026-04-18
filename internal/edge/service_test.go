package edge

import (
	"testing"

	"github.com/caddyserver/certmagic"

	"github.com/define42/muxbridge-e2e/internal/config"
)

func TestBuildTLSConfigUsesConfiguredACMEEmail(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		DataDir:   t.TempDir(),
		AcmeEmail: "ops@example.test",
	}, Options{})

	_, manager, err := service.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}
	if manager == nil {
		t.Fatal("buildTLSConfig() returned nil cert manager")
	}
	if len(manager.Issuers) != 1 {
		t.Fatalf("manager.Issuers len = %d, want 1", len(manager.Issuers))
	}

	issuer, ok := manager.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatalf("manager.Issuers[0] type = %T, want *certmagic.ACMEIssuer", manager.Issuers[0])
	}
	if issuer.Email != "ops@example.test" {
		t.Fatalf("issuer.Email = %q, want %q", issuer.Email, "ops@example.test")
	}
}
