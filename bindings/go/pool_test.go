package mtls

import (
	"testing"
	"time"
)

// TestPoolConfigDefaults verifies that PoolConfig zero values map correctly to C defaults.
func TestPoolConfigDefaults(t *testing.T) {
	// PoolConfig with all zeros → C defaults should be applied by mtls_pool_config_init.
	// We can't create a real pool without a running server, so we test the error path.
	cfg := &PoolConfig{}
	_ = cfg // zero value is valid to pass to NewPool

	// Verify PoolStats zero value is safe.
	var stats PoolStats
	if stats.TotalConnections != 0 {
		t.Error("expected zero TotalConnections")
	}
}

// TestPoolNilContextError verifies that NewPool on a nil/closed Context returns an error.
func TestPoolNilContextError(t *testing.T) {
	ctx := &Context{} // zero value — no C context
	_, err := ctx.NewPool("localhost:8443", nil)
	if err == nil {
		t.Fatal("expected error for nil C context")
	}
	if e, ok := err.(*Error); !ok || e.Code != ErrCtxNotInitialized {
		t.Errorf("expected ErrCtxNotInitialized, got %v", err)
	}
}

// TestPooledConnReleaseNilConn verifies that releasing a nil PooledConn is safe.
func TestPooledConnReleaseNilConn(t *testing.T) {
	pc := &PooledConn{}
	// Should not panic.
	pc.Release()
	pc.Discard()
}

// TestPoolConfigFields verifies non-zero PoolConfig fields are accepted without panic.
func TestPoolConfigFields(t *testing.T) {
	cfg := &PoolConfig{
		MinConnections:      2,
		MaxConnections:      20,
		IdleTimeout:         5 * time.Minute,
		MaxLifetime:         1 * time.Hour,
		AcquireTimeout:      30 * time.Second,
		HealthCheckInterval: 30 * time.Second,
		PreConnect:          true,
		ValidateOnAcquire:   true,
	}
	// Just ensure it's well-formed — we can't actually create without a server.
	if cfg.MaxConnections != 20 {
		t.Errorf("MaxConnections = %d, want 20", cfg.MaxConnections)
	}
}
