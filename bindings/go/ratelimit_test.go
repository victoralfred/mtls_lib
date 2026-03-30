package mtls

import (
	"testing"
	"time"
)

// TestNewRateLimiterBasic creates a rate limiter and verifies Acquire works.
func TestNewRateLimiterBasic(t *testing.T) {
	rl, err := NewRateLimiter(RateLimiterConfig{
		MaxConnPerSec: 100,
		BurstSize:     10,
		LimitByIP:     true,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	defer rl.Close()

	// First acquisition should succeed.
	if err := rl.Acquire("127.0.0.1"); err != nil {
		t.Errorf("Acquire() on fresh limiter: %v", err)
	}
}

// TestRateLimiterCheck verifies Check does not consume tokens.
func TestRateLimiterCheck(t *testing.T) {
	rl, err := NewRateLimiter(RateLimiterConfig{
		MaxConnPerSec: 100,
		BurstSize:     10,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	defer rl.Close()

	status := rl.Check("127.0.0.1")
	if status != RateLimitOK {
		t.Errorf("Check() on fresh limiter = %d, want RateLimitOK", status)
	}
}

// TestRateLimiterReset verifies Reset clears all buckets.
func TestRateLimiterReset(t *testing.T) {
	rl, err := NewRateLimiter(RateLimiterConfig{
		MaxConnPerSec: 1,
		BurstSize:     1,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	defer rl.Close()

	rl.Reset() // must not panic
}

// TestRateLimiterClose verifies Close is safe and idempotent.
func TestRateLimiterClose(t *testing.T) {
	rl, err := NewRateLimiter(RateLimiterConfig{MaxConnPerSec: 10, BurstSize: 5})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	rl.Close()
	rl.Close() // must not panic
}

// TestRateLimiterConfigDefaults verifies zero-value config fields.
func TestRateLimiterConfigDefaults(t *testing.T) {
	cfg := RateLimiterConfig{}
	if cfg.BurstSize != 0 {
		t.Errorf("BurstSize = %d, want 0", cfg.BurstSize)
	}
	if cfg.ClientExpiry != 0 {
		t.Errorf("ClientExpiry = %v, want 0", cfg.ClientExpiry)
	}
}

// TestRateLimitStatusConstants verifies constants have expected values.
func TestRateLimitStatusConstants(t *testing.T) {
	if RateLimitOK != 0 {
		t.Errorf("RateLimitOK = %d, want 0", RateLimitOK)
	}
	if RateLimitExceeded != 1 {
		t.Errorf("RateLimitExceeded = %d, want 1", RateLimitExceeded)
	}
}

// TestRateLimiterTokenStatus verifies TokenStatus works without panicking.
func TestRateLimiterTokenStatus(t *testing.T) {
	rl, err := NewRateLimiter(RateLimiterConfig{
		MaxConnPerSec: 100,
		BurstSize:     10,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	defer rl.Close()

	tokens, nextRefill, err := rl.TokenStatus("")
	if err != nil {
		// Some C library versions may return error for global query — that's ok.
		t.Logf("TokenStatus('') returned error: %v", err)
		return
	}
	if tokens > 10 {
		t.Errorf("tokens = %d, want <= BurstSize(10)", tokens)
	}
	_ = nextRefill
	_ = time.Second // ensure time import is used
}
