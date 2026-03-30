package mtls

/*
#include <mtls/mtls_rate_limit.h>
*/
import "C"

import (
	"runtime"
	"time"
)

// RateLimitStatus represents the result of a rate limit check.
type RateLimitStatus int

const (
	RateLimitOK              RateLimitStatus = C.MTLS_RATE_LIMIT_OK
	RateLimitExceeded        RateLimitStatus = C.MTLS_RATE_LIMIT_EXCEEDED
	RateLimitGlobalExceeded  RateLimitStatus = C.MTLS_RATE_LIMIT_GLOBAL_EXCEEDED
	RateLimitClientExceeded  RateLimitStatus = C.MTLS_RATE_LIMIT_CLIENT_EXCEEDED
)

// RateLimiterConfig holds configuration for a standalone rate limiter.
type RateLimiterConfig struct {
	MaxConnPerSec     uint64        // Global rate limit (0 = unlimited)
	PerClientRate     uint64        // Per-client rate limit (0 = unlimited)
	BurstSize         uint64        // Global burst allowance (default: 10)
	PerClientBurst    uint64        // Per-client burst (default: 5)
	LimitByIP         bool          // Use IP address as client key
	LimitByCN         bool          // Use certificate CN as client key
	CleanupInterval   time.Duration // Interval for cleaning expired buckets
	ClientExpiry      time.Duration // Time before idle client bucket expires
}

// RateLimiterStats holds current rate limiter statistics.
type RateLimiterStats struct {
	TotalRequests    uint64
	AllowedRequests  uint64
	RejectedRequests uint64
	GlobalRejections uint64
	ClientRejections uint64
	ActiveClients    int
	TokensAvailable  uint64
}

// RateLimiter is a standalone token-bucket rate limiter.
//
// The mTLS config-level rate limiting is applied automatically during connects;
// use RateLimiter for custom application-level rate limiting independent of
// individual mTLS contexts.
//
// RateLimiter is safe for concurrent use.
type RateLimiter struct {
	r *C.mtls_rate_limiter
}

// NewRateLimiter creates a standalone rate limiter with the given configuration.
func NewRateLimiter(cfg RateLimiterConfig) (*RateLimiter, error) {
	var cCfg C.mtls_rate_limit_config
	C.mtls_rate_limit_config_init(&cCfg)

	cCfg.enabled = C.bool(true)
	cCfg.max_conn_per_sec = C.uint64_t(cfg.MaxConnPerSec)
	cCfg.per_client_rate = C.uint64_t(cfg.PerClientRate)
	if cfg.BurstSize > 0 {
		cCfg.burst_size = C.uint64_t(cfg.BurstSize)
	}
	if cfg.PerClientBurst > 0 {
		cCfg.per_client_burst = C.uint64_t(cfg.PerClientBurst)
	}
	cCfg.limit_by_ip = C.bool(cfg.LimitByIP)
	cCfg.limit_by_cn = C.bool(cfg.LimitByCN)
	if cfg.CleanupInterval > 0 {
		cCfg.cleanup_interval_sec = C.uint32_t(cfg.CleanupInterval.Seconds())
	}
	if cfg.ClientExpiry > 0 {
		cCfg.client_expiry_sec = C.uint32_t(cfg.ClientExpiry.Seconds())
	}

	var cErr C.mtls_err
	initErr(&cErr)

	var r *C.mtls_rate_limiter
	if C.mtls_rate_limiter_create(&r, &cCfg, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	rl := &RateLimiter{r: r}
	runtime.SetFinalizer(rl, (*RateLimiter).destroy)
	return rl, nil
}

// Acquire attempts to consume a token. Returns nil if allowed, ErrRateLimited otherwise.
//
// clientID identifies the client (IP or CN, depending on configuration).
// Pass an empty string to check only the global bucket.
func (rl *RateLimiter) Acquire(clientID string) error {
	if rl.r == nil {
		return &Error{Code: ErrInternal, Message: "rate limiter is closed"}
	}

	var cClientID *C.char
	if clientID != "" {
		cClientID = C.CString(clientID)
		defer freeString(cClientID)
	}

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_rate_limiter_acquire(rl.r, cClientID, &cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// Check returns the current rate limit status without consuming a token.
func (rl *RateLimiter) Check(clientID string) RateLimitStatus {
	if rl.r == nil {
		return RateLimitExceeded
	}

	var cClientID *C.char
	if clientID != "" {
		cClientID = C.CString(clientID)
		defer freeString(cClientID)
	}

	return RateLimitStatus(C.mtls_rate_limiter_check(rl.r, cClientID))
}

// TokenStatus returns the current token count and time until the next token
// is available for the given client (empty string = global bucket).
func (rl *RateLimiter) TokenStatus(clientID string) (tokens uint64, nextRefill time.Duration, err error) {
	if rl.r == nil {
		return 0, 0, &Error{Code: ErrInternal, Message: "rate limiter is closed"}
	}

	var cClientID *C.char
	if clientID != "" {
		cClientID = C.CString(clientID)
		defer freeString(cClientID)
	}

	var cTokens, cNextRefillMs C.uint64_t
	if C.mtls_rate_limiter_status(rl.r, cClientID, &cTokens, &cNextRefillMs) != 0 {
		return 0, 0, &Error{Code: ErrInternal, Message: "client not found"}
	}
	return uint64(cTokens), time.Duration(cNextRefillMs) * time.Millisecond, nil
}

// Stats returns current rate limiter statistics.
func (rl *RateLimiter) Stats() (RateLimiterStats, error) {
	if rl.r == nil {
		return RateLimiterStats{}, &Error{Code: ErrInternal, Message: "rate limiter is closed"}
	}

	var cStats C.mtls_rate_limit_stats
	if C.mtls_rate_limiter_stats(rl.r, &cStats) != 0 {
		return RateLimiterStats{}, &Error{Code: ErrInternal, Message: "failed to retrieve rate limiter stats"}
	}

	return RateLimiterStats{
		TotalRequests:    uint64(cStats.total_requests),
		AllowedRequests:  uint64(cStats.allowed_requests),
		RejectedRequests: uint64(cStats.rejected_requests),
		GlobalRejections: uint64(cStats.global_rejections),
		ClientRejections: uint64(cStats.client_rejections),
		ActiveClients:    int(cStats.active_clients),
		TokensAvailable:  uint64(cStats.tokens_available),
	}, nil
}

// ResetStats clears accumulated statistics without affecting token buckets.
func (rl *RateLimiter) ResetStats() {
	if rl.r != nil {
		C.mtls_rate_limiter_reset_stats(rl.r)
	}
}

// Reset clears all token buckets.
func (rl *RateLimiter) Reset() {
	if rl.r != nil {
		C.mtls_rate_limiter_reset(rl.r)
	}
}

// RemoveClient removes a specific client's rate limit bucket.
func (rl *RateLimiter) RemoveClient(clientID string) {
	if rl.r == nil || clientID == "" {
		return
	}
	cClientID := C.CString(clientID)
	defer freeString(cClientID)
	C.mtls_rate_limiter_remove_client(rl.r, cClientID)
}

// Close frees the rate limiter resources.
func (rl *RateLimiter) Close() {
	rl.destroy()
}

func (rl *RateLimiter) destroy() {
	if rl != nil && rl.r != nil {
		C.mtls_rate_limiter_free(rl.r)
		rl.r = nil
		runtime.SetFinalizer(rl, nil)
	}
}
