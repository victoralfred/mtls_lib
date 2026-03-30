package mtls

/*
#include <mtls/mtls_pool.h>
*/
import "C"

import (
	"runtime"
	"time"
	"unsafe"
)

// PoolConfig holds configuration for a connection pool.
type PoolConfig struct {
	MinConnections         int           // Minimum connections to maintain (default: 1)
	MaxConnections         int           // Maximum connections allowed (default: 10)
	IdleTimeout            time.Duration // Close idle connections after this time (default: 5m)
	MaxLifetime            time.Duration // Close connections after this lifetime (default: 1h)
	AcquireTimeout         time.Duration // Timeout for acquiring a connection (default: 30s)
	HealthCheckInterval    time.Duration // Interval between health checks (default: 30s)
	PreConnect             bool          // Establish min connections on pool creation
	ValidateOnAcquire      bool          // Validate connection before returning (default: true)
	ValidateOnRelease      bool          // Validate connection on release
}

// PoolStats holds connection pool statistics.
type PoolStats struct {
	TotalConnections  int
	ActiveConnections int
	IdleConnections   int
	InUseConnections  int
	TotalAcquires     uint64
	TotalReleases     uint64
	AcquireTimeouts   uint64
	FailedConnects    uint64
	HealthChecks      uint64
	UnhealthyClosed   uint64
	IdleClosed        uint64
	LifetimeClosed    uint64
	WaitTimeTotalMs   uint64
	WaitTimeMaxMs     uint64
}

// Pool manages a pool of reusable mTLS connections to a single server address.
//
// Pool is safe for concurrent use from multiple goroutines.
type Pool struct {
	p    *C.mtls_pool
	addr string
}

// NewPool creates a connection pool to the given server address.
//
// The addr must be in "host:port" format. If cfg is nil, defaults are used.
func (c *Context) NewPool(addr string, cfg *PoolConfig) (*Pool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "context is closed"}
	}

	var cConfig C.mtls_pool_config
	C.mtls_pool_config_init(&cConfig)

	if cfg != nil {
		if cfg.MinConnections > 0 {
			cConfig.min_connections = C.size_t(cfg.MinConnections)
		}
		if cfg.MaxConnections > 0 {
			cConfig.max_connections = C.size_t(cfg.MaxConnections)
		}
		if cfg.IdleTimeout > 0 {
			cConfig.idle_timeout_ms = C.uint32_t(cfg.IdleTimeout.Milliseconds())
		}
		if cfg.MaxLifetime > 0 {
			cConfig.max_lifetime_ms = C.uint32_t(cfg.MaxLifetime.Milliseconds())
		}
		if cfg.AcquireTimeout > 0 {
			cConfig.acquire_timeout_ms = C.uint32_t(cfg.AcquireTimeout.Milliseconds())
		}
		if cfg.HealthCheckInterval > 0 {
			cConfig.health_check_interval_ms = C.uint32_t(cfg.HealthCheckInterval.Milliseconds())
		}
		cConfig.pre_connect = C.bool(cfg.PreConnect)
		cConfig.validate_on_acquire = C.bool(cfg.ValidateOnAcquire)
		cConfig.validate_on_release = C.bool(cfg.ValidateOnRelease)
	}

	cAddr := C.CString(addr)
	defer freeString(cAddr)

	var cErr C.mtls_err
	initErr(&cErr)

	var cPool *C.mtls_pool
	if C.mtls_pool_create(&cPool, c.ctx, cAddr, &cConfig, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	p := &Pool{p: cPool, addr: addr}
	runtime.SetFinalizer(p, (*Pool).destroy)
	return p, nil
}

// Acquire acquires a connection from the pool.
//
// If timeout is 0 and no connections are available, returns immediately with
// ErrPoolExhausted. Use a positive timeout to wait for a connection.
func (p *Pool) Acquire(timeout time.Duration) (*PooledConn, error) {
	if p.p == nil {
		return nil, &Error{Code: ErrPoolClosed, Message: "pool is closed"}
	}

	ms := C.uint32_t(0)
	if timeout > 0 {
		ms = C.uint32_t(timeout.Milliseconds())
	}

	var cErr C.mtls_err
	initErr(&cErr)

	cConn := C.mtls_pool_acquire(p.p, ms, &cErr)
	if cConn == nil {
		return nil, convertError(&cErr)
	}

	return &PooledConn{conn: cConn, pool: p}, nil
}

// Release returns a connection to the pool.
//
// Prefer using PooledConn.Release() or PooledConn.Discard() instead.
func (p *Pool) Release(pc *PooledConn) {
	if p.p == nil || pc == nil || pc.conn == nil {
		return
	}
	C.mtls_pool_release(p.p, pc.conn)
	pc.conn = nil
}

// Stats returns current pool statistics.
func (p *Pool) Stats() (PoolStats, error) {
	if p.p == nil {
		return PoolStats{}, &Error{Code: ErrPoolClosed, Message: "pool is closed"}
	}

	var cStats C.mtls_pool_stats
	if C.mtls_pool_get_stats(p.p, &cStats) != 0 {
		return PoolStats{}, &Error{Code: ErrInternal, Message: "failed to get pool stats"}
	}

	return PoolStats{
		TotalConnections:  int(cStats.total_connections),
		ActiveConnections: int(cStats.active_connections),
		IdleConnections:   int(cStats.idle_connections),
		InUseConnections:  int(cStats.in_use_connections),
		TotalAcquires:     uint64(cStats.total_acquires),
		TotalReleases:     uint64(cStats.total_releases),
		AcquireTimeouts:   uint64(cStats.acquire_timeouts),
		FailedConnects:    uint64(cStats.failed_connects),
		HealthChecks:      uint64(cStats.health_checks),
		UnhealthyClosed:   uint64(cStats.unhealthy_closed),
		IdleClosed:        uint64(cStats.idle_closed),
		LifetimeClosed:    uint64(cStats.lifetime_closed),
		WaitTimeTotalMs:   uint64(cStats.wait_time_total_ms),
		WaitTimeMaxMs:     uint64(cStats.wait_time_max_ms),
	}, nil
}

// Warmup ensures at least the minimum number of connections are established.
func (p *Pool) Warmup() error {
	if p.p == nil {
		return &Error{Code: ErrPoolClosed, Message: "pool is closed"}
	}
	var cErr C.mtls_err
	initErr(&cErr)
	if C.mtls_pool_warmup(p.p, &cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// Close closes the pool gracefully, waiting up to timeout for in-use connections.
func (p *Pool) Close(timeout time.Duration) error {
	if p.p == nil {
		return nil
	}
	ms := C.uint32_t(timeout.Milliseconds())
	C.mtls_pool_close(p.p, ms)
	return nil
}

// Destroy forcefully destroys the pool and all its connections.
// For graceful shutdown prefer Close() then Destroy().
func (p *Pool) Destroy() {
	p.destroy()
}

func (p *Pool) destroy() {
	if p != nil && p.p != nil {
		C.mtls_pool_destroy(p.p)
		p.p = nil
		runtime.SetFinalizer(p, nil)
	}
}

// PooledConn is a connection acquired from a Pool.
//
// The caller must call Release() or Discard() when done, otherwise the
// connection leaks from the pool's perspective.
type PooledConn struct {
	conn *C.mtls_conn
	pool *Pool
	ctx  *Context
}

// Conn returns a temporary view of the pooled connection for I/O.
// Do NOT call Close() on the returned Conn — use PooledConn.Release() instead.
func (pc *PooledConn) Conn() *Conn {
	if pc.conn == nil {
		return nil
	}
	// Wrap without setting a finalizer — the pool owns this conn.
	return &Conn{conn: pc.conn, ctx: pc.ctx}
}

// Read reads from the connection.
func (pc *PooledConn) Read(p []byte) (int, error) {
	c := pc.Conn()
	if c == nil {
		return 0, &Error{Code: ErrConnectionClosed, Message: "pooled connection is released"}
	}
	return c.Read(p)
}

// Write writes to the connection.
func (pc *PooledConn) Write(p []byte) (int, error) {
	c := pc.Conn()
	if c == nil {
		return 0, &Error{Code: ErrConnectionClosed, Message: "pooled connection is released"}
	}
	return c.Write(p)
}

// Release returns the connection to the pool for reuse.
// After Release, the PooledConn must not be used.
func (pc *PooledConn) Release() {
	if pc.conn == nil {
		return
	}
	C.mtls_pool_release(pc.pool.p, pc.conn)
	pc.conn = nil
}

// Discard closes the connection without returning it to the pool.
// Use when the connection is known to be unhealthy.
func (pc *PooledConn) Discard() {
	if pc.conn == nil {
		return
	}
	C.mtls_pool_discard(pc.pool.p, pc.conn)
	pc.conn = nil
}

// ensure unsafe import is used
var _ = unsafe.Pointer(nil)
