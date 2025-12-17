package mtls

/*
#include <mtls/mtls.h>
*/
import "C"

import (
	"runtime"
	"sync"
)

// Context holds the TLS configuration and can be shared across multiple
// connections. It is safe for concurrent use after creation.
//
// The Context must be closed when no longer needed to free resources.
type Context struct {
	ctx *C.mtls_ctx

	// mu protects ctx during close operations
	mu sync.RWMutex

	// observerID tracks registered event callback for cleanup
	observerID uintptr
}

// NewContext creates a new mTLS context from the given configuration.
//
// The returned Context must be closed when no longer needed.
func NewContext(config *Config) (*Context, error) {
	if config == nil {
		return nil, &Error{
			Code:    ErrInvalidArgument,
			Message: "config is nil",
		}
	}

	// Convert Go config to C config
	cConfig, allocations := config.toC()
	defer freeConfigC(allocations)

	var cErr C.mtls_err
	initErr(&cErr)

	cCtx := C.mtls_ctx_create(cConfig, &cErr)
	if cCtx == nil {
		return nil, convertError(&cErr)
	}

	ctx := &Context{ctx: cCtx}
	runtime.SetFinalizer(ctx, (*Context).finalizer)

	return ctx, nil
}

// Close releases resources associated with the context.
//
// After Close is called, the context cannot be used to create new connections.
// Any existing connections created from this context remain valid until they
// are individually closed.
func (c *Context) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil
	}

	// Unregister observer callback if any
	if c.observerID != 0 {
		unregisterCallback(c.observerID)
		c.observerID = 0
	}

	C.mtls_ctx_free(c.ctx)
	c.ctx = nil

	return nil
}

// finalizer is called by the GC when Context becomes unreachable.
func (c *Context) finalizer() {
	c.Close()
}

// Connect establishes a connection to a remote server.
//
// The addr parameter should be in "host:port" format (e.g., "example.com:443").
// This is a blocking call that performs TCP connection and TLS handshake.
//
// Note: The context read lock is held for the duration of the connect call
// to prevent use-after-free if Close() is called concurrently.
func (c *Context) Connect(addr string) (*Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return nil, &Error{
			Code:    ErrCtxNotInitialized,
			Message: "context is closed",
		}
	}

	cAddr := C.CString(addr)
	defer freeString(cAddr)

	var cErr C.mtls_err
	initErr(&cErr)

	cConn := C.mtls_connect(c.ctx, cAddr, &cErr)
	if cConn == nil {
		return nil, convertError(&cErr)
	}

	conn := &Conn{conn: cConn, ctx: c}
	runtime.SetFinalizer(conn, (*Conn).finalizer)

	return conn, nil
}

// Listen creates a listener for incoming connections on the specified address.
//
// The addr parameter should be in "host:port" format (e.g., "0.0.0.0:8443").
//
// Note: The context read lock is held for the duration of the listen call
// to prevent use-after-free if Close() is called concurrently.
func (c *Context) Listen(addr string) (*Listener, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return nil, &Error{
			Code:    ErrCtxNotInitialized,
			Message: "context is closed",
		}
	}

	cAddr := C.CString(addr)
	defer freeString(cAddr)

	var cErr C.mtls_err
	initErr(&cErr)

	cListener := C.mtls_listen(c.ctx, cAddr, &cErr)
	if cListener == nil {
		return nil, convertError(&cErr)
	}

	listener := &Listener{listener: cListener, ctx: c}
	runtime.SetFinalizer(listener, (*Listener).finalizer)

	return listener, nil
}

// ReloadCerts reloads certificates from the paths specified in the original
// configuration. This is useful for certificate rotation without restart.
//
// Note: This should not be called concurrently with itself.
// The context read lock is held for the duration of the reload call.
func (c *Context) ReloadCerts() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return &Error{
			Code:    ErrCtxNotInitialized,
			Message: "context is closed",
		}
	}

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_ctx_reload_certs(c.ctx, &cErr) != 0 {
		return convertError(&cErr)
	}

	return nil
}

// SetKillSwitch enables or disables the kill-switch.
//
// When enabled, all new connections will fail immediately with
// ErrKillSwitchEnabled. Existing connections are not affected.
//
// This is safe for concurrent use.
func (c *Context) SetKillSwitch(enabled bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx != nil {
		C.mtls_ctx_set_kill_switch(c.ctx, C.bool(enabled))
	}
}

// IsKillSwitchEnabled returns true if the kill-switch is enabled.
//
// This is safe for concurrent use.
func (c *Context) IsKillSwitchEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return false
	}

	return bool(C.mtls_ctx_is_kill_switch_enabled(c.ctx))
}
