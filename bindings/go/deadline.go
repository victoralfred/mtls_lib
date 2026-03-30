package mtls

/*
#include <mtls/mtls_deadline.h>
*/
import "C"

import (
	"io"
	"runtime"
	"time"
	"unsafe"
)

// DeadlineCtx wraps an mtls_deadline_ctx to provide non-destructive timeout
// and cancellation support for mTLS operations.
//
// Unlike ReadContext/WriteContext which close the connection on cancellation,
// DeadlineCtx uses the C library's built-in deadline mechanism which times
// out individual operations without closing the connection.
//
// DeadlineCtx is safe for concurrent use (the C struct uses atomic cancellation).
type DeadlineCtx struct {
	d *C.mtls_deadline_ctx
}

// NewDeadlineCtx creates a deadline context that expires at t.
//
// Since the C library uses CLOCK_MONOTONIC internally, this is implemented
// by computing the remaining duration from now and calling
// NewDeadlineCtxWithTimeout. Returns an error if t is already in the past.
func NewDeadlineCtx(t time.Time) (*DeadlineCtx, error) {
	d := time.Until(t)
	if d <= 0 {
		// Already expired — use 0ms timeout so it is immediately expired.
		d = 0
	}
	return NewDeadlineCtxWithTimeout(d)
}

// NewDeadlineCtxWithTimeout creates a deadline context that expires after d.
func NewDeadlineCtxWithTimeout(d time.Duration) (*DeadlineCtx, error) {
	ms := C.uint32_t(d.Milliseconds())

	var cErr C.mtls_err
	initErr(&cErr)

	var dc *C.mtls_deadline_ctx
	if C.mtls_deadline_ctx_create_with_timeout(&dc, ms, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	result := &DeadlineCtx{d: dc}
	runtime.SetFinalizer(result, (*DeadlineCtx).destroy)
	return result, nil
}

// NewChildDeadlineCtx creates a child deadline context.
//
// The child inherits the parent's deadline unless timeout is shorter.
// Cancelling the parent also cancels the child.
func NewChildDeadlineCtx(parent *DeadlineCtx, timeout time.Duration) (*DeadlineCtx, error) {
	if parent == nil || parent.d == nil {
		return nil, &Error{Code: ErrInvalidArgument, Message: "parent DeadlineCtx is nil"}
	}

	ms := C.uint32_t(timeout.Milliseconds())

	var cErr C.mtls_err
	initErr(&cErr)

	var d *C.mtls_deadline_ctx
	if C.mtls_deadline_ctx_create_child(&d, parent.d, ms, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	dc := &DeadlineCtx{d: d}
	runtime.SetFinalizer(dc, (*DeadlineCtx).destroy)
	return dc, nil
}

// Cancel cancels the deadline context.
//
// After cancellation, all operations using this context return ErrCancelled.
// This is safe to call from any goroutine.
func (dc *DeadlineCtx) Cancel() {
	if dc != nil && dc.d != nil {
		C.mtls_deadline_ctx_cancel(dc.d)
	}
}

// IsCancelled returns true if the deadline has been cancelled.
func (dc *DeadlineCtx) IsCancelled() bool {
	if dc == nil || dc.d == nil {
		return true
	}
	return bool(C.mtls_deadline_ctx_is_cancelled(dc.d))
}

// IsExpired returns true if the deadline has expired or been cancelled.
func (dc *DeadlineCtx) IsExpired() bool {
	if dc == nil || dc.d == nil {
		return true
	}
	return bool(C.mtls_deadline_ctx_is_expired(dc.d))
}

// Remaining returns the time until the deadline expires.
// Returns 0 if expired, negative if cancelled.
func (dc *DeadlineCtx) Remaining() time.Duration {
	if dc == nil || dc.d == nil {
		return 0
	}
	ms := int64(C.mtls_deadline_ctx_remaining_ms(dc.d))
	if ms < 0 {
		return -1 // cancelled
	}
	return time.Duration(ms) * time.Millisecond
}

// Deadline returns the approximate wall-clock deadline time.
//
// Since the C library uses CLOCK_MONOTONIC, the wall-clock time is computed
// as now + Remaining(). The result may drift slightly from the originally
// requested deadline due to time passing between calls.
func (dc *DeadlineCtx) Deadline() time.Time {
	rem := dc.Remaining()
	if rem < 0 {
		return time.Now() // cancelled
	}
	return time.Now().Add(rem)
}

// Close destroys the deadline context and frees C resources.
// It is safe to call Close multiple times.
func (dc *DeadlineCtx) Close() {
	dc.destroy()
}

func (dc *DeadlineCtx) destroy() {
	if dc != nil && dc.d != nil {
		C.mtls_deadline_ctx_destroy(dc.d)
		dc.d = nil
		runtime.SetFinalizer(dc, nil)
	}
}

// ConnectWithDeadline connects to addr within the deadline budget.
//
// This is non-destructive: a timeout causes the connect to fail with
// ErrDeadlineExceeded, but the context remains usable for future connections.
func (c *Context) ConnectWithDeadline(addr string, deadline *DeadlineCtx) (*Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "context is closed"}
	}

	cAddr := C.CString(addr)
	defer freeString(cAddr)

	var cErr C.mtls_err
	initErr(&cErr)

	var dPtr *C.mtls_deadline_ctx
	if deadline != nil {
		dPtr = deadline.d
	}

	cConn := C.mtls_connect_with_deadline(c.ctx, cAddr, dPtr, &cErr)
	runtime.KeepAlive(deadline)
	if cConn == nil {
		return nil, convertError(&cErr)
	}

	conn := &Conn{conn: cConn, ctx: c}
	runtime.SetFinalizer(conn, (*Conn).finalizer)
	return conn, nil
}

// AcceptWithDeadline accepts an incoming connection within the deadline budget.
func (l *Listener) AcceptWithDeadline(deadline *DeadlineCtx) (*Conn, error) {
	l.mu.Lock()
	if l.closed || l.listener == nil {
		l.mu.Unlock()
		return nil, &Error{Code: ErrConnectionClosed, Message: "listener is closed"}
	}
	listener := l.listener
	l.activeAccepts.Add(1)
	l.mu.Unlock()
	defer l.activeAccepts.Done()

	var cErr C.mtls_err
	initErr(&cErr)

	var dPtr *C.mtls_deadline_ctx
	if deadline != nil {
		dPtr = deadline.d
	}

	cConn := C.mtls_accept_with_deadline(listener, dPtr, &cErr)
	runtime.KeepAlive(deadline)
	if cConn == nil {
		return nil, convertError(&cErr)
	}

	return newConnFromC(cConn, l.ctx), nil
}

// ReadWithDeadline reads from the connection within the deadline budget.
//
// Unlike ReadContext, this does NOT close the connection on timeout.
// Returns ErrDeadlineExceeded if the deadline expires.
func (c *Conn) ReadWithDeadline(p []byte, deadline *DeadlineCtx) (int, error) {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return 0, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	conn := c.conn
	ctx := c.ctx
	c.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	var cErr C.mtls_err
	initErr(&cErr)

	var dPtr *C.mtls_deadline_ctx
	if deadline != nil {
		dPtr = deadline.d
	}

	n := C.mtls_read_with_deadline(conn, unsafe.Pointer(&p[0]), C.size_t(len(p)), dPtr, &cErr)
	runtime.KeepAlive(ctx)
	runtime.KeepAlive(deadline)
	if n < 0 {
		return 0, convertError(&cErr)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

// WriteWithDeadline writes to the connection within the deadline budget.
//
// Unlike WriteContext, this does NOT close the connection on timeout.
func (c *Conn) WriteWithDeadline(p []byte, deadline *DeadlineCtx) (int, error) {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return 0, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	conn := c.conn
	ctx := c.ctx
	c.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	var cErr C.mtls_err
	initErr(&cErr)

	var dPtr *C.mtls_deadline_ctx
	if deadline != nil {
		dPtr = deadline.d
	}

	n := C.mtls_write_with_deadline(conn, unsafe.Pointer(&p[0]), C.size_t(len(p)), dPtr, &cErr)
	runtime.KeepAlive(ctx)
	runtime.KeepAlive(deadline)
	if n < 0 {
		return 0, convertError(&cErr)
	}
	return int(n), nil
}
