package mtls

/*
#include <mtls/mtls_async.h>
#include <stdlib.h>

// Forward declarations for Go-exported callback gateways (defined in async_callbacks.go).
extern void goAsyncConnectCb(struct mtls_conn *conn, mtls_err *err, void *userdata);
extern void goAsyncIOCb(struct mtls_conn *conn, ssize_t result, mtls_err *err, void *userdata);
extern void goAsyncCloseCb(mtls_err *err, void *userdata);
*/
import "C"

import (
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// AsyncConnectResult is delivered to the channel returned by AsyncCtx.Connect.
type AsyncConnectResult struct {
	Conn *Conn
	Err  error
}

// AsyncIOResult is delivered to channels returned by AsyncCtx.Read / Write.
type AsyncIOResult struct {
	N   int
	Err error
}

// asyncPending stores the pending state for a single async operation.
// It is registered in the global asyncRegistry so that C callbacks can find it.
type asyncPending struct {
	ctx         *AsyncCtx // back-pointer to parent
	connectCh   chan AsyncConnectResult
	ioCh        chan AsyncIOResult
	closeCh     chan error
	buf         []byte // retained for lifetime of pending read/write
}

var (
	asyncMu       sync.RWMutex
	asyncCounter  uintptr
	asyncRegistry = make(map[uintptr]*asyncPending)
)

func registerAsync(p *asyncPending) uintptr {
	asyncMu.Lock()
	defer asyncMu.Unlock()
	asyncCounter++
	if asyncCounter == 0 {
		asyncCounter = 1
	}
	id := asyncCounter
	for asyncRegistry[id] != nil {
		id++
		if id == 0 {
			id = 1
		}
	}
	asyncRegistry[id] = p
	return id
}

func unregisterAsync(id uintptr) {
	asyncMu.Lock()
	defer asyncMu.Unlock()
	delete(asyncRegistry, id)
}

func lookupAsync(id uintptr) *asyncPending {
	asyncMu.RLock()
	defer asyncMu.RUnlock()
	return asyncRegistry[id]
}

// AsyncCtx manages async I/O for multiple mTLS connections using the C event loop.
//
// Call Poll in a goroutine to drive async I/O. Operations return channels that
// deliver results when they complete.
//
// AsyncCtx is NOT safe for concurrent use of Poll from multiple goroutines.
// Other methods (Connect, Read, Write, Close, Wakeup) are safe.
type AsyncCtx struct {
	a   *C.mtls_async_ctx
	ctx *Context
	mu  sync.Mutex
}

// NewAsyncCtx creates an async context backed by the given mTLS context.
func (c *Context) NewAsyncCtx() (*AsyncCtx, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "context is closed"}
	}

	var cErr C.mtls_err
	initErr(&cErr)

	var a *C.mtls_async_ctx
	if C.mtls_async_ctx_create(&a, c.ctx, &cErr) != 0 {
		return nil, convertError(&cErr)
	}

	ac := &AsyncCtx{a: a, ctx: c}
	runtime.SetFinalizer(ac, (*AsyncCtx).destroy)
	return ac, nil
}

// Poll waits for events and dispatches callbacks.
//
// It blocks for up to timeout (-1 = infinite, 0 = non-blocking).
// Returns the number of events processed and any error.
//
// Call Poll in a dedicated goroutine; only one goroutine should call Poll at a time.
func (ac *AsyncCtx) Poll(timeout time.Duration) (int, error) {
	ac.mu.Lock()
	a := ac.a
	ac.mu.Unlock()

	if a == nil {
		return 0, &Error{Code: ErrCtxNotInitialized, Message: "async context is closed"}
	}

	ms := C.int(-1)
	if timeout >= 0 {
		ms = C.int(timeout.Milliseconds())
	}

	var cErr C.mtls_err
	initErr(&cErr)

	n := C.mtls_async_poll(a, ms, &cErr)
	if n < 0 {
		return 0, convertError(&cErr)
	}
	return int(n), nil
}

// Wakeup interrupts a blocking Poll from another goroutine.
func (ac *AsyncCtx) Wakeup() error {
	ac.mu.Lock()
	a := ac.a
	ac.mu.Unlock()

	if a == nil {
		return nil
	}
	if C.mtls_async_wakeup(a) != 0 {
		return &Error{Code: ErrEventLoopError, Message: "wakeup failed"}
	}
	return nil
}

// PendingCount returns the number of pending async operations.
func (ac *AsyncCtx) PendingCount() int {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.a == nil {
		return 0
	}
	return int(C.mtls_async_pending_count(ac.a))
}

// Connect initiates an async connection. The returned channel receives exactly
// one AsyncConnectResult when the operation completes.
func (ac *AsyncCtx) Connect(addr string) (<-chan AsyncConnectResult, error) {
	ac.mu.Lock()
	a := ac.a
	ac.mu.Unlock()

	if a == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "async context is closed"}
	}

	ch := make(chan AsyncConnectResult, 1)
	p := &asyncPending{ctx: ac, connectCh: ch}
	id := registerAsync(p)

	cAddr := C.CString(addr)
	defer C.free(unsafe.Pointer(cAddr))

	var cErr C.mtls_err
	initErr(&cErr)

	op := C.mtls_async_connect(a, cAddr,
		(C.mtls_async_connect_cb)(C.goAsyncConnectCb),
		unsafe.Pointer(id),
		&cErr)
	if op == nil {
		unregisterAsync(id)
		close(ch)
		return nil, convertError(&cErr)
	}

	return ch, nil
}

// Read initiates an async read. p must remain valid until the result is received.
// The returned channel receives exactly one AsyncIOResult.
func (ac *AsyncCtx) Read(conn *Conn, p []byte) (<-chan AsyncIOResult, error) {
	ac.mu.Lock()
	a := ac.a
	ac.mu.Unlock()

	if a == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "async context is closed"}
	}
	if len(p) == 0 {
		ch := make(chan AsyncIOResult, 1)
		ch <- AsyncIOResult{N: 0}
		return ch, nil
	}

	conn.mu.Lock()
	cConn := conn.conn
	conn.mu.Unlock()
	if cConn == nil {
		return nil, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}

	ch := make(chan AsyncIOResult, 1)
	pending := &asyncPending{ctx: ac, ioCh: ch, buf: p}
	id := registerAsync(pending)

	var cErr C.mtls_err
	initErr(&cErr)

	op := C.mtls_async_read(a, cConn,
		unsafe.Pointer(&p[0]), C.size_t(len(p)),
		(C.mtls_async_io_cb)(C.goAsyncIOCb),
		unsafe.Pointer(id),
		&cErr)
	if op == nil {
		unregisterAsync(id)
		close(ch)
		return nil, convertError(&cErr)
	}

	return ch, nil
}

// Write initiates an async write. p must remain valid until the result is received.
// The returned channel receives exactly one AsyncIOResult.
func (ac *AsyncCtx) Write(conn *Conn, p []byte) (<-chan AsyncIOResult, error) {
	ac.mu.Lock()
	a := ac.a
	ac.mu.Unlock()

	if a == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "async context is closed"}
	}
	if len(p) == 0 {
		ch := make(chan AsyncIOResult, 1)
		ch <- AsyncIOResult{N: 0}
		return ch, nil
	}

	conn.mu.Lock()
	cConn := conn.conn
	conn.mu.Unlock()
	if cConn == nil {
		return nil, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}

	ch := make(chan AsyncIOResult, 1)
	pending := &asyncPending{ctx: ac, ioCh: ch, buf: p}
	id := registerAsync(pending)

	var cErr C.mtls_err
	initErr(&cErr)

	op := C.mtls_async_write(a, cConn,
		unsafe.Pointer(&p[0]), C.size_t(len(p)),
		(C.mtls_async_io_cb)(C.goAsyncIOCb),
		unsafe.Pointer(id),
		&cErr)
	if op == nil {
		unregisterAsync(id)
		close(ch)
		return nil, convertError(&cErr)
	}

	return ch, nil
}

// Close initiates an async close on the connection.
// The returned channel receives exactly one error value (nil on success).
func (ac *AsyncCtx) Close(conn *Conn) (<-chan error, error) {
	ac.mu.Lock()
	a := ac.a
	ac.mu.Unlock()

	if a == nil {
		return nil, &Error{Code: ErrCtxNotInitialized, Message: "async context is closed"}
	}

	conn.mu.Lock()
	cConn := conn.conn
	conn.mu.Unlock()
	if cConn == nil {
		ch := make(chan error, 1)
		ch <- nil
		return ch, nil
	}

	ch := make(chan error, 1)
	p := &asyncPending{ctx: ac, closeCh: ch}
	id := registerAsync(p)

	var cErr C.mtls_err
	initErr(&cErr)

	op := C.mtls_async_close(a, cConn,
		(C.mtls_async_close_cb)(C.goAsyncCloseCb),
		unsafe.Pointer(id),
		&cErr)
	if op == nil {
		unregisterAsync(id)
		close(ch)
		return nil, convertError(&cErr)
	}

	return ch, nil
}

// Destroy cancels all pending operations and frees the async context.
func (ac *AsyncCtx) Destroy() {
	ac.destroy()
}

func (ac *AsyncCtx) destroy() {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.a != nil {
		C.mtls_async_ctx_destroy(ac.a)
		ac.a = nil
		runtime.SetFinalizer(ac, nil)
	}
}
