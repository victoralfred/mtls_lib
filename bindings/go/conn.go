package mtls

/*
#include <mtls/mtls.h>
*/
import "C"

import (
	"context"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

// Conn represents an established mTLS connection.
//
// Conn implements io.Reader, io.Writer, and io.Closer interfaces.
//
// Conn is NOT safe for concurrent use from multiple goroutines.
// For concurrent access, use external synchronization or create
// separate connections.
type Conn struct {
	conn *C.mtls_conn
	ctx  *Context

	// mu protects conn during close operations
	mu sync.Mutex
}

// Ensure Conn implements the standard interfaces.
var (
	_ io.Reader     = (*Conn)(nil)
	_ io.Writer     = (*Conn)(nil)
	_ io.Closer     = (*Conn)(nil)
	_ io.ReadWriter = (*Conn)(nil)
)

// Read reads data from the connection.
//
// Read implements io.Reader. It returns the number of bytes read and any error.
// At end of file, Read returns 0, io.EOF.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	if p == nil || len(p) == 0 {
		return 0, nil
	}

	var cErr C.mtls_err
	initErr(&cErr)

	n := C.mtls_read(c.conn, unsafe.Pointer(&p[0]), C.size_t(len(p)), &cErr)
	runtime.KeepAlive(c.ctx) // Ensure context stays alive during CGo call
	if n < 0 {
		return 0, convertError(&cErr)
	}
	if n == 0 {
		return 0, io.EOF
	}

	return int(n), nil
}

// Write writes data to the connection.
//
// Write implements io.Writer. It returns the number of bytes written and any error.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	if p == nil || len(p) == 0 {
		return 0, nil
	}

	var cErr C.mtls_err
	initErr(&cErr)

	n := C.mtls_write(c.conn, unsafe.Pointer(&p[0]), C.size_t(len(p)), &cErr)
	runtime.KeepAlive(c.ctx) // Ensure context stays alive during CGo call
	if n < 0 {
		return 0, convertError(&cErr)
	}

	return int(n), nil
}

// Close closes the connection.
//
// Close implements io.Closer. It performs a TLS shutdown and closes the
// underlying socket.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	C.mtls_close(c.conn)
	c.conn = nil

	return nil
}

// finalizer is called by the GC when Conn becomes unreachable.
func (c *Conn) finalizer() {
	c.Close()
}

// State returns the current connection state.
func (c *Conn) State() ConnState {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ConnStateClosed
	}

	return ConnState(C.mtls_get_state(c.conn))
}

// RemoteAddr returns the remote address of the connection.
func (c *Conn) RemoteAddr() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	var buf [256]C.char

	if C.mtls_get_remote_addr(c.conn, &buf[0], C.size_t(len(buf))) != 0 {
		return "", &Error{
			Code:    ErrInternal,
			Message: "failed to get remote address",
		}
	}

	return C.GoString(&buf[0]), nil
}

// LocalAddr returns the local address of the connection.
func (c *Conn) LocalAddr() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	var buf [256]C.char

	if C.mtls_get_local_addr(c.conn, &buf[0], C.size_t(len(buf))) != 0 {
		return "", &Error{
			Code:    ErrInternal,
			Message: "failed to get local address",
		}
	}

	return C.GoString(&buf[0]), nil
}

// ReadContext reads data from the connection with context cancellation support.
//
// WARNING: If the context is cancelled, the connection will be closed to interrupt
// the blocking read operation. The connection cannot be reused after cancellation.
func (c *Conn) ReadContext(ctx context.Context, p []byte) (int, error) {
	if ctx == nil {
		return c.Read(p)
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	type readResult struct {
		n   int
		err error
	}

	resultCh := make(chan readResult, 1)

	go func() {
		n, err := c.Read(p)
		resultCh <- readResult{n, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancelled - close connection to interrupt read
		c.Close()
		// Drain the result channel to prevent goroutine leak
		<-resultCh
		return 0, ctx.Err()
	case result := <-resultCh:
		return result.n, result.err
	}
}

// WriteContext writes data to the connection with context cancellation support.
//
// WARNING: If the context is cancelled, the connection will be closed to interrupt
// the blocking write operation. The connection cannot be reused after cancellation.
func (c *Conn) WriteContext(ctx context.Context, p []byte) (int, error) {
	if ctx == nil {
		return c.Write(p)
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	type writeResult struct {
		n   int
		err error
	}

	resultCh := make(chan writeResult, 1)

	go func() {
		n, err := c.Write(p)
		resultCh <- writeResult{n, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancelled - close connection to interrupt write
		c.Close()
		// Drain the result channel to prevent goroutine leak
		<-resultCh
		return 0, ctx.Err()
	case result := <-resultCh:
		return result.n, result.err
	}
}

// ConnectContext connects with context cancellation support.
//
// If the context is cancelled during connection, the connection attempt
// will be aborted. Any successfully established connection is properly closed.
func (ctx *Context) ConnectContext(c context.Context, addr string) (*Conn, error) {
	if c == nil {
		return ctx.Connect(addr)
	}

	// Check if context is already cancelled
	select {
	case <-c.Done():
		return nil, c.Err()
	default:
	}

	type connectResult struct {
		conn *Conn
		err  error
	}

	resultCh := make(chan connectResult, 1)

	go func() {
		conn, err := ctx.Connect(addr)
		resultCh <- connectResult{conn, err}
	}()

	select {
	case <-c.Done():
		// Context cancelled - wait for the connection attempt to complete
		// and properly clean up any established connection
		go func() {
			result := <-resultCh
			if result.conn != nil {
				result.conn.Close()
			}
		}()
		return nil, c.Err()
	case result := <-resultCh:
		return result.conn, result.err
	}
}

// newConnFromC creates a Go Conn wrapper around a C connection.
// Used internally by Listener.Accept.
func newConnFromC(cConn *C.mtls_conn, ctx *Context) *Conn {
	conn := &Conn{conn: cConn, ctx: ctx}
	runtime.SetFinalizer(conn, (*Conn).finalizer)
	return conn
}
