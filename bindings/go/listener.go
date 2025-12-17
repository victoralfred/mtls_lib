package mtls

/*
#include <mtls/mtls.h>
*/
import "C"

import (
	"context"
	"sync"
)

// Listener listens for incoming mTLS connections.
//
// Listener is NOT safe for concurrent use from multiple goroutines.
// For concurrent access, use external synchronization.
type Listener struct {
	listener *C.mtls_listener
	ctx      *Context
	addr     string // bind address stored at creation time

	// mu protects listener pointer during close operations
	mu     sync.Mutex
	closed bool
}

// Accept waits for and returns the next connection to the listener.
//
// Accept is a blocking call that performs TCP accept and TLS handshake
// with mutual authentication.
func (l *Listener) Accept() (*Conn, error) {
	// Check if closed before calling blocking C function
	l.mu.Lock()
	if l.closed || l.listener == nil {
		l.mu.Unlock()
		return nil, &Error{
			Code:    ErrConnectionClosed,
			Message: "listener is closed",
		}
	}
	listener := l.listener
	l.mu.Unlock()

	// Call blocking C function without holding the mutex
	// This allows Close() to interrupt the accept by closing the socket
	var cErr C.mtls_err
	initErr(&cErr)

	cConn := C.mtls_accept(listener, &cErr)
	if cConn == nil {
		return nil, convertError(&cErr)
	}

	return newConnFromC(cConn, l.ctx), nil
}

// AcceptContext accepts a connection with context cancellation support.
//
// WARNING: This method has DESTRUCTIVE cancellation semantics. If the context
// is cancelled, the listener will be permanently closed to interrupt the
// blocking accept operation. After cancellation, the listener cannot accept
// new connections and must be recreated.
//
// For non-destructive timeout behavior, use Accept() with a deadline set on
// the underlying network connection, or implement your own timeout wrapper
// that doesn't close the listener.
//
// This design is necessary because the underlying C library's mtls_accept
// is a blocking call with no interrupt mechanism other than closing the listener.
func (l *Listener) AcceptContext(ctx context.Context) (*Conn, error) {
	if ctx == nil {
		return l.Accept()
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	type acceptResult struct {
		conn *Conn
		err  error
	}

	resultCh := make(chan acceptResult, 1)

	go func() {
		conn, err := l.Accept()
		resultCh <- acceptResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancelled - close listener to interrupt accept
		l.Close()
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.conn, result.err
	}
}

// Close stops the listener from accepting new connections.
//
// Close does not affect connections that have already been accepted.
// Close will interrupt any pending Accept() call by closing the underlying socket.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed || l.listener == nil {
		return nil
	}

	l.closed = true
	C.mtls_listener_close(l.listener)
	l.listener = nil

	return nil
}

// finalizer is called by the GC when Listener becomes unreachable.
func (l *Listener) finalizer() {
	l.Close()
}

// Addr returns the listener's network address (the bind address).
// This returns the address string that was passed to Context.Listen().
func (l *Listener) Addr() string {
	return l.addr
}

// Serve accepts connections in a loop and calls handler for each one.
//
// Serve blocks until the listener is closed or an unrecoverable error occurs.
// Each connection is handled in a new goroutine.
func (l *Listener) Serve(handler func(*Conn)) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			// Check if listener was closed
			l.mu.Lock()
			closed := l.listener == nil
			l.mu.Unlock()

			if closed {
				return nil
			}
			return err
		}

		go handler(conn)
	}
}

// ServeContext is like Serve but with context cancellation support.
func (l *Listener) ServeContext(ctx context.Context, handler func(*Conn)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := l.AcceptContext(ctx)
		if err != nil {
			// Check if context was cancelled
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Check if listener was closed
			l.mu.Lock()
			closed := l.listener == nil
			l.mu.Unlock()

			if closed {
				return nil
			}
			return err
		}

		go handler(conn)
	}
}
