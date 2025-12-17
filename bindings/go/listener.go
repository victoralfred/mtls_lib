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

	// mu protects listener during close operations
	mu sync.Mutex
}

// Accept waits for and returns the next connection to the listener.
//
// Accept is a blocking call that performs TCP accept and TLS handshake
// with mutual authentication.
func (l *Listener) Accept() (*Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.listener == nil {
		return nil, &Error{
			Code:    ErrConnectionClosed,
			Message: "listener is closed",
		}
	}

	var cErr C.mtls_err
	initErr(&cErr)

	cConn := C.mtls_accept(l.listener, &cErr)
	if cConn == nil {
		return nil, convertError(&cErr)
	}

	return newConnFromC(cConn, l.ctx), nil
}

// AcceptContext accepts a connection with context cancellation support.
//
// If the context is cancelled, the listener will be closed to interrupt
// the blocking accept operation.
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
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.listener == nil {
		return nil
	}

	C.mtls_listener_close(l.listener)
	l.listener = nil

	return nil
}

// finalizer is called by the GC when Listener becomes unreachable.
func (l *Listener) finalizer() {
	l.Close()
}

// Addr returns the listener's network address (the bind address).
// Note: This is a convenience method that returns the address passed to Listen.
func (l *Listener) Addr() string {
	// The C library doesn't expose a way to get the listener address,
	// so this would need to be stored when the listener is created.
	// For now, this is a placeholder that returns empty string.
	return ""
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
