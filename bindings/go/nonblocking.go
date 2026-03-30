//go:build linux || darwin || freebsd || openbsd || netbsd
// +build linux darwin freebsd openbsd netbsd

package mtls

/*
#include <mtls/mtls.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// FD returns the underlying socket file descriptor for the connection.
//
// The returned fd is owned by the connection and must NOT be closed by the
// caller. Intended for use with event loops (epoll, kqueue) or tokio AsyncFd.
//
// Returns -1 if the connection is closed or not established.
func (c *Conn) FD() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return -1
	}
	return int(C.mtls_conn_get_fd(c.conn))
}

// ReadNonblocking performs a non-blocking read on the connection.
//
// The connection's socket must have been placed in non-blocking mode before
// calling this function (e.g., by an event loop integration).
//
// Returns:
//   - (n, nil) on success
//   - (0, nil) on EOF
//   - (-1, ErrWouldBlock) if the operation would block — caller should wait
//     for readability on FD() and retry
//   - (-1, err) on other errors
func (c *Conn) ReadNonblocking(p []byte) (int, error) {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return -1, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	conn := c.conn
	ctx := c.ctx
	c.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	var cErr C.mtls_err
	initErr(&cErr)

	n := C.mtls_conn_read_nonblocking(conn, unsafe.Pointer(&p[0]), C.size_t(len(p)), &cErr)
	runtime.KeepAlive(ctx)
	if n < 0 {
		return -1, convertError(&cErr)
	}
	return int(n), nil
}

// WriteNonblocking performs a non-blocking write on the connection.
//
// Returns the number of bytes accepted by the TLS layer (may be less than
// len(p) on a partial write). If -1 and error is ErrWouldBlock, the caller
// should wait for writability on FD() and retry with the same data.
func (c *Conn) WriteNonblocking(p []byte) (int, error) {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return -1, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	conn := c.conn
	ctx := c.ctx
	c.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	var cErr C.mtls_err
	initErr(&cErr)

	n := C.mtls_conn_write_nonblocking(conn, unsafe.Pointer(&p[0]), C.size_t(len(p)), &cErr)
	runtime.KeepAlive(ctx)
	if n < 0 {
		return -1, convertError(&cErr)
	}
	return int(n), nil
}
