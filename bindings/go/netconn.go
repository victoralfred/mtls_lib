package mtls

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// netAddr implements net.Addr for mTLS connections.
type netAddr struct {
	addr    string
	network string
}

func (a *netAddr) Network() string { return a.network }
func (a *netAddr) String() string  { return a.addr }

// maxWriteChunk is the maximum bytes per single C write call.
// The C library rejects writes larger than MTLS_MAX_WRITE_BUFFER_SIZE (16 KB);
// NetConn.Write silently chunks larger buffers to comply with the net.Conn contract.
const maxWriteChunk = 16 * 1024

// NetConn wraps a *Conn to implement the net.Conn interface.
//
// This allows mTLS connections to be used anywhere a net.Conn is accepted
// (e.g., http.Server, grpc, etc.).
//
// Concurrent Read + Write (but not Read+Read or Write+Write) is safe:
// the underlying OpenSSL SSL_read and SSL_write are independent operations
// on separate locks inside OpenSSL, matching gRPC-go's transport model.
type NetConn struct {
	conn *Conn

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// Ensure NetConn implements net.Conn.
var _ net.Conn = (*NetConn)(nil)

// NewNetConn wraps an existing mTLS Conn as a net.Conn.
// Ownership of conn transfers to the NetConn; callers must not call conn.Close()
// directly after wrapping.
func NewNetConn(conn *Conn) *NetConn {
	return &NetConn{conn: conn}
}

// Conn returns the underlying mTLS Conn.
func (n *NetConn) Conn() *Conn { return n.conn }

// Read reads from the connection, honouring any read deadline set via SetDeadline
// or SetReadDeadline. Returns io.EOF on clean connection close.
func (n *NetConn) Read(b []byte) (int, error) {
	n.deadlineMu.RLock()
	dl := n.readDeadline
	n.deadlineMu.RUnlock()

	if !dl.IsZero() {
		d, err := NewDeadlineCtx(dl)
		if err != nil {
			return 0, context.DeadlineExceeded
		}
		defer d.Cancel()
		nr, err := n.conn.ReadWithDeadline(b, d)
		if nr == 0 && err == nil {
			return 0, io.EOF
		}
		return nr, err
	}
	return n.conn.Read(b)
}

// Write writes to the connection, honouring any write deadline set via SetDeadline
// or SetWriteDeadline. Large buffers are automatically chunked to satisfy the C
// library's 16 KB per-write limit while preserving the net.Conn all-or-error contract.
func (n *NetConn) Write(b []byte) (int, error) {
	n.deadlineMu.RLock()
	dl := n.writeDeadline
	n.deadlineMu.RUnlock()

	var d *DeadlineCtx
	if !dl.IsZero() {
		var err error
		d, err = NewDeadlineCtx(dl)
		if err != nil {
			return 0, context.DeadlineExceeded
		}
		defer d.Cancel()
	}

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxWriteChunk {
			chunk = b[:maxWriteChunk]
		}
		var nw int
		var err error
		if d != nil {
			nw, err = n.conn.WriteWithDeadline(chunk, d)
		} else {
			nw, err = n.conn.Write(chunk)
		}
		total += nw
		b = b[nw:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Close closes the connection.
func (n *NetConn) Close() error { return n.conn.Close() }

func (n *NetConn) LocalAddr() net.Addr {
	addr, _ := n.conn.LocalAddr()
	return &netAddr{addr: addr, network: "tcp"}
}

func (n *NetConn) RemoteAddr() net.Addr {
	addr, _ := n.conn.RemoteAddr()
	return &netAddr{addr: addr, network: "tcp"}
}

// SetDeadline sets both the read and write deadlines.
func (n *NetConn) SetDeadline(t time.Time) error {
	n.deadlineMu.Lock()
	defer n.deadlineMu.Unlock()
	n.readDeadline = t
	n.writeDeadline = t
	return nil
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value clears the deadline.
func (n *NetConn) SetReadDeadline(t time.Time) error {
	n.deadlineMu.Lock()
	defer n.deadlineMu.Unlock()
	n.readDeadline = t
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
// A zero value clears the deadline.
func (n *NetConn) SetWriteDeadline(t time.Time) error {
	n.deadlineMu.Lock()
	defer n.deadlineMu.Unlock()
	n.writeDeadline = t
	return nil
}

// NetListener wraps a *Listener to implement the net.Listener interface.
//
// This allows mTLS listeners to be used anywhere a net.Listener is accepted
// (e.g., http.Serve, grpc.NewServer, etc.).
type NetListener struct {
	listener *Listener
}

// Ensure NetListener implements net.Listener.
var _ net.Listener = (*NetListener)(nil)

// NewNetListener wraps an existing mTLS Listener as a net.Listener.
// Ownership transfers to the NetListener.
func NewNetListener(l *Listener) *NetListener {
	return &NetListener{listener: l}
}

// Listener returns the underlying mTLS Listener.
func (n *NetListener) Listener() *Listener { return n.listener }

// Accept waits for and returns the next connection as a net.Conn.
func (n *NetListener) Accept() (net.Conn, error) {
	conn, err := n.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewNetConn(conn), nil
}

// Close closes the listener.
func (n *NetListener) Close() error { return n.listener.Close() }

// Addr returns the listener's network address.
func (n *NetListener) Addr() net.Addr {
	return &netAddr{addr: n.listener.Addr(), network: "tcp"}
}
