package mtls

import (
	"net"
	"time"
)

// netAddr implements net.Addr for mTLS connections.
type netAddr struct {
	addr    string
	network string
}

func (a *netAddr) Network() string { return a.network }
func (a *netAddr) String() string  { return a.addr }

// NetConn wraps a *Conn to implement the net.Conn interface.
//
// This allows mTLS connections to be used anywhere a net.Conn is accepted
// (e.g., http.Server, grpc, etc.).
//
// SetDeadline / SetReadDeadline / SetWriteDeadline are not yet supported
// by the underlying C library and return nil without effect.
type NetConn struct {
	conn *Conn
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

func (n *NetConn) Read(b []byte) (int, error)  { return n.conn.Read(b) }
func (n *NetConn) Write(b []byte) (int, error) { return n.conn.Write(b) }
func (n *NetConn) Close() error                { return n.conn.Close() }

func (n *NetConn) LocalAddr() net.Addr {
	addr, _ := n.conn.LocalAddr()
	return &netAddr{addr: addr, network: "tcp"}
}

func (n *NetConn) RemoteAddr() net.Addr {
	addr, _ := n.conn.RemoteAddr()
	return &netAddr{addr: addr, network: "tcp"}
}

// SetDeadline is a no-op placeholder. Deadline support requires C library changes.
func (n *NetConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op placeholder.
func (n *NetConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op placeholder.
func (n *NetConn) SetWriteDeadline(t time.Time) error { return nil }

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
