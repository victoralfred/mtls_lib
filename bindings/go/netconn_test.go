package mtls

import (
	"errors"
	"net"
	"testing"
)

// TestNetAddrImplementsNetAddr verifies the netAddr type satisfies net.Addr.
func TestNetAddrImplementsNetAddr(t *testing.T) {
	var _ net.Addr = (*netAddr)(nil)

	a := &netAddr{addr: "127.0.0.1:8443", network: "tcp"}
	if a.Network() != "tcp" {
		t.Errorf("Network() = %q, want %q", a.Network(), "tcp")
	}
	if a.String() != "127.0.0.1:8443" {
		t.Errorf("String() = %q, want %q", a.String(), "127.0.0.1:8443")
	}
}

// TestNewNetConnNil verifies that wrapping a nil Conn panics instead of
// silently creating a broken NetConn.
func TestNewNetConnNilConnOps(t *testing.T) {
	// A Conn with a nil underlying pointer represents a closed connection.
	conn := &Conn{}
	nc := NewNetConn(conn)
	if nc == nil {
		t.Fatal("NewNetConn returned nil")
	}

	// Reads and writes on a closed conn should return errors, not panic.
	buf := make([]byte, 16)
	_, err := nc.Read(buf)
	if err == nil {
		t.Error("Read on closed conn should return error")
	}
	_, err = nc.Write(buf)
	if err == nil {
		t.Error("Write on closed conn should return error")
	}
	// Close on a closed conn is a no-op.
	if err := nc.Close(); err != nil {
		t.Errorf("Close on closed conn returned unexpected error: %v", err)
	}
}

// TestNewNetConnInterfaces verifies NetConn implements net.Conn.
func TestNetConnInterfaces(t *testing.T) {
	var _ net.Conn = (*NetConn)(nil)
}

// TestNetListenerInterfaces verifies NetListener implements net.Listener.
func TestNetListenerInterfaces(t *testing.T) {
	var _ net.Listener = (*NetListener)(nil)
}

// TestErrorIs verifies errors.Is works with sentinel error variables.
func TestErrorIs(t *testing.T) {
	err := &Error{Code: ErrConnectFailed, Message: "connection refused"}

	if !errors.Is(err, ErrSentinelConnectFailed) {
		t.Error("errors.Is should match on identical Code")
	}

	if errors.Is(err, ErrSentinelTLSHandshake) {
		t.Error("errors.Is should not match different Code")
	}
}

// TestErrorAs verifies errors.As extracts *Error from wrapped errors.
func TestErrorAs(t *testing.T) {
	wrapped := &Error{Code: ErrCertExpired, Message: "cert expired"}

	var target *Error
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should find *Error")
	}
	if target.Code != ErrCertExpired {
		t.Errorf("Code = %v, want %v", target.Code, ErrCertExpired)
	}
}

// TestCMallocBoundsAllowedSANs verifies that AllowedSANs over the limit are
// silently capped to maxAllowedSANs during toC conversion.
func TestCMallocBoundsAllowedSANs(t *testing.T) {
	// Build a slice with exactly maxAllowedSANs+1 entries.
	sans := make([]string, maxAllowedSANs+1)
	for i := range sans {
		sans[i] = "example.com"
	}

	cfg := &Config{
		CACertPath:  "dummy.pem",
		AllowedSANs: sans,
	}

	// toC must not panic and must cap at maxAllowedSANs.
	cCfg, allocs := cfg.toC()
	defer freeConfigC(allocs)

	if int(cCfg.allowed_sans_count) != maxAllowedSANs {
		t.Errorf("allowed_sans_count = %d, want %d", cCfg.allowed_sans_count, maxAllowedSANs)
	}
}
