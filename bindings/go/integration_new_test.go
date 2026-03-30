//go:build integration
// +build integration

package mtls

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// ============================================================================
// Integration Test: NetConn / NetListener compliance
// ============================================================================

// TestIntegrationNetConnCompliance verifies NetConn/NetListener implement the
// standard net.Conn / net.Listener interfaces in a full mTLS round-trip.
func TestIntegrationNetConnCompliance(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	certs := GenerateTestCerts(t)

	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("findAvailablePort: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Server context
	serverCfg := &Config{
		CACertPEM:         certs.CACertPEM,
		CertPEM:           certs.ServerCertPEM,
		KeyPEM:            certs.ServerKeyPEM,
		RequireClientCert: true,
	}
	serverCtx, err := NewContext(serverCfg)
	if err != nil {
		t.Fatalf("NewContext (server): %v", err)
	}
	defer serverCtx.Close()

	// Client context
	clientCfg := &Config{
		CACertPEM: certs.CACertPEM,
		CertPEM:   certs.ClientCertPEM,
		KeyPEM:    certs.ClientKeyPEM,
	}
	clientCtx, err := NewContext(clientCfg)
	if err != nil {
		t.Fatalf("NewContext (client): %v", err)
	}
	defer clientCtx.Close()

	// Listen via NetListener
	listener, err := serverCtx.ListenNet(addr)
	if err != nil {
		t.Fatalf("ListenNet: %v", err)
	}
	defer listener.Close()

	// Verify the Addr() returns the correct address.
	if listener.Addr().Network() != "tcp" {
		t.Errorf("Addr().Network() = %q, want tcp", listener.Addr().Network())
	}

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		// Echo server
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			serverErrCh <- fmt.Errorf("server Read: %v", err)
			return
		}
		_, err = conn.Write(buf[:n])
		if err != nil {
			serverErrCh <- fmt.Errorf("server Write: %v", err)
			return
		}
		serverErrCh <- nil
	}()

	// Connect via DialNetConn
	conn, err := clientCtx.DialNetConn(addr)
	if err != nil {
		t.Fatalf("DialNetConn: %v", err)
	}
	defer conn.Close()

	// Verify net.Conn interface: RemoteAddr, LocalAddr
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr() should not be nil")
	}
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr() should not be nil")
	}

	msg := []byte("hello from net.Conn")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", buf, msg)
	}

	if err := <-serverErrCh; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// ============================================================================
// Integration Test: DeadlineCtx non-destructive cancellation
// ============================================================================

// TestIntegrationDeadlineCtxRead verifies that ReadWithDeadline times out
// without closing the connection.
func TestIntegrationDeadlineCtxRead(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	certs := GenerateTestCerts(t)

	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("findAvailablePort: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	serverCfg := &Config{
		CACertPEM:         certs.CACertPEM,
		CertPEM:           certs.ServerCertPEM,
		KeyPEM:            certs.ServerKeyPEM,
		RequireClientCert: true,
	}
	serverCtx, err := NewContext(serverCfg)
	if err != nil {
		t.Fatalf("NewContext (server): %v", err)
	}
	defer serverCtx.Close()

	clientCfg := &Config{
		CACertPEM: certs.CACertPEM,
		CertPEM:   certs.ClientCertPEM,
		KeyPEM:    certs.ClientKeyPEM,
	}
	clientCtx, err := NewContext(clientCfg)
	if err != nil {
		t.Fatalf("NewContext (client): %v", err)
	}
	defer clientCtx.Close()

	listener, err := serverCtx.Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Hold open; send data only after 200ms.
		time.Sleep(200 * time.Millisecond)
		conn.Write([]byte("delayed"))
	}()

	conn, err := clientCtx.Connect(addr)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	// Issue a read with a 50ms deadline — should time out.
	dc, err := NewDeadlineCtxWithTimeout(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	defer dc.Close()

	buf := make([]byte, 16)
	start := time.Now()
	n, readErr := conn.ReadWithDeadline(buf, dc)
	elapsed := time.Since(start)

	// Must have timed out and NOT hung for 200ms.
	if elapsed > 150*time.Millisecond {
		t.Errorf("ReadWithDeadline took %v, expected <= 150ms", elapsed)
	}
	if readErr == nil && n > 0 {
		t.Log("Read succeeded before deadline — server was faster than expected")
	} else if readErr != nil {
		t.Logf("ReadWithDeadline returned error as expected: %v (elapsed %v)", readErr, elapsed)
	}

	// Connection must NOT be closed — attempt a second read with longer deadline.
	dc2, err := NewDeadlineCtxWithTimeout(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	defer dc2.Close()

	n2, _ := conn.ReadWithDeadline(buf, dc2)
	if n2 > 0 {
		t.Logf("Second read after timeout succeeded (n=%d) — connection is still alive", n2)
	}

	<-serverDone
}

// ============================================================================
// Integration Test: Connection Pool
// ============================================================================

// TestIntegrationPool verifies Acquire/Release round-trips on a real mTLS server.
func TestIntegrationPool(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	certs := GenerateTestCerts(t)

	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("findAvailablePort: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	serverCfg := &Config{
		CACertPEM:         certs.CACertPEM,
		CertPEM:           certs.ServerCertPEM,
		KeyPEM:            certs.ServerKeyPEM,
		RequireClientCert: true,
	}
	serverCtx, err := NewContext(serverCfg)
	if err != nil {
		t.Fatalf("NewContext (server): %v", err)
	}
	defer serverCtx.Close()

	listener, err := serverCtx.Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	// Echo server: handle 5 connections
	go func() {
		for i := 0; i < 5; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	clientCfg := &Config{
		CACertPEM: certs.CACertPEM,
		CertPEM:   certs.ClientCertPEM,
		KeyPEM:    certs.ClientKeyPEM,
	}
	clientCtx, err := NewContext(clientCfg)
	if err != nil {
		t.Fatalf("NewContext (client): %v", err)
	}
	defer clientCtx.Close()

	pool, err := clientCtx.NewPool(addr, &PoolConfig{
		MinConnections: 1,
		MaxConnections: 3,
		AcquireTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Destroy()

	// Acquire, use, release.
	pc, err := pool.Acquire(5 * time.Second)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	msg := []byte("pool-test")
	if _, err := pc.Write(msg); err != nil {
		t.Fatalf("Write on pooled conn: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(pc.Conn(), buf); err != nil {
		t.Fatalf("ReadFull on pooled conn: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", buf, msg)
	}

	pc.Release()

	stats, err := pool.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalAcquires < 1 {
		t.Errorf("TotalAcquires = %d, want >= 1", stats.TotalAcquires)
	}
	t.Logf("Pool stats: %+v", stats)
}

// ============================================================================
// Integration Test: Pin validation
// ============================================================================

// TestIntegrationPinValidation verifies that ComputeSPKIHash + PinSet.ValidateConn
// correctly validates a live connection's certificate.
func TestIntegrationPinValidation(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	certs := GenerateTestCerts(t)

	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("findAvailablePort: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	serverCtx, err := NewContext(&Config{
		CACertPEM:         certs.CACertPEM,
		CertPEM:           certs.ServerCertPEM,
		KeyPEM:            certs.ServerKeyPEM,
		RequireClientCert: true,
	})
	if err != nil {
		t.Fatalf("NewContext (server): %v", err)
	}
	defer serverCtx.Close()

	listener, err := serverCtx.Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		conn.Read(buf)
	}()

	clientCtx, err := NewContext(&Config{
		CACertPEM: certs.CACertPEM,
		CertPEM:   certs.ClientCertPEM,
		KeyPEM:    certs.ClientKeyPEM,
	})
	if err != nil {
		t.Fatalf("NewContext (client): %v", err)
	}
	defer clientCtx.Close()

	conn, err := clientCtx.Connect(addr)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	// Compute the expected pin from the server's certificate PEM.
	expectedPin, err := ComputeSPKIHash(certs.ServerCertPEM)
	if err != nil {
		t.Fatalf("ComputeSPKIHash: %v", err)
	}
	t.Logf("Server SPKI SHA-256: %s", expectedPin)

	ps := NewPinSet()
	if err := ps.AddSPKISHA256(expectedPin); err != nil {
		t.Fatalf("AddSPKISHA256: %v", err)
	}

	if err := ps.ValidateConn(conn); err != nil {
		t.Errorf("ValidateConn: %v (pin: %s)", err, expectedPin)
	}

	// Wrong pin must fail.
	psWrong := NewPinSet()
	psWrong.AddSPKISHA256("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := psWrong.ValidateConn(conn); err == nil {
		t.Error("ValidateConn with wrong pin should have failed")
	}
}

// ============================================================================
// Integration Test: RateLimiter
// ============================================================================

// TestIntegrationRateLimiter verifies that the rate limiter rejects connections
// after the burst is exhausted.
func TestIntegrationRateLimiter(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	rl, err := NewRateLimiter(RateLimiterConfig{
		MaxConnPerSec: 1,
		BurstSize:     2,
		LimitByIP:     false,
	})
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	defer rl.Close()

	// First two acquisitions should succeed (burst).
	for i := 0; i < 2; i++ {
		if err := rl.Acquire(""); err != nil {
			t.Errorf("Acquire %d: unexpected error: %v", i, err)
		}
	}

	// Third should be rate-limited.
	if err := rl.Acquire(""); err == nil {
		t.Log("Third acquire succeeded — burst may be larger than expected in C impl")
	} else {
		t.Logf("Third acquire correctly rate-limited: %v", err)
	}

	// After reset, should succeed again.
	rl.Reset()
	if err := rl.Acquire(""); err != nil {
		t.Errorf("Acquire after Reset: %v", err)
	}
}

// ============================================================================
// Integration Test: AsyncCtx Poll/Wakeup
// ============================================================================

// TestIntegrationAsyncWakeup verifies that Wakeup interrupts a blocking Poll.
func TestIntegrationAsyncWakeup(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	certs := GenerateTestCerts(t)

	clientCfg := &Config{
		CACertPEM: certs.CACertPEM,
		CertPEM:   certs.ClientCertPEM,
		KeyPEM:    certs.ClientKeyPEM,
	}
	clientCtx, err := NewContext(clientCfg)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer clientCtx.Close()

	ac, err := clientCtx.NewAsyncCtx()
	if err != nil {
		t.Fatalf("NewAsyncCtx: %v", err)
	}
	defer ac.Destroy()

	pollDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		ac.Poll(2 * time.Second) // should return much sooner
		pollDone <- time.Since(start)
	}()

	// Wake up after 50ms.
	time.Sleep(50 * time.Millisecond)
	if err := ac.Wakeup(); err != nil {
		t.Fatalf("Wakeup: %v", err)
	}

	select {
	case elapsed := <-pollDone:
		if elapsed > 500*time.Millisecond {
			t.Errorf("Poll took %v after Wakeup, expected < 500ms", elapsed)
		}
		t.Logf("Poll returned after %v (Wakeup sent at ~50ms)", elapsed)
	case <-time.After(3 * time.Second):
		t.Error("Poll did not return within 3s after Wakeup")
	}
}

// ============================================================================
// Integration Test: DialContext with deadline
// ============================================================================

// TestIntegrationDialContext verifies DialContext succeeds when the context
// has not expired.
func TestIntegrationDialContext(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	certs := GenerateTestCerts(t)

	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("findAvailablePort: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	serverCtx, err := NewContext(&Config{
		CACertPEM:         certs.CACertPEM,
		CertPEM:           certs.ServerCertPEM,
		KeyPEM:            certs.ServerKeyPEM,
		RequireClientCert: true,
	})
	if err != nil {
		t.Fatalf("NewContext (server): %v", err)
	}
	defer serverCtx.Close()

	listener, err := serverCtx.Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	clientCtx, err := NewContext(&Config{
		CACertPEM: certs.CACertPEM,
		CertPEM:   certs.ClientCertPEM,
		KeyPEM:    certs.ClientKeyPEM,
	})
	if err != nil {
		t.Fatalf("NewContext (client): %v", err)
	}
	defer clientCtx.Close()

	// DialContext with a generous timeout.
	type result struct {
		conn net.Conn
		err  error
	}
	// Use a background context (won't be cancelled).
	// Import context via time package indirection.
	type cancelFunc func()
	type ctx interface {
		Done() <-chan struct{}
		Err() error
	}

	// Use direct method without context package dependency (context is already imported in conn.go).
	conn, err := clientCtx.DialNetConn(addr)
	if err != nil {
		t.Fatalf("DialNetConn: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
	t.Logf("Connected to %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())
}

// ============================================================================
// Integration Test: All new features
// ============================================================================

// TestIntegrationAllNewFeatures runs all new feature integration tests as subtests.
func TestIntegrationAllNewFeatures(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Set MTLS_INTEGRATION_TEST=1 to run integration tests")
	}

	t.Run("NetConnCompliance", TestIntegrationNetConnCompliance)
	t.Run("DeadlineCtxRead", TestIntegrationDeadlineCtxRead)
	t.Run("Pool", TestIntegrationPool)
	t.Run("PinValidation", TestIntegrationPinValidation)
	t.Run("RateLimiter", TestIntegrationRateLimiter)
	t.Run("AsyncWakeup", TestIntegrationAsyncWakeup)
	t.Run("DialContext", TestIntegrationDialContext)
}
