//go:build integration
// +build integration

package mtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Test Logger - Verbose output for debugging
// ============================================================================

type TestLogger struct {
	t       *testing.T
	prefix  string
	verbose bool
}

func NewTestLogger(t *testing.T, prefix string) *TestLogger {
	return &TestLogger{
		t:       t,
		prefix:  prefix,
		verbose: true,
	}
}

func (l *TestLogger) Log(format string, args ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, args...)
		l.t.Logf("[%s] %s", l.prefix, msg)
		// Also print to stdout for immediate visibility
		fmt.Printf("[%s] %s\n", l.prefix, msg)
	}
}

func (l *TestLogger) Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.t.Logf("[%s] ✓ %s", l.prefix, msg)
	fmt.Printf("[%s] \033[32m✓ %s\033[0m\n", l.prefix, msg)
}

func (l *TestLogger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.t.Logf("[%s] ✗ %s", l.prefix, msg)
	fmt.Printf("[%s] \033[31m✗ %s\033[0m\n", l.prefix, msg)
}

func (l *TestLogger) Event(event *Event) {
	timestamp := event.Timestamp.Format("15:04:05.000")
	var color string
	switch {
	case event.Type.IsSuccess():
		color = "\033[32m" // Green
	case event.Type.IsFailure():
		color = "\033[31m" // Red
	case event.Type.IsIO():
		color = "\033[36m" // Cyan
	default:
		color = "\033[33m" // Yellow
	}
	reset := "\033[0m"

	extra := ""
	if event.Duration > 0 {
		extra += fmt.Sprintf(" duration=%v", event.Duration)
	}
	if event.Bytes > 0 {
		extra += fmt.Sprintf(" bytes=%d", event.Bytes)
	}
	if event.RemoteAddr != "" {
		extra += fmt.Sprintf(" remote=%s", event.RemoteAddr)
	}
	if event.ErrorCode != ErrOK {
		extra += fmt.Sprintf(" error=%v", event.ErrorCode)
	}

	l.t.Logf("[%s] EVENT: %s%s%s%s", l.prefix, color, event.Type, reset, extra)
	fmt.Printf("[%s] %s[EVENT] %s%s%s\n", timestamp, color, event.Type, extra, reset)
}

// ============================================================================
// Test Certificate Generation
// ============================================================================

type TestCerts struct {
	CACertPEM     []byte
	CAKeyPEM      []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

func GenerateTestCerts(t *testing.T) *TestCerts {
	log := NewTestLogger(t, "CERT-GEN")
	log.Log("Generating test certificates...")

	certs := &TestCerts{}

	// Generate CA key pair
	log.Log("Generating CA key pair...")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	log.Log("Creating CA certificate...")
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	certs.CACertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyDER, _ := x509.MarshalECPrivateKey(caKey)
	certs.CAKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	caCert, _ := x509.ParseCertificate(caCertDER)
	log.Success("CA certificate created: CN=%s", caCert.Subject.CommonName)

	// Generate Server certificate
	log.Log("Generating server certificate...")
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost", "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	certs.ServerCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	certs.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})
	log.Success("Server certificate created: CN=localhost, SANs=[localhost, 127.0.0.1]")

	// Generate Client certificate
	log.Log("Generating client certificate...")
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "test-client",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"test-client"},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	certs.ClientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	certs.ClientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})
	log.Success("Client certificate created: CN=test-client")

	log.Success("All test certificates generated successfully!")
	return certs
}

// ============================================================================
// Helper: Find available port
// ============================================================================

func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

// ============================================================================
// Integration Test: Basic Connection
// ============================================================================

func TestIntegrationBasicConnection(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set MTLS_INTEGRATION_TEST=1 to run.")
	}

	log := NewTestLogger(t, "BASIC-CONN")
	log.Log("========================================")
	log.Log("Starting Basic Connection Integration Test")
	log.Log("========================================")

	// Generate certificates
	certs := GenerateTestCerts(t)

	// Create server config
	log.Log("Creating server configuration...")
	serverConfig := DefaultConfig()
	serverConfig.CACertPEM = certs.CACertPEM
	serverConfig.CertPEM = certs.ServerCertPEM
	serverConfig.KeyPEM = certs.ServerKeyPEM
	serverConfig.RequireClientCert = true

	if err := serverConfig.Validate(); err != nil {
		t.Fatalf("Server config validation failed: %v", err)
	}
	log.Success("Server config validated")

	// Create client config
	log.Log("Creating client configuration...")
	clientConfig := DefaultConfig()
	clientConfig.CACertPEM = certs.CACertPEM
	clientConfig.CertPEM = certs.ClientCertPEM
	clientConfig.KeyPEM = certs.ClientKeyPEM

	if err := clientConfig.Validate(); err != nil {
		t.Fatalf("Client config validation failed: %v", err)
	}
	log.Success("Client config validated")

	// Create server context
	log.Log("Creating server context...")
	serverCtx, err := NewContext(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}
	defer serverCtx.Close()
	log.Success("Server context created")

	// Create client context
	log.Log("Creating client context...")
	clientCtx, err := NewContext(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}
	defer clientCtx.Close()
	log.Success("Client context created")

	// Find available port
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	log.Log("Starting server on %s...", addr)

	listener, err := serverCtx.Listen(addr)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	actualAddr := listener.Addr()
	log.Success("Server listening on %s", actualAddr)

	// Server goroutine
	serverDone := make(chan error, 1)
	var serverConn *Conn
	go func() {
		log.Log("[SERVER] Waiting for client connection...")
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept failed: %v", err)
			return
		}
		serverConn = conn
		log.Success("[SERVER] Client connected!")

		// Get peer identity
		identity, err := conn.PeerIdentity()
		if err != nil {
			log.Error("[SERVER] Failed to get peer identity: %v", err)
		} else {
			log.Success("[SERVER] Peer identity: CN=%s", identity.CommonName)
		}

		// Read data
		buf := make([]byte, 1024)
		log.Log("[SERVER] Reading data from client...")
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("read failed: %v", err)
			return
		}
		log.Success("[SERVER] Received %d bytes: %s", n, string(buf[:n]))

		// Echo back
		log.Log("[SERVER] Echoing data back...")
		_, err = conn.Write(buf[:n])
		if err != nil {
			serverDone <- fmt.Errorf("write failed: %v", err)
			return
		}
		log.Success("[SERVER] Sent %d bytes", n)

		serverDone <- nil
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Client connects
	log.Log("[CLIENT] Connecting to %s...", actualAddr)
	clientConn, err := clientCtx.Connect(actualAddr)
	if err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}
	// Note: clientConn is closed explicitly in cleanup section
	log.Success("[CLIENT] Connected!")

	// Get server identity
	identity, err := clientConn.PeerIdentity()
	if err != nil {
		log.Error("[CLIENT] Failed to get server identity: %v", err)
	} else {
		log.Success("[CLIENT] Server identity: CN=%s", identity.CommonName)
		log.Log("[CLIENT] Server SANs: %v", identity.SANs)
		log.Log("[CLIENT] Certificate valid: %v (expires: %v)", identity.IsValid(), identity.NotAfter)
	}

	// Send data
	testMessage := "Hello, mTLS!"
	log.Log("[CLIENT] Sending: %s", testMessage)
	n, err := clientConn.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Client write failed: %v", err)
	}
	log.Success("[CLIENT] Sent %d bytes", n)

	// Read response
	log.Log("[CLIENT] Reading response...")
	buf := make([]byte, 1024)
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Client read failed: %v", err)
	}
	log.Success("[CLIENT] Received %d bytes: %s", n, string(buf[:n]))

	// Verify echo
	if string(buf[:n]) != testMessage {
		t.Errorf("Echo mismatch: got %q, want %q", string(buf[:n]), testMessage)
	}

	// Wait for server
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Server timeout")
	}

	// Cleanup with timeout - close connections in goroutines to avoid blocking
	log.Log("[CLEANUP] Closing connections...")
	listener.Close()

	cleanupDone := make(chan struct{})
	go func() {
		if serverConn != nil {
			serverConn.Close()
		}
		clientConn.Close()
		close(cleanupDone)
	}()

	select {
	case <-cleanupDone:
		log.Log("[CLEANUP] Connections closed")
	case <-time.After(3 * time.Second):
		log.Log("[CLEANUP] Close timeout - continuing anyway")
	}

	log.Log("========================================")
	log.Success("Basic Connection Test PASSED")
	log.Log("========================================")
}

// ============================================================================
// Integration Test: Event Observability
// ============================================================================

func TestIntegrationEventObservability(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set MTLS_INTEGRATION_TEST=1 to run.")
	}

	log := NewTestLogger(t, "EVENTS")
	log.Log("========================================")
	log.Log("Starting Event Observability Integration Test")
	log.Log("========================================")

	// Generate certificates
	certs := GenerateTestCerts(t)

	// Create configs
	serverConfig := DefaultConfig()
	serverConfig.CACertPEM = certs.CACertPEM
	serverConfig.CertPEM = certs.ServerCertPEM
	serverConfig.KeyPEM = certs.ServerKeyPEM

	clientConfig := DefaultConfig()
	clientConfig.CACertPEM = certs.CACertPEM
	clientConfig.CertPEM = certs.ClientCertPEM
	clientConfig.KeyPEM = certs.ClientKeyPEM

	// Create contexts
	serverCtx, err := NewContext(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}
	defer serverCtx.Close()

	clientCtx, err := NewContext(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}
	defer clientCtx.Close()

	// Setup event tracking
	var eventsMu sync.Mutex
	var events []*Event
	var eventCount int32

	// Register observer on client context
	log.Log("Registering event observer on client context...")
	clientCtx.SetObserver(func(e *Event) {
		atomic.AddInt32(&eventCount, 1)
		eventsMu.Lock()
		events = append(events, e)
		eventsMu.Unlock()
		log.Event(e)
	})
	log.Success("Event observer registered")

	// Start server
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	listener, err := serverCtx.Listen(serverAddr)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	log.Success("Server listening on %s", listener.Addr())

	// Server goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			log.Error("[SERVER] Accept failed: %v", err)
			return
		}
		defer conn.Close()
		log.Success("[SERVER] Client connected")

		// Echo loop
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Log("[SERVER] Read ended: %v", err)
				}
				return
			}
			conn.Write(buf[:n])
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Client connects
	log.Log("[CLIENT] Connecting...")
	conn, err := clientCtx.Connect(serverAddr)
	if err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}

	// Send multiple messages to generate I/O events
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("Message %d", i)
		log.Log("[CLIENT] Sending: %s", msg)
		conn.Write([]byte(msg))

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		log.Log("[CLIENT] Received: %s", string(buf[:n]))
	}

	// Close connection - use a goroutine to avoid blocking on TLS shutdown
	log.Log("[CLIENT] Closing connection...")

	// Close in goroutine with timeout since TLS shutdown can block
	closeDone := make(chan struct{})
	go func() {
		conn.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		log.Log("[CLIENT] Connection closed")
	case <-time.After(5 * time.Second):
		log.Log("[CLIENT] Close timeout - continuing anyway")
	}

	// Close listener and wait for server
	listener.Close()
	select {
	case <-serverDone:
		log.Log("[SERVER] Server goroutine exited")
	case <-time.After(2 * time.Second):
		log.Log("[SERVER] Server exit timeout")
	}

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	// Analyze events
	log.Log("========================================")
	log.Log("Event Analysis")
	log.Log("========================================")

	eventsMu.Lock()
	totalEvents := len(events)
	eventsMu.Unlock()

	log.Log("Total events captured: %d", totalEvents)

	// Count by type
	typeCounts := make(map[EventType]int)
	eventsMu.Lock()
	for _, e := range events {
		typeCounts[e.Type]++
	}
	eventsMu.Unlock()

	log.Log("Events by type:")
	for eventType, count := range typeCounts {
		log.Log("  %s: %d", eventType, count)
	}

	// Verify we got expected events
	if typeCounts[EventConnectStart] == 0 {
		t.Error("Expected ConnectStart event")
	}
	if typeCounts[EventRead] == 0 {
		t.Error("Expected Read events")
	}
	if typeCounts[EventWrite] == 0 {
		t.Error("Expected Write events")
	}

	log.Log("========================================")
	log.Success("Event Observability Test PASSED")
	log.Log("========================================")
}

// ============================================================================
// Integration Test: Metrics Collection
// ============================================================================

func TestIntegrationMetricsCollection(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set MTLS_INTEGRATION_TEST=1 to run.")
	}

	log := NewTestLogger(t, "METRICS")
	log.Log("========================================")
	log.Log("Starting Metrics Collection Integration Test")
	log.Log("========================================")

	// Generate certificates
	certs := GenerateTestCerts(t)

	// Create configs
	serverConfig := DefaultConfig()
	serverConfig.CACertPEM = certs.CACertPEM
	serverConfig.CertPEM = certs.ServerCertPEM
	serverConfig.KeyPEM = certs.ServerKeyPEM

	clientConfig := DefaultConfig()
	clientConfig.CACertPEM = certs.CACertPEM
	clientConfig.CertPEM = certs.ClientCertPEM
	clientConfig.KeyPEM = certs.ClientKeyPEM

	// Create contexts
	serverCtx, err := NewContext(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}
	defer serverCtx.Close()

	clientCtx, err := NewContext(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}
	defer clientCtx.Close()

	// Setup metrics collection
	metrics := NewEventMetrics()
	log.Log("Setting up metrics collection...")

	clientCtx.SetObserver(func(e *Event) {
		metrics.Record(e)
		log.Event(e)
	})
	log.Success("Metrics observer registered")

	// Start server
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	listener, err := serverCtx.Listen(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	log.Success("Server listening on %s", listener.Addr())

	// Server goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
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

	time.Sleep(100 * time.Millisecond)

	// Multiple client connections
	numConnections := 3
	messagesPerConn := 5
	messageSize := 100

	log.Log("Creating %d connections, %d messages each, %d bytes per message",
		numConnections, messagesPerConn, messageSize)

	var wg sync.WaitGroup
	var conns []*Conn
	var connsMu sync.Mutex

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := clientCtx.Connect(listener.Addr())
			if err != nil {
				log.Error("[CONN-%d] Connect failed: %v", connID, err)
				return
			}
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			log.Log("[CONN-%d] Connected", connID)

			message := bytes.Repeat([]byte("X"), messageSize)
			for j := 0; j < messagesPerConn; j++ {
				conn.Write(message)
				buf := make([]byte, 4096)
				conn.Read(buf)
			}
			log.Log("[CONN-%d] Completed %d messages", connID, messagesPerConn)
		}(i)
	}

	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Close all connections with timeout
	listener.Close() // Signal server to stop
	for _, conn := range conns {
		closeDone := make(chan struct{})
		go func(c *Conn) {
			c.Close()
			close(closeDone)
		}(conn)
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
		}
	}

	// Print metrics report
	log.Log("========================================")
	log.Log("Metrics Report")
	log.Log("========================================")
	log.Log("Connection Metrics:")
	log.Log("  Attempts:  %d", metrics.ConnectionAttempts)
	log.Log("  Successes: %d", metrics.ConnectionSuccesses)
	log.Log("  Failures:  %d", metrics.ConnectionFailures)
	log.Log("  Success Rate: %.1f%%", metrics.ConnectionSuccessRate()*100)
	log.Log("  Avg Connect Duration: %v", metrics.AverageConnectDuration())

	log.Log("I/O Metrics:")
	log.Log("  Read Operations:  %d", metrics.ReadOps)
	log.Log("  Write Operations: %d", metrics.WriteOps)
	log.Log("  Bytes Read:    %d", metrics.BytesRead)
	log.Log("  Bytes Written: %d", metrics.BytesWritten)

	log.Log("Error Metrics:")
	log.Log("  Config Errors:   %d", metrics.ConfigErrors)
	log.Log("  Network Errors:  %d", metrics.NetworkErrors)
	log.Log("  TLS Errors:      %d", metrics.TLSErrors)
	log.Log("  Identity Errors: %d", metrics.IdentityErrors)
	log.Log("  Policy Errors:   %d", metrics.PolicyErrors)
	log.Log("  I/O Errors:      %d", metrics.IOErrors)

	// Verify metrics
	expectedMessages := uint64(numConnections * messagesPerConn)
	expectedBytes := uint64(numConnections * messagesPerConn * messageSize)

	if metrics.WriteOps < expectedMessages {
		t.Errorf("Expected at least %d write ops, got %d", expectedMessages, metrics.WriteOps)
	}
	if metrics.BytesWritten < expectedBytes {
		t.Errorf("Expected at least %d bytes written, got %d", expectedBytes, metrics.BytesWritten)
	}

	log.Log("========================================")
	log.Success("Metrics Collection Test PASSED")
	log.Log("========================================")
}

// ============================================================================
// Integration Test: Context Cancellation
// ============================================================================

func TestIntegrationContextCancellation(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set MTLS_INTEGRATION_TEST=1 to run.")
	}

	log := NewTestLogger(t, "CANCEL")
	log.Log("========================================")
	log.Log("Starting Context Cancellation Integration Test")
	log.Log("========================================")

	// Generate certificates
	certs := GenerateTestCerts(t)

	// Create configs
	serverConfig := DefaultConfig()
	serverConfig.CACertPEM = certs.CACertPEM
	serverConfig.CertPEM = certs.ServerCertPEM
	serverConfig.KeyPEM = certs.ServerKeyPEM

	clientConfig := DefaultConfig()
	clientConfig.CACertPEM = certs.CACertPEM
	clientConfig.CertPEM = certs.ClientCertPEM
	clientConfig.KeyPEM = certs.ClientKeyPEM

	// Create contexts
	serverCtx, err := NewContext(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}
	defer serverCtx.Close()

	clientCtx, err := NewContext(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}
	defer clientCtx.Close()

	// Start server
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	listener, err := serverCtx.Listen(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	log.Success("Server listening on %s", listener.Addr())

	// Server that delays response
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		conn.Read(buf)
		time.Sleep(2 * time.Second) // Delay response
		conn.Write([]byte("delayed response"))
	}()

	time.Sleep(100 * time.Millisecond)

	// Test 1: Connect with timeout
	log.Log("Test 1: Connect with short timeout (should succeed)...")
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	conn, err := clientCtx.ConnectContext(ctx1, listener.Addr())
	if err != nil {
		t.Fatalf("ConnectContext failed: %v", err)
	}
	log.Success("Connected with context")

	// Test 2: Read with timeout (should timeout)
	log.Log("Test 2: Read with short timeout (should timeout)...")
	conn.Write([]byte("request"))

	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()

	buf := make([]byte, 1024)
	_, err = conn.ReadContext(ctx2, buf)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	} else if err == context.DeadlineExceeded {
		log.Success("Read correctly timed out: %v", err)
	} else {
		log.Log("Read returned: %v", err)
	}

	// Close connection and listener with timeout
	listener.Close()

	closeDone := make(chan struct{})
	go func() {
		conn.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		log.Log("[CLIENT] Connection closed")
	case <-time.After(2 * time.Second):
		log.Log("[CLIENT] Close timeout - continuing anyway")
	}

	log.Log("========================================")
	log.Success("Context Cancellation Test PASSED")
	log.Log("========================================")
}

// ============================================================================
// Integration Test: Kill Switch
// ============================================================================

func TestIntegrationKillSwitch(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set MTLS_INTEGRATION_TEST=1 to run.")
	}

	log := NewTestLogger(t, "KILLSW")
	log.Log("========================================")
	log.Log("Starting Kill Switch Integration Test")
	log.Log("========================================")

	// Generate certificates
	certs := GenerateTestCerts(t)

	// Create config
	config := DefaultConfig()
	config.CACertPEM = certs.CACertPEM
	config.CertPEM = certs.ClientCertPEM
	config.KeyPEM = certs.ClientKeyPEM

	// Create context
	ctx, _ := NewContext(config)
	defer ctx.Close()

	// Test kill switch status
	log.Log("Initial kill switch status: %v", ctx.IsKillSwitchEnabled())
	if ctx.IsKillSwitchEnabled() {
		t.Error("Kill switch should be disabled initially")
	}
	log.Success("Kill switch initially disabled")

	// Enable kill switch
	log.Log("Enabling kill switch...")
	ctx.SetKillSwitch(true)

	if !ctx.IsKillSwitchEnabled() {
		t.Error("Kill switch should be enabled")
	}
	log.Success("Kill switch enabled")

	// Try to connect (should fail)
	log.Log("Attempting connection with kill switch enabled...")
	_, err := ctx.Connect("127.0.0.1:8443")
	if err == nil {
		t.Error("Connection should fail when kill switch is enabled")
	} else {
		log.Success("Connection correctly rejected: %v", err)
	}

	// Disable kill switch
	log.Log("Disabling kill switch...")
	ctx.SetKillSwitch(false)

	if ctx.IsKillSwitchEnabled() {
		t.Error("Kill switch should be disabled")
	}
	log.Success("Kill switch disabled")

	log.Log("========================================")
	log.Success("Kill Switch Test PASSED")
	log.Log("========================================")
}

// ============================================================================
// Run All Integration Tests
// ============================================================================

func TestIntegrationAll(t *testing.T) {
	if os.Getenv("MTLS_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration tests. Set MTLS_INTEGRATION_TEST=1 to run.")
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  mTLS Go Bindings - Integration Test Suite")
	fmt.Println(strings.Repeat("=", 60) + "\n")

	t.Run("BasicConnection", TestIntegrationBasicConnection)
	t.Run("EventObservability", TestIntegrationEventObservability)
	t.Run("MetricsCollection", TestIntegrationMetricsCollection)
	t.Run("ContextCancellation", TestIntegrationContextCancellation)
	t.Run("KillSwitch", TestIntegrationKillSwitch)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  All Integration Tests Completed!")
	fmt.Println(strings.Repeat("=", 60) + "\n")
}
