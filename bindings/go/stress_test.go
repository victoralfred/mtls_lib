//go:build stress
// +build stress

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// StressTestConfig holds configuration for stress testing
type StressTestConfig struct {
	TotalConnections  int
	ConcurrentWorkers int
	MessageSize       int
	MessagesPerConn   int
}

// StressMetrics tracks stress test results
type StressMetrics struct {
	ConnectionsAttempted int64
	ConnectionsSucceeded int64
	ConnectionsFailed    int64
	BytesSent            int64
	BytesReceived        int64
	TotalConnectTime     int64 // nanoseconds (includes TCP + TLS handshake)
	MaxConcurrentConns   int64
	CurrentConns         int64
	Errors               sync.Map // error message -> count
}

func (m *StressMetrics) RecordError(err error) {
	key := err.Error()
	if val, ok := m.Errors.Load(key); ok {
		m.Errors.Store(key, val.(int)+1)
	} else {
		m.Errors.Store(key, 1)
	}
}

func (m *StressMetrics) PrintSummary() {
	attempted := atomic.LoadInt64(&m.ConnectionsAttempted)
	succeeded := atomic.LoadInt64(&m.ConnectionsSucceeded)
	failed := atomic.LoadInt64(&m.ConnectionsFailed)

	var avgConnectMs float64
	if succeeded > 0 {
		avgConnectMs = float64(atomic.LoadInt64(&m.TotalConnectTime)) / float64(succeeded) / 1e6
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  STRESS TEST RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\nConnection Statistics:\n")
	fmt.Printf("  Attempted:     %d\n", attempted)
	fmt.Printf("  Succeeded:     %d (%.1f%%)\n", succeeded, float64(succeeded)/float64(attempted)*100)
	fmt.Printf("  Failed:        %d\n", failed)
	fmt.Printf("  Max Concurrent: %d\n", atomic.LoadInt64(&m.MaxConcurrentConns))

	fmt.Printf("\nPerformance:\n")
	fmt.Printf("  Avg Connect+Handshake: %.2f ms\n", avgConnectMs)
	fmt.Printf("  Bytes Sent:            %d\n", atomic.LoadInt64(&m.BytesSent))
	fmt.Printf("  Bytes Received:        %d\n", atomic.LoadInt64(&m.BytesReceived))

	// Print errors
	fmt.Printf("\nErrors:\n")
	errorCount := 0
	m.Errors.Range(func(key, value interface{}) bool {
		fmt.Printf("  %s: %d\n", key, value)
		errorCount++
		return true
	})
	if errorCount == 0 {
		fmt.Printf("  (none)\n")
	}
	fmt.Println(strings.Repeat("=", 60))
}

// checkSystemLimits checks and reports system limits
func checkSystemLimits(t *testing.T, targetConns int, workers int) {
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		t.Logf("Warning: Could not get file descriptor limit: %v", err)
		return
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("  SYSTEM LIMITS CHECK")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  File Descriptors (soft): %d\n", rlimit.Cur)
	fmt.Printf("  File Descriptors (hard): %d\n", rlimit.Max)
	fmt.Printf("  Target Connections:      %d\n", targetConns)
	fmt.Printf("  Concurrent Workers:      %d\n", workers)
	fmt.Printf("  GOMAXPROCS:              %d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("  Num CPU:                 %d\n", runtime.NumCPU())

	// With connection recycling, we only need FDs for concurrent connections
	// Each connection uses ~2 FDs (client + server side), plus overhead
	neededFDs := workers*4 + 100
	fmt.Printf("  Est. Max FDs in use:     %d\n", neededFDs)

	if uint64(neededFDs) > rlimit.Cur {
		fmt.Printf("\n  WARNING: May need more file descriptors!\n")
		fmt.Printf("  Run: ulimit -n %d\n", neededFDs)
	} else {
		fmt.Printf("\n  ✓ FD limit sufficient for %d concurrent workers\n", workers)
	}

	fmt.Println(strings.Repeat("=", 60))
}

// generateStressCerts generates certificates for stress testing
func generateStressCerts(t *testing.T) (caCertPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte) {
	// Generate CA
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stress Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate server cert
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	serverCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	serverKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	// Generate client cert
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "stress-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	clientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	clientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	return
}

// findAvailablePortForStress finds an available port
func findAvailablePortForStress() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

// TestStressConnections runs the stress test with connection recycling
// Uses a fixed pool of workers that each process multiple connections sequentially
func TestStressConnections(t *testing.T) {
	if os.Getenv("MTLS_STRESS_TEST") == "" {
		t.Skip("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.")
	}

	// Get target from environment or default
	targetConns := 1000
	if env := os.Getenv("MTLS_STRESS_CONNECTIONS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			targetConns = n
		}
	}

	// Use moderate worker count - each worker processes many connections sequentially
	// This keeps FD usage low while maintaining high throughput
	workers := 48
	if env := os.Getenv("MTLS_STRESS_WORKERS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			workers = n
		}
	}

	config := StressTestConfig{
		TotalConnections:  targetConns,
		ConcurrentWorkers: workers,
		MessageSize:       64,
		MessagesPerConn:   1,
	}

	checkSystemLimits(t, targetConns, workers)

	// Generate certificates
	caCertPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM := generateStressCerts(t)

	// Create server context
	serverConfig := DefaultConfig()
	serverConfig.CACertPEM = caCertPEM
	serverConfig.CertPEM = serverCertPEM
	serverConfig.KeyPEM = serverKeyPEM

	serverCtx, err := NewContext(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}
	defer serverCtx.Close()

	// Create client context
	clientConfig := DefaultConfig()
	clientConfig.CACertPEM = caCertPEM
	clientConfig.CertPEM = clientCertPEM
	clientConfig.KeyPEM = clientKeyPEM

	clientCtx, err := NewContext(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}
	defer clientCtx.Close()

	// Start server
	port, err := findAvailablePortForStress()
	if err != nil {
		t.Fatalf("Failed to find port: %v", err)
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	listener, err := serverCtx.Listen(serverAddr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	// Metrics
	metrics := &StressMetrics{}

	// Server handlers - simple echo with immediate cleanup
	// No tracking of connections - let them be GC'd after handler exits
	serverWg := sync.WaitGroup{}
	stopServer := make(chan struct{})
	activeHandlers := int64(0)

	// Start server acceptors
	for i := 0; i < workers; i++ {
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			for {
				select {
				case <-stopServer:
					return
				default:
				}

				conn, err := listener.Accept()
				if err != nil {
					// Check if we're shutting down
					select {
					case <-stopServer:
						return
					default:
						// Accept error during normal operation
						return
					}
				}

				// Handle connection in goroutine - closes when done
				atomic.AddInt64(&activeHandlers, 1)
				go func(c *Conn) {
					defer atomic.AddInt64(&activeHandlers, -1)
					defer c.Close()

					buf := make([]byte, 1024)
					// Single read-write cycle (matching client behavior)
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
					// Connection closes immediately after response
				}(conn)
			}
		}()
	}

	// Progress reporting
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		startTime := time.Now()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				attempted := atomic.LoadInt64(&metrics.ConnectionsAttempted)
				succeeded := atomic.LoadInt64(&metrics.ConnectionsSucceeded)
				failed := atomic.LoadInt64(&metrics.ConnectionsFailed)
				current := atomic.LoadInt64(&metrics.CurrentConns)
				handlers := atomic.LoadInt64(&activeHandlers)
				elapsed := time.Since(startTime).Seconds()
				rate := float64(succeeded) / elapsed

				fmt.Printf("\r[%5.1fs] Attempted: %6d | Succeeded: %6d | Failed: %4d | Active: %3d/%3d | Rate: %.0f/s    ",
					elapsed, attempted, succeeded, failed, current, handlers, rate)
			}
		}
	}()

	// Client workers - each worker processes multiple connections sequentially
	fmt.Printf("\nStarting stress test: %d connections with %d workers\n\n", targetConns, workers)
	startTime := time.Now()

	clientWg := sync.WaitGroup{}
	connChan := make(chan int, workers*2) // Small buffer to prevent blocking

	// Producer: feed connection IDs to workers
	go func() {
		for i := 0; i < config.TotalConnections; i++ {
			connChan <- i
		}
		close(connChan)
	}()

	// Start client workers
	for w := 0; w < workers; w++ {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()

			message := make([]byte, config.MessageSize)
			for i := range message {
				message[i] = byte('A' + (i % 26))
			}
			buf := make([]byte, 1024)

			// Process connections sequentially - one at a time per worker
			for range connChan {
				atomic.AddInt64(&metrics.ConnectionsAttempted, 1)
				current := atomic.AddInt64(&metrics.CurrentConns, 1)

				// Update max concurrent
				for {
					max := atomic.LoadInt64(&metrics.MaxConcurrentConns)
					if current <= max || atomic.CompareAndSwapInt64(&metrics.MaxConcurrentConns, max, current) {
						break
					}
				}

				// Connect
				connectStart := time.Now()
				conn, err := clientCtx.Connect(serverAddr)
				connectDuration := time.Since(connectStart)

				if err != nil {
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					metrics.RecordError(err)
					continue
				}

				// Send message
				n, err := conn.Write(message)
				if err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					metrics.RecordError(err)
					continue
				}
				atomic.AddInt64(&metrics.BytesSent, int64(n))

				// Receive response
				n, err = conn.Read(buf)
				if err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					metrics.RecordError(err)
					continue
				}
				atomic.AddInt64(&metrics.BytesReceived, int64(n))

				// Close connection immediately - releases FDs
				conn.Close()

				atomic.AddInt64(&metrics.ConnectionsSucceeded, 1)
				atomic.AddInt64(&metrics.TotalConnectTime, connectDuration.Nanoseconds())
				atomic.AddInt64(&metrics.CurrentConns, -1)
			}
		}()
	}

	// Wait for all client connections to complete
	clientWg.Wait()
	totalDuration := time.Since(startTime)

	// Stop progress reporting
	close(progressDone)

	// Graceful server shutdown
	close(stopServer)
	listener.Close()

	// Wait for server to finish (with timeout)
	serverDone := make(chan struct{})
	go func() {
		serverWg.Wait()
		// Wait for handlers to drain
		for atomic.LoadInt64(&activeHandlers) > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		close(serverDone)
	}()

	select {
	case <-serverDone:
		// Clean shutdown
	case <-time.After(5 * time.Second):
		t.Log("Server shutdown timeout - continuing")
	}

	// Print results
	fmt.Printf("\n\nTest completed in %.2f seconds\n", totalDuration.Seconds())

	succeeded := atomic.LoadInt64(&metrics.ConnectionsSucceeded)
	fmt.Printf("Throughput: %.0f connections/second\n", float64(succeeded)/totalDuration.Seconds())

	metrics.PrintSummary()

	// Fail if too many failures
	failRate := float64(atomic.LoadInt64(&metrics.ConnectionsFailed)) / float64(atomic.LoadInt64(&metrics.ConnectionsAttempted))
	if failRate > 0.01 { // 1% failure threshold
		t.Errorf("Failure rate too high: %.2f%%", failRate*100)
	}
}

// TestStress1K runs 1,000 connection stress test
func TestStress1K(t *testing.T) {
	os.Setenv("MTLS_STRESS_TEST", "1")
	os.Setenv("MTLS_STRESS_CONNECTIONS", "1000")
	defer os.Unsetenv("MTLS_STRESS_TEST")
	defer os.Unsetenv("MTLS_STRESS_CONNECTIONS")
	TestStressConnections(t)
}

// TestStress10K runs 10,000 connection stress test
func TestStress10K(t *testing.T) {
	os.Setenv("MTLS_STRESS_TEST", "1")
	os.Setenv("MTLS_STRESS_CONNECTIONS", "10000")
	defer os.Unsetenv("MTLS_STRESS_TEST")
	defer os.Unsetenv("MTLS_STRESS_CONNECTIONS")
	TestStressConnections(t)
}

// TestStress100K runs 100,000 connection stress test
func TestStress100K(t *testing.T) {
	os.Setenv("MTLS_STRESS_TEST", "1")
	os.Setenv("MTLS_STRESS_CONNECTIONS", "100000")
	defer os.Unsetenv("MTLS_STRESS_TEST")
	defer os.Unsetenv("MTLS_STRESS_CONNECTIONS")
	TestStressConnections(t)
}

// TestStress1M runs 1,000,000 connection stress test
func TestStress1M(t *testing.T) {
	os.Setenv("MTLS_STRESS_TEST", "1")
	os.Setenv("MTLS_STRESS_CONNECTIONS", "1000000")
	defer os.Unsetenv("MTLS_STRESS_TEST")
	defer os.Unsetenv("MTLS_STRESS_CONNECTIONS")
	TestStressConnections(t)
}
