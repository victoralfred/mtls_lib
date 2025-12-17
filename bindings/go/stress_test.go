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
	TotalConnections    int
	ConcurrentWorkers   int
	ConnectionsPerBatch int
	RampUpDuration      time.Duration
	HoldDuration        time.Duration
	MessageSize         int
	MessagesPerConn     int
}

// StressMetrics tracks stress test results
type StressMetrics struct {
	ConnectionsAttempted int64
	ConnectionsSucceeded int64
	ConnectionsFailed    int64
	HandshakesFailed     int64
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
func checkSystemLimits(t *testing.T, targetConns int) {
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
	fmt.Printf("  GOMAXPROCS:              %d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("  Num CPU:                 %d\n", runtime.NumCPU())

	// Each connection needs ~3 file descriptors (client, server accept, listener)
	// Plus some for the process itself
	neededFDs := targetConns*3 + 100

	if uint64(neededFDs) > rlimit.Cur {
		fmt.Printf("\n  WARNING: May need more file descriptors!\n")
		fmt.Printf("  Run: ulimit -n %d\n", neededFDs)
	}

	// Memory estimate: ~20KB per TLS connection
	memNeeded := targetConns * 20 * 1024
	fmt.Printf("\n  Estimated Memory Needed: %.1f MB\n", float64(memNeeded)/1024/1024)
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

// TestStressConnections runs the stress test
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

	// Limit workers to avoid FD_SETSIZE (1024) limit in select()
	// Each connection uses ~3 FDs (client, server accept, listener overhead)
	// Stay safely under 1024 concurrent connections
	workers := 32
	if runtime.NumCPU() < 8 {
		workers = runtime.NumCPU() * 2
	}
	if env := os.Getenv("MTLS_STRESS_WORKERS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			workers = n
		}
	}

	config := StressTestConfig{
		TotalConnections:    targetConns,
		ConcurrentWorkers:   workers,
		ConnectionsPerBatch: 100,
		HoldDuration:        0, // No hold - pure throughput test
		MessageSize:         64,
		MessagesPerConn:     1,
	}

	checkSystemLimits(t, targetConns)

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
	defer listener.Close()

	// Metrics
	metrics := &StressMetrics{}

	// Server connection tracking to prevent goroutine leaks
	var serverConns []*Conn
	var serverConnsMu sync.Mutex
	serverHandlerWg := sync.WaitGroup{}

	// Server acceptor
	serverWg := sync.WaitGroup{}
	stopServer := make(chan struct{})

	// Start multiple server acceptors
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
					return
				}

				// Track connection for cleanup
				serverConnsMu.Lock()
				serverConns = append(serverConns, conn)
				serverConnsMu.Unlock()

				serverHandlerWg.Add(1)
				go func(c *Conn) {
					defer serverHandlerWg.Done()
					defer c.Close()
					buf := make([]byte, 1024)
					for {
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
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
				elapsed := time.Since(startTime).Seconds()
				rate := float64(succeeded) / elapsed

				fmt.Printf("\r[%5.1fs] Attempted: %6d | Succeeded: %6d | Failed: %4d | Current: %5d | Rate: %.0f/s    ",
					elapsed, attempted, succeeded, failed, current, rate)
			}
		}
	}()

	// Client workers
	fmt.Printf("\nStarting stress test: %d connections with %d workers\n\n", targetConns, workers)
	startTime := time.Now()

	clientWg := sync.WaitGroup{}
	connChan := make(chan int, config.TotalConnections)

	// Fill the channel with connection IDs
	for i := 0; i < config.TotalConnections; i++ {
		connChan <- i
	}
	close(connChan)

	// Start workers
	for w := 0; w < workers; w++ {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()

			message := make([]byte, config.MessageSize)
			for i := range message {
				message[i] = byte('A' + (i % 26))
			}

			for range connChan {
				atomic.AddInt64(&metrics.ConnectionsAttempted, 1)

				connectStart := time.Now()
				conn, err := clientCtx.Connect(serverAddr)
				connectDuration := time.Since(connectStart)

				if err != nil {
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					metrics.RecordError(err)
					continue
				}

				atomic.AddInt64(&metrics.ConnectionsSucceeded, 1)
				atomic.AddInt64(&metrics.TotalConnectTime, connectDuration.Nanoseconds())

				current := atomic.AddInt64(&metrics.CurrentConns, 1)

				// Update max concurrent
				for {
					max := atomic.LoadInt64(&metrics.MaxConcurrentConns)
					if current <= max || atomic.CompareAndSwapInt64(&metrics.MaxConcurrentConns, max, current) {
						break
					}
				}

				// Send/receive messages
				for m := 0; m < config.MessagesPerConn; m++ {
					n, err := conn.Write(message)
					if err != nil {
						metrics.RecordError(err)
						break
					}
					atomic.AddInt64(&metrics.BytesSent, int64(n))

					buf := make([]byte, 1024)
					n, err = conn.Read(buf)
					if err != nil {
						metrics.RecordError(err)
						break
					}
					atomic.AddInt64(&metrics.BytesReceived, int64(n))
				}

				// Hold connection briefly
				if config.HoldDuration > 0 {
					time.Sleep(config.HoldDuration)
				}

				conn.Close()
				atomic.AddInt64(&metrics.CurrentConns, -1)
			}
		}()
	}

	// Wait for clients
	clientWg.Wait()
	totalDuration := time.Since(startTime)

	// Stop progress reporting
	close(progressDone)

	// Graceful server shutdown:
	// 1. Signal acceptors to stop
	close(stopServer)

	// 2. Close listener to unblock Accept() calls
	listener.Close()

	// 3. Close all tracked server connections in parallel to unblock Read() calls
	serverConnsMu.Lock()
	closeWg := sync.WaitGroup{}
	for _, c := range serverConns {
		closeWg.Add(1)
		go func(conn *Conn) {
			defer closeWg.Done()
			conn.Close()
		}(c)
	}
	serverConnsMu.Unlock()
	closeWg.Wait()

	// 4. Wait for server acceptor goroutines (these exit quickly)
	serverWg.Wait()

	// 5. Wait briefly for handler goroutines (non-blocking for test speed)
	//    Handlers will clean up via deferred Close() when their Read() returns error
	handlersDone := make(chan struct{})
	go func() {
		serverHandlerWg.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
		// All handlers cleaned up
	case <-time.After(500 * time.Millisecond):
		// Handlers still running - they'll clean up eventually via defer
		// This is acceptable as the test has completed its measurements
	}

	// Print results
	fmt.Printf("\n\nTest completed in %.2f seconds\n", totalDuration.Seconds())

	succeeded := atomic.LoadInt64(&metrics.ConnectionsSucceeded)
	fmt.Printf("Throughput: %.0f connections/second\n", float64(succeeded)/totalDuration.Seconds())

	metrics.PrintSummary()

	// Fail if too many failures
	failRate := float64(atomic.LoadInt64(&metrics.ConnectionsFailed)) / float64(atomic.LoadInt64(&metrics.ConnectionsAttempted))
	if failRate > 0.1 {
		t.Errorf("Failure rate too high: %.1f%%", failRate*100)
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
