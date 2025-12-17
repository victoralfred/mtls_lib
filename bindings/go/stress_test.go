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
	ProgressInterval  time.Duration
}

// StressMetrics tracks stress test results
type StressMetrics struct {
	ConnectionsAttempted int64
	ConnectionsSucceeded int64
	ConnectionsFailed    int64
	BytesSent            int64
	BytesReceived        int64
	TotalConnectTime     int64
	MaxConcurrentConns   int64
	CurrentConns         int64
	Errors               sync.Map
}

func (m *StressMetrics) RecordError(err error) {
	if err == nil {
		return
	}
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

// checkSystemLimits reports system limits and warns if insufficient
func checkSystemLimits(t *testing.T, workers int) {
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		t.Logf("Warning: Could not get FD limit: %v", err)
		return
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("  SYSTEM LIMITS CHECK")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  File Descriptors (soft): %d\n", rlimit.Cur)
	fmt.Printf("  File Descriptors (hard): %d\n", rlimit.Max)
	fmt.Printf("  GOMAXPROCS:              %d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("  Num CPU:                 %d\n", runtime.NumCPU())

	estimatedFDs := workers*4 + 100
	fmt.Printf("  Est. Max FDs in use:     %d\n", estimatedFDs)
	if uint64(estimatedFDs) > rlimit.Cur {
		fmt.Printf("\n  WARNING: Increase FDs! Run: ulimit -n %d\n", estimatedFDs)
	} else {
		fmt.Printf("\n  ✓ FD limit sufficient\n")
	}
	fmt.Println(strings.Repeat("=", 60))
}

// generateCertificates creates CA, server, and client certs
func generateCertificates(t *testing.T) (caCertPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte) {
	// CA
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stress Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server
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
	serverDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	serverCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	serverKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	// Client
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "stress-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	clientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	clientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	return
}

// findAvailablePort returns an unused local port
func findAvailablePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// runStressTest executes the MTLS stress test with connection recycling
func runStressTest(t *testing.T, config StressTestConfig) {
	checkSystemLimits(t, config.ConcurrentWorkers)

	caPEM, serverPEM, serverKeyPEM, clientPEM, clientKeyPEM := generateCertificates(t)

	// Server context
	serverCfg := DefaultConfig()
	serverCfg.CACertPEM = caPEM
	serverCfg.CertPEM = serverPEM
	serverCfg.KeyPEM = serverKeyPEM
	serverCtx, err := NewContext(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}
	defer serverCtx.Close()

	// Client context
	clientCfg := DefaultConfig()
	clientCfg.CACertPEM = caPEM
	clientCfg.CertPEM = clientPEM
	clientCfg.KeyPEM = clientKeyPEM
	clientCtx, err := NewContext(clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}
	defer clientCtx.Close()

	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find port: %v", err)
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	listener, err := serverCtx.Listen(serverAddr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	metrics := &StressMetrics{}
	stopServer := make(chan struct{})
	var activeHandlers int64
	serverWg := sync.WaitGroup{}

	// Start server acceptors
	for i := 0; i < config.ConcurrentWorkers; i++ {
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
					select {
					case <-stopServer:
						return
					default:
						return
					}
				}
				atomic.AddInt64(&activeHandlers, 1)
				go func(c *Conn) {
					defer atomic.AddInt64(&activeHandlers, -1)
					defer c.Close()
					buf := make([]byte, 1024)
					n, err := c.Read(buf)
					if err == nil {
						_, _ = c.Write(buf[:n])
					}
				}(conn)
			}
		}()
	}

	// Progress reporting
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(config.ProgressInterval)
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

	// Client workers
	fmt.Printf("\nStarting stress test: %d connections with %d workers\n\n", config.TotalConnections, config.ConcurrentWorkers)
	startTime := time.Now()

	clientWg := sync.WaitGroup{}
	connChan := make(chan int, config.ConcurrentWorkers*2)

	go func() {
		for i := 0; i < config.TotalConnections; i++ {
			connChan <- i
		}
		close(connChan)
	}()

	for w := 0; w < config.ConcurrentWorkers; w++ {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			message := make([]byte, config.MessageSize)
			for i := range message {
				message[i] = byte('A' + (i % 26))
			}
			buf := make([]byte, 1024)
			for range connChan {
				atomic.AddInt64(&metrics.ConnectionsAttempted, 1)
				current := atomic.AddInt64(&metrics.CurrentConns, 1)

				for {
					max := atomic.LoadInt64(&metrics.MaxConcurrentConns)
					if current <= max || atomic.CompareAndSwapInt64(&metrics.MaxConcurrentConns, max, current) {
						break
					}
				}

				connectStart := time.Now()
				conn, err := clientCtx.Connect(serverAddr)
				connectDuration := time.Since(connectStart)

				if err != nil {
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					metrics.RecordError(err)
					continue
				}

				n, err := conn.Write(message)
				if err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					metrics.RecordError(err)
					continue
				}
				atomic.AddInt64(&metrics.BytesSent, int64(n))

				n, err = conn.Read(buf)
				if err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					metrics.RecordError(err)
					continue
				}
				atomic.AddInt64(&metrics.BytesReceived, int64(n))

				conn.Close()
				atomic.AddInt64(&metrics.ConnectionsSucceeded, 1)
				atomic.AddInt64(&metrics.TotalConnectTime, connectDuration.Nanoseconds())
				atomic.AddInt64(&metrics.CurrentConns, -1)
			}
		}()
	}

	clientWg.Wait()
	totalDuration := time.Since(startTime)
	close(progressDone)

	// Server shutdown
	close(stopServer)
	listener.Close()
	serverDone := make(chan struct{})
	go func() {
		serverWg.Wait()
		for atomic.LoadInt64(&activeHandlers) > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		close(serverDone)
	}()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Log("Server shutdown timeout")
	}

	fmt.Printf("\n\nTest completed in %.2f seconds\n", totalDuration.Seconds())
	succeeded := atomic.LoadInt64(&metrics.ConnectionsSucceeded)
	fmt.Printf("Throughput: %.0f connections/second\n", float64(succeeded)/totalDuration.Seconds())
	metrics.PrintSummary()

	failRate := float64(atomic.LoadInt64(&metrics.ConnectionsFailed)) / float64(atomic.LoadInt64(&metrics.ConnectionsAttempted))
	if failRate > 0.01 {
		t.Errorf("Failure rate too high: %.2f%%", failRate*100)
	}
}

// TestStressConnections is the main configurable stress test entry point.
// Configure via environment variables:
//   - MTLS_STRESS_TEST=1 (required to run)
//   - MTLS_STRESS_CONNECTIONS=10000 (default: 1000)
//   - MTLS_STRESS_WORKERS=48 (default: 48)
func TestStressConnections(t *testing.T) {
	if os.Getenv("MTLS_STRESS_TEST") == "" {
		t.Skip("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.")
	}

	conns := 1000
	if env := os.Getenv("MTLS_STRESS_CONNECTIONS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			conns = n
		}
	}

	workers := 48
	if env := os.Getenv("MTLS_STRESS_WORKERS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			workers = n
		}
	}

	config := StressTestConfig{
		TotalConnections:  conns,
		ConcurrentWorkers: workers,
		MessageSize:       64,
		MessagesPerConn:   1,
		ProgressInterval:  time.Second,
	}
	runStressTest(t, config)
}

// Preset stress test runners
func TestStress1K(t *testing.T)   { runPreset(t, 1000, 24) }
func TestStress10K(t *testing.T)  { runPreset(t, 10000, 48) }
func TestStress100K(t *testing.T) { runPreset(t, 100000, 48) }
func TestStress1M(t *testing.T)   { runPreset(t, 1000000, 64) }

// TestStress5M uses the optimized implementation - see stress_test_optimized.go
// For 5M connections, use: MTLS_STRESS_TEST=1 go test -v -tags stress -run TestStress5M -timeout 3600s

func runPreset(t *testing.T, conns, workers int) {
	config := StressTestConfig{
		TotalConnections:  conns,
		ConcurrentWorkers: workers,
		MessageSize:       64,
		MessagesPerConn:   1,
		ProgressInterval:  2 * time.Second,
	}
	runStressTest(t, config)
}
