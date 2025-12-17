//go:build stress
// +build stress

package mtls

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// OptimizedStressConfig holds configuration for high-scale stress testing
type OptimizedStressConfig struct {
	TotalConnections   int
	ConcurrentWorkers  int
	MaxConcurrentConns int // Max concurrent connections at once
	MessageSize        int
	MessagesPerConn    int
	ProgressInterval   time.Duration
	BatchSize          int // Connections per batch
	ConnectionRate     int // Max connections per second (0 = unlimited)
	BufferPoolSize     int // Size of buffer pool
}

// BufferPool provides reusable buffers to reduce allocations
type BufferPool struct {
	pool *sync.Pool
	size int
}

func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
		size: size,
	}
}

func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) >= bp.size {
		bp.pool.Put(buf[:bp.size])
	}
}

// ConnectionTask represents a single connection task
type ConnectionTask struct {
	ID      int
	Message []byte
	Buf     []byte
}

// runOptimizedStressTest executes a high-scale stress test with optimizations
func runOptimizedStressTest(t *testing.T, config OptimizedStressConfig) {
	checkSystemLimits(t, config.ConcurrentWorkers)

	// Adjust workers for very large tests
	if config.TotalConnections > 1000000 {
		if config.ConcurrentWorkers > 128 {
			config.ConcurrentWorkers = 128
		}
		if config.MaxConcurrentConns == 0 {
			config.MaxConcurrentConns = config.ConcurrentWorkers * 10
		}
		if config.BatchSize == 0 {
			config.BatchSize = 100
		}
		if config.BufferPoolSize == 0 {
			config.BufferPoolSize = 1024
		}
	}

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
	defer listener.Close()

	metrics := &StressMetrics{}
	stopServer := make(chan struct{})
	var activeHandlers int64
	serverWg := sync.WaitGroup{}

	// Buffer pools for memory efficiency
	readPool := NewBufferPool(config.BufferPoolSize)
	writePool := NewBufferPool(config.MessageSize)

	// Server handler pool - reuse goroutines
	serverTaskChan := make(chan *Conn, config.ConcurrentWorkers*10)
	serverHandlerWg := sync.WaitGroup{}

	// Start server handler workers (reused goroutines)
	for i := 0; i < config.ConcurrentWorkers; i++ {
		serverHandlerWg.Add(1)
		go func() {
			defer serverHandlerWg.Done()
			buf := readPool.Get()
			defer readPool.Put(buf)
			for conn := range serverTaskChan {
				n, err := conn.Read(buf)
				if err == nil {
					_, _ = conn.Write(buf[:n])
				}
				conn.Close()
				atomic.AddInt64(&activeHandlers, -1)
			}
		}()
	}

	// Start server acceptors (reused goroutines)
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
				select {
				case serverTaskChan <- conn:
				case <-stopServer:
					conn.Close()
					atomic.AddInt64(&activeHandlers, -1)
					return
				}
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
				var rate float64
				if elapsed > 0 {
					rate = float64(succeeded) / elapsed
				}
				fmt.Printf("\r[%6.1fs] Attempted: %8d | Succeeded: %8d | Failed: %6d | Active: %5d/%5d | Rate: %8.0f/s    ",
					elapsed, attempted, succeeded, failed, current, handlers, rate)
			}
		}
	}()

	// Client workers with connection rate limiting
	fmt.Printf("\nStarting optimized stress test: %d connections with %d workers\n", config.TotalConnections, config.ConcurrentWorkers)
	if config.MaxConcurrentConns > 0 {
		fmt.Printf("Max concurrent connections: %d\n", config.MaxConcurrentConns)
	}
	if config.ConnectionRate > 0 {
		fmt.Printf("Connection rate limit: %d/s\n", config.ConnectionRate)
	}
	fmt.Println()

	startTime := time.Now()
	clientWg := sync.WaitGroup{}

	// Connection rate limiter
	var rateLimiter chan struct{}
	if config.ConnectionRate > 0 {
		rateLimiter = make(chan struct{}, config.ConnectionRate)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopServer:
					return
				case <-ticker.C:
					// Refill rate limiter
					for i := 0; i < config.ConnectionRate && len(rateLimiter) < cap(rateLimiter); i++ {
						select {
						case rateLimiter <- struct{}{}:
						default:
						}
					}
				}
			}
		}()
	}

	// Semaphore for max concurrent connections
	var connSemaphore chan struct{}
	if config.MaxConcurrentConns > 0 {
		connSemaphore = make(chan struct{}, config.MaxConcurrentConns)
	}

	// Task channel with batching
	taskChan := make(chan ConnectionTask, config.ConcurrentWorkers*2)

	// Generate tasks in batches
	go func() {
		defer close(taskChan)
		message := make([]byte, config.MessageSize)
		for i := range message {
			message[i] = byte('A' + (i % 26))
		}

		for i := 0; i < config.TotalConnections; i++ {
			// Rate limiting
			if rateLimiter != nil {
				<-rateLimiter
			}

			// Max concurrent connection limiting
			if connSemaphore != nil {
				connSemaphore <- struct{}{}
			}

			taskChan <- ConnectionTask{
				ID:      i,
				Message: message,
				Buf:     writePool.Get(),
			}
		}
	}()

	// Client worker pool (reused goroutines)
	for w := 0; w < config.ConcurrentWorkers; w++ {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			buf := readPool.Get()
			defer readPool.Put(buf)

			for task := range taskChan {
				atomic.AddInt64(&metrics.ConnectionsAttempted, 1)
				current := atomic.AddInt64(&metrics.CurrentConns, 1)

				// Update max concurrent
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
					writePool.Put(task.Buf)
					if connSemaphore != nil {
						<-connSemaphore
					}
					metrics.RecordError(err)
					continue
				}

				// Write
				n, err := conn.Write(task.Message)
				if err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					writePool.Put(task.Buf)
					if connSemaphore != nil {
						<-connSemaphore
					}
					metrics.RecordError(err)
					continue
				}
				atomic.AddInt64(&metrics.BytesSent, int64(n))

				// Read
				n, err = conn.Read(buf)
				if err != nil {
					conn.Close()
					atomic.AddInt64(&metrics.ConnectionsFailed, 1)
					atomic.AddInt64(&metrics.CurrentConns, -1)
					writePool.Put(task.Buf)
					if connSemaphore != nil {
						<-connSemaphore
					}
					metrics.RecordError(err)
					continue
				}
				atomic.AddInt64(&metrics.BytesReceived, int64(n))

				conn.Close()
				atomic.AddInt64(&metrics.ConnectionsSucceeded, 1)
				atomic.AddInt64(&metrics.TotalConnectTime, connectDuration.Nanoseconds())
				atomic.AddInt64(&metrics.CurrentConns, -1)
				writePool.Put(task.Buf)
				if connSemaphore != nil {
					<-connSemaphore
				}
			}
		}()
	}

	clientWg.Wait()
	totalDuration := time.Since(startTime)
	close(progressDone)

	// Server shutdown
	close(stopServer)
	listener.Close()
	close(serverTaskChan)
	serverWg.Wait()
	serverHandlerWg.Wait()

	// Wait for handlers to finish
	timeout := time.After(10 * time.Second)
	for atomic.LoadInt64(&activeHandlers) > 0 {
		select {
		case <-timeout:
			t.Logf("Warning: %d handlers still active after timeout", atomic.LoadInt64(&activeHandlers))
			break
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	fmt.Printf("\n\nTest completed in %.2f seconds\n", totalDuration.Seconds())
	succeeded := atomic.LoadInt64(&metrics.ConnectionsSucceeded)
	if totalDuration.Seconds() > 0 {
		fmt.Printf("Throughput: %.0f connections/second\n", float64(succeeded)/totalDuration.Seconds())
	}
	metrics.PrintSummary()

	failRate := float64(atomic.LoadInt64(&metrics.ConnectionsFailed)) / float64(atomic.LoadInt64(&metrics.ConnectionsAttempted))
	if failRate > 0.01 {
		t.Errorf("Failure rate too high: %.2f%%", failRate*100)
	}
}

// TestStress5M runs a 5 million connection stress test
func TestStress5M(t *testing.T) {
	if os.Getenv("MTLS_STRESS_TEST") == "" {
		t.Skip("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.")
	}

	workers := 128
	if env := os.Getenv("MTLS_STRESS_WORKERS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			workers = n
		}
	}

	maxConcurrent := 0
	if env := os.Getenv("MTLS_STRESS_MAX_CONCURRENT"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			maxConcurrent = n
		}
	}

	rateLimit := 0
	if env := os.Getenv("MTLS_STRESS_RATE_LIMIT"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			rateLimit = n
		}
	}

	config := OptimizedStressConfig{
		TotalConnections:   5000000,
		ConcurrentWorkers:  workers,
		MaxConcurrentConns: maxConcurrent,
		MessageSize:        64,
		MessagesPerConn:    1,
		ProgressInterval:   5 * time.Second,
		BatchSize:          100,
		ConnectionRate:     rateLimit,
		BufferPoolSize:     1024,
	}
	runOptimizedStressTest(t, config)
}

// TestStressConnectionsOptimized is the optimized version of TestStressConnections
func TestStressConnectionsOptimized(t *testing.T) {
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

	maxConcurrent := 0
	if env := os.Getenv("MTLS_STRESS_MAX_CONCURRENT"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			maxConcurrent = n
		}
	}

	rateLimit := 0
	if env := os.Getenv("MTLS_STRESS_RATE_LIMIT"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			rateLimit = n
		}
	}

	config := OptimizedStressConfig{
		TotalConnections:   conns,
		ConcurrentWorkers:  workers,
		MaxConcurrentConns: maxConcurrent,
		MessageSize:        64,
		MessagesPerConn:    1,
		ProgressInterval:   time.Second,
		BatchSize:          50,
		ConnectionRate:     rateLimit,
		BufferPoolSize:     1024,
	}
	runOptimizedStressTest(t, config)
}
