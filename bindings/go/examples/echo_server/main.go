// Package main demonstrates an echo server with SAN-based authorization.
//
// This example shows:
//   - Allowed SAN list configuration
//   - Per-connection authorization
//   - Certificate information logging
//   - Graceful shutdown
//   - Statistics tracking
//
// Usage:
//
//	go run main.go <bind:port> <ca_cert> <server_cert> <server_key>
//
// Example:
//
//	go run main.go 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	mtls "github.com/yourusername/mtls-go"
)

// ServerStats tracks server statistics
type ServerStats struct {
	TotalConnections int64
	SuccessfulAuth   int64
	FailedAuth       int64
	BytesReceived    int64
	BytesSent        int64
}

var stats ServerStats

// AllowedClientSANs defines which client identities are authorized
var AllowedClientSANs = []string{
	"client.example.com",
	"*.clients.example.com",
	"spiffe://example.com/client/*",
	"localhost", // For testing
}

func printStats() {
	fmt.Println()
	fmt.Println("+- Server Statistics --------------------+")
	fmt.Printf("| Total Connections:    %-15d |\n", atomic.LoadInt64(&stats.TotalConnections))
	fmt.Printf("| Successful Auth:      %-15d |\n", atomic.LoadInt64(&stats.SuccessfulAuth))
	fmt.Printf("| Failed Auth:          %-15d |\n", atomic.LoadInt64(&stats.FailedAuth))
	fmt.Printf("| Bytes Received:       %-15d |\n", atomic.LoadInt64(&stats.BytesReceived))
	fmt.Printf("| Bytes Sent:           %-15d |\n", atomic.LoadInt64(&stats.BytesSent))
	fmt.Println("+-----------------------------------------+")
}

func authorizeClient(conn *mtls.Conn) bool {
	identity, err := conn.PeerIdentity()
	if err != nil {
		fmt.Printf("  Failed to get peer identity: %v\n", err)
		return false
	}

	fmt.Printf("  Client CN: %s\n", identity.CommonName)

	// Use built-in SAN validation function
	authorized := mtls.ValidateSANs(identity, AllowedClientSANs)

	if authorized {
		// Find which SAN matched (for logging)
		for _, san := range identity.SANs {
			for _, allowed := range AllowedClientSANs {
				if san == allowed {
					fmt.Printf("  Authorized: %s\n", san)
					break
				}
			}
		}
	} else {
		fmt.Println("  Client NOT authorized")
		fmt.Println("  Client SANs:")
		for _, san := range identity.SANs {
			fmt.Printf("    - %s\n", san)
		}
	}

	// Log certificate expiry warning
	if identity.IsValid() {
		ttlDays := int(identity.TTL().Hours() / 24)
		if ttlDays < 30 {
			fmt.Printf("  Warning: Client cert expires in %d days\n", ttlDays)
		}
	} else {
		fmt.Println("  Warning: Client certificate is EXPIRED")
	}

	return authorized
}

func handleClient(conn *mtls.Conn) {
	remoteAddr, _ := conn.RemoteAddr()
	if remoteAddr != "" {
		fmt.Printf("  Remote: %s\n", remoteAddr)
	}

	// Authorization check
	if !authorizeClient(conn) {
		atomic.AddInt64(&stats.FailedAuth, 1)
		denied := "403 Forbidden: Not authorized\n"
		conn.Write([]byte(denied))
		return
	}

	atomic.AddInt64(&stats.SuccessfulAuth, 1)

	// Echo loop
	fmt.Println("  Starting echo service...")
	buffer := make([]byte, 4096)
	messages := 0

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				fmt.Println("  Connection closed by client")
			} else {
				fmt.Printf("  Read failed: %v\n", err)
			}
			break
		}

		if n > 0 {
			atomic.AddInt64(&stats.BytesReceived, int64(n))
			messages++
			fmt.Printf("  <- Received %d bytes (message #%d)\n", n, messages)

			// Echo back
			sent, err := conn.Write(buffer[:n])
			if err != nil {
				fmt.Printf("  Write failed: %v\n", err)
				break
			}
			atomic.AddInt64(&stats.BytesSent, int64(sent))
			fmt.Printf("  -> Echoed %d bytes\n", sent)
		}
	}

	fmt.Printf("  Session: %d messages echoed\n", messages)
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <bind:port> <ca_cert> <server_cert> <server_key>\n", os.Args[0])
		os.Exit(1)
	}

	bindAddr := os.Args[1]
	caCert := os.Args[2]
	serverCert := os.Args[3]
	serverKey := os.Args[4]

	fmt.Println("+=========================================+")
	fmt.Println("|    mTLS Echo Server (Go)                |")
	fmt.Printf("|    Library: %-25s |\n", mtls.Version())
	fmt.Println("+=========================================+")
	fmt.Println()

	// Setup signal handlers
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Configure allowed client identities
	fmt.Println("-> Configured allowed clients:")
	for _, san := range AllowedClientSANs {
		fmt.Printf("   * %s\n", san)
	}
	fmt.Println()

	// Create configuration
	config := mtls.DefaultConfig()
	config.CACertPath = caCert
	config.CertPath = serverCert
	config.KeyPath = serverKey
	config.RequireClientCert = true

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Create context
	fmt.Println("-> Creating server context...")
	ctx, err := mtls.NewContext(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Context creation failed: %v\n", err)
		os.Exit(1)
	}
	defer ctx.Close()
	fmt.Println("   Context created")
	fmt.Println()

	// Create listener
	fmt.Printf("-> Starting listener on %s...\n", bindAddr)
	listener, err := ctx.Listen(bindAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listener creation failed: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("   Listening for connections")
	fmt.Println("   Press Ctrl+C to stop")
	fmt.Println()

	// Track time
	startTime := time.Now()
	stopChan := make(chan struct{})

	// Handle signal
	go func() {
		<-sigChan
		fmt.Println("\n\nReceived shutdown signal...")
		close(stopChan)
		listener.Close()
	}()

	// Accept loop
	for {
		select {
		case <-stopChan:
			goto shutdown
		default:
		}

		fmt.Println(strings.Repeat("=", 40))
		fmt.Println("Waiting for client...")

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopChan:
				goto shutdown
			default:
				fmt.Printf("Accept failed: %v\n", err)
				continue
			}
		}

		atomic.AddInt64(&stats.TotalConnections, 1)
		fmt.Printf("Client #%d connected\n", atomic.LoadInt64(&stats.TotalConnections))

		// Handle client
		handleClient(conn)

		// Cleanup
		conn.Close()
		fmt.Println("Connection closed")
		fmt.Println()
	}

shutdown:
	// Shutdown
	uptime := time.Since(startTime)

	fmt.Println()
	fmt.Println("+=========================================+")
	fmt.Println("|    Server Shutdown                      |")
	fmt.Println("+=========================================+")

	printStats()

	fmt.Printf("\n   Uptime: %v\n", uptime.Round(time.Second))
}
