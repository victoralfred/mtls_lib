// Package main demonstrates a simple mTLS server using the Go bindings.
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
	"os"
	"os/signal"
	"syscall"

	mtls "github.com/yourusername/mtls-go"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <bind:port> <ca_cert> <server_cert> <server_key>\n", os.Args[0])
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key\n", os.Args[0])
		os.Exit(1)
	}

	bindAddr := os.Args[1]
	caCert := os.Args[2]
	serverCert := os.Args[3]
	serverKey := os.Args[4]

	fmt.Println("===========================================")
	fmt.Println("  mTLS Simple Server (Go)")
	fmt.Printf("  Library version: %s\n", mtls.Version())
	fmt.Println("===========================================")
	fmt.Println()

	// Set up signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create configuration
	config := mtls.DefaultConfig()
	config.CACertPath = caCert
	config.CertPath = serverCert
	config.KeyPath = serverKey
	config.RequireClientCert = true // Enforce mutual TLS

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Create context
	fmt.Println("[1/2] Creating mTLS context...")
	ctx, err := mtls.NewContext(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create context: %v\n", err)
		os.Exit(1)
	}
	defer ctx.Close()
	fmt.Println("  Context created")
	fmt.Println()

	// Create listener
	fmt.Printf("[2/2] Starting listener on %s...\n", bindAddr)
	listener, err := ctx.Listen(bindAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("  Listening for connections")
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	// Track connections
	connectionCount := 0
	stopChan := make(chan struct{})

	// Handle signal
	go func() {
		<-sigChan
		fmt.Println("\nReceived shutdown signal...")
		close(stopChan)
		listener.Close()
	}()

	// Accept connections
	for {
		select {
		case <-stopChan:
			goto shutdown
		default:
		}

		fmt.Println("-------------------------------------------")
		fmt.Println("Waiting for client connection...")

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopChan:
				goto shutdown
			default:
				fmt.Fprintf(os.Stderr, "Accept failed: %v\n", err)
				continue
			}
		}

		connectionCount++
		fmt.Printf("Client connected (#%d)\n", connectionCount)

		// Handle the client
		handleClient(conn)

		// Close connection
		conn.Close()
		fmt.Println("Connection closed")
		fmt.Println()
	}

shutdown:
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("  Server shutting down")
	fmt.Printf("  Total connections: %d\n", connectionCount)
	fmt.Println("===========================================")
}

func handleClient(conn *mtls.Conn) {
	// Get remote address
	remoteAddr, err := conn.RemoteAddr()
	if err == nil {
		fmt.Printf("  Remote address: %s\n", remoteAddr)
	}

	// Get peer identity
	identity, err := conn.PeerIdentity()
	if err == nil {
		fmt.Printf("  Peer CN: %s\n", identity.CommonName)

		if len(identity.SANs) > 0 {
			fmt.Printf("  Peer SANs: ")
			for i, san := range identity.SANs {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Print(san)
			}
			fmt.Println()
		}

		if identity.HasSPIFFEID() {
			fmt.Printf("  SPIFFE ID: %s\n", identity.SPIFFEID)
		}

		// Get organization info
		org, err := conn.PeerOrganization()
		if err == nil && org != "" {
			fmt.Printf("  Organization: %s\n", org)
		}
	}

	// Receive data
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Read failed: %v\n", err)
		return
	}

	if n > 0 {
		fmt.Printf("  Received: \"%s\"\n", string(buffer[:n]))

		// Echo back
		response := "Hello from mTLS server!\n"
		sent, err := conn.Write([]byte(response))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Write failed: %v\n", err)
		} else {
			fmt.Printf("  Sent response: %d bytes\n", sent)
		}
	} else {
		fmt.Println("  Connection closed by client")
	}
}
