// Package main demonstrates a simple mTLS client using the Go bindings.
//
// Usage:
//
//	go run main.go <server:port> <ca_cert> <client_cert> <client_key>
//
// Example:
//
//	go run main.go localhost:8443 certs/ca.pem certs/client.pem certs/client.key
package main

import (
	"fmt"
	"os"

	mtls "github.com/yourusername/mtls-go"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server:port> <ca_cert> <client_cert> <client_key>\n", os.Args[0])
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s localhost:8443 certs/ca.pem certs/client.pem certs/client.key\n", os.Args[0])
		os.Exit(1)
	}

	serverAddr := os.Args[1]
	caCert := os.Args[2]
	clientCert := os.Args[3]
	clientKey := os.Args[4]

	fmt.Println("===========================================")
	fmt.Println("  mTLS Simple Client (Go)")
	fmt.Printf("  Library version: %s\n", mtls.Version())
	fmt.Println("===========================================")
	fmt.Println()

	// Create configuration
	config := mtls.DefaultConfig()
	config.CACertPath = caCert
	config.CertPath = clientCert
	config.KeyPath = clientKey

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Create context
	fmt.Println("[1/4] Creating mTLS context...")
	ctx, err := mtls.NewContext(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create context: %v\n", err)
		os.Exit(1)
	}
	defer ctx.Close()
	fmt.Println("  Context created")
	fmt.Println()

	// Connect to server
	fmt.Printf("[2/4] Connecting to %s...\n", serverAddr)
	conn, err := ctx.Connect(serverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("  Connected successfully")
	fmt.Println()

	// Get peer identity
	fmt.Println("[3/4] Verifying peer identity...")
	identity, err := conn.PeerIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: Could not retrieve peer identity: %v\n", err)
	} else {
		fmt.Printf("  Common Name: %s\n", identity.CommonName)
		fmt.Printf("  SANs: %d\n", len(identity.SANs))
		for _, san := range identity.SANs {
			fmt.Printf("    - %s\n", san)
		}

		if identity.HasSPIFFEID() {
			fmt.Printf("  SPIFFE ID: %s\n", identity.SPIFFEID)
		}

		// Check certificate validity
		if identity.IsValid() {
			ttl := identity.TTL()
			days := int(ttl.Hours() / 24)
			fmt.Printf("  Certificate: Valid (expires in %d days)\n", days)
		} else {
			fmt.Println("  Certificate: EXPIRED or NOT YET VALID")
		}
	}
	fmt.Println()

	// Send a message
	fmt.Println("[4/4] Exchanging data...")
	message := "Hello from mTLS client!\n"
	n, err := conn.Write([]byte(message))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write failed: %v\n", err)
	} else {
		fmt.Printf("  Sent %d bytes\n", n)
	}

	// Receive response
	buffer := make([]byte, 4096)
	n, err = conn.Read(buffer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read failed: %v\n", err)
	} else {
		fmt.Printf("  Received %d bytes:\n", n)
		fmt.Printf("  \"%s\"\n", string(buffer[:n]))
	}

	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("  Client session complete")
	fmt.Println("===========================================")
}
