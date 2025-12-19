// Package main demonstrates an advanced mTLS client with additional features.
//
// This example shows:
//   - Context cancellation support
//   - Connection state monitoring
//   - Certificate validation
//   - Kill-switch demonstration
//   - Retry logic
//   - Multiple message exchange
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
	"context"
	"fmt"
	"os"
	"time"

	mtls "github.com/yourusername/mtls-go"
)

const (
	maxRetries     = 3
	retryDelay     = 2 * time.Second
	connectTimeout = 10 * time.Second
	messageCount   = 5
	messageDelay   = 500 * time.Millisecond
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server:port> <ca_cert> <client_cert> <client_key>\n", os.Args[0])
		os.Exit(1)
	}

	serverAddr := os.Args[1]
	caCert := os.Args[2]
	clientCert := os.Args[3]
	clientKey := os.Args[4]

	fmt.Println("+=========================================+")
	fmt.Println("|    mTLS Advanced Client (Go)            |")
	fmt.Printf("|    Library: %-25s |\n", mtls.Version())
	fmt.Println("+=========================================+")
	fmt.Println()

	// Create configuration with custom settings
	config := mtls.DefaultConfig()
	config.CACertPath = caCert
	config.CertPath = clientCert
	config.KeyPath = clientKey
	config.ConnectTimeout = connectTimeout
	config.ReadTimeout = 30 * time.Second
	config.WriteTimeout = 30 * time.Second
	config.MinTLSVersion = mtls.TLS12
	config.VerifyHostname = true

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Create context
	fmt.Println("[1/5] Creating mTLS context...")
	ctx, err := mtls.NewContext(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create context: %v\n", err)
		os.Exit(1)
	}
	defer ctx.Close()
	fmt.Println("      Context created")
	fmt.Println()

	// Demonstrate kill-switch
	fmt.Println("[2/5] Testing kill-switch...")
	ctx.SetKillSwitch(true)
	if ctx.IsKillSwitchEnabled() {
		fmt.Println("      Kill-switch enabled (connections would fail)")
	}
	ctx.SetKillSwitch(false)
	fmt.Println("      Kill-switch disabled")
	fmt.Println()

	// Connect with retry logic
	fmt.Printf("[3/5] Connecting to %s (with retry)...\n", serverAddr)
	var conn *mtls.Conn
	var connectErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("      Attempt %d/%d...\n", attempt, maxRetries)

		// Use context with timeout for cancellation support
		connCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		conn, connectErr = ctx.ConnectContext(connCtx, serverAddr)
		cancel()

		if connectErr == nil {
			break
		}

		fmt.Printf("      Failed: %v\n", connectErr)
		if attempt < maxRetries {
			fmt.Printf("      Retrying in %v...\n", retryDelay)
			time.Sleep(retryDelay)
		}
	}

	if connectErr != nil {
		fmt.Fprintf(os.Stderr, "Connection failed after %d attempts: %v\n", maxRetries, connectErr)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("      Connected successfully")
	fmt.Printf("      Connection state: %s\n", conn.State())
	fmt.Println()

	// Get connection details
	fmt.Println("[4/5] Connection details...")
	localAddr, _ := conn.LocalAddr()
	remoteAddr, _ := conn.RemoteAddr()
	fmt.Printf("      Local:  %s\n", localAddr)
	fmt.Printf("      Remote: %s\n", remoteAddr)

	// Get peer identity
	identity, err := conn.PeerIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "      Warning: Could not retrieve peer identity: %v\n", err)
	} else {
		fmt.Printf("      Peer CN: %s\n", identity.CommonName)

		if len(identity.SANs) > 0 {
			fmt.Printf("      Peer SANs: %d\n", len(identity.SANs))
			for _, san := range identity.SANs {
				fmt.Printf("        - %s\n", san)
			}
		}

		if identity.HasSPIFFEID() {
			fmt.Printf("      SPIFFE ID: %s\n", identity.SPIFFEID)
		}

		// Certificate validity info
		if identity.IsValid() {
			ttl := identity.TTL()
			days := int(ttl.Hours() / 24)
			hours := int(ttl.Hours()) % 24
			fmt.Printf("      Certificate: Valid (expires in %d days, %d hours)\n", days, hours)
		} else {
			fmt.Println("      Certificate: EXPIRED or NOT YET VALID")
		}

		// Get organization
		org, err := conn.PeerOrganization()
		if err == nil && org != "" {
			fmt.Printf("      Organization: %s\n", org)
		}

		// Get organizational unit
		ou, err := conn.PeerOrgUnit()
		if err == nil && ou != "" {
			fmt.Printf("      Organizational Unit: %s\n", ou)
		}
	}
	fmt.Println()

	// Exchange multiple messages
	fmt.Println("[5/5] Exchanging messages...")
	buffer := make([]byte, 4096)
	var totalSent, totalReceived int

	for i := 1; i <= messageCount; i++ {
		message := fmt.Sprintf("Message %d from advanced client\n", i)

		// Write with context support
		writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		n, err := conn.WriteContext(writeCtx, []byte(message))
		writeCancel()

		if err != nil {
			fmt.Fprintf(os.Stderr, "      Write %d failed: %v\n", i, err)
			break
		}
		totalSent += n
		fmt.Printf("      -> Sent message %d (%d bytes)\n", i, n)

		// Read with context support
		readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
		n, err = conn.ReadContext(readCtx, buffer)
		readCancel()

		if err != nil {
			fmt.Fprintf(os.Stderr, "      Read %d failed: %v\n", i, err)
			break
		}
		totalReceived += n
		fmt.Printf("      <- Received response %d (%d bytes)\n", i, n)

		// Small delay between messages
		if i < messageCount {
			time.Sleep(messageDelay)
		}
	}

	fmt.Println()
	fmt.Printf("      Total sent: %d bytes\n", totalSent)
	fmt.Printf("      Total received: %d bytes\n", totalReceived)

	// Check final connection state
	fmt.Printf("      Final connection state: %s\n", conn.State())

	fmt.Println()
	fmt.Println("+=========================================+")
	fmt.Println("|    Client session complete              |")
	fmt.Println("+=========================================+")
}
