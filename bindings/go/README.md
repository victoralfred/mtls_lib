# mTLS Go Bindings

Idiomatic Go bindings for the mTLS C library, providing secure mutual TLS transport with full CGo integration.

## Features

- **Idiomatic Go API**: Implements `io.Reader`, `io.Writer`, and `io.Closer` interfaces
- **Thread-safe**: Context is safe for concurrent use; connections are per-goroutine
- **Memory-safe**: Proper CGo memory management with no leaks or races
- **Event observability**: Channel-based event streaming and metrics collection
- **Comprehensive errors**: Categorized errors with OS and TLS error inspection
- **Context support**: `context.Context` integration for cancellation and timeouts

## Installation

```bash
go get github.com/yourusername/mtls-go
```

### Prerequisites

- Go 1.18+
- The mTLS C library must be built and installed
- OpenSSL development headers

```bash
# Build the C library first
cd /path/to/mtls_lib
mkdir build && cd build
cmake ..
make
sudo make install

# Then install Go bindings
go get github.com/yourusername/mtls-go
```

## Quick Start

### Client Example

```go
package main

import (
    "fmt"
    "log"

    mtls "github.com/yourusername/mtls-go"
)

func main() {
    // Use secure defaults
    config := mtls.DefaultConfig()
    config.CACertPath = "/path/to/ca.pem"
    config.CertPath = "/path/to/client.pem"
    config.KeyPath = "/path/to/client.key"

    // Create context (can be shared across connections)
    ctx, err := mtls.NewContext(config)
    if err != nil {
        log.Fatalf("Failed to create context: %v", err)
    }
    defer ctx.Close()

    // Connect to server
    conn, err := ctx.Connect("server.example.com:8443")
    if err != nil {
        log.Fatalf("Connection failed: %v", err)
    }
    defer conn.Close()

    // Verify peer identity
    identity, err := conn.PeerIdentity()
    if err != nil {
        log.Fatalf("Failed to get peer identity: %v", err)
    }

    fmt.Printf("Connected to: %s\n", identity.CommonName)
    fmt.Printf("SPIFFE ID: %s\n", identity.SPIFFEID)
    fmt.Printf("Valid until: %s\n", identity.NotAfter)

    // Use as standard io.Reader/Writer
    conn.Write([]byte("Hello, mTLS!"))

    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    fmt.Printf("Response: %s\n", buf[:n])
}
```

### Server Example

```go
package main

import (
    "fmt"
    "io"
    "log"

    mtls "github.com/yourusername/mtls-go"
)

func main() {
    config := mtls.DefaultConfig()
    config.CACertPath = "/path/to/ca.pem"
    config.CertPath = "/path/to/server.pem"
    config.KeyPath = "/path/to/server.key"
    config.RequireClientCert = true

    ctx, err := mtls.NewContext(config)
    if err != nil {
        log.Fatalf("Failed to create context: %v", err)
    }
    defer ctx.Close()

    listener, err := ctx.Listen("0.0.0.0:8443")
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }
    defer listener.Close()

    fmt.Printf("Listening on %s\n", listener.Addr())

    // Use Serve for automatic connection handling
    err = listener.Serve(func(conn *mtls.Conn) {
        defer conn.Close()

        identity, _ := conn.PeerIdentity()
        fmt.Printf("Client connected: %s\n", identity.CommonName)

        // Echo server
        io.Copy(conn, conn)
    })

    if err != nil {
        log.Printf("Server error: %v", err)
    }
}
```

## Configuration

### Default Configuration

```go
config := mtls.DefaultConfig()
// Defaults:
//   MinTLSVersion: TLS12
//   MaxTLSVersion: TLS13
//   ConnectTimeout: 30s
//   ReadTimeout: 60s
//   WriteTimeout: 60s
//   RequireClientCert: true
//   VerifyHostname: true
```

### Certificate Loading

```go
// From files
config.CACertPath = "/path/to/ca.pem"
config.CertPath = "/path/to/cert.pem"
config.KeyPath = "/path/to/key.pem"

// From memory (PEM format)
config.CACertPEM = caCertBytes
config.CertPEM = certBytes
config.KeyPEM = keyBytes
```

### SAN Validation

```go
// Restrict connections to specific SANs
config.AllowedSANs = []string{
    "spiffe://example.com/service/api",
    "*.example.com",  // Wildcard matching
    "service.example.com",
}
```

### Validation

```go
// Validate configuration before use
if err := config.Validate(); err != nil {
    log.Fatalf("Invalid config: %v", err)
}
```

## Error Handling

### Error Categories

```go
conn, err := ctx.Connect("server:8443")
if err != nil {
    if mtlsErr, ok := err.(*mtls.Error); ok {
        switch {
        case mtlsErr.IsNetwork():
            log.Printf("Network error: %s", mtlsErr.Message)
        case mtlsErr.IsTLS():
            log.Printf("TLS error: %s", mtlsErr.Message)
            if mtlsErr.HasTLSError() {
                log.Printf("OpenSSL: %s", mtlsErr.TLSErrorInfo())
            }
        case mtlsErr.IsIdentity():
            log.Printf("Identity error: %s", mtlsErr.Message)
        case mtlsErr.IsPolicy():
            log.Printf("Policy error: %s", mtlsErr.Message)
        }

        // Check underlying OS error
        if mtlsErr.HasOSError() {
            log.Printf("OS error: %v", mtlsErr.OSError)
        }
    }
}
```

### Error Codes

```go
switch mtlsErr.Code {
case mtls.ErrConnectTimeout:
    // Handle timeout
case mtls.ErrCertExpired:
    // Handle expired certificate
case mtls.ErrKillSwitchEnabled:
    // Handle kill switch
case mtls.ErrIdentityMismatch:
    // Handle identity validation failure
}
```

## Event Observability

### Channel-based Events

```go
// Get event channel with buffer size
events, cancel := ctx.Events(100)
defer cancel()

go func() {
    for event := range events {
        switch event.Type {
        case mtls.EventConnectSuccess:
            fmt.Printf("Connected in %v\n", event.Duration)
        case mtls.EventHandshakeSuccess:
            fmt.Printf("Handshake completed in %v\n", event.Duration)
        case mtls.EventRead:
            fmt.Printf("Read %d bytes\n", event.Bytes)
        case mtls.EventWrite:
            fmt.Printf("Wrote %d bytes\n", event.Bytes)
        case mtls.EventKillSwitch:
            fmt.Println("Kill switch triggered!")
        }
    }
}()
```

### Filtered Events

```go
// Only receive error events
errorEvents, cancel := ctx.FilteredEvents(100, mtls.FilterErrors())
defer cancel()

// Only receive I/O events
ioEvents, cancel := ctx.FilteredEvents(100, mtls.FilterIO())
defer cancel()

// Custom filter
customFilter := func(e *mtls.Event) bool {
    return e.Type == mtls.EventConnectSuccess || e.Type == mtls.EventConnectFailure
}
connEvents, cancel := ctx.FilteredEvents(100, customFilter)
defer cancel()
```

### Metrics Collection

```go
metrics := mtls.NewEventMetrics()

// Register metrics callback
ctx.SetObserver(mtls.MetricsCallback(metrics))

// ... perform operations ...

// Read metrics (thread-safe methods)
fmt.Printf("Connection success rate: %.2f%%\n", metrics.ConnectionSuccessRate()*100)
fmt.Printf("Average connect time: %v\n", metrics.AverageConnectDuration())
fmt.Printf("Average handshake time: %v\n", metrics.AverageHandshakeDuration())

// Note: Direct field access (metrics.BytesRead, metrics.BytesWritten) is not
// thread-safe if Record() is being called concurrently. For thread-safe access,
// access these fields only when Record() is not being called, or use the Record()
// method's mutex protection.
fmt.Printf("Bytes read: %d\n", metrics.BytesRead)
fmt.Printf("Bytes written: %d\n", metrics.BytesWritten)
```

### Observer Builder

```go
observer := mtls.NewObserverBuilder().
    OnSuccess(func(e *mtls.Event) {
        log.Printf("Success: %s", e.Type)
    }).
    OnFailure(func(e *mtls.Event) {
        log.Printf("Failure: %s - %v", e.Type, e.ErrorCode)
    }).
    OnIO(func(e *mtls.Event) {
        log.Printf("I/O: %s %d bytes", e.Type, e.Bytes)
    }).
    Build()

ctx.SetObserver(observer)
```

## Identity Verification

### Peer Identity

```go
identity, err := conn.PeerIdentity()
if err != nil {
    log.Fatalf("Failed to get peer identity: %v", err)
}

fmt.Printf("Common Name: %s\n", identity.CommonName)
fmt.Printf("SANs: %v\n", identity.SANs)
fmt.Printf("SPIFFE ID: %s\n", identity.SPIFFEID)
fmt.Printf("Valid from: %s\n", identity.NotBefore)
fmt.Printf("Valid until: %s\n", identity.NotAfter)
fmt.Printf("Is valid: %v\n", identity.IsValid())
fmt.Printf("TTL: %v\n", identity.TTL())
```

### SAN Validation

```go
// Check if peer SANs match allowed list
allowed := []string{"*.example.com", "spiffe://example.com/service"}
valid, err := conn.ValidatePeerSANs(allowed)
if err != nil {
    log.Fatalf("Validation error: %v", err)
}
if !valid {
    log.Fatal("Peer identity not allowed")
}
```

### Organization Info

```go
org, _ := conn.PeerOrganization()
ou, _ := conn.PeerOrgUnit()
fmt.Printf("Organization: %s, Unit: %s\n", org, ou)
```

## Kill Switch

```go
// Enable kill switch (all new connections fail immediately)
ctx.SetKillSwitch(true)

// Check status
if ctx.IsKillSwitchEnabled() {
    log.Println("Kill switch is active")
}

// Disable
ctx.SetKillSwitch(false)
```

## Context Cancellation

### Connect with Context

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

conn, err := mtlsCtx.ConnectContext(ctx, "server:8443")
if err != nil {
    if err == context.DeadlineExceeded {
        log.Println("Connection timed out")
    }
}
```

### Read/Write with Context

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

n, err := conn.ReadContext(ctx, buf)
if err == context.DeadlineExceeded {
    log.Println("Read timed out")
}
```

### Accept with Context (Destructive)

```go
// WARNING: AcceptContext closes the listener on cancellation!
// Use only when you want to stop accepting on cancel.
ctx, cancel := context.WithCancel(context.Background())

conn, err := listener.AcceptContext(ctx)
if err != nil {
    // Listener is now closed
}
```

## Thread Safety

- `Context` is safe for concurrent use after creation
- `Conn` and `Listener` are NOT safe for concurrent use
- Use separate `Conn` instances for different goroutines
- `EventMetrics` methods (ConnectionSuccessRate, AverageConnectDuration, etc.) are thread-safe
- Direct field access to `EventMetrics` fields should only be done when `Record()` is not being called concurrently

## Examples

Complete example programs are available in the `examples/` directory:

- **simple_client** - Basic client that connects and exchanges messages
- **simple_server** - Basic server that accepts connections
- **echo_server** - Echo server with SAN-based authorization
- **advanced_client** - Advanced client with retry logic and context support

See [examples/README.md](examples/README.md) for detailed instructions.

## Testing

```bash
cd bindings/go
go test -v ./...

# With race detector
go test -race -v ./...
```

## Version Information

```go
fmt.Printf("Library version: %s\n", mtls.Version())

major, minor, patch := mtls.VersionComponents()
fmt.Printf("Version: %d.%d.%d\n", major, minor, patch)
```

## License

MIT / Apache 2.0 (dual licensed)
