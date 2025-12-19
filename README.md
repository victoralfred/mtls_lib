# mTLS Transport Library

A minimal, secure, and auditable mTLS (mutual TLS) transport library with cross-platform support and multi-language bindings.

## Features

- **Secure by default**: TLS 1.2+ with secure cipher suites, mandatory mutual authentication
- **Fail-closed**: All security decisions fail closed (deny by default)
- **Cross-platform**: Linux, macOS, Windows support
- **Small & auditable**: Minimal C core with clear separation of concerns
- **Identity verification**: SAN/SPIFFE URI validation
- **Emergency kill-switch**: Immediate global connection blocking
- **Observability layer**: Real-time event tracking, metrics collection, microsecond-precision timing
- **Structured errors**: Categorized error codes for debugging
- **Language bindings**: Go, Rust, Java (planned)

## Security

### Recent Security Fixes (December 2024)

✅ **All critical vulnerabilities remediated** - 20 security and compatibility fixes applied

**Critical Fixes:**
- **Buffer Overflow Vulnerabilities** - Fixed heap and global buffer overflows in constant-time string comparison
- **Authentication Bypass** - Fixed silent truncation allowing oversized SAN bypass attacks
- **Memory Corruption** - Protected against reading past allocated buffer boundaries
- **Certificate Verification** - Enforced SSL_get_verify_result() checks
- **Integer Overflow** - Protected SAN count and PEM length handling

**Security Compliance:**
- ✅ CERT C Secure Coding Standard (STR31-C, ERR33-C, MSC24-C)
- ✅ MISRA C Safety Standard (Rule 15.x, 17.x)
- ✅ AddressSanitizer clean (no memory errors)
- ✅ Timing-attack resistant (constant-time comparison)
- ✅ Fail-closed security (explicit error handling)

### Security Constants

- `MTLS_MAX_IDENTITY_LEN` - Maximum identity string length (10,000 characters)
- Identity strings exceeding this limit are rejected with `MTLS_ERR_IDENTITY_TOO_LONG`

## Project Structure

```
mtls_lib/
├── include/mtls/          # Public API headers
├── src/                   # Core implementation
│   └── internal/          # Platform-specific code
├── tests/                 # Unit and integration tests
├── examples/              # Example programs
├── docs/                  # Documentation
├── bindings/              # Language bindings (Go, Rust, Java)
├── third_party/           # External dependencies (BoringSSL)
└── cmake/                 # CMake configuration modules
```

## Architecture

```
┌─────────────────────────────────────┐
│   Language Bindings (Go/Rust/Java)  │
├─────────────────────────────────────┤
│        C Public API (mtls.h)        │
├─────────────────────────────────────┤
│  ┌──────────┬──────────┬──────────┐ │
│  │ Context  │   Conn   │ Listener │ │
│  │  Mgmt    │ Handling │  (Server)│ │
│  └──────────┴──────────┴──────────┘ │
├─────────────────────────────────────┤
│       BoringSSL/OpenSSL Layer       │
├─────────────────────────────────────┤
│     Platform Abstraction Layer      │
│   (Linux / macOS / Windows sockets) │
└─────────────────────────────────────┘
```

## Building

### Prerequisites

**Linux/macOS**:
- CMake 3.16+
- C compiler (GCC 7+ or Clang 10+)
- OpenSSL 1.1+ or BoringSSL

**Windows**:
- CMake 3.16+
- Visual Studio 2019+ or MinGW-w64
- OpenSSL 1.1+

### Option 1: Using System OpenSSL

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install cmake build-essential libssl-dev

# Install dependencies (macOS)
brew install cmake openssl@3

# Build
mkdir build && cd build
cmake ..
make

# Install
sudo make install
```

### Option 2: Using BoringSSL (Recommended for Security)

```bash
# Clone BoringSSL as submodule
git submodule add https://boringssl.googlesource.com/boringssl third_party/boringssl
git submodule update --init --recursive

# Build
mkdir build && cd build
cmake ..
make

# Install
sudo make install
```

### Build Options

```bash
# Debug build with sanitizers
cmake -DCMAKE_BUILD_TYPE=Debug -DMTLS_ENABLE_ASAN=ON -DMTLS_ENABLE_UBSAN=ON ..

# Release build
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build without tests
cmake -DMTLS_BUILD_TESTS=OFF ..
```

## Quick Start

### Client Example (C)

```c
#include <mtls/mtls.h>
#include <stdio.h>

int main(void) {
    mtls_err err;
    mtls_err_init(&err);

    // Configure mTLS
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/path/to/ca.pem";
    config.cert_path = "/path/to/client-cert.pem";
    config.key_path = "/path/to/client-key.pem";
    config.min_tls_version = MTLS_TLS_1_2;

    // Create context
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "Failed to create context: %s\n", err.message);
        return 1;
    }

    // Connect to server
    mtls_conn* conn = mtls_connect(ctx, "example.com:8443", &err);
    if (!conn) {
        fprintf(stderr, "Connection failed: %s\n", err.message);
        mtls_ctx_free(ctx);
        return 1;
    }

    // Get peer identity
    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) == 0) {
        printf("Connected to: %s\n", identity.common_name);
        printf("SPIFFE ID: %s\n", identity.spiffe_id);
        mtls_free_peer_identity(&identity);
    }

    // Send data
    const char* msg = "Hello, mTLS!\n";
    ssize_t sent = mtls_write(conn, msg, strlen(msg), &err);
    if (sent < 0) {
        fprintf(stderr, "Write failed: %s\n", err.message);
    }

    // Read response
    char buf[1024];
    ssize_t received = mtls_read(conn, buf, sizeof(buf) - 1, &err);
    if (received > 0) {
        buf[received] = '\0';
        printf("Received: %s", buf);
    }

    // Cleanup
    mtls_close(conn);
    mtls_ctx_free(ctx);
    return 0;
}
```

### Server Example (C)

```c
#include <mtls/mtls.h>
#include <stdio.h>

int main(void) {
    mtls_err err;
    mtls_err_init(&err);

    // Configure mTLS server
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/path/to/ca.pem";
    config.cert_path = "/path/to/server-cert.pem";
    config.key_path = "/path/to/server-key.pem";
    config.require_client_cert = true;  // Enforce mTLS

    // Create context
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "Failed to create context: %s\n", err.message);
        return 1;
    }

    // Start listening
    mtls_listener* listener = mtls_listen(ctx, "0.0.0.0:8443", &err);
    if (!listener) {
        fprintf(stderr, "Failed to listen: %s\n", err.message);
        mtls_ctx_free(ctx);
        return 1;
    }

    printf("Listening on :8443\n");

    // Accept loop
    while (1) {
        mtls_conn* conn = mtls_accept(listener, &err);
        if (!conn) {
            fprintf(stderr, "Accept failed: %s\n", err.message);
            continue;
        }

        // Get client identity
        mtls_peer_identity identity;
        if (mtls_get_peer_identity(conn, &identity, &err) == 0) {
            printf("Client connected: %s\n", identity.common_name);
            mtls_free_peer_identity(&identity);
        }

        // Handle connection...
        char buf[1024];
        ssize_t n = mtls_read(conn, buf, sizeof(buf), &err);
        if (n > 0) {
            mtls_write(conn, buf, n, &err);  // Echo
        }

        mtls_close(conn);
    }

    mtls_listener_close(listener);
    mtls_ctx_free(ctx);
    return 0;
}
```

### Go Bindings

```go
package main

import (
    "fmt"
    "log"

    mtls "github.com/yourusername/mtls-go"
)

func main() {
    // Configure mTLS
    config := mtls.DefaultConfig()
    config.CACertPath = "/path/to/ca.pem"
    config.CertPath = "/path/to/client.pem"
    config.KeyPath = "/path/to/client.key"

    // Create context
    ctx, err := mtls.NewContext(config)
    if err != nil {
        log.Fatalf("Failed to create context: %v", err)
    }
    defer ctx.Close()

    // Connect to server
    conn, err := ctx.Connect("example.com:8443")
    if err != nil {
        log.Fatalf("Connection failed: %v", err)
    }
    defer conn.Close()

    // Get peer identity
    identity, err := conn.PeerIdentity()
    if err == nil {
        fmt.Printf("Connected to: %s\n", identity.CommonName)
        fmt.Printf("SPIFFE ID: %s\n", identity.SPIFFEID)
        fmt.Printf("Certificate valid: %v\n", identity.IsValid())
    }

    // Use as io.Reader/Writer
    conn.Write([]byte("Hello, mTLS!\n"))

    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    fmt.Printf("Received: %s", buf[:n])
}
```

See [bindings/go/README.md](bindings/go/README.md) for complete Go documentation.

## Configuration

### Certificate Loading

Certificates can be loaded from files or memory:

```c
// From files
config.ca_cert_path = "/path/to/ca.pem";
config.cert_path = "/path/to/cert.pem";
config.key_path = "/path/to/key.pem";

// From memory (PEM format)
config.ca_cert_pem = ca_pem_data;
config.ca_cert_pem_len = ca_pem_len;
config.cert_pem = cert_pem_data;
config.cert_pem_len = cert_pem_len;
config.key_pem = key_pem_data;
config.key_pem_len = key_pem_len;
```

### Identity Verification

Restrict connections to specific SANs:

```c
const char* allowed_sans[] = {
    "spiffe://example.com/service/api",
    "service.example.com"
};

config.allowed_sans = allowed_sans;
config.allowed_sans_count = 2;
```

### Timeouts

```c
config.connect_timeout_ms = 30000;  // 30 seconds
config.read_timeout_ms = 60000;     // 60 seconds
config.write_timeout_ms = 60000;    // 60 seconds
```

### Kill-Switch

Emergency global shutdown:

```c
// Enable kill-switch (all new connections will fail)
mtls_ctx_set_kill_switch(ctx, true);

// Disable
mtls_ctx_set_kill_switch(ctx, false);
```

### Observability

Track connection lifecycle, I/O operations, and collect metrics:

```c
// Define event callback
void on_event(const mtls_event* event, void* userdata) {
    switch (event->type) {
        case MTLS_EVENT_CONNECT_SUCCESS:
            printf("Connected in %lu us\n", event->duration_us);
            break;
        case MTLS_EVENT_READ:
            printf("Read %zu bytes\n", event->bytes);
            break;
        case MTLS_EVENT_WRITE:
            printf("Wrote %zu bytes\n", event->bytes);
            break;
        case MTLS_EVENT_KILL_SWITCH_TRIGGERED:
            printf("Kill-switch blocked connection\n");
            break;
        // ... handle other events
    }
}

// Register observer
mtls_observers observers = {
    .on_event = on_event,
    .userdata = &my_metrics
};
mtls_set_observers(ctx, &observers);
```

**Event Types:**
- `MTLS_EVENT_CONNECT_START` / `_SUCCESS` / `_FAILURE` - Connection lifecycle
- `MTLS_EVENT_HANDSHAKE_START` / `_SUCCESS` / `_FAILURE` - TLS handshake
- `MTLS_EVENT_READ` / `WRITE` - I/O operations with byte counts
- `MTLS_EVENT_CLOSE` - Connection termination
- `MTLS_EVENT_KILL_SWITCH_TRIGGERED` - Emergency kill-switch activation

All events include microsecond-precision timestamps and durations where applicable. See `examples/observability_demo.c` for a complete metrics tracking implementation.

## Error Handling

Errors are categorized for easier debugging:

```c
mtls_err err;
mtls_err_init(&err);

if (mtls_connect(ctx, addr, &err) == NULL) {
    // Check error category
    if (mtls_err_is_network(err.code)) {
        printf("Network error: %s\n", err.message);
    } else if (mtls_err_is_tls(err.code)) {
        printf("TLS error: %s (SSL: 0x%lx)\n", err.message, err.ssl_err);
    }

    // Format full error
    char err_buf[512];
    mtls_err_format(&err, err_buf, sizeof(err_buf));
    fprintf(stderr, "%s\n", err_buf);
}
```

## Security Best Practices

1. **Always verify peer identity**: Use `mtls_get_peer_identity()` and check SANs
2. **Use TLS 1.3 when possible**: Set `config.min_tls_version = MTLS_TLS_1_3`
3. **Restrict allowed SANs**: Don't accept all certificates
4. **Enable kill-switch in emergencies**: Immediate fail-closed behavior
5. **Rotate certificates regularly**: Use `mtls_ctx_reload_certs()`
6. **Monitor errors**: Check error categories for security incidents

## Testing

```bash
# Run all tests
cd build
ctest --output-on-failure

# Run specific test
./tests/test_identity
./tests/test_san_validation

# Run with verbose output
ctest -V
```

## Example Programs

The library includes six complete example programs demonstrating various usage patterns:

### Simple Client (`simple_client.c`)
Basic mTLS client demonstrating:
- Context creation and configuration
- Connecting to an mTLS server
- Peer identity verification
- Sending and receiving data
- Proper cleanup

```bash
cd build/examples
./simple_client localhost:8443 certs/ca.pem certs/client.pem certs/client.key
```

### Simple Server (`simple_server.c`)
Basic mTLS server demonstrating:
- Server context creation with client certificate requirement
- Listener creation and client acceptance
- Peer identity extraction
- Echo functionality
- Graceful shutdown

```bash
cd build/examples
./simple_server 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key
```

### Advanced Client (`advanced_client.c`)
Production-ready client example showing:
- SAN validation against allowed list
- Detailed peer identity inspection
- Certificate expiration monitoring
- Comprehensive error handling with categorization
- Connection state checking
- Pretty-printed output

```bash
cd build/examples
./advanced_client localhost:8443 certs/ca.pem certs/client.pem certs/client.key
```

### Echo Server (`echo_server.c`)
Production-like server with advanced features:
- SAN-based client authorization
- Configurable allowed client list
- Connection statistics tracking
- Per-connection logging
- Graceful shutdown handling
- Certificate expiration warnings

```bash
cd build/examples
./echo_server 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key
```

### Kill Switch Demo (`kill_switch_demo.c`)
Emergency kill switch demonstration showing:
- Dynamic kill switch enable/disable via signals
- Connection rejection during kill switch activation
- Zero-downtime emergency shutdown capability
- Signal-based control (SIGUSR1/SIGUSR2)
- Real-time status monitoring

```bash
cd build/examples
./kill_switch_demo 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key

# In another terminal:
kill -USR1 <pid>  # Enable kill switch (block new connections)
kill -USR2 <pid>  # Disable kill switch (allow new connections)
```

### Certificate Reload Demo (`cert_reload_demo.c`)
Hot certificate reloading demonstration showing:
- Certificate reload without service restart
- Zero-downtime certificate rotation
- Signal-triggered reload (SIGUSR1)
- Certificate expiration monitoring
- Existing connection preservation during reload

```bash
cd build/examples
./cert_reload_demo 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key

# Update certificates on disk, then:
kill -USR1 <pid>  # Reload certificates without downtime
```

### Observability Demo (`observability_demo.c`)
Comprehensive observability demonstration showing:
- Real-time event tracking for all connection operations
- Metrics collection (connections, bytes, durations)
- Color-coded event visualization
- Aggregated statistics display
- Practical monitoring implementation patterns
- Client-server communication with event streams

```bash
cd build/examples
./observability_demo
```

This demo runs a complete client-server session while tracking:
- Connection lifecycle events (start, success, failure)
- TLS handshake timing with microsecond precision
- I/O operations with byte counts
- Kill-switch activation events
- Aggregated metrics for monitoring dashboards

All examples include proper error handling and demonstrate best practices for:
- Resource cleanup
- Error reporting
- Security validation
- Operational monitoring

## License

MIT / Apache 2.0 (dual licensed)

## Development

### Quick Start

```bash
# Install git hooks and validation tools
make install-hooks

# Format code
make format

# Run static analysis
make check

# Build and test
make build
make test
```

The project includes industrial-standard pre-commit hooks that validate:
- Code formatting (clang-format)
- Static analysis (clang-tidy, cppcheck)
- Build verification
- Test execution
- Security checks

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for complete development guide.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Documentation

- [BUILD.md](docs/BUILD.md) - Build status and compilation instructions
- [DEVELOPMENT.md](docs/DEVELOPMENT.md) - Development workflow and tooling
- [Go Bindings](bindings/go/README.md) - Go language bindings documentation
