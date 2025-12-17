# mTLS Rust Bindings

Safe, idiomatic Rust bindings for the mTLS C library.

## Crate Structure

- **mtls-sys**: Low-level FFI bindings generated with bindgen
- **mtls**: Safe, high-level Rust API

## Features

- RAII memory management via `Drop` trait
- Implements `std::io::Read` and `std::io::Write` for connections
- Builder pattern for configuration
- Rich error types with categorization
- Event observability with callback support
- Thread safety via Rust's type system

## Quick Start

### Client Example

```rust
use mtls::{Config, Context};
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .ca_cert_file("ca.pem")
        .cert_file("client.pem", "client.key")
        .build()?;

    let ctx = Context::new(&config)?;
    let mut conn = ctx.connect("server:8443")?;

    conn.write_all(b"Hello, mTLS!")?;

    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf)?;
    println!("Received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
```

### Server Example

```rust
use mtls::{Config, Context};
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .ca_cert_file("ca.pem")
        .cert_file("server.pem", "server.key")
        .require_client_cert(true)
        .build()?;

    let ctx = Context::new(&config)?;
    let listener = ctx.listen("0.0.0.0:8443")?;

    for conn_result in listener.incoming() {
        match conn_result {
            Ok(mut conn) => {
                // Handle connection...
                let mut buf = [0u8; 1024];
                let n = conn.read(&mut buf)?;
                conn.write_all(&buf[..n])?;
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }

    Ok(())
}
```

## API Overview

### Configuration

```rust
let config = Config::builder()
    .ca_cert_file("/path/to/ca.pem")
    .cert_file("/path/to/cert.pem", "/path/to/key.pem")
    .min_tls_version(TlsVersion::Tls12)
    .max_tls_version(TlsVersion::Tls13)
    .connect_timeout(Duration::from_secs(10))
    .read_timeout(Duration::from_secs(30))
    .write_timeout(Duration::from_secs(30))
    .require_client_cert(true)
    .verify_hostname(true)
    .allowed_sans(vec!["client.example.com", "*.example.com"])
    .build()?;
```

### PEM Data Loading

```rust
let config = Config::builder()
    .ca_cert_pem(include_bytes!("../certs/ca.pem"))
    .cert_pem(
        include_bytes!("../certs/client.pem"),
        include_bytes!("../certs/client.key"),
    )
    .build()?;
```

### Peer Identity

```rust
if let Some(identity) = conn.peer_identity() {
    println!("Common Name: {}", identity.common_name);
    println!("SANs: {:?}", identity.sans);
    if let Some(spiffe_id) = &identity.spiffe_id {
        println!("SPIFFE ID: {}", spiffe_id);
    }
    println!("Certificate valid: {}", identity.is_valid());
    if let Some(ttl) = identity.ttl() {
        println!("Time until expiry: {:?}", ttl);
    }
}
```

### Event Observability

```rust
let _handle = ctx.set_observer(|event| {
    println!("[{}] {} from {}",
        event.timestamp_us,
        event.event_type,
        event.remote_addr
    );
})?;
```

### Kill Switch

```rust
// Enable kill switch (blocks all new connections)
ctx.set_kill_switch(true);

// Check status
if ctx.is_kill_switch_enabled() {
    println!("Kill switch is active");
}

// Disable kill switch
ctx.set_kill_switch(false);
```

## Thread Safety

- `Context` is `Send + Sync` - can be shared across threads
- `Conn` is `Send` but NOT `Sync` - use from one thread at a time
- `Listener` is `Send` but NOT `Sync` - use from one thread at a time

## Error Handling

Errors are categorized by code range:

| Range | Category    | Examples                        |
|-------|-------------|--------------------------------|
| 1xx   | Config      | Invalid config, cert not found |
| 2xx   | Network     | Connect failed, DNS failed     |
| 3xx   | TLS         | Handshake failed, cert expired |
| 4xx   | Identity    | SAN not allowed, CN mismatch   |
| 5xx   | Policy      | Kill switch enabled            |
| 6xx   | I/O         | Read/write failed, timeout     |
| 9xx   | Internal    | Unknown errors                 |

```rust
match result {
    Ok(conn) => { /* success */ }
    Err(e) => {
        if e.is_network() {
            println!("Network error: {}", e);
        } else if e.is_tls() {
            println!("TLS error: {}", e);
        } else if e.is_recoverable() {
            println!("Recoverable error, retrying...");
        }
    }
}
```

## Building

```bash
# Build the library
cargo build

# Run tests
cargo test

# Run examples
cargo run --example simple_client -- server:8443 ca.pem client.pem client.key
cargo run --example simple_server -- 0.0.0.0:8443 ca.pem server.pem server.key
cargo run --example echo_server -- 0.0.0.0:8443 ca.pem server.pem server.key
```

## Requirements

- Rust 1.70+
- The mTLS C library must be installed
- OpenSSL development headers

## License

MIT OR Apache-2.0
