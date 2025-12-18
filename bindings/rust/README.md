# mTLS Rust Bindings

Safe, idiomatic Rust bindings for the mTLS C library.

## Crate Structure

- **mtls-sys**: Low-level FFI bindings generated with bindgen
- **mtls**: Safe, high-level Rust API

## Features

- RAII memory management via `Drop` trait
- Implements `std::io::Read` and `std::io::Write` for connections
- **Async support** via `async-tokio` feature (thread pool wrapper)
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

### Server Example (Simple)

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

    // Simple loop - works for single-threaded servers
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

### Server Example (Multi-threaded with Graceful Shutdown)

When you need to shut down the listener from another thread (e.g., for graceful shutdown), use `ListenerShutdownHandle`. This avoids sharing `Listener` across threads and avoids unsafe “unlock-before-accept” patterns.

```rust
use mtls::{Config, Context, ListenerShutdownHandle};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .ca_cert_file("ca.pem")
        .cert_file("server.pem", "server.key")
        .require_client_cert(true)
        .build()?;

    let ctx = Context::new(&config)?;
    let listener = ctx.listen("0.0.0.0:8443")?;
    let shutdown: ListenerShutdownHandle = listener
        .shutdown_handle()
        .expect("listener should be open");
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Spawn acceptor thread
    let stop_acceptor = stop_flag.clone();
    let acceptor_handle = thread::spawn(move || {
        loop {
            if stop_acceptor.load(Ordering::SeqCst) {
                break;
            }

            let accept_result = listener.accept();

            match accept_result {
                Ok(mut conn) => {
                    // Handle connection (spawn handler thread if needed)...
                    thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        if let Ok(n) = conn.read(&mut buf) {
                            let _ = conn.write_all(&buf[..n]);
                        }
                        conn.close();
                    });
                }
                Err(_) => {
                    if stop_acceptor.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        }
    });

    // ... do work ...

    // Graceful shutdown: signal stop and shutdown listener
    stop_flag.store(true, Ordering::SeqCst);
    shutdown.shutdown(); // Interrupts blocking accept() calls

    acceptor_handle.join().unwrap();
    Ok(())
}
```

**Important Notes on Listener Shutdown:**
- `accept()` blocks until a connection arrives or the listener is shut down
- `shutdown()` interrupts blocking `accept()` calls by calling `shutdown()` on the underlying socket at the OS level
- Prefer `ListenerShutdownHandle` for cross-thread shutdown (no locking and no unsafe pointers)

## API Overview

### Listener

The `Listener` type provides three main ways to accept connections:

1. **`incoming()` iterator** - Simplest for single-threaded servers:
   ```rust
   for conn_result in listener.incoming() {
       match conn_result {
           Ok(conn) => { /* handle */ }
           Err(e) => { /* error */ }
       }
   }
   ```

2. **`accept()` loop** - More control, suitable for single-threaded use:
   ```rust
   loop {
       match listener.accept() {
           Ok(conn) => { /* handle */ }
           Err(e) => { /* error */ }
       }
   }
   ```

3. **`serve()` method** - Convenience method that handles the accept loop:
   ```rust
   listener.serve(|conn| {
       thread::spawn(move || {
           // Handle connection in separate thread
       });
       Ok(())
   })?;
   ```

For multi-threaded scenarios where you need to shut down from another thread, use `Arc<Mutex<Listener>>` and release the lock before calling `accept()`, as shown in the multi-threaded example above.

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
- `Listener` is `Send` but NOT `Sync` - can be moved between threads, but use from one thread at a time

### Listener Thread Safety and Shutdown

The `Listener` type can be moved between threads (`Send`), but concurrent access requires synchronization:

- **Single-threaded use**: Direct use is fine - `accept()` blocks until a connection arrives
- **Multi-threaded shutdown**: Prefer `ListenerShutdownHandle` obtained via `listener.shutdown_handle()`
  - It can be called from another thread/task to interrupt a blocking `accept()`

See the "Multi-threaded with Graceful Shutdown" example above for the correct pattern.

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

## Async Support

The library provides async support via the `async-tokio` feature flag. This uses a thread pool wrapper to provide async-compatible APIs while keeping the underlying blocking C library unchanged.

### Enabling Async Support

Add the `async-tokio` feature to your `Cargo.toml`:

```toml
[dependencies]
mtls = { path = "../mtls", features = ["async-tokio"] }
```

### Async API

With the `async-tokio` feature enabled, the following async methods are available:

- `Context::connect_async()` - Async client connection
- `Listener::accept_async()` - Async server accept
- `AsyncConn` - Async connection wrapper with explicit async I/O methods:
  - `read(&mut self, buf: &mut [u8])`
  - `write(&mut self, buf: &[u8])`
  - `write_all(&mut self, buf: &[u8])`
  - `flush(&mut self)`
  - `close(&mut self)`

### Async Examples

```bash
# Async client
cargo run --example async_client --features async-tokio -- server:8443 ca.pem client.pem client.key

# Async server
cargo run --example async_server --features async-tokio -- 0.0.0.0:8443 ca.pem server.pem server.key
```

### Performance Considerations

The async API uses `tokio::task::spawn_blocking` to execute blocking operations on a thread pool. This provides good performance for most use cases (up to ~10K-50K concurrent connections) but has some overhead compared to true async I/O.

For maximum performance with extreme concurrency (100K+ connections), true async support in the C library (non-blocking sockets + poll/epoll/kqueue) would be required.

## Building

```bash
# From bindings/rust/
cd bindings/rust

# Build the Rust workspace
cargo build

# Build with async support
cargo build --features async-tokio

# Run tests
cargo test

# Run examples
cargo run --example simple_client -- server:8443 ca.pem client.pem client.key
cargo run --example simple_server -- 0.0.0.0:8443 ca.pem server.pem server.key
cargo run --example echo_server -- 0.0.0.0:8443 ca.pem server.pem server.key

# Run async examples (requires async-tokio feature)
cargo run --example async_client --features async-tokio -- server:8443 ca.pem client.pem client.key
cargo run --example async_server --features async-tokio -- 0.0.0.0:8443 ca.pem server.pem server.key
```

## Requirements

- Rust 1.78+
- The mTLS C library must be installed
- OpenSSL development headers

## License

MIT OR Apache-2.0
