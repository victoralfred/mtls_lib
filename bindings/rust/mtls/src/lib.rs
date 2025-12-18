//! Safe, idiomatic Rust bindings for the mTLS C library.
//!
//! This crate provides a safe, ergonomic API for mutual TLS (mTLS) connections
//! using the mTLS C library.
//!
//! # Features
//!
//! - Safe wrappers around the C library with RAII cleanup
//! - Implements `std::io::Read` and `std::io::Write` for connections
//! - Builder pattern for configuration
//! - Rich error types with categorization
//! - Event observability with callback support
//!
//! # Quick Start
//!
//! ## Client Example
//!
//! ```ignore
//! use mtls::{Config, Context};
//! use std::io::{Read, Write};
//!
//! let config = Config::builder()
//!     .ca_cert_file("ca.pem")
//!     .cert_file("client.pem", "client.key")
//!     .build()?;
//!
//! let ctx = Context::new(&config)?;
//! let mut conn = ctx.connect("server:8443")?;
//!
//! conn.write_all(b"Hello, mTLS!")?;
//!
//! let mut buf = [0u8; 1024];
//! let n = conn.read(&mut buf)?;
//! println!("Received: {}", String::from_utf8_lossy(&buf[..n]));
//! ```
//!
//! ## Server Example
//!
//! ```ignore
//! use mtls::{Config, Context};
//! use std::io::{Read, Write};
//!
//! let config = Config::builder()
//!     .ca_cert_file("ca.pem")
//!     .cert_file("server.pem", "server.key")
//!     .require_client_cert(true)
//!     .build()?;
//!
//! let ctx = Context::new(&config)?;
//! let listener = ctx.listen("0.0.0.0:8443")?;
//!
//! loop {
//!     let mut conn = listener.accept()?;
//!     // Handle connection...
//! }
//! ```
//!
//! # Thread Safety
//!
//! - `Context` is `Send + Sync` - can be shared across threads
//! - `Conn` is `Send` but NOT `Sync` - use from one thread at a time
//! - `Listener` is `Send` but NOT `Sync` - use from one thread at a time

// Modules
mod config;
mod conn;
mod context;
mod error;
mod event;
mod ffi_helpers;
mod identity;
mod listener;

// Re-exports
pub use config::{Config, ConfigBuilder, TlsVersion};
pub use conn::Conn;
pub use context::Context;
pub use error::{Error, ErrorCode, Result};
pub use event::{Event, EventType};
pub use identity::{ConnState, PeerIdentity};
pub use listener::{Listener, ListenerShutdownHandle};

// Async re-exports
#[cfg(feature = "async-tokio")]
pub use conn::AsyncConn;

/// Returns the library version string.
pub fn version() -> String {
    unsafe {
        let ptr = mtls_sys::mtls_version();
        if ptr.is_null() {
            return String::from("unknown");
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

/// Returns the library version components.
pub fn version_components() -> (i32, i32, i32) {
    let mut major: i32 = 0;
    let mut minor: i32 = 0;
    let mut patch: i32 = 0;
    unsafe {
        mtls_sys::mtls_version_components(&mut major, &mut minor, &mut patch);
    }
    (major, minor, patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
        assert!(v.contains('.'));
    }

    #[test]
    fn test_version_components() {
        let (major, minor, patch) = version_components();
        assert!(major >= 0);
        assert!(minor >= 0);
        assert!(patch >= 0);
    }
}
