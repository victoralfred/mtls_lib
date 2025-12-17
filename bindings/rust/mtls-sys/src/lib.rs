//! Low-level FFI bindings for the mTLS C library.
//!
//! This crate provides raw, unsafe bindings to the mTLS C library.
//! For a safe, idiomatic Rust API, use the `mtls` crate instead.
//!
//! # Safety
//!
//! All functions in this crate are unsafe and require careful handling of:
//! - Null pointers
//! - Memory allocation and deallocation
//! - Thread safety guarantees
//!
//! # Example
//!
//! ```ignore
//! use mtls_sys::*;
//!
//! unsafe {
//!     let version = mtls_version();
//!     let version_str = std::ffi::CStr::from_ptr(version);
//!     println!("mTLS version: {}", version_str.to_string_lossy());
//! }
//! ```

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::all)]

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_version() {
        unsafe {
            let version = mtls_version();
            assert!(!version.is_null());
            let version_str = CStr::from_ptr(version).to_string_lossy();
            assert!(version_str.contains('.'), "Version should contain a dot");
        }
    }

    #[test]
    fn test_version_components() {
        unsafe {
            let mut major: i32 = 0;
            let mut minor: i32 = 0;
            let mut patch: i32 = 0;
            mtls_version_components(&mut major, &mut minor, &mut patch);
            assert!(major >= 0);
            assert!(minor >= 0);
            assert!(patch >= 0);
        }
    }

    #[test]
    fn test_error_init() {
        unsafe {
            let mut err: mtls_err = std::mem::zeroed();
            mtls_err_init(&mut err);
            assert_eq!(err.code, mtls_error_code::MTLS_OK);
        }
    }

    #[test]
    fn test_config_init() {
        unsafe {
            let mut config = mtls_config::default();
            mtls_config_init(&mut config);
            // Check defaults
            assert_eq!(config.min_tls_version, mtls_tls_version::MTLS_TLS_1_2);
            assert_eq!(config.max_tls_version, mtls_tls_version::MTLS_TLS_1_3);
            assert!(config.require_client_cert);
            assert!(config.verify_hostname);
        }
    }
}
