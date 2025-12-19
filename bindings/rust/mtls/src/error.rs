//! Error types for the mTLS library.
//!
//! This module provides rich error types with categorization matching
//! the C library's error code structure.

use std::error::Error as StdError;
use std::fmt;
use std::io;

/// Error codes matching the C library.
///
/// Error codes are organized into categories by range:
/// - 1xx: Configuration errors
/// - 2xx: Network/connection errors
/// - 3xx: TLS/certificate errors
/// - 4xx: Identity/verification errors
/// - 5xx: Policy errors
/// - 6xx: I/O errors
/// - 9xx: Internal errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    // Success
    Ok = 0,

    // Configuration errors (1xx)
    InvalidConfig = 100,
    InvalidArgument = 101,
    CaCertNotFound = 102,
    CertNotFound = 103,
    KeyNotFound = 104,
    CaCertParseFailed = 105,
    CertParseFailed = 106,
    KeyParseFailed = 107,
    CertKeyMismatch = 108,
    OutOfMemory = 109,
    CtxNotInitialized = 110,

    // Network errors (2xx)
    ConnectFailed = 200,
    ConnectTimeout = 201,
    DnsFailed = 202,
    SocketCreateFailed = 203,
    SocketBindFailed = 204,
    SocketListenFailed = 205,
    AcceptFailed = 206,
    ConnectionRefused = 207,
    NetworkUnreachable = 208,
    HostUnreachable = 209,
    AddressInUse = 210,
    InvalidAddress = 211,

    // TLS errors (3xx)
    TlsInitFailed = 300,
    TlsHandshakeFailed = 301,
    TlsVersionMismatch = 302,
    TlsCipherMismatch = 303,
    CertExpired = 304,
    CertNotYetValid = 305,
    CertRevoked = 306,
    CertUntrusted = 307,
    CertChainTooLong = 308,
    CertSignatureInvalid = 309,
    NoPeerCert = 310,
    HostnameMismatch = 311,
    TlsShutdownFailed = 312,

    // Identity errors (4xx)
    IdentityMismatch = 400,
    SanNotAllowed = 401,
    SpiffeParseFailed = 402,
    CnNotAllowed = 403,
    NoAllowedIdentity = 404,
    IdentityTooLong = 405,

    // Policy errors (5xx)
    KillSwitchEnabled = 500,
    PolicyDenied = 501,
    ConnectionNotAllowed = 502,

    // I/O errors (6xx)
    ReadFailed = 600,
    WriteFailed = 601,
    ConnectionClosed = 602,
    ConnectionReset = 603,
    ReadTimeout = 604,
    WriteTimeout = 605,
    WouldBlock = 606,
    PartialWrite = 607,
    Eof = 608,

    // Internal errors (9xx)
    Internal = 900,
    NotImplemented = 901,
    ContextCreationFailed = 902,
    ConnectionFailed = 903,
    ListenerFailed = 904,
    ListenerClosed = 905,
    Timeout = 906,
    Unknown = 999,
}

impl ErrorCode {
    /// Convert from a raw i32 error code.
    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => ErrorCode::Ok,
            // Configuration errors
            100 => ErrorCode::InvalidConfig,
            101 => ErrorCode::InvalidArgument,
            102 => ErrorCode::CaCertNotFound,
            103 => ErrorCode::CertNotFound,
            104 => ErrorCode::KeyNotFound,
            105 => ErrorCode::CaCertParseFailed,
            106 => ErrorCode::CertParseFailed,
            107 => ErrorCode::KeyParseFailed,
            108 => ErrorCode::CertKeyMismatch,
            109 => ErrorCode::OutOfMemory,
            110 => ErrorCode::CtxNotInitialized,
            // Network errors
            200 => ErrorCode::ConnectFailed,
            201 => ErrorCode::ConnectTimeout,
            202 => ErrorCode::DnsFailed,
            203 => ErrorCode::SocketCreateFailed,
            204 => ErrorCode::SocketBindFailed,
            205 => ErrorCode::SocketListenFailed,
            206 => ErrorCode::AcceptFailed,
            207 => ErrorCode::ConnectionRefused,
            208 => ErrorCode::NetworkUnreachable,
            209 => ErrorCode::HostUnreachable,
            210 => ErrorCode::AddressInUse,
            211 => ErrorCode::InvalidAddress,
            // TLS errors
            300 => ErrorCode::TlsInitFailed,
            301 => ErrorCode::TlsHandshakeFailed,
            302 => ErrorCode::TlsVersionMismatch,
            303 => ErrorCode::TlsCipherMismatch,
            304 => ErrorCode::CertExpired,
            305 => ErrorCode::CertNotYetValid,
            306 => ErrorCode::CertRevoked,
            307 => ErrorCode::CertUntrusted,
            308 => ErrorCode::CertChainTooLong,
            309 => ErrorCode::CertSignatureInvalid,
            310 => ErrorCode::NoPeerCert,
            311 => ErrorCode::HostnameMismatch,
            312 => ErrorCode::TlsShutdownFailed,
            // Identity errors
            400 => ErrorCode::IdentityMismatch,
            401 => ErrorCode::SanNotAllowed,
            402 => ErrorCode::SpiffeParseFailed,
            403 => ErrorCode::CnNotAllowed,
            404 => ErrorCode::NoAllowedIdentity,
            405 => ErrorCode::IdentityTooLong,
            // Policy errors
            500 => ErrorCode::KillSwitchEnabled,
            501 => ErrorCode::PolicyDenied,
            502 => ErrorCode::ConnectionNotAllowed,
            // I/O errors
            600 => ErrorCode::ReadFailed,
            601 => ErrorCode::WriteFailed,
            602 => ErrorCode::ConnectionClosed,
            603 => ErrorCode::ConnectionReset,
            604 => ErrorCode::ReadTimeout,
            605 => ErrorCode::WriteTimeout,
            606 => ErrorCode::WouldBlock,
            607 => ErrorCode::PartialWrite,
            608 => ErrorCode::Eof,
            // Internal errors
            900 => ErrorCode::Internal,
            901 => ErrorCode::NotImplemented,
            902 => ErrorCode::ContextCreationFailed,
            903 => ErrorCode::ConnectionFailed,
            904 => ErrorCode::ListenerFailed,
            905 => ErrorCode::ListenerClosed,
            906 => ErrorCode::Timeout,
            _ => ErrorCode::Unknown,
        }
    }

    /// Returns true if this is a configuration error (1xx).
    pub fn is_config(&self) -> bool {
        let code = *self as i32;
        (100..200).contains(&code)
    }

    /// Returns true if this is a network error (2xx).
    pub fn is_network(&self) -> bool {
        let code = *self as i32;
        (200..300).contains(&code)
    }

    /// Returns true if this is a TLS/certificate error (3xx).
    pub fn is_tls(&self) -> bool {
        let code = *self as i32;
        (300..400).contains(&code)
    }

    /// Returns true if this is an identity error (4xx).
    pub fn is_identity(&self) -> bool {
        let code = *self as i32;
        (400..500).contains(&code)
    }

    /// Returns true if this is a policy error (5xx).
    pub fn is_policy(&self) -> bool {
        let code = *self as i32;
        (500..600).contains(&code)
    }

    /// Returns true if this is an I/O error (6xx).
    pub fn is_io(&self) -> bool {
        let code = *self as i32;
        (600..700).contains(&code)
    }

    /// Returns true if this error is potentially recoverable.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ErrorCode::ConnectTimeout
                | ErrorCode::ReadTimeout
                | ErrorCode::WriteTimeout
                | ErrorCode::WouldBlock
        )
    }

    /// Returns the error code name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            ErrorCode::Ok => "OK",
            ErrorCode::InvalidConfig => "INVALID_CONFIG",
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::CaCertNotFound => "CA_CERT_NOT_FOUND",
            ErrorCode::CertNotFound => "CERT_NOT_FOUND",
            ErrorCode::KeyNotFound => "KEY_NOT_FOUND",
            ErrorCode::CaCertParseFailed => "CA_CERT_PARSE_FAILED",
            ErrorCode::CertParseFailed => "CERT_PARSE_FAILED",
            ErrorCode::KeyParseFailed => "KEY_PARSE_FAILED",
            ErrorCode::CertKeyMismatch => "CERT_KEY_MISMATCH",
            ErrorCode::OutOfMemory => "OUT_OF_MEMORY",
            ErrorCode::CtxNotInitialized => "CTX_NOT_INITIALIZED",
            ErrorCode::ConnectFailed => "CONNECT_FAILED",
            ErrorCode::ConnectTimeout => "CONNECT_TIMEOUT",
            ErrorCode::DnsFailed => "DNS_FAILED",
            ErrorCode::SocketCreateFailed => "SOCKET_CREATE_FAILED",
            ErrorCode::SocketBindFailed => "SOCKET_BIND_FAILED",
            ErrorCode::SocketListenFailed => "SOCKET_LISTEN_FAILED",
            ErrorCode::AcceptFailed => "ACCEPT_FAILED",
            ErrorCode::ConnectionRefused => "CONNECTION_REFUSED",
            ErrorCode::NetworkUnreachable => "NETWORK_UNREACHABLE",
            ErrorCode::HostUnreachable => "HOST_UNREACHABLE",
            ErrorCode::AddressInUse => "ADDRESS_IN_USE",
            ErrorCode::InvalidAddress => "INVALID_ADDRESS",
            ErrorCode::TlsInitFailed => "TLS_INIT_FAILED",
            ErrorCode::TlsHandshakeFailed => "TLS_HANDSHAKE_FAILED",
            ErrorCode::TlsVersionMismatch => "TLS_VERSION_MISMATCH",
            ErrorCode::TlsCipherMismatch => "TLS_CIPHER_MISMATCH",
            ErrorCode::CertExpired => "CERT_EXPIRED",
            ErrorCode::CertNotYetValid => "CERT_NOT_YET_VALID",
            ErrorCode::CertRevoked => "CERT_REVOKED",
            ErrorCode::CertUntrusted => "CERT_UNTRUSTED",
            ErrorCode::CertChainTooLong => "CERT_CHAIN_TOO_LONG",
            ErrorCode::CertSignatureInvalid => "CERT_SIGNATURE_INVALID",
            ErrorCode::NoPeerCert => "NO_PEER_CERT",
            ErrorCode::HostnameMismatch => "HOSTNAME_MISMATCH",
            ErrorCode::TlsShutdownFailed => "TLS_SHUTDOWN_FAILED",
            ErrorCode::IdentityMismatch => "IDENTITY_MISMATCH",
            ErrorCode::SanNotAllowed => "SAN_NOT_ALLOWED",
            ErrorCode::SpiffeParseFailed => "SPIFFE_PARSE_FAILED",
            ErrorCode::CnNotAllowed => "CN_NOT_ALLOWED",
            ErrorCode::NoAllowedIdentity => "NO_ALLOWED_IDENTITY",
            ErrorCode::IdentityTooLong => "IDENTITY_TOO_LONG",
            ErrorCode::KillSwitchEnabled => "KILL_SWITCH_ENABLED",
            ErrorCode::PolicyDenied => "POLICY_DENIED",
            ErrorCode::ConnectionNotAllowed => "CONNECTION_NOT_ALLOWED",
            ErrorCode::ReadFailed => "READ_FAILED",
            ErrorCode::WriteFailed => "WRITE_FAILED",
            ErrorCode::ConnectionClosed => "CONNECTION_CLOSED",
            ErrorCode::ConnectionReset => "CONNECTION_RESET",
            ErrorCode::ReadTimeout => "READ_TIMEOUT",
            ErrorCode::WriteTimeout => "WRITE_TIMEOUT",
            ErrorCode::WouldBlock => "WOULD_BLOCK",
            ErrorCode::PartialWrite => "PARTIAL_WRITE",
            ErrorCode::Eof => "EOF",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::NotImplemented => "NOT_IMPLEMENTED",
            ErrorCode::ContextCreationFailed => "CONTEXT_CREATION_FAILED",
            ErrorCode::ConnectionFailed => "CONNECTION_FAILED",
            ErrorCode::ListenerFailed => "LISTENER_FAILED",
            ErrorCode::ListenerClosed => "LISTENER_CLOSED",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::Unknown => "UNKNOWN",
        }
    }

    /// Returns the error category name.
    pub fn category(&self) -> &'static str {
        if self.is_config() {
            "Configuration"
        } else if self.is_network() {
            "Network"
        } else if self.is_tls() {
            "TLS"
        } else if self.is_identity() {
            "Identity"
        } else if self.is_policy() {
            "Policy"
        } else if self.is_io() {
            "I/O"
        } else {
            "Internal"
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// The main error type for mTLS operations.
#[derive(Debug)]
pub struct Error {
    code: ErrorCode,
    message: String,
    os_error: Option<i32>,
    tls_error: Option<u64>,
    source_file: Option<String>,
    source_line: Option<i32>,
}

impl Error {
    /// Create a new error with the given code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            os_error: None,
            tls_error: None,
            source_file: None,
            source_line: None,
        }
    }

    /// Create an error from a C mtls_err structure.
    pub(crate) fn from_c_err(c_err: &mtls_sys::mtls_err) -> Self {
        let code = ErrorCode::from_i32(c_err.code as i32);

        let message = unsafe {
            std::ffi::CStr::from_ptr(c_err.message.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let os_error = if c_err.os_errno != 0 {
            Some(c_err.os_errno)
        } else {
            None
        };

        let tls_error: Option<u64> = if c_err.ssl_err != 0 {
            Some(c_err.ssl_err.into())
        } else {
            None
        };

        let source_file = if !c_err.file.is_null() {
            Some(unsafe {
                std::ffi::CStr::from_ptr(c_err.file)
                    .to_string_lossy()
                    .into_owned()
            })
        } else {
            None
        };

        let source_line = if c_err.line != 0 {
            Some(c_err.line)
        } else {
            None
        };

        Error {
            code,
            message,
            os_error,
            tls_error,
            source_file,
            source_line,
        }
    }

    /// Returns the error code.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the OS error code if available.
    pub fn os_error(&self) -> Option<i32> {
        self.os_error
    }

    /// Returns the TLS/SSL error code if available.
    pub fn tls_error(&self) -> Option<u64> {
        self.tls_error
    }

    /// Returns the source file if available (debug info).
    pub fn source_file(&self) -> Option<&str> {
        self.source_file.as_deref()
    }

    /// Returns the source line if available (debug info).
    pub fn source_line(&self) -> Option<i32> {
        self.source_line
    }

    /// Returns true if this is a configuration error.
    pub fn is_config(&self) -> bool {
        self.code.is_config()
    }

    /// Returns true if this is a network error.
    pub fn is_network(&self) -> bool {
        self.code.is_network()
    }

    /// Returns true if this is a TLS/certificate error.
    pub fn is_tls(&self) -> bool {
        self.code.is_tls()
    }

    /// Returns true if this is an identity error.
    pub fn is_identity(&self) -> bool {
        self.code.is_identity()
    }

    /// Returns true if this is a policy error.
    pub fn is_policy(&self) -> bool {
        self.code.is_policy()
    }

    /// Returns true if this is an I/O error.
    pub fn is_io(&self) -> bool {
        self.code.is_io()
    }

    /// Returns true if this error is potentially recoverable.
    pub fn is_recoverable(&self) -> bool {
        self.code.is_recoverable()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl StdError for Error {}

/// Convert to std::io::Error for Read/Write trait compatibility.
impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match e.code {
            ErrorCode::ConnectTimeout
            | ErrorCode::ReadTimeout
            | ErrorCode::WriteTimeout
            | ErrorCode::Timeout => io::ErrorKind::TimedOut,
            ErrorCode::ConnectionClosed | ErrorCode::ConnectionReset | ErrorCode::Eof => {
                io::ErrorKind::ConnectionReset
            }
            ErrorCode::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            // `io::ErrorKind::{NetworkUnreachable,HostUnreachable}` require newer Rust.
            // For our MSRV (1.78), map these to `Other` while preserving the original error.
            ErrorCode::NetworkUnreachable | ErrorCode::HostUnreachable => io::ErrorKind::Other,
            ErrorCode::InvalidAddress | ErrorCode::InvalidArgument => io::ErrorKind::InvalidInput,
            ErrorCode::WouldBlock => io::ErrorKind::WouldBlock,
            ErrorCode::AddressInUse => io::ErrorKind::AddrInUse,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// Type alias for Result with mTLS Error.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_categories() {
        assert!(ErrorCode::InvalidConfig.is_config());
        assert!(ErrorCode::ConnectFailed.is_network());
        assert!(ErrorCode::TlsHandshakeFailed.is_tls());
        assert!(ErrorCode::IdentityMismatch.is_identity());
        assert!(ErrorCode::KillSwitchEnabled.is_policy());
        assert!(ErrorCode::ReadFailed.is_io());
    }

    #[test]
    fn test_error_code_from_i32() {
        assert_eq!(ErrorCode::from_i32(0), ErrorCode::Ok);
        assert_eq!(ErrorCode::from_i32(100), ErrorCode::InvalidConfig);
        assert_eq!(ErrorCode::from_i32(200), ErrorCode::ConnectFailed);
        assert_eq!(ErrorCode::from_i32(300), ErrorCode::TlsInitFailed);
        assert_eq!(ErrorCode::from_i32(12345), ErrorCode::Unknown);
    }

    #[test]
    fn test_error_recoverable() {
        assert!(ErrorCode::ConnectTimeout.is_recoverable());
        assert!(ErrorCode::ReadTimeout.is_recoverable());
        assert!(!ErrorCode::CertExpired.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = Error::new(ErrorCode::ConnectFailed, "connection failed");
        assert_eq!(err.to_string(), "connection failed");
    }

    #[test]
    fn test_error_to_io_error() {
        let err = Error::new(ErrorCode::ConnectTimeout, "timeout");
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
    }
}
