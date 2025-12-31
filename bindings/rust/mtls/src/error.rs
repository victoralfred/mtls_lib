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
    HsmInitFailed = 111,
    HsmPinRequired = 112,
    HsmPinInvalid = 113,
    HsmKeyNotFound = 114,
    HsmOperationFailed = 115,
    HsmSlotNotFound = 116,
    HsmModuleNotFound = 117,

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
    PoolExhausted = 212,
    PoolAcquireTimeout = 213,
    PoolClosed = 214,
    ConnUnhealthy = 215,

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
    OcspFailed = 313,
    OcspTimeout = 314,
    OcspResponderError = 315,
    CrlFailed = 316,
    CrlDownloadFailed = 317,
    CrlExpired = 318,
    CrlParseFailed = 319,
    PinValidationFailed = 320,
    PinInvalidFormat = 321,
    PinComputeFailed = 322,
    CtValidationFailed = 323,
    CtNoScts = 324,
    CtInsufficientScts = 325,
    CtInvalidSct = 326,
    CtUnknownLog = 327,
    CtLogListParse = 328,

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
    RateLimited = 503,
    RateLimitGlobal = 504,
    RateLimitClient = 505,

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
    DeadlineExceeded = 609,
    Cancelled = 610,
    AsyncPending = 611,
    AsyncCancelled = 612,
    EventLoopError = 613,

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
            111 => ErrorCode::HsmInitFailed,
            112 => ErrorCode::HsmPinRequired,
            113 => ErrorCode::HsmPinInvalid,
            114 => ErrorCode::HsmKeyNotFound,
            115 => ErrorCode::HsmOperationFailed,
            116 => ErrorCode::HsmSlotNotFound,
            117 => ErrorCode::HsmModuleNotFound,
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
            212 => ErrorCode::PoolExhausted,
            213 => ErrorCode::PoolAcquireTimeout,
            214 => ErrorCode::PoolClosed,
            215 => ErrorCode::ConnUnhealthy,
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
            313 => ErrorCode::OcspFailed,
            314 => ErrorCode::OcspTimeout,
            315 => ErrorCode::OcspResponderError,
            316 => ErrorCode::CrlFailed,
            317 => ErrorCode::CrlDownloadFailed,
            318 => ErrorCode::CrlExpired,
            319 => ErrorCode::CrlParseFailed,
            320 => ErrorCode::PinValidationFailed,
            321 => ErrorCode::PinInvalidFormat,
            322 => ErrorCode::PinComputeFailed,
            323 => ErrorCode::CtValidationFailed,
            324 => ErrorCode::CtNoScts,
            325 => ErrorCode::CtInsufficientScts,
            326 => ErrorCode::CtInvalidSct,
            327 => ErrorCode::CtUnknownLog,
            328 => ErrorCode::CtLogListParse,
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
            503 => ErrorCode::RateLimited,
            504 => ErrorCode::RateLimitGlobal,
            505 => ErrorCode::RateLimitClient,
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
            609 => ErrorCode::DeadlineExceeded,
            610 => ErrorCode::Cancelled,
            611 => ErrorCode::AsyncPending,
            612 => ErrorCode::AsyncCancelled,
            613 => ErrorCode::EventLoopError,
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

    /// Returns true if this is an OCSP error.
    pub fn is_ocsp(&self) -> bool {
        matches!(
            self,
            ErrorCode::OcspFailed | ErrorCode::OcspTimeout | ErrorCode::OcspResponderError
        )
    }

    /// Returns true if this is a CRL error.
    pub fn is_crl(&self) -> bool {
        matches!(
            self,
            ErrorCode::CrlFailed
                | ErrorCode::CrlDownloadFailed
                | ErrorCode::CrlExpired
                | ErrorCode::CrlParseFailed
        )
    }

    /// Returns true if this is a revocation error (OCSP or CRL).
    pub fn is_revocation(&self) -> bool {
        self.is_ocsp() || self.is_crl()
    }

    /// Returns true if this is a certificate pinning error.
    pub fn is_pinning(&self) -> bool {
        matches!(
            self,
            ErrorCode::PinValidationFailed
                | ErrorCode::PinInvalidFormat
                | ErrorCode::PinComputeFailed
        )
    }

    /// Returns true if this is a Certificate Transparency error.
    pub fn is_ct(&self) -> bool {
        matches!(
            self,
            ErrorCode::CtValidationFailed
                | ErrorCode::CtNoScts
                | ErrorCode::CtInsufficientScts
                | ErrorCode::CtInvalidSct
                | ErrorCode::CtUnknownLog
                | ErrorCode::CtLogListParse
        )
    }

    /// Returns true if this is an HSM error.
    pub fn is_hsm(&self) -> bool {
        matches!(
            self,
            ErrorCode::HsmInitFailed
                | ErrorCode::HsmPinRequired
                | ErrorCode::HsmPinInvalid
                | ErrorCode::HsmKeyNotFound
                | ErrorCode::HsmOperationFailed
                | ErrorCode::HsmSlotNotFound
                | ErrorCode::HsmModuleNotFound
        )
    }

    /// Returns true if this is a rate limiting error.
    pub fn is_rate_limit(&self) -> bool {
        matches!(
            self,
            ErrorCode::RateLimited | ErrorCode::RateLimitGlobal | ErrorCode::RateLimitClient
        )
    }

    /// Returns true if this is a deadline/cancellation error.
    pub fn is_deadline(&self) -> bool {
        matches!(self, ErrorCode::DeadlineExceeded | ErrorCode::Cancelled)
    }

    /// Returns true if this is a connection pool error.
    pub fn is_pool(&self) -> bool {
        matches!(
            self,
            ErrorCode::PoolExhausted
                | ErrorCode::PoolAcquireTimeout
                | ErrorCode::PoolClosed
                | ErrorCode::ConnUnhealthy
        )
    }

    /// Returns true if this is an async I/O error.
    pub fn is_async(&self) -> bool {
        matches!(
            self,
            ErrorCode::AsyncPending | ErrorCode::AsyncCancelled | ErrorCode::EventLoopError
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
            ErrorCode::HsmInitFailed => "HSM_INIT_FAILED",
            ErrorCode::HsmPinRequired => "HSM_PIN_REQUIRED",
            ErrorCode::HsmPinInvalid => "HSM_PIN_INVALID",
            ErrorCode::HsmKeyNotFound => "HSM_KEY_NOT_FOUND",
            ErrorCode::HsmOperationFailed => "HSM_OPERATION_FAILED",
            ErrorCode::HsmSlotNotFound => "HSM_SLOT_NOT_FOUND",
            ErrorCode::HsmModuleNotFound => "HSM_MODULE_NOT_FOUND",
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
            ErrorCode::PoolExhausted => "POOL_EXHAUSTED",
            ErrorCode::PoolAcquireTimeout => "POOL_ACQUIRE_TIMEOUT",
            ErrorCode::PoolClosed => "POOL_CLOSED",
            ErrorCode::ConnUnhealthy => "CONN_UNHEALTHY",
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
            ErrorCode::OcspFailed => "OCSP_FAILED",
            ErrorCode::OcspTimeout => "OCSP_TIMEOUT",
            ErrorCode::OcspResponderError => "OCSP_RESPONDER_ERROR",
            ErrorCode::CrlFailed => "CRL_FAILED",
            ErrorCode::CrlDownloadFailed => "CRL_DOWNLOAD_FAILED",
            ErrorCode::CrlExpired => "CRL_EXPIRED",
            ErrorCode::CrlParseFailed => "CRL_PARSE_FAILED",
            ErrorCode::PinValidationFailed => "PIN_VALIDATION_FAILED",
            ErrorCode::PinInvalidFormat => "PIN_INVALID_FORMAT",
            ErrorCode::PinComputeFailed => "PIN_COMPUTE_FAILED",
            ErrorCode::CtValidationFailed => "CT_VALIDATION_FAILED",
            ErrorCode::CtNoScts => "CT_NO_SCTS",
            ErrorCode::CtInsufficientScts => "CT_INSUFFICIENT_SCTS",
            ErrorCode::CtInvalidSct => "CT_INVALID_SCT",
            ErrorCode::CtUnknownLog => "CT_UNKNOWN_LOG",
            ErrorCode::CtLogListParse => "CT_LOG_LIST_PARSE",
            ErrorCode::IdentityMismatch => "IDENTITY_MISMATCH",
            ErrorCode::SanNotAllowed => "SAN_NOT_ALLOWED",
            ErrorCode::SpiffeParseFailed => "SPIFFE_PARSE_FAILED",
            ErrorCode::CnNotAllowed => "CN_NOT_ALLOWED",
            ErrorCode::NoAllowedIdentity => "NO_ALLOWED_IDENTITY",
            ErrorCode::IdentityTooLong => "IDENTITY_TOO_LONG",
            ErrorCode::KillSwitchEnabled => "KILL_SWITCH_ENABLED",
            ErrorCode::PolicyDenied => "POLICY_DENIED",
            ErrorCode::ConnectionNotAllowed => "CONNECTION_NOT_ALLOWED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::RateLimitGlobal => "RATE_LIMIT_GLOBAL",
            ErrorCode::RateLimitClient => "RATE_LIMIT_CLIENT",
            ErrorCode::ReadFailed => "READ_FAILED",
            ErrorCode::WriteFailed => "WRITE_FAILED",
            ErrorCode::ConnectionClosed => "CONNECTION_CLOSED",
            ErrorCode::ConnectionReset => "CONNECTION_RESET",
            ErrorCode::ReadTimeout => "READ_TIMEOUT",
            ErrorCode::WriteTimeout => "WRITE_TIMEOUT",
            ErrorCode::WouldBlock => "WOULD_BLOCK",
            ErrorCode::PartialWrite => "PARTIAL_WRITE",
            ErrorCode::Eof => "EOF",
            ErrorCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
            ErrorCode::Cancelled => "CANCELLED",
            ErrorCode::AsyncPending => "ASYNC_PENDING",
            ErrorCode::AsyncCancelled => "ASYNC_CANCELLED",
            ErrorCode::EventLoopError => "EVENTLOOP_ERROR",
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

        #[allow(clippy::useless_conversion)] // c_ulong is u32 on Windows, u64 on Linux
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

    /// Returns true if this is an OCSP error.
    pub fn is_ocsp(&self) -> bool {
        self.code.is_ocsp()
    }

    /// Returns true if this is a CRL error.
    pub fn is_crl(&self) -> bool {
        self.code.is_crl()
    }

    /// Returns true if this is a revocation error (OCSP or CRL).
    pub fn is_revocation(&self) -> bool {
        self.code.is_revocation()
    }

    /// Returns true if this is a certificate pinning error.
    pub fn is_pinning(&self) -> bool {
        self.code.is_pinning()
    }

    /// Returns true if this is a Certificate Transparency error.
    pub fn is_ct(&self) -> bool {
        self.code.is_ct()
    }

    /// Returns true if this is an HSM error.
    pub fn is_hsm(&self) -> bool {
        self.code.is_hsm()
    }

    /// Returns true if this is a rate limiting error.
    pub fn is_rate_limit(&self) -> bool {
        self.code.is_rate_limit()
    }

    /// Returns true if this is a deadline/cancellation error.
    pub fn is_deadline(&self) -> bool {
        self.code.is_deadline()
    }

    /// Returns true if this is a connection pool error.
    pub fn is_pool(&self) -> bool {
        self.code.is_pool()
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

    #[test]
    fn test_ocsp_crl_error_codes() {
        // Test OCSP error categorization
        assert!(ErrorCode::OcspFailed.is_ocsp());
        assert!(ErrorCode::OcspTimeout.is_ocsp());
        assert!(ErrorCode::OcspResponderError.is_ocsp());
        assert!(!ErrorCode::CrlFailed.is_ocsp());

        // Test CRL error categorization
        assert!(ErrorCode::CrlFailed.is_crl());
        assert!(ErrorCode::CrlDownloadFailed.is_crl());
        assert!(ErrorCode::CrlExpired.is_crl());
        assert!(ErrorCode::CrlParseFailed.is_crl());
        assert!(!ErrorCode::OcspFailed.is_crl());

        // Test revocation (either OCSP or CRL)
        assert!(ErrorCode::OcspFailed.is_revocation());
        assert!(ErrorCode::CrlFailed.is_revocation());
        assert!(!ErrorCode::ConnectFailed.is_revocation());

        // All OCSP/CRL errors are TLS errors
        assert!(ErrorCode::OcspFailed.is_tls());
        assert!(ErrorCode::CrlFailed.is_tls());
    }

    #[test]
    fn test_ocsp_crl_error_from_i32() {
        assert_eq!(ErrorCode::from_i32(313), ErrorCode::OcspFailed);
        assert_eq!(ErrorCode::from_i32(314), ErrorCode::OcspTimeout);
        assert_eq!(ErrorCode::from_i32(315), ErrorCode::OcspResponderError);
        assert_eq!(ErrorCode::from_i32(316), ErrorCode::CrlFailed);
        assert_eq!(ErrorCode::from_i32(317), ErrorCode::CrlDownloadFailed);
        assert_eq!(ErrorCode::from_i32(318), ErrorCode::CrlExpired);
        assert_eq!(ErrorCode::from_i32(319), ErrorCode::CrlParseFailed);
    }

    #[test]
    fn test_ocsp_crl_error_names() {
        assert_eq!(ErrorCode::OcspFailed.name(), "OCSP_FAILED");
        assert_eq!(ErrorCode::OcspTimeout.name(), "OCSP_TIMEOUT");
        assert_eq!(ErrorCode::OcspResponderError.name(), "OCSP_RESPONDER_ERROR");
        assert_eq!(ErrorCode::CrlFailed.name(), "CRL_FAILED");
        assert_eq!(ErrorCode::CrlDownloadFailed.name(), "CRL_DOWNLOAD_FAILED");
        assert_eq!(ErrorCode::CrlExpired.name(), "CRL_EXPIRED");
        assert_eq!(ErrorCode::CrlParseFailed.name(), "CRL_PARSE_FAILED");
    }

    #[test]
    fn test_ct_error_codes() {
        // Test CT error categorization
        assert!(ErrorCode::CtValidationFailed.is_ct());
        assert!(ErrorCode::CtNoScts.is_ct());
        assert!(ErrorCode::CtInsufficientScts.is_ct());
        assert!(ErrorCode::CtInvalidSct.is_ct());
        assert!(ErrorCode::CtUnknownLog.is_ct());
        assert!(ErrorCode::CtLogListParse.is_ct());
        assert!(!ErrorCode::ConnectFailed.is_ct());

        // All CT errors are TLS errors
        assert!(ErrorCode::CtValidationFailed.is_tls());
        assert!(ErrorCode::CtNoScts.is_tls());
    }

    #[test]
    fn test_ct_error_from_i32() {
        assert_eq!(ErrorCode::from_i32(323), ErrorCode::CtValidationFailed);
        assert_eq!(ErrorCode::from_i32(324), ErrorCode::CtNoScts);
        assert_eq!(ErrorCode::from_i32(325), ErrorCode::CtInsufficientScts);
        assert_eq!(ErrorCode::from_i32(326), ErrorCode::CtInvalidSct);
        assert_eq!(ErrorCode::from_i32(327), ErrorCode::CtUnknownLog);
        assert_eq!(ErrorCode::from_i32(328), ErrorCode::CtLogListParse);
    }

    #[test]
    fn test_ct_error_names() {
        assert_eq!(ErrorCode::CtValidationFailed.name(), "CT_VALIDATION_FAILED");
        assert_eq!(ErrorCode::CtNoScts.name(), "CT_NO_SCTS");
        assert_eq!(ErrorCode::CtInsufficientScts.name(), "CT_INSUFFICIENT_SCTS");
        assert_eq!(ErrorCode::CtInvalidSct.name(), "CT_INVALID_SCT");
        assert_eq!(ErrorCode::CtUnknownLog.name(), "CT_UNKNOWN_LOG");
        assert_eq!(ErrorCode::CtLogListParse.name(), "CT_LOG_LIST_PARSE");
    }

    #[test]
    fn test_hsm_error_codes() {
        // Test HSM error categorization
        assert!(ErrorCode::HsmInitFailed.is_hsm());
        assert!(ErrorCode::HsmPinRequired.is_hsm());
        assert!(ErrorCode::HsmPinInvalid.is_hsm());
        assert!(ErrorCode::HsmKeyNotFound.is_hsm());
        assert!(ErrorCode::HsmOperationFailed.is_hsm());
        assert!(ErrorCode::HsmSlotNotFound.is_hsm());
        assert!(ErrorCode::HsmModuleNotFound.is_hsm());
        assert!(!ErrorCode::ConnectFailed.is_hsm());

        // All HSM errors are config errors (1xx range)
        assert!(ErrorCode::HsmInitFailed.is_config());
        assert!(ErrorCode::HsmPinRequired.is_config());
    }

    #[test]
    fn test_hsm_error_from_i32() {
        assert_eq!(ErrorCode::from_i32(111), ErrorCode::HsmInitFailed);
        assert_eq!(ErrorCode::from_i32(112), ErrorCode::HsmPinRequired);
        assert_eq!(ErrorCode::from_i32(113), ErrorCode::HsmPinInvalid);
        assert_eq!(ErrorCode::from_i32(114), ErrorCode::HsmKeyNotFound);
        assert_eq!(ErrorCode::from_i32(115), ErrorCode::HsmOperationFailed);
        assert_eq!(ErrorCode::from_i32(116), ErrorCode::HsmSlotNotFound);
        assert_eq!(ErrorCode::from_i32(117), ErrorCode::HsmModuleNotFound);
    }

    #[test]
    fn test_hsm_error_names() {
        assert_eq!(ErrorCode::HsmInitFailed.name(), "HSM_INIT_FAILED");
        assert_eq!(ErrorCode::HsmPinRequired.name(), "HSM_PIN_REQUIRED");
        assert_eq!(ErrorCode::HsmPinInvalid.name(), "HSM_PIN_INVALID");
        assert_eq!(ErrorCode::HsmKeyNotFound.name(), "HSM_KEY_NOT_FOUND");
        assert_eq!(ErrorCode::HsmOperationFailed.name(), "HSM_OPERATION_FAILED");
        assert_eq!(ErrorCode::HsmSlotNotFound.name(), "HSM_SLOT_NOT_FOUND");
        assert_eq!(ErrorCode::HsmModuleNotFound.name(), "HSM_MODULE_NOT_FOUND");
    }

    #[test]
    fn test_pool_error_codes() {
        // Test pool error categorization
        assert!(ErrorCode::PoolExhausted.is_pool());
        assert!(ErrorCode::PoolAcquireTimeout.is_pool());
        assert!(ErrorCode::PoolClosed.is_pool());
        assert!(ErrorCode::ConnUnhealthy.is_pool());
        assert!(!ErrorCode::ConnectFailed.is_pool());

        // All pool errors are network errors (2xx range)
        assert!(ErrorCode::PoolExhausted.is_network());
        assert!(ErrorCode::PoolAcquireTimeout.is_network());
        assert!(ErrorCode::PoolClosed.is_network());
        assert!(ErrorCode::ConnUnhealthy.is_network());
    }

    #[test]
    fn test_pool_error_from_i32() {
        assert_eq!(ErrorCode::from_i32(212), ErrorCode::PoolExhausted);
        assert_eq!(ErrorCode::from_i32(213), ErrorCode::PoolAcquireTimeout);
        assert_eq!(ErrorCode::from_i32(214), ErrorCode::PoolClosed);
        assert_eq!(ErrorCode::from_i32(215), ErrorCode::ConnUnhealthy);
    }

    #[test]
    fn test_pool_error_names() {
        assert_eq!(ErrorCode::PoolExhausted.name(), "POOL_EXHAUSTED");
        assert_eq!(ErrorCode::PoolAcquireTimeout.name(), "POOL_ACQUIRE_TIMEOUT");
        assert_eq!(ErrorCode::PoolClosed.name(), "POOL_CLOSED");
        assert_eq!(ErrorCode::ConnUnhealthy.name(), "CONN_UNHEALTHY");
    }
}
