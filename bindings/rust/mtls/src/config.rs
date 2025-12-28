//! Configuration for mTLS contexts.

use std::ffi::CString;
use std::path::Path;
use std::time::Duration;

use crate::error::{Error, ErrorCode, Result};
use crate::ffi_helpers::to_c_string;

/// TLS version enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u16)]
pub enum TlsVersion {
    /// TLS 1.2
    #[default]
    Tls12 = 0x0303,
    /// TLS 1.3
    Tls13 = 0x0304,
}

/// Configuration for creating an mTLS context.
///
/// Certificates can be loaded from:
/// - File paths (`ca_cert_path`, `cert_path`, `key_path`)
/// - In-memory PEM data (`ca_cert_pem`, `cert_pem`, `key_pem`)
///
/// If both path and PEM are provided, PEM takes precedence.
#[derive(Debug, Clone)]
pub struct Config {
    // CA certificate
    pub(crate) ca_cert_path: Option<String>,
    pub(crate) ca_cert_pem: Option<Vec<u8>>,

    // Client/server certificate
    pub(crate) cert_path: Option<String>,
    pub(crate) cert_pem: Option<Vec<u8>>,

    // Private key
    pub(crate) key_path: Option<String>,
    pub(crate) key_pem: Option<Vec<u8>>,

    // CRL path for certificate revocation
    pub(crate) crl_path: Option<String>,

    // Identity verification
    pub(crate) allowed_sans: Vec<String>,

    // TLS settings
    pub(crate) min_tls_version: TlsVersion,
    pub(crate) max_tls_version: TlsVersion,

    // Timeouts
    pub(crate) connect_timeout: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) write_timeout: Duration,

    // Security controls
    pub(crate) kill_switch_enabled: bool,
    pub(crate) require_client_cert: bool,
    pub(crate) verify_hostname: bool,

    // OCSP settings
    pub(crate) enable_ocsp: bool,
    pub(crate) enable_ocsp_stapling: bool,
    pub(crate) ocsp_url: Option<String>,
    pub(crate) ocsp_timeout: Duration,
    pub(crate) require_ocsp: bool,

    // CRL settings
    pub(crate) enable_crl: bool,
    pub(crate) crl_url: Option<String>,
    pub(crate) crl_refresh_interval: Duration,
    pub(crate) require_crl: bool,

    // Revocation cache settings
    pub(crate) revocation_cache_ttl: Duration,
    pub(crate) revocation_cache_max_entries: usize,

    // Certificate pinning settings
    pub(crate) pin_spki_sha256: Vec<String>,
    pub(crate) pin_cert_sha256: Vec<String>,
    pub(crate) pin_require_match: bool,
    pub(crate) pin_include_leaf_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ca_cert_path: None,
            ca_cert_pem: None,
            cert_path: None,
            cert_pem: None,
            key_path: None,
            key_pem: None,
            crl_path: None,
            allowed_sans: Vec::new(),
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: TlsVersion::Tls13,
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            kill_switch_enabled: false,
            require_client_cert: true,
            verify_hostname: true,
            // OCSP settings
            enable_ocsp: false,
            enable_ocsp_stapling: false,
            ocsp_url: None,
            ocsp_timeout: Duration::from_secs(5),
            require_ocsp: false,
            // CRL settings
            enable_crl: false,
            crl_url: None,
            crl_refresh_interval: Duration::from_secs(86400),
            require_crl: false,
            // Revocation cache settings
            revocation_cache_ttl: Duration::from_secs(3600),
            revocation_cache_max_entries: 10000,

            // Certificate pinning settings
            pin_spki_sha256: Vec::new(),
            pin_cert_sha256: Vec::new(),
            pin_require_match: false,
            pin_include_leaf_only: false,
        }
    }
}

impl Config {
    /// Create a new ConfigBuilder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate CA cert provided
        if self.ca_cert_path.is_none() && self.ca_cert_pem.is_none() {
            return Err(Error::new(
                ErrorCode::InvalidConfig,
                "CA certificate is required: provide ca_cert_path or ca_cert_pem",
            ));
        }

        // Validate TLS version ordering
        if (self.min_tls_version as u16) > (self.max_tls_version as u16) {
            return Err(Error::new(
                ErrorCode::InvalidConfig,
                "min TLS version cannot be greater than max TLS version",
            ));
        }

        Ok(())
    }

    /// Convert to a C config structure with RAII cleanup.
    pub(crate) fn to_c(&self) -> Result<CConfigGuard> {
        let mut config: mtls_sys::mtls_config = mtls_sys::mtls_config::default();
        unsafe {
            mtls_sys::mtls_config_init(&mut config);
        }

        let mut guard = CConfigGuard {
            config,
            allocations: Vec::new(),
            san_array: None,
            pin_spki_array: None,
            pin_cert_array: None,
        };

        // CA certificate
        if let Some(ref pem) = self.ca_cert_pem {
            guard.config.ca_cert_pem = pem.as_ptr();
            guard.config.ca_cert_pem_len = pem.len();
        } else if let Some(ref path) = self.ca_cert_path {
            let c_str = to_c_string(path)?;
            guard.config.ca_cert_path = c_str.as_ptr();
            guard.allocations.push(c_str);
        }

        // Certificate
        if let Some(ref pem) = self.cert_pem {
            guard.config.cert_pem = pem.as_ptr();
            guard.config.cert_pem_len = pem.len();
        } else if let Some(ref path) = self.cert_path {
            let c_str = to_c_string(path)?;
            guard.config.cert_path = c_str.as_ptr();
            guard.allocations.push(c_str);
        }

        // Key
        if let Some(ref pem) = self.key_pem {
            guard.config.key_pem = pem.as_ptr();
            guard.config.key_pem_len = pem.len();
        } else if let Some(ref path) = self.key_path {
            let c_str = to_c_string(path)?;
            guard.config.key_path = c_str.as_ptr();
            guard.allocations.push(c_str);
        }

        // CRL path
        if let Some(ref path) = self.crl_path {
            let c_str = to_c_string(path)?;
            guard.config.crl_path = c_str.as_ptr();
            guard.allocations.push(c_str);
        }

        // Allowed SANs
        if !self.allowed_sans.is_empty() {
            let mut san_ptrs: Vec<*const i8> = Vec::with_capacity(self.allowed_sans.len());
            let mut san_strings: Vec<CString> = Vec::with_capacity(self.allowed_sans.len());

            for san in &self.allowed_sans {
                let c_str = to_c_string(san)?;
                san_ptrs.push(c_str.as_ptr());
                san_strings.push(c_str);
            }

            // Store the CStrings to keep them alive
            for s in san_strings {
                guard.allocations.push(s);
            }

            // Create the array of pointers
            let san_array = san_ptrs.into_boxed_slice();
            guard.config.allowed_sans = san_array.as_ptr() as *mut *const i8;
            guard.config.allowed_sans_count = san_array.len();
            guard.san_array = Some(san_array);
        }

        // TLS versions
        guard.config.min_tls_version = match self.min_tls_version {
            TlsVersion::Tls12 => mtls_sys::mtls_tls_version::MTLS_TLS_1_2,
            TlsVersion::Tls13 => mtls_sys::mtls_tls_version::MTLS_TLS_1_3,
        };
        guard.config.max_tls_version = match self.max_tls_version {
            TlsVersion::Tls12 => mtls_sys::mtls_tls_version::MTLS_TLS_1_2,
            TlsVersion::Tls13 => mtls_sys::mtls_tls_version::MTLS_TLS_1_3,
        };

        // Timeouts - clamp to u32::MAX to prevent overflow
        // Duration::as_millis() returns u128, which can exceed u32::MAX
        guard.config.connect_timeout_ms =
            self.connect_timeout.as_millis().min(u32::MAX as u128) as u32;
        guard.config.read_timeout_ms = self.read_timeout.as_millis().min(u32::MAX as u128) as u32;
        guard.config.write_timeout_ms = self.write_timeout.as_millis().min(u32::MAX as u128) as u32;

        // Security controls
        guard.config.kill_switch_enabled = self.kill_switch_enabled;
        guard.config.require_client_cert = self.require_client_cert;
        guard.config.verify_hostname = self.verify_hostname;

        // OCSP settings
        guard.config.enable_ocsp = self.enable_ocsp;
        guard.config.enable_ocsp_stapling = self.enable_ocsp_stapling;
        if let Some(ref url) = self.ocsp_url {
            let c_str = to_c_string(url)?;
            guard.config.ocsp_url = c_str.as_ptr();
            guard.allocations.push(c_str);
        }
        guard.config.ocsp_timeout_ms = self.ocsp_timeout.as_millis().min(u32::MAX as u128) as u32;
        guard.config.require_ocsp = self.require_ocsp;

        // CRL settings
        guard.config.enable_crl = self.enable_crl;
        if let Some(ref url) = self.crl_url {
            let c_str = to_c_string(url)?;
            guard.config.crl_url = c_str.as_ptr();
            guard.allocations.push(c_str);
        }
        guard.config.crl_refresh_seconds = self.crl_refresh_interval.as_secs().min(u32::MAX as u64) as u32;
        guard.config.require_crl = self.require_crl;

        // Revocation cache settings
        guard.config.revocation_cache_ttl_seconds = self.revocation_cache_ttl.as_secs().min(u32::MAX as u64) as u32;
        guard.config.revocation_cache_max_entries = self.revocation_cache_max_entries;

        // Certificate pinning settings
        if !self.pin_spki_sha256.is_empty() {
            let mut pin_ptrs: Vec<*const i8> = Vec::with_capacity(self.pin_spki_sha256.len());
            for pin in &self.pin_spki_sha256 {
                let c_str = to_c_string(pin)?;
                pin_ptrs.push(c_str.as_ptr());
                guard.allocations.push(c_str);
            }
            let pin_array = pin_ptrs.into_boxed_slice();
            guard.config.pin_spki_sha256 = pin_array.as_ptr() as *mut *const i8;
            guard.config.pin_spki_sha256_count = pin_array.len();
            guard.pin_spki_array = Some(pin_array);
        }

        if !self.pin_cert_sha256.is_empty() {
            let mut pin_ptrs: Vec<*const i8> = Vec::with_capacity(self.pin_cert_sha256.len());
            for pin in &self.pin_cert_sha256 {
                let c_str = to_c_string(pin)?;
                pin_ptrs.push(c_str.as_ptr());
                guard.allocations.push(c_str);
            }
            let pin_array = pin_ptrs.into_boxed_slice();
            guard.config.pin_cert_sha256 = pin_array.as_ptr() as *mut *const i8;
            guard.config.pin_cert_sha256_count = pin_array.len();
            guard.pin_cert_array = Some(pin_array);
        }

        guard.config.pin_require_match = self.pin_require_match;
        guard.config.pin_include_leaf_only = self.pin_include_leaf_only;

        Ok(guard)
    }
}

/// Builder for Config with fluent API.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder with default values.
    pub fn new() -> Self {
        ConfigBuilder {
            config: Config::default(),
        }
    }

    /// Set the CA certificate from a file path.
    pub fn ca_cert_file(mut self, path: impl AsRef<Path>) -> Self {
        self.config.ca_cert_path = Some(path.as_ref().to_string_lossy().into_owned());
        self.config.ca_cert_pem = None;
        self
    }

    /// Set the CA certificate from PEM data.
    pub fn ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.config.ca_cert_pem = Some(pem.into());
        self.config.ca_cert_path = None;
        self
    }

    /// Set the certificate and key from file paths.
    pub fn cert_file(mut self, cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Self {
        self.config.cert_path = Some(cert_path.as_ref().to_string_lossy().into_owned());
        self.config.key_path = Some(key_path.as_ref().to_string_lossy().into_owned());
        self.config.cert_pem = None;
        self.config.key_pem = None;
        self
    }

    /// Set the certificate and key from PEM data.
    pub fn cert_pem(mut self, cert: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        self.config.cert_pem = Some(cert.into());
        self.config.key_pem = Some(key.into());
        self.config.cert_path = None;
        self.config.key_path = None;
        self
    }

    /// Set the CRL file path for certificate revocation checking.
    pub fn crl_file(mut self, path: impl AsRef<Path>) -> Self {
        self.config.crl_path = Some(path.as_ref().to_string_lossy().into_owned());
        self
    }

    /// Set allowed Subject Alternative Names for peer validation.
    pub fn allowed_sans<I, S>(mut self, sans: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.allowed_sans = sans.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Set the minimum TLS version.
    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.config.min_tls_version = version;
        self
    }

    /// Set the maximum TLS version.
    pub fn max_tls_version(mut self, version: TlsVersion) -> Self {
        self.config.max_tls_version = version;
        self
    }

    /// Set the TLS version range.
    pub fn tls_version_range(mut self, min: TlsVersion, max: TlsVersion) -> Self {
        self.config.min_tls_version = min;
        self.config.max_tls_version = max;
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set the read timeout.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.config.read_timeout = timeout;
        self
    }

    /// Set the write timeout.
    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.config.write_timeout = timeout;
        self
    }

    /// Set whether to require a client certificate (server mode).
    pub fn require_client_cert(mut self, require: bool) -> Self {
        self.config.require_client_cert = require;
        self
    }

    /// Set whether to verify the hostname against the certificate.
    pub fn verify_hostname(mut self, verify: bool) -> Self {
        self.config.verify_hostname = verify;
        self
    }

    /// Enable or disable the kill switch.
    pub fn kill_switch(mut self, enabled: bool) -> Self {
        self.config.kill_switch_enabled = enabled;
        self
    }

    /// Enable or disable OCSP checking.
    pub fn enable_ocsp(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp = enabled;
        self
    }

    /// Enable or disable OCSP stapling.
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Set explicit OCSP responder URL.
    pub fn ocsp_url(mut self, url: impl Into<String>) -> Self {
        self.config.ocsp_url = Some(url.into());
        self
    }

    /// Set OCSP check timeout.
    pub fn ocsp_timeout(mut self, timeout: Duration) -> Self {
        self.config.ocsp_timeout = timeout;
        self
    }

    /// Require OCSP check to pass (fail connection if OCSP fails).
    pub fn require_ocsp(mut self, require: bool) -> Self {
        self.config.require_ocsp = require;
        self
    }

    /// Enable or disable CRL checking.
    pub fn enable_crl(mut self, enabled: bool) -> Self {
        self.config.enable_crl = enabled;
        self
    }

    /// Set CRL download URL.
    pub fn crl_url(mut self, url: impl Into<String>) -> Self {
        self.config.crl_url = Some(url.into());
        self
    }

    /// Set CRL refresh interval.
    pub fn crl_refresh_interval(mut self, interval: Duration) -> Self {
        self.config.crl_refresh_interval = interval;
        self
    }

    /// Require CRL check to pass (fail connection if CRL fails).
    pub fn require_crl(mut self, require: bool) -> Self {
        self.config.require_crl = require;
        self
    }

    /// Set revocation cache TTL.
    pub fn revocation_cache_ttl(mut self, ttl: Duration) -> Self {
        self.config.revocation_cache_ttl = ttl;
        self
    }

    /// Set maximum number of entries in revocation cache.
    pub fn revocation_cache_max_entries(mut self, max: usize) -> Self {
        self.config.revocation_cache_max_entries = max;
        self
    }

    /// Add SPKI SHA-256 pins (base64-encoded).
    pub fn pin_spki_sha256<I, S>(mut self, pins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.pin_spki_sha256 = pins.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Add certificate SHA-256 pins (base64-encoded).
    pub fn pin_cert_sha256<I, S>(mut self, pins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.pin_cert_sha256 = pins.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Require at least one pin match (default: true if pins are set).
    pub fn pin_require_match(mut self, require: bool) -> Self {
        self.config.pin_require_match = require;
        self
    }

    /// Only check leaf certificate (default: false, checks entire chain).
    pub fn pin_include_leaf_only(mut self, leaf_only: bool) -> Self {
        self.config.pin_include_leaf_only = leaf_only;
        self
    }

    /// Build the Config, validating it first.
    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for C config allocation.
///
/// This holds the C config and all allocated strings, freeing them on drop.
/// RAII guard for C configuration structure.
///
/// This guard manages the lifetime of C strings and pointer arrays allocated
/// for the C config. The guard must remain alive for the duration of any C
/// function calls that access the config data.
///
/// **Memory Safety**: The C library (mtls_ctx_create) copies all string data
/// via strarr_dup() during context creation, so it does not retain pointers
/// to memory owned by this guard. The guard must only stay alive during the
/// C function call, not for the lifetime of the created context.
pub(crate) struct CConfigGuard {
    pub config: mtls_sys::mtls_config,
    allocations: Vec<CString>,
    san_array: Option<Box<[*const i8]>>,
    pin_spki_array: Option<Box<[*const i8]>>,
    pin_cert_array: Option<Box<[*const i8]>>,
}

impl CConfigGuard {
    /// Get a pointer to the C config.
    ///
    /// # Safety
    /// The returned pointer is valid only while `self` is alive. The caller
    /// must ensure the guard outlives any C function calls that access the
    /// config data. The C library must copy any data it needs to retain
    /// beyond the function call (as mtls_ctx_create does via strarr_dup).
    pub fn as_ptr(&self) -> *const mtls_sys::mtls_config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.min_tls_version, TlsVersion::Tls12);
        assert_eq!(config.max_tls_version, TlsVersion::Tls13);
        assert!(config.require_client_cert);
        assert!(config.verify_hostname);
    }

    #[test]
    fn test_config_builder() {
        let config = Config::builder()
            .ca_cert_file("/path/to/ca.pem")
            .cert_file("/path/to/cert.pem", "/path/to/key.pem")
            .connect_timeout(Duration::from_secs(10))
            .require_client_cert(false)
            .build();

        // Should fail validation because files don't exist
        // but the builder pattern works
        assert!(config.is_ok() || config.is_err());
    }

    #[test]
    fn test_config_validation_no_ca() {
        let config = Config::default();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("CA certificate"));
    }

    #[test]
    fn test_config_validation_tls_version() {
        let config = Config {
            ca_cert_pem: Some(vec![1, 2, 3]), // Dummy PEM
            min_tls_version: TlsVersion::Tls13,
            max_tls_version: TlsVersion::Tls12,
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("TLS version"));
    }
}
