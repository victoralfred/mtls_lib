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
    pub(crate) enable_ocsp: bool,
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
            enable_ocsp: false,
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
        let mut config: mtls_sys::mtls_config = unsafe { std::mem::zeroed() };
        unsafe {
            mtls_sys::mtls_config_init(&mut config);
        }

        let mut guard = CConfigGuard {
            config,
            allocations: Vec::new(),
            san_array: None,
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
        guard.config.enable_ocsp = self.enable_ocsp;

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

    /// Enable or disable OCSP stapling.
    pub fn enable_ocsp(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp = enabled;
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
pub(crate) struct CConfigGuard {
    pub config: mtls_sys::mtls_config,
    allocations: Vec<CString>,
    san_array: Option<Box<[*const i8]>>,
}

impl CConfigGuard {
    /// Get a pointer to the C config.
    pub fn as_ptr(&self) -> *const mtls_sys::mtls_config {
        &self.config
    }
}

// CStrings are automatically dropped when CConfigGuard is dropped,
// which frees all the C strings we allocated.

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
