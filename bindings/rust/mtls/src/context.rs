//! mTLS Context for creating connections and listeners.

use std::ptr::NonNull;
use std::sync::Arc;

use crate::config::Config;
use crate::conn::Conn;
use crate::error::{Error, ErrorCode, Result};
use crate::ffi_helpers::{init_c_err, is_c_err_ok, to_c_string};
use crate::listener::Listener;

/// Inner context data that holds the C pointer.
struct ContextInner {
    ptr: NonNull<mtls_sys::mtls_ctx>,
}

// SAFETY: mtls_ctx is thread-safe after creation per C library design.
unsafe impl Send for ContextInner {}
unsafe impl Sync for ContextInner {}

impl Drop for ContextInner {
    fn drop(&mut self) {
        unsafe {
            mtls_sys::mtls_ctx_free(self.ptr.as_ptr());
        }
    }
}

/// mTLS context for creating connections and listeners.
///
/// The context holds the TLS configuration and can be used to create
/// multiple connections or listeners. It is thread-safe and can be
/// shared across threads.
///
/// # Example
///
/// ```ignore
/// use mtls::{Config, Context};
///
/// let config = Config::builder()
///     .ca_cert_file("ca.pem")
///     .cert_file("client.pem", "client.key")
///     .build()?;
///
/// let ctx = Context::new(&config)?;
/// let conn = ctx.connect("server:8443")?;
/// ```
#[derive(Clone)]
pub struct Context {
    inner: Arc<ContextInner>,
}

impl Context {
    /// Create a new mTLS context from configuration.
    ///
    /// This initializes the TLS context with the provided certificates
    /// and configuration options.
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;

        // Keep the guard alive for the entire duration of mtls_ctx_create().
        // The C library:
        // 1. Validates the config, accessing config->allowed_sans array (and the CStrings it points to)
        // 2. Copies the data via strarr_dup() which allocates new memory and duplicates strings
        // 3. Stores the copied data in ctx->allowed_sans, so it no longer depends on our guard
        // After mtls_ctx_create returns, the guard can be safely dropped because the C library
        // has its own copy of all the data. The guard's lifetime ensures all pointers remain
        // valid throughout the entire mtls_ctx_create call.
        let c_config = config.to_c()?;
        let mut err = init_c_err();

        let ptr = unsafe { mtls_sys::mtls_ctx_create(c_config.as_ptr(), &mut err) };

        if ptr.is_null() || !is_c_err_ok(&err) {
            return Err(Error::from_c_err(&err));
        }

        let ptr = NonNull::new(ptr).ok_or_else(|| {
            Error::new(
                ErrorCode::ContextCreationFailed,
                "context creation returned null",
            )
        })?;

        Ok(Context {
            inner: Arc::new(ContextInner { ptr }),
        })
    }

    /// Connect to a remote mTLS server.
    ///
    /// The address should be in the format "host:port".
    ///
    /// # Example
    ///
    /// ```ignore
    /// let conn = ctx.connect("server.example.com:8443")?;
    /// ```
    pub fn connect(&self, addr: &str) -> Result<Conn> {
        let c_addr = to_c_string(addr)?;
        let mut err = init_c_err();

        let conn_ptr =
            unsafe { mtls_sys::mtls_connect(self.inner.ptr.as_ptr(), c_addr.as_ptr(), &mut err) };

        if conn_ptr.is_null() || !is_c_err_ok(&err) {
            return Err(Error::from_c_err(&err));
        }

        let conn_ptr = NonNull::new(conn_ptr)
            .ok_or_else(|| Error::new(ErrorCode::ConnectionFailed, "connect returned null"))?;

        Ok(Conn::from_raw(conn_ptr))
    }

    /// Connect to a remote mTLS server asynchronously.
    ///
    /// This method uses `tokio::task::spawn_blocking` to execute the blocking
    /// connection operation on a thread pool, allowing the async runtime to
    /// continue processing other tasks.
    ///
    /// The address should be in the format "host:port".
    ///
    /// Requires the `async-tokio` feature.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let conn = ctx.connect_async("server.example.com:8443").await?;
    /// ```
    #[cfg(feature = "async-tokio")]
    pub async fn connect_async(&self, addr: &str) -> Result<Conn> {
        let ctx = self.clone();
        let addr = addr.to_string();
        tokio::task::spawn_blocking(move || ctx.connect(&addr))
            .await
            .map_err(|e| Error::new(ErrorCode::ConnectionFailed, format!("task panicked: {}", e)))?
    }

    /// Create a listener bound to the given address.
    ///
    /// The address should be in the format "host:port" or ":port".
    ///
    /// # Example
    ///
    /// ```ignore
    /// let listener = ctx.listen("0.0.0.0:8443")?;
    /// ```
    pub fn listen(&self, addr: &str) -> Result<Listener> {
        let c_addr = to_c_string(addr)?;
        let mut err = init_c_err();

        let listener_ptr =
            unsafe { mtls_sys::mtls_listen(self.inner.ptr.as_ptr(), c_addr.as_ptr(), &mut err) };

        if listener_ptr.is_null() || !is_c_err_ok(&err) {
            return Err(Error::from_c_err(&err));
        }

        let listener_ptr = NonNull::new(listener_ptr)
            .ok_or_else(|| Error::new(ErrorCode::ListenerFailed, "listen returned null"))?;

        Ok(Listener::from_raw(listener_ptr, addr.to_string()))
    }

    /// Enable or disable the kill switch.
    ///
    /// When enabled, all new connections will fail immediately.
    /// Existing connections are not affected. Use this for emergency shutdown scenarios.
    ///
    /// # Arguments
    /// * `enabled` - `true` to enable kill switch, `false` to disable
    pub fn set_kill_switch(&self, enabled: bool) {
        unsafe {
            mtls_sys::mtls_ctx_set_kill_switch(self.inner.ptr.as_ptr(), enabled);
        }
    }

    /// Check if the kill switch is currently enabled.
    pub fn is_kill_switch_enabled(&self) -> bool {
        unsafe { mtls_sys::mtls_ctx_is_kill_switch_enabled(self.inner.ptr.as_ptr()) }
    }

    /// Get the raw context pointer for advanced use.
    ///
    /// # Safety
    /// The caller must ensure the pointer is not used after the Context is dropped.
    pub(crate) fn as_ptr(&self) -> *mut mtls_sys::mtls_ctx {
        self.inner.ptr.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_requires_config() {
        // Config without CA cert should fail validation
        let config = Config::default();
        let result = Context::new(&config);
        assert!(result.is_err());
    }
}
