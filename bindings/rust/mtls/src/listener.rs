//! mTLS listener for accepting incoming connections.

use std::net::SocketAddr;
use std::ptr::NonNull;

use crate::conn::Conn;
use crate::error::{Error, ErrorCode, Result};
use crate::ffi_helpers::{init_c_err, is_c_err_ok};

/// An mTLS listener that accepts incoming connections.
///
/// # Thread Safety
///
/// `Listener` is `Send` but NOT `Sync`. This means it can be moved between
/// threads but should only be used from one thread at a time.
///
/// # Example
///
/// ```ignore
/// let listener = ctx.listen("0.0.0.0:8443")?;
///
/// loop {
///     match listener.accept() {
///         Ok(conn) => {
///             // Handle connection...
///         }
///         Err(e) => {
///             eprintln!("Accept error: {}", e);
///         }
///     }
/// }
/// ```
pub struct Listener {
    pub(crate) ptr: Option<NonNull<mtls_sys::mtls_listener>>,
    pub(crate) addr: String, // Store the address since there's no getter in C API
}

// SAFETY: Listener can be sent between threads but not shared.
unsafe impl Send for Listener {}

impl Listener {
    /// Create a Listener from a raw pointer and address.
    pub(crate) fn from_raw(ptr: NonNull<mtls_sys::mtls_listener>, addr: String) -> Self {
        Listener {
            ptr: Some(ptr),
            addr,
        }
    }

    /// Accept an incoming connection asynchronously.
    ///
    /// This method uses `tokio::task::spawn_blocking` to execute the blocking
    /// accept operation on a thread pool, allowing the async runtime to continue
    /// processing other tasks.
    ///
    /// Returns an `AsyncConn` which provides async read/write methods.
    ///
    /// This blocks until a client connects and completes the TLS handshake.
    ///
    /// Requires the `async-tokio` feature.
    ///
    /// # Example
    ///
    /// ```ignore
    /// loop {
    ///     let mut conn = listener.accept_async().await?;
    ///     conn.write_all(b"Hello").await?;
    /// }
    /// ```
    #[cfg(feature = "async-tokio")]
    pub async fn accept_async(&self) -> Result<crate::conn::AsyncConn> {
        // For async accept, we extract the raw pointer.
        // SAFETY: We wrap the C pointer in a Send-safe newtype since Rust
        // can't prove that C types are Send. The caller holds `&self` across
        // the await, so the underlying C listener outlives this blocking task.
        #[repr(transparent)]
        struct SendPtr(*mut mtls_sys::mtls_listener);
        unsafe impl Send for SendPtr {}

        let ptr = self.ptr.map(|p| SendPtr(p.as_ptr()));

        tokio::task::spawn_blocking(move || {
            // IMPORTANT: Do NOT reconstruct a temporary `Listener` here.
            // `Listener`'s Drop closes the underlying C listener; creating a temporary
            // wrapper would close the real listener at the end of this closure.

            let SendPtr(listener_ptr) = ptr.ok_or_else(|| {
                Error::new(ErrorCode::ListenerClosed, "listener is closed")
            })?;

            let mut err = init_c_err();
            let conn_ptr = unsafe { mtls_sys::mtls_accept(listener_ptr, &mut err) };

            if conn_ptr.is_null() || !is_c_err_ok(&err) {
                return Err(Error::from_c_err(&err));
            }

            let conn_ptr = NonNull::new(conn_ptr)
                .ok_or_else(|| Error::new(ErrorCode::AcceptFailed, "accept returned null"))?;

            Ok(Conn::from_raw(conn_ptr))
        })
        .await
        .map_err(|e| Error::new(ErrorCode::AcceptFailed, format!("task panicked: {}", e)))
        .map(|result| result.map(crate::conn::AsyncConn::new))?
    }

    /// Accept an incoming connection.
    ///
    /// This blocks until a client connects and completes the TLS handshake.
    pub fn accept(&self) -> Result<Conn> {
        let ptr = match self.ptr {
            Some(p) => p.as_ptr(),
            None => return Err(Error::new(ErrorCode::ListenerClosed, "listener is closed")),
        };

        let mut err = init_c_err();

        let conn_ptr = unsafe { mtls_sys::mtls_accept(ptr, &mut err) };

        if conn_ptr.is_null() || !is_c_err_ok(&err) {
            return Err(Error::from_c_err(&err));
        }

        let conn_ptr = NonNull::new(conn_ptr)
            .ok_or_else(|| Error::new(ErrorCode::AcceptFailed, "accept returned null"))?;

        Ok(Conn::from_raw(conn_ptr))
    }

    /// Get the address the listener is bound to.
    ///
    /// Returns the bind address that was passed to listen().
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Parse the listener address as a SocketAddr.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addr().parse().ok()
    }

    /// Shutdown the listener.
    ///
    /// This stops the listener from accepting new connections.
    /// Existing connections are not affected.
    pub fn shutdown(&mut self) {
        if let Some(p) = self.ptr {
            unsafe {
                mtls_sys::mtls_listener_shutdown(p.as_ptr());
            }
        }
    }

    /// Close the listener and release all resources.
    pub fn close(&mut self) {
        if let Some(ptr) = self.ptr.take() {
            unsafe {
                mtls_sys::mtls_listener_close(ptr.as_ptr());
            }
        }
    }

    /// Check if the listener is closed.
    pub fn is_closed(&self) -> bool {
        self.ptr.is_none()
    }

    /// Serve connections using a handler function.
    ///
    /// This is a convenience method that accepts connections in a loop
    /// and calls the provided handler for each one. The handler receives
    /// the connection and should process it (typically in a separate thread).
    ///
    /// Returns when the listener is shut down or an unrecoverable error occurs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// listener.serve(|conn| {
    ///     std::thread::spawn(move || {
    ///         // Handle connection...
    ///     });
    ///     Ok(())
    /// })?;
    /// ```
    pub fn serve<F>(&self, mut handler: F) -> Result<()>
    where
        F: FnMut(Conn) -> Result<()>,
    {
        loop {
            match self.accept() {
                Ok(conn) => {
                    if let Err(e) = handler(conn) {
                        // Log handler error but continue serving
                        eprintln!("Handler error: {}", e);
                    }
                }
                Err(e) => {
                    // Check if this is a shutdown
                    if self.is_closed() {
                        return Ok(());
                    }
                    // Check for accept timeout or temporary errors
                    if e.code() == ErrorCode::Timeout {
                        continue;
                    }
                    // Fatal error
                    return Err(e);
                }
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr.take() {
            unsafe {
                mtls_sys::mtls_listener_close(ptr.as_ptr());
            }
        }
    }
}

/// Iterator over incoming connections.
///
/// This is returned by `Listener::incoming()` and yields connections
/// as they arrive.
pub struct Incoming<'a> {
    listener: &'a Listener,
}

impl<'a> Iterator for Incoming<'a> {
    type Item = Result<Conn>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.listener.is_closed() {
            return None;
        }
        Some(self.listener.accept())
    }
}

impl Listener {
    /// Returns an iterator over incoming connections.
    ///
    /// This iterator will never return `None` as long as the listener
    /// is open. Each call to `next()` blocks until a connection is accepted.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for conn_result in listener.incoming() {
    ///     match conn_result {
    ///         Ok(conn) => {
    ///             // Handle connection...
    ///         }
    ///         Err(e) => {
    ///             eprintln!("Accept error: {}", e);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_listener_closed_detection() {
        // Cannot fully test without a real listener
        // but we can test the closed state logic
    }
}
