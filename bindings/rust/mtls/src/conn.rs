//! mTLS connection with Read/Write trait implementations.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::ptr::NonNull;

use crate::error::Error;
use crate::ffi_helpers::{from_c_char_array, init_c_err, is_c_err_ok};
use crate::identity::{ConnState, PeerIdentity};

/// An mTLS connection.
///
/// Implements `std::io::Read` and `std::io::Write` for easy integration
/// with standard I/O operations.
///
/// # Thread Safety
///
/// `Conn` is `Send` but NOT `Sync`. This means it can be moved between
/// threads but should only be used from one thread at a time.
///
/// # Example
///
/// ```ignore
/// use std::io::{Read, Write};
///
/// let mut conn = ctx.connect("server:8443")?;
///
/// conn.write_all(b"Hello")?;
///
/// let mut buf = [0u8; 1024];
/// let n = conn.read(&mut buf)?;
/// ```
pub struct Conn {
    ptr: Option<NonNull<mtls_sys::mtls_conn>>,
}

// SAFETY: Conn can be sent between threads but not shared.
unsafe impl Send for Conn {}

impl Conn {
    /// Create a Conn from a raw pointer.
    pub(crate) fn from_raw(ptr: NonNull<mtls_sys::mtls_conn>) -> Self {
        Conn { ptr: Some(ptr) }
    }

    /// Get the connection state.
    pub fn state(&self) -> ConnState {
        let ptr = match self.ptr {
            Some(p) => p.as_ptr(),
            None => return ConnState::Closed,
        };

        let state = unsafe { mtls_sys::mtls_get_state(ptr) };
        ConnState::from_c(state)
    }

    /// Check if the connection is established.
    pub fn is_established(&self) -> bool {
        self.state().is_established()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.ptr.is_none() || self.state().is_closed()
    }

    /// Get the peer's identity from their certificate.
    ///
    /// Returns `None` if no peer certificate is available.
    ///
    /// # Note
    /// The C library allocates memory for SANs. This function copies all data
    /// into Rust-owned structures, so the caller doesn't need to free anything.
    pub fn peer_identity(&self) -> Option<PeerIdentity> {
        let ptr = self.ptr?.as_ptr();

        let mut identity: mtls_sys::mtls_peer_identity = unsafe { std::mem::zeroed() };
        let mut err = init_c_err();

        let result = unsafe { mtls_sys::mtls_get_peer_identity(ptr, &mut identity, &mut err) };

        if result != 0 || !is_c_err_ok(&err) {
            return None;
        }

        let rust_identity = unsafe { PeerIdentity::from_c(&identity) };

        // Free the C library's allocated memory for SANs
        unsafe {
            mtls_sys::mtls_free_peer_identity(&mut identity);
        }

        Some(rust_identity)
    }

    /// Get the peer's organization from their certificate.
    pub fn peer_organization(&self) -> Option<String> {
        let ptr = self.ptr?.as_ptr();

        let mut org = [0i8; 256];

        let result =
            unsafe { mtls_sys::mtls_get_peer_organization(ptr, org.as_mut_ptr(), org.len()) };

        if result != 0 {
            return None;
        }

        let s = unsafe { from_c_char_array(&org) };
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Get the peer's organizational unit from their certificate.
    pub fn peer_org_unit(&self) -> Option<String> {
        let ptr = self.ptr?.as_ptr();

        let mut ou = [0i8; 256];

        let result = unsafe { mtls_sys::mtls_get_peer_org_unit(ptr, ou.as_mut_ptr(), ou.len()) };

        if result != 0 {
            return None;
        }

        let s = unsafe { from_c_char_array(&ou) };
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Get the remote address of the connection.
    pub fn remote_addr(&self) -> Option<String> {
        let ptr = self.ptr?.as_ptr();

        let mut addr = [0i8; 128];

        let result = unsafe { mtls_sys::mtls_get_remote_addr(ptr, addr.as_mut_ptr(), addr.len()) };

        if result != 0 {
            return None;
        }

        let s = unsafe { from_c_char_array(&addr) };
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Get the local address of the connection.
    pub fn local_addr(&self) -> Option<String> {
        let ptr = self.ptr?.as_ptr();

        let mut addr = [0i8; 128];

        let result = unsafe { mtls_sys::mtls_get_local_addr(ptr, addr.as_mut_ptr(), addr.len()) };

        if result != 0 {
            return None;
        }

        let s = unsafe { from_c_char_array(&addr) };
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Parse the remote address as a SocketAddr.
    pub fn remote_socket_addr(&self) -> Option<SocketAddr> {
        self.remote_addr()?.parse().ok()
    }

    /// Parse the local address as a SocketAddr.
    pub fn local_socket_addr(&self) -> Option<SocketAddr> {
        self.local_addr()?.parse().ok()
    }

    /// Close the connection gracefully.
    ///
    /// This performs a TLS shutdown followed by closing the socket.
    pub fn close(&mut self) {
        if let Some(ptr) = self.ptr.take() {
            unsafe {
                mtls_sys::mtls_close(ptr.as_ptr());
            }
        }
    }

    /// Get the raw pointer for advanced operations.
    #[allow(dead_code)]
    pub(crate) fn as_ptr(&self) -> Option<*mut mtls_sys::mtls_conn> {
        self.ptr.map(|p| p.as_ptr())
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ptr = match self.ptr {
            Some(p) => p.as_ptr(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection is closed",
                ))
            }
        };

        if buf.is_empty() {
            return Ok(0);
        }

        let mut err = init_c_err();

        let result =
            unsafe { mtls_sys::mtls_read(ptr, buf.as_mut_ptr() as *mut _, buf.len(), &mut err) };

        if result < 0 {
            let error = Error::from_c_err(&err);
            return Err(error.into());
        }

        Ok(result as usize)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ptr = match self.ptr {
            Some(p) => p.as_ptr(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection is closed",
                ))
            }
        };

        if buf.is_empty() {
            return Ok(0);
        }

        let mut err = init_c_err();

        let result =
            unsafe { mtls_sys::mtls_write(ptr, buf.as_ptr() as *const _, buf.len(), &mut err) };

        if result < 0 {
            let error = Error::from_c_err(&err);
            return Err(error.into());
        }

        Ok(result as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // TLS handles buffering internally, no explicit flush needed
        Ok(())
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr.take() {
            unsafe {
                mtls_sys::mtls_close(ptr.as_ptr());
            }
        }
    }
}

/// `AsRawFd` is needed so `tokio::io::unix::AsyncFd<Conn>` can register the
/// socket fd with epoll/kqueue. Only available on Unix.
#[cfg(unix)]
impl std::os::unix::io::AsRawFd for Conn {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.ptr
            .map(|p| unsafe { mtls_sys::mtls_conn_get_fd(p.as_ptr()) })
            .unwrap_or(-1)
    }
}

/// Async connection wrapper that owns a Conn and provides async I/O.
///
/// This wrapper is needed because the underlying C library uses blocking I/O,
/// and we need to run those operations on a blocking thread pool.
#[cfg(feature = "async-tokio")]
pub struct AsyncConn {
    conn: Option<Conn>,
    read_scratch: Vec<u8>,
}

#[cfg(feature = "async-tokio")]
impl AsyncConn {
    /// Create a new AsyncConn from a Conn.
    pub fn new(conn: Conn) -> Self {
        AsyncConn {
            conn: Some(conn),
            read_scratch: Vec::new(),
        }
    }

    /// Read data from the connection asynchronously.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut conn = ctx.connect_async("server:8443").await?;
    /// let mut buf = [0u8; 1024];
    /// let n = conn.read(&mut buf).await?;
    /// ```
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // We must NOT pass raw pointers into a spawned blocking task, because the future
        // can be cancelled (dropped) while the task is still running, which could make
        // stack/borrowed buffers invalid. Instead we read into an owned scratch buffer
        // that lives inside the blocking task.
        let mut conn = self
            .conn
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection is closed"))?;
        let mut scratch = std::mem::take(&mut self.read_scratch);
        if scratch.len() < buf.len() {
            scratch.resize(buf.len(), 0u8);
        }

        let buf_len = buf.len();
        let (returned_conn, result, returned_scratch) = tokio::task::spawn_blocking(move || {
            let result = std::io::Read::read(&mut conn, &mut scratch[..buf_len]);
            (conn, result, scratch)
        })
        .await
        .map_err(|e| io::Error::other(format!("task panicked: {}", e)))?;

        self.conn = Some(returned_conn);
        self.read_scratch = returned_scratch;

        match result {
            Ok(n) => {
                buf[..n].copy_from_slice(&self.read_scratch[..n]);
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }

    /// Write data to the connection asynchronously.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut conn = ctx.connect_async("server:8443").await?;
    /// let n = conn.write(b"Hello").await?;
    /// ```
    pub async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut conn = self
            .conn
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection is closed"))?;

        // Copy into an owned buffer so cancellation is safe.
        let owned = buf.to_vec();
        let (returned_conn, result) = tokio::task::spawn_blocking(move || {
            let result = std::io::Write::write(&mut conn, &owned);
            (conn, result)
        })
        .await
        .map_err(|e| io::Error::other(format!("task panicked: {}", e)))?;

        self.conn = Some(returned_conn);
        result
    }

    /// Write all data to the connection asynchronously.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut conn = ctx.connect_async("server:8443").await?;
    /// conn.write_all(b"Hello").await?;
    /// ```
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut conn = self
            .conn
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection is closed"))?;

        // Copy into an owned buffer so cancellation is safe.
        let owned = buf.to_vec();
        let (returned_conn, result) = tokio::task::spawn_blocking(move || {
            let result = std::io::Write::write_all(&mut conn, &owned);
            (conn, result)
        })
        .await
        .map_err(|e| io::Error::other(format!("task panicked: {}", e)))?;

        self.conn = Some(returned_conn);
        result
    }

    /// Flush the connection asynchronously.
    pub async fn flush(&mut self) -> io::Result<()> {
        // `Conn::flush()` is a no-op (TLS buffers internally).
        // Keep this async API for symmetry, but avoid a thread hop.
        if self.conn.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection is closed",
            ));
        }
        Ok(())
    }

    /// Close the connection.
    pub fn close(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            conn.close();
        }
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.conn.as_ref().map(|c| c.is_closed()).unwrap_or(true)
    }

    /// Get the connection state.
    pub fn state(&self) -> crate::identity::ConnState {
        self.conn
            .as_ref()
            .map(|c| c.state())
            .unwrap_or(crate::identity::ConnState::Closed)
    }

    /// Get peer identity if available.
    pub fn peer_identity(&self) -> Option<crate::identity::PeerIdentity> {
        self.conn.as_ref().and_then(|c| c.peer_identity())
    }

    /// Get remote address if available.
    pub fn remote_addr(&self) -> Option<String> {
        self.conn.as_ref().and_then(|c| c.remote_addr())
    }

    /// Get local address if available.
    pub fn local_addr(&self) -> Option<String> {
        self.conn.as_ref().and_then(|c| c.local_addr())
    }
}

#[cfg(feature = "async-tokio")]
impl Drop for AsyncConn {
    fn drop(&mut self) {
        // Connection will be closed when the inner Conn is dropped
    }
}

/// True non-blocking async connection using `tokio::io::unix::AsyncFd`.
///
/// Unlike [`AsyncConn`] which wraps blocking I/O in `spawn_blocking`, this
/// type registers the raw socket file descriptor with tokio's reactor and
/// performs I/O directly on the tokio thread pool via non-blocking OpenSSL
/// calls (`mtls_conn_read_nonblocking` / `mtls_conn_write_nonblocking`).
///
/// # Platform
///
/// Available on Unix platforms only (Linux, macOS). The underlying C function
/// `mtls_conn_get_fd()` returns a POSIX file descriptor; `AsyncFd` requires
/// a valid Unix fd.
///
/// # Feature flag
///
/// Enable the `async-tokio-native` feature to use this type.
#[cfg(all(feature = "async-tokio-native", unix))]
pub struct AsyncFdConn {
    inner: tokio::io::unix::AsyncFd<Conn>,
}

#[cfg(all(feature = "async-tokio-native", unix))]
impl AsyncFdConn {
    /// Wrap a [`Conn`] for native async I/O.
    ///
    /// The underlying socket is set to non-blocking mode. Returns an error if
    /// the connection has no valid file descriptor (e.g. already closed).
    pub fn new(conn: Conn) -> io::Result<Self> {
        use std::os::unix::io::RawFd;

        // Retrieve the raw fd before handing conn to AsyncFd
        let raw_fd: RawFd = {
            let fd = unsafe {
                mtls_sys::mtls_conn_get_fd(
                    conn.ptr
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotConnected, "connection has no fd")
                        })?
                        .as_ptr(),
                )
            };
            if fd < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection has no valid fd",
                ));
            }
            fd
        };

        // Put the socket into non-blocking mode so OpenSSL returns WANT_READ/WRITE.
        unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
            if flags == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(AsyncFdConn {
            inner: tokio::io::unix::AsyncFd::new(conn)?,
        })
    }

    /// Read data from the connection without blocking the tokio thread.
    ///
    /// Waits until the socket is readable, then calls the non-blocking C
    /// function. Retries automatically if the C layer returns `WOULD_BLOCK`
    /// (OpenSSL renegotiation / fragmentation).
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            let conn_ptr = match self.inner.get_ref().ptr {
                Some(p) => p.as_ptr(),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection is closed",
                    ))
                }
            };

            let mut err = crate::ffi_helpers::init_c_err();
            let n = unsafe {
                mtls_sys::mtls_conn_read_nonblocking(
                    conn_ptr,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    &mut err,
                )
            };

            if n > 0 {
                return Ok(n as usize);
            }
            if n == 0 {
                return Ok(0); // EOF
            }

            // n < 0 — check for WOULD_BLOCK
            if err.code == mtls_sys::mtls_error_code::MTLS_ERR_WOULD_BLOCK {
                guard.clear_ready();
                continue;
            }

            return Err(Error::from_c_err(&err).into());
        }
    }

    /// Write data to the connection without blocking the tokio thread.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            let conn_ptr = match self.inner.get_ref().ptr {
                Some(p) => p.as_ptr(),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection is closed",
                    ))
                }
            };

            let mut err = crate::ffi_helpers::init_c_err();
            let n = unsafe {
                mtls_sys::mtls_conn_write_nonblocking(
                    conn_ptr,
                    buf.as_ptr() as *const _,
                    buf.len(),
                    &mut err,
                )
            };

            if n >= 0 {
                return Ok(n as usize);
            }

            if err.code == mtls_sys::mtls_error_code::MTLS_ERR_WOULD_BLOCK {
                guard.clear_ready();
                continue;
            }

            return Err(Error::from_c_err(&err).into());
        }
    }

    /// Write all bytes in `buf`, retrying on partial writes.
    pub async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            let n = self.write(&buf[written..]).await?;
            written += n;
        }
        Ok(())
    }

    /// Close the connection gracefully.
    pub fn close(&mut self) {
        self.inner.get_mut().close();
    }

    /// Get the connection state.
    pub fn state(&self) -> crate::identity::ConnState {
        self.inner.get_ref().state()
    }

    /// Get peer identity if available.
    pub fn peer_identity(&self) -> Option<crate::identity::PeerIdentity> {
        self.inner.get_ref().peer_identity()
    }

    /// Get remote address if available.
    pub fn remote_addr(&self) -> Option<String> {
        self.inner.get_ref().remote_addr()
    }

    /// Get local address if available.
    pub fn local_addr(&self) -> Option<String> {
        self.inner.get_ref().local_addr()
    }
}

#[cfg(all(feature = "async-tokio-native", unix))]
impl std::os::unix::io::AsRawFd for AsyncFdConn {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        unsafe {
            self.inner
                .get_ref()
                .ptr
                .map(|p| mtls_sys::mtls_conn_get_fd(p.as_ptr()))
                .unwrap_or(-1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_state_initial() {
        // Cannot test fully without a real connection, but we can test the enum
        assert!(ConnState::Established.is_established());
        assert!(ConnState::Closed.is_closed());
    }
}
