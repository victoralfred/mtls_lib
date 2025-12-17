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

        let result = unsafe {
            mtls_sys::mtls_get_peer_identity(ptr, &mut identity, &mut err)
        };

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

        let result = unsafe {
            mtls_sys::mtls_get_peer_organization(ptr, org.as_mut_ptr(), org.len())
        };

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

        let result = unsafe {
            mtls_sys::mtls_get_peer_org_unit(ptr, ou.as_mut_ptr(), ou.len())
        };

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

        let result = unsafe {
            mtls_sys::mtls_get_remote_addr(ptr, addr.as_mut_ptr(), addr.len())
        };

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

        let result = unsafe {
            mtls_sys::mtls_get_local_addr(ptr, addr.as_mut_ptr(), addr.len())
        };

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

        let result = unsafe {
            mtls_sys::mtls_read(ptr, buf.as_mut_ptr() as *mut _, buf.len(), &mut err)
        };

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

        let result = unsafe {
            mtls_sys::mtls_write(ptr, buf.as_ptr() as *const _, buf.len(), &mut err)
        };

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
