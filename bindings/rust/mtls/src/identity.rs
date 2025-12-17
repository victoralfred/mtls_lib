//! Peer identity and connection state types.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ffi_helpers::from_c_char_array;

/// Connection state enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ConnState {
    /// Connection not initialized.
    None = 0,
    /// TCP connection in progress.
    Connecting = 1,
    /// TLS handshake in progress.
    Handshaking = 2,
    /// Connection established and verified.
    Established = 3,
    /// Shutdown in progress.
    Closing = 4,
    /// Connection closed.
    Closed = 5,
    /// Connection in error state.
    Error = 6,
}

impl ConnState {
    /// Convert from C mtls_conn_state enum.
    pub fn from_c(state: mtls_sys::mtls_conn_state) -> Self {
        match state {
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_NONE => ConnState::None,
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_CONNECTING => ConnState::Connecting,
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_HANDSHAKING => ConnState::Handshaking,
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_ESTABLISHED => ConnState::Established,
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_CLOSING => ConnState::Closing,
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_CLOSED => ConnState::Closed,
            mtls_sys::mtls_conn_state::MTLS_CONN_STATE_ERROR => ConnState::Error,
        }
    }

    /// Convert from a raw i32 value.
    pub fn from_i32(state: i32) -> Self {
        match state {
            0 => ConnState::None,
            1 => ConnState::Connecting,
            2 => ConnState::Handshaking,
            3 => ConnState::Established,
            4 => ConnState::Closing,
            5 => ConnState::Closed,
            6 => ConnState::Error,
            _ => ConnState::None,
        }
    }

    /// Returns true if the connection is established.
    pub fn is_established(&self) -> bool {
        *self == ConnState::Established
    }

    /// Returns true if the connection is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self, ConnState::Closed | ConnState::Error)
    }
}

impl std::fmt::Display for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ConnState::None => "None",
            ConnState::Connecting => "Connecting",
            ConnState::Handshaking => "Handshaking",
            ConnState::Established => "Established",
            ConnState::Closing => "Closing",
            ConnState::Closed => "Closed",
            ConnState::Error => "Error",
        };
        write!(f, "{}", name)
    }
}

/// Peer certificate identity information.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// Common Name (CN) from the certificate subject.
    pub common_name: String,

    /// Subject Alternative Names (SANs) from the certificate.
    pub sans: Vec<String>,

    /// SPIFFE ID if present in the certificate SANs.
    pub spiffe_id: Option<String>,

    /// Certificate validity start time.
    pub not_before: SystemTime,

    /// Certificate validity end time.
    pub not_after: SystemTime,
}

impl PeerIdentity {
    /// Create a PeerIdentity from a C mtls_peer_identity structure.
    ///
    /// # Safety
    /// The c_identity pointer must be valid and point to a properly initialized structure.
    pub(crate) unsafe fn from_c(c_identity: &mtls_sys::mtls_peer_identity) -> Self {
        let common_name = from_c_char_array(&c_identity.common_name);

        // Extract SANs
        let mut sans = Vec::new();
        if c_identity.san_count > 0 && !c_identity.sans.is_null() {
            let san_slice = std::slice::from_raw_parts(
                c_identity.sans,
                c_identity.san_count.min(128), // Bound to MTLS_MAX_CERT_SANS
            );
            for &san_ptr in san_slice {
                if !san_ptr.is_null() {
                    let san = std::ffi::CStr::from_ptr(san_ptr)
                        .to_string_lossy()
                        .into_owned();
                    sans.push(san);
                }
            }
        }

        // Extract SPIFFE ID
        let spiffe_id_str = from_c_char_array(&c_identity.spiffe_id);
        let spiffe_id = if spiffe_id_str.is_empty() {
            None
        } else {
            Some(spiffe_id_str)
        };

        // Convert timestamps
        let not_before = UNIX_EPOCH + Duration::from_secs(c_identity.cert_not_before as u64);
        let not_after = UNIX_EPOCH + Duration::from_secs(c_identity.cert_not_after as u64);

        PeerIdentity {
            common_name,
            sans,
            spiffe_id,
            not_before,
            not_after,
        }
    }

    /// Returns true if the certificate is currently valid.
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();
        now >= self.not_before && now < self.not_after
    }

    /// Returns the time until the certificate expires.
    ///
    /// Returns None if the certificate has already expired.
    pub fn ttl(&self) -> Option<Duration> {
        self.not_after.duration_since(SystemTime::now()).ok()
    }

    /// Returns true if the certificate contains a SPIFFE ID.
    pub fn has_spiffe_id(&self) -> bool {
        self.spiffe_id.is_some()
    }

    /// Check if any of the identity's SANs match the allowed patterns.
    ///
    /// Supports exact matching and wildcard DNS matching (*.example.com).
    pub fn validate_sans(&self, allowed_sans: &[String]) -> bool {
        if allowed_sans.is_empty() {
            return false;
        }

        // Check each peer SAN
        for peer_san in &self.sans {
            for allowed in allowed_sans {
                if match_san(peer_san, allowed) {
                    return true;
                }
            }
        }

        // Also check SPIFFE ID
        if let Some(ref spiffe_id) = self.spiffe_id {
            for allowed in allowed_sans {
                if match_san(spiffe_id, allowed) {
                    return true;
                }
            }
        }

        false
    }
}

/// Match a SAN against a pattern, supporting wildcards.
fn match_san(san: &str, pattern: &str) -> bool {
    // Exact match
    if san == pattern {
        return true;
    }

    // Wildcard match (*.example.com)
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // .example.com
        if san.len() > suffix.len() && san.ends_with(suffix) {
            // Check that prefix has no dots (single level wildcard)
            let prefix = &san[..san.len() - suffix.len()];
            if !prefix.contains('.') {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_state() {
        assert!(ConnState::Established.is_established());
        assert!(ConnState::Closed.is_closed());
        assert!(ConnState::Error.is_closed());
        assert!(!ConnState::Connecting.is_closed());
    }

    #[test]
    fn test_match_san_exact() {
        assert!(match_san("example.com", "example.com"));
        assert!(!match_san("example.com", "other.com"));
    }

    #[test]
    fn test_match_san_wildcard() {
        assert!(match_san("foo.example.com", "*.example.com"));
        assert!(match_san("bar.example.com", "*.example.com"));
        assert!(!match_san("foo.bar.example.com", "*.example.com")); // Multi-level
        assert!(!match_san("example.com", "*.example.com")); // No prefix
    }

    #[test]
    fn test_peer_identity_validate_sans() {
        let identity = PeerIdentity {
            common_name: "test".to_string(),
            sans: vec!["client.example.com".to_string()],
            spiffe_id: None,
            not_before: UNIX_EPOCH,
            not_after: SystemTime::now() + Duration::from_secs(3600),
        };

        assert!(identity.validate_sans(&["client.example.com".to_string()]));
        assert!(identity.validate_sans(&["*.example.com".to_string()]));
        assert!(!identity.validate_sans(&["other.com".to_string()]));
    }
}
