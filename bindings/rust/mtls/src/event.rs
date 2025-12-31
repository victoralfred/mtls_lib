//! Event system for observing mTLS connection lifecycle events.

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use crate::context::Context;
use crate::ffi_helpers::from_c_str;

/// Event types emitted by the mTLS library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum EventType {
    /// Connection start.
    ConnectStart = 1,
    /// Connection success.
    ConnectSuccess = 2,
    /// Connection failure.
    ConnectFailure = 3,
    /// Handshake start.
    HandshakeStart = 4,
    /// Handshake success.
    HandshakeSuccess = 5,
    /// Handshake failure.
    HandshakeFailed = 6,
    /// Data read.
    Read = 7,
    /// Data written.
    Write = 8,
    /// Connection closed.
    Close = 9,
    /// Kill switch triggered.
    KillSwitchTriggered = 10,
    // OCSP/CRL events (11-20)
    /// OCSP check started.
    OcspCheckStart = 11,
    /// OCSP check succeeded.
    OcspCheckSuccess = 12,
    /// OCSP check failed.
    OcspCheckFailure = 13,
    /// OCSP staple verified.
    OcspStapleVerified = 14,
    /// CRL check started.
    CrlCheckStart = 15,
    /// CRL check succeeded.
    CrlCheckSuccess = 16,
    /// CRL check failed.
    CrlCheckFailure = 17,
    /// CRL download started.
    CrlDownloadStart = 18,
    /// CRL download succeeded.
    CrlDownloadSuccess = 19,
    /// CRL download failed.
    CrlDownloadFailure = 20,
    // Certificate pinning events (60-62)
    /// Pin check started.
    PinCheckStart = 60,
    /// Pin check succeeded.
    PinCheckSuccess = 61,
    /// Pin check failed.
    PinCheckFailure = 62,
    // HSM events (70-73)
    /// HSM initialization started.
    HsmInitStart = 70,
    /// HSM initialization succeeded.
    HsmInitSuccess = 71,
    /// HSM initialization failed.
    HsmInitFailure = 72,
    /// HSM key loaded.
    HsmKeyLoaded = 73,
    // Rate limiting events (21-23)
    /// Rate limit check.
    RateLimitCheck = 21,
    /// Rate limit exceeded.
    RateLimitExceeded = 22,
    /// Rate limit allowed.
    RateLimitAllowed = 23,
    // Deadline events (30-31)
    /// Deadline-aware operation started.
    DeadlineStart = 30,
    /// Deadline exceeded.
    DeadlineExceeded = 31,
    // Certificate Transparency events (80-83)
    /// CT check started.
    CtCheckStart = 80,
    /// CT check succeeded.
    CtCheckSuccess = 81,
    /// CT check failed.
    CtCheckFailure = 82,
    /// SCT validated.
    CtSctValidated = 83,
    /// Unknown event type.
    Unknown = 0,
}

impl EventType {
    /// Convert from C mtls_event_type enum.
    pub fn from_c(value: mtls_sys::mtls_event_type) -> Self {
        match value {
            mtls_sys::mtls_event_type::MTLS_EVENT_CONNECT_START => EventType::ConnectStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_CONNECT_SUCCESS => EventType::ConnectSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_CONNECT_FAILURE => EventType::ConnectFailure,
            mtls_sys::mtls_event_type::MTLS_EVENT_HANDSHAKE_START => EventType::HandshakeStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_HANDSHAKE_SUCCESS => EventType::HandshakeSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_HANDSHAKE_FAILURE => EventType::HandshakeFailed,
            mtls_sys::mtls_event_type::MTLS_EVENT_READ => EventType::Read,
            mtls_sys::mtls_event_type::MTLS_EVENT_WRITE => EventType::Write,
            mtls_sys::mtls_event_type::MTLS_EVENT_CLOSE => EventType::Close,
            mtls_sys::mtls_event_type::MTLS_EVENT_KILL_SWITCH_TRIGGERED => {
                EventType::KillSwitchTriggered
            }
            mtls_sys::mtls_event_type::MTLS_EVENT_OCSP_CHECK_START => EventType::OcspCheckStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_OCSP_CHECK_SUCCESS => EventType::OcspCheckSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_OCSP_CHECK_FAILURE => EventType::OcspCheckFailure,
            mtls_sys::mtls_event_type::MTLS_EVENT_OCSP_STAPLE_VERIFIED => {
                EventType::OcspStapleVerified
            }
            mtls_sys::mtls_event_type::MTLS_EVENT_CRL_CHECK_START => EventType::CrlCheckStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_CRL_CHECK_SUCCESS => EventType::CrlCheckSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_CRL_CHECK_FAILURE => EventType::CrlCheckFailure,
            mtls_sys::mtls_event_type::MTLS_EVENT_CRL_DOWNLOAD_START => EventType::CrlDownloadStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_CRL_DOWNLOAD_SUCCESS => {
                EventType::CrlDownloadSuccess
            }
            mtls_sys::mtls_event_type::MTLS_EVENT_CRL_DOWNLOAD_FAILURE => {
                EventType::CrlDownloadFailure
            }
            mtls_sys::mtls_event_type::MTLS_EVENT_PIN_CHECK_START => EventType::PinCheckStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_PIN_CHECK_SUCCESS => EventType::PinCheckSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_PIN_CHECK_FAILURE => EventType::PinCheckFailure,
            mtls_sys::mtls_event_type::MTLS_EVENT_HSM_INIT_START => EventType::HsmInitStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_HSM_INIT_SUCCESS => EventType::HsmInitSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_HSM_INIT_FAILURE => EventType::HsmInitFailure,
            mtls_sys::mtls_event_type::MTLS_EVENT_HSM_KEY_LOADED => EventType::HsmKeyLoaded,
            mtls_sys::mtls_event_type::MTLS_EVENT_CT_CHECK_START => EventType::CtCheckStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_CT_CHECK_SUCCESS => EventType::CtCheckSuccess,
            mtls_sys::mtls_event_type::MTLS_EVENT_CT_CHECK_FAILURE => EventType::CtCheckFailure,
            mtls_sys::mtls_event_type::MTLS_EVENT_CT_SCT_VALIDATED => EventType::CtSctValidated,
            mtls_sys::mtls_event_type::MTLS_EVENT_RATE_LIMIT_CHECK => EventType::RateLimitCheck,
            mtls_sys::mtls_event_type::MTLS_EVENT_RATE_LIMIT_EXCEEDED => {
                EventType::RateLimitExceeded
            }
            mtls_sys::mtls_event_type::MTLS_EVENT_RATE_LIMIT_ALLOWED => {
                EventType::RateLimitAllowed
            }
            mtls_sys::mtls_event_type::MTLS_EVENT_DEADLINE_START => EventType::DeadlineStart,
            mtls_sys::mtls_event_type::MTLS_EVENT_DEADLINE_EXCEEDED => EventType::DeadlineExceeded,
        }
    }

    /// Check if this is an error-related event.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            EventType::ConnectFailure
                | EventType::HandshakeFailed
                | EventType::OcspCheckFailure
                | EventType::CrlCheckFailure
                | EventType::CrlDownloadFailure
                | EventType::PinCheckFailure
                | EventType::HsmInitFailure
                | EventType::CtCheckFailure
                | EventType::RateLimitExceeded
                | EventType::DeadlineExceeded
        )
    }

    /// Check if this is a success event.
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            EventType::ConnectSuccess
                | EventType::HandshakeSuccess
                | EventType::OcspCheckSuccess
                | EventType::OcspStapleVerified
                | EventType::CrlCheckSuccess
                | EventType::CrlDownloadSuccess
                | EventType::PinCheckSuccess
                | EventType::HsmInitSuccess
                | EventType::CtCheckSuccess
                | EventType::RateLimitAllowed
        )
    }

    /// Check if this is a connection lifecycle event.
    pub fn is_connection_event(&self) -> bool {
        matches!(
            self,
            EventType::ConnectStart
                | EventType::ConnectSuccess
                | EventType::ConnectFailure
                | EventType::HandshakeStart
                | EventType::HandshakeSuccess
                | EventType::HandshakeFailed
                | EventType::Close
        )
    }

    /// Check if this is an OCSP event.
    pub fn is_ocsp(&self) -> bool {
        matches!(
            self,
            EventType::OcspCheckStart
                | EventType::OcspCheckSuccess
                | EventType::OcspCheckFailure
                | EventType::OcspStapleVerified
        )
    }

    /// Check if this is a CRL event.
    pub fn is_crl(&self) -> bool {
        matches!(
            self,
            EventType::CrlCheckStart
                | EventType::CrlCheckSuccess
                | EventType::CrlCheckFailure
                | EventType::CrlDownloadStart
                | EventType::CrlDownloadSuccess
                | EventType::CrlDownloadFailure
        )
    }

    /// Check if this is a revocation event (OCSP or CRL).
    pub fn is_revocation(&self) -> bool {
        self.is_ocsp() || self.is_crl()
    }

    /// Check if this is an I/O event.
    pub fn is_io(&self) -> bool {
        matches!(self, EventType::Read | EventType::Write)
    }

    /// Check if this is a certificate pinning event.
    pub fn is_pinning(&self) -> bool {
        matches!(
            self,
            EventType::PinCheckStart | EventType::PinCheckSuccess | EventType::PinCheckFailure
        )
    }

    /// Check if this is a Certificate Transparency event.
    pub fn is_ct(&self) -> bool {
        matches!(
            self,
            EventType::CtCheckStart
                | EventType::CtCheckSuccess
                | EventType::CtCheckFailure
                | EventType::CtSctValidated
        )
    }

    /// Check if this is an HSM event.
    pub fn is_hsm(&self) -> bool {
        matches!(
            self,
            EventType::HsmInitStart
                | EventType::HsmInitSuccess
                | EventType::HsmInitFailure
                | EventType::HsmKeyLoaded
        )
    }

    /// Check if this is a rate limiting event.
    pub fn is_rate_limit(&self) -> bool {
        matches!(
            self,
            EventType::RateLimitCheck
                | EventType::RateLimitExceeded
                | EventType::RateLimitAllowed
        )
    }

    /// Check if this is a deadline event.
    pub fn is_deadline(&self) -> bool {
        matches!(
            self,
            EventType::DeadlineStart | EventType::DeadlineExceeded
        )
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            EventType::ConnectStart => "ConnectStart",
            EventType::ConnectSuccess => "ConnectSuccess",
            EventType::ConnectFailure => "ConnectFailure",
            EventType::HandshakeStart => "HandshakeStart",
            EventType::HandshakeSuccess => "HandshakeSuccess",
            EventType::HandshakeFailed => "HandshakeFailed",
            EventType::Read => "Read",
            EventType::Write => "Write",
            EventType::Close => "Close",
            EventType::KillSwitchTriggered => "KillSwitchTriggered",
            EventType::OcspCheckStart => "OcspCheckStart",
            EventType::OcspCheckSuccess => "OcspCheckSuccess",
            EventType::OcspCheckFailure => "OcspCheckFailure",
            EventType::OcspStapleVerified => "OcspStapleVerified",
            EventType::CrlCheckStart => "CrlCheckStart",
            EventType::CrlCheckSuccess => "CrlCheckSuccess",
            EventType::CrlCheckFailure => "CrlCheckFailure",
            EventType::CrlDownloadStart => "CrlDownloadStart",
            EventType::CrlDownloadSuccess => "CrlDownloadSuccess",
            EventType::CrlDownloadFailure => "CrlDownloadFailure",
            EventType::PinCheckStart => "PinCheckStart",
            EventType::PinCheckSuccess => "PinCheckSuccess",
            EventType::PinCheckFailure => "PinCheckFailure",
            EventType::HsmInitStart => "HsmInitStart",
            EventType::HsmInitSuccess => "HsmInitSuccess",
            EventType::HsmInitFailure => "HsmInitFailure",
            EventType::HsmKeyLoaded => "HsmKeyLoaded",
            EventType::CtCheckStart => "CtCheckStart",
            EventType::CtCheckSuccess => "CtCheckSuccess",
            EventType::CtCheckFailure => "CtCheckFailure",
            EventType::CtSctValidated => "CtSctValidated",
            EventType::RateLimitCheck => "RateLimitCheck",
            EventType::RateLimitExceeded => "RateLimitExceeded",
            EventType::RateLimitAllowed => "RateLimitAllowed",
            EventType::DeadlineStart => "DeadlineStart",
            EventType::DeadlineExceeded => "DeadlineExceeded",
            EventType::Unknown => "Unknown",
        };
        write!(f, "{}", name)
    }
}

/// An event emitted by the mTLS library.
#[derive(Debug, Clone)]
pub struct Event {
    /// The type of event.
    pub event_type: EventType,
    /// Remote address (if applicable).
    pub remote_addr: String,
    /// Error code (if applicable).
    pub error_code: i32,
    /// Timestamp in microseconds since epoch.
    pub timestamp_us: u64,
    /// Duration of the operation in microseconds.
    pub duration_us: u64,
    /// Number of bytes (for read/write events).
    pub bytes: usize,
}

impl Event {
    /// Create an Event from a C mtls_event structure.
    ///
    /// # Safety
    /// The c_event pointer must be valid.
    pub(crate) unsafe fn from_c(c_event: &mtls_sys::mtls_event) -> Self {
        Event {
            event_type: EventType::from_c(c_event.type_),
            remote_addr: from_c_str(c_event.remote_addr),
            error_code: c_event.error_code,
            timestamp_us: c_event.timestamp_us,
            duration_us: c_event.duration_us,
            bytes: c_event.bytes,
        }
    }
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} addr={} bytes={}",
            self.timestamp_us, self.event_type, self.remote_addr, self.bytes
        )
    }
}

/// Type alias for event callback functions.
/// Uses Arc for efficient cloning to avoid holding locks during callback execution.
pub type EventCallback = Arc<dyn Fn(&Event) + Send + Sync>;

/// Global registry for event callbacks.
///
/// This is needed because C function pointers cannot capture state,
/// so we store callbacks in a global registry and pass IDs through
/// the user_data pointer.
///
/// Performance note: Uses a `RwLock` so callback dispatch takes a shared read lock
/// (many concurrent readers), while register/unregister take an exclusive write lock
/// (rare). This reduces contention on hot event paths.
static CALLBACK_REGISTRY: OnceLock<RwLock<HashMap<usize, EventCallback>>> = OnceLock::new();
static NEXT_CALLBACK_ID: AtomicUsize = AtomicUsize::new(1);

#[inline]
fn callback_registry() -> &'static RwLock<HashMap<usize, EventCallback>> {
    CALLBACK_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a callback and return its ID.
fn register_callback(callback: Box<dyn Fn(&Event) + Send + Sync + 'static>) -> usize {
    let id = NEXT_CALLBACK_ID.fetch_add(1, Ordering::Relaxed);
    let mut registry = callback_registry().write().unwrap();
    registry.insert(id, Arc::from(callback));
    id
}

/// Unregister a callback by ID.
fn unregister_callback(id: usize) {
    let mut registry = callback_registry().write().unwrap();
    registry.remove(&id);
}

/// The C callback gateway function.
///
/// This function is called by the C library and dispatches to the
/// registered Rust callback based on the user_data ID.
///
/// # Safety
/// This function is called from C code, so it must be safe to call
/// from any thread. We minimize lock hold time by cloning the Arc
/// (which is cheap) and calling the callback outside the lock.
extern "C" fn c_event_callback(event: *const mtls_sys::mtls_event, user_data: *mut c_void) {
    if event.is_null() {
        return;
    }

    let id = user_data as usize;
    if id == 0 {
        return;
    }

    // Convert C event to Rust event (safe - event is valid during callback)
    let rust_event = unsafe { Event::from_c(&*event) };

    // Look up and clone the callback (Arc clone is cheap)
    // This allows us to release the lock before calling the callback,
    // preventing deadlocks if the callback tries to register/unregister
    let callback = {
        let registry = callback_registry().read().unwrap();
        registry.get(&id).cloned()
    };

    // Call callback outside of lock to avoid deadlock if callback
    // tries to register/unregister other callbacks or acquires locks
    // Use catch_unwind to prevent panics from unwinding through C code (undefined behavior)
    if let Some(callback) = callback {
        if let Err(panic_info) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            callback(&rust_event);
        })) {
            // Log the panic - this prevents silent failures in production
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            log::error!(
                "mtls event callback panicked: {} (event: {:?})",
                panic_msg,
                rust_event.event_type
            );
        }
    }
}

/// Handle for a registered event observer.
///
/// When dropped, automatically unregisters the callback.
pub struct ObserverHandle {
    id: usize,
}

impl Drop for ObserverHandle {
    fn drop(&mut self) {
        unregister_callback(self.id);
    }
}

impl Context {
    /// Set an event observer callback on this context.
    ///
    /// The callback will be invoked for all events related to this context.
    /// Returns a handle that unregisters the callback when dropped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let _handle = ctx.set_observer(|event| {
    ///     println!("Event: {}", event);
    /// })?;
    /// ```
    pub fn set_observer<F>(&self, callback: F) -> crate::error::Result<ObserverHandle>
    where
        F: Fn(&Event) + Send + Sync + 'static,
    {
        let id = register_callback(Box::new(callback));

        let observers = mtls_sys::mtls_observers {
            on_event: Some(c_event_callback),
            userdata: id as *mut c_void,
        };

        let result = unsafe { mtls_sys::mtls_set_observers(self.as_ptr(), &observers) };

        if result != 0 {
            unregister_callback(id);
            return Err(crate::error::Error::new(
                crate::error::ErrorCode::Internal,
                "failed to set observer",
            ));
        }

        Ok(ObserverHandle { id })
    }

    /// Clear the event observer callback.
    pub fn clear_observer(&self) {
        let observers = mtls_sys::mtls_observers {
            on_event: None,
            userdata: std::ptr::null_mut(),
        };
        unsafe {
            mtls_sys::mtls_set_observers(self.as_ptr(), &observers);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_from_c() {
        assert_eq!(
            EventType::from_c(mtls_sys::mtls_event_type::MTLS_EVENT_CONNECT_START),
            EventType::ConnectStart
        );
        assert_eq!(
            EventType::from_c(mtls_sys::mtls_event_type::MTLS_EVENT_CLOSE),
            EventType::Close
        );
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::ConnectStart), "ConnectStart");
        assert_eq!(format!("{}", EventType::HandshakeFailed), "HandshakeFailed");
    }

    #[test]
    fn test_event_type_categories() {
        assert!(EventType::HandshakeFailed.is_error());
        assert!(EventType::ConnectStart.is_connection_event());
        assert!(!EventType::Read.is_connection_event());
    }

    #[test]
    fn test_ocsp_crl_event_categories() {
        // OCSP events
        assert!(EventType::OcspCheckStart.is_ocsp());
        assert!(EventType::OcspCheckSuccess.is_ocsp());
        assert!(EventType::OcspCheckFailure.is_ocsp());
        assert!(EventType::OcspStapleVerified.is_ocsp());
        assert!(!EventType::CrlCheckStart.is_ocsp());

        // CRL events
        assert!(EventType::CrlCheckStart.is_crl());
        assert!(EventType::CrlCheckSuccess.is_crl());
        assert!(EventType::CrlCheckFailure.is_crl());
        assert!(EventType::CrlDownloadStart.is_crl());
        assert!(EventType::CrlDownloadSuccess.is_crl());
        assert!(EventType::CrlDownloadFailure.is_crl());
        assert!(!EventType::OcspCheckStart.is_crl());

        // Revocation (either OCSP or CRL)
        assert!(EventType::OcspCheckStart.is_revocation());
        assert!(EventType::CrlCheckStart.is_revocation());
        assert!(!EventType::ConnectStart.is_revocation());

        // Success/error categorization
        assert!(EventType::OcspCheckSuccess.is_success());
        assert!(EventType::OcspStapleVerified.is_success());
        assert!(EventType::CrlCheckSuccess.is_success());
        assert!(EventType::CrlDownloadSuccess.is_success());

        assert!(EventType::OcspCheckFailure.is_error());
        assert!(EventType::CrlCheckFailure.is_error());
        assert!(EventType::CrlDownloadFailure.is_error());
    }

    #[test]
    fn test_ocsp_crl_event_display() {
        assert_eq!(format!("{}", EventType::OcspCheckStart), "OcspCheckStart");
        assert_eq!(format!("{}", EventType::CrlDownloadSuccess), "CrlDownloadSuccess");
    }

    #[test]
    fn test_io_event_category() {
        assert!(EventType::Read.is_io());
        assert!(EventType::Write.is_io());
        assert!(!EventType::ConnectStart.is_io());
    }

    #[test]
    fn test_callback_registry() {
        let id = register_callback(Box::new(|_| {}));
        assert!(id > 0);

        unregister_callback(id);
    }

    #[test]
    fn test_ct_event_categories() {
        // CT events
        assert!(EventType::CtCheckStart.is_ct());
        assert!(EventType::CtCheckSuccess.is_ct());
        assert!(EventType::CtCheckFailure.is_ct());
        assert!(EventType::CtSctValidated.is_ct());
        assert!(!EventType::ConnectStart.is_ct());

        // Success/error categorization
        assert!(EventType::CtCheckSuccess.is_success());
        assert!(EventType::CtCheckFailure.is_error());
    }

    #[test]
    fn test_ct_event_display() {
        assert_eq!(format!("{}", EventType::CtCheckStart), "CtCheckStart");
        assert_eq!(format!("{}", EventType::CtCheckSuccess), "CtCheckSuccess");
        assert_eq!(format!("{}", EventType::CtCheckFailure), "CtCheckFailure");
        assert_eq!(format!("{}", EventType::CtSctValidated), "CtSctValidated");
    }

    #[test]
    fn test_hsm_event_categories() {
        // HSM events
        assert!(EventType::HsmInitStart.is_hsm());
        assert!(EventType::HsmInitSuccess.is_hsm());
        assert!(EventType::HsmInitFailure.is_hsm());
        assert!(EventType::HsmKeyLoaded.is_hsm());
        assert!(!EventType::ConnectStart.is_hsm());

        // Success/error categorization
        assert!(EventType::HsmInitSuccess.is_success());
        assert!(EventType::HsmInitFailure.is_error());
    }

    #[test]
    fn test_hsm_event_display() {
        assert_eq!(format!("{}", EventType::HsmInitStart), "HsmInitStart");
        assert_eq!(format!("{}", EventType::HsmInitSuccess), "HsmInitSuccess");
        assert_eq!(format!("{}", EventType::HsmInitFailure), "HsmInitFailure");
        assert_eq!(format!("{}", EventType::HsmKeyLoaded), "HsmKeyLoaded");
    }

    #[test]
    fn test_deadline_event_categories() {
        // Deadline events
        assert!(EventType::DeadlineStart.is_deadline());
        assert!(EventType::DeadlineExceeded.is_deadline());
        assert!(!EventType::ConnectStart.is_deadline());

        // Error categorization
        assert!(EventType::DeadlineExceeded.is_error());
        assert!(!EventType::DeadlineStart.is_error());
    }

    #[test]
    fn test_deadline_event_display() {
        assert_eq!(format!("{}", EventType::DeadlineStart), "DeadlineStart");
        assert_eq!(format!("{}", EventType::DeadlineExceeded), "DeadlineExceeded");
    }
}
