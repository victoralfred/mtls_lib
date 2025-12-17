//! Event system for observing mTLS connection lifecycle events.

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

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
        }
    }

    /// Check if this is an error-related event.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            EventType::ConnectFailure | EventType::HandshakeFailed
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
/// Performance note: Uses Mutex for thread safety. The lock is held
/// only briefly during lookup, minimizing contention. For high-throughput
/// scenarios, consider using a lock-free data structure or sharding.
static CALLBACK_REGISTRY: LazyLock<Mutex<HashMap<usize, EventCallback>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_CALLBACK_ID: AtomicUsize = AtomicUsize::new(1);

/// Register a callback and return its ID.
fn register_callback(callback: Box<dyn Fn(&Event) + Send + Sync + 'static>) -> usize {
    let id = NEXT_CALLBACK_ID.fetch_add(1, Ordering::SeqCst);
    let mut registry = CALLBACK_REGISTRY.lock().unwrap();
    registry.insert(id, Arc::from(callback));
    id
}

/// Unregister a callback by ID.
fn unregister_callback(id: usize) {
    let mut registry = CALLBACK_REGISTRY.lock().unwrap();
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
        let registry = CALLBACK_REGISTRY.lock().unwrap();
        registry.get(&id).cloned()
    };

    // Call callback outside of lock to avoid deadlock if callback
    // tries to register/unregister other callbacks or acquires locks
    if let Some(callback) = callback {
        callback(&rust_event);
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

        let mut observers = mtls_sys::mtls_observers::default();
        observers.on_event = Some(c_event_callback);
        observers.userdata = id as *mut c_void;

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
    fn test_callback_registry() {
        let id = register_callback(Box::new(|_| {}));
        assert!(id > 0);

        unregister_callback(id);
    }
}
