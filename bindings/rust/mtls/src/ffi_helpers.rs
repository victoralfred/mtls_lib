//! FFI helper utilities for safe C interop.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::error::{Error, ErrorCode};

/// Convert a Rust string to a C string.
pub(crate) fn to_c_string(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::new(ErrorCode::InvalidArgument, "string contains null byte"))
}

/// Read a C string pointer into an owned String.
///
/// # Safety
/// The pointer must point to a valid null-terminated C string.
pub(crate) unsafe fn from_c_str(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

/// Read a fixed-size C char array into a String.
///
/// # Safety
/// The array must contain a null-terminated string.
pub(crate) unsafe fn from_c_char_array(arr: &[c_char]) -> String {
    if arr.is_empty() {
        return String::new();
    }
    CStr::from_ptr(arr.as_ptr()).to_string_lossy().into_owned()
}

/// Initialize a C mtls_err structure.
pub(crate) fn init_c_err() -> mtls_sys::mtls_err {
    let mut err: mtls_sys::mtls_err = unsafe { std::mem::zeroed() };
    unsafe {
        mtls_sys::mtls_err_init(&mut err);
    }
    err
}

/// Check if a C error indicates success.
pub(crate) fn is_c_err_ok(err: &mtls_sys::mtls_err) -> bool {
    err.code == mtls_sys::mtls_error_code::MTLS_OK
}
