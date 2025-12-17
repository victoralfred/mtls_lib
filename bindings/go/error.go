package mtls

/*
#include <mtls/mtls.h>
*/
import "C"

import (
	"fmt"
	"syscall"
)

// ErrorCode represents an mTLS error code.
type ErrorCode int

// Error code constants matching C library error codes.
const (
	// Success
	ErrOK ErrorCode = 0

	// Configuration errors (1xx)
	ErrInvalidConfig     ErrorCode = 100
	ErrInvalidArgument   ErrorCode = 101
	ErrCACertNotFound    ErrorCode = 102
	ErrCertNotFound      ErrorCode = 103
	ErrKeyNotFound       ErrorCode = 104
	ErrCACertParseFailed ErrorCode = 105
	ErrCertParseFailed   ErrorCode = 106
	ErrKeyParseFailed    ErrorCode = 107
	ErrCertKeyMismatch   ErrorCode = 108
	ErrOutOfMemory       ErrorCode = 109
	ErrCtxNotInitialized ErrorCode = 110

	// Connection/network errors (2xx)
	ErrConnectFailed      ErrorCode = 200
	ErrConnectTimeout     ErrorCode = 201
	ErrDNSFailed          ErrorCode = 202
	ErrSocketCreateFailed ErrorCode = 203
	ErrSocketBindFailed   ErrorCode = 204
	ErrSocketListenFailed ErrorCode = 205
	ErrAcceptFailed       ErrorCode = 206
	ErrConnectionRefused  ErrorCode = 207
	ErrNetworkUnreachable ErrorCode = 208
	ErrHostUnreachable    ErrorCode = 209
	ErrAddressInUse       ErrorCode = 210
	ErrInvalidAddress     ErrorCode = 211

	// TLS/certificate errors (3xx)
	ErrTLSInitFailed        ErrorCode = 300
	ErrTLSHandshakeFailed   ErrorCode = 301
	ErrTLSVersionMismatch   ErrorCode = 302
	ErrTLSCipherMismatch    ErrorCode = 303
	ErrCertExpired          ErrorCode = 304
	ErrCertNotYetValid      ErrorCode = 305
	ErrCertRevoked          ErrorCode = 306
	ErrCertUntrusted        ErrorCode = 307
	ErrCertChainTooLong     ErrorCode = 308
	ErrCertSignatureInvalid ErrorCode = 309
	ErrNoPeerCert           ErrorCode = 310
	ErrHostnameMismatch     ErrorCode = 311
	ErrTLSShutdownFailed    ErrorCode = 312

	// Identity/verification errors (4xx)
	ErrIdentityMismatch  ErrorCode = 400
	ErrSANNotAllowed     ErrorCode = 401
	ErrSPIFFEParseFailed ErrorCode = 402
	ErrCNNotAllowed      ErrorCode = 403
	ErrNoAllowedIdentity ErrorCode = 404
	ErrIdentityTooLong   ErrorCode = 405

	// Policy errors (5xx)
	ErrKillSwitchEnabled    ErrorCode = 500
	ErrPolicyDenied         ErrorCode = 501
	ErrConnectionNotAllowed ErrorCode = 502

	// I/O errors (6xx)
	ErrReadFailed       ErrorCode = 600
	ErrWriteFailed      ErrorCode = 601
	ErrConnectionClosed ErrorCode = 602
	ErrConnectionReset  ErrorCode = 603
	ErrReadTimeout      ErrorCode = 604
	ErrWriteTimeout     ErrorCode = 605
	ErrWouldBlock       ErrorCode = 606
	ErrPartialWrite     ErrorCode = 607
	ErrEOF              ErrorCode = 608

	// Internal/unknown errors (9xx)
	ErrInternal       ErrorCode = 900
	ErrNotImplemented ErrorCode = 901
	ErrUnknown        ErrorCode = 999
)

// String returns the error code name.
func (c ErrorCode) String() string {
	cName := C.mtls_err_code_name(C.mtls_error_code(c))
	if cName != nil {
		return C.GoString(cName)
	}
	return fmt.Sprintf("UNKNOWN_ERROR_%d", c)
}

// Category returns the error category name.
func (c ErrorCode) Category() string {
	cCat := C.mtls_err_category_name(C.mtls_error_code(c))
	if cCat != nil {
		return C.GoString(cCat)
	}
	return "unknown"
}

// Error represents an mTLS library error with full context.
//
// The error may contain multiple underlying causes:
//   - OSError: Set for syscall/OS-level failures (e.g., ECONNREFUSED)
//   - TLSError: Set for OpenSSL-level failures (contains packed OpenSSL error)
//
// Use Unwrap() with errors.Is/As to check for OS errors.
// Use HasTLSError() and TLSErrorInfo() to inspect OpenSSL errors.
type Error struct {
	// Code is the primary error code.
	Code ErrorCode
	// Message is a human-readable error message.
	Message string
	// OSError is the underlying OS error (if any). This is set for syscall failures
	// and can be unwrapped using errors.Is/As.
	OSError error
	// TLSError is the OpenSSL error code (if any). This is a packed OpenSSL error
	// that can be inspected using HasTLSError() and TLSErrorInfo().
	TLSError uint64
	// File is the source file where the error occurred (debug info).
	File string
	// Line is the source line where the error occurred (debug info).
	Line int
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Message
}

// Unwrap returns the underlying OS error for use with errors.Is/As.
func (e *Error) Unwrap() error {
	return e.OSError
}

// IsConfig returns true if this is a configuration error.
func (e *Error) IsConfig() bool {
	return e.Code >= 100 && e.Code < 200
}

// IsNetwork returns true if this is a network error.
func (e *Error) IsNetwork() bool {
	return e.Code >= 200 && e.Code < 300
}

// IsTLS returns true if this is a TLS/certificate error.
func (e *Error) IsTLS() bool {
	return e.Code >= 300 && e.Code < 400
}

// IsIdentity returns true if this is an identity/verification error.
func (e *Error) IsIdentity() bool {
	return e.Code >= 400 && e.Code < 500
}

// IsPolicy returns true if this is a policy error.
func (e *Error) IsPolicy() bool {
	return e.Code >= 500 && e.Code < 600
}

// IsIO returns true if this is an I/O error.
func (e *Error) IsIO() bool {
	return e.Code >= 600 && e.Code < 700
}

// IsRecoverable returns true if the error is potentially recoverable
// (timeouts, would-block conditions).
func (e *Error) IsRecoverable() bool {
	return e.Code == ErrConnectTimeout ||
		e.Code == ErrReadTimeout ||
		e.Code == ErrWriteTimeout ||
		e.Code == ErrWouldBlock
}

// HasTLSError returns true if this error contains OpenSSL error information.
func (e *Error) HasTLSError() bool {
	return e.TLSError != 0
}

// TLSErrorInfo returns a human-readable description of the OpenSSL error.
// Returns an empty string if no TLS error is present.
func (e *Error) TLSErrorInfo() string {
	if e.TLSError == 0 {
		return ""
	}
	// OpenSSL error format: library (8 bits), reason (12 bits)
	// The library and reason can be extracted, but without OpenSSL headers
	// we can only provide the raw code. The Message field typically contains
	// the human-readable OpenSSL error string from the C library.
	return fmt.Sprintf("OpenSSL error 0x%x", e.TLSError)
}

// HasOSError returns true if this error contains an underlying OS error.
func (e *Error) HasOSError() bool {
	return e.OSError != nil
}

// convertError converts a C mtls_err to a Go Error.
// Returns nil if the error code is MTLS_OK (success).
func convertError(cErr *C.mtls_err) error {
	if cErr == nil || cErr.code == C.MTLS_OK {
		return nil
	}

	err := &Error{
		Code:     ErrorCode(cErr.code),
		Message:  C.GoString(&cErr.message[0]),
		TLSError: uint64(cErr.ssl_err),
	}

	if cErr.os_errno != 0 {
		err.OSError = syscall.Errno(cErr.os_errno)
	}

	if cErr.file != nil {
		err.File = C.GoString(cErr.file)
	}
	err.Line = int(cErr.line)

	return err
}

// initErr initializes a C mtls_err structure.
func initErr(cErr *C.mtls_err) {
	C.mtls_err_init(cErr)
}

// IsConfigError returns true if err is an mTLS configuration error.
func IsConfigError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsConfig()
	}
	return false
}

// IsNetworkError returns true if err is an mTLS network error.
func IsNetworkError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsNetwork()
	}
	return false
}

// IsTLSError returns true if err is an mTLS TLS/certificate error.
func IsTLSError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsTLS()
	}
	return false
}

// IsIdentityError returns true if err is an mTLS identity error.
func IsIdentityError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsIdentity()
	}
	return false
}

// IsPolicyError returns true if err is an mTLS policy error.
func IsPolicyError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsPolicy()
	}
	return false
}

// IsIOError returns true if err is an mTLS I/O error.
func IsIOError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsIO()
	}
	return false
}

// IsRecoverableError returns true if err is potentially recoverable.
func IsRecoverableError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsRecoverable()
	}
	return false
}
