package mtls

/*
#include <mtls/mtls_pinning.h>
*/
import "C"

import (
	"unsafe"
)

// PinResult represents the outcome of a pin validation.
type PinResult int

const (
	PinResultMatch       PinResult = C.MTLS_PIN_RESULT_MATCH
	PinResultNoMatch     PinResult = C.MTLS_PIN_RESULT_NO_MATCH
	PinResultInvalidPin  PinResult = C.MTLS_PIN_RESULT_INVALID_PIN
	PinResultError       PinResult = C.MTLS_PIN_RESULT_ERROR
)

// PinType specifies the type of certificate pin.
type PinType int

const (
	PinTypeSPKISHA256 PinType = C.MTLS_PIN_TYPE_SPKI_SHA256
	PinTypeCertSHA256 PinType = C.MTLS_PIN_TYPE_CERT_SHA256
)

// PinReport contains detailed results from a pin validation.
type PinReport struct {
	Result      PinResult
	MatchedType PinType
	MatchedPin  string
	CertSPKIHash string
	CertHash    string
	CertIndex   int
}

// PinSet holds a set of certificate pins for validation.
type PinSet struct {
	s C.mtls_pin_set
}

// NewPinSet creates a new pin set with default settings.
// By default RequireMatch is true and the full certificate chain is checked.
func NewPinSet() *PinSet {
	ps := &PinSet{}
	C.mtls_pin_set_init(&ps.s)
	return ps
}

// AddSPKISHA256 adds an SPKI SHA-256 pin (base64-encoded).
// SPKI pins are recommended as they survive certificate renewal.
func (ps *PinSet) AddSPKISHA256(base64Hash string) error {
	cHash := C.CString(base64Hash)
	defer freeString(cHash)

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_pin_set_add_spki_sha256(&ps.s, cHash, &cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// AddCertSHA256 adds a certificate SHA-256 pin (base64-encoded).
func (ps *PinSet) AddCertSHA256(base64Hash string) error {
	cHash := C.CString(base64Hash)
	defer freeString(cHash)

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_pin_set_add_cert_sha256(&ps.s, cHash, &cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// Count returns the total number of pins in the set.
func (ps *PinSet) Count() int {
	return int(C.mtls_pin_set_count(&ps.s))
}

// Clear removes all pins from the set.
func (ps *PinSet) Clear() {
	C.mtls_pin_set_clear(&ps.s)
}

// SetRequireMatch configures whether validation fails when no pin matches.
func (ps *PinSet) SetRequireMatch(require bool) {
	ps.s.require_match = C.bool(require)
}

// SetLeafOnly configures whether only the leaf certificate is checked.
func (ps *PinSet) SetLeafOnly(leafOnly bool) {
	ps.s.include_leaf_only = C.bool(leafOnly)
}

// ValidateConn validates a connection's peer certificate against the pin set.
func (ps *PinSet) ValidateConn(conn *Conn) error {
	conn.mu.Lock()
	if conn.conn == nil {
		conn.mu.Unlock()
		return &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	c := conn.conn
	conn.mu.Unlock()

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_pin_validate_conn(c, &ps.s, &cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// ValidateConnReport validates a connection and returns a detailed report.
func (ps *PinSet) ValidateConnReport(conn *Conn) (PinReport, error) {
	conn.mu.Lock()
	if conn.conn == nil {
		conn.mu.Unlock()
		return PinReport{}, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	c := conn.conn
	conn.mu.Unlock()

	var cReport C.mtls_pin_report
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_pin_validate_conn_report(c, &ps.s, &cReport, &cErr)

	report := PinReport{
		Result:       PinResult(cReport.result),
		MatchedType:  PinType(cReport.matched_type),
		MatchedPin:   C.GoString(&cReport.matched_pin[0]),
		CertSPKIHash: C.GoString(&cReport.cert_spki_hash[0]),
		CertHash:     C.GoString(&cReport.cert_hash[0]),
		CertIndex:    int(cReport.cert_index),
	}

	if rc != 0 {
		return report, convertError(&cErr)
	}
	return report, nil
}

// ComputeSPKIHash computes the SPKI SHA-256 hash of a PEM certificate.
// Returns the base64-encoded hash suitable for use with AddSPKISHA256.
func ComputeSPKIHash(certPEM []byte) (string, error) {
	if len(certPEM) == 0 {
		return "", &Error{Code: ErrInvalidArgument, Message: "cert PEM required"}
	}

	var hashBuf [C.MTLS_PIN_SHA256_BASE64_SIZE]C.char
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_pin_compute_spki_hash(
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		&hashBuf[0], C.size_t(len(hashBuf)),
		&cErr,
	)
	if rc != 0 {
		return "", convertError(&cErr)
	}
	return C.GoString(&hashBuf[0]), nil
}

// ComputeCertHash computes the full certificate SHA-256 hash of a PEM certificate.
func ComputeCertHash(certPEM []byte) (string, error) {
	if len(certPEM) == 0 {
		return "", &Error{Code: ErrInvalidArgument, Message: "cert PEM required"}
	}

	var hashBuf [C.MTLS_PIN_SHA256_BASE64_SIZE]C.char
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_pin_compute_cert_hash(
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		&hashBuf[0], C.size_t(len(hashBuf)),
		&cErr,
	)
	if rc != 0 {
		return "", convertError(&cErr)
	}
	return C.GoString(&hashBuf[0]), nil
}
