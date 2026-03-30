package mtls

/*
#include <mtls/mtls_ocsp.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

// OCSPStatus represents the OCSP certificate revocation status.
type OCSPStatus int

const (
	OCSPStatusGood    OCSPStatus = C.MTLS_OCSP_STATUS_GOOD
	OCSPStatusRevoked OCSPStatus = C.MTLS_OCSP_STATUS_REVOKED
	OCSPStatusUnknown OCSPStatus = C.MTLS_OCSP_STATUS_UNKNOWN
	OCSPStatusError   OCSPStatus = C.MTLS_OCSP_STATUS_ERROR
)

// CRLStatus represents the CRL certificate revocation status.
type CRLStatus int

const (
	CRLStatusGood    CRLStatus = C.MTLS_CRL_STATUS_GOOD
	CRLStatusRevoked CRLStatus = C.MTLS_CRL_STATUS_REVOKED
	CRLStatusUnknown CRLStatus = C.MTLS_CRL_STATUS_UNKNOWN
	CRLStatusError   CRLStatus = C.MTLS_CRL_STATUS_ERROR
)

// RevocationResult holds the combined OCSP and CRL revocation check result.
type RevocationResult struct {
	OCSPStatus      OCSPStatus
	CRLStatus       CRLStatus
	OCSPChecked     bool
	CRLChecked      bool
	RevocationTime  time.Time
	RevocationReason int
	OCSPThisUpdate  time.Time
	OCSPNextUpdate  time.Time
	CRLLastUpdate   time.Time
	CRLNextUpdate   time.Time
	ResponderURL    string
}

func revocationResultFromC(r *C.mtls_revocation_result) RevocationResult {
	result := RevocationResult{
		OCSPStatus:       OCSPStatus(r.ocsp_status),
		CRLStatus:        CRLStatus(r.crl_status),
		OCSPChecked:      bool(r.ocsp_checked),
		CRLChecked:       bool(r.crl_checked),
		RevocationReason: int(r.revocation_reason),
		ResponderURL:     C.GoString(&r.responder_url[0]),
	}
	if r.revocation_time != 0 {
		result.RevocationTime = time.Unix(int64(r.revocation_time), 0)
	}
	if r.ocsp_this_update != 0 {
		result.OCSPThisUpdate = time.Unix(int64(r.ocsp_this_update), 0)
	}
	if r.ocsp_next_update != 0 {
		result.OCSPNextUpdate = time.Unix(int64(r.ocsp_next_update), 0)
	}
	if r.crl_last_update != 0 {
		result.CRLLastUpdate = time.Unix(int64(r.crl_last_update), 0)
	}
	if r.crl_next_update != 0 {
		result.CRLNextUpdate = time.Unix(int64(r.crl_next_update), 0)
	}
	return result
}

// OCSPCheck checks certificate revocation status via OCSP.
//
// certPEM and issuerPEM must be PEM-encoded certificates.
func (c *Context) OCSPCheck(certPEM, issuerPEM []byte) (RevocationResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return RevocationResult{}, &Error{Code: ErrCtxNotInitialized, Message: "context is closed"}
	}
	if len(certPEM) == 0 || len(issuerPEM) == 0 {
		return RevocationResult{}, &Error{Code: ErrInvalidArgument, Message: "cert and issuer PEM required"}
	}

	var cResult C.mtls_revocation_result
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_ocsp_check(
		c.ctx,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		(*C.uint8_t)(unsafe.Pointer(&issuerPEM[0])), C.size_t(len(issuerPEM)),
		&cResult, &cErr,
	)
	if rc != 0 {
		return RevocationResult{}, convertError(&cErr)
	}
	return revocationResultFromC(&cResult), nil
}

// OCSPCheckURL checks certificate revocation using an explicit OCSP responder URL.
func OCSPCheckURL(ocspURL string, certPEM, issuerPEM []byte, timeout time.Duration) (RevocationResult, error) {
	if len(certPEM) == 0 || len(issuerPEM) == 0 {
		return RevocationResult{}, &Error{Code: ErrInvalidArgument, Message: "cert and issuer PEM required"}
	}

	cURL := C.CString(ocspURL)
	defer freeString(cURL)

	var cResult C.mtls_revocation_result
	var cErr C.mtls_err
	initErr(&cErr)

	ms := C.uint32_t(0)
	if timeout > 0 {
		ms = C.uint32_t(timeout.Milliseconds())
	}

	rc := C.mtls_ocsp_check_url(
		cURL,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		(*C.uint8_t)(unsafe.Pointer(&issuerPEM[0])), C.size_t(len(issuerPEM)),
		ms, &cResult, &cErr,
	)
	if rc != 0 {
		return RevocationResult{}, convertError(&cErr)
	}
	return revocationResultFromC(&cResult), nil
}

// CRLCheck checks certificate revocation via CRL using the context configuration.
func (c *Context) CRLCheck(certPEM []byte) (RevocationResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ctx == nil {
		return RevocationResult{}, &Error{Code: ErrCtxNotInitialized, Message: "context is closed"}
	}
	if len(certPEM) == 0 {
		return RevocationResult{}, &Error{Code: ErrInvalidArgument, Message: "cert PEM required"}
	}

	var cResult C.mtls_revocation_result
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_crl_check(
		c.ctx,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		&cResult, &cErr,
	)
	if rc != 0 {
		return RevocationResult{}, convertError(&cErr)
	}
	return revocationResultFromC(&cResult), nil
}

// GetOCSPResponderURL extracts the OCSP responder URL from a PEM-encoded certificate.
// Returns an empty string if no OCSP URL is present.
func GetOCSPResponderURL(certPEM []byte) (string, error) {
	if len(certPEM) == 0 {
		return "", &Error{Code: ErrInvalidArgument, Message: "cert PEM required"}
	}

	var urlBuf [512]C.char
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_ocsp_get_responder_url(
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		&urlBuf[0], C.size_t(len(urlBuf)),
		&cErr,
	)
	if rc != 0 {
		return "", nil // no URL found
	}
	return C.GoString(&urlBuf[0]), nil
}
