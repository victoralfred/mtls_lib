package mtls

/*
#include <stdlib.h>
#include <mtls/mtls_ct.h>
*/
import "C"

import (
	"runtime"
	"time"
	"unsafe"
)

// CTResult represents the overall Certificate Transparency validation result.
type CTResult int

const (
	CTResultValid       CTResult = C.MTLS_CT_RESULT_VALID
	CTResultNoSCTs      CTResult = C.MTLS_CT_RESULT_NO_SCTS
	CTResultInsufficient CTResult = C.MTLS_CT_RESULT_INSUFFICIENT
	CTResultInvalid     CTResult = C.MTLS_CT_RESULT_INVALID
	CTResultError       CTResult = C.MTLS_CT_RESULT_ERROR
)

// SCTSource indicates where an SCT was obtained from.
type SCTSource int

const (
	SCTSourceEmbedded     SCTSource = C.MTLS_SCT_SOURCE_EMBEDDED
	SCTSourceTLSExtension SCTSource = C.MTLS_SCT_SOURCE_TLS_EXTENSION
	SCTSourceOCSP         SCTSource = C.MTLS_SCT_SOURCE_OCSP
)

// SCTValidationResult represents the result of validating a single SCT.
type SCTValidationResult int

const (
	SCTValid            SCTValidationResult = C.MTLS_SCT_VALID
	SCTInvalidSignature SCTValidationResult = C.MTLS_SCT_INVALID_SIGNATURE
	SCTUnknownLog       SCTValidationResult = C.MTLS_SCT_UNKNOWN_LOG
	SCTInvalidTimestamp SCTValidationResult = C.MTLS_SCT_INVALID_TIMESTAMP
	SCTInvalidVersion   SCTValidationResult = C.MTLS_SCT_INVALID_VERSION
	SCTParseError       SCTValidationResult = C.MTLS_SCT_PARSE_ERROR
	SCTLogDisqualified  SCTValidationResult = C.MTLS_SCT_LOG_DISQUALIFIED
)

// SCT represents a Signed Certificate Timestamp.
type SCT struct {
	Timestamp        time.Time
	Source           SCTSource
	ValidationResult SCTValidationResult
}

// CTReport contains detailed results from CT validation.
type CTReport struct {
	Result          CTResult
	SCTs            []SCT
	ValidSCTCount   int
	EmbeddedSCTs    int
	TLSSCTs         int
	OCSPSCTs        int
}

// CTLogStatus indicates the operational status of a CT log.
type CTLogStatus int

const (
	CTLogStatusUnknown      CTLogStatus = C.MTLS_CT_LOG_STATUS_UNKNOWN
	CTLogStatusUsable       CTLogStatus = C.MTLS_CT_LOG_STATUS_USABLE
	CTLogStatusReadOnly     CTLogStatus = C.MTLS_CT_LOG_STATUS_READONLY
	CTLogStatusRetired      CTLogStatus = C.MTLS_CT_LOG_STATUS_RETIRED
	CTLogStatusDisqualified CTLogStatus = C.MTLS_CT_LOG_STATUS_DISQUALIFIED
)

// CTLogList holds a list of known CT logs for SCT validation.
//
// CTLogList is heap-allocated because the C struct is ~80KB — too large for
// the Go stack. Always create with NewCTLogList.
type CTLogList struct {
	list *C.mtls_ct_log_list
}

// NewCTLogList creates an empty CT log list.
func NewCTLogList() *CTLogList {
	ll := &CTLogList{
		list: (*C.mtls_ct_log_list)(C.malloc(C.size_t(C.sizeof_mtls_ct_log_list))),
	}
	if ll.list == nil {
		panic("mtls: C.malloc for CTLogList returned nil: out of memory")
	}
	C.mtls_ct_log_list_init(ll.list)
	runtime.SetFinalizer(ll, (*CTLogList).destroy)
	return ll
}

// LoadFile loads CT logs from a JSON file (Chrome/Apple log list format).
func (ll *CTLogList) LoadFile(path string) error {
	cPath := C.CString(path)
	defer freeString(cPath)

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_ct_log_list_load_file(ll.list, cPath, &cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// LoadJSON loads CT logs from JSON data in memory.
func (ll *CTLogList) LoadJSON(data []byte) error {
	if len(data) == 0 {
		return &Error{Code: ErrInvalidArgument, Message: "JSON data is empty"}
	}

	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_ct_log_list_load_json(ll.list,
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cErr) != 0 {
		return convertError(&cErr)
	}
	return nil
}

// Count returns the number of logs in the list.
func (ll *CTLogList) Count() int {
	return int(C.mtls_ct_log_list_count(ll.list))
}

// Clear removes all logs from the list.
func (ll *CTLogList) Clear() {
	C.mtls_ct_log_list_clear(ll.list)
}

// Close frees the log list resources.
func (ll *CTLogList) Close() {
	ll.destroy()
}

func (ll *CTLogList) destroy() {
	if ll != nil && ll.list != nil {
		C.mtls_ct_log_list_free(ll.list)
		C.free(unsafe.Pointer(ll.list))
		ll.list = nil
		runtime.SetFinalizer(ll, nil)
	}
}

// ValidateConn validates CT for a connection using the log list.
//
// minValidSCTs is the minimum number of valid SCTs required.
// If allowUnknownLogs is true, SCTs from logs not in the list are not rejected.
func (ll *CTLogList) ValidateConn(conn *Conn, minValidSCTs int, allowUnknownLogs bool) (CTReport, error) {
	conn.mu.Lock()
	if conn.conn == nil {
		conn.mu.Unlock()
		return CTReport{}, &Error{Code: ErrConnectionClosed, Message: "connection is closed"}
	}
	c := conn.conn
	conn.mu.Unlock()

	var cReport C.mtls_ct_report
	var cErr C.mtls_err
	initErr(&cErr)

	rc := C.mtls_ct_validate_conn(
		c, ll.list,
		C.size_t(minValidSCTs),
		C.bool(allowUnknownLogs),
		&cReport, &cErr,
	)

	report := ctReportFromC(&cReport)
	if rc != 0 {
		return report, convertError(&cErr)
	}
	return report, nil
}

func ctReportFromC(r *C.mtls_ct_report) CTReport {
	report := CTReport{
		Result:        CTResult(r.result),
		ValidSCTCount: int(r.valid_sct_count),
		EmbeddedSCTs:  int(r.embedded_sct_count),
		TLSSCTs:       int(r.tls_sct_count),
		OCSPSCTs:      int(r.ocsp_sct_count),
	}
	n := int(r.sct_count)
	report.SCTs = make([]SCT, n)
	for i := 0; i < n; i++ {
		cs := r.scts[i]
		report.SCTs[i] = SCT{
			Timestamp:        time.UnixMilli(int64(cs.timestamp)),
			Source:           SCTSource(cs.source),
			ValidationResult: SCTValidationResult(cs.validation_result),
		}
	}
	return report
}
