package mtls

import (
	"sync"
	"time"
)

// EventType represents the type of an mTLS event.
type EventType int

const (
	// EventConnectStart is emitted when a connection attempt begins.
	EventConnectStart EventType = iota + 1
	// EventConnectSuccess is emitted when a connection is established.
	EventConnectSuccess
	// EventConnectFailure is emitted when a connection attempt fails.
	EventConnectFailure
	// EventHandshakeStart is emitted when TLS handshake begins.
	EventHandshakeStart
	// EventHandshakeSuccess is emitted when TLS handshake completes.
	EventHandshakeSuccess
	// EventHandshakeFailure is emitted when TLS handshake fails.
	EventHandshakeFailure
	// EventRead is emitted after a read operation.
	EventRead
	// EventWrite is emitted after a write operation.
	EventWrite
	// EventClose is emitted when a connection is closed.
	EventClose
	// EventKillSwitch is emitted when the kill-switch is triggered.
	EventKillSwitch
)

// Rate limiting events (21-23)
const (
	// EventRateLimitCheck is emitted when rate limit is checked.
	EventRateLimitCheck EventType = 21
	// EventRateLimitExceeded is emitted when rate limit is exceeded.
	EventRateLimitExceeded EventType = 22
	// EventRateLimitAllowed is emitted when request passes rate limiting.
	EventRateLimitAllowed EventType = 23
)

// Deadline events (30-31)
const (
	// EventDeadlineStart is emitted when a deadline-aware operation starts.
	EventDeadlineStart EventType = 30
	// EventDeadlineExceeded is emitted when a deadline is exceeded.
	EventDeadlineExceeded EventType = 31
)

// Connection pool events (40-45)
const (
	// EventPoolAcquireStart is emitted when pool acquire begins.
	EventPoolAcquireStart EventType = 40
	// EventPoolAcquireSuccess is emitted when pool acquire succeeds.
	EventPoolAcquireSuccess EventType = 41
	// EventPoolAcquireTimeout is emitted when pool acquire times out.
	EventPoolAcquireTimeout EventType = 42
	// EventPoolRelease is emitted when a connection is released to pool.
	EventPoolRelease EventType = 43
	// EventPoolConnCreated is emitted when a new pooled connection is created.
	EventPoolConnCreated EventType = 44
	// EventPoolConnClosed is emitted when a pooled connection is closed.
	EventPoolConnClosed EventType = 45
)

// OCSP/CRL events (11-20)
const (
	// EventOCSPCheckStart is emitted when OCSP check begins.
	EventOCSPCheckStart EventType = 11
	// EventOCSPCheckSuccess is emitted when OCSP check succeeds.
	EventOCSPCheckSuccess EventType = 12
	// EventOCSPCheckFailure is emitted when OCSP check fails.
	EventOCSPCheckFailure EventType = 13
	// EventOCSPStapleVerified is emitted when OCSP staple is verified.
	EventOCSPStapleVerified EventType = 14
	// EventCRLCheckStart is emitted when CRL check begins.
	EventCRLCheckStart EventType = 15
	// EventCRLCheckSuccess is emitted when CRL check succeeds.
	EventCRLCheckSuccess EventType = 16
	// EventCRLCheckFailure is emitted when CRL check fails.
	EventCRLCheckFailure EventType = 17
	// EventCRLDownloadStart is emitted when CRL download begins.
	EventCRLDownloadStart EventType = 18
	// EventCRLDownloadSuccess is emitted when CRL download succeeds.
	EventCRLDownloadSuccess EventType = 19
	// EventCRLDownloadFailure is emitted when CRL download fails.
	EventCRLDownloadFailure EventType = 20
)

// Certificate pinning events (60-62)
const (
	// EventPinCheckStart is emitted when certificate pinning check begins.
	EventPinCheckStart EventType = 60
	// EventPinCheckSuccess is emitted when certificate pinning check succeeds.
	EventPinCheckSuccess EventType = 61
	// EventPinCheckFailure is emitted when certificate pinning check fails.
	EventPinCheckFailure EventType = 62
)

// HSM events (70-73)
const (
	// EventHSMInitStart is emitted when HSM initialization begins.
	EventHSMInitStart EventType = 70
	// EventHSMInitSuccess is emitted when HSM initialization succeeds.
	EventHSMInitSuccess EventType = 71
	// EventHSMInitFailure is emitted when HSM initialization fails.
	EventHSMInitFailure EventType = 72
	// EventHSMKeyLoaded is emitted when a key is loaded from HSM.
	EventHSMKeyLoaded EventType = 73
)

// Certificate Transparency events (80-83)
const (
	// EventCTCheckStart is emitted when CT verification begins.
	EventCTCheckStart EventType = 80
	// EventCTCheckSuccess is emitted when CT verification succeeds.
	EventCTCheckSuccess EventType = 81
	// EventCTCheckFailure is emitted when CT verification fails.
	EventCTCheckFailure EventType = 82
	// EventCTSCTValidated is emitted when an SCT is validated.
	EventCTSCTValidated EventType = 83
)

// String returns a human-readable name for the event type.
func (t EventType) String() string {
	switch t {
	case EventConnectStart:
		return "ConnectStart"
	case EventConnectSuccess:
		return "ConnectSuccess"
	case EventConnectFailure:
		return "ConnectFailure"
	case EventHandshakeStart:
		return "HandshakeStart"
	case EventHandshakeSuccess:
		return "HandshakeSuccess"
	case EventHandshakeFailure:
		return "HandshakeFailure"
	case EventRead:
		return "Read"
	case EventWrite:
		return "Write"
	case EventClose:
		return "Close"
	case EventKillSwitch:
		return "KillSwitch"
	case EventOCSPCheckStart:
		return "OCSPCheckStart"
	case EventOCSPCheckSuccess:
		return "OCSPCheckSuccess"
	case EventOCSPCheckFailure:
		return "OCSPCheckFailure"
	case EventOCSPStapleVerified:
		return "OCSPStapleVerified"
	case EventCRLCheckStart:
		return "CRLCheckStart"
	case EventCRLCheckSuccess:
		return "CRLCheckSuccess"
	case EventCRLCheckFailure:
		return "CRLCheckFailure"
	case EventCRLDownloadStart:
		return "CRLDownloadStart"
	case EventCRLDownloadSuccess:
		return "CRLDownloadSuccess"
	case EventCRLDownloadFailure:
		return "CRLDownloadFailure"
	case EventPinCheckStart:
		return "PinCheckStart"
	case EventPinCheckSuccess:
		return "PinCheckSuccess"
	case EventPinCheckFailure:
		return "PinCheckFailure"
	case EventHSMInitStart:
		return "HSMInitStart"
	case EventHSMInitSuccess:
		return "HSMInitSuccess"
	case EventHSMInitFailure:
		return "HSMInitFailure"
	case EventHSMKeyLoaded:
		return "HSMKeyLoaded"
	case EventCTCheckStart:
		return "CTCheckStart"
	case EventCTCheckSuccess:
		return "CTCheckSuccess"
	case EventCTCheckFailure:
		return "CTCheckFailure"
	case EventCTSCTValidated:
		return "CTSCTValidated"
	case EventRateLimitCheck:
		return "RateLimitCheck"
	case EventRateLimitExceeded:
		return "RateLimitExceeded"
	case EventRateLimitAllowed:
		return "RateLimitAllowed"
	case EventDeadlineStart:
		return "DeadlineStart"
	case EventDeadlineExceeded:
		return "DeadlineExceeded"
	case EventPoolAcquireStart:
		return "PoolAcquireStart"
	case EventPoolAcquireSuccess:
		return "PoolAcquireSuccess"
	case EventPoolAcquireTimeout:
		return "PoolAcquireTimeout"
	case EventPoolRelease:
		return "PoolRelease"
	case EventPoolConnCreated:
		return "PoolConnCreated"
	case EventPoolConnClosed:
		return "PoolConnClosed"
	default:
		return "Unknown"
	}
}

// IsSuccess returns true if the event type indicates success.
func (t EventType) IsSuccess() bool {
	return t == EventConnectSuccess || t == EventHandshakeSuccess ||
		t == EventOCSPCheckSuccess || t == EventOCSPStapleVerified ||
		t == EventCRLCheckSuccess || t == EventCRLDownloadSuccess ||
		t == EventPinCheckSuccess || t == EventHSMInitSuccess ||
		t == EventCTCheckSuccess || t == EventRateLimitAllowed
}

// IsFailure returns true if the event type indicates failure.
func (t EventType) IsFailure() bool {
	return t == EventConnectFailure || t == EventHandshakeFailure ||
		t == EventOCSPCheckFailure || t == EventCRLCheckFailure ||
		t == EventCRLDownloadFailure || t == EventPinCheckFailure ||
		t == EventHSMInitFailure || t == EventCTCheckFailure ||
		t == EventRateLimitExceeded || t == EventDeadlineExceeded
}

// IsIO returns true if the event type is an I/O event.
func (t EventType) IsIO() bool {
	return t == EventRead || t == EventWrite
}

// IsOCSP returns true if the event type is an OCSP event.
func (t EventType) IsOCSP() bool {
	return t >= EventOCSPCheckStart && t <= EventOCSPStapleVerified
}

// IsCRL returns true if the event type is a CRL event.
func (t EventType) IsCRL() bool {
	return t >= EventCRLCheckStart && t <= EventCRLDownloadFailure
}

// IsRevocation returns true if the event type is a revocation check event (OCSP or CRL).
func (t EventType) IsRevocation() bool {
	return t.IsOCSP() || t.IsCRL()
}

// IsPinning returns true if the event type is a certificate pinning event.
func (t EventType) IsPinning() bool {
	return t >= EventPinCheckStart && t <= EventPinCheckFailure
}

// IsHSM returns true if the event type is an HSM event.
func (t EventType) IsHSM() bool {
	return t >= EventHSMInitStart && t <= EventHSMKeyLoaded
}

// IsCT returns true if the event type is a Certificate Transparency event.
func (t EventType) IsCT() bool {
	return t >= EventCTCheckStart && t <= EventCTSCTValidated
}

// IsRateLimit returns true if the event type is a rate limiting event.
func (t EventType) IsRateLimit() bool {
	return t >= EventRateLimitCheck && t <= EventRateLimitAllowed
}

// IsDeadline returns true if the event type is a deadline event.
func (t EventType) IsDeadline() bool {
	return t >= EventDeadlineStart && t <= EventDeadlineExceeded
}

// IsPool returns true if the event type is a connection pool event.
func (t EventType) IsPool() bool {
	return t >= EventPoolAcquireStart && t <= EventPoolConnClosed
}

// Event represents an mTLS event emitted by the library.
type Event struct {
	// Type is the type of event.
	Type EventType

	// RemoteAddr is the remote address (if applicable).
	RemoteAddr string

	// ErrorCode is the error code (if applicable, 0 for success).
	ErrorCode ErrorCode

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Duration is the duration of the operation (for completed operations).
	Duration time.Duration

	// Bytes is the number of bytes transferred (for I/O events).
	Bytes uint64
}

// IsError returns true if the event indicates an error.
func (e *Event) IsError() bool {
	return e.ErrorCode != ErrOK
}

// EventCallback is a function that handles events.
type EventCallback func(*Event)

// EventFilter is a function that filters events.
// Return true to include the event, false to exclude it.
type EventFilter func(*Event) bool

// FilterByType returns an EventFilter that includes only events of the given types.
func FilterByType(types ...EventType) EventFilter {
	typeSet := make(map[EventType]bool)
	for _, t := range types {
		typeSet[t] = true
	}
	return func(e *Event) bool {
		return typeSet[e.Type]
	}
}

// FilterErrors returns an EventFilter that includes only error events.
func FilterErrors() EventFilter {
	return func(e *Event) bool {
		return e.IsError()
	}
}

// FilterSuccess returns an EventFilter that includes only success events.
func FilterSuccess() EventFilter {
	return func(e *Event) bool {
		return e.Type.IsSuccess()
	}
}

// FilterIO returns an EventFilter that includes only I/O events.
func FilterIO() EventFilter {
	return func(e *Event) bool {
		return e.Type.IsIO()
	}
}

// FilterRateLimit returns an EventFilter that includes only rate limiting events.
func FilterRateLimit() EventFilter {
	return func(e *Event) bool {
		return e.Type.IsRateLimit()
	}
}

// CombineFilters returns an EventFilter that applies all given filters (AND logic).
func CombineFilters(filters ...EventFilter) EventFilter {
	return func(e *Event) bool {
		for _, f := range filters {
			if !f(e) {
				return false
			}
		}
		return true
	}
}

// AnyFilter returns an EventFilter that passes if any filter passes (OR logic).
func AnyFilter(filters ...EventFilter) EventFilter {
	return func(e *Event) bool {
		for _, f := range filters {
			if f(e) {
				return true
			}
		}
		return false
	}
}

// EventMetrics tracks aggregate metrics from events.
// EventMetrics is thread-safe and can be used from multiple goroutines.
type EventMetrics struct {
	mu sync.Mutex

	// Connection metrics
	ConnectionAttempts  uint64
	ConnectionSuccesses uint64
	ConnectionFailures  uint64

	// Handshake metrics
	HandshakeAttempts  uint64
	HandshakeSuccesses uint64
	HandshakeFailures  uint64

	// I/O metrics
	BytesRead    uint64
	BytesWritten uint64
	ReadOps      uint64
	WriteOps     uint64

	// Error counts by category
	ConfigErrors   uint64
	NetworkErrors  uint64
	TLSErrors      uint64
	IdentityErrors uint64
	PolicyErrors   uint64
	IOErrors       uint64

	// Rate limiting metrics
	RateLimitChecks   uint64
	RateLimitExceeded uint64
	RateLimitAllowed  uint64

	// Timing (cumulative)
	TotalConnectDuration   time.Duration
	TotalHandshakeDuration time.Duration
}

// NewEventMetrics creates a new EventMetrics tracker.
func NewEventMetrics() *EventMetrics {
	return &EventMetrics{}
}

// Record updates metrics based on an event.
// Record is thread-safe.
func (m *EventMetrics) Record(e *Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch e.Type {
	case EventConnectStart:
		m.ConnectionAttempts++
	case EventConnectSuccess:
		m.ConnectionSuccesses++
		m.TotalConnectDuration += e.Duration
	case EventConnectFailure:
		m.ConnectionFailures++
		m.recordErrorLocked(e.ErrorCode)
	case EventHandshakeStart:
		m.HandshakeAttempts++
	case EventHandshakeSuccess:
		m.HandshakeSuccesses++
		m.TotalHandshakeDuration += e.Duration
	case EventHandshakeFailure:
		m.HandshakeFailures++
		m.recordErrorLocked(e.ErrorCode)
	case EventRead:
		m.ReadOps++
		m.BytesRead += e.Bytes
	case EventWrite:
		m.WriteOps++
		m.BytesWritten += e.Bytes
	case EventRateLimitCheck:
		m.RateLimitChecks++
	case EventRateLimitExceeded:
		m.RateLimitExceeded++
	case EventRateLimitAllowed:
		m.RateLimitAllowed++
	}
}

// recordErrorLocked updates error counts. Caller must hold mu.
func (m *EventMetrics) recordErrorLocked(code ErrorCode) {
	switch {
	case code >= 100 && code < 200:
		m.ConfigErrors++
	case code >= 200 && code < 300:
		m.NetworkErrors++
	case code >= 300 && code < 400:
		m.TLSErrors++
	case code >= 400 && code < 500:
		m.IdentityErrors++
	case code >= 500 && code < 600:
		m.PolicyErrors++
	case code >= 600 && code < 700:
		m.IOErrors++
	}
}

// ConnectionSuccessRate returns the connection success rate (0.0 to 1.0).
// ConnectionSuccessRate is thread-safe.
func (m *EventMetrics) ConnectionSuccessRate() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ConnectionAttempts == 0 {
		return 0
	}
	return float64(m.ConnectionSuccesses) / float64(m.ConnectionAttempts)
}

// HandshakeSuccessRate returns the handshake success rate (0.0 to 1.0).
// HandshakeSuccessRate is thread-safe.
func (m *EventMetrics) HandshakeSuccessRate() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.HandshakeAttempts == 0 {
		return 0
	}
	return float64(m.HandshakeSuccesses) / float64(m.HandshakeAttempts)
}

// AverageConnectDuration returns the average connection duration.
// AverageConnectDuration is thread-safe.
func (m *EventMetrics) AverageConnectDuration() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ConnectionSuccesses == 0 {
		return 0
	}
	return m.TotalConnectDuration / time.Duration(m.ConnectionSuccesses)
}

// AverageHandshakeDuration returns the average handshake duration.
// AverageHandshakeDuration is thread-safe.
func (m *EventMetrics) AverageHandshakeDuration() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.HandshakeSuccesses == 0 {
		return 0
	}
	return m.TotalHandshakeDuration / time.Duration(m.HandshakeSuccesses)
}

// MetricsCallback returns an EventCallback that updates metrics.
func MetricsCallback(m *EventMetrics) EventCallback {
	return func(e *Event) {
		m.Record(e)
	}
}
