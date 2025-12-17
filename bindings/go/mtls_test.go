package mtls

import (
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Error("Version() returned empty string")
	}
	t.Logf("Library version: %s", v)
}

func TestVersionComponents(t *testing.T) {
	major, minor, patch := VersionComponents()
	if major < 0 || minor < 0 || patch < 0 {
		t.Errorf("Invalid version components: %d.%d.%d", major, minor, patch)
	}
	t.Logf("Version components: %d.%d.%d", major, minor, patch)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if config.MinTLSVersion != TLS12 {
		t.Errorf("MinTLSVersion = %v, want %v", config.MinTLSVersion, TLS12)
	}

	if config.MaxTLSVersion != TLS13 {
		t.Errorf("MaxTLSVersion = %v, want %v", config.MaxTLSVersion, TLS13)
	}

	if config.ConnectTimeout != 30*time.Second {
		t.Errorf("ConnectTimeout = %v, want %v", config.ConnectTimeout, 30*time.Second)
	}

	if !config.RequireClientCert {
		t.Error("RequireClientCert should be true by default")
	}

	if !config.VerifyHostname {
		t.Error("VerifyHostname should be true by default")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantErr   bool
		errCode   ErrorCode
		errSubstr string
	}{
		{
			name: "valid config with CA path",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				MinTLSVersion: TLS12,
				MaxTLSVersion: TLS13,
			},
			wantErr: false,
		},
		{
			name: "valid config with CA PEM",
			config: &Config{
				CACertPEM:     []byte("-----BEGIN CERTIFICATE-----\n..."),
				MinTLSVersion: TLS12,
				MaxTLSVersion: TLS13,
			},
			wantErr: false,
		},
		{
			name: "valid config with TLS12 only",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				MinTLSVersion: TLS12,
				MaxTLSVersion: TLS12,
			},
			wantErr: false,
		},
		{
			name: "valid config with TLS13 only",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				MinTLSVersion: TLS13,
				MaxTLSVersion: TLS13,
			},
			wantErr: false,
		},
		{
			name: "valid config with zero TLS versions (use defaults)",
			config: &Config{
				CACertPath: "/path/to/ca.pem",
			},
			wantErr: false,
		},
		{
			name: "missing CA certificate",
			config: &Config{
				MinTLSVersion: TLS12,
				MaxTLSVersion: TLS13,
			},
			wantErr:   true,
			errCode:   ErrInvalidConfig,
			errSubstr: "CA certificate is required",
		},
		{
			name: "invalid MinTLSVersion",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				MinTLSVersion: 0x0301, // TLS 1.0
				MaxTLSVersion: TLS13,
			},
			wantErr:   true,
			errCode:   ErrInvalidConfig,
			errSubstr: "invalid MinTLSVersion",
		},
		{
			name: "invalid MaxTLSVersion",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				MinTLSVersion: TLS12,
				MaxTLSVersion: 0x0305, // Invalid version
			},
			wantErr:   true,
			errCode:   ErrInvalidConfig,
			errSubstr: "invalid MaxTLSVersion",
		},
		{
			name: "MinTLSVersion greater than MaxTLSVersion",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				MinTLSVersion: TLS13,
				MaxTLSVersion: TLS12,
			},
			wantErr:   true,
			errCode:   ErrInvalidConfig,
			errSubstr: "MinTLSVersion cannot be greater than MaxTLSVersion",
		},
		{
			name: "both CA path and PEM provided (PEM takes precedence, should be valid)",
			config: &Config{
				CACertPath:    "/path/to/ca.pem",
				CACertPEM:     []byte("-----BEGIN CERTIFICATE-----\n..."),
				MinTLSVersion: TLS12,
				MaxTLSVersion: TLS13,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
					return
				}

				mtlsErr, ok := err.(*Error)
				if !ok {
					t.Errorf("Validate() error type = %T, want *Error", err)
					return
				}

				if mtlsErr.Code != tt.errCode {
					t.Errorf("Validate() error code = %v, want %v", mtlsErr.Code, tt.errCode)
				}

				if tt.errSubstr != "" && !contains(mtlsErr.Message, tt.errSubstr) {
					t.Errorf("Validate() error message = %q, want to contain %q", mtlsErr.Message, tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigValidateDefaultConfig(t *testing.T) {
	// DefaultConfig needs a CA cert to be valid
	config := DefaultConfig()
	config.CACertPath = "/path/to/ca.pem"

	err := config.Validate()
	if err != nil {
		t.Errorf("DefaultConfig with CA should validate: %v", err)
	}
}

func TestConfigValidateDefaultConfigWithoutCA(t *testing.T) {
	// DefaultConfig without CA cert should fail validation
	config := DefaultConfig()

	err := config.Validate()
	if err == nil {
		t.Error("DefaultConfig without CA should fail validation")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchSubstring(s, substr)))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestErrorCodeString(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
	}{
		{ErrOK, "MTLS_OK"},
		{ErrInvalidConfig, "MTLS_ERR_INVALID_CONFIG"},
		{ErrConnectFailed, "MTLS_ERR_CONNECT_FAILED"},
		{ErrTLSHandshakeFailed, "MTLS_ERR_TLS_HANDSHAKE_FAILED"},
	}

	for _, tt := range tests {
		got := tt.code.String()
		if got != tt.want {
			t.Errorf("ErrorCode(%d).String() = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestErrorCodeCategory(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
	}{
		{ErrInvalidConfig, "Configuration"},
		{ErrConnectFailed, "Network"},
		{ErrTLSHandshakeFailed, "TLS/Certificate"},
		{ErrIdentityMismatch, "Identity"},
		{ErrKillSwitchEnabled, "Policy"},
		{ErrReadFailed, "I/O"},
	}

	for _, tt := range tests {
		got := tt.code.Category()
		if got != tt.want {
			t.Errorf("ErrorCode(%d).Category() = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestErrorCategories(t *testing.T) {
	tests := []struct {
		err        *Error
		isConfig   bool
		isNetwork  bool
		isTLS      bool
		isIdentity bool
		isPolicy   bool
		isIO       bool
	}{
		{&Error{Code: ErrInvalidConfig}, true, false, false, false, false, false},
		{&Error{Code: ErrConnectFailed}, false, true, false, false, false, false},
		{&Error{Code: ErrTLSHandshakeFailed}, false, false, true, false, false, false},
		{&Error{Code: ErrIdentityMismatch}, false, false, false, true, false, false},
		{&Error{Code: ErrKillSwitchEnabled}, false, false, false, false, true, false},
		{&Error{Code: ErrReadFailed}, false, false, false, false, false, true},
	}

	for _, tt := range tests {
		if tt.err.IsConfig() != tt.isConfig {
			t.Errorf("Error{%d}.IsConfig() = %v, want %v", tt.err.Code, tt.err.IsConfig(), tt.isConfig)
		}
		if tt.err.IsNetwork() != tt.isNetwork {
			t.Errorf("Error{%d}.IsNetwork() = %v, want %v", tt.err.Code, tt.err.IsNetwork(), tt.isNetwork)
		}
		if tt.err.IsTLS() != tt.isTLS {
			t.Errorf("Error{%d}.IsTLS() = %v, want %v", tt.err.Code, tt.err.IsTLS(), tt.isTLS)
		}
		if tt.err.IsIdentity() != tt.isIdentity {
			t.Errorf("Error{%d}.IsIdentity() = %v, want %v", tt.err.Code, tt.err.IsIdentity(), tt.isIdentity)
		}
		if tt.err.IsPolicy() != tt.isPolicy {
			t.Errorf("Error{%d}.IsPolicy() = %v, want %v", tt.err.Code, tt.err.IsPolicy(), tt.isPolicy)
		}
		if tt.err.IsIO() != tt.isIO {
			t.Errorf("Error{%d}.IsIO() = %v, want %v", tt.err.Code, tt.err.IsIO(), tt.isIO)
		}
	}
}

func TestConnStateString(t *testing.T) {
	tests := []struct {
		state ConnState
		want  string
	}{
		{ConnStateNone, "None"},
		{ConnStateConnecting, "Connecting"},
		{ConnStateHandshaking, "Handshaking"},
		{ConnStateEstablished, "Established"},
		{ConnStateClosing, "Closing"},
		{ConnStateClosed, "Closed"},
		{ConnStateError, "Error"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("ConnState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		eventType EventType
		want      string
	}{
		{EventConnectStart, "ConnectStart"},
		{EventConnectSuccess, "ConnectSuccess"},
		{EventConnectFailure, "ConnectFailure"},
		{EventHandshakeStart, "HandshakeStart"},
		{EventHandshakeSuccess, "HandshakeSuccess"},
		{EventHandshakeFailure, "HandshakeFailure"},
		{EventRead, "Read"},
		{EventWrite, "Write"},
		{EventClose, "Close"},
		{EventKillSwitch, "KillSwitch"},
	}

	for _, tt := range tests {
		got := tt.eventType.String()
		if got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.eventType, got, tt.want)
		}
	}
}

func TestEventTypePredicates(t *testing.T) {
	if !EventConnectSuccess.IsSuccess() {
		t.Error("EventConnectSuccess.IsSuccess() should be true")
	}
	if !EventHandshakeSuccess.IsSuccess() {
		t.Error("EventHandshakeSuccess.IsSuccess() should be true")
	}

	if !EventConnectFailure.IsFailure() {
		t.Error("EventConnectFailure.IsFailure() should be true")
	}
	if !EventHandshakeFailure.IsFailure() {
		t.Error("EventHandshakeFailure.IsFailure() should be true")
	}

	if !EventRead.IsIO() {
		t.Error("EventRead.IsIO() should be true")
	}
	if !EventWrite.IsIO() {
		t.Error("EventWrite.IsIO() should be true")
	}
}

func TestMatchSAN(t *testing.T) {
	tests := []struct {
		san     string
		pattern string
		want    bool
	}{
		// Exact match
		{"example.com", "example.com", true},
		{"server.example.com", "server.example.com", true},

		// Wildcard match
		{"server.example.com", "*.example.com", true},
		{"api.example.com", "*.example.com", true},

		// Wildcard should not match subdomain of subdomain
		{"deep.server.example.com", "*.example.com", false},

		// No match
		{"example.com", "other.com", false},
		{"example.com", "*.other.com", false},

		// SPIFFE ID exact match
		{"spiffe://example.com/service", "spiffe://example.com/service", true},
		{"spiffe://example.com/service", "spiffe://other.com/service", false},

		// SPIFFE ID wildcard (prefix matching)
		{"spiffe://example.com/service/api", "spiffe://example.com/*", true},
		{"spiffe://example.com/client/frontend", "spiffe://example.com/client/*", true},
		{"spiffe://example.com/service", "spiffe://example.com/*", true},
		{"spiffe://example.com/service", "spiffe://example.com/client/*", false},
		{"spiffe://other.com/service", "spiffe://example.com/*", false},
	}

	for _, tt := range tests {
		got := matchSAN(tt.san, tt.pattern)
		if got != tt.want {
			t.Errorf("matchSAN(%q, %q) = %v, want %v", tt.san, tt.pattern, got, tt.want)
		}
	}
}

func TestValidateSANsWithSPIFFEWildcard(t *testing.T) {
	// Test that SPIFFE ID wildcards work correctly
	identity := &PeerIdentity{
		CommonName: "test",
		SANs:       []string{"client.example.com"},
		SPIFFEID:   "spiffe://example.com/client/frontend",
		NotBefore:  time.Now().Add(-24 * time.Hour),
		NotAfter:   time.Now().Add(24 * time.Hour),
	}

	// Test SPIFFE wildcard matching
	allowed := []string{
		"spiffe://example.com/client/*", // Should match
		"*.example.com",                 // DNS wildcard
	}
	if !ValidateSANs(identity, allowed) {
		t.Error("ValidateSANs should match SPIFFE wildcard pattern")
	}

	// Test non-matching SPIFFE wildcard
	allowed2 := []string{
		"spiffe://example.com/service/*", // Should not match
	}
	if ValidateSANs(identity, allowed2) {
		t.Error("ValidateSANs should not match different SPIFFE wildcard pattern")
	}

	// Test exact SPIFFE match
	allowed3 := []string{
		"spiffe://example.com/client/frontend", // Exact match
	}
	if !ValidateSANs(identity, allowed3) {
		t.Error("ValidateSANs should match exact SPIFFE ID")
	}

	// Test that wildcard does NOT match base SPIFFE ID without path
	identity2 := &PeerIdentity{
		CommonName: "test",
		SANs:       []string{},
		SPIFFEID:   "spiffe://example.com", // No path component
		NotBefore:  time.Now().Add(-24 * time.Hour),
		NotAfter:   time.Now().Add(24 * time.Hour),
	}
	allowed4 := []string{
		"spiffe://example.com/*", // Wildcard should NOT match base ID
	}
	if ValidateSANs(identity2, allowed4) {
		t.Error("SPIFFE wildcard pattern should not match base SPIFFE ID without path")
	}

	// Test that exact match still works for base SPIFFE ID
	allowed5 := []string{
		"spiffe://example.com", // Exact match should work
	}
	if !ValidateSANs(identity2, allowed5) {
		t.Error("Exact match should work for base SPIFFE ID")
	}
}

func TestEventMetrics(t *testing.T) {
	m := NewEventMetrics()

	// Record some events
	m.Record(&Event{Type: EventConnectStart})
	m.Record(&Event{Type: EventConnectSuccess, Duration: 10 * time.Millisecond})
	m.Record(&Event{Type: EventConnectStart})
	m.Record(&Event{Type: EventConnectFailure, ErrorCode: ErrConnectFailed})

	m.Record(&Event{Type: EventHandshakeStart})
	m.Record(&Event{Type: EventHandshakeSuccess, Duration: 5 * time.Millisecond})

	m.Record(&Event{Type: EventRead, Bytes: 100})
	m.Record(&Event{Type: EventWrite, Bytes: 50})

	// Verify metrics
	if m.ConnectionAttempts != 2 {
		t.Errorf("ConnectionAttempts = %d, want 2", m.ConnectionAttempts)
	}
	if m.ConnectionSuccesses != 1 {
		t.Errorf("ConnectionSuccesses = %d, want 1", m.ConnectionSuccesses)
	}
	if m.ConnectionFailures != 1 {
		t.Errorf("ConnectionFailures = %d, want 1", m.ConnectionFailures)
	}

	if m.HandshakeAttempts != 1 {
		t.Errorf("HandshakeAttempts = %d, want 1", m.HandshakeAttempts)
	}
	if m.HandshakeSuccesses != 1 {
		t.Errorf("HandshakeSuccesses = %d, want 1", m.HandshakeSuccesses)
	}

	if m.BytesRead != 100 {
		t.Errorf("BytesRead = %d, want 100", m.BytesRead)
	}
	if m.BytesWritten != 50 {
		t.Errorf("BytesWritten = %d, want 50", m.BytesWritten)
	}

	// Check success rates
	rate := m.ConnectionSuccessRate()
	if rate != 0.5 {
		t.Errorf("ConnectionSuccessRate() = %f, want 0.5", rate)
	}

	// Check average duration
	avgConnect := m.AverageConnectDuration()
	if avgConnect != 10*time.Millisecond {
		t.Errorf("AverageConnectDuration() = %v, want 10ms", avgConnect)
	}
}

func TestFilterByType(t *testing.T) {
	filter := FilterByType(EventConnectStart, EventConnectSuccess)

	if !filter(&Event{Type: EventConnectStart}) {
		t.Error("Filter should include EventConnectStart")
	}
	if !filter(&Event{Type: EventConnectSuccess}) {
		t.Error("Filter should include EventConnectSuccess")
	}
	if filter(&Event{Type: EventConnectFailure}) {
		t.Error("Filter should exclude EventConnectFailure")
	}
}

func TestCombineFilters(t *testing.T) {
	// Filter for success events with duration > 5ms
	filter := CombineFilters(
		FilterSuccess(),
		func(e *Event) bool { return e.Duration > 5*time.Millisecond },
	)

	if filter(&Event{Type: EventConnectSuccess, Duration: 10 * time.Millisecond}) != true {
		t.Error("Should include successful event with duration > 5ms")
	}
	if filter(&Event{Type: EventConnectSuccess, Duration: 1 * time.Millisecond}) != false {
		t.Error("Should exclude successful event with duration < 5ms")
	}
	if filter(&Event{Type: EventConnectFailure, Duration: 10 * time.Millisecond}) != false {
		t.Error("Should exclude failure event even with duration > 5ms")
	}
}

func TestPeerIdentityIsValid(t *testing.T) {
	now := time.Now()

	// Valid certificate
	valid := &PeerIdentity{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	if !valid.IsValid() {
		t.Error("Certificate should be valid")
	}

	// Expired certificate
	expired := &PeerIdentity{
		NotBefore: now.Add(-2 * time.Hour),
		NotAfter:  now.Add(-time.Hour),
	}
	if expired.IsValid() {
		t.Error("Certificate should be expired")
	}

	// Not yet valid
	notYetValid := &PeerIdentity{
		NotBefore: now.Add(time.Hour),
		NotAfter:  now.Add(2 * time.Hour),
	}
	if notYetValid.IsValid() {
		t.Error("Certificate should not be valid yet")
	}
}

func TestNewContextNilConfig(t *testing.T) {
	_, err := NewContext(nil)
	if err == nil {
		t.Error("NewContext(nil) should return an error")
	}
}

func TestObserverBuilder(t *testing.T) {
	var successCount, failureCount int

	builder := NewObserverBuilder().
		OnSuccess(func(e *Event) { successCount++ }).
		OnFailure(func(e *Event) { failureCount++ })

	callback := builder.Build()

	// Simulate events
	callback(&Event{Type: EventConnectSuccess})
	callback(&Event{Type: EventConnectFailure})
	callback(&Event{Type: EventHandshakeSuccess})
	callback(&Event{Type: EventRead}) // Neither success nor failure

	if successCount != 2 {
		t.Errorf("successCount = %d, want 2", successCount)
	}
	if failureCount != 1 {
		t.Errorf("failureCount = %d, want 1", failureCount)
	}
}
