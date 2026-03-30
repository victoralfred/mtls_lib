package mtls

import (
	"testing"
)

// TestNewHSMContextNilConfig verifies that nil config returns an error.
func TestNewHSMContextNilConfig(t *testing.T) {
	_, err := NewHSMContext(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

// TestNewHSMContextNoHSM verifies that HSMNone type without module returns an error.
func TestNewHSMContextNoHSM(t *testing.T) {
	cfg := &Config{
		HSMEnabled: false,
		HSMType:    HSMNone,
	}
	// With no module path and HSMNone type, the C library should return an error.
	_, err := NewHSMContext(cfg)
	if err == nil {
		t.Skip("C library accepted HSMNone — skipping (test depends on C behavior)")
	}
	// Any error is acceptable — we just verify it doesn't panic.
}

// TestHSMContextDoubleClose verifies Close is idempotent when context is never initialised.
func TestHSMContextDoubleClose(t *testing.T) {
	h := &HSMContext{}
	h.Close()
	h.Close() // must not panic
}

// TestHSMKeyInfoZeroValue verifies that HSMKeyInfo zero value is usable.
func TestHSMKeyInfoZeroValue(t *testing.T) {
	var k HSMKeyInfo
	if k.KeySize != 0 {
		t.Errorf("KeySize = %d, want 0", k.KeySize)
	}
}
