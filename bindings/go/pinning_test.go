package mtls

import (
	"testing"
)

// TestNewPinSet verifies that a freshly created pin set starts empty.
func TestNewPinSet(t *testing.T) {
	ps := NewPinSet()
	if ps.Count() != 0 {
		t.Errorf("Count() = %d, want 0", ps.Count())
	}
}

// TestPinSetAddInvalidPin verifies that a malformed base64 pin returns an error.
func TestPinSetAddInvalidPin(t *testing.T) {
	ps := NewPinSet()
	// Too short to be a valid base64 SHA-256 hash.
	err := ps.AddSPKISHA256("not-a-valid-pin")
	if err == nil {
		t.Error("expected error for invalid SPKI pin")
	}
}

// TestPinSetClear verifies Clear resets the pin count.
func TestPinSetClear(t *testing.T) {
	ps := NewPinSet()
	ps.Clear()
	if ps.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", ps.Count())
	}
}

// TestComputeSPKIHashEmptyPEM verifies error for empty certPEM.
func TestComputeSPKIHashEmptyPEM(t *testing.T) {
	_, err := ComputeSPKIHash(nil)
	if err == nil {
		t.Error("expected error for nil certPEM")
	}
}

// TestComputeCertHashEmptyPEM verifies error for empty certPEM.
func TestComputeCertHashEmptyPEM(t *testing.T) {
	_, err := ComputeCertHash(nil)
	if err == nil {
		t.Error("expected error for nil certPEM")
	}
}

// TestPinValidateConnClosed verifies validation on a closed conn returns an error.
func TestPinValidateConnClosed(t *testing.T) {
	ps := NewPinSet()
	conn := &Conn{}
	err := ps.ValidateConn(conn)
	if err == nil {
		t.Error("expected error for closed connection")
	}
}

// TestPinResultConstants verifies PinResult constants have expected values.
func TestPinResultConstants(t *testing.T) {
	if PinResultMatch != 0 {
		t.Errorf("PinResultMatch = %d, want 0", PinResultMatch)
	}
	if PinResultNoMatch != 1 {
		t.Errorf("PinResultNoMatch = %d, want 1", PinResultNoMatch)
	}
}
