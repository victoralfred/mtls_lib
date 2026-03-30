package mtls

import (
	"testing"
	"time"
)

// TestNewDeadlineCtxWithTimeout creates a deadline context and checks Remaining > 0.
func TestNewDeadlineCtxWithTimeout(t *testing.T) {
	dc, err := NewDeadlineCtxWithTimeout(5 * time.Second)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	defer dc.Close()

	if dc.IsExpired() {
		t.Error("deadline should not be expired immediately after creation")
	}
	if dc.IsCancelled() {
		t.Error("deadline should not be cancelled")
	}
	rem := dc.Remaining()
	if rem <= 0 || rem > 5*time.Second {
		t.Errorf("Remaining() = %v, want 0 < x <= 5s", rem)
	}
}

// TestDeadlineCtxCancel verifies that Cancel() causes IsCancelled() to return true.
func TestDeadlineCtxCancel(t *testing.T) {
	dc, err := NewDeadlineCtxWithTimeout(60 * time.Second)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	defer dc.Close()

	dc.Cancel()

	if !dc.IsCancelled() {
		t.Error("IsCancelled() should return true after Cancel()")
	}
}

// TestDeadlineCtxExpired creates a 1ms deadline and waits for it to expire.
func TestDeadlineCtxExpired(t *testing.T) {
	dc, err := NewDeadlineCtxWithTimeout(1 * time.Millisecond)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout(1ms): %v", err)
	}
	defer dc.Close()

	// Wait a bit longer than the deadline.
	time.Sleep(10 * time.Millisecond)

	if !dc.IsExpired() {
		t.Error("1ms deadline should be expired after 10ms sleep")
	}
}

// TestDeadlineCtxDeadline verifies the deadline time is approximately correct.
// Since the C library uses CLOCK_MONOTONIC, we check that Deadline() is
// within a generous window of the originally requested time.
func TestDeadlineCtxDeadline(t *testing.T) {
	timeout := 10 * time.Second
	before := time.Now()
	dc, err := NewDeadlineCtxWithTimeout(timeout)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	defer dc.Close()

	got := dc.Deadline()
	expected := before.Add(timeout)
	diff := got.Sub(expected)
	if diff < 0 {
		diff = -diff
	}
	if diff > 100*time.Millisecond {
		t.Errorf("Deadline() ~= %v, expected ~%v (diff %v)", got, expected, diff)
	}
}

// TestChildDeadlineCtxNilParent verifies that NewChildDeadlineCtx with a nil parent errors.
func TestChildDeadlineCtxNilParent(t *testing.T) {
	_, err := NewChildDeadlineCtx(nil, time.Second)
	if err == nil {
		t.Error("expected error for nil parent")
	}
}

// TestDeadlineCtxDoubleClose verifies that Close is idempotent.
func TestDeadlineCtxDoubleClose(t *testing.T) {
	dc, err := NewDeadlineCtxWithTimeout(time.Second)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	dc.Close()
	dc.Close() // must not panic
}

// TestConnDeadlineMethods verifies the deadline methods on Conn don't panic on closed conn.
func TestConnDeadlineMethods(t *testing.T) {
	conn := &Conn{}
	dc, err := NewDeadlineCtxWithTimeout(time.Second)
	if err != nil {
		t.Fatalf("NewDeadlineCtxWithTimeout: %v", err)
	}
	defer dc.Close()

	buf := make([]byte, 16)
	_, err = conn.ReadWithDeadline(buf, dc)
	if err == nil {
		t.Error("ReadWithDeadline on closed conn should return error")
	}
	_, err = conn.WriteWithDeadline(buf, dc)
	if err == nil {
		t.Error("WriteWithDeadline on closed conn should return error")
	}
}
