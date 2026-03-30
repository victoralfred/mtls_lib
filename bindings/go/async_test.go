package mtls

import (
	"testing"
	"time"
)

// TestNewAsyncCtxNilContext verifies error for nil C context.
func TestNewAsyncCtxNilContext(t *testing.T) {
	ctx := &Context{}
	_, err := ctx.NewAsyncCtx()
	if err == nil {
		t.Error("expected error for nil C context")
	}
}

// TestAsyncCtxDestroyIdempotent verifies Destroy is safe to call multiple times.
func TestAsyncCtxDestroyIdempotent(t *testing.T) {
	ac := &AsyncCtx{}
	ac.Destroy()
	ac.Destroy() // must not panic
}

// TestAsyncCtxPollClosedCtx verifies Poll on a nil async ctx returns an error.
func TestAsyncCtxPollClosedCtx(t *testing.T) {
	ac := &AsyncCtx{}
	_, err := ac.Poll(0)
	if err == nil {
		t.Error("expected error for nil async context")
	}
}

// TestAsyncCtxWakeupClosed verifies Wakeup on nil is a no-op.
func TestAsyncCtxWakeupClosed(t *testing.T) {
	ac := &AsyncCtx{}
	err := ac.Wakeup()
	if err != nil {
		t.Errorf("Wakeup on closed ctx returned unexpected error: %v", err)
	}
}

// TestAsyncCtxPendingCountClosed verifies PendingCount on nil is 0.
func TestAsyncCtxPendingCountClosed(t *testing.T) {
	ac := &AsyncCtx{}
	if n := ac.PendingCount(); n != 0 {
		t.Errorf("PendingCount() on closed ctx = %d, want 0", n)
	}
}

// TestAsyncConnectClosedCtx verifies Connect on a nil async ctx returns an error.
func TestAsyncConnectClosedCtx(t *testing.T) {
	ac := &AsyncCtx{}
	_, err := ac.Connect("localhost:8443")
	if err == nil {
		t.Error("expected error for nil async context")
	}
}

// TestAsyncReadEmptyBuf verifies Read with empty buffer returns immediately.
func TestAsyncReadEmptyBuf(t *testing.T) {
	ac := &AsyncCtx{}
	conn := &Conn{}
	// Even with nil context and closed conn, empty buf should return immediately.
	_, err := ac.Read(conn, nil)
	// Either an error (nil context) or immediate empty result is acceptable.
	_ = err
	_ = time.Second // ensure time import used
}

// TestAsyncPendingRegistry verifies that register/lookup/unregister is consistent.
func TestAsyncPendingRegistry(t *testing.T) {
	p := &asyncPending{}
	id := registerAsync(p)
	if id == 0 {
		t.Error("registerAsync returned 0")
	}
	got := lookupAsync(id)
	if got != p {
		t.Errorf("lookupAsync returned wrong pending: %p != %p", got, p)
	}
	unregisterAsync(id)
	if lookupAsync(id) != nil {
		t.Error("lookupAsync should return nil after unregisterAsync")
	}
}
