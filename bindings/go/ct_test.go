package mtls

import (
	"testing"
)

// TestNewCTLogList verifies a fresh log list starts empty.
func TestNewCTLogList(t *testing.T) {
	ll := NewCTLogList()
	defer ll.Close()

	if ll.Count() != 0 {
		t.Errorf("Count() = %d, want 0", ll.Count())
	}
}

// TestCTLogListDoubleClose verifies Close is idempotent.
func TestCTLogListDoubleClose(t *testing.T) {
	ll := NewCTLogList()
	ll.Close()
	ll.Close() // must not panic
}

// TestCTLogListClear verifies Clear resets the list.
func TestCTLogListClear(t *testing.T) {
	ll := NewCTLogList()
	defer ll.Close()
	ll.Clear()
	if ll.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", ll.Count())
	}
}

// TestCTLogListLoadEmptyJSON verifies LoadJSON returns error for empty data.
func TestCTLogListLoadEmptyJSON(t *testing.T) {
	ll := NewCTLogList()
	defer ll.Close()

	err := ll.LoadJSON(nil)
	if err == nil {
		t.Error("expected error for empty JSON data")
	}
}

// TestCTLogListLoadInvalidJSON verifies LoadJSON returns error for invalid JSON.
func TestCTLogListLoadInvalidJSON(t *testing.T) {
	ll := NewCTLogList()
	defer ll.Close()

	err := ll.LoadJSON([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestCTValidateConnClosed verifies ValidateConn on a closed connection returns an error.
func TestCTValidateConnClosed(t *testing.T) {
	ll := NewCTLogList()
	defer ll.Close()

	conn := &Conn{}
	_, err := ll.ValidateConn(conn, 2, false)
	if err == nil {
		t.Error("expected error for closed connection")
	}
}

// TestCTResultConstants verifies CT result constants have expected values.
func TestCTResultConstants(t *testing.T) {
	if CTResultValid != 0 {
		t.Errorf("CTResultValid = %d, want 0", CTResultValid)
	}
	if CTResultNoSCTs != 1 {
		t.Errorf("CTResultNoSCTs = %d, want 1", CTResultNoSCTs)
	}
}
