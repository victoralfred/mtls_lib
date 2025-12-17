// Package mtls provides idiomatic Go bindings for the mTLS C library.
//
// This package wraps the C mTLS library using cgo to provide a secure,
// mutual TLS transport layer for Go applications.
//
// # Basic Usage
//
//	config := &mtls.Config{
//	    CACertPath:   "/path/to/ca.crt",
//	    CertPath:     "/path/to/client.crt",
//	    KeyPath:      "/path/to/client.key",
//	}
//
//	ctx, err := mtls.NewContext(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ctx.Close()
//
//	conn, err := ctx.Connect("server:8443")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer conn.Close()
//
//	// Use conn as io.Reader/Writer
//	io.WriteString(conn, "Hello, mTLS!")
//
// # Thread Safety
//
// Context is safe for concurrent use after creation. Individual Conn and
// Listener instances are NOT thread-safe and should be used from a single
// goroutine at a time. Different connections can be used concurrently from
// different goroutines.
//
// # Memory Management
//
// All resources are automatically cleaned up using Go finalizers when they
// become unreachable. However, for deterministic cleanup, you should call
// Close() explicitly when done with a resource.
package mtls

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../build -lmtls -lssl -lcrypto -lpthread

#include <stdlib.h>
#include <mtls/mtls.h>
*/
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

// Version returns the library version string.
func Version() string {
	return C.GoString(C.mtls_version())
}

// VersionComponents returns the major, minor, and patch version numbers.
func VersionComponents() (major, minor, patch int) {
	var cMajor, cMinor, cPatch C.int
	C.mtls_version_components(&cMajor, &cMinor, &cPatch)
	return int(cMajor), int(cMinor), int(cPatch)
}

// TLSVersion represents a TLS protocol version.
type TLSVersion uint16

const (
	// TLS12 represents TLS 1.2
	TLS12 TLSVersion = 0x0303
	// TLS13 represents TLS 1.3
	TLS13 TLSVersion = 0x0304
)

// ConnState represents the state of a connection.
type ConnState int

const (
	// ConnStateNone indicates the connection is not initialized.
	ConnStateNone ConnState = iota
	// ConnStateConnecting indicates TCP connection is in progress.
	ConnStateConnecting
	// ConnStateHandshaking indicates TLS handshake is in progress.
	ConnStateHandshaking
	// ConnStateEstablished indicates the connection is established and verified.
	ConnStateEstablished
	// ConnStateClosing indicates shutdown is in progress.
	ConnStateClosing
	// ConnStateClosed indicates the connection is closed.
	ConnStateClosed
	// ConnStateError indicates the connection is in an error state.
	ConnStateError
)

// String returns a human-readable name for the connection state.
func (s ConnState) String() string {
	switch s {
	case ConnStateNone:
		return "None"
	case ConnStateConnecting:
		return "Connecting"
	case ConnStateHandshaking:
		return "Handshaking"
	case ConnStateEstablished:
		return "Established"
	case ConnStateClosing:
		return "Closing"
	case ConnStateClosed:
		return "Closed"
	case ConnStateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// Internal callback registry for event observers.
// Uses a map with mutex to store Go callback functions indexed by a unique ID.
// The ID is passed to C as userdata and used to look up the callback.
var (
	callbackMu      sync.RWMutex
	callbackCounter uintptr
	callbacks       = make(map[uintptr]EventCallback)
)

// registerCallback stores a Go callback and returns an ID for use as C userdata.
func registerCallback(cb EventCallback) uintptr {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	callbackCounter++
	id := callbackCounter
	callbacks[id] = cb
	return id
}

// unregisterCallback removes a callback from the registry.
func unregisterCallback(id uintptr) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	delete(callbacks, id)
}

// lookupCallback retrieves a callback by ID.
func lookupCallback(id uintptr) EventCallback {
	callbackMu.RLock()
	defer callbackMu.RUnlock()
	return callbacks[id]
}

// freeString is a helper to free a C string.
func freeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// keepAlive ensures the object is not garbage collected before this point.
// This is a wrapper around runtime.KeepAlive for documentation purposes.
func keepAlive(x interface{}) {
	runtime.KeepAlive(x)
}
