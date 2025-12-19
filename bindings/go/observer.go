package mtls

/*
#include <mtls/mtls.h>

// Forward declaration of the Go callback gateway
extern void mtlsEventGateway(mtls_event *event, void *userdata);
*/
import "C"

import (
	"log"
	"sync"
	"time"
	"unsafe"
)

// SetObserver registers a callback function to receive events from this context.
//
// The callback is invoked synchronously from the thread that triggers the event.
// The callback must be safe for concurrent invocation if the context is used
// from multiple goroutines.
//
// Set callback to nil to disable the observer.
//
// Note: This function is NOT thread-safe. Call it before creating any
// connections, or close all connections before changing the observer.
func (c *Context) SetObserver(callback EventCallback) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return &Error{
			Code:    ErrCtxNotInitialized,
			Message: "context is closed",
		}
	}

	// Unregister previous callback if any
	if c.observerID != 0 {
		unregisterCallback(c.observerID)
		c.observerID = 0
	}

	if callback == nil {
		// Disable observers
		C.mtls_set_observers(c.ctx, nil)
		return nil
	}

	// Register new callback
	c.observerID = registerCallback(callback)

	var observers C.mtls_observers
	observers.on_event = (C.mtls_event_callback)(C.mtlsEventGateway)
	// Note: observerID is a uintptr (integer), not a Go pointer.
	// Converting it to unsafe.Pointer for C userdata is safe because:
	// 1. It's not a Go pointer, so GC won't move it
	// 2. We manage the ID lifecycle explicitly via register/unregister
	// 3. The C code only stores and passes back this value, never dereferences it
	observers.userdata = unsafe.Pointer(c.observerID)

	C.mtls_set_observers(c.ctx, &observers)

	return nil
}

// Events returns a channel that receives events from this context.
//
// The channel is buffered with the specified size. Events are dropped
// if the channel buffer is full (non-blocking send).
//
// Call the returned cancel function to stop receiving events and
// close the channel.
//
// Example:
//
//	events, cancel := ctx.Events(100)
//	defer cancel()
//
//	for event := range events {
//	    fmt.Printf("Event: %s\n", event.Type)
//	}
func (c *Context) Events(bufferSize int) (<-chan *Event, func()) {
	if bufferSize < 1 {
		bufferSize = 1
	}

	ch := make(chan *Event, bufferSize)
	done := make(chan struct{})

	callback := func(e *Event) {
		select {
		case <-done:
			return
		case ch <- e:
		default:
			// Buffer full, drop event
		}
	}

	c.SetObserver(callback)

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			close(done)
			c.SetObserver(nil)
			close(ch)
		})
	}

	return ch, cancel
}

// FilteredEvents returns a channel that receives only events matching the filter.
func (c *Context) FilteredEvents(bufferSize int, filter EventFilter) (<-chan *Event, func()) {
	if filter == nil {
		return c.Events(bufferSize)
	}

	ch := make(chan *Event, bufferSize)
	done := make(chan struct{})

	callback := func(e *Event) {
		if !filter(e) {
			return
		}
		select {
		case <-done:
			return
		case ch <- e:
		default:
			// Buffer full, drop event
		}
	}

	c.SetObserver(callback)

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			close(done)
			c.SetObserver(nil)
			close(ch)
		})
	}

	return ch, cancel
}

// mtlsEventGateway is the C callback gateway that invokes Go callbacks.
// This function is exported to C and called from the C library.
//
//export mtlsEventGateway
func mtlsEventGateway(cEvent *C.mtls_event, userdata unsafe.Pointer) {
	if cEvent == nil || userdata == nil {
		return
	}

	id := uintptr(userdata)
	callback := lookupCallback(id)
	if callback == nil {
		return
	}

	// Convert C event to Go event
	event := &Event{
		Type:      EventType(cEvent._type),
		ErrorCode: ErrorCode(cEvent.error_code),
		Timestamp: time.UnixMicro(int64(cEvent.timestamp_us)),
		Duration:  time.Duration(cEvent.duration_us) * time.Microsecond,
		Bytes:     uint64(cEvent.bytes),
	}

	if cEvent.remote_addr != nil {
		event.RemoteAddr = C.GoString(cEvent.remote_addr)
	}

	// Invoke Go callback with panic recovery to prevent crashes from propagating
	// through C code (which would cause undefined behavior)
	defer func() {
		if r := recover(); r != nil {
			// Log the panic to prevent silent failures in production
			log.Printf("mtls: event callback panicked: %v (event: %s)", r, event.Type)
		}
	}()
	callback(event)
}

// ObserverBuilder helps construct complex event observers.
type ObserverBuilder struct {
	callbacks []EventCallback
	filters   []EventFilter
}

// NewObserverBuilder creates a new ObserverBuilder.
func NewObserverBuilder() *ObserverBuilder {
	return &ObserverBuilder{}
}

// OnEvent adds a callback that receives all events.
func (b *ObserverBuilder) OnEvent(cb EventCallback) *ObserverBuilder {
	b.callbacks = append(b.callbacks, cb)
	return b
}

// OnSuccess adds a callback that receives only success events.
func (b *ObserverBuilder) OnSuccess(cb EventCallback) *ObserverBuilder {
	b.callbacks = append(b.callbacks, func(e *Event) {
		if e.Type.IsSuccess() {
			cb(e)
		}
	})
	return b
}

// OnFailure adds a callback that receives only failure events.
func (b *ObserverBuilder) OnFailure(cb EventCallback) *ObserverBuilder {
	b.callbacks = append(b.callbacks, func(e *Event) {
		if e.Type.IsFailure() {
			cb(e)
		}
	})
	return b
}

// OnIO adds a callback that receives only I/O events.
func (b *ObserverBuilder) OnIO(cb EventCallback) *ObserverBuilder {
	b.callbacks = append(b.callbacks, func(e *Event) {
		if e.Type.IsIO() {
			cb(e)
		}
	})
	return b
}

// OnEventType adds a callback that receives only specific event types.
func (b *ObserverBuilder) OnEventType(types []EventType, cb EventCallback) *ObserverBuilder {
	typeSet := make(map[EventType]bool)
	for _, t := range types {
		typeSet[t] = true
	}
	b.callbacks = append(b.callbacks, func(e *Event) {
		if typeSet[e.Type] {
			cb(e)
		}
	})
	return b
}

// Build returns a single EventCallback that invokes all registered callbacks.
func (b *ObserverBuilder) Build() EventCallback {
	callbacks := make([]EventCallback, len(b.callbacks))
	copy(callbacks, b.callbacks)

	return func(e *Event) {
		for _, cb := range callbacks {
			cb(e)
		}
	}
}

// Apply registers the built observer with the context.
func (b *ObserverBuilder) Apply(ctx *Context) error {
	return ctx.SetObserver(b.Build())
}
