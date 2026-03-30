package mtls

/*
#include <mtls/mtls_async.h>
#include <mtls/mtls.h>

// Forward declarations so C callbacks can reference these Go-exported functions.
extern void goAsyncConnectCb(struct mtls_conn *conn, mtls_err *err, void *userdata);
extern void goAsyncIOCb(struct mtls_conn *conn, ssize_t result, mtls_err *err, void *userdata);
extern void goAsyncCloseCb(mtls_err *err, void *userdata);
*/
import "C"

import "unsafe"

// goAsyncConnectCb is the C-callable gateway for async connect callbacks.
// It looks up the pending channel by the ID stored as userdata and sends the result.
//
//export goAsyncConnectCb
func goAsyncConnectCb(cConn *C.struct_mtls_conn, cErr *C.mtls_err, userdata unsafe.Pointer) {
	id := uintptr(userdata)
	p := lookupAsync(id)
	if p == nil {
		return
	}
	unregisterAsync(id)

	if cConn != nil {
		conn := &Conn{conn: (*C.mtls_conn)(cConn), ctx: p.ctx.ctx}
		p.connectCh <- AsyncConnectResult{Conn: conn}
	} else {
		p.connectCh <- AsyncConnectResult{Err: convertError(cErr)}
	}
}

// goAsyncIOCb is the C-callable gateway for async read/write callbacks.
//
//export goAsyncIOCb
func goAsyncIOCb(cConn *C.struct_mtls_conn, result C.ssize_t, cErr *C.mtls_err, userdata unsafe.Pointer) {
	id := uintptr(userdata)
	p := lookupAsync(id)
	if p == nil {
		return
	}
	unregisterAsync(id)

	if result < 0 {
		p.ioCh <- AsyncIOResult{N: -1, Err: convertError(cErr)}
	} else {
		p.ioCh <- AsyncIOResult{N: int(result)}
	}
}

// goAsyncCloseCb is the C-callable gateway for async close callbacks.
//
//export goAsyncCloseCb
func goAsyncCloseCb(cErr *C.mtls_err, userdata unsafe.Pointer) {
	id := uintptr(userdata)
	p := lookupAsync(id)
	if p == nil {
		return
	}
	unregisterAsync(id)

	if cErr != nil && cErr.code != C.MTLS_OK {
		p.closeCh <- convertError(cErr)
	} else {
		p.closeCh <- nil
	}
}
