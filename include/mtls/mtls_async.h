/**
 * @file mtls_async.h
 * @brief Asynchronous I/O support for mTLS connections
 *
 * This module provides non-blocking, event-driven I/O operations for mTLS
 * connections. It uses platform-specific event notification mechanisms:
 * - Linux: epoll
 * - macOS/BSD: kqueue
 * - Windows: IOCP
 *
 * Features:
 * - Callback-based async connect, read, and write operations
 * - Event loop integration for custom event loops
 * - Cancellation support for pending operations
 * - Thread-safe operation dispatch
 *
 * Example usage:
 * @code
 * mtls_async_ctx *async_ctx;
 * if (mtls_async_ctx_create(&async_ctx, ctx, &err) == 0) {
 *     // Start async connect
 *     mtls_async_connect(async_ctx, "server.example.com:8443",
 *                        on_connect, userdata, &err);
 *
 *     // Run event loop
 *     while (running) {
 *         mtls_async_poll(async_ctx, 1000, &err);
 *     }
 *
 *     mtls_async_ctx_destroy(async_ctx);
 * }
 *
 * void on_connect(mtls_conn *conn, mtls_err *err, void *userdata) {
 *     if (conn) {
 *         // Connection succeeded, start async read
 *         mtls_async_read(conn, buffer, sizeof(buffer), on_read, userdata, NULL);
 *     } else {
 *         // Handle error
 *     }
 * }
 * @endcode
 */

#ifndef MTLS_ASYNC_H
#define MTLS_ASYNC_H

#include "mtls_error.h"
#include "mtls_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * Forward Declarations
 * =============================================================================
 */

struct mtls_ctx;
struct mtls_conn;

/*
 * =============================================================================
 * Async Types and Constants
 * =============================================================================
 */

/**
 * Async operation state
 */
typedef enum mtls_async_state {
    MTLS_ASYNC_STATE_IDLE = 0,        /**< No operation in progress */
    MTLS_ASYNC_STATE_CONNECTING = 1,  /**< Connect in progress */
    MTLS_ASYNC_STATE_HANDSHAKING = 2, /**< TLS handshake in progress */
    MTLS_ASYNC_STATE_READING = 3,     /**< Read operation pending */
    MTLS_ASYNC_STATE_WRITING = 4,     /**< Write operation pending */
    MTLS_ASYNC_STATE_CLOSING = 5,     /**< Close in progress */
    MTLS_ASYNC_STATE_ERROR = 6        /**< Error state */
} mtls_async_state;

/**
 * Async context constants
 */
enum {
    /** Maximum pending operations per context */
    MTLS_ASYNC_MAX_PENDING = 1024,
    /** Default poll timeout in milliseconds */
    MTLS_ASYNC_DEFAULT_TIMEOUT_MS = 1000
};

/**
 * Opaque async context handle
 */
typedef struct mtls_async_ctx mtls_async_ctx;

/**
 * Opaque async operation handle
 */
typedef struct mtls_async_op mtls_async_op;

/*
 * =============================================================================
 * Callback Types
 * =============================================================================
 */

/**
 * Callback for async connect operations
 *
 * @param conn Connection on success, NULL on failure
 * @param err Error details if conn is NULL
 * @param userdata User-provided context data
 */
typedef void (*mtls_async_connect_cb)(struct mtls_conn *conn, mtls_err *err, void *userdata);

/**
 * Callback for async read/write operations
 *
 * @param conn The connection
 * @param result Bytes transferred on success, -1 on error
 * @param err Error details if result is -1
 * @param userdata User-provided context data
 */
typedef void (*mtls_async_io_cb)(struct mtls_conn *conn, ssize_t result, mtls_err *err,
                                 void *userdata);

/**
 * Callback for async close operations
 *
 * @param err Error details if close failed, NULL on success
 * @param userdata User-provided context data
 */
typedef void (*mtls_async_close_cb)(mtls_err *err, void *userdata);

/*
 * =============================================================================
 * Async Context Lifecycle
 * =============================================================================
 */

/**
 * Create an async context
 *
 * The async context manages event notification and pending operations.
 * One async context can handle multiple connections.
 *
 * @param async_ctx Pointer to receive new async context handle
 * @param ctx mTLS context to use for connections
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_async_ctx_create(mtls_async_ctx **async_ctx, struct mtls_ctx *ctx, mtls_err *err);

/**
 * Destroy an async context
 *
 * Cancels all pending operations and frees resources.
 * Does NOT close connections - they remain valid.
 *
 * @param async_ctx Async context to destroy (safe to call with NULL)
 */
MTLS_API void mtls_async_ctx_destroy(mtls_async_ctx *async_ctx);

/**
 * Get the underlying file descriptor for event loop integration
 *
 * Returns the epoll/kqueue/IOCP handle for custom event loop integration.
 * The caller should NOT close this file descriptor.
 *
 * @param async_ctx Async context
 * @return File descriptor, or -1 if invalid
 */
MTLS_API int mtls_async_ctx_get_fd(mtls_async_ctx *async_ctx);

/*
 * =============================================================================
 * Event Loop
 * =============================================================================
 */

/**
 * Poll for events and dispatch callbacks
 *
 * Waits for events on pending operations and invokes callbacks.
 * This is the main event loop driver function.
 *
 * @param async_ctx Async context
 * @param timeout_ms Maximum wait time (-1 = infinite, 0 = non-blocking)
 * @param err Error structure to populate on failure
 * @return Number of events processed, or -1 on error
 */
MTLS_API int mtls_async_poll(mtls_async_ctx *async_ctx, int timeout_ms, mtls_err *err);

/**
 * Wake up a blocking poll from another thread
 *
 * Thread-safe way to interrupt a poll() call. Useful for
 * signaling shutdown or adding new operations.
 *
 * @param async_ctx Async context
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_async_wakeup(mtls_async_ctx *async_ctx);

/**
 * Get the number of pending operations
 *
 * @param async_ctx Async context
 * @return Number of pending operations
 */
MTLS_API size_t mtls_async_pending_count(mtls_async_ctx *async_ctx);

/*
 * =============================================================================
 * Async Operations
 * =============================================================================
 */

/**
 * Start an async connect operation
 *
 * Initiates a non-blocking connection. The callback is invoked when
 * the connection completes or fails.
 *
 * @param async_ctx Async context
 * @param addr Server address in "host:port" format
 * @param callback Function to call on completion
 * @param userdata User context passed to callback
 * @param err Error structure to populate on immediate failure
 * @return Operation handle on success, NULL on immediate failure
 */
MTLS_API mtls_async_op *mtls_async_connect(mtls_async_ctx *async_ctx, const char *addr,
                                           mtls_async_connect_cb callback, void *userdata,
                                           mtls_err *err);

/**
 * Start an async read operation
 *
 * Initiates a non-blocking read. The callback is invoked when
 * data is available or an error occurs.
 *
 * @param async_ctx Async context
 * @param conn Connection to read from
 * @param buf Buffer to read into
 * @param len Maximum bytes to read
 * @param callback Function to call on completion
 * @param userdata User context passed to callback
 * @param err Error structure to populate on immediate failure
 * @return Operation handle on success, NULL on immediate failure
 */
MTLS_API mtls_async_op *mtls_async_read(mtls_async_ctx *async_ctx, struct mtls_conn *conn,
                                        void *buf, size_t len, mtls_async_io_cb callback,
                                        void *userdata, mtls_err *err);

/**
 * Start an async write operation
 *
 * Initiates a non-blocking write. The callback is invoked when
 * the write completes or an error occurs.
 *
 * @param async_ctx Async context
 * @param conn Connection to write to
 * @param buf Data to write
 * @param len Bytes to write
 * @param callback Function to call on completion
 * @param userdata User context passed to callback
 * @param err Error structure to populate on immediate failure
 * @return Operation handle on success, NULL on immediate failure
 */
MTLS_API mtls_async_op *mtls_async_write(mtls_async_ctx *async_ctx, struct mtls_conn *conn,
                                         const void *buf, size_t len, mtls_async_io_cb callback,
                                         void *userdata, mtls_err *err);

/**
 * Start an async close operation
 *
 * Initiates a graceful connection close. The callback is invoked
 * when the close completes.
 *
 * @param async_ctx Async context
 * @param conn Connection to close
 * @param callback Function to call on completion (may be NULL)
 * @param userdata User context passed to callback
 * @param err Error structure to populate on immediate failure
 * @return Operation handle on success, NULL on immediate failure
 */
MTLS_API mtls_async_op *mtls_async_close(mtls_async_ctx *async_ctx, struct mtls_conn *conn,
                                         mtls_async_close_cb callback, void *userdata,
                                         mtls_err *err);

/*
 * =============================================================================
 * Operation Management
 * =============================================================================
 */

/**
 * Cancel a pending async operation
 *
 * Cancels the operation and invokes its callback with an error.
 * Safe to call on completed operations (no-op).
 *
 * @param async_op Operation to cancel
 * @return 0 if cancelled, -1 if already completed
 */
MTLS_API int mtls_async_op_cancel(mtls_async_op *async_op);

/**
 * Get the state of an async operation
 *
 * @param async_op Operation to query
 * @return Current operation state
 */
MTLS_API mtls_async_state mtls_async_op_get_state(mtls_async_op *async_op);

/**
 * Check if an operation is still pending
 *
 * @param async_op Operation to check
 * @return true if pending, false if completed or cancelled
 */
MTLS_API bool mtls_async_op_is_pending(mtls_async_op *async_op);

/*
 * =============================================================================
 * Connection Integration
 * =============================================================================
 */

/**
 * Get the file descriptor for a connection
 *
 * Returns the underlying socket file descriptor for custom event loop
 * integration. The caller should NOT close this file descriptor.
 *
 * @param conn Connection to query
 * @return File descriptor, or -1 if invalid
 */
MTLS_API int mtls_async_conn_get_fd(struct mtls_conn *conn);

/**
 * Register a connection with an async context
 *
 * Associates a connection with the async context for event notification.
 * This is done automatically for connections created via mtls_async_connect.
 *
 * @param async_ctx Async context
 * @param conn Connection to register
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_async_register_conn(mtls_async_ctx *async_ctx, struct mtls_conn *conn,
                                      mtls_err *err);

/**
 * Unregister a connection from an async context
 *
 * Removes the connection from event notification. Pending operations
 * on this connection are cancelled.
 *
 * @param async_ctx Async context
 * @param conn Connection to unregister
 */
MTLS_API void mtls_async_unregister_conn(mtls_async_ctx *async_ctx, struct mtls_conn *conn);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Get human-readable string for async state
 *
 * @param state Async state
 * @return Static string describing the state
 */
MTLS_API const char *mtls_async_state_string(mtls_async_state state);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_ASYNC_H */
