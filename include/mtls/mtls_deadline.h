/**
 * @file mtls_deadline.h
 * @brief Deadline context for mTLS operations
 *
 * This header provides deadline-based timeout management for mTLS operations.
 * Deadlines enforce a total time budget across multiple operations (connect,
 * handshake, read, write), unlike socket-level timeouts which apply per-operation.
 *
 * Usage example:
 * @code
 * mtls_deadline_ctx *deadline = NULL;
 * mtls_err err;
 * mtls_err_init(&err);
 *
 * // Create deadline for 5 seconds from now
 * if (mtls_deadline_ctx_create_with_timeout(&deadline, 5000, &err) < 0) {
 *     // Handle error
 * }
 *
 * // Connect with deadline
 * mtls_conn *conn = mtls_connect_with_deadline(ctx, "example.com:443", deadline, &err);
 * if (conn == NULL) {
 *     if (err.code == MTLS_ERR_DEADLINE_EXCEEDED) {
 *         // Deadline expired
 *     }
 * }
 *
 * // Read with remaining deadline
 * char buf[1024];
 * ssize_t n = mtls_read_with_deadline(conn, buf, sizeof(buf), deadline, &err);
 *
 * mtls_deadline_ctx_destroy(deadline);
 * @endcode
 */

#ifndef MTLS_DEADLINE_H
#define MTLS_DEADLINE_H

#include "mtls_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct mtls_err mtls_err;
typedef struct mtls_ctx mtls_ctx;
typedef struct mtls_conn mtls_conn;
typedef struct mtls_listener mtls_listener;

/**
 * Deadline context structure.
 *
 * Tracks an absolute deadline and optional cancellation state.
 * Thread-safe: the cancelled flag uses atomic operations.
 */
typedef struct mtls_deadline_ctx {
    _Atomic bool cancelled;           /* Cancellation flag (atomic for thread safety) */
    uint64_t deadline_us;             /* Absolute deadline in microseconds since epoch */
    struct mtls_deadline_ctx *parent; /* Parent context for hierarchical cancellation */
} mtls_deadline_ctx;

/**
 * Create a deadline context with an absolute timestamp.
 *
 * @param ctx Pointer to receive the created context
 * @param deadline_us Absolute deadline in microseconds since epoch
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_deadline_ctx_create(mtls_deadline_ctx **ctx, uint64_t deadline_us, mtls_err *err);

/**
 * Create a deadline context with a timeout from now.
 *
 * @param ctx Pointer to receive the created context
 * @param timeout_ms Timeout in milliseconds from now
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_deadline_ctx_create_with_timeout(mtls_deadline_ctx **ctx, uint32_t timeout_ms,
                                                   mtls_err *err);

/**
 * Create a child deadline context.
 *
 * The child inherits the parent's deadline (or uses a shorter one if specified)
 * and will be cancelled when the parent is cancelled.
 *
 * @param ctx Pointer to receive the created context
 * @param parent Parent deadline context
 * @param timeout_ms Optional additional timeout (0 = inherit parent deadline)
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_deadline_ctx_create_child(mtls_deadline_ctx **ctx, mtls_deadline_ctx *parent,
                                            uint32_t timeout_ms, mtls_err *err);

/**
 * Destroy a deadline context.
 *
 * @param ctx Context to destroy (can be NULL)
 */
MTLS_API void mtls_deadline_ctx_destroy(mtls_deadline_ctx *ctx);

/**
 * Cancel a deadline context.
 *
 * Once cancelled, all operations using this context will fail with
 * MTLS_ERR_CANCELLED. This also cancels any child contexts.
 *
 * Thread-safe: can be called from any thread.
 *
 * @param ctx Context to cancel
 */
MTLS_API void mtls_deadline_ctx_cancel(mtls_deadline_ctx *ctx);

/**
 * Get remaining time until deadline in milliseconds.
 *
 * @param ctx Deadline context
 * @return Remaining milliseconds, 0 if expired, -1 if cancelled
 */
MTLS_API int64_t mtls_deadline_ctx_remaining_ms(const mtls_deadline_ctx *ctx);

/**
 * Check if deadline has expired.
 *
 * @param ctx Deadline context
 * @return true if expired or cancelled, false otherwise
 */
MTLS_API bool mtls_deadline_ctx_is_expired(const mtls_deadline_ctx *ctx);

/**
 * Check if deadline context has been cancelled.
 *
 * @param ctx Deadline context
 * @return true if cancelled, false otherwise
 */
MTLS_API bool mtls_deadline_ctx_is_cancelled(const mtls_deadline_ctx *ctx);

/**
 * Get the absolute deadline timestamp.
 *
 * @param ctx Deadline context
 * @return Deadline in microseconds since epoch
 */
MTLS_API uint64_t mtls_deadline_ctx_get_deadline(const mtls_deadline_ctx *ctx);

/**
 * Connect to a server with a deadline.
 *
 * This function performs the full connection including TCP connect and
 * TLS handshake, all within the deadline budget.
 *
 * @param ctx mTLS context
 * @param addr Server address in "host:port" format
 * @param deadline Deadline context (can be NULL for no deadline)
 * @param err Error structure to populate on failure
 * @return Connection on success, NULL on failure
 */
MTLS_API mtls_conn *mtls_connect_with_deadline(mtls_ctx *ctx, const char *addr,
                                               const mtls_deadline_ctx *deadline, mtls_err *err);

/**
 * Accept a connection with a deadline.
 *
 * @param listener Listener to accept from
 * @param deadline Deadline context (can be NULL for no deadline)
 * @param err Error structure to populate on failure
 * @return Connection on success, NULL on failure
 */
MTLS_API mtls_conn *mtls_accept_with_deadline(mtls_listener *listener,
                                              const mtls_deadline_ctx *deadline, mtls_err *err);

/**
 * Read data with a deadline.
 *
 * @param conn Connection to read from
 * @param buf Buffer to read into
 * @param len Maximum bytes to read
 * @param deadline Deadline context (can be NULL for no deadline)
 * @param err Error structure to populate on failure
 * @return Bytes read on success, -1 on failure
 */
MTLS_API ssize_t mtls_read_with_deadline(mtls_conn *conn, void *buf, size_t len,
                                         const mtls_deadline_ctx *deadline, mtls_err *err);

/**
 * Write data with a deadline.
 *
 * @param conn Connection to write to
 * @param buf Buffer to write from
 * @param len Bytes to write
 * @param deadline Deadline context (can be NULL for no deadline)
 * @param err Error structure to populate on failure
 * @return Bytes written on success, -1 on failure
 */
MTLS_API ssize_t mtls_write_with_deadline(mtls_conn *conn, const void *buf, size_t len,
                                          const mtls_deadline_ctx *deadline, mtls_err *err);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_DEADLINE_H */
