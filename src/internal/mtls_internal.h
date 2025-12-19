/**
 * @file mtls_internal.h
 * @brief Internal struct definitions for mTLS library
 *
 * This header exposes internal struct definitions to source files
 * while keeping them opaque to public API users.
 */

#ifndef MTLS_INTERNAL_H
#define MTLS_INTERNAL_H

#include "mtls/mtls.h" // NOLINT(misc-include-cleaner)
#include "mtls/mtls_types.h"
#include "mtls/mtls_config.h"
#include "platform.h"
#include <stdatomic.h>
#include <openssl/ssl.h> // NOLINT(misc-include-cleaner)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Internal context structure
 */
struct mtls_ctx {
    mtls_config config;
    void *tls_ctx;                   /* SSL_CTX from OpenSSL/BoringSSL */
    atomic_bool kill_switch_enabled; /* Thread-safe kill switch */
    mtls_observers observers;

    /* Ownership of dynamic strings */
    char *ca_cert_path;
    char *cert_path;
    char *key_path;
    char *crl_path;
    char **allowed_sans;
};

/*
 * Internal connection structure
 */
struct mtls_conn {
    mtls_ctx *ctx;
    mtls_socket_t sock;
    SSL *ssl;         // NOLINT(misc-include-cleaner)
    atomic_int state; /* Thread-safe connection state */
    mtls_addr remote_addr;
    mtls_addr local_addr;
    bool is_server;
};

/*
 * Internal listener structure
 */
struct mtls_listener {
    mtls_ctx *ctx;
    mtls_socket_t sock;
    mtls_addr bind_addr;
};

/* Forward declarations for TLS functions (implemented in mtls_tls.c) */
void *mtls_tls_ctx_create(const mtls_config *config, mtls_err *err);
void mtls_tls_ctx_free(void *tls_ctx);
int mtls_tls_ctx_reload_certs(void *tls_ctx, const mtls_config *config, mtls_err *err);
SSL_CTX *mtls_tls_get_ssl_ctx(void *tls_ctx); // NOLINT(misc-include-cleaner)

/* Note: mtls_validate_peer_sans is now in public API (mtls.h) */
/* Note: Other identity functions are declared in public API (mtls.h) */

/*
 * Helper function to emit observability events
 *
 * THREAD SAFETY REQUIREMENTS:
 *
 * 1. This function does NOT hold any locks when invoking the callback.
 *    The callback may be invoked concurrently from multiple threads if
 *    multiple connections are active on the same context.
 *
 * 2. The observers structure (ctx->observers) must NOT be modified while
 *    connections are active. Modifying on_event or userdata during active
 *    connections results in undefined behavior (data race).
 *
 * 3. The callback implementation MUST be thread-safe if the application
 *    uses multiple connections concurrently. Use appropriate synchronization
 *    (mutexes, atomics) in the callback when accessing shared state.
 *
 * 4. The callback MUST NOT block for extended periods as it runs in the
 *    I/O path and may delay connection handling.
 *
 * 5. All pointers in the mtls_event structure are valid only for the
 *    duration of the callback. Copy data if persistence is needed.
 *
 * 6. The callback MUST NOT throw exceptions (C++) or call longjmp/setjmp
 *    as this can corrupt library state. For C++ bindings, wrap callbacks
 *    in try-catch blocks at the binding layer.
 *
 * SAFE USAGE PATTERN:
 *   - Set observers before creating any connections
 *   - Do not modify observers until all connections are closed
 *   - Use thread-safe logging/metrics in the callback
 *   - Keep callbacks lightweight and non-blocking
 *   - Validate all event data in callbacks before use
 */
static inline void mtls_emit_event(mtls_ctx *ctx, const mtls_event *event)
{
    if (!ctx || !event) {
        return;
    }

    /* Load observer callback to local variable to minimize window for data race.
     * This provides a best-effort protection against reading partially-written
     * observer data if observers are modified concurrently (which is undefined
     * behavior but we try to be defensive).
     */
    mtls_event_callback callback = ctx->observers.on_event;
    void *userdata = ctx->observers.userdata;

    if (!callback) {
        return;
    }

    /* Validate event data before invoking callback to prevent callback issues
     * from invalid event types or corrupted data.
     */
    if (event->type < MTLS_EVENT_CONNECT_START || event->type > MTLS_EVENT_KILL_SWITCH_TRIGGERED) {
        /* Invalid event type - skip emission to prevent callback issues.
         * This should never happen in normal operation, but protects against
         * memory corruption or programming errors.
         */
        return;
    }

    /* Invoke callback.
     * NOTE: Callback failures (exceptions, crashes) will propagate to the caller.
     * For production use, ensure callbacks are robust and don't throw exceptions.
     * C++ bindings should wrap callbacks in try-catch at the binding layer.
     * This is standard practice for C callback APIs - the library cannot protect
     * against callback failures without platform-specific exception handling which
     * would add complexity and portability issues.
     */
    callback(event, userdata);
}

#ifdef __cplusplus
}
#endif

#endif /* MTLS_INTERNAL_H */
