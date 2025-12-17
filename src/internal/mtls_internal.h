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
 * SAFE USAGE PATTERN:
 *   - Set observers before creating any connections
 *   - Do not modify observers until all connections are closed
 *   - Use thread-safe logging/metrics in the callback
 */
static inline void mtls_emit_event(mtls_ctx *ctx, const mtls_event *event)
{
    if (ctx && ctx->observers.on_event) {
        ctx->observers.on_event(event, ctx->observers.userdata);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* MTLS_INTERNAL_H */
