/**
 * @file mtls_listener.c
 * @brief Server-side listener implementation
 */

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_config.h"
#include "internal/mtls_internal.h"
#include "internal/platform.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#if !defined(_WIN32)
#    include <sys/types.h>
#    include <sys/socket.h>
#endif
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

mtls_listener *mtls_listen(mtls_ctx *ctx, const char *bind_addr, mtls_err *err)
{
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return NULL;
    }

    if (!bind_addr) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Bind address is NULL");
        return NULL;
    }

    /* Allocate listener */
    mtls_listener *listener = calloc(1, sizeof(*listener));
    if (!listener) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate listener");
        return NULL;
    }

    listener->ctx = ctx;
    listener->sock = MTLS_INVALID_SOCKET;

    /* Parse bind address */
    if (platform_parse_addr(bind_addr, &listener->bind_addr, err) < 0) {
        free(listener);
        return NULL;
    }

    /* Create socket */
    int addr_family = listener->bind_addr.addr.sa.sa_family;
    /* Validate address family */
    if (addr_family != AF_INET && addr_family != AF_INET6) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Unsupported address family");
        free(listener);
        return NULL;
    }
    listener->sock = platform_socket_create(addr_family, SOCK_STREAM, 0, err);
    if (listener->sock == MTLS_INVALID_SOCKET) {
        free(listener);
        return NULL;
    }

    /* Set SO_REUSEADDR */
    platform_socket_set_reuseaddr(listener->sock, true, NULL);

    /* Bind */
    if (platform_socket_bind(listener->sock, &listener->bind_addr, err) < 0) {
        platform_socket_close(listener->sock);
        free(listener);
        return NULL;
    }

    /* Listen */
    if (platform_socket_listen(listener->sock, MTLS_LISTEN_BACKLOG, err) < 0) {
        platform_socket_close(listener->sock);
        free(listener);
        return NULL;
    }

    return listener;
}

mtls_conn *mtls_accept(mtls_listener *listener, mtls_err *err)
{
    uint64_t start_time = platform_get_time_us();

    if (!listener) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Listener is NULL");
        return NULL;
    }

    /* Emit CONNECT_START event (server-side) */
    mtls_event event = {.type = MTLS_EVENT_CONNECT_START,
                        .remote_addr = NULL, /* Not known yet */
                        .conn = NULL,
                        .error_code = 0,
                        .timestamp_us = start_time,
                        .duration_us = 0,
                        .bytes = 0};
    mtls_emit_event(listener->ctx, &event);

    /* Check kill-switch */
    if (mtls_ctx_is_kill_switch_enabled(listener->ctx)) {
        MTLS_ERR_SET(err, MTLS_ERR_KILL_SWITCH_ENABLED, "Kill-switch is enabled");

        /* Emit KILL_SWITCH_TRIGGERED event */
        event.type = MTLS_EVENT_KILL_SWITCH_TRIGGERED;
        event.error_code = MTLS_ERR_KILL_SWITCH_ENABLED;
        event.timestamp_us = platform_get_time_us();
        mtls_emit_event(listener->ctx, &event);

        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.duration_us = platform_get_time_us() - start_time;
        mtls_emit_event(listener->ctx, &event);

        return NULL;
    }

    /* Allocate connection */
    mtls_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate connection");
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_OUT_OF_MEMORY;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(listener->ctx, &event);
        return NULL;
    }

    conn->ctx = listener->ctx;
    conn->sock = MTLS_INVALID_SOCKET;
    atomic_init(&conn->state, MTLS_CONN_STATE_NONE);
    conn->is_server = true;

    /* Accept connection */
    conn->sock = platform_socket_accept(listener->sock, &conn->remote_addr, err);
    if (conn->sock == MTLS_INVALID_SOCKET) {
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = err ? (int)err->code : MTLS_ERR_ACCEPT_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(listener->ctx, &event);
        free(conn);
        return NULL;
    }

    /* Format remote address for events */
    char remote_addr_str[MTLS_ADDR_STR_MAX_LEN];
    platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    event.remote_addr = remote_addr_str;
    event.conn = conn;

    /* Create SSL object */
    SSL_CTX *ssl_ctx = mtls_tls_get_ssl_ctx(listener->ctx->tls_ctx);
    conn->ssl = SSL_new(ssl_ctx);
    if (!conn->ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to create SSL object");
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_TLS_INIT_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(listener->ctx, &event);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Attach socket to SSL */
    if (!SSL_set_fd(conn->ssl, (int)conn->sock)) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to attach socket to SSL");
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_TLS_INIT_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(listener->ctx, &event);
        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Perform TLS handshake (server mode) */
    atomic_store(&conn->state, MTLS_CONN_STATE_HANDSHAKING);

    /* Emit HANDSHAKE_START event */
    event.type = MTLS_EVENT_HANDSHAKE_START;
    event.timestamp_us = platform_get_time_us();
    mtls_emit_event(listener->ctx, &event);

    uint64_t handshake_start = platform_get_time_us();
    if (SSL_accept(conn->ssl) <= 0) {
        unsigned long ssl_err = ERR_get_error();
        MTLS_ERR_SET(err, MTLS_ERR_TLS_HANDSHAKE_FAILED, "TLS handshake failed");
        if (err) {
            err->ssl_err = ssl_err;
        }

        /* Emit HANDSHAKE_FAILURE event */
        event.type = MTLS_EVENT_HANDSHAKE_FAILURE;
        event.error_code = MTLS_ERR_TLS_HANDSHAKE_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - handshake_start;
        mtls_emit_event(listener->ctx, &event);

        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(listener->ctx, &event);

        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Emit HANDSHAKE_SUCCESS event */
    event.type = MTLS_EVENT_HANDSHAKE_SUCCESS;
    event.error_code = 0;
    event.timestamp_us = platform_get_time_us();
    event.duration_us = event.timestamp_us - handshake_start;
    mtls_emit_event(listener->ctx, &event);

    /* Verify certificate validation result */
    long verify_result = SSL_get_verify_result(conn->ssl);
    if (verify_result != X509_V_OK) {
        const char *verify_msg = X509_verify_cert_error_string(verify_result);
        MTLS_ERR_SET(err, MTLS_ERR_CERT_UNTRUSTED,
                     "Certificate verification failed: %s (code: %ld)",
                     verify_msg ? verify_msg : "Unknown error", verify_result);
        if (err) {
            err->ssl_err = verify_result;
        }

        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_CERT_UNTRUSTED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(listener->ctx, &event);

        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Get local address */
    socklen_t local_len = sizeof(conn->local_addr.addr.ss);
    if (getsockname(conn->sock, &conn->local_addr.addr.sa, &local_len) == 0) {
        conn->local_addr.len = local_len;
    } else {
        /* Failed to get local address, but not critical - continue */
        conn->local_addr.len = 0;
    }

    /* Validate peer identity against allowed SANs if configured */
    if (listener->ctx->config.allowed_sans_count > 0) {
        mtls_peer_identity identity;
        if (mtls_get_peer_identity(conn, &identity, err) == 0) {
            /* Use helper function with wildcard support */
            bool allowed = mtls_validate_peer_sans(&identity, listener->ctx->config.allowed_sans,
                                                   listener->ctx->config.allowed_sans_count);
            mtls_free_peer_identity(&identity);

            if (!allowed) {
                MTLS_ERR_SET(err, MTLS_ERR_IDENTITY_MISMATCH,
                             "Peer identity not in allowed SANs list");

                /* Emit CONNECT_FAILURE event */
                event.type = MTLS_EVENT_CONNECT_FAILURE;
                event.error_code = MTLS_ERR_IDENTITY_MISMATCH;
                event.timestamp_us = platform_get_time_us();
                event.duration_us = event.timestamp_us - start_time;
                mtls_emit_event(listener->ctx, &event);

                SSL_free(conn->ssl);
                platform_socket_close(conn->sock);
                free(conn);
                return NULL;
            }
        } else {
            /* If identity extraction failed but SANs are required, reject */
            MTLS_ERR_SET(err, MTLS_ERR_IDENTITY_MISMATCH,
                         "Failed to extract peer identity for validation");

            /* Emit CONNECT_FAILURE event */
            event.type = MTLS_EVENT_CONNECT_FAILURE;
            event.error_code = MTLS_ERR_IDENTITY_MISMATCH;
            event.timestamp_us = platform_get_time_us();
            event.duration_us = event.timestamp_us - start_time;
            mtls_emit_event(listener->ctx, &event);

            SSL_free(conn->ssl);
            platform_socket_close(conn->sock);
            free(conn);
            return NULL;
        }
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_ESTABLISHED);

    /* Emit CONNECT_SUCCESS event */
    event.type = MTLS_EVENT_CONNECT_SUCCESS;
    event.error_code = 0;
    event.timestamp_us = platform_get_time_us();
    event.duration_us = event.timestamp_us - start_time;
    mtls_emit_event(listener->ctx, &event);

    return conn;
}

void mtls_listener_close(mtls_listener *listener)
{
    if (!listener) {
        return;
    }

    if (listener->sock != MTLS_INVALID_SOCKET) {
        platform_socket_close(listener->sock);
        listener->sock = MTLS_INVALID_SOCKET;
    }

    platform_secure_zero(listener, sizeof(*listener));
    free(listener);
}
