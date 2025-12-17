/**
 * @file mtls_conn.c
 * @brief Connection handling implementation
 */

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_config.h"
#include "internal/mtls_internal.h"
#include "internal/platform.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#if !defined(_WIN32)
#    include <sys/types.h>
#    include <sys/socket.h>
#    include <netinet/in.h>
#endif
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

mtls_conn *mtls_connect(mtls_ctx *ctx, const char *addr, mtls_err *err)
{
    uint64_t start_time = platform_get_time_us();

    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return NULL;
    }

    if (!addr) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Address is NULL");
        return NULL;
    }

    /* Emit CONNECT_START event */
    mtls_event event = {.type = MTLS_EVENT_CONNECT_START,
                        .remote_addr = addr,
                        .conn = NULL,
                        .error_code = 0,
                        .timestamp_us = start_time,
                        .duration_us = 0,
                        .bytes = 0};
    mtls_emit_event(ctx, &event);

    /* Check kill-switch */
    if (mtls_ctx_is_kill_switch_enabled(ctx)) {
        MTLS_ERR_SET(err, MTLS_ERR_KILL_SWITCH_ENABLED, "Kill-switch is enabled");

        /* Emit KILL_SWITCH_TRIGGERED event */
        event.type = MTLS_EVENT_KILL_SWITCH_TRIGGERED;
        event.error_code = MTLS_ERR_KILL_SWITCH_ENABLED;
        event.timestamp_us = platform_get_time_us();
        mtls_emit_event(ctx, &event);

        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.duration_us = platform_get_time_us() - start_time;
        mtls_emit_event(ctx, &event);

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
        mtls_emit_event(ctx, &event);
        return NULL;
    }

    conn->ctx = ctx;
    conn->sock = MTLS_INVALID_SOCKET;
    atomic_init(&conn->state, MTLS_CONN_STATE_NONE);
    conn->is_server = false;

    /* Parse address */
    if (platform_parse_addr(addr, &conn->remote_addr, err) < 0) {
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = err ? (int)err->code : MTLS_ERR_INVALID_ADDRESS;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        free(conn);
        return NULL;
    }

    /* Create socket */
    int addr_family = conn->remote_addr.addr.sa.sa_family;
    /* Validate address family */
    if (addr_family != AF_INET && addr_family != AF_INET6) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Unsupported address family");
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_INVALID_ADDRESS;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        free(conn);
        return NULL;
    }
    conn->sock = platform_socket_create(addr_family, SOCK_STREAM, 0, err);
    if (conn->sock == MTLS_INVALID_SOCKET) {
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = err ? (int)err->code : MTLS_ERR_SOCKET_CREATE_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        free(conn);
        return NULL;
    }

    /* Set timeouts */
    uint32_t timeout = ctx->config.connect_timeout_ms;
    if (timeout == 0) {
        timeout = MTLS_DEFAULT_CONNECT_TIMEOUT_MS;
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_CONNECTING);

    /* Connect */
    if (platform_socket_connect(conn->sock, &conn->remote_addr, timeout, err) < 0) {
        /* Emit CONNECT_FAILURE event */
        char remote_addr_str[128];
        platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.remote_addr = remote_addr_str;
        event.conn = conn;
        event.error_code = err ? (int)err->code : MTLS_ERR_CONNECT_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Format remote address for events */
    char remote_addr_str[128];
    platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    event.remote_addr = remote_addr_str;
    event.conn = conn;

    /* Create SSL object */
    SSL_CTX *ssl_ctx = mtls_tls_get_ssl_ctx(ctx->tls_ctx);
    if (!ssl_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_CTX_NOT_INITIALIZED, "TLS context not initialized");
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_CTX_NOT_INITIALIZED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }
    conn->ssl = SSL_new(ssl_ctx);
    if (!conn->ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to create SSL object");
        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.error_code = MTLS_ERR_TLS_INIT_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
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
        mtls_emit_event(ctx, &event);
        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Hostname verification (client mode) - must be set before handshake */
    if (ctx->config.verify_hostname) {
        /* Extract hostname from address string */
        const char *colon = strrchr(addr, ':');
        if (colon) {
            size_t hostname_len = colon - addr;
            char hostname[256];
            /* Ensure space for null terminator */
            if (hostname_len > 0 && hostname_len <= sizeof(hostname) - 1) {
                memcpy(hostname, addr, hostname_len);
                hostname[hostname_len] = '\0';

                /* Validate hostname doesn't contain invalid characters */
                bool valid = true;
                for (size_t i = 0; i < hostname_len; i++) {
                    if (hostname[i] == '\0' || hostname[i] == '\n' || hostname[i] == '\r') {
                        valid = false;
                        break;
                    }
                }

                if (!valid) {
                    MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Invalid characters in hostname");
                    /* Emit CONNECT_FAILURE event */
                    event.type = MTLS_EVENT_CONNECT_FAILURE;
                    event.error_code = MTLS_ERR_INVALID_ADDRESS;
                    event.timestamp_us = platform_get_time_us();
                    event.duration_us = event.timestamp_us - start_time;
                    mtls_emit_event(ctx, &event);
                    SSL_free(conn->ssl);
                    platform_socket_close(conn->sock);
                    free(conn);
                    return NULL;
                }

/* Use SSL_set1_host for hostname verification (OpenSSL 1.0.2+) */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
                if (SSL_set1_host(conn->ssl, hostname) == 0) {
                    MTLS_ERR_SET(err, MTLS_ERR_HOSTNAME_MISMATCH,
                                 "Failed to set hostname for verification: %s", hostname);
                    /* Emit CONNECT_FAILURE event */
                    event.type = MTLS_EVENT_CONNECT_FAILURE;
                    event.error_code = MTLS_ERR_HOSTNAME_MISMATCH;
                    event.timestamp_us = platform_get_time_us();
                    event.duration_us = event.timestamp_us - start_time;
                    mtls_emit_event(ctx, &event);
                    SSL_free(conn->ssl);
                    platform_socket_close(conn->sock);
                    free(conn);
                    return NULL;
                }
#endif
            } else {
                MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Hostname too long");
                /* Emit CONNECT_FAILURE event */
                event.type = MTLS_EVENT_CONNECT_FAILURE;
                event.error_code = MTLS_ERR_INVALID_ADDRESS;
                event.timestamp_us = platform_get_time_us();
                event.duration_us = event.timestamp_us - start_time;
                mtls_emit_event(ctx, &event);
                SSL_free(conn->ssl);
                platform_socket_close(conn->sock);
                free(conn);
                return NULL;
            }
        }
    }

    /* Perform TLS handshake */
    atomic_store(&conn->state, MTLS_CONN_STATE_HANDSHAKING);

    /* Emit HANDSHAKE_START event */
    event.type = MTLS_EVENT_HANDSHAKE_START;
    event.timestamp_us = platform_get_time_us();
    mtls_emit_event(ctx, &event);

    uint64_t handshake_start = platform_get_time_us();
    if (SSL_connect(conn->ssl) <= 0) {
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
        mtls_emit_event(ctx, &event);

        /* Emit CONNECT_FAILURE event */
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);

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
    mtls_emit_event(ctx, &event);

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
        mtls_emit_event(ctx, &event);

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
    if (ctx->config.allowed_sans_count > 0) {
        mtls_peer_identity identity;
        if (mtls_get_peer_identity(conn, &identity, err) == 0) {
            /* Use helper function with wildcard support */
            bool allowed = mtls_validate_peer_sans(&identity, ctx->config.allowed_sans,
                                                   ctx->config.allowed_sans_count);
            mtls_free_peer_identity(&identity);

            if (!allowed) {
                MTLS_ERR_SET(err, MTLS_ERR_IDENTITY_MISMATCH,
                             "Peer identity not in allowed SANs list");
                /* Emit CONNECT_FAILURE event */
                event.type = MTLS_EVENT_CONNECT_FAILURE;
                event.error_code = MTLS_ERR_IDENTITY_MISMATCH;
                event.timestamp_us = platform_get_time_us();
                event.duration_us = event.timestamp_us - start_time;
                mtls_emit_event(ctx, &event);
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
            mtls_emit_event(ctx, &event);
            SSL_free(conn->ssl);
            platform_socket_close(conn->sock);
            free(conn);
            return NULL;
        }
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_ESTABLISHED);

    /* Emit CONNECT_SUCCESS event */
    event.type = MTLS_EVENT_CONNECT_SUCCESS;
    event.conn = conn;
    event.error_code = 0;
    event.timestamp_us = platform_get_time_us();
    event.duration_us = event.timestamp_us - start_time;
    mtls_emit_event(ctx, &event);

    return conn;
}

ssize_t mtls_read(mtls_conn *conn, void *buffer, size_t len, mtls_err *err)
{
    if (!conn || !buffer) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (len == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Read length cannot be zero");
        return -1;
    }

    /* Check connection state atomically */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    /* Validate buffer length to prevent integer overflow and DoS */
    if (len > INT_MAX) {
        len = INT_MAX;
    }
    /* Additional safety: limit read size to prevent excessive memory usage */
    if (len > (size_t)MTLS_MAX_READ_BUFFER_SIZE) {
        len = (size_t)MTLS_MAX_READ_BUFFER_SIZE;
    }

    int bytes_read = SSL_read(conn->ssl, buffer, (int)len);
    if (bytes_read <= 0) {
        int ssl_err = SSL_get_error(conn->ssl, bytes_read);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            /* Connection closed gracefully */
            atomic_store(&conn->state, MTLS_CONN_STATE_CLOSED);
            return 0; /* EOF */
        }
        MTLS_ERR_SET(err, MTLS_ERR_READ_FAILED, "SSL_read failed");
        if (err) {
            err->ssl_err = ERR_get_error();
        }
        return -1;
    }

    /* Emit READ event */
    char remote_addr_str[128];
    platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    mtls_event event = {.type = MTLS_EVENT_READ,
                        .remote_addr = remote_addr_str,
                        .conn = conn,
                        .error_code = 0,
                        .timestamp_us = platform_get_time_us(),
                        .duration_us = 0,
                        .bytes = (size_t)bytes_read};
    mtls_emit_event(conn->ctx, &event);

    return bytes_read;
}

ssize_t mtls_write(mtls_conn *conn, const void *buffer, size_t len, mtls_err *err)
{
    if (!conn || !buffer) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (len == 0) {
        return 0; /* Zero-length write is valid */
    }

    /* Check connection state atomically */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    /* Validate write length */
    if (len > (size_t)MTLS_MAX_WRITE_BUFFER_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Write buffer too large (max %d bytes)",
                     MTLS_MAX_WRITE_BUFFER_SIZE);
        return -1;
    }

    /* Handle partial writes - SSL_write may not write all data in one call */
    ssize_t total_written = 0;
    const uint8_t *buf_ptr = (const uint8_t *)buffer;

    while (total_written < (ssize_t)len) {
        size_t remaining = len - (size_t)total_written;
        /* Limit to INT_MAX for SSL_write */
        int write_len = 0;
        if (remaining > (size_t)INT_MAX) {
            write_len = INT_MAX;
        } else {
            write_len = (int)remaining;
        }

        int bytes_written = SSL_write(conn->ssl, buf_ptr + total_written, write_len);
        if (bytes_written <= 0) {
            int ssl_err = SSL_get_error(conn->ssl, bytes_written);
            if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                /* Should not happen with blocking I/O, but handle gracefully */
                if (total_written > 0) {
                    return total_written; /* Return partial write */
                }
                MTLS_ERR_SET(err, MTLS_ERR_WOULD_BLOCK, "SSL_write would block");
            } else {
                MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED, "SSL_write failed");
                if (err) {
                    err->ssl_err = ERR_get_error();
                }
            }
            return (total_written > 0) ? total_written : -1;
        }
/* Check for integer overflow before adding */
/* SSIZE_MAX may not be defined on all platforms, use SIZE_MAX/2 as safe limit */
#ifndef SSIZE_MAX
#    define SSIZE_MAX ((ssize_t)(SIZE_MAX / 2))
#endif
        if (total_written > SSIZE_MAX - (ssize_t)bytes_written) {
            MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED, "Write would overflow ssize_t");
            return (total_written > 0) ? total_written : -1;
        }
        total_written += bytes_written;
    }

    /* Emit WRITE event */
    char remote_addr_str[128];
    platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    mtls_event event = {.type = MTLS_EVENT_WRITE,
                        .remote_addr = remote_addr_str,
                        .conn = conn,
                        .error_code = 0,
                        .timestamp_us = platform_get_time_us(),
                        .duration_us = 0,
                        .bytes = (size_t)total_written};
    mtls_emit_event(conn->ctx, &event);

    return total_written;
}

void mtls_close(mtls_conn *conn)
{
    if (!conn) {
        return;
    }

    /* Atomically set state to CLOSING to prevent concurrent operations.
     * Handle all possible states to avoid race conditions. */
    int current_state = atomic_load(&conn->state);

    /* Spin until we successfully transition to CLOSING or detect already closed */
    while (current_state != MTLS_CONN_STATE_CLOSING && current_state != MTLS_CONN_STATE_CLOSED) {
        if (atomic_compare_exchange_weak(&conn->state, &current_state, MTLS_CONN_STATE_CLOSING)) {
            /* Successfully transitioned to CLOSING */
            break;
        }
        /* CAS failed, current_state was updated - loop will re-check */
    }

    /* If already closing or closed, avoid double-close */
    if (current_state == MTLS_CONN_STATE_CLOSING || current_state == MTLS_CONN_STATE_CLOSED) {
        return;
    }

    /* Emit CLOSE event */
    char remote_addr_str[128];
    platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    mtls_event event = {.type = MTLS_EVENT_CLOSE,
                        .remote_addr = remote_addr_str,
                        .conn = conn,
                        .error_code = 0,
                        .timestamp_us = platform_get_time_us(),
                        .duration_us = 0,
                        .bytes = 0};
    mtls_emit_event(conn->ctx, &event);

    if (conn->ssl) {
        /* Perform bidirectional TLS shutdown for clean termination.
         * SSL_shutdown returns:
         *   0 = shutdown sent, need to call again for bidirectional
         *   1 = shutdown complete
         *  <0 = error */
        int shutdown_ret = SSL_shutdown(conn->ssl);
        if (shutdown_ret == 0) {
            /* First phase complete, call again for bidirectional shutdown.
             * Don't block indefinitely - proceed with cleanup regardless. */
            (void)SSL_shutdown(conn->ssl);
        }
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if (conn->sock != MTLS_INVALID_SOCKET) {
        platform_socket_close(conn->sock);
        conn->sock = MTLS_INVALID_SOCKET;
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_CLOSED);

    platform_secure_zero(conn, sizeof(*conn));
    free(conn);
}

mtls_conn_state mtls_get_state(const mtls_conn *conn)
{
    return conn ? (mtls_conn_state)atomic_load(&conn->state) : MTLS_CONN_STATE_NONE;
}

int mtls_get_remote_addr(const mtls_conn *conn, char *addr_buf, size_t addr_buf_len)
{
    if (!conn || !addr_buf) {
        return -1;
    }
    return platform_format_addr(&conn->remote_addr, addr_buf, addr_buf_len);
}

int mtls_get_local_addr(const mtls_conn *conn, char *addr_buf, size_t addr_buf_len)
{
    if (!conn || !addr_buf) {
        return -1;
    }
    return platform_format_addr(&conn->local_addr, addr_buf, addr_buf_len);
}
