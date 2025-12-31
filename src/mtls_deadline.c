/**
 * @file mtls_deadline.c
 * @brief Deadline context implementation for mTLS operations
 */

#include "mtls/mtls_deadline.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls.h"
#include "internal/mtls_internal.h"
#include "internal/platform.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int mtls_deadline_ctx_create(mtls_deadline_ctx **ctx, uint64_t deadline_us, mtls_err *err)
{
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context pointer is NULL");
        return -1;
    }

    mtls_deadline_ctx *deadline = calloc(1, sizeof(*deadline));
    if (!deadline) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate deadline context");
        return -1;
    }

    atomic_init(&deadline->cancelled, false);
    deadline->deadline_us = deadline_us;
    deadline->parent = NULL;

    *ctx = deadline;
    return 0;
}

int mtls_deadline_ctx_create_with_timeout(mtls_deadline_ctx **ctx, uint32_t timeout_ms,
                                          mtls_err *err)
{
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context pointer is NULL");
        return -1;
    }

    uint64_t now_us = platform_get_time_us();
    uint64_t deadline_us = now_us + ((uint64_t)timeout_ms * 1000);

    return mtls_deadline_ctx_create(ctx, deadline_us, err);
}

int mtls_deadline_ctx_create_child(mtls_deadline_ctx **ctx, mtls_deadline_ctx *parent,
                                   uint32_t timeout_ms, mtls_err *err)
{
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context pointer is NULL");
        return -1;
    }

    if (!parent) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Parent context is NULL");
        return -1;
    }

    uint64_t now_us = platform_get_time_us();
    uint64_t deadline_us = parent->deadline_us;

    /* If timeout is specified, use the earlier of parent deadline or timeout */
    if (timeout_ms > 0) {
        uint64_t child_deadline = now_us + ((uint64_t)timeout_ms * 1000);
        if (child_deadline < deadline_us) {
            deadline_us = child_deadline;
        }
    }

    mtls_deadline_ctx *deadline = calloc(1, sizeof(*deadline));
    if (!deadline) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate child deadline context");
        return -1;
    }

    atomic_init(&deadline->cancelled, false);
    deadline->deadline_us = deadline_us;
    deadline->parent = parent;

    *ctx = deadline;
    return 0;
}

void mtls_deadline_ctx_destroy(mtls_deadline_ctx *ctx)
{
    if (ctx) {
        free(ctx);
    }
}

void mtls_deadline_ctx_cancel(mtls_deadline_ctx *ctx)
{
    if (ctx) {
        atomic_store(&ctx->cancelled, true);
    }
}

int64_t mtls_deadline_ctx_remaining_ms(const mtls_deadline_ctx *ctx)
{
    if (!ctx) {
        return 0;
    }

    /* Check parent cancellation first */
    if (ctx->parent && atomic_load(&ctx->parent->cancelled)) {
        return -1;
    }

    /* Check self cancellation */
    if (atomic_load(&ctx->cancelled)) {
        return -1;
    }

    uint64_t now_us = platform_get_time_us();
    if (now_us >= ctx->deadline_us) {
        return 0;
    }

    return (int64_t)((ctx->deadline_us - now_us) / 1000);
}

bool mtls_deadline_ctx_is_expired(const mtls_deadline_ctx *ctx)
{
    if (!ctx) {
        return true;
    }

    /* Check cancellation */
    if (mtls_deadline_ctx_is_cancelled(ctx)) {
        return true;
    }

    /* Check deadline */
    return platform_get_time_us() >= ctx->deadline_us;
}

bool mtls_deadline_ctx_is_cancelled(const mtls_deadline_ctx *ctx)
{
    if (!ctx) {
        return false;
    }

    /* Check parent cancellation */
    if (ctx->parent && atomic_load(&ctx->parent->cancelled)) {
        return true;
    }

    return atomic_load(&ctx->cancelled);
}

uint64_t mtls_deadline_ctx_get_deadline(const mtls_deadline_ctx *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->deadline_us;
}

/**
 * Helper to check deadline and calculate remaining timeout.
 *
 * @param deadline Deadline context (may be NULL)
 * @param timeout_out Pointer to receive calculated timeout in ms
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 if deadline expired/cancelled
 */
static int deadline_check_remaining(const mtls_deadline_ctx *deadline, uint32_t *timeout_out,
                                    mtls_err *err)
{
    if (!deadline) {
        /* No deadline - use a large timeout */
        *timeout_out = UINT32_MAX;
        return 0;
    }

    /* Check cancellation */
    if (mtls_deadline_ctx_is_cancelled(deadline)) {
        MTLS_ERR_SET(err, MTLS_ERR_CANCELLED, "Operation cancelled");
        return -1;
    }

    /* Get remaining time */
    int64_t remaining = mtls_deadline_ctx_remaining_ms(deadline);
    if (remaining < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_CANCELLED, "Operation cancelled");
        return -1;
    }
    if (remaining == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_DEADLINE_EXCEEDED, "Deadline exceeded");
        return -1;
    }

    /* Cap to uint32_t max */
    if (remaining > UINT32_MAX) {
        remaining = UINT32_MAX;
    }

    *timeout_out = (uint32_t)remaining;
    return 0;
}

mtls_conn *mtls_connect_with_deadline(mtls_ctx *ctx, const char *addr,
                                      const mtls_deadline_ctx *deadline, mtls_err *err)
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

    /* Emit DEADLINE_START event */
    if (deadline) {
        mtls_event event = {.type = MTLS_EVENT_DEADLINE_START,
                            .remote_addr = addr,
                            .conn = NULL,
                            .error_code = 0,
                            .timestamp_us = start_time,
                            .duration_us = 0,
                            .bytes = 0};
        mtls_emit_event(ctx, &event);
    }

    /* Check deadline */
    uint32_t remaining_ms = 0;
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        if (deadline && err && err->code == MTLS_ERR_DEADLINE_EXCEEDED) {
            /* Emit DEADLINE_EXCEEDED event */
            mtls_event event = {.type = MTLS_EVENT_DEADLINE_EXCEEDED,
                                .remote_addr = addr,
                                .conn = NULL,
                                .error_code = MTLS_ERR_DEADLINE_EXCEEDED,
                                .timestamp_us = platform_get_time_us(),
                                .duration_us = platform_get_time_us() - start_time,
                                .bytes = 0};
            mtls_emit_event(ctx, &event);
        }
        return NULL;
    }

    /* Emit CONNECT_START event */
    mtls_event event = {.type = MTLS_EVENT_CONNECT_START,
                        .remote_addr = addr,
                        .conn = NULL,
                        .error_code = 0,
                        .timestamp_us = platform_get_time_us(),
                        .duration_us = 0,
                        .bytes = 0};
    mtls_emit_event(ctx, &event);

    /* Check kill-switch */
    if (mtls_ctx_is_kill_switch_enabled(ctx)) {
        MTLS_ERR_SET(err, MTLS_ERR_KILL_SWITCH_ENABLED, "Kill-switch is enabled");

        event.type = MTLS_EVENT_KILL_SWITCH_TRIGGERED;
        event.error_code = MTLS_ERR_KILL_SWITCH_ENABLED;
        event.timestamp_us = platform_get_time_us();
        mtls_emit_event(ctx, &event);

        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.duration_us = platform_get_time_us() - start_time;
        mtls_emit_event(ctx, &event);

        return NULL;
    }

    /* Allocate connection */
    mtls_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate connection");
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
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.conn = conn;
        event.error_code = err ? (int)err->code : MTLS_ERR_INVALID_ADDRESS;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        free(conn);
        return NULL;
    }

    /* Create socket */
    int addr_family = conn->remote_addr.addr.sa.sa_family;
    if (addr_family != AF_INET && addr_family != AF_INET6) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Unsupported address family");
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.conn = conn;
        event.error_code = MTLS_ERR_INVALID_ADDRESS;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        free(conn);
        return NULL;
    }

    conn->sock = platform_socket_create(addr_family, SOCK_STREAM, 0, err);
    if (conn->sock == MTLS_INVALID_SOCKET) {
        event.type = MTLS_EVENT_CONNECT_FAILURE;
        event.conn = conn;
        event.error_code = err ? (int)err->code : MTLS_ERR_SOCKET_CREATE_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - start_time;
        mtls_emit_event(ctx, &event);
        free(conn);
        return NULL;
    }

    /* Recalculate remaining time before connect */
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        if (deadline && err && err->code == MTLS_ERR_DEADLINE_EXCEEDED) {
            mtls_event deadline_event = {.type = MTLS_EVENT_DEADLINE_EXCEEDED,
                                         .remote_addr = addr,
                                         .conn = conn,
                                         .error_code = MTLS_ERR_DEADLINE_EXCEEDED,
                                         .timestamp_us = platform_get_time_us(),
                                         .duration_us = platform_get_time_us() - start_time,
                                         .bytes = 0};
            mtls_emit_event(ctx, &deadline_event);
        }
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Use the smaller of deadline remaining or config timeout */
    uint32_t connect_timeout = ctx->config.connect_timeout_ms;
    if (connect_timeout == 0) {
        connect_timeout = MTLS_DEFAULT_CONNECT_TIMEOUT_MS;
    }
    if (remaining_ms < connect_timeout) {
        connect_timeout = remaining_ms;
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_CONNECTING);

    /* Connect with deadline-aware timeout */
    if (platform_socket_connect(conn->sock, &conn->remote_addr, connect_timeout, err) < 0) {
        char remote_addr_str[MTLS_ADDR_STR_MAX_LEN];
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

    /* Recalculate remaining time for handshake */
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        if (deadline && err && err->code == MTLS_ERR_DEADLINE_EXCEEDED) {
            mtls_event deadline_event = {.type = MTLS_EVENT_DEADLINE_EXCEEDED,
                                         .remote_addr = addr,
                                         .conn = conn,
                                         .error_code = MTLS_ERR_DEADLINE_EXCEEDED,
                                         .timestamp_us = platform_get_time_us(),
                                         .duration_us = platform_get_time_us() - start_time,
                                         .bytes = 0};
            mtls_emit_event(ctx, &deadline_event);
        }
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Apply deadline-aware socket timeouts for handshake */
    (void)platform_socket_set_recv_timeout(conn->sock, remaining_ms, NULL);
    (void)platform_socket_set_send_timeout(conn->sock, remaining_ms, NULL);

    /* Format remote address for events */
    char remote_addr_str[MTLS_ADDR_STR_MAX_LEN];
    platform_format_addr(&conn->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    event.remote_addr = remote_addr_str;
    event.conn = conn;

    /* Create SSL object */
    SSL_CTX *ssl_ctx = mtls_tls_get_ssl_ctx(ctx->tls_ctx);
    if (!ssl_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_CTX_NOT_INITIALIZED, "TLS context not initialized");
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

    /* Perform TLS handshake */
    atomic_store(&conn->state, MTLS_CONN_STATE_HANDSHAKING);

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

        event.type = MTLS_EVENT_HANDSHAKE_FAILURE;
        event.error_code = MTLS_ERR_TLS_HANDSHAKE_FAILED;
        event.timestamp_us = platform_get_time_us();
        event.duration_us = event.timestamp_us - handshake_start;
        mtls_emit_event(ctx, &event);

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
    event.timestamp_us = platform_get_time_us();
    event.duration_us = event.timestamp_us - handshake_start;
    mtls_emit_event(ctx, &event);

    /* Mark as established */
    atomic_store(&conn->state, MTLS_CONN_STATE_ESTABLISHED);

    /* Restore normal timeouts after handshake */
    uint32_t read_timeout = ctx->config.read_timeout_ms;
    uint32_t write_timeout = ctx->config.write_timeout_ms;
    if (read_timeout > 0) {
        (void)platform_socket_set_recv_timeout(conn->sock, read_timeout, NULL);
    }
    if (write_timeout > 0) {
        (void)platform_socket_set_send_timeout(conn->sock, write_timeout, NULL);
    }

    /* Emit CONNECT_SUCCESS event */
    event.type = MTLS_EVENT_CONNECT_SUCCESS;
    event.timestamp_us = platform_get_time_us();
    event.duration_us = event.timestamp_us - start_time;
    mtls_emit_event(ctx, &event);

    return conn;
}

mtls_conn *mtls_accept_with_deadline(mtls_listener *listener, const mtls_deadline_ctx *deadline,
                                     mtls_err *err)
{
    if (!listener) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Listener is NULL");
        return NULL;
    }

    /* Check deadline */
    uint32_t remaining_ms = 0;
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        return NULL;
    }

    /* Apply deadline-aware timeout to listener socket */
    if (remaining_ms < UINT32_MAX) {
        (void)platform_socket_set_recv_timeout(listener->sock, remaining_ms, NULL);
    }

    /* Accept connection */
    mtls_addr client_addr;
    mtls_socket_t client_sock = platform_socket_accept(listener->sock, &client_addr, err);
    if (client_sock == MTLS_INVALID_SOCKET) {
        return NULL;
    }

    /* Recalculate remaining time for handshake */
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        platform_socket_close(client_sock);
        return NULL;
    }

    /* Apply deadline-aware socket timeouts */
    (void)platform_socket_set_recv_timeout(client_sock, remaining_ms, NULL);
    (void)platform_socket_set_send_timeout(client_sock, remaining_ms, NULL);

    /* Allocate connection */
    mtls_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate connection");
        platform_socket_close(client_sock);
        return NULL;
    }

    conn->ctx = listener->ctx;
    conn->sock = client_sock;
    conn->remote_addr = client_addr;
    atomic_init(&conn->state, MTLS_CONN_STATE_HANDSHAKING);
    conn->is_server = true;

    /* Create SSL object */
    SSL_CTX *ssl_ctx = mtls_tls_get_ssl_ctx(listener->ctx->tls_ctx);
    if (!ssl_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_CTX_NOT_INITIALIZED, "TLS context not initialized");
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    conn->ssl = SSL_new(ssl_ctx);
    if (!conn->ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to create SSL object");
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    if (!SSL_set_fd(conn->ssl, (int)conn->sock)) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to attach socket to SSL");
        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Perform TLS handshake (server side) */
    if (SSL_accept(conn->ssl) <= 0) {
        unsigned long ssl_err = ERR_get_error();
        MTLS_ERR_SET(err, MTLS_ERR_TLS_HANDSHAKE_FAILED, "TLS handshake failed");
        if (err) {
            err->ssl_err = ssl_err;
        }
        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_ESTABLISHED);

    /* Restore normal timeouts */
    uint32_t read_timeout = listener->ctx->config.read_timeout_ms;
    uint32_t write_timeout = listener->ctx->config.write_timeout_ms;
    if (read_timeout > 0) {
        (void)platform_socket_set_recv_timeout(conn->sock, read_timeout, NULL);
    }
    if (write_timeout > 0) {
        (void)platform_socket_set_send_timeout(conn->sock, write_timeout, NULL);
    }

    return conn;
}

ssize_t mtls_read_with_deadline(mtls_conn *conn, void *buf, size_t len,
                                const mtls_deadline_ctx *deadline, mtls_err *err)
{
    if (!conn || !buf) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (len == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Read length cannot be zero");
        return -1;
    }

    /* Check connection state */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    /* Check deadline */
    uint32_t remaining_ms = 0;
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        return -1;
    }

    /* Apply deadline-aware timeout */
    if (remaining_ms < UINT32_MAX) {
        (void)platform_socket_set_recv_timeout(conn->sock, remaining_ms, NULL);
    }

    /* Validate buffer length */
    if (len > INT_MAX) {
        len = INT_MAX;
    }
    if (len > (size_t)MTLS_MAX_READ_BUFFER_SIZE) {
        len = (size_t)MTLS_MAX_READ_BUFFER_SIZE;
    }

    int bytes_read = SSL_read(conn->ssl, buf, (int)len);
    if (bytes_read <= 0) {
        int ssl_err = SSL_get_error(conn->ssl, bytes_read);
        switch (ssl_err) {
        case SSL_ERROR_ZERO_RETURN:
            MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection closed by peer");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            MTLS_ERR_SET(err, MTLS_ERR_WOULD_BLOCK, "Operation would block");
            break;
        case SSL_ERROR_SYSCALL:
            if (platform_get_socket_error() == EAGAIN ||
                platform_get_socket_error() == EWOULDBLOCK) {
                MTLS_ERR_SET(err, MTLS_ERR_READ_TIMEOUT, "Read timed out");
            } else {
                MTLS_ERR_SET(err, MTLS_ERR_READ_FAILED, "Read failed");
            }
            break;
        default:
            MTLS_ERR_SET(err, MTLS_ERR_READ_FAILED, "Read failed");
            break;
        }
        return -1;
    }

    return bytes_read;
}

ssize_t mtls_write_with_deadline(mtls_conn *conn, const void *buf, size_t len,
                                 const mtls_deadline_ctx *deadline, mtls_err *err)
{
    if (!conn || !buf) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    /* Check connection state */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    /* Check deadline */
    uint32_t remaining_ms = 0;
    if (deadline_check_remaining(deadline, &remaining_ms, err) < 0) {
        return -1;
    }

    /* Apply deadline-aware timeout */
    if (remaining_ms < UINT32_MAX) {
        (void)platform_socket_set_send_timeout(conn->sock, remaining_ms, NULL);
    }

    /* Validate write length */
    if (len > (size_t)MTLS_MAX_WRITE_BUFFER_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Write buffer too large (max %d bytes)",
                     MTLS_MAX_WRITE_BUFFER_SIZE);
        return -1;
    }

    int bytes_written = SSL_write(conn->ssl, buf, (int)len);
    if (bytes_written <= 0) {
        int ssl_err = SSL_get_error(conn->ssl, bytes_written);
        switch (ssl_err) {
        case SSL_ERROR_ZERO_RETURN:
            MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection closed by peer");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            MTLS_ERR_SET(err, MTLS_ERR_WOULD_BLOCK, "Operation would block");
            break;
        case SSL_ERROR_SYSCALL:
            if (platform_get_socket_error() == EAGAIN ||
                platform_get_socket_error() == EWOULDBLOCK) {
                MTLS_ERR_SET(err, MTLS_ERR_WRITE_TIMEOUT, "Write timed out");
            } else {
                MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED, "Write failed");
            }
            break;
        default:
            MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED, "Write failed");
            break;
        }
        return -1;
    }

    return bytes_written;
}
