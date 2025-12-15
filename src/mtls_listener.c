/**
 * @file mtls_listener.c
 * @brief Server-side listener implementation
 */

#include "mtls/mtls.h"
#include "internal/mtls_internal.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>

mtls_listener* mtls_listen(mtls_ctx* ctx, const char* bind_addr, mtls_err* err) {
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return NULL;
    }

    if (!bind_addr) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Bind address is NULL");
        return NULL;
    }

    /* Allocate listener */
    mtls_listener* listener = calloc(1, sizeof(*listener));
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
    int af = listener->bind_addr.addr.sa.sa_family;
    /* Validate address family */
    if (af != AF_INET && af != AF_INET6) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Unsupported address family");
        free(listener);
        return NULL;
    }
    listener->sock = platform_socket_create(af, SOCK_STREAM, 0, err);
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
    if (platform_socket_listen(listener->sock, 128, err) < 0) {
        platform_socket_close(listener->sock);
        free(listener);
        return NULL;
    }

    return listener;
}

mtls_conn* mtls_accept(mtls_listener* listener, mtls_err* err) {
    if (!listener) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Listener is NULL");
        return NULL;
    }

    /* Check kill-switch */
    if (mtls_ctx_is_kill_switch_enabled(listener->ctx)) {
        MTLS_ERR_SET(err, MTLS_ERR_KILL_SWITCH_ENABLED, "Kill-switch is enabled");
        return NULL;
    }

    /* Allocate connection */
    mtls_conn* conn = calloc(1, sizeof(*conn));
    if (!conn) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate connection");
        return NULL;
    }

    conn->ctx = listener->ctx;
    conn->sock = MTLS_INVALID_SOCKET;
    atomic_init(&conn->state, MTLS_CONN_STATE_NONE);
    conn->is_server = true;

    /* Accept connection */
    conn->sock = platform_socket_accept(listener->sock, &conn->remote_addr, err);
    if (conn->sock == MTLS_INVALID_SOCKET) {
        free(conn);
        return NULL;
    }

    /* Create SSL object */
    SSL_CTX* ssl_ctx = mtls_tls_get_ssl_ctx(listener->ctx->tls_ctx);
    conn->ssl = SSL_new(ssl_ctx);
    if (!conn->ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to create SSL object");
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Attach socket to SSL */
    if (!SSL_set_fd(conn->ssl, (int)conn->sock)) {
        MTLS_ERR_SET(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to attach socket to SSL");
        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Perform TLS handshake (server mode) */
    atomic_store(&conn->state, MTLS_CONN_STATE_HANDSHAKING);
    if (SSL_accept(conn->ssl) <= 0) {
        unsigned long ssl_err = ERR_get_error();
        MTLS_ERR_SET(err, MTLS_ERR_TLS_HANDSHAKE_FAILED, "TLS handshake failed");
        if (err) err->ssl_err = ssl_err;
        SSL_free(conn->ssl);
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Verify certificate validation result */
    long verify_result = SSL_get_verify_result(conn->ssl);
    if (verify_result != X509_V_OK) {
        const char* verify_msg = X509_verify_cert_error_string(verify_result);
        MTLS_ERR_SET(err, MTLS_ERR_CERT_UNTRUSTED,
                     "Certificate verification failed: %s (code: %ld)",
                     verify_msg ? verify_msg : "Unknown error", verify_result);
        if (err) err->ssl_err = verify_result;
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
            bool allowed = mtls_validate_peer_sans(&identity,
                                                    (const char**)listener->ctx->config.allowed_sans,
                                                    listener->ctx->config.allowed_sans_count);
            mtls_free_peer_identity(&identity);

            if (!allowed) {
                MTLS_ERR_SET(err, MTLS_ERR_IDENTITY_MISMATCH,
                             "Peer identity not in allowed SANs list");
                SSL_free(conn->ssl);
                platform_socket_close(conn->sock);
                free(conn);
                return NULL;
            }
        } else {
            /* If identity extraction failed but SANs are required, reject */
            MTLS_ERR_SET(err, MTLS_ERR_IDENTITY_MISMATCH,
                         "Failed to extract peer identity for validation");
            SSL_free(conn->ssl);
            platform_socket_close(conn->sock);
            free(conn);
            return NULL;
        }
    }

    atomic_store(&conn->state, MTLS_CONN_STATE_ESTABLISHED);
    return conn;
}

void mtls_listener_close(mtls_listener* listener) {
    if (!listener) return;

    if (listener->sock != MTLS_INVALID_SOCKET) {
        platform_socket_close(listener->sock);
        listener->sock = MTLS_INVALID_SOCKET;
    }

    platform_secure_zero(listener, sizeof(*listener));
    free(listener);
}
