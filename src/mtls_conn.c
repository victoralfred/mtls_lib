/**
 * @file mtls_conn.c
 * @brief Connection handling implementation
 */

#include "mtls/mtls.h"
#include "internal/mtls_internal.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/err.h>

mtls_conn* mtls_connect(mtls_ctx* ctx, const char* addr, mtls_err* err) {
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return NULL;
    }

    if (!addr) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Address is NULL");
        return NULL;
    }

    /* Check kill-switch */
    if (mtls_ctx_is_kill_switch_enabled(ctx)) {
        MTLS_ERR_SET(err, MTLS_ERR_KILL_SWITCH_ENABLED, "Kill-switch is enabled");
        return NULL;
    }

    /* Allocate connection */
    mtls_conn* conn = calloc(1, sizeof(*conn));
    if (!conn) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate connection");
        return NULL;
    }

    conn->ctx = ctx;
    conn->sock = MTLS_INVALID_SOCKET;
    conn->state = MTLS_CONN_STATE_NONE;
    conn->is_server = false;

    /* Parse address */
    if (platform_parse_addr(addr, &conn->remote_addr, err) < 0) {
        free(conn);
        return NULL;
    }

    /* Create socket */
    int af = conn->remote_addr.addr.sa.sa_family;
    /* Validate address family */
    if (af != AF_INET && af != AF_INET6) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Unsupported address family");
        free(conn);
        return NULL;
    }
    conn->sock = platform_socket_create(af, SOCK_STREAM, 0, err);
    if (conn->sock == MTLS_INVALID_SOCKET) {
        free(conn);
        return NULL;
    }

    /* Set timeouts */
    uint32_t timeout = ctx->config.connect_timeout_ms;
    if (timeout == 0) timeout = MTLS_DEFAULT_CONNECT_TIMEOUT_MS;

    conn->state = MTLS_CONN_STATE_CONNECTING;

    /* Connect */
    if (platform_socket_connect(conn->sock, &conn->remote_addr, timeout, err) < 0) {
        platform_socket_close(conn->sock);
        free(conn);
        return NULL;
    }

    /* Create SSL object */
    SSL_CTX* ssl_ctx = mtls_tls_get_ssl_ctx(ctx->tls_ctx);
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

    /* Hostname verification (client mode) - must be set before handshake */
    if (ctx->config.verify_hostname) {
        /* Extract hostname from address string */
        const char* colon = strrchr(addr, ':');
        if (colon) {
            size_t hostname_len = colon - addr;
            char hostname[256];
            if (hostname_len > 0 && hostname_len < sizeof(hostname)) {
                memcpy(hostname, addr, hostname_len);
                hostname[hostname_len] = '\0';
                
                /* Use SSL_set1_host for hostname verification (OpenSSL 1.0.2+) */
                #if OPENSSL_VERSION_NUMBER >= 0x10002000L
                if (SSL_set1_host(conn->ssl, hostname) != 0) {
                    MTLS_ERR_SET(err, MTLS_ERR_HOSTNAME_MISMATCH,
                                 "Failed to set hostname for verification: %s", hostname);
                    SSL_free(conn->ssl);
                    platform_socket_close(conn->sock);
                    free(conn);
                    return NULL;
                }
                #endif
            }
        }
    }

    /* Perform TLS handshake */
    conn->state = MTLS_CONN_STATE_HANDSHAKING;
    if (SSL_connect(conn->ssl) <= 0) {
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
    }

    /* Validate peer identity against allowed SANs if configured */
    if (ctx->config.allowed_sans_count > 0) {
        mtls_peer_identity identity;
        if (mtls_get_peer_identity(conn, &identity, err) == 0) {
            /* Use helper function with wildcard support */
            bool allowed = mtls_validate_peer_sans(&identity,
                                                    (const char**)ctx->config.allowed_sans,
                                                    ctx->config.allowed_sans_count);
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

    conn->state = MTLS_CONN_STATE_ESTABLISHED;
    return conn;
}

ssize_t mtls_read(mtls_conn* conn, void* buffer, size_t len, mtls_err* err) {
    if (!conn || !buffer) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (conn->state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    int n = SSL_read(conn->ssl, buffer, (int)len);
    if (n <= 0) {
        int ssl_err = SSL_get_error(conn->ssl, n);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            return 0;  /* EOF */
        }
        MTLS_ERR_SET(err, MTLS_ERR_READ_FAILED, "SSL_read failed");
        if (err) err->ssl_err = ERR_get_error();
        return -1;
    }

    return n;
}

ssize_t mtls_write(mtls_conn* conn, const void* buffer, size_t len, mtls_err* err) {
    if (!conn || !buffer) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (conn->state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    /* Handle partial writes - SSL_write may not write all data in one call */
    ssize_t total_written = 0;
    const uint8_t* buf_ptr = (const uint8_t*)buffer;
    
    while (total_written < (ssize_t)len) {
        size_t remaining = len - (size_t)total_written;
        /* Limit to INT_MAX for SSL_write */
        int write_len = (remaining > (size_t)INT_MAX) ? INT_MAX : (int)remaining;
        
        int n = SSL_write(conn->ssl, buf_ptr + total_written, write_len);
        if (n <= 0) {
            int ssl_err = SSL_get_error(conn->ssl, n);
            if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                /* Should not happen with blocking I/O, but handle gracefully */
                if (total_written > 0) {
                    return total_written;  /* Return partial write */
                }
                MTLS_ERR_SET(err, MTLS_ERR_WOULD_BLOCK, "SSL_write would block");
            } else {
                MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED, "SSL_write failed");
                if (err) err->ssl_err = ERR_get_error();
            }
            return (total_written > 0) ? total_written : -1;
        }
        total_written += n;
    }

    return total_written;
}

void mtls_close(mtls_conn* conn) {
    if (!conn) return;

    conn->state = MTLS_CONN_STATE_CLOSING;

    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if (conn->sock != MTLS_INVALID_SOCKET) {
        platform_socket_close(conn->sock);
        conn->sock = MTLS_INVALID_SOCKET;
    }

    conn->state = MTLS_CONN_STATE_CLOSED;

    platform_secure_zero(conn, sizeof(*conn));
    free(conn);
}

mtls_conn_state mtls_get_state(const mtls_conn* conn) {
    return conn ? conn->state : MTLS_CONN_STATE_NONE;
}

int mtls_get_remote_addr(const mtls_conn* conn, char* addr_buf, size_t addr_buf_len) {
    if (!conn || !addr_buf) return -1;
    return platform_format_addr(&conn->remote_addr, addr_buf, addr_buf_len);
}

int mtls_get_local_addr(const mtls_conn* conn, char* addr_buf, size_t addr_buf_len) {
    if (!conn || !addr_buf) return -1;
    return platform_format_addr(&conn->local_addr, addr_buf, addr_buf_len);
}
