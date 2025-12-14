/**
 * @file mtls_internal.h
 * @brief Internal struct definitions for mTLS library
 *
 * This header exposes internal struct definitions to source files
 * while keeping them opaque to public API users.
 */

#ifndef MTLS_INTERNAL_H
#define MTLS_INTERNAL_H

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include "mtls/mtls_config.h"
#include "platform.h"
#include <stdatomic.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Internal context structure
 */
struct mtls_ctx {
    mtls_config config;
    void* tls_ctx;              /* SSL_CTX from OpenSSL/BoringSSL */
    atomic_bool kill_switch_enabled;  /* Thread-safe kill switch */
    mtls_observers observers;

    /* Ownership of dynamic strings */
    char* ca_cert_path;
    char* cert_path;
    char* key_path;
    char* crl_path;
    char** allowed_sans;
};

/*
 * Internal connection structure
 */
struct mtls_conn {
    mtls_ctx* ctx;
    mtls_socket_t sock;
    SSL* ssl;
    mtls_conn_state state;
    mtls_addr remote_addr;
    mtls_addr local_addr;
    bool is_server;
};

/*
 * Internal listener structure
 */
struct mtls_listener {
    mtls_ctx* ctx;
    mtls_socket_t sock;
    mtls_addr bind_addr;
};

/* Forward declarations for TLS functions (implemented in mtls_tls.c) */
void* mtls_tls_ctx_create(const mtls_config* config, mtls_err* err);
void mtls_tls_ctx_free(void* tls_ctx);
int mtls_tls_ctx_reload_certs(void* tls_ctx, const mtls_config* config, mtls_err* err);
SSL_CTX* mtls_tls_get_ssl_ctx(void* tls_ctx);

/* Forward declarations for identity validation helpers (implemented in mtls_identity.c) */
bool mtls_validate_peer_sans(const mtls_peer_identity* identity,
                              const char** allowed_sans,
                              size_t allowed_sans_count);
bool mtls_is_peer_cert_valid(const mtls_peer_identity* identity);
int64_t mtls_get_cert_ttl_seconds(const mtls_peer_identity* identity);
bool mtls_has_spiffe_id(const mtls_peer_identity* identity);
int mtls_get_peer_organization(mtls_conn* conn, char* org_buf, size_t org_buf_len);
int mtls_get_peer_org_unit(mtls_conn* conn, char* ou_buf, size_t ou_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_INTERNAL_H */
