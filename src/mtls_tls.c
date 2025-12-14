/**
 * @file mtls_tls.c
 * @brief BoringSSL/OpenSSL integration
 *
 * This file handles all TLS-specific operations using BoringSSL.
 * It is isolated from the rest of the codebase to make it easier to audit.
 */

#include "mtls/mtls.h"
#include "internal/platform.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* BoringSSL/OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

/*
 * Internal TLS context structure
 */
struct mtls_tls_ctx_internal {
    SSL_CTX* ssl_ctx;
    const mtls_config* config;
};

/*
 * Get SSL error and populate mtls_err
 */
static void set_ssl_error(mtls_err* err, mtls_error_code code, const char* msg) {
    unsigned long ssl_err = ERR_get_error();

    if (err) {
        err->code = code;
        err->ssl_err = ssl_err;

        if (ssl_err != 0) {
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            snprintf(err->message, MTLS_ERR_MESSAGE_SIZE, "%s: %s", msg, err_buf);
        } else {
            snprintf(err->message, MTLS_ERR_MESSAGE_SIZE, "%s", msg);
        }
    }
}

void* mtls_tls_ctx_create(const mtls_config* config, mtls_err* err) {
    /* Initialize OpenSSL (deprecated functions are no-ops in OpenSSL 1.1.0+)
     * For BoringSSL, these may still be needed, but they're safe to call */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

    /* Create SSL context */
    const SSL_METHOD* method = TLS_method();
    SSL_CTX* ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        set_ssl_error(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to create SSL context");
        return NULL;
    }

    /* Set minimum TLS version */
    int min_version = (config->min_tls_version == MTLS_TLS_1_3) ? TLS1_3_VERSION : TLS1_2_VERSION;
    if (!SSL_CTX_set_min_proto_version(ssl_ctx, min_version)) {
        set_ssl_error(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to set minimum TLS version");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    /* Set maximum TLS version if specified */
    if (config->max_tls_version != 0) {
        int max_version = (config->max_tls_version == MTLS_TLS_1_3) ? TLS1_3_VERSION : TLS1_2_VERSION;
        if (!SSL_CTX_set_max_proto_version(ssl_ctx, max_version)) {
            set_ssl_error(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to set maximum TLS version");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
    }

    /* Load CA certificate */
    if (config->ca_cert_pem) {
        /* Check for integer overflow */
        if (config->ca_cert_pem_len > INT_MAX) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "CA certificate PEM too large");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        BIO* bio = BIO_new_mem_buf(config->ca_cert_pem, (int)config->ca_cert_pem_len);
        X509* ca_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!ca_cert) {
            set_ssl_error(err, MTLS_ERR_CA_CERT_PARSE_FAILED, "Failed to parse CA certificate from memory");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }

        X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
        if (!X509_STORE_add_cert(store, ca_cert)) {
            set_ssl_error(err, MTLS_ERR_CA_CERT_PARSE_FAILED, "Failed to add CA certificate to store");
            X509_free(ca_cert);
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        X509_free(ca_cert);
    } else if (config->ca_cert_path) {
        if (!SSL_CTX_load_verify_locations(ssl_ctx, config->ca_cert_path, NULL)) {
            set_ssl_error(err, MTLS_ERR_CA_CERT_NOT_FOUND, "Failed to load CA certificate from file");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
    }

    /* Load client/server certificate and key if provided */
    if (config->cert_pem) {
        /* Check for integer overflow */
        if (config->cert_pem_len > INT_MAX) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Certificate PEM too large");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        BIO* cert_bio = BIO_new_mem_buf(config->cert_pem, (int)config->cert_pem_len);
        X509* cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        BIO_free(cert_bio);

        if (!cert || !SSL_CTX_use_certificate(ssl_ctx, cert)) {
            set_ssl_error(err, MTLS_ERR_CERT_PARSE_FAILED, "Failed to load certificate from memory");
            if (cert) X509_free(cert);
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        X509_free(cert);
    } else if (config->cert_path) {
        if (!SSL_CTX_use_certificate_file(ssl_ctx, config->cert_path, SSL_FILETYPE_PEM)) {
            set_ssl_error(err, MTLS_ERR_CERT_NOT_FOUND, "Failed to load certificate from file");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
    }

    if (config->key_pem) {
        /* Check for integer overflow */
        if (config->key_pem_len > INT_MAX) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Private key PEM too large");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        BIO* key_bio = BIO_new_mem_buf(config->key_pem, (int)config->key_pem_len);
        EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
        BIO_free(key_bio);

        if (!key || !SSL_CTX_use_PrivateKey(ssl_ctx, key)) {
            set_ssl_error(err, MTLS_ERR_KEY_PARSE_FAILED, "Failed to load private key from memory");
            if (key) EVP_PKEY_free(key);
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        EVP_PKEY_free(key);
    } else if (config->key_path) {
        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, config->key_path, SSL_FILETYPE_PEM)) {
            set_ssl_error(err, MTLS_ERR_KEY_NOT_FOUND, "Failed to load private key from file");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
    }

    /* Verify certificate and key match */
    if (config->cert_path || config->cert_pem) {
        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            set_ssl_error(err, MTLS_ERR_CERT_KEY_MISMATCH, "Certificate and private key do not match");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
    }

    /* Set certificate chain verification depth (prevent DoS from long chains) */
    SSL_CTX_set_verify_depth(ssl_ctx, 10);  /* Reasonable limit */

    /* Enable mutual TLS (require client certificates) */
    if (config->require_client_cert) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

    /* Set cipher suites (restrict to secure ciphers) */
    const char* cipher_list = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
                              "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
    if (!SSL_CTX_set_cipher_list(ssl_ctx, cipher_list)) {
        set_ssl_error(err, MTLS_ERR_TLS_INIT_FAILED, "Failed to set cipher list");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    /* Allocate internal context */
    struct mtls_tls_ctx_internal* tls_ctx = calloc(1, sizeof(*tls_ctx));
    if (!tls_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate TLS context");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    tls_ctx->ssl_ctx = ssl_ctx;
    tls_ctx->config = config;

    return tls_ctx;
}

void mtls_tls_ctx_free(void* tls_ctx_ptr) {
    if (!tls_ctx_ptr) return;

    struct mtls_tls_ctx_internal* tls_ctx = (struct mtls_tls_ctx_internal*)tls_ctx_ptr;

    if (tls_ctx->ssl_ctx) {
        SSL_CTX_free(tls_ctx->ssl_ctx);
    }

    platform_secure_zero(tls_ctx, sizeof(*tls_ctx));
    free(tls_ctx);
}

int mtls_tls_ctx_reload_certs(void* tls_ctx_ptr, const mtls_config* config, mtls_err* err) {
    (void)tls_ctx_ptr;
    (void)config;
    MTLS_ERR_SET(err, MTLS_ERR_NOT_IMPLEMENTED, "Certificate reload not yet implemented");
    return -1;
}

SSL_CTX* mtls_tls_get_ssl_ctx(void* tls_ctx_ptr) {
    if (!tls_ctx_ptr) return NULL;
    struct mtls_tls_ctx_internal* tls_ctx = (struct mtls_tls_ctx_internal*)tls_ctx_ptr;
    return tls_ctx->ssl_ctx;
}
