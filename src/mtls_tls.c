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

            /* Build error message in parts to avoid truncation warnings */
            size_t msg_len = strlen(msg);
            size_t err_len = strlen(err_buf);
            size_t separator_len = 2;  /* ": " */
            size_t total_needed = msg_len + separator_len + err_len + 1;  /* +1 for null terminator */

            if (total_needed <= MTLS_ERR_MESSAGE_SIZE) {
                /* Everything fits */
                size_t pos = 0;
                memcpy(err->message + pos, msg, msg_len);
                pos += msg_len;
                memcpy(err->message + pos, ": ", separator_len);
                pos += separator_len;
                memcpy(err->message + pos, err_buf, err_len + 1);  /* Include null terminator */
            } else {
                /* Truncate message prefix to fit */
                size_t available_for_msg = MTLS_ERR_MESSAGE_SIZE - separator_len - err_len - 1;
                size_t msg_copy_len = (msg_len < available_for_msg) ? msg_len : available_for_msg;
                size_t pos = 0;
                memcpy(err->message + pos, msg, msg_copy_len);
                pos += msg_copy_len;
                memcpy(err->message + pos, ": ", separator_len);
                pos += separator_len;
                memcpy(err->message + pos, err_buf, err_len + 1);  /* Include null terminator */
            }
        } else {
            /* No SSL error, just copy the message */
            size_t msg_len = strlen(msg);
            if (msg_len >= MTLS_ERR_MESSAGE_SIZE) {
                memcpy(err->message, msg, MTLS_ERR_MESSAGE_SIZE - 1);
                err->message[MTLS_ERR_MESSAGE_SIZE - 1] = '\0';
            } else {
                memcpy(err->message, msg, msg_len + 1);  /* Include null terminator */
            }
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
        /* Validate PEM data length */
        if (config->ca_cert_pem_len == 0 || config->ca_cert_pem_len > 1024 * 1024) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "CA certificate PEM length invalid (max 1MB)");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
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
        /* Validate PEM data length */
        if (config->cert_pem_len == 0 || config->cert_pem_len > 1024 * 1024) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Certificate PEM length invalid (max 1MB)");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
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
        /* Validate PEM data length */
        if (config->key_pem_len == 0 || config->key_pem_len > 1024 * 1024) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Private key PEM length invalid (max 1MB)");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
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
    if (!tls_ctx_ptr || !config) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Invalid context or config for certificate reload");
        return -1;
    }

    struct mtls_tls_ctx_internal* tls_ctx = (struct mtls_tls_ctx_internal*)tls_ctx_ptr;
    SSL_CTX* ssl_ctx = tls_ctx->ssl_ctx;

    /* Reload CA certificate if provided */
    if (config->ca_cert_pem || config->ca_cert_path) {
        /* Create a new certificate store to replace the old one */
        X509_STORE* new_store = X509_STORE_new();
        if (!new_store) {
            set_ssl_error(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to create new certificate store");
            return -1;
        }

        if (config->ca_cert_pem) {
            /* Validate PEM data length */
            if (config->ca_cert_pem_len == 0 || config->ca_cert_pem_len > 1024 * 1024) {
                MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "CA certificate PEM length invalid (max 1MB)");
                X509_STORE_free(new_store);
                return -1;
            }
            if (config->ca_cert_pem_len > INT_MAX) {
                MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "CA certificate PEM too large");
                X509_STORE_free(new_store);
                return -1;
            }

            BIO* bio = BIO_new_mem_buf(config->ca_cert_pem, (int)config->ca_cert_pem_len);
            X509* ca_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            BIO_free(bio);

            if (!ca_cert) {
                set_ssl_error(err, MTLS_ERR_CA_CERT_PARSE_FAILED, "Failed to parse CA certificate from memory");
                X509_STORE_free(new_store);
                return -1;
            }

            if (!X509_STORE_add_cert(new_store, ca_cert)) {
                set_ssl_error(err, MTLS_ERR_CA_CERT_PARSE_FAILED, "Failed to add CA certificate to store");
                X509_free(ca_cert);
                X509_STORE_free(new_store);
                return -1;
            }
            X509_free(ca_cert);
        } else if (config->ca_cert_path) {
            /* Load CA from file into the new store */
            if (!X509_STORE_load_locations(new_store, config->ca_cert_path, NULL)) {
                set_ssl_error(err, MTLS_ERR_CA_CERT_NOT_FOUND, "Failed to load CA certificate from file");
                X509_STORE_free(new_store);
                return -1;
            }
        }

        /* Replace the SSL_CTX's certificate store */
        SSL_CTX_set_cert_store(ssl_ctx, new_store);
    }

    /* Reload client/server certificate if provided */
    if (config->cert_pem) {
        /* Validate PEM data length */
        if (config->cert_pem_len == 0 || config->cert_pem_len > 1024 * 1024) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Certificate PEM length invalid (max 1MB)");
            return -1;
        }
        if (config->cert_pem_len > INT_MAX) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Certificate PEM too large");
            return -1;
        }

        BIO* cert_bio = BIO_new_mem_buf(config->cert_pem, (int)config->cert_pem_len);
        X509* cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        BIO_free(cert_bio);

        if (!cert || !SSL_CTX_use_certificate(ssl_ctx, cert)) {
            set_ssl_error(err, MTLS_ERR_CERT_PARSE_FAILED, "Failed to reload certificate from memory");
            if (cert) X509_free(cert);
            return -1;
        }
        X509_free(cert);
    } else if (config->cert_path) {
        if (!SSL_CTX_use_certificate_file(ssl_ctx, config->cert_path, SSL_FILETYPE_PEM)) {
            set_ssl_error(err, MTLS_ERR_CERT_NOT_FOUND, "Failed to reload certificate from file");
            return -1;
        }
    }

    /* Reload private key if provided */
    if (config->key_pem) {
        /* Validate PEM data length */
        if (config->key_pem_len == 0 || config->key_pem_len > 1024 * 1024) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Private key PEM length invalid (max 1MB)");
            return -1;
        }
        if (config->key_pem_len > INT_MAX) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Private key PEM too large");
            return -1;
        }

        BIO* key_bio = BIO_new_mem_buf(config->key_pem, (int)config->key_pem_len);
        EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
        BIO_free(key_bio);

        if (!key || !SSL_CTX_use_PrivateKey(ssl_ctx, key)) {
            set_ssl_error(err, MTLS_ERR_KEY_PARSE_FAILED, "Failed to reload private key from memory");
            if (key) EVP_PKEY_free(key);
            return -1;
        }
        EVP_PKEY_free(key);
    } else if (config->key_path) {
        if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, config->key_path, SSL_FILETYPE_PEM)) {
            set_ssl_error(err, MTLS_ERR_KEY_NOT_FOUND, "Failed to reload private key from file");
            return -1;
        }
    }

    /* Verify certificate and key match */
    if (config->cert_path || config->cert_pem) {
        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            set_ssl_error(err, MTLS_ERR_CERT_KEY_MISMATCH, "Reloaded certificate and private key do not match");
            return -1;
        }
    }

    return 0;
}

SSL_CTX* mtls_tls_get_ssl_ctx(void* tls_ctx_ptr) {
    if (!tls_ctx_ptr) return NULL;
    struct mtls_tls_ctx_internal* tls_ctx = (struct mtls_tls_ctx_internal*)tls_ctx_ptr;
    return tls_ctx->ssl_ctx;
}
