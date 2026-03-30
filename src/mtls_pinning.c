/**
 * @file mtls_pinning.c
 * @brief Certificate pinning implementation
 */

// NOLINTBEGIN(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

#include "mtls/mtls_pinning.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_types.h"
#include "internal/mtls_internal.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <string.h>
#include <stdlib.h>

/*
 * =============================================================================
 * Base64 Encoding/Decoding Utilities
 * =============================================================================
 */

/**
 * Base64 encode data
 */
static int base64_encode(const uint8_t *input, size_t input_len, char *output, size_t output_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!bio || !b64) {
        BIO_free_all(bio);
        BIO_free_all(b64);
        return -1;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, (int)input_len);
    BIO_flush(bio);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);

    if (bptr->length >= output_len) {
        BIO_free_all(bio);
        return -1;
    }

    memcpy(output, bptr->data, bptr->length);
    output[bptr->length] = '\0';

    BIO_free_all(bio);
    return 0;
}

/**
 * Base64 decode data
 */
static int base64_decode(const char *input, uint8_t *output, size_t output_len, size_t *decoded_len)
{
    size_t input_len = strlen(input);
    BIO *bio = BIO_new_mem_buf(input, (int)input_len);
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!bio || !b64) {
        BIO_free_all(bio);
        BIO_free_all(b64);
        return -1;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int len = BIO_read(bio, output, (int)output_len);
    BIO_free_all(bio);

    if (len < 0) {
        return -1;
    }

    *decoded_len = (size_t)len;
    return 0;
}

/*
 * =============================================================================
 * Internal Helper Functions
 * =============================================================================
 */

/**
 * Parse a PEM-encoded certificate
 */
static X509 *parse_pem_cert(const uint8_t *pem, size_t pem_len, mtls_err *err)
{
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to create BIO for certificate");
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_PARSE_FAILED, "Failed to parse PEM certificate");
        return NULL;
    }

    return cert;
}

/**
 * Compute SHA-256 hash of SPKI (Subject Public Key Info)
 */
static int compute_spki_sha256(X509 *cert, uint8_t *hash_out, mtls_err *err)
{
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED,
                     "Failed to extract public key from certificate");
        return -1;
    }

    /* Get DER-encoded SPKI */
    unsigned char *spki_der = NULL;
    int spki_len = i2d_PUBKEY(pkey, &spki_der);
    EVP_PKEY_free(pkey);

    if (spki_len <= 0 || !spki_der) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to encode SPKI");
        return -1;
    }

    /* Compute SHA-256 hash */
    unsigned int hash_len = 0;
    if (!EVP_Digest(spki_der, (size_t)spki_len, hash_out, &hash_len, EVP_sha256(), NULL)) {
        OPENSSL_free(spki_der);
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to compute SHA-256 hash");
        return -1;
    }

    OPENSSL_free(spki_der);
    return 0;
}

/**
 * Compute SHA-256 hash of entire certificate
 */
static int compute_cert_sha256(X509 *cert, uint8_t *hash_out, mtls_err *err)
{
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);

    if (der_len <= 0 || !der) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to encode certificate");
        return -1;
    }

    unsigned int hash_len = 0;
    if (!EVP_Digest(der, (size_t)der_len, hash_out, &hash_len, EVP_sha256(), NULL)) {
        OPENSSL_free(der);
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to compute SHA-256 hash");
        return -1;
    }

    OPENSSL_free(der);
    return 0;
}

/**
 * Check if a hash matches any pin in the set
 */
static bool hash_matches_pins(const char *base64_hash,
                              const char pins[][MTLS_PIN_SHA256_BASE64_SIZE], size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(base64_hash, pins[i]) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * =============================================================================
 * Pin Set Management
 * =============================================================================
 */

void mtls_pin_set_init(mtls_pin_set *set)
{
    if (!set) {
        return;
    }
    memset(set, 0, sizeof(*set));
    set->require_match = true;
    set->include_leaf_only = false;
}

int mtls_pin_set_add_spki_sha256(mtls_pin_set *set, const char *base64_hash, mtls_err *err)
{
    if (!set || !base64_hash) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for pin set add");
        return -1;
    }

    if (!mtls_pin_validate_hash_format(base64_hash)) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_INVALID_FORMAT, "Invalid base64 SHA-256 hash format");
        return -1;
    }

    if (set->spki_sha256_count >= MTLS_PIN_MAX_PINS) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Maximum number of SPKI pins reached");
        return -1;
    }

    size_t len = strlen(base64_hash);
    if (len >= MTLS_PIN_SHA256_BASE64_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_INVALID_FORMAT, "Pin hash too long");
        return -1;
    }

    memcpy(set->spki_sha256_pins[set->spki_sha256_count], base64_hash, len + 1);
    set->spki_sha256_count++;
    return 0;
}

int mtls_pin_set_add_cert_sha256(mtls_pin_set *set, const char *base64_hash, mtls_err *err)
{
    if (!set || !base64_hash) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for pin set add");
        return -1;
    }

    if (!mtls_pin_validate_hash_format(base64_hash)) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_INVALID_FORMAT, "Invalid base64 SHA-256 hash format");
        return -1;
    }

    if (set->cert_sha256_count >= MTLS_PIN_MAX_PINS) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Maximum number of certificate pins reached");
        return -1;
    }

    size_t len = strlen(base64_hash);
    if (len >= MTLS_PIN_SHA256_BASE64_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_INVALID_FORMAT, "Pin hash too long");
        return -1;
    }

    memcpy(set->cert_sha256_pins[set->cert_sha256_count], base64_hash, len + 1);
    set->cert_sha256_count++;
    return 0;
}

void mtls_pin_set_clear(mtls_pin_set *set)
{
    if (set) {
        bool require = set->require_match;
        bool leaf = set->include_leaf_only;
        memset(set, 0, sizeof(*set));
        set->require_match = require;
        set->include_leaf_only = leaf;
    }
}

size_t mtls_pin_set_count(const mtls_pin_set *set)
{
    if (!set) {
        return 0;
    }
    return set->spki_sha256_count + set->cert_sha256_count;
}

/*
 * =============================================================================
 * Pin Validation
 * =============================================================================
 */

int mtls_pin_validate_conn(mtls_conn *conn, const mtls_pin_set *set, mtls_err *err)
{
    return mtls_pin_validate_conn_report(conn, set, NULL, err);
}

int mtls_pin_validate_conn_report(mtls_conn *conn, const mtls_pin_set *set, mtls_pin_report *report,
                                  mtls_err *err)
{
    if (!conn || !set) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for pin validation");
        return -1;
    }

    if (report) {
        memset(report, 0, sizeof(*report));
        report->result = MTLS_PIN_RESULT_NO_MATCH;
        report->cert_index = -1;
    }

    /* No pins configured - pass if require_match is false */
    if (mtls_pin_set_count(set) == 0) {
        if (report) {
            report->result = MTLS_PIN_RESULT_MATCH;
        }
        return 0;
    }

    /* Get peer certificate chain */
    SSL *ssl = conn->ssl;
    if (!ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No SSL connection established");
        if (report) {
            report->result = MTLS_PIN_RESULT_ERROR;
        }
        return -1;
    }

    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    X509 *peer_cert = SSL_get_peer_certificate(ssl);

    if (!peer_cert) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No peer certificate available");
        if (report) {
            report->result = MTLS_PIN_RESULT_ERROR;
        }
        return -1;
    }

    /* Determine how many certs to check */
    int max_depth = 1;
    if (!set->include_leaf_only && chain) {
        max_depth = sk_X509_num(chain) + 1;
    }

    bool matched = false;
    char spki_hash[MTLS_PIN_SHA256_BASE64_SIZE];
    char cert_hash[MTLS_PIN_SHA256_BASE64_SIZE];
    uint8_t hash_bytes[MTLS_PIN_SHA256_SIZE];

    for (int i = 0; i < max_depth && !matched; i++) {
        X509 *cert = (i == 0) ? peer_cert : sk_X509_value(chain, i - 1);
        if (!cert) {
            continue;
        }

        /* Compute and check SPKI hash */
        if (set->spki_sha256_count > 0) {
            if (compute_spki_sha256(cert, hash_bytes, err) == 0) {
                if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, spki_hash, sizeof(spki_hash)) ==
                    0) {
                    if (hash_matches_pins(spki_hash, set->spki_sha256_pins,
                                          set->spki_sha256_count)) {
                        matched = true;
                        if (report) {
                            report->result = MTLS_PIN_RESULT_MATCH;
                            report->matched_type = MTLS_PIN_TYPE_SPKI_SHA256;
                            memcpy(report->matched_pin, spki_hash, sizeof(spki_hash));
                            memcpy(report->cert_spki_hash, spki_hash, sizeof(spki_hash));
                            report->cert_index = i;
                        }
                    } else if (report && i == 0) {
                        memcpy(report->cert_spki_hash, spki_hash, sizeof(spki_hash));
                    }
                }
            }
        }

        /* Compute and check certificate hash */
        if (!matched && set->cert_sha256_count > 0) {
            if (compute_cert_sha256(cert, hash_bytes, err) == 0) {
                if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, cert_hash, sizeof(cert_hash)) ==
                    0) {
                    if (hash_matches_pins(cert_hash, set->cert_sha256_pins,
                                          set->cert_sha256_count)) {
                        matched = true;
                        if (report) {
                            report->result = MTLS_PIN_RESULT_MATCH;
                            report->matched_type = MTLS_PIN_TYPE_CERT_SHA256;
                            memcpy(report->matched_pin, cert_hash, sizeof(cert_hash));
                            memcpy(report->cert_hash, cert_hash, sizeof(cert_hash));
                            report->cert_index = i;
                        }
                    } else if (report && i == 0) {
                        memcpy(report->cert_hash, cert_hash, sizeof(cert_hash));
                    }
                }
            }
        }
    }

    X509_free(peer_cert);

    if (!matched && set->require_match) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_VALIDATION_FAILED,
                     "No matching pin found for peer certificate");
        return -1;
    }

    return 0;
}

int mtls_pin_validate_cert(const uint8_t *cert_pem, size_t cert_pem_len, const mtls_pin_set *set,
                           mtls_err *err)
{
    if (!cert_pem || !set) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for pin validation");
        return -1;
    }

    if (mtls_pin_set_count(set) == 0) {
        return 0;
    }

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        return -1;
    }

    bool matched = false;
    uint8_t hash_bytes[MTLS_PIN_SHA256_SIZE];
    char hash_str[MTLS_PIN_SHA256_BASE64_SIZE];

    /* Check SPKI hash */
    if (set->spki_sha256_count > 0) {
        if (compute_spki_sha256(cert, hash_bytes, err) == 0) {
            if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, hash_str, sizeof(hash_str)) == 0) {
                if (hash_matches_pins(hash_str, set->spki_sha256_pins, set->spki_sha256_count)) {
                    matched = true;
                }
            }
        }
    }

    /* Check certificate hash */
    if (!matched && set->cert_sha256_count > 0) {
        if (compute_cert_sha256(cert, hash_bytes, err) == 0) {
            if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, hash_str, sizeof(hash_str)) == 0) {
                if (hash_matches_pins(hash_str, set->cert_sha256_pins, set->cert_sha256_count)) {
                    matched = true;
                }
            }
        }
    }

    X509_free(cert);

    if (!matched && set->require_match) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_VALIDATION_FAILED,
                     "Certificate does not match any configured pin");
        return -1;
    }

    return 0;
}

/*
 * =============================================================================
 * Pin Computation
 * =============================================================================
 */

int mtls_pin_compute_spki_hash(const uint8_t *cert_pem, size_t cert_pem_len, char *base64_out,
                               size_t len, mtls_err *err)
{
    if (!cert_pem || !base64_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for SPKI hash computation");
        return -1;
    }

    if (len < MTLS_PIN_SHA256_BASE64_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Output buffer too small for base64 hash");
        return -1;
    }

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        return -1;
    }

    uint8_t hash_bytes[MTLS_PIN_SHA256_SIZE];
    int ret = compute_spki_sha256(cert, hash_bytes, err);
    X509_free(cert);

    if (ret < 0) {
        return -1;
    }

    if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, base64_out, len) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to base64 encode SPKI hash");
        return -1;
    }

    return 0;
}

int mtls_pin_compute_cert_hash(const uint8_t *cert_pem, size_t cert_pem_len, char *base64_out,
                               size_t len, mtls_err *err)
{
    if (!cert_pem || !base64_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT,
                     "Invalid arguments for certificate hash computation");
        return -1;
    }

    if (len < MTLS_PIN_SHA256_BASE64_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Output buffer too small for base64 hash");
        return -1;
    }

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        return -1;
    }

    uint8_t hash_bytes[MTLS_PIN_SHA256_SIZE];
    int ret = compute_cert_sha256(cert, hash_bytes, err);
    X509_free(cert);

    if (ret < 0) {
        return -1;
    }

    if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, base64_out, len) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to base64 encode certificate hash");
        return -1;
    }

    return 0;
}

int mtls_pin_compute_conn_spki_hash(mtls_conn *conn, char *base64_out, size_t len, mtls_err *err)
{
    if (!conn || !base64_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for connection SPKI hash");
        return -1;
    }

    if (len < MTLS_PIN_SHA256_BASE64_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Output buffer too small for base64 hash");
        return -1;
    }

    SSL *ssl = conn->ssl;
    if (!ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No SSL connection established");
        return -1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No peer certificate available");
        return -1;
    }

    uint8_t hash_bytes[MTLS_PIN_SHA256_SIZE];
    int ret = compute_spki_sha256(cert, hash_bytes, err);
    X509_free(cert);

    if (ret < 0) {
        return -1;
    }

    if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, base64_out, len) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to base64 encode SPKI hash");
        return -1;
    }

    return 0;
}

int mtls_pin_compute_conn_cert_hash(mtls_conn *conn, char *base64_out, size_t len, mtls_err *err)
{
    if (!conn || !base64_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for connection cert hash");
        return -1;
    }

    if (len < MTLS_PIN_SHA256_BASE64_SIZE) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Output buffer too small for base64 hash");
        return -1;
    }

    SSL *ssl = conn->ssl;
    if (!ssl) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No SSL connection established");
        return -1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No peer certificate available");
        return -1;
    }

    uint8_t hash_bytes[MTLS_PIN_SHA256_SIZE];
    int ret = compute_cert_sha256(cert, hash_bytes, err);
    X509_free(cert);

    if (ret < 0) {
        return -1;
    }

    if (base64_encode(hash_bytes, MTLS_PIN_SHA256_SIZE, base64_out, len) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_PIN_COMPUTE_FAILED, "Failed to base64 encode certificate hash");
        return -1;
    }

    return 0;
}

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

const char *mtls_pin_result_string(mtls_pin_result result)
{
    switch (result) {
    case MTLS_PIN_RESULT_MATCH:
        return "match";
    case MTLS_PIN_RESULT_NO_MATCH:
        return "no_match";
    case MTLS_PIN_RESULT_INVALID_PIN:
        return "invalid_pin";
    case MTLS_PIN_RESULT_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

const char *mtls_pin_type_string(mtls_pin_type type)
{
    switch (type) {
    case MTLS_PIN_TYPE_SPKI_SHA256:
        return "spki_sha256";
    case MTLS_PIN_TYPE_CERT_SHA256:
        return "cert_sha256";
    default:
        return "unknown";
    }
}

bool mtls_pin_validate_hash_format(const char *base64_hash)
{
    if (!base64_hash) {
        return false;
    }

    size_t len = strlen(base64_hash);

    /* Base64-encoded SHA-256 should be 43-44 characters (depending on padding) */
    if (len < 43 || len > 44) {
        return false;
    }

    /* Check for valid base64 characters */
    for (size_t i = 0; i < len; i++) {
        char chr = base64_hash[i];
        bool valid = (chr >= 'A' && chr <= 'Z') || (chr >= 'a' && chr <= 'z') ||
                     (chr >= '0' && chr <= '9') || chr == '+' || chr == '/' || chr == '=';
        if (!valid) {
            return false;
        }
    }

    /* Try to decode and verify length */
    uint8_t decoded[64];
    size_t decoded_len = 0;
    if (base64_decode(base64_hash, decoded, sizeof(decoded), &decoded_len) < 0) {
        return false;
    }

    return decoded_len == MTLS_PIN_SHA256_SIZE;
}

// NOLINTEND(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
