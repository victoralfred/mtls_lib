/**
 * @file mtls_pinning.h
 * @brief Certificate pinning for enhanced security
 *
 * This header provides functions for certificate pinning, which allows
 * clients to verify that server certificates match expected values,
 * providing protection against MITM attacks even with compromised CAs.
 *
 * Supports two types of pins:
 * - SPKI (Subject Public Key Info) SHA-256 hashes (recommended)
 * - Certificate SHA-256 hashes
 */

#ifndef MTLS_PINNING_H
#define MTLS_PINNING_H

#include "mtls_types.h"
#include "mtls_error.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct mtls_ctx mtls_ctx;
typedef struct mtls_conn mtls_conn;

/*
 * =============================================================================
 * Pinning Types and Constants
 * =============================================================================
 */

/**
 * Pinning constants
 */
enum {
    /** Maximum number of pins per type */
    MTLS_PIN_MAX_PINS = 64,
    /** SHA-256 hash size in bytes */
    MTLS_PIN_SHA256_SIZE = 32,
    /** Base64-encoded SHA-256 hash size (including null terminator) */
    MTLS_PIN_SHA256_BASE64_SIZE = 45
};

/**
 * Pin type enumeration
 */
typedef enum mtls_pin_type {
    MTLS_PIN_TYPE_SPKI_SHA256 = 1, /**< SPKI (Subject Public Key Info) hash */
    MTLS_PIN_TYPE_CERT_SHA256 = 2  /**< Full certificate hash */
} mtls_pin_type;

/**
 * Pin validation result
 */
typedef enum mtls_pin_result {
    MTLS_PIN_RESULT_MATCH = 0,       /**< Pin matched successfully */
    MTLS_PIN_RESULT_NO_MATCH = 1,    /**< No matching pin found */
    MTLS_PIN_RESULT_INVALID_PIN = 2, /**< Pin format is invalid */
    MTLS_PIN_RESULT_ERROR = 3        /**< Error computing pin */
} mtls_pin_result;

/**
 * Pin set structure for holding multiple pins
 */
typedef struct mtls_pin_set {
    char spki_sha256_pins[MTLS_PIN_MAX_PINS][MTLS_PIN_SHA256_BASE64_SIZE];
    size_t spki_sha256_count;
    char cert_sha256_pins[MTLS_PIN_MAX_PINS][MTLS_PIN_SHA256_BASE64_SIZE];
    size_t cert_sha256_count;
    bool require_match;     /**< If true, validation fails when no match */
    bool include_leaf_only; /**< If true, only check leaf certificate */
} mtls_pin_set;

/**
 * Pin validation report for diagnostics
 */
typedef struct mtls_pin_report {
    mtls_pin_result result;
    mtls_pin_type matched_type;                       /**< Type of pin that matched */
    char matched_pin[MTLS_PIN_SHA256_BASE64_SIZE];    /**< The pin that matched */
    char cert_spki_hash[MTLS_PIN_SHA256_BASE64_SIZE]; /**< Computed SPKI hash */
    char cert_hash[MTLS_PIN_SHA256_BASE64_SIZE];      /**< Computed cert hash */
    int cert_index;                                   /**< Index in chain (0=leaf) */
} mtls_pin_report;

/*
 * =============================================================================
 * Pin Set Management
 * =============================================================================
 */

/**
 * Initialize a pin set with default values
 *
 * Sets:
 *   - require_match = true
 *   - include_leaf_only = false (check entire chain)
 *   - All pin counts to 0
 *
 * @param set Pin set to initialize
 */
MTLS_API void mtls_pin_set_init(mtls_pin_set *set);

/**
 * Add an SPKI SHA-256 pin to the set
 *
 * SPKI pins are the recommended pin type as they survive certificate
 * renewal while the same key pair is used.
 *
 * @param set Pin set to add to
 * @param base64_hash Base64-encoded SHA-256 hash of the SPKI
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pin_set_add_spki_sha256(mtls_pin_set *set, const char *base64_hash,
                                          mtls_err *err);

/**
 * Add a certificate SHA-256 pin to the set
 *
 * Certificate pins are more restrictive as they require exact certificate
 * match, meaning they must be updated when certificates are renewed.
 *
 * @param set Pin set to add to
 * @param base64_hash Base64-encoded SHA-256 hash of the DER-encoded certificate
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pin_set_add_cert_sha256(mtls_pin_set *set, const char *base64_hash,
                                          mtls_err *err);

/**
 * Clear all pins from a set
 *
 * @param set Pin set to clear
 */
MTLS_API void mtls_pin_set_clear(mtls_pin_set *set);

/**
 * Get the total number of pins in a set
 *
 * @param set Pin set to query
 * @return Total number of pins (SPKI + cert)
 */
MTLS_API size_t mtls_pin_set_count(const mtls_pin_set *set);

/*
 * =============================================================================
 * Pin Validation
 * =============================================================================
 */

/**
 * Validate a connection against a pin set
 *
 * Checks the peer certificate (and optionally the entire chain) against
 * the configured pins. Both SPKI and certificate hash pins are checked.
 *
 * @param conn Connection to validate
 * @param set Pin set to validate against
 * @param err Error structure to populate on failure
 * @return 0 if validation passes, -1 if validation fails
 */
MTLS_API int mtls_pin_validate_conn(mtls_conn *conn, const mtls_pin_set *set, mtls_err *err);

/**
 * Validate a connection and get a detailed report
 *
 * Same as mtls_pin_validate_conn but provides additional information
 * about which pin matched or why validation failed.
 *
 * @param conn Connection to validate
 * @param set Pin set to validate against
 * @param report Report structure to populate
 * @param err Error structure to populate on failure
 * @return 0 if validation passes, -1 if validation fails
 */
MTLS_API int mtls_pin_validate_conn_report(mtls_conn *conn, const mtls_pin_set *set,
                                           mtls_pin_report *report, mtls_err *err);

/**
 * Validate a PEM-encoded certificate against a pin set
 *
 * Useful for validating certificates before establishing a connection.
 *
 * @param cert_pem PEM-encoded certificate data
 * @param cert_pem_len Length of the PEM data
 * @param set Pin set to validate against
 * @param err Error structure to populate on failure
 * @return 0 if validation passes, -1 if validation fails
 */
MTLS_API int mtls_pin_validate_cert(const uint8_t *cert_pem, size_t cert_pem_len,
                                    const mtls_pin_set *set, mtls_err *err);

/*
 * =============================================================================
 * Pin Computation
 * =============================================================================
 */

/**
 * Compute SPKI SHA-256 hash for a PEM-encoded certificate
 *
 * The SPKI hash is computed over the DER-encoded SubjectPublicKeyInfo
 * structure, which includes the public key and algorithm identifier.
 *
 * @param cert_pem PEM-encoded certificate
 * @param cert_pem_len Length of the PEM data
 * @param base64_out Buffer for base64-encoded hash (at least MTLS_PIN_SHA256_BASE64_SIZE)
 * @param len Size of output buffer
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pin_compute_spki_hash(const uint8_t *cert_pem, size_t cert_pem_len,
                                        char *base64_out, size_t len, mtls_err *err);

/**
 * Compute certificate SHA-256 hash for a PEM-encoded certificate
 *
 * The certificate hash is computed over the entire DER-encoded certificate.
 *
 * @param cert_pem PEM-encoded certificate
 * @param cert_pem_len Length of the PEM data
 * @param base64_out Buffer for base64-encoded hash (at least MTLS_PIN_SHA256_BASE64_SIZE)
 * @param len Size of output buffer
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pin_compute_cert_hash(const uint8_t *cert_pem, size_t cert_pem_len,
                                        char *base64_out, size_t len, mtls_err *err);

/**
 * Compute SPKI SHA-256 hash for a connection's peer certificate
 *
 * @param conn Connection with established peer certificate
 * @param base64_out Buffer for base64-encoded hash
 * @param len Size of output buffer
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pin_compute_conn_spki_hash(mtls_conn *conn, char *base64_out, size_t len,
                                             mtls_err *err);

/**
 * Compute certificate SHA-256 hash for a connection's peer certificate
 *
 * @param conn Connection with established peer certificate
 * @param base64_out Buffer for base64-encoded hash
 * @param len Size of output buffer
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pin_compute_conn_cert_hash(mtls_conn *conn, char *base64_out, size_t len,
                                             mtls_err *err);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Get human-readable string for pin result
 *
 * @param result Pin validation result
 * @return Static string describing the result
 */
MTLS_API const char *mtls_pin_result_string(mtls_pin_result result);

/**
 * Get human-readable string for pin type
 *
 * @param type Pin type
 * @return Static string describing the type
 */
MTLS_API const char *mtls_pin_type_string(mtls_pin_type type);

/**
 * Validate a base64-encoded SHA-256 hash format
 *
 * Checks that the hash:
 * - Has correct length (43-44 characters)
 * - Contains only valid base64 characters
 * - Decodes to exactly 32 bytes
 *
 * @param base64_hash Hash to validate
 * @return true if valid, false otherwise
 */
MTLS_API bool mtls_pin_validate_hash_format(const char *base64_hash);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_PINNING_H */
