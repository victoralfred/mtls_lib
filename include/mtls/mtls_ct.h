/**
 * @file mtls_ct.h
 * @brief Certificate Transparency (CT) support
 *
 * This header provides functions for Certificate Transparency verification,
 * which ensures that certificates are logged to public append-only logs,
 * providing protection against misissued certificates.
 *
 * Supports:
 * - SCT (Signed Certificate Timestamp) extraction and validation
 * - CT log list management (Chrome/Apple JSON format)
 * - Policy enforcement (minimum SCTs, known logs only)
 * - SCT sources: embedded in certificate, TLS extension, OCSP response
 */

#ifndef MTLS_CT_H
#define MTLS_CT_H

#include "mtls_error.h"
#include "mtls_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct mtls_ctx mtls_ctx;
typedef struct mtls_conn mtls_conn;

/*
 * =============================================================================
 * CT Types and Constants
 * =============================================================================
 */

/**
 * CT constants
 */
enum {
    /** Maximum number of CT logs supported */
    MTLS_CT_MAX_LOGS = 128,
    /** Maximum number of SCTs per certificate */
    MTLS_CT_MAX_SCTS = 16,
    /** CT log ID size (SHA-256 of log public key) */
    MTLS_CT_LOG_ID_SIZE = 32,
    /** CT log ID base64 size (44 chars + null) */
    MTLS_CT_LOG_ID_BASE64_SIZE = 45,
    /** Maximum SCT signature size */
    MTLS_CT_MAX_SIGNATURE_SIZE = 512,
    /** Maximum log description length */
    MTLS_CT_MAX_LOG_DESCRIPTION = 256
};

/**
 * SCT version
 */
typedef enum mtls_sct_version {
    MTLS_SCT_VERSION_V1 = 0 /**< SCT version 1 (RFC 6962) */
} mtls_sct_version;

/**
 * SCT source - where the SCT was obtained from
 */
typedef enum mtls_sct_source {
    MTLS_SCT_SOURCE_EMBEDDED = 1,      /**< Embedded in X.509 certificate */
    MTLS_SCT_SOURCE_TLS_EXTENSION = 2, /**< TLS extension (ServerHello) */
    MTLS_SCT_SOURCE_OCSP = 3           /**< OCSP response extension */
} mtls_sct_source;

/**
 * CT log status
 */
typedef enum mtls_ct_log_status {
    MTLS_CT_LOG_STATUS_UNKNOWN = 0,     /**< Unknown status */
    MTLS_CT_LOG_STATUS_USABLE = 1,      /**< Log is usable for new SCTs */
    MTLS_CT_LOG_STATUS_READONLY = 2,    /**< Log is read-only (no new entries) */
    MTLS_CT_LOG_STATUS_RETIRED = 3,     /**< Log is retired */
    MTLS_CT_LOG_STATUS_DISQUALIFIED = 4 /**< Log has been disqualified */
} mtls_ct_log_status;

/**
 * SCT validation result
 */
typedef enum mtls_sct_validation_result {
    MTLS_SCT_VALID = 0,             /**< SCT is valid */
    MTLS_SCT_INVALID_SIGNATURE = 1, /**< Signature verification failed */
    MTLS_SCT_UNKNOWN_LOG = 2,       /**< Log ID not in known log list */
    MTLS_SCT_INVALID_TIMESTAMP = 3, /**< Timestamp is invalid/future */
    MTLS_SCT_INVALID_VERSION = 4,   /**< Unsupported SCT version */
    MTLS_SCT_PARSE_ERROR = 5,       /**< Failed to parse SCT */
    MTLS_SCT_LOG_DISQUALIFIED = 6   /**< Log was disqualified at SCT time */
} mtls_sct_validation_result;

/**
 * CT validation result (overall)
 */
typedef enum mtls_ct_result {
    MTLS_CT_RESULT_VALID = 0,        /**< CT validation passed */
    MTLS_CT_RESULT_NO_SCTS = 1,      /**< No SCTs found */
    MTLS_CT_RESULT_INSUFFICIENT = 2, /**< Not enough valid SCTs */
    MTLS_CT_RESULT_INVALID = 3,      /**< SCT validation failed */
    MTLS_CT_RESULT_ERROR = 4         /**< Internal error */
} mtls_ct_result;

/**
 * Signed Certificate Timestamp (SCT)
 *
 * Note: Fields ordered for optimal struct padding per clang-analyzer.
 */
typedef struct mtls_sct {
    uint64_t timestamp;                            /**< Milliseconds since epoch */
    size_t signature_len;                          /**< Signature length */
    mtls_sct_version version;                      /**< SCT version */
    mtls_sct_source source;                        /**< Source of SCT */
    mtls_sct_validation_result validation_result;  /**< Validation result */
    uint16_t signature_algorithm;                  /**< Hash + signature algorithm */
    uint8_t log_id[MTLS_CT_LOG_ID_SIZE];           /**< CT log ID */
    uint8_t signature[MTLS_CT_MAX_SIGNATURE_SIZE]; /**< SCT signature */
} mtls_sct;

/**
 * CT log entry
 */
typedef struct mtls_ct_log {
    uint8_t log_id[MTLS_CT_LOG_ID_SIZE];
    char description[MTLS_CT_MAX_LOG_DESCRIPTION];
    uint8_t *public_key_der;
    size_t public_key_der_len;
    mtls_ct_log_status status;
    uint64_t disqualified_at; /**< Timestamp when disqualified (0 if not) */
} mtls_ct_log;

/**
 * CT log list
 */
typedef struct mtls_ct_log_list {
    mtls_ct_log logs[MTLS_CT_MAX_LOGS];
    size_t log_count;
} mtls_ct_log_list;

/**
 * CT validation report
 */
typedef struct mtls_ct_report {
    mtls_ct_result result;
    mtls_sct scts[MTLS_CT_MAX_SCTS];
    size_t sct_count;
    size_t valid_sct_count;
    size_t embedded_sct_count;
    size_t tls_sct_count;
    size_t ocsp_sct_count;
} mtls_ct_report;

/*
 * =============================================================================
 * CT Log List Management
 * =============================================================================
 */

/**
 * Initialize a CT log list with default values
 *
 * @param list Log list to initialize
 */
MTLS_API void mtls_ct_log_list_init(mtls_ct_log_list *list);

/**
 * Load CT logs from a JSON file (Chrome/Apple log list format)
 *
 * Supports the standard CT log list JSON format used by Chrome and Apple:
 * https://www.gstatic.com/ct/log_list/v3/log_list.json
 *
 * @param list Log list to populate
 * @param json_path Path to JSON file
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_log_list_load_file(mtls_ct_log_list *list, const char *json_path,
                                        mtls_err *err);

/**
 * Load CT logs from JSON data in memory
 *
 * @param list Log list to populate
 * @param json_data JSON data
 * @param json_len Length of JSON data
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_log_list_load_json(mtls_ct_log_list *list, const uint8_t *json_data,
                                        size_t json_len, mtls_err *err);

/**
 * Add a single log to the list manually
 *
 * @param list Log list to add to
 * @param log_id 32-byte log ID (SHA-256 of public key)
 * @param description Human-readable description
 * @param public_key_der DER-encoded public key
 * @param public_key_der_len Length of public key
 * @param status Log status
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_log_list_add(mtls_ct_log_list *list, const uint8_t *log_id,
                                  const char *description, const uint8_t *public_key_der,
                                  size_t public_key_der_len, mtls_ct_log_status status,
                                  mtls_err *err);

/**
 * Find a log by its ID
 *
 * @param list Log list to search
 * @param log_id 32-byte log ID to find
 * @return Pointer to log entry, or NULL if not found
 */
MTLS_API const mtls_ct_log *mtls_ct_log_list_find(const mtls_ct_log_list *list,
                                                  const uint8_t *log_id);

/**
 * Get the number of logs in the list
 *
 * @param list Log list to query
 * @return Number of logs
 */
MTLS_API size_t mtls_ct_log_list_count(const mtls_ct_log_list *list);

/**
 * Clear all logs from the list
 *
 * @param list Log list to clear
 */
MTLS_API void mtls_ct_log_list_clear(mtls_ct_log_list *list);

/**
 * Free resources allocated for the log list
 *
 * @param list Log list to free
 */
MTLS_API void mtls_ct_log_list_free(mtls_ct_log_list *list);

/*
 * =============================================================================
 * SCT Extraction
 * =============================================================================
 */

/**
 * Extract SCTs embedded in a certificate (X.509 extension)
 *
 * @param cert_pem PEM-encoded certificate
 * @param cert_pem_len Length of PEM data
 * @param scts Array to store extracted SCTs
 * @param max_scts Maximum number of SCTs to extract
 * @param sct_count Output: number of SCTs extracted
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_extract_scts_from_cert(const uint8_t *cert_pem, size_t cert_pem_len,
                                            mtls_sct *scts, size_t max_scts, size_t *sct_count,
                                            mtls_err *err);

/**
 * Extract SCTs from a connection (all sources)
 *
 * Extracts SCTs from:
 * - Certificate extensions
 * - TLS signed_certificate_timestamp extension
 * - OCSP response extensions
 *
 * @param conn Connection to extract from
 * @param scts Array to store extracted SCTs
 * @param max_scts Maximum number of SCTs to extract
 * @param sct_count Output: number of SCTs extracted
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_extract_scts_from_conn(mtls_conn *conn, mtls_sct *scts, size_t max_scts,
                                            size_t *sct_count, mtls_err *err);

/*
 * =============================================================================
 * SCT Validation
 * =============================================================================
 */

/**
 * Validate a single SCT
 *
 * @param sct SCT to validate
 * @param cert_pem Certificate the SCT applies to (PEM)
 * @param cert_pem_len Length of certificate PEM
 * @param issuer_pem Issuer certificate (PEM, for precert validation)
 * @param issuer_pem_len Length of issuer PEM (0 if not available)
 * @param log_list CT log list to use for validation
 * @param err Error structure to populate on failure
 * @return Validation result
 */
MTLS_API mtls_sct_validation_result mtls_ct_validate_sct(
    mtls_sct *sct, const uint8_t *cert_pem, size_t cert_pem_len, const uint8_t *issuer_pem,
    size_t issuer_pem_len, const mtls_ct_log_list *log_list, mtls_err *err);

/**
 * Validate all SCTs for a certificate
 *
 * @param scts Array of SCTs to validate
 * @param sct_count Number of SCTs
 * @param cert_pem Certificate the SCTs apply to (PEM)
 * @param cert_pem_len Length of certificate PEM
 * @param issuer_pem Issuer certificate (PEM)
 * @param issuer_pem_len Length of issuer PEM
 * @param log_list CT log list to use
 * @param min_valid_scts Minimum number of valid SCTs required
 * @param allow_unknown_logs Allow SCTs from unknown logs
 * @param report Output: detailed validation report
 * @param err Error structure to populate on failure
 * @return CT validation result
 */
MTLS_API mtls_ct_result mtls_ct_validate_scts(mtls_sct *scts, size_t sct_count,
                                              const uint8_t *cert_pem, size_t cert_pem_len,
                                              const uint8_t *issuer_pem, size_t issuer_pem_len,
                                              const mtls_ct_log_list *log_list,
                                              size_t min_valid_scts, bool allow_unknown_logs,
                                              mtls_ct_report *report, mtls_err *err);

/**
 * Validate CT for a connection
 *
 * Convenience function that extracts SCTs and validates them.
 *
 * @param conn Connection to validate
 * @param log_list CT log list to use
 * @param min_valid_scts Minimum number of valid SCTs required
 * @param allow_unknown_logs Allow SCTs from unknown logs
 * @param report Output: detailed validation report (optional, can be NULL)
 * @param err Error structure to populate on failure
 * @return 0 if CT validation passes, -1 if it fails
 */
MTLS_API int mtls_ct_validate_conn(mtls_conn *conn, const mtls_ct_log_list *log_list,
                                   size_t min_valid_scts, bool allow_unknown_logs,
                                   mtls_ct_report *report, mtls_err *err);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Get human-readable string for CT result
 *
 * @param result CT validation result
 * @return Static string describing the result
 */
MTLS_API const char *mtls_ct_result_string(mtls_ct_result result);

/**
 * Get human-readable string for SCT validation result
 *
 * @param result SCT validation result
 * @return Static string describing the result
 */
MTLS_API const char *mtls_sct_validation_result_string(mtls_sct_validation_result result);

/**
 * Get human-readable string for SCT source
 *
 * @param source SCT source
 * @return Static string describing the source
 */
MTLS_API const char *mtls_sct_source_string(mtls_sct_source source);

/**
 * Get human-readable string for CT log status
 *
 * @param status Log status
 * @return Static string describing the status
 */
MTLS_API const char *mtls_ct_log_status_string(mtls_ct_log_status status);

/**
 * Compute CT log ID from a public key
 *
 * The log ID is the SHA-256 hash of the DER-encoded public key.
 *
 * @param public_key_der DER-encoded public key
 * @param public_key_der_len Length of public key
 * @param log_id Output: 32-byte log ID
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_compute_log_id(const uint8_t *public_key_der, size_t public_key_der_len,
                                    uint8_t *log_id, mtls_err *err);

/**
 * Format a log ID as a base64 string
 *
 * @param log_id 32-byte log ID
 * @param base64_out Output buffer (at least 45 bytes)
 * @param len Size of output buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ct_log_id_to_base64(const uint8_t *log_id, char *base64_out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_CT_H */
