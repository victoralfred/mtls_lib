/**
 * @file mtls_ocsp.h
 * @brief OCSP and CRL certificate revocation checking
 *
 * This header provides functions for checking certificate revocation status
 * using OCSP (Online Certificate Status Protocol) and CRL (Certificate
 * Revocation Lists).
 */

#ifndef MTLS_OCSP_H
#define MTLS_OCSP_H

#include "mtls_types.h"
#include "mtls_error.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct mtls_ctx mtls_ctx;
typedef struct mtls_conn mtls_conn;

/*
 * =============================================================================
 * OCSP Types and Constants
 * =============================================================================
 */

/**
 * OCSP/CRL constants
 */
enum {
    /** Maximum size for OCSP response (1MB) */
    MTLS_OCSP_MAX_RESPONSE_SIZE = 1024 * 1024,
    /** Default OCSP timeout in milliseconds */
    MTLS_OCSP_DEFAULT_TIMEOUT_MS = 5000,
    /** Default CRL refresh interval in seconds (24 hours) */
    MTLS_CRL_DEFAULT_REFRESH_SECONDS = 86400,
    /** Default revocation cache TTL in seconds (1 hour) */
    MTLS_REVOCATION_CACHE_DEFAULT_TTL_SECONDS = 3600,
    /** Default maximum entries in revocation cache */
    MTLS_REVOCATION_CACHE_DEFAULT_MAX_ENTRIES = 10000
};

/**
 * OCSP certificate status
 */
typedef enum mtls_ocsp_status {
    MTLS_OCSP_STATUS_GOOD = 0,    /**< Certificate is valid */
    MTLS_OCSP_STATUS_REVOKED = 1, /**< Certificate has been revoked */
    MTLS_OCSP_STATUS_UNKNOWN = 2, /**< Status could not be determined */
    MTLS_OCSP_STATUS_ERROR = 3    /**< Error occurred during check */
} mtls_ocsp_status;

/**
 * CRL certificate status
 */
typedef enum mtls_crl_status {
    MTLS_CRL_STATUS_GOOD = 0,    /**< Certificate is not in CRL */
    MTLS_CRL_STATUS_REVOKED = 1, /**< Certificate is in CRL */
    MTLS_CRL_STATUS_UNKNOWN = 2, /**< Status could not be determined */
    MTLS_CRL_STATUS_ERROR = 3    /**< Error occurred during check */
} mtls_crl_status;

/**
 * Revocation check result combining OCSP and CRL
 */
typedef struct mtls_revocation_result {
    mtls_ocsp_status ocsp_status; /**< OCSP check result */
    mtls_crl_status crl_status;   /**< CRL check result */
    bool ocsp_checked;            /**< Whether OCSP check was performed */
    bool crl_checked;             /**< Whether CRL check was performed */
    time_t revocation_time;       /**< Time of revocation (if revoked) */
    int revocation_reason;        /**< Revocation reason code */
    time_t ocsp_this_update;      /**< OCSP response thisUpdate time */
    time_t ocsp_next_update;      /**< OCSP response nextUpdate time */
    time_t crl_last_update;       /**< CRL lastUpdate time */
    time_t crl_next_update;       /**< CRL nextUpdate time */
    char responder_url[512];      /**< OCSP responder URL used */
} mtls_revocation_result;

/*
 * =============================================================================
 * Revocation Cache Types
 * =============================================================================
 */

/**
 * Opaque revocation cache handle
 */
typedef struct mtls_revocation_cache mtls_revocation_cache;

/**
 * Cache entry status
 */
typedef struct mtls_cache_stats {
    size_t total_entries; /**< Total entries in cache */
    size_t hits;          /**< Cache hits since creation */
    size_t misses;        /**< Cache misses since creation */
    size_t evictions;     /**< Entries evicted due to capacity */
    size_t expirations;   /**< Entries expired by TTL */
} mtls_cache_stats;

/*
 * =============================================================================
 * OCSP Functions
 * =============================================================================
 */

/**
 * Check certificate revocation status via OCSP
 *
 * Performs an OCSP check for the given certificate against its issuer.
 * If the certificate contains an AIA (Authority Information Access)
 * extension with an OCSP responder URL, that URL is used. Otherwise,
 * the ocsp_url from config is used if provided.
 *
 * @param ctx mTLS context
 * @param cert_pem Certificate to check (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param issuer_pem Issuer certificate (PEM format)
 * @param issuer_pem_len Length of issuer PEM
 * @param result Output structure for result
 * @param err Error structure to populate on failure
 * @return 0 on success (check was performed), -1 on error
 */
MTLS_API int mtls_ocsp_check(mtls_ctx *ctx, const uint8_t *cert_pem, size_t cert_pem_len,
                             const uint8_t *issuer_pem, size_t issuer_pem_len,
                             mtls_revocation_result *result, mtls_err *err);

/**
 * Check certificate revocation status via OCSP with explicit URL
 *
 * @param ocsp_url OCSP responder URL to use
 * @param cert_pem Certificate to check (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param issuer_pem Issuer certificate (PEM format)
 * @param issuer_pem_len Length of issuer PEM
 * @param timeout_ms Timeout in milliseconds (0 = use default)
 * @param result Output structure for result
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_ocsp_check_url(const char *ocsp_url, const uint8_t *cert_pem, size_t cert_pem_len,
                                 const uint8_t *issuer_pem, size_t issuer_pem_len,
                                 uint32_t timeout_ms, mtls_revocation_result *result,
                                 mtls_err *err);

/**
 * Verify an OCSP stapled response
 *
 * Verifies an OCSP response that was stapled during TLS handshake.
 *
 * @param response OCSP response data (DER format)
 * @param response_len Length of response data
 * @param cert_pem Certificate the response is for (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param issuer_pem Issuer certificate (PEM format)
 * @param issuer_pem_len Length of issuer PEM
 * @param result Output structure for result
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_ocsp_verify_stapled(const uint8_t *response, size_t response_len,
                                      const uint8_t *cert_pem, size_t cert_pem_len,
                                      const uint8_t *issuer_pem, size_t issuer_pem_len,
                                      mtls_revocation_result *result, mtls_err *err);

/**
 * Extract OCSP responder URL from certificate
 *
 * Extracts the OCSP responder URL from the certificate's Authority
 * Information Access (AIA) extension.
 *
 * @param cert_pem Certificate (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param url_out Buffer to store URL
 * @param url_out_len Size of URL buffer
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 if no URL found or error
 */
MTLS_API int mtls_ocsp_get_responder_url(const uint8_t *cert_pem, size_t cert_pem_len,
                                         char *url_out, size_t url_out_len, mtls_err *err);

/*
 * =============================================================================
 * CRL Functions
 * =============================================================================
 */

/**
 * Check certificate revocation status via CRL
 *
 * Checks if the certificate has been revoked by consulting CRL data.
 * The CRL can be loaded from a file path (config->crl_path) or
 * downloaded from the certificate's CDP (CRL Distribution Point).
 *
 * @param ctx mTLS context
 * @param cert_pem Certificate to check (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param result Output structure for result
 * @param err Error structure to populate on failure
 * @return 0 on success (check was performed), -1 on error
 */
MTLS_API int mtls_crl_check(mtls_ctx *ctx, const uint8_t *cert_pem, size_t cert_pem_len,
                            mtls_revocation_result *result, mtls_err *err);

/**
 * Check certificate revocation against CRL data
 *
 * @param crl_data CRL data (DER or PEM format)
 * @param crl_data_len Length of CRL data
 * @param cert_pem Certificate to check (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param result Output structure for result
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_crl_check_data(const uint8_t *crl_data, size_t crl_data_len,
                                 const uint8_t *cert_pem, size_t cert_pem_len,
                                 mtls_revocation_result *result, mtls_err *err);

/**
 * Load CRL from file
 *
 * Loads a CRL from a file and stores it in the context for
 * subsequent revocation checks.
 *
 * @param ctx mTLS context
 * @param crl_path Path to CRL file (DER or PEM format)
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_crl_load_file(mtls_ctx *ctx, const char *crl_path, mtls_err *err);

/**
 * Download CRL from URL
 *
 * Downloads a CRL from the specified URL and stores it in the context.
 *
 * @param ctx mTLS context
 * @param crl_url URL to download CRL from
 * @param timeout_ms Timeout in milliseconds (0 = use default)
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_crl_download(mtls_ctx *ctx, const char *crl_url, uint32_t timeout_ms,
                               mtls_err *err);

/**
 * Extract CRL distribution point URLs from certificate
 *
 * @param cert_pem Certificate (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param urls_out Array of URL buffers to fill
 * @param url_buf_len Size of each URL buffer
 * @param max_urls Maximum number of URLs to extract
 * @param num_urls_out Output: number of URLs extracted
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_crl_get_distribution_points(const uint8_t *cert_pem, size_t cert_pem_len,
                                              char (*urls_out)[512], size_t max_urls,
                                              size_t *num_urls_out, mtls_err *err);

/*
 * =============================================================================
 * Combined Revocation Check
 * =============================================================================
 */

/**
 * Check certificate revocation using configured methods
 *
 * Performs revocation checking using all enabled methods (OCSP and/or CRL)
 * according to the context configuration. Results are cached if caching
 * is enabled.
 *
 * @param ctx mTLS context
 * @param cert_pem Certificate to check (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param issuer_pem Issuer certificate (PEM format, can be NULL for CRL-only)
 * @param issuer_pem_len Length of issuer PEM
 * @param result Output structure for combined result
 * @param err Error structure to populate on failure
 * @return 0 on success (certificate is valid), -1 on error or revoked
 */
MTLS_API int mtls_check_revocation(mtls_ctx *ctx, const uint8_t *cert_pem, size_t cert_pem_len,
                                   const uint8_t *issuer_pem, size_t issuer_pem_len,
                                   mtls_revocation_result *result, mtls_err *err);

/*
 * =============================================================================
 * Revocation Cache Functions
 * =============================================================================
 */

/**
 * Create a revocation cache
 *
 * @param cache_out Output: created cache handle
 * @param max_entries Maximum number of entries
 * @param ttl_seconds Entry TTL in seconds
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_revocation_cache_create(mtls_revocation_cache **cache_out, size_t max_entries,
                                          uint32_t ttl_seconds, mtls_err *err);

/**
 * Free a revocation cache
 *
 * @param cache Cache to free (safe to call with NULL)
 */
MTLS_API void mtls_revocation_cache_free(mtls_revocation_cache *cache);

/**
 * Look up a certificate in the cache
 *
 * @param cache Cache handle
 * @param cert_fingerprint SHA-256 fingerprint of certificate (32 bytes)
 * @param result Output: cached result if found
 * @return 0 if found, -1 if not found
 */
MTLS_API int mtls_revocation_cache_get(mtls_revocation_cache *cache,
                                       const uint8_t *cert_fingerprint,
                                       mtls_revocation_result *result);

/**
 * Store a result in the cache
 *
 * @param cache Cache handle
 * @param cert_fingerprint SHA-256 fingerprint of certificate (32 bytes)
 * @param result Result to cache
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_revocation_cache_put(mtls_revocation_cache *cache,
                                       const uint8_t *cert_fingerprint,
                                       const mtls_revocation_result *result);

/**
 * Remove an entry from the cache
 *
 * @param cache Cache handle
 * @param cert_fingerprint SHA-256 fingerprint of certificate (32 bytes)
 * @return 0 on success (removed or not found), -1 on error
 */
MTLS_API int mtls_revocation_cache_remove(mtls_revocation_cache *cache,
                                          const uint8_t *cert_fingerprint);

/**
 * Clear all entries from the cache
 *
 * @param cache Cache handle
 */
MTLS_API void mtls_revocation_cache_clear(mtls_revocation_cache *cache);

/**
 * Get cache statistics
 *
 * @param cache Cache handle
 * @param stats Output: cache statistics
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_revocation_cache_stats(mtls_revocation_cache *cache, mtls_cache_stats *stats);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Compute SHA-256 fingerprint of certificate
 *
 * @param cert_pem Certificate (PEM format)
 * @param cert_pem_len Length of certificate PEM
 * @param fingerprint_out Output buffer (must be at least 32 bytes)
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on error
 */
MTLS_API int mtls_cert_fingerprint(const uint8_t *cert_pem, size_t cert_pem_len,
                                   uint8_t *fingerprint_out, mtls_err *err);

/**
 * Get human-readable string for OCSP status
 *
 * @param status OCSP status
 * @return Static string describing the status
 */
MTLS_API const char *mtls_ocsp_status_string(mtls_ocsp_status status);

/**
 * Get human-readable string for CRL status
 *
 * @param status CRL status
 * @return Static string describing the status
 */
MTLS_API const char *mtls_crl_status_string(mtls_crl_status status);

/**
 * Get human-readable string for revocation reason
 *
 * @param reason Revocation reason code (CRL reason code)
 * @return Static string describing the reason
 */
MTLS_API const char *mtls_revocation_reason_string(int reason);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_OCSP_H */
