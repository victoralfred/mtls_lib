/**
 * @file mtls_rate_limit.h
 * @brief Rate limiting for mTLS connections
 *
 * This module provides rate limiting capabilities to protect against
 * connection flooding and DoS attacks. It implements a token bucket
 * algorithm with support for both global and per-client limits.
 *
 * Features:
 * - Global connection rate limiting
 * - Per-client rate limiting (by IP or certificate CN)
 * - Token bucket algorithm with burst support
 * - Thread-safe implementation
 *
 * Example usage:
 * @code
 * mtls_config config;
 * mtls_config_init(&config);
 * config.rate_limit_enabled = true;
 * config.rate_limit_max_conn_per_sec = 100;    // 100 conn/sec global
 * config.rate_limit_per_client = 10;           // 10 conn/sec per client
 * config.rate_limit_burst_size = 20;           // Allow burst of 20
 * config.rate_limit_by_ip = true;              // Track by IP address
 * @endcode
 */

#ifndef MTLS_RATE_LIMIT_H
#define MTLS_RATE_LIMIT_H

#include "mtls_error.h"
#include "mtls_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * Rate Limiting Types and Constants
 * =============================================================================
 */

/**
 * Rate limiting constants
 */
enum {
    /** Maximum number of per-client buckets */
    MTLS_RATE_LIMIT_MAX_CLIENTS = 65536,
    /** Default bucket cleanup interval in seconds */
    MTLS_RATE_LIMIT_CLEANUP_INTERVAL_SEC = 60,
    /** Default client bucket expiry in seconds */
    MTLS_RATE_LIMIT_CLIENT_EXPIRY_SEC = 300,
    /** Maximum client ID length */
    MTLS_RATE_LIMIT_MAX_CLIENT_ID_LEN = 256
};

/**
 * Rate limit status
 */
typedef enum mtls_rate_limit_status {
    MTLS_RATE_LIMIT_OK = 0,              /**< Request allowed */
    MTLS_RATE_LIMIT_EXCEEDED = 1,        /**< Rate limit exceeded */
    MTLS_RATE_LIMIT_GLOBAL_EXCEEDED = 2, /**< Global limit exceeded */
    MTLS_RATE_LIMIT_CLIENT_EXCEEDED = 3  /**< Per-client limit exceeded */
} mtls_rate_limit_status;

/**
 * Rate limiter configuration
 */
typedef struct mtls_rate_limit_config {
    bool enabled;                  /**< Enable rate limiting */
    uint64_t max_conn_per_sec;     /**< Global rate limit (0 = unlimited) */
    uint64_t per_client_rate;      /**< Per-client rate limit (0 = unlimited) */
    uint64_t burst_size;           /**< Global burst allowance */
    uint64_t per_client_burst;     /**< Per-client burst allowance */
    bool limit_by_ip;              /**< Use IP address as client ID */
    bool limit_by_cn;              /**< Use certificate CN as client ID */
    uint32_t cleanup_interval_sec; /**< Interval for cleaning expired buckets */
    uint32_t client_expiry_sec;    /**< Time before client bucket expires */
} mtls_rate_limit_config;

/**
 * Token bucket structure (internal)
 */
typedef struct mtls_token_bucket {
    uint64_t tokens;         /**< Current token count (fixed-point) */
    uint64_t max_tokens;     /**< Maximum tokens (burst size) */
    uint64_t refill_rate;    /**< Tokens per second (fixed-point) */
    uint64_t last_refill_us; /**< Last refill timestamp (microseconds) */
} mtls_token_bucket;

/**
 * Rate limiter statistics
 */
typedef struct mtls_rate_limit_stats {
    uint64_t total_requests;    /**< Total requests processed */
    uint64_t allowed_requests;  /**< Requests that were allowed */
    uint64_t rejected_requests; /**< Requests that were rejected */
    uint64_t global_rejections; /**< Rejections due to global limit */
    uint64_t client_rejections; /**< Rejections due to per-client limit */
    size_t active_clients;      /**< Number of active client buckets */
    uint64_t tokens_available;  /**< Current global tokens available */
} mtls_rate_limit_stats;

/**
 * Opaque rate limiter handle
 */
typedef struct mtls_rate_limiter mtls_rate_limiter;

/*
 * =============================================================================
 * Rate Limiter Management
 * =============================================================================
 */

/**
 * Initialize rate limiter configuration with defaults
 *
 * Sets:
 *   - enabled = false
 *   - max_conn_per_sec = 0 (unlimited)
 *   - per_client_rate = 0 (unlimited)
 *   - burst_size = 10
 *   - per_client_burst = 5
 *   - limit_by_ip = true
 *   - limit_by_cn = false
 *   - cleanup_interval_sec = 60
 *   - client_expiry_sec = 300
 *
 * @param config Configuration to initialize
 */
MTLS_API void mtls_rate_limit_config_init(mtls_rate_limit_config *config);

/**
 * Create a new rate limiter
 *
 * @param limiter Pointer to receive new limiter handle
 * @param config Rate limiter configuration
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_rate_limiter_create(mtls_rate_limiter **limiter,
                                      const mtls_rate_limit_config *config, mtls_err *err);

/**
 * Free a rate limiter
 *
 * @param limiter Rate limiter to free (safe to call with NULL)
 */
MTLS_API void mtls_rate_limiter_free(mtls_rate_limiter *limiter);

/**
 * Update rate limiter configuration
 *
 * Can be called at runtime to adjust limits without recreating the limiter.
 *
 * @param limiter Rate limiter handle
 * @param config New configuration
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_rate_limiter_update_config(mtls_rate_limiter *limiter,
                                             const mtls_rate_limit_config *config, mtls_err *err);

/*
 * =============================================================================
 * Rate Limiting Operations
 * =============================================================================
 */

/**
 * Try to acquire a token (check rate limit)
 *
 * This is the main rate limiting function. It attempts to acquire a token
 * from both the global bucket and the per-client bucket (if configured).
 *
 * @param limiter Rate limiter handle
 * @param client_id Client identifier (IP address or CN, depending on config)
 * @param err Error structure to populate on failure
 * @return 0 if allowed, -1 if rate limited (error set to appropriate code)
 */
MTLS_API int mtls_rate_limiter_acquire(mtls_rate_limiter *limiter, const char *client_id,
                                       mtls_err *err);

/**
 * Check rate limit status without consuming a token
 *
 * @param limiter Rate limiter handle
 * @param client_id Client identifier (can be NULL for global only)
 * @return Rate limit status
 */
MTLS_API mtls_rate_limit_status mtls_rate_limiter_check(mtls_rate_limiter *limiter,
                                                        const char *client_id);

/**
 * Get current token status
 *
 * Returns the number of tokens available and time until next refill.
 *
 * @param limiter Rate limiter handle
 * @param client_id Client identifier (NULL for global bucket)
 * @param tokens_out Output: current tokens available (can be NULL)
 * @param next_refill_ms_out Output: ms until next token (can be NULL)
 * @return 0 on success, -1 if client not found
 */
MTLS_API int mtls_rate_limiter_status(mtls_rate_limiter *limiter, const char *client_id,
                                      uint64_t *tokens_out, uint64_t *next_refill_ms_out);

/**
 * Reset rate limiter (clear all buckets)
 *
 * @param limiter Rate limiter handle
 */
MTLS_API void mtls_rate_limiter_reset(mtls_rate_limiter *limiter);

/**
 * Remove a specific client's bucket
 *
 * @param limiter Rate limiter handle
 * @param client_id Client identifier to remove
 * @return 0 on success, -1 if not found
 */
MTLS_API int mtls_rate_limiter_remove_client(mtls_rate_limiter *limiter, const char *client_id);

/**
 * Clean up expired client buckets
 *
 * This is called automatically based on cleanup_interval_sec, but can
 * also be called manually.
 *
 * @param limiter Rate limiter handle
 * @return Number of buckets removed
 */
MTLS_API size_t mtls_rate_limiter_cleanup(mtls_rate_limiter *limiter);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * Get rate limiter statistics
 *
 * @param limiter Rate limiter handle
 * @param stats Output: statistics structure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_rate_limiter_stats(mtls_rate_limiter *limiter, mtls_rate_limit_stats *stats);

/**
 * Reset rate limiter statistics
 *
 * @param limiter Rate limiter handle
 */
MTLS_API void mtls_rate_limiter_reset_stats(mtls_rate_limiter *limiter);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Get human-readable string for rate limit status
 *
 * @param status Rate limit status
 * @return Static string describing the status
 */
MTLS_API const char *mtls_rate_limit_status_string(mtls_rate_limit_status status);

/**
 * Estimate wait time until a token is available
 *
 * @param limiter Rate limiter handle
 * @param client_id Client identifier (NULL for global only)
 * @return Estimated wait time in milliseconds (0 if token available)
 */
MTLS_API uint64_t mtls_rate_limiter_wait_time(mtls_rate_limiter *limiter, const char *client_id);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_RATE_LIMIT_H */
