/**
 * @file mtls_pool.h
 * @brief Connection pooling for mTLS connections
 *
 * This module provides connection pooling capabilities to reduce the overhead
 * of establishing new TLS connections. Pools maintain a set of pre-established
 * connections that can be acquired and released efficiently.
 *
 * Features:
 * - Configurable min/max connection limits
 * - Idle connection timeout and cleanup
 * - Maximum connection lifetime enforcement
 * - Health checking with automatic reconnection
 * - Thread-safe acquire/release operations
 * - Connection warmup (pre-connect) support
 *
 * Example usage:
 * @code
 * mtls_pool_config config;
 * mtls_pool_config_init(&config);
 * config.min_connections = 2;
 * config.max_connections = 10;
 * config.idle_timeout_ms = 300000;     // 5 minutes
 * config.max_lifetime_ms = 3600000;    // 1 hour
 * config.acquire_timeout_ms = 30000;   // 30 seconds
 * config.health_check_interval_ms = 30000;
 * config.pre_connect = true;
 *
 * mtls_pool *pool;
 * if (mtls_pool_create(&pool, ctx, "server.example.com:8443", &config, &err) == 0) {
 *     mtls_conn *conn = mtls_pool_acquire(pool, 5000, &err);
 *     if (conn) {
 *         // Use connection...
 *         mtls_pool_release(pool, conn);
 *     }
 *     mtls_pool_destroy(pool);
 * }
 * @endcode
 */

#ifndef MTLS_POOL_H
#define MTLS_POOL_H

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
 * Forward Declarations
 * =============================================================================
 */

struct mtls_ctx;
struct mtls_conn;

/*
 * =============================================================================
 * Connection Pool Types and Constants
 * =============================================================================
 */

/**
 * Connection pool constants
 */
enum {
    /** Default minimum connections */
    MTLS_POOL_DEFAULT_MIN_CONNECTIONS = 1,
    /** Default maximum connections */
    MTLS_POOL_DEFAULT_MAX_CONNECTIONS = 10,
    /** Default idle timeout in milliseconds (5 minutes) */
    MTLS_POOL_DEFAULT_IDLE_TIMEOUT_MS = 300000,
    /** Default maximum lifetime in milliseconds (1 hour) */
    MTLS_POOL_DEFAULT_MAX_LIFETIME_MS = 3600000,
    /** Default acquire timeout in milliseconds (30 seconds) */
    MTLS_POOL_DEFAULT_ACQUIRE_TIMEOUT_MS = 30000,
    /** Default health check interval in milliseconds (30 seconds) */
    MTLS_POOL_DEFAULT_HEALTH_CHECK_INTERVAL_MS = 30000,
    /** Maximum address length */
    MTLS_POOL_MAX_ADDR_LEN = 256
};

/**
 * Connection state within the pool
 */
typedef enum mtls_pooled_conn_state {
    MTLS_POOLED_CONN_IDLE = 0,     /**< Connection is idle in pool */
    MTLS_POOLED_CONN_IN_USE = 1,   /**< Connection is acquired by client */
    MTLS_POOLED_CONN_CLOSED = 2,   /**< Connection has been closed */
    MTLS_POOLED_CONN_UNHEALTHY = 3 /**< Connection failed health check */
} mtls_pooled_conn_state;

/**
 * Pool state
 */
typedef enum mtls_pool_state {
    MTLS_POOL_STATE_RUNNING = 0, /**< Pool is active and accepting requests */
    MTLS_POOL_STATE_CLOSING = 1, /**< Pool is closing, rejecting new acquires */
    MTLS_POOL_STATE_CLOSED = 2   /**< Pool is fully closed */
} mtls_pool_state;

/**
 * Connection pool configuration
 */
typedef struct mtls_pool_config {
    size_t min_connections;            /**< Minimum connections to maintain */
    size_t max_connections;            /**< Maximum connections allowed */
    uint32_t idle_timeout_ms;          /**< Close idle connections after this time */
    uint32_t max_lifetime_ms;          /**< Close connections after this lifetime */
    uint32_t acquire_timeout_ms;       /**< Timeout for acquiring a connection */
    uint32_t health_check_interval_ms; /**< Interval between health checks */
    bool pre_connect;                  /**< Create min_connections on pool creation */
    bool validate_on_acquire;          /**< Validate connection before returning */
    bool validate_on_release;          /**< Validate connection on release */
} mtls_pool_config;

/**
 * Pool statistics
 */
typedef struct mtls_pool_stats {
    size_t total_connections;    /**< Total connections created */
    size_t active_connections;   /**< Connections currently in pool (idle + in_use) */
    size_t idle_connections;     /**< Connections available for use */
    size_t in_use_connections;   /**< Connections currently acquired */
    uint64_t total_acquires;     /**< Total acquire operations */
    uint64_t total_releases;     /**< Total release operations */
    uint64_t acquire_timeouts;   /**< Acquires that timed out */
    uint64_t failed_connects;    /**< Failed connection attempts */
    uint64_t health_checks;      /**< Health checks performed */
    uint64_t unhealthy_closed;   /**< Connections closed due to health check */
    uint64_t idle_closed;        /**< Connections closed due to idle timeout */
    uint64_t lifetime_closed;    /**< Connections closed due to max lifetime */
    uint64_t wait_time_total_ms; /**< Total time spent waiting for connections */
    uint64_t wait_time_max_ms;   /**< Maximum wait time for a connection */
} mtls_pool_stats;

/**
 * Opaque connection pool handle
 */
typedef struct mtls_pool mtls_pool;

/*
 * =============================================================================
 * Pool Configuration
 * =============================================================================
 */

/**
 * Initialize pool configuration with defaults
 *
 * Sets:
 *   - min_connections = 1
 *   - max_connections = 10
 *   - idle_timeout_ms = 300000 (5 minutes)
 *   - max_lifetime_ms = 3600000 (1 hour)
 *   - acquire_timeout_ms = 30000 (30 seconds)
 *   - health_check_interval_ms = 30000 (30 seconds)
 *   - pre_connect = false
 *   - validate_on_acquire = true
 *   - validate_on_release = false
 *
 * @param config Configuration to initialize
 */
MTLS_API void mtls_pool_config_init(mtls_pool_config *config);

/**
 * Validate pool configuration
 *
 * @param config Configuration to validate
 * @param err Error structure to populate on failure
 * @return 0 if valid, -1 if invalid
 */
MTLS_API int mtls_pool_config_validate(const mtls_pool_config *config, mtls_err *err);

/*
 * =============================================================================
 * Pool Lifecycle
 * =============================================================================
 */

/**
 * Create a new connection pool
 *
 * Creates a pool that manages connections to the specified server address.
 * If pre_connect is enabled, min_connections will be established immediately.
 *
 * @param pool Pointer to receive new pool handle
 * @param ctx mTLS context to use for connections
 * @param addr Server address in "host:port" format
 * @param config Pool configuration (NULL for defaults)
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pool_create(mtls_pool **pool, struct mtls_ctx *ctx, const char *addr,
                              const mtls_pool_config *config, mtls_err *err);

/**
 * Destroy a connection pool
 *
 * Closes all connections and frees resources. Any connections still
 * in use will be force-closed.
 *
 * @param pool Pool to destroy (safe to call with NULL)
 */
MTLS_API void mtls_pool_destroy(mtls_pool *pool);

/**
 * Close pool gracefully
 *
 * Marks pool as closing, rejects new acquires, and waits for in-use
 * connections to be released (up to timeout_ms).
 *
 * @param pool Pool to close
 * @param timeout_ms Maximum time to wait for in-use connections
 * @return 0 if all connections released, -1 if timeout
 */
MTLS_API int mtls_pool_close(mtls_pool *pool, uint32_t timeout_ms);

/*
 * =============================================================================
 * Connection Acquisition and Release
 * =============================================================================
 */

/**
 * Acquire a connection from the pool
 *
 * Returns an idle connection if available, or creates a new one if the pool
 * has capacity. If no connections are available, waits up to timeout_ms.
 *
 * @param pool Pool to acquire from
 * @param timeout_ms Maximum time to wait (0 = no wait, UINT32_MAX = infinite)
 * @param err Error structure to populate on failure
 * @return Connection on success, NULL on failure
 */
MTLS_API struct mtls_conn *mtls_pool_acquire(mtls_pool *pool, uint32_t timeout_ms, mtls_err *err);

/**
 * Release a connection back to the pool
 *
 * Returns the connection to the pool for reuse. If the connection is
 * unhealthy or the pool is full, it will be closed instead.
 *
 * @param pool Pool to release to
 * @param conn Connection to release
 * @return 0 on success (returned to pool), 1 if closed, -1 on error
 */
MTLS_API int mtls_pool_release(mtls_pool *pool, struct mtls_conn *conn);

/**
 * Discard a connection (close without returning to pool)
 *
 * Use this when you know the connection is unhealthy or you want to
 * force creation of a new connection next time.
 *
 * @param pool Pool the connection belongs to
 * @param conn Connection to discard
 */
MTLS_API void mtls_pool_discard(mtls_pool *pool, struct mtls_conn *conn);

/*
 * =============================================================================
 * Pool Management
 * =============================================================================
 */

/**
 * Get pool statistics
 *
 * @param pool Pool to query
 * @param stats Output: statistics structure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pool_get_stats(mtls_pool *pool, mtls_pool_stats *stats);

/**
 * Reset pool statistics
 *
 * @param pool Pool to reset
 */
MTLS_API void mtls_pool_reset_stats(mtls_pool *pool);

/**
 * Get current pool state
 *
 * @param pool Pool to query
 * @return Current pool state
 */
MTLS_API mtls_pool_state mtls_pool_get_state(const mtls_pool *pool);

/**
 * Run health check on idle connections
 *
 * Checks all idle connections and closes any that fail. This is called
 * automatically based on health_check_interval_ms.
 *
 * @param pool Pool to check
 * @return Number of unhealthy connections closed
 */
MTLS_API size_t mtls_pool_health_check(mtls_pool *pool);

/**
 * Clean up expired connections
 *
 * Closes connections that have exceeded idle_timeout_ms or max_lifetime_ms.
 *
 * @param pool Pool to clean
 * @return Number of connections closed
 */
MTLS_API size_t mtls_pool_cleanup(mtls_pool *pool);

/**
 * Warm up the pool
 *
 * Ensures at least min_connections are established. Useful after creation
 * if pre_connect was not enabled.
 *
 * @param pool Pool to warm up
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 if unable to establish min_connections
 */
MTLS_API int mtls_pool_warmup(mtls_pool *pool, mtls_err *err);

/**
 * Resize the pool
 *
 * Adjusts min/max connections. If new max is less than current connections,
 * excess connections will be closed as they become idle.
 *
 * @param pool Pool to resize
 * @param min_connections New minimum
 * @param max_connections New maximum
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_pool_resize(mtls_pool *pool, size_t min_connections, size_t max_connections,
                              mtls_err *err);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Get human-readable string for pool state
 *
 * @param state Pool state
 * @return Static string describing the state
 */
MTLS_API const char *mtls_pool_state_string(mtls_pool_state state);

/**
 * Get human-readable string for pooled connection state
 *
 * @param state Pooled connection state
 * @return Static string describing the state
 */
MTLS_API const char *mtls_pooled_conn_state_string(mtls_pooled_conn_state state);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_POOL_H */
