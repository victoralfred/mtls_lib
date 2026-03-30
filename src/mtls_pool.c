/**
 * @file mtls_pool.c
 * @brief Connection pool implementation
 */

// NOLINTBEGIN(misc-include-cleaner,bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* Enable POSIX extensions for pthread */
#ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#endif

#include "mtls/mtls_pool.h"
#include "internal/mtls_internal.h"
#include "internal/platform.h"
#include "mtls/mtls.h"
#include "mtls/mtls_error.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/*
 * =============================================================================
 * Internal Types
 * =============================================================================
 */

/**
 * Pooled connection entry
 */
typedef struct pooled_conn {
    struct mtls_conn *conn;       /**< The actual connection */
    mtls_pooled_conn_state state; /**< Current state */
    uint64_t created_us;          /**< When connection was created */
    uint64_t last_used_us;        /**< Last time connection was used */
    uint64_t acquire_time_us;     /**< When current acquire started */
    struct pooled_conn *next;     /**< Next in list */
    struct pooled_conn *prev;     /**< Previous in list */
} pooled_conn;

/**
 * Connection pool structure
 */
struct mtls_pool {
    struct mtls_ctx *ctx;              /**< mTLS context */
    char addr[MTLS_POOL_MAX_ADDR_LEN]; /**< Server address */
    mtls_pool_config config;           /**< Pool configuration */
    mtls_pool_state state;             /**< Current state */

    /* Connection lists */
    pooled_conn *idle_head;   /**< Idle connections list */
    pooled_conn *idle_tail;   /**< Idle connections tail */
    pooled_conn *in_use_head; /**< In-use connections list */
    size_t idle_count;        /**< Number of idle connections */
    size_t in_use_count;      /**< Number of in-use connections */
    size_t total_created;     /**< Total connections created */

    /* Synchronization */
    pthread_mutex_t lock;          /**< Pool lock */
    pthread_cond_t available_cond; /**< Signaled when conn available */

    /* Statistics (atomic for lock-free reads) */
    atomic_uint_fast64_t stats_total_acquires;
    atomic_uint_fast64_t stats_total_releases;
    atomic_uint_fast64_t stats_acquire_timeouts;
    atomic_uint_fast64_t stats_failed_connects;
    atomic_uint_fast64_t stats_health_checks;
    atomic_uint_fast64_t stats_unhealthy_closed;
    atomic_uint_fast64_t stats_idle_closed;
    atomic_uint_fast64_t stats_lifetime_closed;
    atomic_uint_fast64_t stats_wait_time_total_ms;
    atomic_uint_fast64_t stats_wait_time_max_ms;

    /* Cleanup tracking */
    uint64_t last_health_check_us;
    uint64_t last_cleanup_us;
};

/*
 * =============================================================================
 * Internal Helpers
 * =============================================================================
 */

/**
 * Create a new pooled connection entry
 */
static pooled_conn *pooled_conn_create(struct mtls_conn *conn)
{
    pooled_conn *pconn = calloc(1, sizeof(pooled_conn));
    if (!pconn) {
        return NULL;
    }
    pconn->conn = conn;
    pconn->state = MTLS_POOLED_CONN_IDLE;
    pconn->created_us = platform_get_time_us();
    pconn->last_used_us = pconn->created_us;
    return pconn;
}

/**
 * Free a pooled connection entry (and close the underlying connection)
 */
static void pooled_conn_destroy(pooled_conn *pconn)
{
    if (!pconn) {
        return;
    }
    if (pconn->conn) {
        mtls_close(pconn->conn);
    }
    free(pconn);
}

/**
 * Add connection to idle list (at head for LIFO behavior - most recently used first)
 */
static void add_to_idle_list(mtls_pool *pool, pooled_conn *pconn)
{
    pconn->state = MTLS_POOLED_CONN_IDLE;
    pconn->last_used_us = platform_get_time_us();
    pconn->prev = NULL;
    pconn->next = pool->idle_head;

    if (pool->idle_head) {
        pool->idle_head->prev = pconn;
    }
    pool->idle_head = pconn;
    if (!pool->idle_tail) {
        pool->idle_tail = pconn;
    }
    pool->idle_count++;
}

/**
 * Remove connection from idle list
 */
static void remove_from_idle_list(mtls_pool *pool, pooled_conn *pconn)
{
    if (pconn->prev) {
        pconn->prev->next = pconn->next;
    } else {
        pool->idle_head = pconn->next;
    }
    if (pconn->next) {
        pconn->next->prev = pconn->prev;
    } else {
        pool->idle_tail = pconn->prev;
    }
    pconn->prev = NULL;
    pconn->next = NULL;
    pool->idle_count--;
}

/**
 * Add connection to in-use list
 */
static void add_to_in_use_list(mtls_pool *pool, pooled_conn *pconn)
{
    pconn->state = MTLS_POOLED_CONN_IN_USE;
    pconn->acquire_time_us = platform_get_time_us();
    pconn->prev = NULL;
    pconn->next = pool->in_use_head;

    if (pool->in_use_head) {
        pool->in_use_head->prev = pconn;
    }
    pool->in_use_head = pconn;
    pool->in_use_count++;
}

/**
 * Remove connection from in-use list
 */
static void remove_from_in_use_list(mtls_pool *pool, pooled_conn *pconn)
{
    if (pconn->prev) {
        pconn->prev->next = pconn->next;
    } else {
        pool->in_use_head = pconn->next;
    }
    if (pconn->next) {
        pconn->next->prev = pconn->prev;
    }
    pconn->prev = NULL;
    pconn->next = NULL;
    pool->in_use_count--;
}

/**
 * Find pooled_conn by mtls_conn in in-use list
 */
static pooled_conn *find_in_use_conn(mtls_pool *pool, const struct mtls_conn *conn)
{
    for (pooled_conn *pconn = pool->in_use_head; pconn; pconn = pconn->next) {
        if (pconn->conn == conn) {
            return pconn;
        }
    }
    return NULL;
}

/**
 * Check if a connection is still healthy
 */
static bool is_conn_healthy(const pooled_conn *pconn, uint64_t now_us,
                            const mtls_pool_config *config)
{
    if (!pconn || !pconn->conn) {
        return false;
    }

    /* Check connection state */
    mtls_conn_state state = mtls_get_state(pconn->conn);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        return false;
    }

    /* Check max lifetime */
    if (config->max_lifetime_ms > 0) {
        uint64_t age_us = now_us - pconn->created_us;
        if (age_us >= (uint64_t)config->max_lifetime_ms * 1000ULL) {
            return false;
        }
    }

    return true;
}

/**
 * Check if a connection has been idle too long
 */
static bool is_conn_idle_expired(const pooled_conn *pconn, uint64_t now_us,
                                 const mtls_pool_config *config)
{
    if (!pconn || config->idle_timeout_ms == 0) {
        return false;
    }

    uint64_t idle_us = now_us - pconn->last_used_us;
    return idle_us >= (uint64_t)config->idle_timeout_ms * 1000ULL;
}

/**
 * Create a new connection to the pool's target address
 */
static struct mtls_conn *create_new_connection(mtls_pool *pool, mtls_err *err)
{
    struct mtls_conn *conn = mtls_connect(pool->ctx, pool->addr, err);
    if (!conn) {
        atomic_fetch_add(&pool->stats_failed_connects, 1);
        return NULL;
    }
    return conn;
}

/**
 * Emit pool event
 */
static void emit_pool_event(mtls_pool *pool, mtls_event_type type, struct mtls_conn *conn,
                            mtls_error_code error_code)
{
    mtls_event event = {.type = type,
                        .remote_addr = pool->addr,
                        .conn = conn,
                        .error_code = error_code,
                        .timestamp_us = platform_get_time_us(),
                        .duration_us = 0,
                        .bytes = 0};
    mtls_emit_event(pool->ctx, &event);
}

/*
 * =============================================================================
 * Public API - Configuration
 * =============================================================================
 */

void mtls_pool_config_init(mtls_pool_config *config)
{
    if (!config) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->min_connections = MTLS_POOL_DEFAULT_MIN_CONNECTIONS;
    config->max_connections = MTLS_POOL_DEFAULT_MAX_CONNECTIONS;
    config->idle_timeout_ms = MTLS_POOL_DEFAULT_IDLE_TIMEOUT_MS;
    config->max_lifetime_ms = MTLS_POOL_DEFAULT_MAX_LIFETIME_MS;
    config->acquire_timeout_ms = MTLS_POOL_DEFAULT_ACQUIRE_TIMEOUT_MS;
    config->health_check_interval_ms = MTLS_POOL_DEFAULT_HEALTH_CHECK_INTERVAL_MS;
    config->pre_connect = false;
    config->validate_on_acquire = true;
    config->validate_on_release = false;
}

int mtls_pool_config_validate(const mtls_pool_config *config, mtls_err *err)
{
    if (!config) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Configuration is NULL");
        return -1;
    }

    if (config->min_connections > config->max_connections) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "min_connections cannot exceed max_connections");
        return -1;
    }

    if (config->max_connections == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "max_connections must be at least 1");
        return -1;
    }

    return 0;
}

/*
 * =============================================================================
 * Public API - Lifecycle
 * =============================================================================
 */

int mtls_pool_create(mtls_pool **pool_out, struct mtls_ctx *ctx, const char *addr,
                     const mtls_pool_config *config, mtls_err *err)
{
    if (!pool_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Pool output pointer is NULL");
        return -1;
    }
    *pool_out = NULL;

    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return -1;
    }

    if (!addr || strlen(addr) == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Address is NULL or empty");
        return -1;
    }

    if (strlen(addr) >= MTLS_POOL_MAX_ADDR_LEN) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Address too long");
        return -1;
    }

    /* Use defaults if no config provided */
    mtls_pool_config default_config;
    if (!config) {
        mtls_pool_config_init(&default_config);
        config = &default_config;
    }

    /* Validate config */
    if (mtls_pool_config_validate(config, err) < 0) {
        return -1;
    }

    /* Allocate pool */
    mtls_pool *pool = calloc(1, sizeof(mtls_pool));
    if (!pool) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate pool");
        return -1;
    }

    pool->ctx = ctx;
    strncpy(pool->addr, addr, MTLS_POOL_MAX_ADDR_LEN - 1);
    pool->addr[MTLS_POOL_MAX_ADDR_LEN - 1] = '\0';
    pool->config = *config;
    pool->state = MTLS_POOL_STATE_RUNNING;

    /* Initialize synchronization primitives */
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to initialize mutex");
        free(pool);
        return -1;
    }

    if (pthread_cond_init(&pool->available_cond, NULL) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to initialize condition variable");
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return -1;
    }

    /* Pre-connect if requested */
    if (config->pre_connect && config->min_connections > 0) {
        for (size_t i = 0; i < config->min_connections; i++) {
            struct mtls_conn *conn = create_new_connection(pool, err);
            if (!conn) {
                /* Failed to create min connections - clean up and fail */
                mtls_pool_destroy(pool);
                return -1;
            }

            pooled_conn *pconn = pooled_conn_create(conn);
            if (!pconn) {
                mtls_close(conn);
                mtls_pool_destroy(pool);
                MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate pooled connection");
                return -1;
            }

            add_to_idle_list(pool, pconn);
            pool->total_created++;

            emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CREATED, conn, MTLS_OK);
        }
    }

    *pool_out = pool;
    return 0;
}

void mtls_pool_destroy(mtls_pool *pool)
{
    if (!pool) {
        return;
    }

    pthread_mutex_lock(&pool->lock);
    pool->state = MTLS_POOL_STATE_CLOSED;

    /* Close all idle connections */
    pooled_conn *pconn = pool->idle_head;
    while (pconn) {
        pooled_conn *next = pconn->next;
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
        pooled_conn_destroy(pconn);
        pconn = next;
    }
    pool->idle_head = NULL;
    pool->idle_tail = NULL;
    pool->idle_count = 0;

    /* Force close in-use connections */
    pconn = pool->in_use_head;
    while (pconn) {
        pooled_conn *next = pconn->next;
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
        pooled_conn_destroy(pconn);
        pconn = next;
    }
    pool->in_use_head = NULL;
    pool->in_use_count = 0;

    pthread_mutex_unlock(&pool->lock);

    /* Wake up any waiting acquires */
    pthread_cond_broadcast(&pool->available_cond);

    pthread_cond_destroy(&pool->available_cond);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

int mtls_pool_close(mtls_pool *pool, uint32_t timeout_ms)
{
    if (!pool) {
        return -1;
    }

    pthread_mutex_lock(&pool->lock);

    if (pool->state == MTLS_POOL_STATE_CLOSED) {
        pthread_mutex_unlock(&pool->lock);
        return 0;
    }

    pool->state = MTLS_POOL_STATE_CLOSING;

    /* Wake up waiting acquires - they'll get POOL_CLOSED error */
    pthread_cond_broadcast(&pool->available_cond);

    /* Wait for in-use connections to be released */
    if (pool->in_use_count > 0 && timeout_ms > 0) {
        struct timespec timeout_spec;
        clock_gettime(CLOCK_REALTIME, &timeout_spec);
        timeout_spec.tv_sec += timeout_ms / 1000;
        timeout_spec.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (timeout_spec.tv_nsec >= 1000000000) {
            timeout_spec.tv_sec++;
            timeout_spec.tv_nsec -= 1000000000;
        }

        while (pool->in_use_count > 0) {
            int wait_result =
                pthread_cond_timedwait(&pool->available_cond, &pool->lock, &timeout_spec);
            if (wait_result != 0) {
                break; /* Timeout or error */
            }
        }
    }

    int result = (pool->in_use_count == 0) ? 0 : -1;

    /* Close all remaining connections */
    pooled_conn *pconn = pool->idle_head;
    while (pconn) {
        pooled_conn *next = pconn->next;
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
        pooled_conn_destroy(pconn);
        pconn = next;
    }
    pool->idle_head = NULL;
    pool->idle_tail = NULL;
    pool->idle_count = 0;

    pool->state = MTLS_POOL_STATE_CLOSED;
    pthread_mutex_unlock(&pool->lock);

    return result;
}

/*
 * =============================================================================
 * Public API - Acquire/Release
 * =============================================================================
 */

struct mtls_conn *mtls_pool_acquire(mtls_pool *pool, uint32_t timeout_ms, mtls_err *err)
{
    if (!pool) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Pool is NULL");
        return NULL;
    }

    uint64_t start_time = platform_get_time_us();
    atomic_fetch_add(&pool->stats_total_acquires, 1);

    emit_pool_event(pool, MTLS_EVENT_POOL_ACQUIRE_START, NULL, MTLS_OK);

    pthread_mutex_lock(&pool->lock);

    /* Check pool state */
    if (pool->state != MTLS_POOL_STATE_RUNNING) {
        pthread_mutex_unlock(&pool->lock);
        MTLS_ERR_SET(err, MTLS_ERR_POOL_CLOSED, "Pool is closed");
        return NULL;
    }

    struct mtls_conn *result = NULL;
    uint64_t deadline_us =
        (timeout_ms == UINT32_MAX) ? UINT64_MAX : start_time + (uint64_t)timeout_ms * 1000ULL;

    while (!result && pool->state == MTLS_POOL_STATE_RUNNING) {
        uint64_t now = platform_get_time_us();

        /* Try to get an idle connection */
        while (pool->idle_head) {
            pooled_conn *pconn = pool->idle_head;
            remove_from_idle_list(pool, pconn);

            /* Validate connection if configured */
            if (pool->config.validate_on_acquire) {
                if (!is_conn_healthy(pconn, now, &pool->config)) {
                    emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
                    pooled_conn_destroy(pconn);
                    atomic_fetch_add(&pool->stats_unhealthy_closed, 1);
                    continue;
                }
            }

            /* Found a valid connection */
            add_to_in_use_list(pool, pconn);
            result = pconn->conn;
            break;
        }

        if (result) {
            break;
        }

        /* No idle connection - try to create a new one if under limit */
        size_t total_connections = pool->idle_count + pool->in_use_count;
        if (total_connections < pool->config.max_connections) {
            pthread_mutex_unlock(&pool->lock);

            struct mtls_conn *conn = create_new_connection(pool, err);
            if (conn) {
                pooled_conn *pconn = pooled_conn_create(conn);
                if (!pconn) {
                    mtls_close(conn);
                    MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY,
                                 "Failed to allocate pooled connection");
                    return NULL;
                }

                pthread_mutex_lock(&pool->lock);
                pool->total_created++;
                add_to_in_use_list(pool, pconn);
                result = pconn->conn;

                emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CREATED, conn, MTLS_OK);
                break;
            }

            pthread_mutex_lock(&pool->lock);
            /* Connection failed - fall through to wait */
        }

        /* Pool exhausted - wait for a connection to become available */
        if (timeout_ms == 0) {
            pthread_mutex_unlock(&pool->lock);
            atomic_fetch_add(&pool->stats_acquire_timeouts, 1);
            emit_pool_event(pool, MTLS_EVENT_POOL_ACQUIRE_TIMEOUT, NULL, MTLS_ERR_POOL_EXHAUSTED);
            MTLS_ERR_SET(err, MTLS_ERR_POOL_EXHAUSTED, "No connections available");
            return NULL;
        }

        now = platform_get_time_us();
        if (now >= deadline_us) {
            pthread_mutex_unlock(&pool->lock);
            atomic_fetch_add(&pool->stats_acquire_timeouts, 1);
            emit_pool_event(pool, MTLS_EVENT_POOL_ACQUIRE_TIMEOUT, NULL,
                            MTLS_ERR_POOL_ACQUIRE_TIMEOUT);
            MTLS_ERR_SET(err, MTLS_ERR_POOL_ACQUIRE_TIMEOUT, "Acquire timeout");
            return NULL;
        }

        /* Calculate remaining wait time */
        uint64_t remaining_us = deadline_us - now;
        struct timespec timeout_spec;
        clock_gettime(CLOCK_REALTIME, &timeout_spec);
        timeout_spec.tv_sec += (long)(remaining_us / 1000000ULL);
        timeout_spec.tv_nsec += (long)((remaining_us % 1000000ULL) * 1000);
        if (timeout_spec.tv_nsec >= 1000000000) {
            timeout_spec.tv_sec++;
            timeout_spec.tv_nsec -= 1000000000;
        }

        pthread_cond_timedwait(&pool->available_cond, &pool->lock, &timeout_spec);
    }

    pthread_mutex_unlock(&pool->lock);

    if (result) {
        /* Track wait time */
        uint64_t end_time = platform_get_time_us();
        uint64_t wait_ms = (end_time - start_time) / 1000;
        atomic_fetch_add(&pool->stats_wait_time_total_ms, wait_ms);

        /* Update max wait time (non-atomic, but acceptable for stats) */
        uint64_t current_max = atomic_load(&pool->stats_wait_time_max_ms);
        if (wait_ms > current_max) {
            atomic_store(&pool->stats_wait_time_max_ms, wait_ms);
        }

        emit_pool_event(pool, MTLS_EVENT_POOL_ACQUIRE_SUCCESS, result, MTLS_OK);
    }

    return result;
}

int mtls_pool_release(mtls_pool *pool, struct mtls_conn *conn)
{
    if (!pool || !conn) {
        return -1;
    }

    atomic_fetch_add(&pool->stats_total_releases, 1);

    pthread_mutex_lock(&pool->lock);

    /* Find the pooled connection */
    pooled_conn *pconn = find_in_use_conn(pool, conn);
    if (!pconn) {
        pthread_mutex_unlock(&pool->lock);
        return -1; /* Not from this pool */
    }

    remove_from_in_use_list(pool, pconn);

    /* Check if pool is closing or at max capacity */
    if (pool->state != MTLS_POOL_STATE_RUNNING) {
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, conn, MTLS_OK);
        pooled_conn_destroy(pconn);
        pthread_cond_signal(&pool->available_cond);
        pthread_mutex_unlock(&pool->lock);
        return 1; /* Closed */
    }

    /* Validate connection if configured */
    uint64_t now = platform_get_time_us();
    if (pool->config.validate_on_release) {
        if (!is_conn_healthy(pconn, now, &pool->config)) {
            emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, conn, MTLS_OK);
            pooled_conn_destroy(pconn);
            atomic_fetch_add(&pool->stats_unhealthy_closed, 1);
            pthread_cond_signal(&pool->available_cond);
            pthread_mutex_unlock(&pool->lock);
            return 1; /* Closed */
        }
    }

    /* Check max lifetime */
    if (pool->config.max_lifetime_ms > 0) {
        uint64_t age_us = now - pconn->created_us;
        if (age_us >= (uint64_t)pool->config.max_lifetime_ms * 1000ULL) {
            emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, conn, MTLS_OK);
            pooled_conn_destroy(pconn);
            atomic_fetch_add(&pool->stats_lifetime_closed, 1);
            pthread_cond_signal(&pool->available_cond);
            pthread_mutex_unlock(&pool->lock);
            return 1; /* Closed */
        }
    }

    /* Return to idle pool */
    add_to_idle_list(pool, pconn);
    emit_pool_event(pool, MTLS_EVENT_POOL_RELEASE, conn, MTLS_OK);

    pthread_cond_signal(&pool->available_cond);
    pthread_mutex_unlock(&pool->lock);

    return 0;
}

void mtls_pool_discard(mtls_pool *pool, struct mtls_conn *conn)
{
    if (!pool || !conn) {
        return;
    }

    pthread_mutex_lock(&pool->lock);

    pooled_conn *pconn = find_in_use_conn(pool, conn);
    if (pconn) {
        remove_from_in_use_list(pool, pconn);
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, conn, MTLS_OK);
        pooled_conn_destroy(pconn);
        pthread_cond_signal(&pool->available_cond);
    }

    pthread_mutex_unlock(&pool->lock);
}

/*
 * =============================================================================
 * Public API - Management
 * =============================================================================
 */

int mtls_pool_get_stats(mtls_pool *pool, mtls_pool_stats *stats)
{
    if (!pool || !stats) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));

    pthread_mutex_lock(&pool->lock);
    stats->total_connections = pool->total_created;
    stats->active_connections = pool->idle_count + pool->in_use_count;
    stats->idle_connections = pool->idle_count;
    stats->in_use_connections = pool->in_use_count;
    pthread_mutex_unlock(&pool->lock);

    stats->total_acquires = atomic_load(&pool->stats_total_acquires);
    stats->total_releases = atomic_load(&pool->stats_total_releases);
    stats->acquire_timeouts = atomic_load(&pool->stats_acquire_timeouts);
    stats->failed_connects = atomic_load(&pool->stats_failed_connects);
    stats->health_checks = atomic_load(&pool->stats_health_checks);
    stats->unhealthy_closed = atomic_load(&pool->stats_unhealthy_closed);
    stats->idle_closed = atomic_load(&pool->stats_idle_closed);
    stats->lifetime_closed = atomic_load(&pool->stats_lifetime_closed);
    stats->wait_time_total_ms = atomic_load(&pool->stats_wait_time_total_ms);
    stats->wait_time_max_ms = atomic_load(&pool->stats_wait_time_max_ms);

    return 0;
}

void mtls_pool_reset_stats(mtls_pool *pool)
{
    if (!pool) {
        return;
    }

    atomic_store(&pool->stats_total_acquires, 0);
    atomic_store(&pool->stats_total_releases, 0);
    atomic_store(&pool->stats_acquire_timeouts, 0);
    atomic_store(&pool->stats_failed_connects, 0);
    atomic_store(&pool->stats_health_checks, 0);
    atomic_store(&pool->stats_unhealthy_closed, 0);
    atomic_store(&pool->stats_idle_closed, 0);
    atomic_store(&pool->stats_lifetime_closed, 0);
    atomic_store(&pool->stats_wait_time_total_ms, 0);
    atomic_store(&pool->stats_wait_time_max_ms, 0);
}

mtls_pool_state mtls_pool_get_state(const mtls_pool *pool)
{
    if (!pool) {
        return MTLS_POOL_STATE_CLOSED;
    }
    return pool->state;
}

size_t mtls_pool_health_check(mtls_pool *pool)
{
    if (!pool) {
        return 0;
    }

    atomic_fetch_add(&pool->stats_health_checks, 1);

    pthread_mutex_lock(&pool->lock);

    size_t closed_count = 0;
    uint64_t now = platform_get_time_us();

    /* Check idle connections */
    pooled_conn *pconn = pool->idle_head;
    while (pconn) {
        pooled_conn *next = pconn->next;

        if (!is_conn_healthy(pconn, now, &pool->config)) {
            remove_from_idle_list(pool, pconn);
            emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
            pooled_conn_destroy(pconn);
            closed_count++;
            atomic_fetch_add(&pool->stats_unhealthy_closed, 1);
        }

        pconn = next;
    }

    pool->last_health_check_us = now;
    pthread_mutex_unlock(&pool->lock);

    return closed_count;
}

size_t mtls_pool_cleanup(mtls_pool *pool)
{
    if (!pool) {
        return 0;
    }

    pthread_mutex_lock(&pool->lock);

    size_t closed_count = 0;
    uint64_t now = platform_get_time_us();

    /* Check idle connections for expiry */
    pooled_conn *pconn = pool->idle_tail; /* Start from oldest (tail) */
    while (pconn && pool->idle_count > pool->config.min_connections) {
        pooled_conn *prev = pconn->prev;

        if (is_conn_idle_expired(pconn, now, &pool->config)) {
            remove_from_idle_list(pool, pconn);
            emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
            pooled_conn_destroy(pconn);
            closed_count++;
            atomic_fetch_add(&pool->stats_idle_closed, 1);
        } else {
            break; /* Connections before this are even newer */
        }

        pconn = prev;
    }

    pool->last_cleanup_us = now;
    pthread_mutex_unlock(&pool->lock);

    return closed_count;
}

int mtls_pool_warmup(mtls_pool *pool, mtls_err *err)
{
    if (!pool) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Pool is NULL");
        return -1;
    }

    pthread_mutex_lock(&pool->lock);

    if (pool->state != MTLS_POOL_STATE_RUNNING) {
        pthread_mutex_unlock(&pool->lock);
        MTLS_ERR_SET(err, MTLS_ERR_POOL_CLOSED, "Pool is not running");
        return -1;
    }

    size_t current = pool->idle_count + pool->in_use_count;
    size_t needed =
        (current < pool->config.min_connections) ? pool->config.min_connections - current : 0;

    pthread_mutex_unlock(&pool->lock);

    for (size_t i = 0; i < needed; i++) {
        struct mtls_conn *conn = create_new_connection(pool, err);
        if (!conn) {
            return -1;
        }

        pooled_conn *pconn = pooled_conn_create(conn);
        if (!pconn) {
            mtls_close(conn);
            MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate pooled connection");
            return -1;
        }

        pthread_mutex_lock(&pool->lock);
        pool->total_created++;
        add_to_idle_list(pool, pconn);
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CREATED, conn, MTLS_OK);
        pthread_mutex_unlock(&pool->lock);
    }

    return 0;
}

int mtls_pool_resize(mtls_pool *pool, size_t min_connections, size_t max_connections, mtls_err *err)
{
    if (!pool) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Pool is NULL");
        return -1;
    }

    if (min_connections > max_connections) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "min_connections cannot exceed max_connections");
        return -1;
    }

    if (max_connections == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "max_connections must be at least 1");
        return -1;
    }

    pthread_mutex_lock(&pool->lock);
    pool->config.min_connections = min_connections;
    pool->config.max_connections = max_connections;

    /* If we have too many idle connections, close excess */
    while (pool->idle_count > max_connections) {
        pooled_conn *pconn = pool->idle_tail; /* Remove oldest */
        if (!pconn) {
            break;
        }
        /* pconn remains valid after removal from list until destroyed */
        remove_from_idle_list(pool, pconn); // NOLINT(clang-analyzer-unix.Malloc)
        emit_pool_event(pool, MTLS_EVENT_POOL_CONN_CLOSED, pconn->conn, MTLS_OK);
        pooled_conn_destroy(pconn);
    }

    pthread_mutex_unlock(&pool->lock);

    return 0;
}

/*
 * =============================================================================
 * Public API - Utility
 * =============================================================================
 */

const char *mtls_pool_state_string(mtls_pool_state state)
{
    switch (state) {
    case MTLS_POOL_STATE_RUNNING:
        return "running";
    case MTLS_POOL_STATE_CLOSING:
        return "closing";
    case MTLS_POOL_STATE_CLOSED:
        return "closed";
    default:
        return "unknown";
    }
}

const char *mtls_pooled_conn_state_string(mtls_pooled_conn_state state)
{
    switch (state) {
    case MTLS_POOLED_CONN_IDLE:
        return "idle";
    case MTLS_POOLED_CONN_IN_USE:
        return "in_use";
    case MTLS_POOLED_CONN_CLOSED:
        return "closed";
    case MTLS_POOLED_CONN_UNHEALTHY:
        return "unhealthy";
    default:
        return "unknown";
    }
}

// NOLINTEND(misc-include-cleaner,bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
