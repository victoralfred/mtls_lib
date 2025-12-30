/**
 * @file mtls_rate_limit.c
 * @brief Rate limiting implementation using token bucket algorithm
 */

// NOLINTBEGIN(misc-include-cleaner,bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* Enable POSIX extensions for pthread_rwlock_t */
#ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#endif

#include "mtls/mtls_rate_limit.h"
#include "mtls/mtls_error.h"
#include "internal/platform.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/*
 * Fixed-point arithmetic for token calculations
 * Use 16 bits of fractional precision
 */
#define TOKEN_SCALE 65536ULL
#define TOKENS_TO_FIXED(x) ((x) * TOKEN_SCALE)
#define FIXED_TO_TOKENS(x) ((x) / TOKEN_SCALE)

/*
 * Client bucket entry in hash map
 */
typedef struct client_bucket_entry {
    char client_id[MTLS_RATE_LIMIT_MAX_CLIENT_ID_LEN];
    mtls_token_bucket bucket;
    uint64_t last_access_us;
    struct client_bucket_entry *next; /* For hash collision chaining */
} client_bucket_entry;

/*
 * Hash map for per-client buckets
 */
enum { CLIENT_MAP_SIZE = 1024 };

typedef struct client_bucket_map {
    client_bucket_entry *buckets[CLIENT_MAP_SIZE];
    size_t count;
    pthread_rwlock_t lock;
} client_bucket_map;

/*
 * Rate limiter structure
 */
struct mtls_rate_limiter {
    mtls_rate_limit_config config;
    mtls_token_bucket global_bucket;
    client_bucket_map client_map;
    pthread_mutex_t global_lock;

    /* Statistics */
    atomic_uint_fast64_t total_requests;
    atomic_uint_fast64_t allowed_requests;
    atomic_uint_fast64_t rejected_requests;
    atomic_uint_fast64_t global_rejections;
    atomic_uint_fast64_t client_rejections;

    /* Cleanup tracking */
    uint64_t last_cleanup_us;
};

/*
 * Simple hash function for client IDs (djb2)
 */
static uint32_t hash_client_id(const char *client_id)
{
    uint32_t hash = 5381;
    int chr = 0;
    while ((chr = (unsigned char)*client_id++) != 0) {
        hash = ((hash << 5) + hash) + (uint32_t)chr;
    }
    return hash % CLIENT_MAP_SIZE;
}

/*
 * Initialize a token bucket
 */
static void init_bucket(mtls_token_bucket *bucket, uint64_t rate_per_sec, uint64_t burst_size)
{
    bucket->max_tokens = TOKENS_TO_FIXED(burst_size > 0 ? burst_size : rate_per_sec);
    bucket->tokens = bucket->max_tokens; /* Start full */
    bucket->refill_rate = TOKENS_TO_FIXED(rate_per_sec);
    bucket->last_refill_us = platform_get_time_us();
}

/*
 * Refill tokens based on elapsed time
 */
static void refill_bucket(mtls_token_bucket *bucket, uint64_t now_us)
{
    if (bucket->refill_rate == 0) {
        return; /* Unlimited */
    }

    uint64_t elapsed_us = now_us - bucket->last_refill_us;
    if (elapsed_us == 0) {
        return;
    }

    /* Calculate tokens to add: (elapsed_us / 1000000) * refill_rate */
    uint64_t tokens_to_add = (elapsed_us * bucket->refill_rate) / 1000000ULL;

    if (tokens_to_add > 0) {
        bucket->tokens += tokens_to_add;
        if (bucket->tokens > bucket->max_tokens) {
            bucket->tokens = bucket->max_tokens;
        }
        bucket->last_refill_us = now_us;
    }
}

/*
 * Try to consume a token from a bucket
 * Returns true if successful, false if no tokens available
 */
static bool try_consume_token(mtls_token_bucket *bucket, uint64_t now_us)
{
    /* Unlimited rate */
    if (bucket->refill_rate == 0) {
        return true;
    }

    refill_bucket(bucket, now_us);

    if (bucket->tokens >= TOKEN_SCALE) {
        bucket->tokens -= TOKEN_SCALE;
        return true;
    }

    return false;
}

/*
 * Get or create a client bucket entry
 */
static client_bucket_entry *get_or_create_client_bucket(mtls_rate_limiter *limiter,
                                                        const char *client_id, bool create)
{
    uint32_t hash = hash_client_id(client_id);

    /* Check for existing entry */
    client_bucket_entry *entry = limiter->client_map.buckets[hash];
    while (entry) {
        if (strcmp(entry->client_id, client_id) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    if (!create) {
        return NULL;
    }

    /* Check if we've hit the limit */
    if (limiter->client_map.count >= MTLS_RATE_LIMIT_MAX_CLIENTS) {
        return NULL;
    }

    /* Create new entry */
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return NULL;
    }

    size_t id_len = strlen(client_id);
    if (id_len >= MTLS_RATE_LIMIT_MAX_CLIENT_ID_LEN) {
        id_len = MTLS_RATE_LIMIT_MAX_CLIENT_ID_LEN - 1;
    }
    memcpy(entry->client_id, client_id, id_len);
    entry->client_id[id_len] = '\0';

    init_bucket(&entry->bucket, limiter->config.per_client_rate, limiter->config.per_client_burst);
    entry->last_access_us = platform_get_time_us();

    /* Insert at head of chain */
    entry->next = limiter->client_map.buckets[hash];
    limiter->client_map.buckets[hash] = entry;
    limiter->client_map.count++;

    return entry;
}

/*
 * =============================================================================
 * Public API Implementation
 * =============================================================================
 */

void mtls_rate_limit_config_init(mtls_rate_limit_config *config)
{
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(*config));
    config->enabled = false;
    config->max_conn_per_sec = 0; /* Unlimited */
    config->per_client_rate = 0;  /* Unlimited */
    config->burst_size = 10;
    config->per_client_burst = 5;
    config->limit_by_ip = true;
    config->limit_by_cn = false;
    config->cleanup_interval_sec = MTLS_RATE_LIMIT_CLEANUP_INTERVAL_SEC;
    config->client_expiry_sec = MTLS_RATE_LIMIT_CLIENT_EXPIRY_SEC;
}

int mtls_rate_limiter_create(mtls_rate_limiter **limiter, const mtls_rate_limit_config *config,
                             mtls_err *err)
{
    if (!limiter) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Limiter pointer is NULL");
        return -1;
    }

    *limiter = NULL;

    mtls_rate_limiter *new_limiter = calloc(1, sizeof(*new_limiter));
    if (!new_limiter) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate rate limiter");
        return -1;
    }

    /* Copy configuration */
    if (config) {
        new_limiter->config = *config;
    } else {
        mtls_rate_limit_config_init(&new_limiter->config);
    }

    /* Initialize global bucket */
    init_bucket(&new_limiter->global_bucket, new_limiter->config.max_conn_per_sec,
                new_limiter->config.burst_size);

    /* Initialize locks */
    if (pthread_mutex_init(&new_limiter->global_lock, NULL) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to initialize global mutex");
        free(new_limiter);
        return -1;
    }

    if (pthread_rwlock_init(&new_limiter->client_map.lock, NULL) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to initialize client map lock");
        pthread_mutex_destroy(&new_limiter->global_lock);
        free(new_limiter);
        return -1;
    }

    /* Initialize atomics */
    atomic_init(&new_limiter->total_requests, 0);
    atomic_init(&new_limiter->allowed_requests, 0);
    atomic_init(&new_limiter->rejected_requests, 0);
    atomic_init(&new_limiter->global_rejections, 0);
    atomic_init(&new_limiter->client_rejections, 0);

    new_limiter->last_cleanup_us = platform_get_time_us();

    *limiter = new_limiter;
    return 0;
}

void mtls_rate_limiter_free(mtls_rate_limiter *limiter)
{
    if (!limiter) {
        return;
    }

    /* Free all client bucket entries */
    for (size_t i = 0; i < CLIENT_MAP_SIZE; i++) {
        client_bucket_entry *entry = limiter->client_map.buckets[i];
        while (entry) {
            client_bucket_entry *next = entry->next;
            platform_secure_zero(entry, sizeof(*entry));
            free(entry);
            entry = next;
        }
    }

    pthread_rwlock_destroy(&limiter->client_map.lock);
    pthread_mutex_destroy(&limiter->global_lock);

    platform_secure_zero(limiter, sizeof(*limiter));
    free(limiter);
}

int mtls_rate_limiter_update_config(mtls_rate_limiter *limiter,
                                    const mtls_rate_limit_config *config, mtls_err *err)
{
    if (!limiter || !config) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    pthread_mutex_lock(&limiter->global_lock);

    /* Update configuration */
    limiter->config = *config;

    /* Update global bucket rate */
    limiter->global_bucket.refill_rate = TOKENS_TO_FIXED(config->max_conn_per_sec);
    limiter->global_bucket.max_tokens =
        TOKENS_TO_FIXED(config->burst_size > 0 ? config->burst_size : config->max_conn_per_sec);

    pthread_mutex_unlock(&limiter->global_lock);

    return 0;
}

int mtls_rate_limiter_acquire(mtls_rate_limiter *limiter, const char *client_id, mtls_err *err)
{
    if (!limiter) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Limiter is NULL");
        return -1;
    }

    if (!limiter->config.enabled) {
        return 0; /* Rate limiting disabled */
    }

    uint64_t now_us = platform_get_time_us();

    atomic_fetch_add(&limiter->total_requests, 1);

    /* Check global limit first */
    if (limiter->config.max_conn_per_sec > 0) {
        pthread_mutex_lock(&limiter->global_lock);
        bool global_ok = try_consume_token(&limiter->global_bucket, now_us);
        pthread_mutex_unlock(&limiter->global_lock);

        if (!global_ok) {
            atomic_fetch_add(&limiter->rejected_requests, 1);
            atomic_fetch_add(&limiter->global_rejections, 1);
            MTLS_ERR_SET(err, MTLS_ERR_RATE_LIMIT_GLOBAL, "Global rate limit exceeded");
            return -1;
        }
    }

    /* Check per-client limit */
    if (limiter->config.per_client_rate > 0 && client_id && client_id[0] != '\0') {
        pthread_rwlock_wrlock(&limiter->client_map.lock);

        client_bucket_entry *entry = get_or_create_client_bucket(limiter, client_id, true);
        if (entry) {
            entry->last_access_us = now_us;
            bool client_ok = try_consume_token(&entry->bucket, now_us);
            pthread_rwlock_unlock(&limiter->client_map.lock);

            if (!client_ok) {
                atomic_fetch_add(&limiter->rejected_requests, 1);
                atomic_fetch_add(&limiter->client_rejections, 1);
                MTLS_ERR_SET(err, MTLS_ERR_RATE_LIMIT_CLIENT, "Per-client rate limit exceeded");
                return -1;
            }
        } else {
            pthread_rwlock_unlock(&limiter->client_map.lock);
        }
    }

    /* Periodic cleanup */
    uint64_t cleanup_interval_us = (uint64_t)limiter->config.cleanup_interval_sec * 1000000ULL;
    if (now_us - limiter->last_cleanup_us > cleanup_interval_us) {
        mtls_rate_limiter_cleanup(limiter);
    }

    atomic_fetch_add(&limiter->allowed_requests, 1);
    return 0;
}

mtls_rate_limit_status mtls_rate_limiter_check(mtls_rate_limiter *limiter, const char *client_id)
{
    if (!limiter || !limiter->config.enabled) {
        return MTLS_RATE_LIMIT_OK;
    }

    uint64_t now_us = platform_get_time_us();

    /* Check global limit */
    if (limiter->config.max_conn_per_sec > 0) {
        pthread_mutex_lock(&limiter->global_lock);
        refill_bucket(&limiter->global_bucket, now_us);
        bool has_token = limiter->global_bucket.tokens >= TOKEN_SCALE;
        pthread_mutex_unlock(&limiter->global_lock);

        if (!has_token) {
            return MTLS_RATE_LIMIT_GLOBAL_EXCEEDED;
        }
    }

    /* Check per-client limit */
    if (limiter->config.per_client_rate > 0 && client_id && client_id[0] != '\0') {
        pthread_rwlock_rdlock(&limiter->client_map.lock);
        client_bucket_entry *entry = get_or_create_client_bucket(limiter, client_id, false);
        if (entry) {
            refill_bucket(&entry->bucket, now_us);
            bool has_token = entry->bucket.tokens >= TOKEN_SCALE;
            pthread_rwlock_unlock(&limiter->client_map.lock);

            if (!has_token) {
                return MTLS_RATE_LIMIT_CLIENT_EXCEEDED;
            }
        } else {
            pthread_rwlock_unlock(&limiter->client_map.lock);
        }
    }

    return MTLS_RATE_LIMIT_OK;
}

int mtls_rate_limiter_status(mtls_rate_limiter *limiter, const char *client_id,
                             uint64_t *tokens_out, uint64_t *next_refill_ms_out)
{
    if (!limiter) {
        return -1;
    }

    uint64_t now_us = platform_get_time_us();
    mtls_token_bucket *bucket = NULL;
    bool found = false;

    if (client_id && client_id[0] != '\0') {
        pthread_rwlock_rdlock(&limiter->client_map.lock);
        client_bucket_entry *entry = get_or_create_client_bucket(limiter, client_id, false);
        if (entry) {
            refill_bucket(&entry->bucket, now_us);
            if (tokens_out) {
                *tokens_out = FIXED_TO_TOKENS(entry->bucket.tokens);
            }
            if (next_refill_ms_out && entry->bucket.refill_rate > 0) {
                /* Calculate ms until next token */
                uint64_t tokens_needed = TOKEN_SCALE - (entry->bucket.tokens % TOKEN_SCALE);
                *next_refill_ms_out = (tokens_needed * 1000ULL) / entry->bucket.refill_rate;
            }
            found = true;
        }
        pthread_rwlock_unlock(&limiter->client_map.lock);
    } else {
        pthread_mutex_lock(&limiter->global_lock);
        bucket = &limiter->global_bucket;
        refill_bucket(bucket, now_us);
        if (tokens_out) {
            *tokens_out = FIXED_TO_TOKENS(bucket->tokens);
        }
        if (next_refill_ms_out && bucket->refill_rate > 0) {
            uint64_t tokens_needed = TOKEN_SCALE - (bucket->tokens % TOKEN_SCALE);
            *next_refill_ms_out = (tokens_needed * 1000ULL) / bucket->refill_rate;
        }
        pthread_mutex_unlock(&limiter->global_lock);
        found = true;
    }

    return found ? 0 : -1;
}

void mtls_rate_limiter_reset(mtls_rate_limiter *limiter)
{
    if (!limiter) {
        return;
    }

    uint64_t now_us = platform_get_time_us();

    /* Reset global bucket */
    pthread_mutex_lock(&limiter->global_lock);
    limiter->global_bucket.tokens = limiter->global_bucket.max_tokens;
    limiter->global_bucket.last_refill_us = now_us;
    pthread_mutex_unlock(&limiter->global_lock);

    /* Clear all client buckets */
    pthread_rwlock_wrlock(&limiter->client_map.lock);
    for (size_t i = 0; i < CLIENT_MAP_SIZE; i++) {
        client_bucket_entry *entry = limiter->client_map.buckets[i];
        while (entry) {
            client_bucket_entry *next = entry->next;
            platform_secure_zero(entry, sizeof(*entry));
            free(entry);
            entry = next;
        }
        limiter->client_map.buckets[i] = NULL;
    }
    limiter->client_map.count = 0;
    pthread_rwlock_unlock(&limiter->client_map.lock);
}

int mtls_rate_limiter_remove_client(mtls_rate_limiter *limiter, const char *client_id)
{
    if (!limiter || !client_id) {
        return -1;
    }

    uint32_t hash = hash_client_id(client_id);

    pthread_rwlock_wrlock(&limiter->client_map.lock);

    client_bucket_entry *prev = NULL;
    client_bucket_entry *entry = limiter->client_map.buckets[hash];

    while (entry) {
        if (strcmp(entry->client_id, client_id) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                limiter->client_map.buckets[hash] = entry->next;
            }
            limiter->client_map.count--;
            pthread_rwlock_unlock(&limiter->client_map.lock);

            platform_secure_zero(entry, sizeof(*entry));
            free(entry);
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_rwlock_unlock(&limiter->client_map.lock);
    return -1;
}

size_t mtls_rate_limiter_cleanup(mtls_rate_limiter *limiter)
{
    if (!limiter) {
        return 0;
    }

    uint64_t now_us = platform_get_time_us();
    uint64_t expiry_us = (uint64_t)limiter->config.client_expiry_sec * 1000000ULL;
    size_t removed = 0;

    pthread_rwlock_wrlock(&limiter->client_map.lock);

    for (size_t i = 0; i < CLIENT_MAP_SIZE; i++) {
        client_bucket_entry *prev = NULL;
        client_bucket_entry *entry = limiter->client_map.buckets[i];

        while (entry) {
            client_bucket_entry *next = entry->next;

            if (now_us - entry->last_access_us > expiry_us) {
                /* Remove expired entry */
                if (prev) {
                    prev->next = next;
                } else {
                    limiter->client_map.buckets[i] = next;
                }
                limiter->client_map.count--;
                platform_secure_zero(entry, sizeof(*entry));
                free(entry);
                removed++;
            } else {
                prev = entry;
            }

            entry = next;
        }
    }

    limiter->last_cleanup_us = now_us;
    pthread_rwlock_unlock(&limiter->client_map.lock);

    return removed;
}

int mtls_rate_limiter_stats(mtls_rate_limiter *limiter, mtls_rate_limit_stats *stats)
{
    if (!limiter || !stats) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));

    stats->total_requests = atomic_load(&limiter->total_requests);
    stats->allowed_requests = atomic_load(&limiter->allowed_requests);
    stats->rejected_requests = atomic_load(&limiter->rejected_requests);
    stats->global_rejections = atomic_load(&limiter->global_rejections);
    stats->client_rejections = atomic_load(&limiter->client_rejections);

    pthread_rwlock_rdlock(&limiter->client_map.lock);
    stats->active_clients = limiter->client_map.count;
    pthread_rwlock_unlock(&limiter->client_map.lock);

    pthread_mutex_lock(&limiter->global_lock);
    refill_bucket(&limiter->global_bucket, platform_get_time_us());
    stats->tokens_available = FIXED_TO_TOKENS(limiter->global_bucket.tokens);
    pthread_mutex_unlock(&limiter->global_lock);

    return 0;
}

void mtls_rate_limiter_reset_stats(mtls_rate_limiter *limiter)
{
    if (!limiter) {
        return;
    }

    atomic_store(&limiter->total_requests, 0);
    atomic_store(&limiter->allowed_requests, 0);
    atomic_store(&limiter->rejected_requests, 0);
    atomic_store(&limiter->global_rejections, 0);
    atomic_store(&limiter->client_rejections, 0);
}

const char *mtls_rate_limit_status_string(mtls_rate_limit_status status)
{
    switch (status) {
    case MTLS_RATE_LIMIT_OK:
        return "OK";
    case MTLS_RATE_LIMIT_EXCEEDED:
        return "Rate limit exceeded";
    case MTLS_RATE_LIMIT_GLOBAL_EXCEEDED:
        return "Global rate limit exceeded";
    case MTLS_RATE_LIMIT_CLIENT_EXCEEDED:
        return "Per-client rate limit exceeded";
    default:
        return "Unknown";
    }
}

uint64_t mtls_rate_limiter_wait_time(mtls_rate_limiter *limiter, const char *client_id)
{
    if (!limiter) {
        return 0;
    }

    uint64_t global_wait = 0;
    uint64_t client_wait = 0;

    /* Check global bucket */
    pthread_mutex_lock(&limiter->global_lock);
    if (limiter->global_bucket.refill_rate > 0 && limiter->global_bucket.tokens < TOKEN_SCALE) {
        uint64_t tokens_needed = TOKEN_SCALE - limiter->global_bucket.tokens;
        global_wait = (tokens_needed * 1000ULL) / limiter->global_bucket.refill_rate;
    }
    pthread_mutex_unlock(&limiter->global_lock);

    /* Check per-client bucket */
    if (client_id && client_id[0] != '\0') {
        pthread_rwlock_rdlock(&limiter->client_map.lock);
        client_bucket_entry *entry = get_or_create_client_bucket(limiter, client_id, false);
        if (entry && entry->bucket.refill_rate > 0 && entry->bucket.tokens < TOKEN_SCALE) {
            uint64_t tokens_needed = TOKEN_SCALE - entry->bucket.tokens;
            client_wait = (tokens_needed * 1000ULL) / entry->bucket.refill_rate;
        }
        pthread_rwlock_unlock(&limiter->client_map.lock);
    }

    return (global_wait > client_wait) ? global_wait : client_wait;
}

// NOLINTEND(misc-include-cleaner,bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
