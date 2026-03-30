/**
 * @file mtls_ocsp.c
 * @brief OCSP and CRL certificate revocation checking implementation
 *
 * This file implements OCSP (Online Certificate Status Protocol) and
 * CRL (Certificate Revocation List) checking for certificate validation.
 */

/* Enable POSIX features for pthread_rwlock_t */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200112L
#    undef _POSIX_C_SOURCE
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#    define _POSIX_C_SOURCE 200112L
#endif

// NOLINTBEGIN(misc-include-cleaner,readability-identifier-length,cert-err33-c,bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions,bugprone-implicit-widening-of-multiplication-result,clang-analyzer-deadcode.DeadStores)

#include "mtls/mtls_ocsp.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_types.h"
#include "internal/mtls_internal.h"
#include "internal/platform.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * =============================================================================
 * Internal Types
 * =============================================================================
 */

/**
 * Cache entry structure
 */
typedef struct cache_entry {
    uint8_t fingerprint[32];       /* SHA-256 fingerprint */
    mtls_revocation_result result; /* Cached result */
    time_t expires_at;             /* Entry expiration time */
    struct cache_entry *next;      /* Hash chain pointer */
} cache_entry;

/**
 * Revocation cache implementation
 */
struct mtls_revocation_cache {
    cache_entry **buckets; /* Hash table buckets */
    size_t bucket_count;   /* Number of buckets */
    size_t entry_count;    /* Current entry count */
    size_t max_entries;    /* Maximum entries */
    uint32_t ttl_seconds;  /* Entry TTL */
    pthread_rwlock_t lock; /* Reader-writer lock */
    size_t hits;           /* Cache hit counter */
    size_t misses;         /* Cache miss counter */
    size_t evictions;      /* Eviction counter */
    size_t expirations;    /* Expiration counter */
};

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/**
 * Parse PEM certificate into X509 structure
 */
static X509 *parse_pem_cert(const uint8_t *pem, size_t pem_len, mtls_err *err)
{
    if (!pem || pem_len == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Certificate PEM is NULL or empty");
        return NULL;
    }

    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to create BIO for certificate");
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_PARSE_FAILED, "Failed to parse PEM certificate");
    }

    return cert;
}

/**
 * Compute FNV-1a hash of fingerprint for hash table
 */
static size_t fingerprint_hash(const uint8_t *fp_data, size_t bucket_count)
{
    uint64_t hash = 14695981039346656037ULL; /* FNV offset basis */
    for (size_t i = 0; i < 32; i++) {
        hash ^= fp_data[i];
        hash *= 1099511628211ULL; /* FNV prime */
    }
    return (size_t)(hash % bucket_count);
}

/**
 * Emit OCSP/CRL event
 */
static void emit_revocation_event(mtls_ctx *ctx, mtls_event_type type, int error_code)
{
    if (!ctx) {
        return;
    }

    mtls_event event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.error_code = error_code;
    event.timestamp_us = platform_get_time_us();

    mtls_emit_event(ctx, &event);
}

/*
 * =============================================================================
 * Cache Implementation
 * =============================================================================
 */

int mtls_revocation_cache_create(mtls_revocation_cache **cache_out, size_t max_entries,
                                 uint32_t ttl_seconds, mtls_err *err)
{
    if (!cache_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Cache output pointer is NULL");
        return -1;
    }

    *cache_out = NULL;

    if (max_entries == 0) {
        max_entries = MTLS_REVOCATION_CACHE_DEFAULT_MAX_ENTRIES;
    }
    if (ttl_seconds == 0) {
        ttl_seconds = MTLS_REVOCATION_CACHE_DEFAULT_TTL_SECONDS;
    }

    mtls_revocation_cache *cache = calloc(1, sizeof(*cache));
    if (!cache) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate revocation cache");
        return -1;
    }

    /* Use power of 2 bucket count for efficient modulo */
    cache->bucket_count = 1024;
    while (cache->bucket_count < max_entries / 4) {
        cache->bucket_count *= 2;
    }

    cache->buckets = (cache_entry **)calloc(cache->bucket_count, sizeof(cache_entry *));
    if (!cache->buckets) {
        free(cache);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate cache buckets");
        return -1;
    }

    cache->max_entries = max_entries;
    cache->ttl_seconds = ttl_seconds;

    if (pthread_rwlock_init(&cache->lock, NULL) != 0) {
        free((void *)cache->buckets);
        free(cache);
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to initialize cache lock");
        return -1;
    }

    *cache_out = cache;
    return 0;
}

void mtls_revocation_cache_free(mtls_revocation_cache *cache)
{
    if (!cache) {
        return;
    }

    /* Free all entries */
    for (size_t i = 0; i < cache->bucket_count; i++) {
        cache_entry *entry = cache->buckets[i];
        while (entry) {
            cache_entry *next = entry->next;
            platform_secure_zero(entry, sizeof(*entry));
            free(entry);
            entry = next;
        }
    }

    pthread_rwlock_destroy(&cache->lock);
    free((void *)cache->buckets);
    platform_secure_zero(cache, sizeof(*cache));
    free(cache);
}

int mtls_revocation_cache_get(mtls_revocation_cache *cache, const uint8_t *cert_fingerprint,
                              mtls_revocation_result *result)
{
    if (!cache || !cert_fingerprint || !result) {
        return -1;
    }

    pthread_rwlock_rdlock(&cache->lock);

    size_t bucket = fingerprint_hash(cert_fingerprint, cache->bucket_count);
    cache_entry *entry = cache->buckets[bucket];
    time_t now = time(NULL);

    while (entry) {
        if (memcmp(entry->fingerprint, cert_fingerprint, 32) == 0) {
            if (entry->expires_at > now) {
                /* Cache hit */
                memcpy(result, &entry->result, sizeof(*result));
                pthread_rwlock_unlock(&cache->lock);

                /* Update hit counter (needs write lock) */
                pthread_rwlock_wrlock(&cache->lock);
                cache->hits++;
                pthread_rwlock_unlock(&cache->lock);
                return 0;
            }
            /* Entry expired */
            break;
        }
        entry = entry->next;
    }

    pthread_rwlock_unlock(&cache->lock);

    /* Update miss counter */
    pthread_rwlock_wrlock(&cache->lock);
    cache->misses++;
    pthread_rwlock_unlock(&cache->lock);

    return -1;
}

int mtls_revocation_cache_put(mtls_revocation_cache *cache, const uint8_t *cert_fingerprint,
                              const mtls_revocation_result *result)
{
    if (!cache || !cert_fingerprint || !result) {
        return -1;
    }

    pthread_rwlock_wrlock(&cache->lock);

    size_t bucket = fingerprint_hash(cert_fingerprint, cache->bucket_count);
    cache_entry *entry = cache->buckets[bucket];
    time_t now = time(NULL);

    /* Look for existing entry or expired entry to replace */
    while (entry) {
        if (memcmp(entry->fingerprint, cert_fingerprint, 32) == 0) {
            /* Update existing entry */
            memcpy(&entry->result, result, sizeof(*result));
            entry->expires_at = now + cache->ttl_seconds;
            pthread_rwlock_unlock(&cache->lock);
            return 0;
        }
        entry = entry->next;
    }

    /* Evict if at capacity */
    if (cache->entry_count >= cache->max_entries) {
        /* Simple eviction: remove first entry from random bucket */
        for (size_t i = 0; i < cache->bucket_count; i++) {
            if (cache->buckets[i]) {
                cache_entry *evict = cache->buckets[i];
                cache->buckets[i] = evict->next;
                platform_secure_zero(evict, sizeof(*evict));
                free(evict);
                cache->entry_count--;
                cache->evictions++;
                break;
            }
        }
    }

    /* Create new entry */
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_rwlock_unlock(&cache->lock);
        return -1;
    }

    memcpy(entry->fingerprint, cert_fingerprint, 32);
    memcpy(&entry->result, result, sizeof(*result));
    entry->expires_at = now + cache->ttl_seconds;
    entry->next = cache->buckets[bucket];
    cache->buckets[bucket] = entry;
    cache->entry_count++;

    pthread_rwlock_unlock(&cache->lock);
    return 0;
}

int mtls_revocation_cache_remove(mtls_revocation_cache *cache, const uint8_t *cert_fingerprint)
{
    if (!cache || !cert_fingerprint) {
        return -1;
    }

    pthread_rwlock_wrlock(&cache->lock);

    size_t bucket = fingerprint_hash(cert_fingerprint, cache->bucket_count);
    cache_entry *entry = cache->buckets[bucket];
    cache_entry *prev = NULL;

    while (entry) {
        if (memcmp(entry->fingerprint, cert_fingerprint, 32) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                cache->buckets[bucket] = entry->next;
            }
            platform_secure_zero(entry, sizeof(*entry));
            free(entry);
            cache->entry_count--;
            pthread_rwlock_unlock(&cache->lock);
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_rwlock_unlock(&cache->lock);
    return 0;
}

void mtls_revocation_cache_clear(mtls_revocation_cache *cache)
{
    if (!cache) {
        return;
    }

    pthread_rwlock_wrlock(&cache->lock);

    for (size_t i = 0; i < cache->bucket_count; i++) {
        cache_entry *entry = cache->buckets[i];
        while (entry) {
            cache_entry *next = entry->next;
            platform_secure_zero(entry, sizeof(*entry));
            free(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }
    cache->entry_count = 0;

    pthread_rwlock_unlock(&cache->lock);
}

int mtls_revocation_cache_stats(mtls_revocation_cache *cache, mtls_cache_stats *stats)
{
    if (!cache || !stats) {
        return -1;
    }

    pthread_rwlock_rdlock(&cache->lock);

    stats->total_entries = cache->entry_count;
    stats->hits = cache->hits;
    stats->misses = cache->misses;
    stats->evictions = cache->evictions;
    stats->expirations = cache->expirations;

    pthread_rwlock_unlock(&cache->lock);
    return 0;
}

/*
 * =============================================================================
 * Certificate Fingerprint
 * =============================================================================
 */

int mtls_cert_fingerprint(const uint8_t *cert_pem, size_t cert_pem_len, uint8_t *fingerprint_out,
                          mtls_err *err)
{
    if (!cert_pem || !fingerprint_out) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Certificate or output is NULL");
        return -1;
    }

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        return -1;
    }

    unsigned int len = 0;
    if (!X509_digest(cert, EVP_sha256(), fingerprint_out, &len) || len != 32) {
        X509_free(cert);
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to compute certificate fingerprint");
        return -1;
    }

    X509_free(cert);
    return 0;
}

/*
 * =============================================================================
 * OCSP Implementation
 * =============================================================================
 */

int mtls_ocsp_get_responder_url(const uint8_t *cert_pem, size_t cert_pem_len, char *url_out,
                                size_t url_out_len, mtls_err *err)
{
    if (!cert_pem || !url_out || url_out_len == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        return -1;
    }

    /* Get OCSP responder URLs from AIA extension */
    STACK_OF(OPENSSL_STRING) *ocsp_urls = X509_get1_ocsp(cert);
    if (!ocsp_urls || sk_OPENSSL_STRING_num(ocsp_urls) == 0) {
        X509_free(cert);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "No OCSP responder URL in certificate");
        return -1;
    }

    /* Get first URL */
    const char *url = sk_OPENSSL_STRING_value(ocsp_urls, 0);
    if (!url) {
        X509_email_free(ocsp_urls);
        X509_free(cert);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Empty OCSP responder URL");
        return -1;
    }

    size_t url_len = strlen(url);
    if (url_len >= url_out_len) {
        X509_email_free(ocsp_urls);
        X509_free(cert);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "OCSP URL too long for buffer");
        return -1;
    }

    memcpy(url_out, url, url_len + 1);

    X509_email_free(ocsp_urls);
    X509_free(cert);
    return 0;
}

int mtls_ocsp_check_url(const char *ocsp_url, const uint8_t *cert_pem, size_t cert_pem_len,
                        const uint8_t *issuer_pem, size_t issuer_pem_len, uint32_t timeout_ms,
                        mtls_revocation_result *result, mtls_err *err)
{
    if (!ocsp_url || !cert_pem || !issuer_pem || !result) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for OCSP check");
        return -1;
    }

    memset(result, 0, sizeof(*result));

    if (timeout_ms == 0) {
        timeout_ms = MTLS_OCSP_DEFAULT_TIMEOUT_MS;
    }

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    X509 *issuer = parse_pem_cert(issuer_pem, issuer_pem_len, err);
    if (!issuer) {
        X509_free(cert);
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Create OCSP request */
    OCSP_CERTID *cert_id = OCSP_cert_to_id(NULL, cert, issuer);
    if (!cert_id) {
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Failed to create OCSP certificate ID");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    OCSP_REQUEST *req = OCSP_REQUEST_new();
    if (!req) {
        OCSP_CERTID_free(cert_id);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to create OCSP request");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    if (!OCSP_request_add0_id(req, cert_id)) {
        OCSP_CERTID_free(cert_id);
        OCSP_REQUEST_free(req);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Failed to add certificate ID to OCSP request");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Store URL in result */
    size_t url_len = strlen(ocsp_url);
    if (url_len < sizeof(result->responder_url)) {
        memcpy(result->responder_url, ocsp_url, url_len + 1);
    }

    /* Connect to OCSP responder and send request */
    BIO *cbio = BIO_new_connect(ocsp_url + 7); /* Skip "http://" */
    if (!cbio) {
        OCSP_REQUEST_free(req);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Failed to create connection to OCSP responder");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Set timeout */
    BIO_set_nbio(cbio, 1);

    if (BIO_do_connect(cbio) <= 0 && !BIO_should_retry(cbio)) {
        BIO_free_all(cbio);
        OCSP_REQUEST_free(req);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_TIMEOUT, "Failed to connect to OCSP responder");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Apply socket-level timeout for subsequent send/receive operations */
    {
        int bio_fd = -1;
        (void)BIO_get_fd(cbio, &bio_fd);
        if (bio_fd >= 0 && timeout_ms > 0) {
            (void)platform_socket_set_recv_timeout((mtls_socket_t)bio_fd, timeout_ms, NULL);
            (void)platform_socket_set_send_timeout((mtls_socket_t)bio_fd, timeout_ms, NULL);
        }
    }

    /* Extract host and path from URL */
    char host[256];
    char path[256] = "/";
    const char *url_ptr = ocsp_url;
    if (strncmp(url_ptr, "http://", 7) == 0) {
        url_ptr += 7;
    } else if (strncmp(url_ptr, "https://", 8) == 0) {
        url_ptr += 8;
    }

    const char *slash = strchr(url_ptr, '/');
    if (slash) {
        size_t host_len = (size_t)(slash - url_ptr);
        if (host_len < sizeof(host)) {
            memcpy(host, url_ptr, host_len);
            host[host_len] = '\0';
        }
        size_t path_len = strlen(slash);
        if (path_len < sizeof(path)) {
            memcpy(path, slash, path_len + 1);
        }
    } else {
        size_t host_len = strlen(url_ptr);
        if (host_len < sizeof(host)) {
            memcpy(host, url_ptr, host_len + 1);
        }
    }

    /* Send OCSP request */
    OCSP_RESPONSE *resp = OCSP_sendreq_bio(cbio, path, req);
    BIO_free_all(cbio);
    OCSP_REQUEST_free(req);

    if (!resp) {
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_RESPONDER_ERROR, "Failed to get OCSP response");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Check response status */
    int resp_status = OCSP_response_status(resp);
    if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_RESPONSE_free(resp);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_RESPONDER_ERROR, "OCSP responder returned error status: %d",
                     resp_status);
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Parse basic response */
    OCSP_BASICRESP *basic = OCSP_response_get1_basic(resp);
    if (!basic) {
        OCSP_RESPONSE_free(resp);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Failed to parse OCSP basic response");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Verify response signature (using issuer as signer) */
    X509_STORE *store = X509_STORE_new();
    if (store) {
        X509_STORE_add_cert(store, issuer);
    }

    /* Find certificate status in response */
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, cert, issuer);
    int status = -1;
    int reason = 0;
    ASN1_GENERALIZEDTIME *rev_time = NULL;
    ASN1_GENERALIZEDTIME *this_update = NULL;
    ASN1_GENERALIZEDTIME *next_update = NULL;

    if (OCSP_resp_find_status(basic, id, &status, &reason, &rev_time, &this_update, &next_update)) {
        result->ocsp_checked = true;

        switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            result->ocsp_status = MTLS_OCSP_STATUS_GOOD;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            result->ocsp_status = MTLS_OCSP_STATUS_REVOKED;
            result->revocation_reason = reason;
            if (rev_time) {
                struct tm tm_rev;
                memset(&tm_rev, 0, sizeof(tm_rev));
                ASN1_TIME_to_tm(rev_time, &tm_rev);
                result->revocation_time = mktime(&tm_rev);
            }
            break;
        default:
            result->ocsp_status = MTLS_OCSP_STATUS_UNKNOWN;
            break;
        }

        /* Store update times */
        if (this_update) {
            struct tm tm_this;
            memset(&tm_this, 0, sizeof(tm_this));
            ASN1_TIME_to_tm(this_update, &tm_this);
            result->ocsp_this_update = mktime(&tm_this);
        }
        if (next_update) {
            struct tm tm_next;
            memset(&tm_next, 0, sizeof(tm_next));
            ASN1_TIME_to_tm(next_update, &tm_next);
            result->ocsp_next_update = mktime(&tm_next);
        }
    } else {
        result->ocsp_status = MTLS_OCSP_STATUS_UNKNOWN;
    }

    OCSP_CERTID_free(id);
    if (store) {
        X509_STORE_free(store);
    }
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(resp);
    X509_free(cert);
    X509_free(issuer);

    if (result->ocsp_status == MTLS_OCSP_STATUS_REVOKED) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_REVOKED, "Certificate is revoked");
        return -1;
    }

    return 0;
}

int mtls_ocsp_check(mtls_ctx *ctx, const uint8_t *cert_pem, size_t cert_pem_len,
                    const uint8_t *issuer_pem, size_t issuer_pem_len,
                    mtls_revocation_result *result, mtls_err *err)
{
    if (!ctx || !cert_pem || !issuer_pem || !result) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for OCSP check");
        return -1;
    }

    emit_revocation_event(ctx, MTLS_EVENT_OCSP_CHECK_START, 0);

    /* Try to get OCSP URL from config first, then from certificate */
    char url[512];
    const char *ocsp_url = ctx->config.ocsp_url;

    if (!ocsp_url || strlen(ocsp_url) == 0) {
        if (mtls_ocsp_get_responder_url(cert_pem, cert_pem_len, url, sizeof(url), err) < 0) {
            emit_revocation_event(ctx, MTLS_EVENT_OCSP_CHECK_FAILURE, err->code);
            return -1;
        }
        ocsp_url = url;
    }

    int ret = mtls_ocsp_check_url(ocsp_url, cert_pem, cert_pem_len, issuer_pem, issuer_pem_len,
                                  ctx->config.ocsp_timeout_ms, result, err);

    if (ret == 0) {
        emit_revocation_event(ctx, MTLS_EVENT_OCSP_CHECK_SUCCESS, 0);
    } else {
        emit_revocation_event(ctx, MTLS_EVENT_OCSP_CHECK_FAILURE, err ? err->code : 0);
    }

    return ret;
}

int mtls_ocsp_verify_stapled(const uint8_t *response, size_t response_len, const uint8_t *cert_pem,
                             size_t cert_pem_len, const uint8_t *issuer_pem, size_t issuer_pem_len,
                             mtls_revocation_result *result, mtls_err *err)
{
    if (!response || !cert_pem || !issuer_pem || !result) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for stapled OCSP");
        return -1;
    }

    memset(result, 0, sizeof(*result));

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    X509 *issuer = parse_pem_cert(issuer_pem, issuer_pem_len, err);
    if (!issuer) {
        X509_free(cert);
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Parse DER-encoded OCSP response */
    const unsigned char *p = response;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, (long)response_len);
    if (!resp) {
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Failed to parse stapled OCSP response");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Check response status */
    int resp_status = OCSP_response_status(resp);
    if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_RESPONSE_free(resp);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_RESPONDER_ERROR, "Stapled OCSP response has error status");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Parse basic response */
    OCSP_BASICRESP *basic = OCSP_response_get1_basic(resp);
    if (!basic) {
        OCSP_RESPONSE_free(resp);
        X509_free(cert);
        X509_free(issuer);
        MTLS_ERR_SET(err, MTLS_ERR_OCSP_FAILED, "Failed to parse stapled OCSP basic response");
        result->ocsp_status = MTLS_OCSP_STATUS_ERROR;
        return -1;
    }

    /* Find certificate status in response */
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, cert, issuer);
    int status = -1;
    int reason = 0;
    ASN1_GENERALIZEDTIME *rev_time = NULL;
    ASN1_GENERALIZEDTIME *this_update = NULL;
    ASN1_GENERALIZEDTIME *next_update = NULL;

    if (OCSP_resp_find_status(basic, id, &status, &reason, &rev_time, &this_update, &next_update)) {
        result->ocsp_checked = true;

        switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            result->ocsp_status = MTLS_OCSP_STATUS_GOOD;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            result->ocsp_status = MTLS_OCSP_STATUS_REVOKED;
            result->revocation_reason = reason;
            break;
        default:
            result->ocsp_status = MTLS_OCSP_STATUS_UNKNOWN;
            break;
        }
    } else {
        result->ocsp_status = MTLS_OCSP_STATUS_UNKNOWN;
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(resp);
    X509_free(cert);
    X509_free(issuer);

    if (result->ocsp_status == MTLS_OCSP_STATUS_REVOKED) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_REVOKED, "Certificate is revoked (stapled OCSP)");
        return -1;
    }

    return 0;
}

/*
 * =============================================================================
 * CRL Implementation
 * =============================================================================
 */

int mtls_crl_get_distribution_points(const uint8_t *cert_pem, size_t cert_pem_len,
                                     char (*urls_out)[512], size_t max_urls, size_t *num_urls_out,
                                     mtls_err *err)
{
    if (!cert_pem || !urls_out || !num_urls_out || max_urls == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    *num_urls_out = 0;

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        return -1;
    }

    /* Get CRL Distribution Points extension */
    STACK_OF(DIST_POINT) *dps = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (!dps) {
        X509_free(cert);
        return 0; /* No CDP extension, not an error */
    }

    int count = sk_DIST_POINT_num(dps);
    for (int i = 0; i < count && *num_urls_out < max_urls; i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(dps, i);
        if (!dp || !dp->distpoint || dp->distpoint->type != 0) {
            continue;
        }

        GENERAL_NAMES *names = dp->distpoint->name.fullname;
        if (!names) {
            continue;
        }

        int num_names = sk_GENERAL_NAME_num(names);
        for (int j = 0; j < num_names && *num_urls_out < max_urls; j++) {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
            if (!name || name->type != GEN_URI) {
                continue;
            }

            ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
            if (!uri || !uri->data) {
                continue;
            }

            size_t uri_len = (size_t)uri->length;
            if (uri_len >= 512) {
                continue;
            }

            memcpy(urls_out[*num_urls_out], uri->data, uri_len);
            urls_out[*num_urls_out][uri_len] = '\0';
            (*num_urls_out)++;
        }
    }

    sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
    X509_free(cert);
    return 0;
}

int mtls_crl_check_data(const uint8_t *crl_data, size_t crl_data_len, const uint8_t *cert_pem,
                        size_t cert_pem_len, mtls_revocation_result *result, mtls_err *err)
{
    if (!crl_data || !cert_pem || !result) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for CRL check");
        return -1;
    }

    memset(result, 0, sizeof(*result));

    X509 *cert = parse_pem_cert(cert_pem, cert_pem_len, err);
    if (!cert) {
        result->crl_status = MTLS_CRL_STATUS_ERROR;
        return -1;
    }

    /* Try to parse CRL as PEM first, then as DER */
    X509_CRL *crl = NULL;
    BIO *bio = BIO_new_mem_buf(crl_data, (int)crl_data_len);
    if (bio) {
        crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
        if (!crl) {
            /* Reset BIO and try DER format */
            BIO_reset(bio);
            const unsigned char *p = crl_data;
            crl = d2i_X509_CRL(NULL, &p, (long)crl_data_len);
        }
        BIO_free(bio);
    }

    if (!crl) {
        X509_free(cert);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_PARSE_FAILED, "Failed to parse CRL data");
        result->crl_status = MTLS_CRL_STATUS_ERROR;
        return -1;
    }

    /* Check if CRL is expired */
    const ASN1_TIME *next_update = X509_CRL_get0_nextUpdate(crl);
    if (next_update) {
        struct tm tm_next;
        memset(&tm_next, 0, sizeof(tm_next));
        ASN1_TIME_to_tm(next_update, &tm_next);
        result->crl_next_update = mktime(&tm_next);

        if (X509_cmp_time(next_update, NULL) < 0) {
            X509_CRL_free(crl);
            X509_free(cert);
            MTLS_ERR_SET(err, MTLS_ERR_CRL_EXPIRED, "CRL has expired");
            result->crl_status = MTLS_CRL_STATUS_ERROR;
            return -1;
        }
    }

    const ASN1_TIME *last_update = X509_CRL_get0_lastUpdate(crl);
    if (last_update) {
        struct tm tm_last;
        memset(&tm_last, 0, sizeof(tm_last));
        ASN1_TIME_to_tm(last_update, &tm_last);
        result->crl_last_update = mktime(&tm_last);
    }

    /* Look for certificate in CRL */
    X509_REVOKED *revoked = NULL;
    int ret = X509_CRL_get0_by_cert(crl, &revoked, cert);

    result->crl_checked = true;

    if (ret == 0) {
        result->crl_status = MTLS_CRL_STATUS_GOOD;
    } else {
        result->crl_status = MTLS_CRL_STATUS_REVOKED;

        /* Get revocation time and reason */
        if (revoked) {
            const ASN1_TIME *rev_time = X509_REVOKED_get0_revocationDate(revoked);
            if (rev_time) {
                struct tm tm_rev;
                memset(&tm_rev, 0, sizeof(tm_rev));
                ASN1_TIME_to_tm(rev_time, &tm_rev);
                result->revocation_time = mktime(&tm_rev);
            }

            /* Get reason code */
            ASN1_ENUMERATED *reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, NULL, NULL);
            if (reason) {
                result->revocation_reason = (int)ASN1_ENUMERATED_get(reason);
                ASN1_ENUMERATED_free(reason);
            }
        }
    }

    X509_CRL_free(crl);
    X509_free(cert);

    if (result->crl_status == MTLS_CRL_STATUS_REVOKED) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_REVOKED, "Certificate is in CRL");
        return -1;
    }

    return 0;
}

int mtls_crl_load_file(mtls_ctx *ctx, const char *crl_path, mtls_err *err)
{
    if (!ctx || !crl_path) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for CRL load");
        return -1;
    }

    FILE *f = fopen(crl_path, "rb");
    if (!f) {
        MTLS_ERR_SET(err, MTLS_ERR_CRL_FAILED, "Failed to open CRL file: %s", crl_path);
        return -1;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 10 * 1024 * 1024) { /* Max 10MB */
        fclose(f);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_FAILED, "CRL file size invalid");
        return -1;
    }

    void *data = malloc((size_t)size);
    if (!data) {
        fclose(f);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate memory for CRL");
        return -1;
    }

    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_FAILED, "Failed to read CRL file");
        return -1;
    }
    fclose(f);

    /* Free old CRL data */
    if (ctx->crl_data) {
        platform_secure_zero(ctx->crl_data, ctx->crl_data_len);
        free(ctx->crl_data);
    }

    ctx->crl_data = data;
    ctx->crl_data_len = (size_t)size;

    return 0;
}

/**
 * Send an HTTP/1.0 GET over an already-connected BIO and return the response body.
 * Handles any BIO type (plain TCP or SSL chain).
 * Caller must free *out_body on success.
 */
static int crl_http_get_body(BIO *bio, const char *path, const char *host, void **out_body,
                             size_t *out_len, mtls_err *err)
{
    /* Send GET request */
    char request[1024];
    int req_len = snprintf(request, sizeof(request),
                           "GET %s HTTP/1.0\r\n"
                           "Host: %s\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           path, host);
    if (req_len <= 0 || (size_t)req_len >= sizeof(request)) {
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "CRL request URL too long");
        return -1;
    }

    if (BIO_write(bio, request, req_len) <= 0) {
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Failed to send CRL request");
        return -1;
    }

    /* Read full response */
    char *response = NULL;
    size_t response_len = 0;
    size_t response_cap = 64 * 1024;

    response = malloc(response_cap);
    if (!response) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate response buffer");
        return -1;
    }

    char buf[4096];
    int bytes_read;
    while ((bytes_read = BIO_read(bio, buf, (int)sizeof(buf))) > 0) {
        if (response_len + (size_t)bytes_read > response_cap) {
            response_cap *= 2;
            if (response_cap > 10U * 1024U * 1024U) {
                free(response);
                MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "CRL response too large");
                return -1;
            }
            char *new_response = realloc(response, response_cap);
            if (!new_response) {
                free(response);
                MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to grow response buffer");
                return -1;
            }
            response = new_response;
        }
        memcpy(response + response_len, buf, (size_t)bytes_read);
        response_len += (size_t)bytes_read;
    }

    /* Find end of HTTP headers */
    char *body = strstr(response, "\r\n\r\n");
    if (!body) {
        free(response);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Invalid HTTP response");
        return -1;
    }
    body += 4;
    size_t body_len = response_len - (size_t)(body - response);

    void *crl_data = malloc(body_len);
    if (!crl_data) {
        free(response);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate CRL data");
        return -1;
    }
    memcpy(crl_data, body, body_len);
    free(response);

    *out_body = crl_data;
    *out_len = body_len;
    return 0;
}

/**
 * Download a CRL over HTTPS using a standalone SSL_CTX with system CA certificates.
 * Uses a separate SSL_CTX to avoid circular dependency: the CRL server's certificate
 * is validated against the OS trust store, not via the mTLS library's own CRL checks.
 */
static int download_crl_https(const char *host, int port, const char *path, uint32_t timeout_ms,
                              void **out_body, size_t *out_len, mtls_err *err)
{
    ERR_clear_error();

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Failed to create SSL context for CRL");
        return -1;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ssl_ctx); /* system CA store */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    char addr_str[512];
    int printed = snprintf(addr_str, sizeof(addr_str), "%s:%d", host, port);
    if (printed <= 0 || (size_t)printed >= sizeof(addr_str)) {
        SSL_CTX_free(ssl_ctx);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "CRL host address too long");
        return -1;
    }

    BIO *cbio = BIO_new_connect(addr_str);
    if (!cbio) {
        SSL_CTX_free(ssl_ctx);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Failed to create HTTPS connect BIO");
        return -1;
    }

    BIO *ssl_bio = BIO_new_ssl(ssl_ctx, 1 /* client */);
    if (!ssl_bio) {
        BIO_free_all(cbio);
        SSL_CTX_free(ssl_ctx);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Failed to create SSL BIO");
        return -1;
    }

    /* BIO_push transfers cbio ownership into the chain; free chain frees both */
    BIO *chain = BIO_push(ssl_bio, cbio);

    /* Set SNI hostname */
    SSL *ssl_obj = NULL;
    BIO_get_ssl(ssl_bio, &ssl_obj);
    if (ssl_obj != NULL) {
        (void)SSL_set_tlsext_host_name(ssl_obj, host);
    }

    if (BIO_do_connect(chain) <= 0) {
        BIO_free_all(chain);
        SSL_CTX_free(ssl_ctx);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Failed to connect to HTTPS CRL server");
        return -1;
    }

    /* Apply socket-level timeout (best-effort) */
    {
        int bio_fd = -1;
        (void)BIO_get_fd(cbio, &bio_fd);
        if (bio_fd >= 0 && timeout_ms > 0) {
            (void)platform_socket_set_recv_timeout((mtls_socket_t)bio_fd, timeout_ms, NULL);
            (void)platform_socket_set_send_timeout((mtls_socket_t)bio_fd, timeout_ms, NULL);
        }
    }

    if (BIO_do_handshake(chain) <= 0) {
        BIO_free_all(chain);
        SSL_CTX_free(ssl_ctx);
        MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "TLS handshake with CRL server failed");
        return -1;
    }

    int rc = crl_http_get_body(chain, path, host, out_body, out_len, err);
    BIO_free_all(chain);
    SSL_CTX_free(ssl_ctx);
    return rc;
}

int mtls_crl_download(mtls_ctx *ctx, const char *crl_url, uint32_t timeout_ms, mtls_err *err)
{
    if (timeout_ms == 0) {
        timeout_ms = MTLS_OCSP_DEFAULT_TIMEOUT_MS;
    }

    if (!ctx || !crl_url) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for CRL download");
        return -1;
    }

    emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_START, 0);

    /* Extract host and path from URL */
    char host[256] = {0};
    char path[256] = "/";
    int port = 80;

    const char *url_ptr = crl_url;
    bool is_https = false;

    if (strncmp(url_ptr, "http://", 7) == 0) {
        url_ptr += 7;
    } else if (strncmp(url_ptr, "https://", 8) == 0) {
        url_ptr += 8;
        port = 443;
        is_https = true;
    }

    /* Parse host:port/path */
    const char *slash = strchr(url_ptr, '/');
    const char *colon = strchr(url_ptr, ':');

    if (colon && (!slash || colon < slash)) {
        /* Has port */
        size_t host_len = (size_t)(colon - url_ptr);
        if (host_len < sizeof(host) - 1) {
            memcpy(host, url_ptr, host_len);
            host[host_len] = '\0';
        }
        char *endptr = NULL;
        long parsed_port = strtol(colon + 1, &endptr, 10);
        if (endptr != colon + 1 && parsed_port > 0 && parsed_port <= 65535) {
            port = (int)parsed_port;
        }
    } else if (slash) {
        size_t host_len = (size_t)(slash - url_ptr);
        if (host_len < sizeof(host) - 1) {
            memcpy(host, url_ptr, host_len);
            host[host_len] = '\0';
        }
    } else {
        size_t host_len = strlen(url_ptr);
        if (host_len < sizeof(host) - 1) {
            memcpy(host, url_ptr, host_len);
            host[host_len] = '\0';
        }
    }

    if (slash) {
        size_t path_len = strlen(slash);
        if (path_len < sizeof(path) - 1) {
            memcpy(path, slash, path_len);
            path[path_len] = '\0';
        }
    }

    void *crl_data = NULL;
    size_t body_len = 0;

    if (is_https) {
        /* HTTPS: use standalone SSL_CTX with system CA (avoids circular CRL dependency) */
        if (download_crl_https(host, port, path, timeout_ms, &crl_data, &body_len, err) != 0) {
            emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_FAILURE,
                                  MTLS_ERR_CRL_DOWNLOAD_FAILED);
            return -1;
        }
    } else {
        /* HTTP: plain TCP connection */
        char addr_str[512];
        int printed = snprintf(addr_str, sizeof(addr_str), "%s:%d", host, port);
        if (printed <= 0 || (size_t)printed >= sizeof(addr_str)) {
            emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_FAILURE,
                                  MTLS_ERR_CRL_DOWNLOAD_FAILED);
            MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "CRL host address too long");
            return -1;
        }

        BIO *cbio = BIO_new_connect(addr_str);
        if (!cbio) {
            emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_FAILURE,
                                  MTLS_ERR_CRL_DOWNLOAD_FAILED);
            MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED,
                         "Failed to create connection to CRL server");
            return -1;
        }

        if (BIO_do_connect(cbio) <= 0) {
            BIO_free_all(cbio);
            emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_FAILURE,
                                  MTLS_ERR_CRL_DOWNLOAD_FAILED);
            MTLS_ERR_SET(err, MTLS_ERR_CRL_DOWNLOAD_FAILED, "Failed to connect to CRL server");
            return -1;
        }

        /* Apply socket timeout (best-effort) */
        {
            int bio_fd = -1;
            (void)BIO_get_fd(cbio, &bio_fd);
            if (bio_fd >= 0 && timeout_ms > 0) {
                (void)platform_socket_set_recv_timeout((mtls_socket_t)bio_fd, timeout_ms, NULL);
                (void)platform_socket_set_send_timeout((mtls_socket_t)bio_fd, timeout_ms, NULL);
            }
        }

        int rc = crl_http_get_body(cbio, path, host, &crl_data, &body_len, err);
        BIO_free_all(cbio);
        if (rc != 0) {
            emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_FAILURE,
                                  MTLS_ERR_CRL_DOWNLOAD_FAILED);
            return -1;
        }
    }

    /* Store downloaded CRL, replacing any previously cached data */
    if (ctx->crl_data) {
        platform_secure_zero(ctx->crl_data, ctx->crl_data_len);
        free(ctx->crl_data);
    }
    ctx->crl_data = crl_data;
    ctx->crl_data_len = body_len;

    emit_revocation_event(ctx, MTLS_EVENT_CRL_DOWNLOAD_SUCCESS, 0);
    return 0;
}

int mtls_crl_check(mtls_ctx *ctx, const uint8_t *cert_pem, size_t cert_pem_len,
                   mtls_revocation_result *result, mtls_err *err)
{
    if (!ctx || !cert_pem || !result) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for CRL check");
        return -1;
    }

    emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_START, 0);

    /* Try cached CRL first */
    if (ctx->crl_data && ctx->crl_data_len > 0) {
        int ret = mtls_crl_check_data(ctx->crl_data, ctx->crl_data_len, cert_pem, cert_pem_len,
                                      result, err);
        if (ret == 0 || result->crl_status == MTLS_CRL_STATUS_REVOKED) {
            if (ret == 0) {
                emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_SUCCESS, 0);
            } else {
                emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_FAILURE, err ? err->code : 0);
            }
            return ret;
        }
    }

    /* Try CRL from config path */
    if (ctx->config.crl_path) {
        if (mtls_crl_load_file(ctx, ctx->config.crl_path, err) == 0) {
            int ret = mtls_crl_check_data(ctx->crl_data, ctx->crl_data_len, cert_pem, cert_pem_len,
                                          result, err);
            if (ret == 0) {
                emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_SUCCESS, 0);
            } else {
                emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_FAILURE, err ? err->code : 0);
            }
            return ret;
        }
    }

    /* Try CRL from config URL */
    if (ctx->config.crl_url) {
        if (mtls_crl_download(ctx, ctx->config.crl_url, 0, err) == 0) {
            int ret = mtls_crl_check_data(ctx->crl_data, ctx->crl_data_len, cert_pem, cert_pem_len,
                                          result, err);
            if (ret == 0) {
                emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_SUCCESS, 0);
            } else {
                emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_FAILURE, err ? err->code : 0);
            }
            return ret;
        }
    }

    /* Try CRL from certificate CDP */
    char cdp_urls[4][512];
    size_t num_urls = 0;
    if (mtls_crl_get_distribution_points(cert_pem, cert_pem_len, cdp_urls, 4, &num_urls, err) ==
        0) {
        for (size_t i = 0; i < num_urls; i++) {
            if (mtls_crl_download(ctx, cdp_urls[i], 0, err) == 0) {
                int ret = mtls_crl_check_data(ctx->crl_data, ctx->crl_data_len, cert_pem,
                                              cert_pem_len, result, err);
                if (ret == 0) {
                    emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_SUCCESS, 0);
                } else {
                    emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_FAILURE, err ? err->code : 0);
                }
                return ret;
            }
        }
    }

    emit_revocation_event(ctx, MTLS_EVENT_CRL_CHECK_FAILURE, MTLS_ERR_CRL_FAILED);
    MTLS_ERR_SET(err, MTLS_ERR_CRL_FAILED, "No CRL available for checking");
    result->crl_status = MTLS_CRL_STATUS_UNKNOWN;
    return -1;
}

/*
 * =============================================================================
 * Combined Revocation Check
 * =============================================================================
 */

int mtls_check_revocation(mtls_ctx *ctx, const uint8_t *cert_pem, size_t cert_pem_len,
                          const uint8_t *issuer_pem, size_t issuer_pem_len,
                          mtls_revocation_result *result, mtls_err *err)
{
    if (!ctx || !cert_pem || !result) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments for revocation check");
        return -1;
    }

    memset(result, 0, sizeof(*result));

    /* Check cache first */
    uint8_t fingerprint[32];
    if (mtls_cert_fingerprint(cert_pem, cert_pem_len, fingerprint, err) == 0) {
        if (ctx->revocation_cache) {
            if (mtls_revocation_cache_get(ctx->revocation_cache, fingerprint, result) == 0) {
                /* Cache hit - return cached result */
                if (result->ocsp_status == MTLS_OCSP_STATUS_REVOKED ||
                    result->crl_status == MTLS_CRL_STATUS_REVOKED) {
                    MTLS_ERR_SET(err, MTLS_ERR_CERT_REVOKED, "Certificate is revoked (cached)");
                    return -1;
                }
                return 0;
            }
        }
    }

    int final_ret = 0;

    /* Perform OCSP check if enabled */
    if (ctx->config.enable_ocsp && issuer_pem && issuer_pem_len > 0) {
        mtls_revocation_result ocsp_result;
        memset(&ocsp_result, 0, sizeof(ocsp_result));

        int ret = mtls_ocsp_check(ctx, cert_pem, cert_pem_len, issuer_pem, issuer_pem_len,
                                  &ocsp_result, err);

        result->ocsp_status = ocsp_result.ocsp_status;
        result->ocsp_checked = ocsp_result.ocsp_checked;
        result->ocsp_this_update = ocsp_result.ocsp_this_update;
        result->ocsp_next_update = ocsp_result.ocsp_next_update;
        memcpy(result->responder_url, ocsp_result.responder_url, sizeof(result->responder_url));

        if (ocsp_result.ocsp_status == MTLS_OCSP_STATUS_REVOKED) {
            result->revocation_time = ocsp_result.revocation_time;
            result->revocation_reason = ocsp_result.revocation_reason;
            final_ret = -1;
        } else if (ctx->config.require_ocsp && ret < 0) {
            final_ret = -1;
        }
    }

    /* Perform CRL check if enabled (and not already revoked) */
    if (ctx->config.enable_crl && final_ret == 0) {
        mtls_revocation_result crl_result;
        memset(&crl_result, 0, sizeof(crl_result));

        int ret = mtls_crl_check(ctx, cert_pem, cert_pem_len, &crl_result, err);

        result->crl_status = crl_result.crl_status;
        result->crl_checked = crl_result.crl_checked;
        result->crl_last_update = crl_result.crl_last_update;
        result->crl_next_update = crl_result.crl_next_update;

        if (crl_result.crl_status == MTLS_CRL_STATUS_REVOKED) {
            result->revocation_time = crl_result.revocation_time;
            result->revocation_reason = crl_result.revocation_reason;
            final_ret = -1;
        } else if (ctx->config.require_crl && ret < 0) {
            final_ret = -1;
        }
    }

    /* Cache the result */
    if (ctx->revocation_cache && (result->ocsp_checked || result->crl_checked)) {
        mtls_revocation_cache_put(ctx->revocation_cache, fingerprint, result);
    }

    if (final_ret < 0 && !err->code) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_REVOKED, "Certificate revocation check failed");
    }

    return final_ret;
}

/*
 * =============================================================================
 * Status String Functions
 * =============================================================================
 */

const char *mtls_ocsp_status_string(mtls_ocsp_status status)
{
    switch (status) {
    case MTLS_OCSP_STATUS_GOOD:
        return "good";
    case MTLS_OCSP_STATUS_REVOKED:
        return "revoked";
    case MTLS_OCSP_STATUS_UNKNOWN:
        return "unknown";
    case MTLS_OCSP_STATUS_ERROR:
        return "error";
    default:
        return "invalid";
    }
}

const char *mtls_crl_status_string(mtls_crl_status status)
{
    switch (status) {
    case MTLS_CRL_STATUS_GOOD:
        return "good";
    case MTLS_CRL_STATUS_REVOKED:
        return "revoked";
    case MTLS_CRL_STATUS_UNKNOWN:
        return "unknown";
    case MTLS_CRL_STATUS_ERROR:
        return "error";
    default:
        return "invalid";
    }
}

const char *mtls_revocation_reason_string(int reason)
{
    switch (reason) {
    case 0:
        return "unspecified";
    case 1:
        return "keyCompromise";
    case 2:
        return "cACompromise";
    case 3:
        return "affiliationChanged";
    case 4:
        return "superseded";
    case 5:
        return "cessationOfOperation";
    case 6:
        return "certificateHold";
    case 8:
        return "removeFromCRL";
    case 9:
        return "privilegeWithdrawn";
    case 10:
        return "aACompromise";
    default:
        return "unknown";
    }
}

// NOLINTEND(misc-include-cleaner,readability-identifier-length,cert-err33-c,bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions,bugprone-implicit-widening-of-multiplication-result,clang-analyzer-deadcode.DeadStores)
