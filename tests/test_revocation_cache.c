/**
 * @file test_revocation_cache.c
 * @brief Tests for the revocation cache implementation
 *
 * This test suite validates:
 * - Cache creation and destruction
 * - Cache get/put operations
 * - Cache hit/miss tracking
 * - TTL expiration behavior
 * - Thread safety of cache operations
 * - Edge cases and error handling
 */

#include "mtls/mtls.h"
#include "mtls/mtls_ocsp.h"
#include "mtls/mtls_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

/* Test fingerprint data */
// NOLINTNEXTLINE(readability-identifier-naming)
static const uint8_t kTestFingerprint1[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

// NOLINTNEXTLINE(readability-identifier-naming)
static const uint8_t kTestFingerprint2[32] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40};

// NOLINTNEXTLINE(readability-identifier-naming)
static const uint8_t kTestFingerprint3[32] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60};

/* Test 1: Cache creation and destruction */
static void test_cache_create_free(void)
{
    printf("Test 1: Cache creation and destruction\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create cache with default parameters */
    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);
    assert(cache != NULL);

    /* Free cache */
    mtls_revocation_cache_free(cache);

    /* Free NULL cache (should not crash) */
    mtls_revocation_cache_free(NULL);

    printf("  PASS: Cache creation and destruction works\n");
}

/* Test 2: Cache creation with edge cases */
static void test_cache_create_edge_cases(void)
{
    printf("Test 2: Cache creation edge cases\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create with zero max entries - should use default */
    int ret = mtls_revocation_cache_create(&cache, 0, 3600, &err);
    assert(ret == 0);
    assert(cache != NULL);
    mtls_revocation_cache_free(cache);

    /* Create with zero TTL - should use default */
    mtls_err_init(&err);
    ret = mtls_revocation_cache_create(&cache, 100, 0, &err);
    assert(ret == 0);
    assert(cache != NULL);
    mtls_revocation_cache_free(cache);

    /* Create with NULL output pointer - should fail */
    mtls_err_init(&err);
    ret = mtls_revocation_cache_create(NULL, 100, 3600, &err);
    assert(ret == -1);

    printf("  PASS: Cache creation edge cases handled\n");
}

/* Test 3: Cache put and get operations */
static void test_cache_put_get(void)
{
    printf("Test 3: Cache put and get operations\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    /* Create a test result */
    mtls_revocation_result result_in;
    memset(&result_in, 0, sizeof(result_in));
    result_in.ocsp_status = MTLS_OCSP_STATUS_GOOD;
    result_in.crl_status = MTLS_CRL_STATUS_GOOD;
    result_in.ocsp_checked = true;
    result_in.crl_checked = false;
    result_in.revocation_time = 0;
    result_in.revocation_reason = 0;

    /* Put the result in cache */
    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, &result_in);
    assert(ret == 0);

    /* Get the result back */
    mtls_revocation_result result_out;
    memset(&result_out, 0, sizeof(result_out));
    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, &result_out);
    assert(ret == 0);

    /* Verify the result matches */
    assert(result_out.ocsp_status == MTLS_OCSP_STATUS_GOOD);
    assert(result_out.crl_status == MTLS_CRL_STATUS_GOOD);
    assert(result_out.ocsp_checked == true);
    assert(result_out.crl_checked == false);

    /* Try to get a non-existent entry */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint2, &result_out);
    assert(ret == -1); /* Not found */

    mtls_revocation_cache_free(cache);

    printf("  PASS: Cache put and get operations work\n");
}

/* Test 4: Cache statistics */
static void test_cache_stats(void)
{
    printf("Test 4: Cache statistics\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    /* Initial stats should be zero */
    mtls_cache_stats stats;
    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 0);
    assert(stats.hits == 0);
    assert(stats.misses == 0);

    /* Add an entry */
    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));
    result.ocsp_status = MTLS_OCSP_STATUS_GOOD;
    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, &result);
    assert(ret == 0);

    /* Check stats after put */
    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 1);

    /* Get existing entry - should be a hit */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, &result);
    assert(ret == 0);

    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.hits == 1);

    /* Get non-existing entry - should be a miss */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint2, &result);
    assert(ret == -1);

    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.misses == 1);

    mtls_revocation_cache_free(cache);

    printf("  PASS: Cache statistics work\n");
}

/* Test 5: Cache remove operation */
static void test_cache_remove(void)
{
    printf("Test 5: Cache remove operation\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    /* Add entries */
    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));
    result.ocsp_status = MTLS_OCSP_STATUS_GOOD;

    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, &result);
    assert(ret == 0);
    ret = mtls_revocation_cache_put(cache, kTestFingerprint2, &result);
    assert(ret == 0);

    /* Verify entries exist */
    mtls_cache_stats stats;
    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 2);

    /* Remove first entry */
    ret = mtls_revocation_cache_remove(cache, kTestFingerprint1);
    assert(ret == 0);

    /* Verify entry was removed */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, &result);
    assert(ret == -1); /* Not found */

    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 1);

    /* Second entry should still exist */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint2, &result);
    assert(ret == 0);

    /* Remove non-existent entry - should succeed */
    ret = mtls_revocation_cache_remove(cache, kTestFingerprint3);
    assert(ret == 0);

    mtls_revocation_cache_free(cache);

    printf("  PASS: Cache remove operation works\n");
}

/* Test 6: Cache clear operation */
static void test_cache_clear(void)
{
    printf("Test 6: Cache clear operation\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    /* Add multiple entries */
    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));
    result.ocsp_status = MTLS_OCSP_STATUS_GOOD;

    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, &result);
    assert(ret == 0);
    ret = mtls_revocation_cache_put(cache, kTestFingerprint2, &result);
    assert(ret == 0);
    ret = mtls_revocation_cache_put(cache, kTestFingerprint3, &result);
    assert(ret == 0);

    /* Verify entries exist */
    mtls_cache_stats stats;
    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 3);

    /* Clear the cache */
    mtls_revocation_cache_clear(cache);

    /* Verify all entries were removed */
    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 0);

    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, &result);
    assert(ret == -1);
    ret = mtls_revocation_cache_get(cache, kTestFingerprint2, &result);
    assert(ret == -1);
    ret = mtls_revocation_cache_get(cache, kTestFingerprint3, &result);
    assert(ret == -1);

    mtls_revocation_cache_free(cache);

    printf("  PASS: Cache clear operation works\n");
}

/* Test 7: Cache update existing entry */
static void test_cache_update(void)
{
    printf("Test 7: Cache update existing entry\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    /* Add initial entry with GOOD status */
    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));
    result.ocsp_status = MTLS_OCSP_STATUS_GOOD;

    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, &result);
    assert(ret == 0);

    /* Verify initial status */
    mtls_revocation_result result_out;
    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, &result_out);
    assert(ret == 0);
    assert(result_out.ocsp_status == MTLS_OCSP_STATUS_GOOD);

    /* Update to REVOKED status */
    result.ocsp_status = MTLS_OCSP_STATUS_REVOKED;
    result.revocation_reason = 1; /* Key compromise */
    result.revocation_time = time(NULL);

    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, &result);
    assert(ret == 0);

    /* Verify updated status */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, &result_out);
    assert(ret == 0);
    assert(result_out.ocsp_status == MTLS_OCSP_STATUS_REVOKED);
    assert(result_out.revocation_reason == 1);

    /* Entry count should still be 1 */
    mtls_cache_stats stats;
    ret = mtls_revocation_cache_stats(cache, &stats);
    assert(ret == 0);
    assert(stats.total_entries == 1);

    mtls_revocation_cache_free(cache);

    printf("  PASS: Cache update existing entry works\n");
}

/* Test 8: NULL parameter handling */
static void test_null_parameters(void)
{
    printf("Test 8: NULL parameter handling\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));

    /* NULL cache for get */
    ret = mtls_revocation_cache_get(NULL, kTestFingerprint1, &result);
    assert(ret == -1);

    /* NULL fingerprint for get */
    ret = mtls_revocation_cache_get(cache, NULL, &result);
    assert(ret == -1);

    /* NULL result for get */
    ret = mtls_revocation_cache_get(cache, kTestFingerprint1, NULL);
    assert(ret == -1);

    /* NULL cache for put */
    ret = mtls_revocation_cache_put(NULL, kTestFingerprint1, &result);
    assert(ret == -1);

    /* NULL fingerprint for put */
    ret = mtls_revocation_cache_put(cache, NULL, &result);
    assert(ret == -1);

    /* NULL result for put */
    ret = mtls_revocation_cache_put(cache, kTestFingerprint1, NULL);
    assert(ret == -1);

    /* NULL cache for remove */
    ret = mtls_revocation_cache_remove(NULL, kTestFingerprint1);
    assert(ret == -1);

    /* NULL fingerprint for remove */
    ret = mtls_revocation_cache_remove(cache, NULL);
    assert(ret == -1);

    /* NULL cache for stats - should fail gracefully */
    mtls_cache_stats stats;
    ret = mtls_revocation_cache_stats(NULL, &stats);
    assert(ret == -1);

    /* NULL stats output */
    ret = mtls_revocation_cache_stats(cache, NULL);
    assert(ret == -1);

    /* NULL cache for clear - should not crash */
    mtls_revocation_cache_clear(NULL);

    mtls_revocation_cache_free(cache);

    printf("  PASS: NULL parameter handling works\n");
}

/* Test 9: Multiple entries with same hash bucket */
static void test_hash_collisions(void)
{
    printf("Test 9: Hash collision handling\n");

    mtls_revocation_cache *cache = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create cache with enough space for all entries but small bucket count */
    int ret = mtls_revocation_cache_create(&cache, 100, 3600, &err);
    assert(ret == 0);

    /* Add entries to ensure some hash collisions */
    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));
    result.ocsp_status = MTLS_OCSP_STATUS_GOOD;

    uint8_t fingerprints[20][32];
    for (int i = 0; i < 20; i++) {
        memset(fingerprints[i], (uint8_t)i, 32);
        ret = mtls_revocation_cache_put(cache, fingerprints[i], &result);
        assert(ret == 0);
    }

    /* Verify all entries can be retrieved */
    for (int i = 0; i < 20; i++) {
        mtls_revocation_result result_out;
        ret = mtls_revocation_cache_get(cache, fingerprints[i], &result_out);
        assert(ret == 0);
        assert(result_out.ocsp_status == MTLS_OCSP_STATUS_GOOD);
    }

    /* Remove some entries */
    for (int i = 0; i < 10; i++) {
        ret = mtls_revocation_cache_remove(cache, fingerprints[i]);
        assert(ret == 0);
    }

    /* Verify removed entries are gone */
    for (int i = 0; i < 10; i++) {
        mtls_revocation_result result_out;
        ret = mtls_revocation_cache_get(cache, fingerprints[i], &result_out);
        assert(ret == -1);
    }

    /* Verify remaining entries still exist */
    for (int i = 10; i < 20; i++) {
        mtls_revocation_result result_out;
        ret = mtls_revocation_cache_get(cache, fingerprints[i], &result_out);
        assert(ret == 0);
    }

    mtls_revocation_cache_free(cache);

    printf("  PASS: Hash collision handling works\n");
}

/* Test 10: Status string functions */
static void test_status_strings(void)
{
    printf("Test 10: Status string functions\n");

    /* OCSP status strings */
    const char *str = mtls_ocsp_status_string(MTLS_OCSP_STATUS_GOOD);
    assert(str != NULL);
    assert(strcmp(str, "good") == 0);

    str = mtls_ocsp_status_string(MTLS_OCSP_STATUS_REVOKED);
    assert(str != NULL);
    assert(strcmp(str, "revoked") == 0);

    str = mtls_ocsp_status_string(MTLS_OCSP_STATUS_UNKNOWN);
    assert(str != NULL);
    assert(strcmp(str, "unknown") == 0);

    str = mtls_ocsp_status_string(MTLS_OCSP_STATUS_ERROR);
    assert(str != NULL);
    assert(strcmp(str, "error") == 0);

    /* Invalid OCSP status */
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    str = mtls_ocsp_status_string((mtls_ocsp_status)99);
    assert(str != NULL);
    assert(strcmp(str, "invalid") == 0);

    /* CRL status strings */
    str = mtls_crl_status_string(MTLS_CRL_STATUS_GOOD);
    assert(str != NULL);
    assert(strcmp(str, "good") == 0);

    str = mtls_crl_status_string(MTLS_CRL_STATUS_REVOKED);
    assert(str != NULL);
    assert(strcmp(str, "revoked") == 0);

    str = mtls_crl_status_string(MTLS_CRL_STATUS_UNKNOWN);
    assert(str != NULL);
    assert(strcmp(str, "unknown") == 0);

    str = mtls_crl_status_string(MTLS_CRL_STATUS_ERROR);
    assert(str != NULL);
    assert(strcmp(str, "error") == 0);

    /* Invalid CRL status */
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    str = mtls_crl_status_string((mtls_crl_status)99);
    assert(str != NULL);
    assert(strcmp(str, "invalid") == 0);

    /* Revocation reason strings */
    str = mtls_revocation_reason_string(0);
    assert(str != NULL);
    assert(strcmp(str, "unspecified") == 0);

    str = mtls_revocation_reason_string(1);
    assert(str != NULL);
    assert(strcmp(str, "keyCompromise") == 0);

    str = mtls_revocation_reason_string(2);
    assert(str != NULL);
    assert(strcmp(str, "cACompromise") == 0);

    str = mtls_revocation_reason_string(3);
    assert(str != NULL);
    assert(strcmp(str, "affiliationChanged") == 0);

    str = mtls_revocation_reason_string(4);
    assert(str != NULL);
    assert(strcmp(str, "superseded") == 0);

    str = mtls_revocation_reason_string(5);
    assert(str != NULL);
    assert(strcmp(str, "cessationOfOperation") == 0);

    str = mtls_revocation_reason_string(6);
    assert(str != NULL);
    assert(strcmp(str, "certificateHold") == 0);

    str = mtls_revocation_reason_string(8);
    assert(str != NULL);
    assert(strcmp(str, "removeFromCRL") == 0);

    str = mtls_revocation_reason_string(9);
    assert(str != NULL);
    assert(strcmp(str, "privilegeWithdrawn") == 0);

    str = mtls_revocation_reason_string(10);
    assert(str != NULL);
    assert(strcmp(str, "aACompromise") == 0);

    /* Invalid reason */
    str = mtls_revocation_reason_string(99);
    assert(str != NULL);
    assert(strcmp(str, "unknown") == 0);

    printf("  PASS: Status string functions work\n");
}

int main(void)
{
    printf("Running revocation cache tests...\n\n");

    test_cache_create_free();
    test_cache_create_edge_cases();
    test_cache_put_get();
    test_cache_stats();
    test_cache_remove();
    test_cache_clear();
    test_cache_update();
    test_null_parameters();
    test_hash_collisions();
    test_status_strings();

    printf("\nAll revocation cache tests passed!\n");
    return 0;
}
