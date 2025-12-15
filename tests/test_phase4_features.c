/**
 * @file test_phase4_features.c
 * @brief Tests for Phase 4 features: constant-time comparison, certificate reload
 */

#include "mtls/mtls.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_config.h"
#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Test framework macros */
#define TEST_ASSERT(condition, msg) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg); \
            return false; \
        } \
    } while (0)

#define TEST_RUN(name) \
    do { \
        printf("Running test: %s\n", #name); \
        if (test_##name()) { \
            printf("  PASS: %s\n", #name); \
            passed++; \
        } else { \
            printf("  FAIL: %s\n", #name); \
            failed++; \
        } \
    } while (0)

/* Test counters */
static int passed = 0;
static int failed = 0;

/* ============================================================================
 * Constant-Time String Comparison Tests
 * ============================================================================ */

/**
 * Test 1: Basic string equality
 */
static bool test_consttime_strcmp_equal(void) {
    const char* str1 = "hello";
    const char* str2 = "hello";

    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result == 0, "Equal strings should return 0");

    return true;
}

/**
 * Test 2: String inequality
 */
static bool test_consttime_strcmp_not_equal(void) {
    const char* str1 = "hello";
    const char* str2 = "world";

    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result != 0, "Different strings should return non-zero");

    return true;
}

/**
 * Test 3: Empty strings
 */
static bool test_consttime_strcmp_empty(void) {
    const char* str1 = "";
    const char* str2 = "";

    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result == 0, "Empty strings should be equal");

    /* One empty, one not */
    const char* str3 = "hello";
    result = platform_consttime_strcmp(str1, str3);
    TEST_ASSERT(result != 0, "Empty vs non-empty should not be equal");

    return true;
}

/**
 * Test 4: NULL pointer handling
 */
static bool test_consttime_strcmp_null(void) {
    const char* str = "hello";

    /* Both NULL should be considered equal */
    int result = platform_consttime_strcmp(NULL, NULL);
    TEST_ASSERT(result == 0, "NULL == NULL should return 0");

    /* One NULL should not equal non-NULL */
    result = platform_consttime_strcmp(str, NULL);
    TEST_ASSERT(result != 0, "String vs NULL should not be equal");

    result = platform_consttime_strcmp(NULL, str);
    TEST_ASSERT(result != 0, "NULL vs String should not be equal");

    return true;
}

/**
 * Test 5: Different length strings
 */
static bool test_consttime_strcmp_different_lengths(void) {
    const char* short_str = "hi";
    const char* long_str = "hello";

    int result = platform_consttime_strcmp(short_str, long_str);
    TEST_ASSERT(result != 0, "Different length strings should not be equal");

    return true;
}

/**
 * Test 6: Case sensitivity
 */
static bool test_consttime_strcmp_case_sensitive(void) {
    const char* lower = "hello";
    const char* upper = "HELLO";

    int result = platform_consttime_strcmp(lower, upper);
    TEST_ASSERT(result != 0, "Comparison should be case-sensitive");

    return true;
}

/**
 * Test 7: Strings with special characters
 */
static bool test_consttime_strcmp_special_chars(void) {
    const char* str1 = "hello@world!";
    const char* str2 = "hello@world!";
    const char* str3 = "hello@world?";

    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result == 0, "Equal strings with special chars should return 0");

    result = platform_consttime_strcmp(str1, str3);
    TEST_ASSERT(result != 0, "Different special chars should not be equal");

    return true;
}

/**
 * Test 8: Long strings (within safety limit)
 */
static bool test_consttime_strcmp_long_strings(void) {
    /* Create strings within the 10000 character safety limit */
    char long_str1[5000];
    char long_str2[5000];

    memset(long_str1, 'A', sizeof(long_str1) - 1);
    long_str1[sizeof(long_str1) - 1] = '\0';

    memcpy(long_str2, long_str1, sizeof(long_str2));

    /* Should work correctly within the limit */
    int result = platform_consttime_strcmp(long_str1, long_str2);
    TEST_ASSERT(result == 0, "Long equal strings should return 0");

    /* Make one character different near the end */
    long_str2[4900] = 'B';
    result = platform_consttime_strcmp(long_str1, long_str2);
    TEST_ASSERT(result != 0, "Long different strings should not be equal");

    /* Make one character different at the beginning */
    memcpy(long_str2, long_str1, sizeof(long_str2));
    long_str2[0] = 'B';
    result = platform_consttime_strcmp(long_str1, long_str2);
    TEST_ASSERT(result != 0, "Difference at start should be detected");

    /* Make one character different in the middle */
    memcpy(long_str2, long_str1, sizeof(long_str2));
    long_str2[2500] = 'B';
    result = platform_consttime_strcmp(long_str1, long_str2);
    TEST_ASSERT(result != 0, "Difference in middle should be detected");

    return true;
}

/**
 * Test 9: String at maximum allowed length (boundary test)
 */
static bool test_consttime_strcmp_max_length(void) {
    /* MTLS_MAX_IDENTITY_LEN = 10000, so create strings of exactly that length */
    char* max_str1 = (char*)malloc(MTLS_MAX_IDENTITY_LEN + 1);
    char* max_str2 = (char*)malloc(MTLS_MAX_IDENTITY_LEN + 1);
    TEST_ASSERT(max_str1 && max_str2, "Memory allocation should succeed");

    /* Fill with 'A' characters up to the maximum length */
    memset(max_str1, 'A', MTLS_MAX_IDENTITY_LEN);
    max_str1[MTLS_MAX_IDENTITY_LEN] = '\0';
    memcpy(max_str2, max_str1, MTLS_MAX_IDENTITY_LEN + 1);

    /* Strings at exactly the limit should work correctly */
    int result = platform_consttime_strcmp(max_str1, max_str2);
    TEST_ASSERT(result == 0, "Strings at max length should be comparable when equal");

    /* Make one character different */
    max_str2[MTLS_MAX_IDENTITY_LEN - 1] = 'B';
    result = platform_consttime_strcmp(max_str1, max_str2);
    TEST_ASSERT(result != 0 && result != -1, "Strings at max length should be comparable when different");

    free(max_str1);
    free(max_str2);

    return true;
}

/**
 * Test 10: Oversized strings (should be rejected)
 */
static bool test_consttime_strcmp_oversized(void) {
    /* Create strings that exceed MTLS_MAX_IDENTITY_LEN */
    size_t oversized_len = MTLS_MAX_IDENTITY_LEN + 100;
    char* oversized_str1 = (char*)malloc(oversized_len + 1);
    char* oversized_str2 = (char*)malloc(oversized_len + 1);
    TEST_ASSERT(oversized_str1 && oversized_str2, "Memory allocation should succeed");

    memset(oversized_str1, 'A', oversized_len);
    oversized_str1[oversized_len] = '\0';
    memcpy(oversized_str2, oversized_str1, oversized_len + 1);

    /* Oversized strings should return -1 (error) even when equal */
    int result = platform_consttime_strcmp(oversized_str1, oversized_str2);
    TEST_ASSERT(result == -1, "Oversized equal strings should return -1 (error)");

    /* Oversized strings should also return -1 when different */
    oversized_str2[0] = 'B';
    result = platform_consttime_strcmp(oversized_str1, oversized_str2);
    TEST_ASSERT(result == -1, "Oversized different strings should return -1 (error)");

    free(oversized_str1);
    free(oversized_str2);

    return true;
}

/**
 * Test 11: Asymmetric oversized strings
 */
static bool test_consttime_strcmp_asymmetric_oversized(void) {
    /* One normal string, one oversized */
    const char* normal_str = "hello";
    size_t oversized_len = MTLS_MAX_IDENTITY_LEN + 100;
    char* oversized_str = (char*)malloc(oversized_len + 1);
    TEST_ASSERT(oversized_str, "Memory allocation should succeed");

    memset(oversized_str, 'A', oversized_len);
    oversized_str[oversized_len] = '\0';

    /* Should reject when first string is oversized */
    int result = platform_consttime_strcmp(oversized_str, normal_str);
    TEST_ASSERT(result == -1, "Oversized first string should return -1");

    /* Should reject when second string is oversized */
    result = platform_consttime_strcmp(normal_str, oversized_str);
    TEST_ASSERT(result == -1, "Oversized second string should return -1");

    free(oversized_str);

    return true;
}

/* ============================================================================
 * Constant-Time Memory Comparison Tests
 * ============================================================================ */

/**
 * Test 12: Basic memory equality
 */
static bool test_consttime_memcmp_equal(void) {
    const unsigned char data1[] = {0x01, 0x02, 0x03, 0x04};
    const unsigned char data2[] = {0x01, 0x02, 0x03, 0x04};

    int result = platform_consttime_memcmp(data1, data2, sizeof(data1));
    TEST_ASSERT(result == 0, "Equal memory regions should return 0");

    return true;
}

/**
 * Test 13: Memory inequality
 */
static bool test_consttime_memcmp_not_equal(void) {
    const unsigned char data1[] = {0x01, 0x02, 0x03, 0x04};
    const unsigned char data2[] = {0x01, 0x02, 0x03, 0x05};

    int result = platform_consttime_memcmp(data1, data2, sizeof(data1));
    TEST_ASSERT(result != 0, "Different memory regions should return non-zero");

    return true;
}

/**
 * Test 14: Zero-length comparison
 */
static bool test_consttime_memcmp_zero_length(void) {
    const unsigned char data1[] = {0x01, 0x02};
    const unsigned char data2[] = {0x03, 0x04};

    int result = platform_consttime_memcmp(data1, data2, 0);
    TEST_ASSERT(result == 0, "Zero-length comparison should return 0");

    return true;
}

/**
 * Test 15: NULL pointer handling in memcmp
 */
static bool test_consttime_memcmp_null(void) {
    const unsigned char data[] = {0x01, 0x02};

    /* Both NULL should be considered equal */
    int result = platform_consttime_memcmp(NULL, NULL, 10);
    TEST_ASSERT(result == 0, "NULL == NULL should return 0");

    /* One NULL should not equal non-NULL */
    result = platform_consttime_memcmp(data, NULL, sizeof(data));
    TEST_ASSERT(result != 0, "Data vs NULL should not be equal");

    result = platform_consttime_memcmp(NULL, data, sizeof(data));
    TEST_ASSERT(result != 0, "NULL vs Data should not be equal");

    return true;
}

/**
 * Test 16: Difference at different positions
 */
static bool test_consttime_memcmp_diff_positions(void) {
    const unsigned char data1[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char data2[5];

    /* Test difference at each position */
    for (size_t i = 0; i < sizeof(data1); i++) {
        memcpy(data2, data1, sizeof(data1));
        data2[i] ^= 0xFF;  /* Flip all bits at position i */

        int result = platform_consttime_memcmp(data1, data2, sizeof(data1));
        TEST_ASSERT(result != 0, "Difference at any position should be detected");
    }

    return true;
}

/**
 * Test 17: All-zeros vs all-ones
 */
static bool test_consttime_memcmp_extremes(void) {
    unsigned char zeros[16];
    unsigned char ones[16];

    memset(zeros, 0x00, sizeof(zeros));
    memset(ones, 0xFF, sizeof(ones));

    int result = platform_consttime_memcmp(zeros, ones, sizeof(zeros));
    TEST_ASSERT(result != 0, "All-zeros vs all-ones should not be equal");

    result = platform_consttime_memcmp(zeros, zeros, sizeof(zeros));
    TEST_ASSERT(result == 0, "All-zeros should equal all-zeros");

    result = platform_consttime_memcmp(ones, ones, sizeof(ones));
    TEST_ASSERT(result == 0, "All-ones should equal all-ones");

    return true;
}

/**
 * Test 18: Large memory blocks
 */
static bool test_consttime_memcmp_large_blocks(void) {
    size_t size = 10000;
    unsigned char* data1 = (unsigned char*)malloc(size);
    unsigned char* data2 = (unsigned char*)malloc(size);

    TEST_ASSERT(data1 && data2, "Memory allocation should succeed");

    /* Fill with pseudo-random data */
    for (size_t i = 0; i < size; i++) {
        data1[i] = (unsigned char)(i & 0xFF);
    }
    memcpy(data2, data1, size);

    int result = platform_consttime_memcmp(data1, data2, size);
    TEST_ASSERT(result == 0, "Large equal blocks should return 0");

    /* Make one byte different */
    data2[size / 2] ^= 0x01;
    result = platform_consttime_memcmp(data1, data2, size);
    TEST_ASSERT(result != 0, "Large blocks with one difference should not be equal");

    free(data1);
    free(data2);

    return true;
}

/* ============================================================================
 * Certificate Reload Tests
 * ============================================================================ */

/**
 * Test 19: Certificate reload with NULL context
 */
static bool test_cert_reload_null_context(void) {
    mtls_config config;
    mtls_config_init(&config);

    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_ctx_reload_certs(NULL, &err);
    TEST_ASSERT(result == -1, "NULL context should fail");
    TEST_ASSERT(err.code == MTLS_ERR_INVALID_ARGUMENT, "Should return INVALID_ARGUMENT error");

    return true;
}

/**
 * Test 20: SAN validation with NULL identity
 */
static bool test_san_validation_null_identity(void) {
    const char* allowed_sans[] = {"example.com"};

    bool result = mtls_validate_peer_sans(NULL, allowed_sans, 1);
    TEST_ASSERT(result == false, "NULL identity should return false");

    return true;
}

/**
 * Test 21: SAN validation with NULL allowed list
 */
static bool test_san_validation_null_allowed(void) {
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));

    bool result = mtls_validate_peer_sans(&identity, NULL, 1);
    TEST_ASSERT(result == false, "NULL allowed list should return false");

    return true;
}

/**
 * Test 22: SAN validation with zero count
 */
static bool test_san_validation_zero_count(void) {
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));

    const char* allowed_sans[] = {"example.com"};

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 0);
    TEST_ASSERT(result == false, "Zero count should return false");

    return true;
}

/**
 * Test 23: SAN validation with empty identity SANs
 */
static bool test_san_validation_empty_sans(void) {
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));
    identity.san_count = 0;
    identity.sans = NULL;

    const char* allowed_sans[] = {"example.com"};

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    TEST_ASSERT(result == false, "Empty SANs should return false");

    return true;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */
int main(void) {
    printf("========================================\n");
    printf("Phase 4 Features Test Suite\n");
    printf("========================================\n\n");

    /* Constant-time string comparison tests */
    printf("--- Constant-Time String Comparison ---\n");
    TEST_RUN(consttime_strcmp_equal);
    TEST_RUN(consttime_strcmp_not_equal);
    TEST_RUN(consttime_strcmp_empty);
    TEST_RUN(consttime_strcmp_null);
    TEST_RUN(consttime_strcmp_different_lengths);
    TEST_RUN(consttime_strcmp_case_sensitive);
    TEST_RUN(consttime_strcmp_special_chars);
    TEST_RUN(consttime_strcmp_long_strings);
    TEST_RUN(consttime_strcmp_max_length);
    TEST_RUN(consttime_strcmp_oversized);
    TEST_RUN(consttime_strcmp_asymmetric_oversized);

    /* Constant-time memory comparison tests */
    printf("\n--- Constant-Time Memory Comparison ---\n");
    TEST_RUN(consttime_memcmp_equal);
    TEST_RUN(consttime_memcmp_not_equal);
    TEST_RUN(consttime_memcmp_zero_length);
    TEST_RUN(consttime_memcmp_null);
    TEST_RUN(consttime_memcmp_diff_positions);
    TEST_RUN(consttime_memcmp_extremes);
    TEST_RUN(consttime_memcmp_large_blocks);

    /* Certificate reload and SAN validation edge cases */
    printf("\n--- Certificate Reload & SAN Validation ---\n");
    TEST_RUN(cert_reload_null_context);
    TEST_RUN(san_validation_null_identity);
    TEST_RUN(san_validation_null_allowed);
    TEST_RUN(san_validation_zero_count);
    TEST_RUN(san_validation_empty_sans);

    printf("\n========================================\n");
    printf("Test Results: %d passed, %d failed\n", passed, failed);
    printf("========================================\n");

    return (failed == 0) ? 0 : 1;
}
