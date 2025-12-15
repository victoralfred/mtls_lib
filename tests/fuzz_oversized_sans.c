/**
 * @file fuzz_oversized_sans.c
 * @brief Fuzz test for oversized SAN handling
 *
 * This test generates various sized strings around the MTLS_MAX_IDENTITY_LEN
 * boundary to ensure robust handling of oversized identities and prevent
 * bypass attacks, resource exhaustion, and buffer overflows.
 *
 * Test objectives:
 * 1. Verify strings exactly at limit are accepted
 * 2. Verify strings over limit are rejected (fail-closed)
 * 3. Verify no buffer overflows with various string sizes
 * 4. Test with random content (not just repeated characters)
 * 5. Verify constant-time comparison remains secure
 */

#include "mtls/mtls.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_config.h"
#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

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

/* Seed for reproducible random tests */
#define FUZZ_SEED 0x12345678

/**
 * Generate a random string of specified length
 * Uses printable ASCII characters (0x20-0x7E)
 */
static char* generate_random_string(size_t len) {
    char* str = (char*)malloc(len + 1);
    if (!str) return NULL;

    for (size_t i = 0; i < len; i++) {
        /* Generate printable ASCII: space (0x20) to tilde (0x7E) */
        str[i] = 0x20 + (rand() % (0x7E - 0x20 + 1));
    }
    str[len] = '\0';

    return str;
}

/**
 * Generate a valid DNS-like string of specified length
 */
static char* generate_dns_string(size_t len) {
    if (len < 3) len = 3; /* Minimum: "a.b" */

    char* str = (char*)malloc(len + 1);
    if (!str) return NULL;

    const char dns_chars[] = "abcdefghijklmnopqrstuvwxyz0123456789-.";
    size_t charset_len = strlen(dns_chars);

    for (size_t i = 0; i < len; i++) {
        str[i] = dns_chars[rand() % charset_len];
    }
    str[len] = '\0';

    /* Ensure it doesn't start or end with a dot or dash */
    if (str[0] == '.' || str[0] == '-') str[0] = 'a';
    if (str[len-1] == '.' || str[len-1] == '-') str[len-1] = 'z';

    return str;
}

/* ============================================================================
 * Boundary Tests
 * ============================================================================ */

/**
 * Test 1: Strings exactly at MTLS_MAX_IDENTITY_LEN boundary
 */
static bool test_boundary_exact_limit(void) {
    /* Create two identical strings at exact limit */
    char* str1 = generate_random_string(MTLS_MAX_IDENTITY_LEN);
    char* str2 = (char*)malloc(MTLS_MAX_IDENTITY_LEN + 1);
    TEST_ASSERT(str1 && str2, "Memory allocation should succeed");

    memcpy(str2, str1, MTLS_MAX_IDENTITY_LEN + 1);

    /* Should be accepted (not -1 error) */
    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result == 0, "Strings at exact limit should compare equal");
    TEST_ASSERT(result != -1, "Strings at exact limit should not error");

    free(str1);
    free(str2);

    return true;
}

/**
 * Test 2: String just over limit (limit + 1)
 */
static bool test_boundary_over_by_one(void) {
    char* str1 = generate_random_string(MTLS_MAX_IDENTITY_LEN + 1);
    char* str2 = generate_random_string(MTLS_MAX_IDENTITY_LEN + 1);
    TEST_ASSERT(str1 && str2, "Memory allocation should succeed");

    /* Should be rejected with -1 */
    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result == -1, "Strings over limit by 1 should return error -1");

    free(str1);
    free(str2);

    return true;
}

/**
 * Test 3: Far exceeding limit (limit + 1000)
 */
static bool test_boundary_far_over_limit(void) {
    char* str1 = generate_random_string(MTLS_MAX_IDENTITY_LEN + 1000);
    char* str2 = generate_random_string(MTLS_MAX_IDENTITY_LEN + 1000);
    TEST_ASSERT(str1 && str2, "Memory allocation should succeed");

    /* Should be rejected with -1 */
    int result = platform_consttime_strcmp(str1, str2);
    TEST_ASSERT(result == -1, "Strings far over limit should return error -1");

    free(str1);
    free(str2);

    return true;
}

/**
 * Test 4: Asymmetric - one at limit, one over
 */
static bool test_boundary_asymmetric(void) {
    char* at_limit = generate_random_string(MTLS_MAX_IDENTITY_LEN);
    char* over_limit = generate_random_string(MTLS_MAX_IDENTITY_LEN + 1);
    TEST_ASSERT(at_limit && over_limit, "Memory allocation should succeed");

    /* Should be rejected because second string is over limit */
    int result = platform_consttime_strcmp(at_limit, over_limit);
    TEST_ASSERT(result == -1, "Should reject when one string exceeds limit");

    /* Test reversed order */
    result = platform_consttime_strcmp(over_limit, at_limit);
    TEST_ASSERT(result == -1, "Should reject regardless of parameter order");

    free(at_limit);
    free(over_limit);

    return true;
}

/* ============================================================================
 * Random Fuzz Tests
 * ============================================================================ */

/**
 * Test 5: Fuzz with random lengths around boundary (1000 iterations)
 */
static bool test_fuzz_random_lengths(void) {
    const int iterations = 1000;
    int accepted = 0;
    int rejected = 0;

    for (int i = 0; i < iterations; i++) {
        /* Generate random length: 90% within bounds, 10% over */
        size_t len;
        bool should_accept;

        if (i % 10 == 0) {
            /* 10% over limit */
            len = MTLS_MAX_IDENTITY_LEN + 1 + (rand() % 5000);
            should_accept = false;
        } else {
            /* 90% within limit */
            len = 1 + (rand() % MTLS_MAX_IDENTITY_LEN);
            should_accept = true;
        }

        char* str1 = generate_random_string(len);
        char* str2 = generate_random_string(len);
        TEST_ASSERT(str1 && str2, "Memory allocation should succeed");

        int result = platform_consttime_strcmp(str1, str2);

        if (should_accept) {
            TEST_ASSERT(result != -1, "Within-limit strings should not error");
            accepted++;
        } else {
            TEST_ASSERT(result == -1, "Over-limit strings should error");
            rejected++;
        }

        free(str1);
        free(str2);
    }

    printf("  Fuzz stats: %d accepted, %d rejected\n", accepted, rejected);
    TEST_ASSERT(accepted > 0 && rejected > 0, "Should have both accepted and rejected cases");

    return true;
}

/**
 * Test 6: Fuzz with DNS-like patterns
 */
static bool test_fuzz_dns_patterns(void) {
    const int iterations = 500;

    for (int i = 0; i < iterations; i++) {
        /* Test various DNS-like string lengths */
        size_t len = 10 + (rand() % (MTLS_MAX_IDENTITY_LEN + 100));

        char* san1 = generate_dns_string(len);
        char* san2 = generate_dns_string(len);
        TEST_ASSERT(san1 && san2, "Memory allocation should succeed");

        int result = platform_consttime_strcmp(san1, san2);

        if (len <= MTLS_MAX_IDENTITY_LEN) {
            TEST_ASSERT(result != -1, "Valid-length DNS strings should not error");
        } else {
            TEST_ASSERT(result == -1, "Oversized DNS strings should error");
        }

        free(san1);
        free(san2);
    }

    return true;
}

/* ============================================================================
 * SAN Validation Integration Tests
 * ============================================================================ */

/**
 * Test 7: SAN validation rejects oversized identities
 */
static bool test_san_validation_rejects_oversized(void) {
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));

    /* Create oversized SAN */
    char* oversized_san = generate_random_string(MTLS_MAX_IDENTITY_LEN + 100);
    TEST_ASSERT(oversized_san, "Memory allocation should succeed");

    identity.san_count = 1;
    identity.sans = (char**)malloc(sizeof(char*));
    identity.sans[0] = oversized_san;

    const char* allowed_sans[] = {"example.com"};

    /* Should return false (rejected) due to oversized SAN */
    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    TEST_ASSERT(result == false, "Oversized SAN should be rejected");

    free(identity.sans);
    free(oversized_san);

    return true;
}

/**
 * Test 8: SAN validation with allowed pattern also oversized
 */
static bool test_san_validation_both_oversized(void) {
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));

    /* Create oversized SAN */
    char* oversized_san = generate_random_string(MTLS_MAX_IDENTITY_LEN + 50);
    TEST_ASSERT(oversized_san, "Memory allocation should succeed");

    identity.san_count = 1;
    identity.sans = (char**)malloc(sizeof(char*));
    identity.sans[0] = oversized_san;

    /* Create oversized allowed pattern (matching the SAN) */
    char* oversized_allowed = (char*)malloc(MTLS_MAX_IDENTITY_LEN + 51);
    strcpy(oversized_allowed, oversized_san);
    const char* allowed_sans[] = {oversized_allowed};

    /* Should return false - both oversized */
    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    TEST_ASSERT(result == false, "Should reject when both SAN and pattern oversized");

    free(identity.sans);
    free(oversized_san);
    free(oversized_allowed);

    return true;
}

/**
 * Helper to duplicate a string (portable alternative to strdup)
 */
static char* duplicate_string(const char* str) {
    size_t len = strlen(str);
    char* dup = (char*)malloc(len + 1);
    if (dup) {
        strcpy(dup, str);
    }
    return dup;
}

/**
 * Test 9: Multiple SANs, one oversized
 */
static bool test_san_validation_mixed_sizes(void) {
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));

    /* Create mix of normal and oversized SANs */
    identity.san_count = 3;
    identity.sans = (char**)malloc(3 * sizeof(char*));
    identity.sans[0] = duplicate_string("api.example.com");
    identity.sans[1] = generate_random_string(MTLS_MAX_IDENTITY_LEN + 100); /* Oversized */
    identity.sans[2] = duplicate_string("service.example.com");

    const char* allowed_sans[] = {"service.example.com"};

    /* Should match the valid SAN (sans[2]) and ignore the oversized one */
    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    TEST_ASSERT(result == true, "Should match valid SAN, ignoring oversized one");

    free(identity.sans[0]);
    free(identity.sans[1]);
    free(identity.sans[2]);
    free(identity.sans);

    return true;
}

/* ============================================================================
 * Stress Tests
 * ============================================================================ */

/**
 * Test 10: Maximum length stress test
 */
static bool test_stress_maximum_length(void) {
    /* Create strings at absolute maximum length */
    char* max_str1 = generate_random_string(MTLS_MAX_IDENTITY_LEN);
    char* max_str2 = generate_random_string(MTLS_MAX_IDENTITY_LEN);
    TEST_ASSERT(max_str1 && max_str2, "Memory allocation should succeed");

    /* Perform multiple comparisons */
    for (int i = 0; i < 100; i++) {
        int result = platform_consttime_strcmp(max_str1, max_str2);
        TEST_ASSERT(result != -1, "Maximum length strings should not error");
    }

    free(max_str1);
    free(max_str2);

    return true;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */
int main(void) {
    /* Initialize random seed for reproducibility */
    srand(FUZZ_SEED);

    printf("========================================\n");
    printf("Fuzz Test: Oversized SANs\n");
    printf("========================================\n");
    printf("MTLS_MAX_IDENTITY_LEN: %d\n", MTLS_MAX_IDENTITY_LEN);
    printf("Random seed: 0x%08X\n\n", FUZZ_SEED);

    /* Boundary tests */
    printf("--- Boundary Tests ---\n");
    TEST_RUN(boundary_exact_limit);
    TEST_RUN(boundary_over_by_one);
    TEST_RUN(boundary_far_over_limit);
    TEST_RUN(boundary_asymmetric);

    /* Random fuzz tests */
    printf("\n--- Random Fuzz Tests ---\n");
    TEST_RUN(fuzz_random_lengths);
    TEST_RUN(fuzz_dns_patterns);

    /* SAN validation integration */
    printf("\n--- SAN Validation Integration ---\n");
    TEST_RUN(san_validation_rejects_oversized);
    TEST_RUN(san_validation_both_oversized);
    TEST_RUN(san_validation_mixed_sizes);

    /* Stress tests */
    printf("\n--- Stress Tests ---\n");
    TEST_RUN(stress_maximum_length);

    printf("\n========================================\n");
    printf("Test Results: %d passed, %d failed\n", passed, failed);
    printf("========================================\n");

    return (failed == 0) ? 0 : 1;
}
