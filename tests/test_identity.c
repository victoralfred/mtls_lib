/**
 * @file test_identity.c
 * @brief Unit tests for identity verification
 */

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Color codes for output */
#define COLOR_GREEN "\x1b[32m"
#define COLOR_RED "\x1b[31m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET "\x1b[0m"

/* Test macros */
#define TEST_START(name)                    \
    do {                                    \
        tests_run++;                        \
        printf("  Testing: %s ... ", name); \
        (void)fflush(stdout);               \
    } while (0)

#define TEST_PASS()                                  \
    do {                                             \
        tests_passed++;                              \
        printf(COLOR_GREEN "PASS" COLOR_RESET "\n"); \
    } while (0)

#define TEST_FAIL(msg)                                      \
    do {                                                    \
        tests_failed++;                                     \
        printf(COLOR_RED "FAIL" COLOR_RESET ": %s\n", msg); \
    } while (0)

#define ASSERT(condition, msg) \
    do {                       \
        if (!(condition)) {    \
            TEST_FAIL(msg);    \
            return;            \
        }                      \
    } while (0)

#define ASSERT_EQ(actual, expected, msg)                                                    \
    do {                                                                                    \
        if ((actual) != (expected)) {                                                       \
            char buf[256];                                                                  \
            snprintf(buf, sizeof(buf), "%s (expected %ld, got %ld)", msg, (long)(expected), \
                     (long)(actual));                                                       \
            TEST_FAIL(buf);                                                                 \
            return;                                                                         \
        }                                                                                   \
    } while (0)

#define ASSERT_STR_EQ(actual, expected, msg)                                                 \
    do {                                                                                     \
        if (strcmp((actual), (expected)) != 0) {                                             \
            size_t msg_len = strlen(msg);                                                    \
            size_t exp_len = strlen(expected);                                               \
            size_t act_len = strlen(actual);                                                 \
            size_t buf_size = msg_len + exp_len + act_len + 50; /* extra for format chars */ \
            char *buf = malloc(buf_size);                                                    \
            if (buf) {                                                                       \
                snprintf(buf, buf_size, "%s (expected '%s', got '%s')", msg, (expected),     \
                         (actual));                                                          \
                TEST_FAIL(buf);                                                              \
                free(buf);                                                                   \
            } else {                                                                         \
                TEST_FAIL(msg);                                                              \
            }                                                                                \
            return;                                                                          \
        }                                                                                    \
    } while (0)

#define ASSERT_TRUE(condition, msg) ASSERT((condition), msg)
#define ASSERT_FALSE(condition, msg) ASSERT(!(condition), msg)

/*
 * =============================================================================
 * Mock Peer Identity Creation
 * =============================================================================
 */

/**
 * Create a mock peer identity for testing
 */
static void create_mock_identity(mtls_peer_identity *identity, const char *common_name,
                                 const char **sans, size_t san_count, const char *spiffe_id,
                                 time_t not_before, time_t not_after)
{
    (void)mtls_memset_s(identity, sizeof(*identity), 0, sizeof(*identity));

    if (common_name) {
        (void)snprintf(identity->common_name, sizeof(identity->common_name), "%s", common_name);
    }

    if (sans && san_count > 0) {
        identity->sans = (char **)calloc(san_count, sizeof(char *));
        identity->san_count = san_count;

        for (size_t i = 0; i < san_count; i++) {
            size_t len = strlen(sans[i]);
            identity->sans[i] = malloc(len + 1);
            (void)mtls_memcpy_s(identity->sans[i], len + 1, sans[i], len + 1);
        }
    }

    if (spiffe_id) {
        (void)snprintf(identity->spiffe_id, sizeof(identity->spiffe_id), "%s", spiffe_id);
    }

    identity->cert_not_before = not_before;
    identity->cert_not_after = not_after;
}

/*
 * =============================================================================
 * Test: Peer Identity Structure
 * =============================================================================
 */

static void test_peer_identity_structure(void)
{
    TEST_START("Peer identity structure");

    mtls_peer_identity identity;
    const char *sans[] = {"api.example.com", "service.example.com",
                          "spiffe://example.com/service/api"};

    time_t now = time(NULL);
    create_mock_identity(&identity, "test-service", sans, 3, "spiffe://example.com/service/api",
                         now - 86400, now + 86400);

    ASSERT_STR_EQ(identity.common_name, "test-service", "Common name mismatch");
    ASSERT_EQ(identity.san_count, 3, "SAN count mismatch");
    ASSERT_STR_EQ(identity.sans[0], "api.example.com", "SAN[0] mismatch");
    ASSERT_STR_EQ(identity.sans[1], "service.example.com", "SAN[1] mismatch");
    ASSERT_STR_EQ(identity.sans[2], "spiffe://example.com/service/api", "SAN[2] mismatch");
    ASSERT_STR_EQ(identity.spiffe_id, "spiffe://example.com/service/api", "SPIFFE ID mismatch");

    mtls_free_peer_identity(&identity);

    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Certificate Validity Checking
 * =============================================================================
 */

static void test_cert_validity_valid(void)
{
    TEST_START("Certificate validity - valid cert");

    mtls_peer_identity identity;
    time_t now = time(NULL);
    create_mock_identity(&identity, "test", NULL, 0, NULL, now - 86400, /* 1 day ago */
                         now + 86400);                                  /* 1 day from now */

    ASSERT_TRUE(mtls_is_peer_cert_valid(&identity), "Should be valid");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_cert_validity_expired(void)
{
    TEST_START("Certificate validity - expired");

    mtls_peer_identity identity;
    time_t now = time(NULL);
    create_mock_identity(&identity, "test", NULL, 0, NULL, now - 172800, /* 2 days ago */
                         now - 86400);                                   /* 1 day ago (expired) */

    ASSERT_FALSE(mtls_is_peer_cert_valid(&identity), "Should be expired");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_cert_validity_not_yet_valid(void)
{
    TEST_START("Certificate validity - not yet valid");

    mtls_peer_identity identity;
    time_t now = time(NULL);
    create_mock_identity(&identity, "test", NULL, 0, NULL, now + 86400, /* 1 day from now */
                         now + 172800);                                 /* 2 days from now */

    ASSERT_FALSE(mtls_is_peer_cert_valid(&identity), "Should not be valid yet");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Certificate TTL
 * =============================================================================
 */

static void test_cert_ttl_valid(void)
{
    TEST_START("Certificate TTL - valid");

    mtls_peer_identity identity;
    time_t now = time(NULL);
    create_mock_identity(&identity, "test", NULL, 0, NULL, now - 86400,
                         now + 86400); /* Expires in 1 day */

    int64_t ttl = mtls_get_cert_ttl_seconds(&identity);
    ASSERT_TRUE(ttl > 0 && ttl <= 86400, "TTL should be ~1 day");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_cert_ttl_expired(void)
{
    TEST_START("Certificate TTL - expired");

    mtls_peer_identity identity;
    time_t now = time(NULL);
    create_mock_identity(&identity, "test", NULL, 0, NULL, now - 172800,
                         now - 86400); /* Expired 1 day ago */

    int64_t ttl = mtls_get_cert_ttl_seconds(&identity);
    ASSERT_EQ(ttl, -1, "TTL should be -1 for expired cert");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_cert_ttl_null_identity(void)
{
    TEST_START("Certificate TTL - null identity");

    int64_t ttl = mtls_get_cert_ttl_seconds(NULL);
    ASSERT_EQ(ttl, -1, "TTL should be -1 for null identity");

    TEST_PASS();
}

/*
 * =============================================================================
 * Test: SPIFFE ID Detection
 * =============================================================================
 */

static void test_spiffe_id_present(void)
{
    TEST_START("SPIFFE ID - present");

    mtls_peer_identity identity;
    create_mock_identity(&identity, "test", NULL, 0, "spiffe://example.com/service/api", 0, 0);

    ASSERT_TRUE(mtls_has_spiffe_id(&identity), "Should have SPIFFE ID");
    ASSERT_STR_EQ(identity.spiffe_id, "spiffe://example.com/service/api", "SPIFFE ID mismatch");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_spiffe_id_absent(void)
{
    TEST_START("SPIFFE ID - absent");

    mtls_peer_identity identity;
    create_mock_identity(&identity, "test", NULL, 0, NULL, 0, 0);

    ASSERT_FALSE(mtls_has_spiffe_id(&identity), "Should not have SPIFFE ID");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_spiffe_id_null_identity(void)
{
    TEST_START("SPIFFE ID - null identity");

    ASSERT_FALSE(mtls_has_spiffe_id(NULL), "Should handle null identity");

    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Memory Management
 * =============================================================================
 */

static void test_free_peer_identity_null(void)
{
    TEST_START("Free peer identity - null");

    /* Should not crash */
    mtls_free_peer_identity(NULL);

    TEST_PASS();
}

static void test_free_peer_identity_no_sans(void)
{
    TEST_START("Free peer identity - no SANs");

    mtls_peer_identity identity;
    create_mock_identity(&identity, "test", NULL, 0, NULL, 0, 0);

    mtls_free_peer_identity(&identity);

    TEST_PASS();
}

static void test_free_peer_identity_with_sans(void)
{
    TEST_START("Free peer identity - with SANs");

    mtls_peer_identity identity;
    const char *sans[] = {"a.example.com", "b.example.com", "c.example.com"};
    create_mock_identity(&identity, "test", sans, 3, NULL, 0, 0);

    mtls_free_peer_identity(&identity);
    /* Should have freed all memory without leaks */

    TEST_PASS();
}

static void test_multiple_free_calls(void)
{
    TEST_START("Multiple free calls");

    mtls_peer_identity identity;
    const char *sans[] = {"a.example.com"};
    create_mock_identity(&identity, "test", sans, 1, NULL, 0, 0);

    mtls_free_peer_identity(&identity);

    /* Second call should be safe (sans is NULL after first free) */
    mtls_free_peer_identity(&identity);

    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Error Handling
 * =============================================================================
 */

static void test_is_cert_valid_null(void)
{
    TEST_START("Certificate validity - null identity");

    ASSERT_FALSE(mtls_is_peer_cert_valid(NULL), "Should return false for null");

    TEST_PASS();
}

/*
 * =============================================================================
 * Test: SAN Limits
 * =============================================================================
 */

static void test_large_san_count(void)
{
    TEST_START("Large SAN count");

    mtls_peer_identity identity;
    const char *sans[100];
    char san_buffers[100][64];

    /* Create 100 SANs */
    for (int i = 0; i < 100; i++) {
        snprintf(san_buffers[i], sizeof(san_buffers[i]), "service%d.example.com", i);
        sans[i] = san_buffers[i];
    }

    create_mock_identity(&identity, "test", sans, 100, NULL, 0, 0);

    ASSERT_EQ(identity.san_count, 100, "Should handle 100 SANs");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_max_length_strings(void)
{
    TEST_START("Max length strings");

    mtls_peer_identity identity;

    /* Create max-length common name */
    char common_name[MTLS_MAX_COMMON_NAME_LEN];
    (void)mtls_memset_s(common_name, sizeof(common_name), 'A', MTLS_MAX_COMMON_NAME_LEN - 1);
    common_name[MTLS_MAX_COMMON_NAME_LEN - 1] = '\0';

    /* Create max-length SPIFFE ID */
    char spiffe[MTLS_MAX_SPIFFE_ID_LEN];
    strcpy(spiffe, "spiffe://example.com/");
    size_t prefix_len = strlen(spiffe);
    (void)mtls_memset_s(spiffe + prefix_len, MTLS_MAX_SPIFFE_ID_LEN - prefix_len, 'B',
                        MTLS_MAX_SPIFFE_ID_LEN - prefix_len - 1);
    spiffe[MTLS_MAX_SPIFFE_ID_LEN - 1] = '\0';

    create_mock_identity(&identity, common_name, NULL, 0, spiffe, 0, 0);

    ASSERT_TRUE(strlen(identity.common_name) < MTLS_MAX_COMMON_NAME_LEN,
                "Common name should be within limits");
    ASSERT_TRUE(strlen(identity.spiffe_id) < MTLS_MAX_SPIFFE_ID_LEN,
                "SPIFFE ID should be within limits");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Edge Cases
 * =============================================================================
 */

static void test_empty_common_name(void)
{
    TEST_START("Empty common name");

    mtls_peer_identity identity;
    create_mock_identity(&identity, "", NULL, 0, NULL, 0, 0);

    ASSERT_STR_EQ(identity.common_name, "", "Should handle empty CN");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_empty_spiffe_id(void)
{
    TEST_START("Empty SPIFFE ID");

    mtls_peer_identity identity;
    create_mock_identity(&identity, "test", NULL, 0, "", 0, 0);

    ASSERT_FALSE(mtls_has_spiffe_id(&identity), "Empty SPIFFE ID should be false");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_zero_timestamp(void)
{
    TEST_START("Zero timestamps");

    mtls_peer_identity identity;
    create_mock_identity(&identity, "test", NULL, 0, NULL, 0, 0);

    /* Certificates with zero timestamps are invalid (before epoch) */
    ASSERT_FALSE(mtls_is_peer_cert_valid(&identity), "Zero timestamps should be invalid");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test Runner
 * =============================================================================
 */

static void run_all_tests(void)
{
    printf("\n");
    printf("===============================================\n");
    printf("  Identity Verification Test Suite\n");
    printf("===============================================\n\n");

    printf(COLOR_YELLOW "Structure Tests:" COLOR_RESET "\n");
    test_peer_identity_structure();

    printf("\n" COLOR_YELLOW "Certificate Validity Tests:" COLOR_RESET "\n");
    test_cert_validity_valid();
    test_cert_validity_expired();
    test_cert_validity_not_yet_valid();
    test_is_cert_valid_null();

    printf("\n" COLOR_YELLOW "Certificate TTL Tests:" COLOR_RESET "\n");
    test_cert_ttl_valid();
    test_cert_ttl_expired();
    test_cert_ttl_null_identity();

    printf("\n" COLOR_YELLOW "SPIFFE ID Tests:" COLOR_RESET "\n");
    test_spiffe_id_present();
    test_spiffe_id_absent();
    test_spiffe_id_null_identity();

    printf("\n" COLOR_YELLOW "Memory Management Tests:" COLOR_RESET "\n");
    test_free_peer_identity_null();
    test_free_peer_identity_no_sans();
    test_free_peer_identity_with_sans();
    test_multiple_free_calls();

    printf("\n" COLOR_YELLOW "Limits and Edge Cases:" COLOR_RESET "\n");
    test_large_san_count();
    test_max_length_strings();
    test_empty_common_name();
    test_empty_spiffe_id();
    test_zero_timestamp();
}

int main(void)
{
    run_all_tests();

    printf("\n");
    printf("===============================================\n");
    printf("  Test Results\n");
    printf("===============================================\n");
    printf("  Total:  %d\n", tests_run);
    printf("  " COLOR_GREEN "Passed: %d" COLOR_RESET "\n", tests_passed);
    if (tests_failed > 0) {
        printf("  " COLOR_RED "Failed: %d" COLOR_RESET "\n", tests_failed);
    } else {
        printf("  Failed: 0\n");
    }
    printf("===============================================\n\n");

    if (tests_failed == 0) {
        printf(COLOR_GREEN "✓ All tests passed!" COLOR_RESET "\n\n");
        return 0;
    }
    printf(COLOR_RED "✗ Some tests failed" COLOR_RESET "\n\n");
    return 1;
}
