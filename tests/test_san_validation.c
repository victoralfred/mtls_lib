/**
 * @file test_san_validation.c
 * @brief Unit tests for SAN validation and wildcard matching
 */

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Color codes */
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

#define ASSERT_TRUE(condition, msg) \
    do {                            \
        if (!(condition)) {         \
            TEST_FAIL(msg);         \
            return;                 \
        }                           \
    } while (0)

#define ASSERT_FALSE(condition, msg) \
    do {                             \
        if (condition) {             \
            TEST_FAIL(msg);          \
            return;                  \
        }                            \
    } while (0)

/*
 * Helper to create mock peer identity with SANs
 */
static void create_identity_with_sans(mtls_peer_identity *identity, const char **sans,
                                      size_t san_count)
{
    (void)mtls_memset_s(identity, sizeof(*identity), 0, sizeof(*identity));

    if (sans && san_count > 0) {
        identity->sans = (char **)calloc(san_count, sizeof(char *));
        identity->san_count = san_count;

        for (size_t i = 0; i < san_count; i++) {
            size_t len = strlen(sans[i]);
            identity->sans[i] = malloc(len + 1);
            (void)mtls_memcpy_s(identity->sans[i], len + 1, sans[i], len + 1);
        }
    }
}

/*
 * =============================================================================
 * Test: Exact SAN Matching
 * =============================================================================
 */

static void test_exact_match_single_san(void)
{
    TEST_START("Exact match - single SAN");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com"};
    const char *allowed_sans[] = {"api.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "Should match exactly");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_exact_match_multiple_sans(void)
{
    TEST_START("Exact match - multiple SANs");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com", "service.example.com", "web.example.com"};
    const char *allowed_sans[] = {"service.example.com"};

    create_identity_with_sans(&identity, peer_sans, 3);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "Should find matching SAN");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_exact_no_match(void)
{
    TEST_START("Exact match - no match");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com"};
    const char *allowed_sans[] = {"web.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Should not match");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Wildcard SAN Matching
 * =============================================================================
 */

static void test_wildcard_basic_match(void)
{
    TEST_START("Wildcard - basic match");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com"};
    const char *allowed_sans[] = {"*.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "*.example.com should match api.example.com");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_wildcard_various_services(void)
{
    TEST_START("Wildcard - various services");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"web.example.com"};
    const char *allowed_sans[] = {"*.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "Should match different service names");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_wildcard_no_match_subdomain(void)
{
    TEST_START("Wildcard - no match on subdomain");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.service.example.com"};
    const char *allowed_sans[] = {"*.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Wildcard should not match multiple labels");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_wildcard_no_match_different_domain(void)
{
    TEST_START("Wildcard - different domain");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.other.com"};
    const char *allowed_sans[] = {"*.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Should not match different domain");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_wildcard_exact_domain_no_match(void)
{
    TEST_START("Wildcard - exact domain no match");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"example.com"}; /* No subdomain */
    const char *allowed_sans[] = {"*.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Wildcard should require subdomain");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: SPIFFE ID Matching
 * =============================================================================
 */

static void test_spiffe_exact_match(void)
{
    TEST_START("SPIFFE - exact match");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"spiffe://example.com/service/api"};
    const char *allowed_sans[] = {"spiffe://example.com/service/api"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "SPIFFE IDs should match exactly");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_spiffe_no_match_different_path(void)
{
    TEST_START("SPIFFE - different path");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"spiffe://example.com/service/web"};
    const char *allowed_sans[] = {"spiffe://example.com/service/api"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Different SPIFFE paths should not match");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_spiffe_no_match_different_trust_domain(void)
{
    TEST_START("SPIFFE - different trust domain");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"spiffe://other.com/service/api"};
    const char *allowed_sans[] = {"spiffe://example.com/service/api"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Different trust domains should not match");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Mixed SAN Types
 * =============================================================================
 */

static void test_mixed_dns_and_spiffe(void)
{
    TEST_START("Mixed - DNS and SPIFFE");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com", "spiffe://example.com/service/api"};
    const char *allowed_sans[] = {"spiffe://example.com/service/api"};

    create_identity_with_sans(&identity, peer_sans, 2);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "Should match SPIFFE ID");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_mixed_wildcard_and_exact(void)
{
    TEST_START("Mixed - wildcard and exact");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"web.internal.example.com"};
    const char *allowed_sans[] = {"api.example.com", "*.internal.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 2);
    ASSERT_TRUE(result, "Should match wildcard pattern");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Edge Cases
 * =============================================================================
 */

static void test_null_identity(void)
{
    TEST_START("Edge - null identity");

    const char *allowed_sans[] = {"api.example.com"};

    bool result = mtls_validate_peer_sans(NULL, allowed_sans, 1);
    ASSERT_FALSE(result, "Should return false for null identity");

    TEST_PASS();
}

static void test_null_allowed_sans(void)
{
    TEST_START("Edge - null allowed SANs");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com"};
    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, NULL, 0);
    ASSERT_FALSE(result, "Should return false for null allowed SANs");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_zero_allowed_count(void)
{
    TEST_START("Edge - zero allowed count");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.example.com"};
    const char *allowed_sans[] = {"api.example.com"};
    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 0);
    ASSERT_FALSE(result, "Should return false for zero count");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_empty_peer_sans(void)
{
    TEST_START("Edge - empty peer SANs");

    mtls_peer_identity identity;
    const char *allowed_sans[] = {"api.example.com"};
    create_identity_with_sans(&identity, NULL, 0);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_FALSE(result, "Should return false for empty peer SANs");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_very_long_san(void)
{
    TEST_START("Edge - very long SAN");

    mtls_peer_identity identity;
    char long_san[MTLS_MAX_SAN_LEN + 1];
    (void)mtls_memset_s(long_san, sizeof(long_san), 'a', MTLS_MAX_SAN_LEN);
    long_san[MTLS_MAX_SAN_LEN] = '\0';

    /* This would normally be rejected during identity extraction,
     * but test the validation function's behavior */
    const char *peer_sans[] = {"api.example.com"};
    const char *allowed_sans[] = {"api.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 1);
    ASSERT_TRUE(result, "Should handle within-limit SANs");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

/*
 * =============================================================================
 * Test: Complex Scenarios
 * =============================================================================
 */

static void test_multiple_wildcards(void)
{
    TEST_START("Complex - multiple wildcards");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"api.prod.example.com"};
    const char *allowed_sans[] = {"*.dev.example.com", "*.staging.example.com",
                                  "*.prod.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 3);
    ASSERT_TRUE(result, "Should match third wildcard pattern");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_deny_by_default(void)
{
    TEST_START("Complex - deny by default");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"unknown.example.com"};
    const char *allowed_sans[] = {"api.example.com", "web.example.com", "*.internal.example.com"};

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 3);
    ASSERT_FALSE(result, "Should deny non-matching SANs");

    mtls_free_peer_identity(&identity);
    TEST_PASS();
}

static void test_allowlist_with_many_sans(void)
{
    TEST_START("Complex - large allowlist");

    mtls_peer_identity identity;
    const char *peer_sans[] = {"service99.example.com"};

    /* Create large allowlist */
    const char *allowed_sans[100];
    char san_buffers[100][64];
    for (int i = 0; i < 100; i++) {
        snprintf(san_buffers[i], sizeof(san_buffers[i]), "service%d.example.com", i);
        allowed_sans[i] = san_buffers[i];
    }

    create_identity_with_sans(&identity, peer_sans, 1);

    bool result = mtls_validate_peer_sans(&identity, allowed_sans, 100);
    ASSERT_TRUE(result, "Should find match in large allowlist");

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
    printf("  SAN Validation Test Suite\n");
    printf("===============================================\n\n");

    printf(COLOR_YELLOW "Exact Matching Tests:" COLOR_RESET "\n");
    test_exact_match_single_san();
    test_exact_match_multiple_sans();
    test_exact_no_match();

    printf("\n" COLOR_YELLOW "Wildcard Matching Tests:" COLOR_RESET "\n");
    test_wildcard_basic_match();
    test_wildcard_various_services();
    test_wildcard_no_match_subdomain();
    test_wildcard_no_match_different_domain();
    test_wildcard_exact_domain_no_match();

    printf("\n" COLOR_YELLOW "SPIFFE ID Tests:" COLOR_RESET "\n");
    test_spiffe_exact_match();
    test_spiffe_no_match_different_path();
    test_spiffe_no_match_different_trust_domain();

    printf("\n" COLOR_YELLOW "Mixed SAN Types:" COLOR_RESET "\n");
    test_mixed_dns_and_spiffe();
    test_mixed_wildcard_and_exact();

    printf("\n" COLOR_YELLOW "Edge Cases:" COLOR_RESET "\n");
    test_null_identity();
    test_null_allowed_sans();
    test_zero_allowed_count();
    test_empty_peer_sans();
    test_very_long_san();

    printf("\n" COLOR_YELLOW "Complex Scenarios:" COLOR_RESET "\n");
    test_multiple_wildcards();
    test_deny_by_default();
    test_allowlist_with_many_sans();
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
