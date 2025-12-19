/**
 * @file fuzz_san_validation.c
 * @brief LibFuzzer harness for SAN (Subject Alternative Name) validation
 *
 * This fuzzer tests:
 * - Constant-time string comparison functions
 * - SAN validation against patterns (exact, wildcard, SPIFFE)
 * - Boundary conditions around MTLS_MAX_IDENTITY_LEN
 * - Oversized string handling
 *
 * Build: cmake -DMTLS_ENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang ..
 * Run: ./tests/fuzz/fuzz_san_validation corpus/fuzz_san_validation/
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include "internal/platform.h"
#include "fuzz_common.h"

/**
 * LibFuzzer entry point
 *
 * @param Data Fuzzer-provided input data
 * @param Size Size of input data
 * @return 0 to continue fuzzing
 */
// NOLINT(readability-identifier-naming) - libFuzzer requires this name
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    /* Reject unreasonable sizes early to avoid wasting fuzzing cycles */
    if (Size == 0 || Size > MTLS_MAX_IDENTITY_LEN + 10000) {
        return 0;
    }

    /* Test 1: Constant-time strcmp with fuzzer data */
    char *san1 = fuzz_strndup(Data, Size);
    if (!san1) {
        return 0;
    }

    /* Test against itself (should always return 0 for equal strings) */
    volatile int result = platform_consttime_strcmp(san1, san1);
    (void)result; /* Use result to prevent optimization */

    /* Test against a copy */
    char *san2 = fuzz_strndup((const uint8_t *)san1, strlen(san1));
    if (san2) {
        volatile int result2 = platform_consttime_strcmp(san1, san2);
        (void)result2;
        free(san2);
    }

    /* Test 2: Constant-time strcmp with different-length comparison */
    const char *test_patterns[] = {
        "example.com", "*.example.com", "spiffe://trust-domain/service", "api.service.local", "",
        "a", /* Single char */
        NULL};

    for (size_t i = 0; test_patterns[i] != NULL; i++) {
        volatile int cmp_result = platform_consttime_strcmp(san1, test_patterns[i]);
        (void)cmp_result;
    }

    /* Test 3: SAN validation with fuzzer data
     * Create a mock peer identity structure and test validation
     */
    mtls_peer_identity identity;
    memset(&identity, 0, sizeof(identity));

    identity.san_count = 1;
    identity.sans = (char **)malloc(sizeof(char *));
    if (identity.sans) {
        identity.sans[0] = san1;

        /* Test against various allowed patterns */
        const char *allowed_patterns[] = {"example.com", "*.example.com", "spiffe://trust-domain/*",
                                          "api.*.local"};

        /* Validate against each pattern */
        for (size_t i = 0; i < sizeof(allowed_patterns) / sizeof(allowed_patterns[0]); i++) {
            volatile int valid = mtls_validate_peer_sans(&identity, &allowed_patterns[i], 1);
            (void)valid;
        }

        free((void *)identity.sans);
    }

    /* Test 4: Constant-time memcmp with fuzzer data prefix */
    if (Size >= 10) {
        /* Test SPIFFE prefix detection (constant-time) */
        const char SPIFFE_PREFIX[] = "spiffe://";
        volatile int is_spiffe = platform_consttime_memcmp(Data, SPIFFE_PREFIX, 9);
        (void)is_spiffe;

        /* Test PEM-like prefix (though PEM is binary-safe) */
        const char PEM_PREFIX[] = "-----BEGIN";
        volatile int is_pem = platform_consttime_memcmp(Data, PEM_PREFIX, 10);
        (void)is_pem;
    }

    /* Test 5: Mixed size comparisons (early detection of timing issues) */
    if (Size > 50 && Size < MTLS_MAX_IDENTITY_LEN) {
        /* Create truncated version */
        char *truncated = fuzz_strndup(Data, Size / 2);
        if (truncated) {
            volatile int trunc_result = platform_consttime_strcmp(san1, truncated);
            (void)trunc_result;
            free(truncated);
        }
    }

    /* Test 6: NULL and edge case handling */
    platform_consttime_strcmp(san1, NULL); /* Should handle NULL gracefully */
    platform_consttime_strcmp(NULL, san1); /* Should handle NULL gracefully */
    platform_consttime_strcmp("", san1);   /* Empty string */

    /* Cleanup */
    free(san1);

    return 0; /* Continue fuzzing */
}

/**
 * Optional: libFuzzer initialization
 * Can be used to set up test fixtures or seed initial corpus
 */
__attribute__((used)) int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    /* No initialization needed for this fuzzer */
    return 0;
}
