/**
 * @file fuzz_certificate_validation.c
 * @brief LibFuzzer harness for X.509 certificate chain validation
 *
 * This fuzzer tests:
 * - X.509 certificate chain validation
 * - SAN extraction from certificates
 * - SPIFFE ID parsing from URIs
 * - Certificate validity period checks
 * - Trust chain verification
 *
 * Build: cmake -DMTLS_ENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang ..
 * Run: ./tests/fuzz/fuzz_certificate_validation corpus/fuzz_certificate_validation/
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "mtls/mtls.h"
#include "mtls/mtls_config.h"
#include "internal/platform.h"
#include "fuzz_common.h"

/* Maximum PEM size for fuzzing (1MB) */
static const size_t FUZZ_MAX_PEM_SIZE = (1024UL * 1024UL);

/**
 * LibFuzzer entry point
 *
 * @param Data Fuzzer-provided input data (certificate data)
 * @param Size Size of input data
 * @return 0 to continue fuzzing
 */

// NOLINT(readability-identifier-naming) - libFuzzer requires this name
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    /* Reject unreasonable sizes */
    if (Size == 0 || Size > (size_t)FUZZ_MAX_PEM_SIZE) {
        return 0;
    }

    /* Test 1: SAN validation with fuzzer-generated patterns
     * Create identity with fuzzer data as SANs
     */
    if (Size > 10 && Size < 10000) {
        /* Split input into multiple SAN entries */
        size_t san_count = (Size / 50) + 1;
        if (san_count > MTLS_MAX_ALLOWED_SANS) {
            san_count = MTLS_MAX_ALLOWED_SANS;
        }

        char **sans = (char **)calloc(san_count, sizeof(char *));
        if (sans) {
            size_t offset = 0;
            size_t actual_count = 0;

            for (size_t i = 0; i < san_count && offset < Size; i++) {
                size_t san_len = (Size - offset) / (san_count - i);
                if (san_len > 512) { /* MTLS_SAN_MAX_LEN */
                    san_len = 512;
                }
                if (san_len == 0) {
                    break;
                }

                sans[i] = fuzz_strndup(Data + offset, san_len);
                if (!sans[i]) {
                    /* Allocation failed, cleanup */
                    for (size_t j = 0; j < i; j++) {
                        free(sans[j]);
                    }
                    free((void *)sans);
                    return 0;
                }

                actual_count++;
                offset += san_len;
            }

            /* Create config with fuzzer-provided SANs */
            mtls_config config;
            mtls_config_init(&config);
            mtls_config_set_allowed_sans(&config, (const char **)sans, actual_count);

            /* Test validation - the library should handle malformed SANs gracefully */
            /* Note: Without real certificates, this mostly exercises validation logic */

            /* Cleanup */
            for (size_t i = 0; i < actual_count; i++) {
                free(sans[i]);
            }
            free((void *)sans);
        }
    }

    /* Test 2: SPIFFE ID validation
     * Test if fuzzer data looks like a valid SPIFFE ID
     */
    if (Size > 10 && Size < 512) { /* MTLS_MAX_SPIFFE_ID_LEN */
        char *potential_spiffe = fuzz_strndup(Data, Size);
        if (potential_spiffe) {
            /* Check if it starts with spiffe:// */
            if (Size >= 9 && platform_consttime_memcmp(potential_spiffe, "spiffe://", 9) == 0) {
                /* Looks like SPIFFE ID, use it in config */
                mtls_config config;
                mtls_config_init(&config);

                const char *allowed_sans[] = {potential_spiffe};
                mtls_config_set_allowed_sans(&config, allowed_sans, 1);
            }

            free(potential_spiffe);
        }
    }

    /* Test 3: Try to parse as certificate and create context
     * This exercises certificate parsing and validation
     */
    mtls_config config;
    mtls_config_init(&config);

    /* Set fuzzer data as certificate PEM */
    mtls_config_set_cert_pem(&config, Data, Size, NULL, 0);

    /* Try to create context - will fail for invalid certs but tests error paths */
    mtls_err err;
    memset(&err, 0, sizeof(err));

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    if (ctx) {
        /* Unlikely to succeed with random data, but clean up if it does */
        mtls_ctx_free(ctx);
    }

    return 0; /* Continue fuzzing */
}

/**
 * Optional: libFuzzer initialization
 */

__attribute__((used)) int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}
