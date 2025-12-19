/**
 * @file fuzz_pem_parsing.c
 * @brief LibFuzzer harness for PEM certificate/key parsing
 *
 * This fuzzer tests:
 * - PEM format validation
 * - Certificate loading from PEM data
 * - Private key loading from PEM data
 * - Truncated/malformed PEM handling
 * - Oversized PEM data handling
 *
 * Build: cmake -DMTLS_ENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang ..
 * Run: ./tests/fuzz/fuzz_pem_parsing corpus/fuzz_pem_parsing/
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "mtls/mtls.h"
#include "mtls/mtls_config.h"
#include "fuzz_common.h"

/* Maximum PEM size for fuzzing (1MB) */
static const size_t FUZZ_MAX_PEM_SIZE = (1024UL * 1024UL);

/**
 * LibFuzzer entry point
 *
 * @param Data Fuzzer-provided input data (PEM-formatted or random)
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

    mtls_config config;
    mtls_err err;

    /* Initialize config to zero */
    memset(&config, 0, sizeof(config));
    memset(&err, 0, sizeof(err));
    mtls_config_init(&config);

    /* Test 1: Parse as certificate PEM
     * This exercises is_valid_pem_format() and OpenSSL's PEM parser
     * mtls_config_set_cert_pem(config, cert_pem, cert_len, key_pem, key_len)
     */
    mtls_config_set_cert_pem(&config, Data, Size, NULL, 0);

    /* Test 2: Try to create context with potentially malformed PEM
     * This will exercise the full TLS initialization path
     */
    mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    if (ctx) {
        /* If we successfully created a context, clean it up */
        mtls_ctx_free(ctx);
    }

    /* Test 3: Edge cases - multiple PEM blocks
     * Some PEM files contain multiple certificates (chains)
     * Split input into two halves and try concatenation
     */
    if (Size > 100) {
        size_t mid = Size / 2;

        /* Try first half as cert */
        mtls_config_set_cert_pem(&config, Data, mid, NULL, 0);

        /* Try second half as cert */
        mtls_config_set_cert_pem(&config, Data + mid, Size - mid, NULL, 0);

        /* Try first half as cert, second half as key */
        mtls_config_set_cert_pem(&config, Data, mid, Data + mid, Size - mid);
    }

    /* Test 4: Common PEM header variations
     * Fuzzer might generate data that looks like PEM headers
     */
    const char *pem_headers[] = {"-----BEGIN CERTIFICATE-----", "-----BEGIN RSA PRIVATE KEY-----",
                                 "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
                                 "-----BEGIN ENCRYPTED PRIVATE KEY-----"};

    for (size_t i = 0; i < sizeof(pem_headers) / sizeof(pem_headers[0]); i++) {
        size_t header_len = strlen(pem_headers[i]);
        if (Size > header_len) {
            /* Prepend header to fuzzer data and test */
            size_t combined_size = header_len + Size;
            if (combined_size <= FUZZ_MAX_PEM_SIZE) {
                uint8_t *combined = (uint8_t *)malloc(combined_size);
                if (combined) {
                    memcpy(combined, pem_headers[i], header_len);
                    memcpy(combined + header_len, Data, Size);

                    mtls_config_set_cert_pem(&config, combined, combined_size, NULL, 0);

                    free(combined);
                }
            }
        }
    }

    /* Test 5: Null byte injection
     * PEM parsing should handle embedded nulls correctly
     */
    if (Size > 10) {
        uint8_t *with_null = (uint8_t *)malloc(Size);
        if (with_null) {
            memcpy(with_null, Data, Size);
            /* Inject null byte at midpoint */
            with_null[Size / 2] = '\0';

            mtls_config_set_cert_pem(&config, with_null, Size, NULL, 0);

            free(with_null);
        }
    }

    /* No cleanup needed for config - it just contains pointers */

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
