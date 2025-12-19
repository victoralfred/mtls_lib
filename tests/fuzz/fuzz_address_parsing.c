/**
 * @file fuzz_address_parsing.c
 * @brief LibFuzzer harness for network address parsing
 *
 * This fuzzer tests:
 * - IPv4 address parsing
 * - IPv6 address parsing
 * - Hostname parsing
 * - Port number parsing
 * - Malformed address handling
 *
 * Build: cmake -DMTLS_ENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang ..
 * Run: ./tests/fuzz/fuzz_address_parsing corpus/fuzz_address_parsing/
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mtls/mtls.h"
#include "mtls/mtls_types.h"
#include "internal/platform.h"
#include "fuzz_common.h"

/**
 * LibFuzzer entry point
 *
 * @param Data Fuzzer-provided input data (address string)
 * @param Size Size of input data
 * @return 0 to continue fuzzing
 */

// NOLINT(readability-identifier-naming) - libFuzzer requires this name
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    /* Reject unreasonable sizes */
    if (Size == 0 || Size > (size_t)(MTLS_ADDR_STR_MAX_LEN * 2)) {
        return 0;
    }

    /* Test 1: Direct address parsing
     * This exercises platform_parse_addr() with fuzzer data
     */
    char *addr_str = fuzz_strndup(Data, Size);
    if (!addr_str) {
        return 0;
    }

    mtls_addr addr;
    mtls_err err;
    memset(&addr, 0, sizeof(addr));
    memset(&err, 0, sizeof(err));

    /* Parse address - should handle all malformed inputs gracefully */
    (void)platform_parse_addr(addr_str, &addr, &err);

    /* Test 2: Common address format variations */
    const char *prefixes[] = {"",         /* No prefix */
                              "http://",  /* HTTP URL */
                              "https://", /* HTTPS URL */
                              "tcp://",   /* TCP prefix */
                              "//",       /* Protocol-relative */
                              ":",        /* Port only */
                              NULL};

    for (size_t i = 0; prefixes[i] != NULL; i++) {
        size_t prefix_len = strlen(prefixes[i]);
        size_t combined_len = prefix_len + Size;

        if (combined_len <= MTLS_ADDR_STR_MAX_LEN) {
            char *combined = (char *)malloc(combined_len + 1);
            if (combined) {
                memcpy(combined, prefixes[i], prefix_len);
                memcpy(combined + prefix_len, Data, Size);
                combined[combined_len] = '\0';

                (void)platform_parse_addr(combined, &addr, &err);

                free(combined);
            }
        }
    }

    /* Test 3: IPv6 bracket notation
     * IPv6 addresses should be wrapped in brackets: [::1]:port
     */
    if (Size > 2 && Size < MTLS_ADDR_STR_MAX_LEN - 10) {
        char *ipv6_format = (char *)malloc(Size + 12);
        if (ipv6_format) {
            ipv6_format[0] = '[';
            memcpy(ipv6_format + 1, Data, Size);
            memcpy(ipv6_format + Size + 1, "]:8080",
                   7); /* Safe: buffer has Size+12, writing at Size+1 leaves 11 bytes */

            (void)platform_parse_addr(ipv6_format, &addr, &err);

            free(ipv6_format);
        }
    }

    /* Test 4: Port number variations
     * Append various port numbers to fuzzer data
     */
    const char *ports[] = {":0",      /* Minimum port */
                           ":80",     /* HTTP */
                           ":443",    /* HTTPS */
                           ":8080",   /* Alt HTTP */
                           ":65535",  /* Maximum port */
                           ":999999", /* Oversized port */
                           ":-1",     /* Negative port */
                           ":0xFFFF", /* Hex port */
                           NULL};

    for (size_t i = 0; ports[i] != NULL; i++) {
        size_t port_len = strlen(ports[i]);
        size_t combined_len = Size + port_len;

        if (combined_len <= MTLS_ADDR_STR_MAX_LEN) {
            char *with_port = (char *)malloc(combined_len + 1);
            if (with_port) {
                memcpy(with_port, Data, Size);
                memcpy(with_port + Size, ports[i], port_len);
                with_port[combined_len] = '\0';

                (void)platform_parse_addr(with_port, &addr, &err);

                free(with_port);
            }
        }
    }

    /* Test 5: Split input on colon to test host:port parsing
     * If fuzzer provides data with a colon, test both parts
     */
    size_t part1_size = 0;
    size_t colon_pos = fuzz_split_input(Data, Size, ':', &part1_size);

    if (colon_pos < Size && part1_size > 0) {
        /* Found a colon - test host and port separately */
        char *host = fuzz_strndup(Data, part1_size);
        char *port = fuzz_strndup(Data + colon_pos + 1, Size - colon_pos - 1);

        if (host && port) {
            size_t combined_len = part1_size + 1 + (Size - colon_pos - 1);
            if (combined_len <= MTLS_ADDR_STR_MAX_LEN) {
                char *host_port = (char *)malloc(combined_len + 1);
                if (host_port) {
                    snprintf(host_port, combined_len + 1, "%s:%s", host, port);
                    (void)platform_parse_addr(host_port, &addr, &err);
                    free(host_port);
                }
            }
        }

        free(host);
        free(port);
    }

    /* Test 6: Null byte injection
     * Address parsing should handle embedded nulls correctly
     */
    if (Size > 5) {
        char *with_null = (char *)malloc(Size + 1);
        if (with_null) {
            memcpy(with_null, Data, Size);
            with_null[Size / 2] = '\0'; /* Inject null at midpoint */
            with_null[Size] = '\0';

            (void)platform_parse_addr(with_null, &addr, &err);

            free(with_null);
        }
    }

    /* Test 7: Edge cases */
    (void)platform_parse_addr("", &addr, &err);     /* Empty string */
    (void)platform_parse_addr(NULL, &addr, &err);   /* NULL pointer */
    (void)platform_parse_addr(":", &addr, &err);    /* Colon only */
    (void)platform_parse_addr("::", &addr, &err);   /* Double colon */
    (void)platform_parse_addr(":::", &addr, &err);  /* Triple colon */
    (void)platform_parse_addr("[]", &addr, &err);   /* Empty brackets */
    (void)platform_parse_addr("[]:0", &addr, &err); /* Empty brackets with port */

    /* Cleanup */
    free(addr_str);

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
