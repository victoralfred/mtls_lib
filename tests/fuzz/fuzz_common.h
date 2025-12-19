/**
 * @file fuzz_common.h
 * @brief Shared utilities for libFuzzer harnesses
 */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Safe string duplication with null termination
 */
char *fuzz_strndup(const uint8_t *data, size_t size);

/**
 * Check if data contains only printable ASCII characters
 */
int fuzz_is_printable_ascii(const uint8_t *data, size_t size);

/**
 * Split input into two parts at delimiter
 */
size_t fuzz_split_input(const uint8_t *data, size_t size, uint8_t delimiter, size_t *part1_size);

/**
 * Validate no null bytes in data
 */
int fuzz_no_null_bytes(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* FUZZ_COMMON_H */
