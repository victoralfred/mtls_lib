/**
 * @file fuzz_common.c
 * @brief Shared utilities for libFuzzer harnesses
 *
 * This file provides common helper functions used across multiple
 * fuzzing targets for the mTLS library.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/**
 * Safe string duplication with null termination
 * Allocates size+1 bytes and ensures null termination
 *
 * @param data Input data (may not be null-terminated)
 * @param size Number of bytes to copy
 * @return Newly allocated null-terminated string, or NULL on failure
 */
char *fuzz_strndup(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return NULL;
    }

    char *str = (char *)malloc(size + 1);
    if (!str) {
        return NULL;
    }

    memcpy(str, data, size);
    str[size] = '\0';

    return str;
}

/**
 * Check if fuzzer data contains only printable ASCII characters
 *
 * @param data Input data
 * @param size Data size
 * @return 1 if all printable, 0 otherwise
 */
int fuzz_is_printable_ascii(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (data[i] < 32 || data[i] > 126) {
            return 0;
        }
    }
    return 1;
}

/**
 * Split fuzzer input into two parts at the first occurrence of delimiter
 *
 * @param data Input data
 * @param size Data size
 * @param delimiter Delimiter byte
 * @param part1_size Output: size of first part
 * @return Index of delimiter, or size if not found
 */
size_t fuzz_split_input(const uint8_t *data, size_t size, uint8_t delimiter, size_t *part1_size)
{
    for (size_t i = 0; i < size; i++) {
        if (data[i] == delimiter) {
            if (part1_size) {
                *part1_size = i;
            }
            return i;
        }
    }

    if (part1_size) {
        *part1_size = size;
    }
    return size;
}

/**
 * Validate that fuzzer data doesn't contain null bytes
 *
 * @param data Input data
 * @param size Data size
 * @return 1 if no nulls found, 0 if null byte present
 */
int fuzz_no_null_bytes(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0) {
            return 0;
        }
    }
    return 1;
}
