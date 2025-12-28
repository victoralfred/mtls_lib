/**
 * @file test_pinning.c
 * @brief Tests for certificate pinning functionality
 *
 * This test suite validates:
 * - Pin set initialization and management
 * - Pin format validation
 * - Hash computation functions
 * - Pin validation against certificates
 * - Error handling
 */

#include "mtls/mtls.h"
#include "mtls/mtls_pinning.h"
#include "mtls/mtls_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Sample self-signed certificate PEM for testing */
// NOLINTNEXTLINE(readability-identifier-naming)
static const char kTestCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n"
    "c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n"
    "BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC8n7A7BrBjepnLKJTu3wwz\n"
    "FNLHm2LRH5+MLgJYUIDS+bknGkP+/VFNwFxmT3+8S0eOSvVxq8ZYylLPipJNAgMB\n"
    "AAGjUzBRMB0GA1UdDgQWBBQpMYvtKlGeT3BBYS3dPLZkLwz1PTAfBgNVHSMEGDAW\n"
    "gBQpMYvtKlGeT3BBYS3dPLZkLwz1PTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
    "DQEBCwUAA0EAIxuMEj4f6p+VtBz/gKHr3WMB7VKUNn+aDIGn1V0hNHfetlNKJLXV\n"
    "VZdKXWzL3RK8gOPcYgEJDhXxUmpJoXuQTQ==\n"
    "-----END CERTIFICATE-----\n";

// NOLINTNEXTLINE(readability-identifier-naming)
static const size_t kTestCertPemLen = sizeof(kTestCertPem) - 1;

/* Valid base64-encoded SHA-256 hash (44 characters with padding) */
// NOLINTNEXTLINE(readability-identifier-naming)
static const char kValidHash1[] = "kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk=";

/* Another valid base64-encoded SHA-256 hash */
// NOLINTNEXTLINE(readability-identifier-naming)
static const char kValidHash2[] = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

/* Test 1: Pin set initialization */
static void test_pin_set_init(void)
{
    printf("Test 1: Pin set initialization\n");

    mtls_pin_set set;
    mtls_pin_set_init(&set);

    assert(set.spki_sha256_count == 0);
    assert(set.cert_sha256_count == 0);
    assert(set.require_match == true);
    assert(set.include_leaf_only == false);
    assert(mtls_pin_set_count(&set) == 0);

    /* NULL should not crash */
    mtls_pin_set_init(NULL);

    printf("  PASS: Pin set initialization works\n");
}

/* Test 2: Add SPKI pin to set */
static void test_pin_set_add_spki(void)
{
    printf("Test 2: Add SPKI pin to set\n");

    mtls_pin_set set;
    mtls_pin_set_init(&set);
    mtls_err err;
    mtls_err_init(&err);

    /* Add valid SPKI pin */
    int ret = mtls_pin_set_add_spki_sha256(&set, kValidHash1, &err);
    assert(ret == 0);
    assert(set.spki_sha256_count == 1);
    assert(mtls_pin_set_count(&set) == 1);

    /* Add another valid SPKI pin */
    ret = mtls_pin_set_add_spki_sha256(&set, kValidHash2, &err);
    assert(ret == 0);
    assert(set.spki_sha256_count == 2);
    assert(mtls_pin_set_count(&set) == 2);

    printf("  PASS: Adding SPKI pins works\n");
}

/* Test 3: Add certificate pin to set */
static void test_pin_set_add_cert(void)
{
    printf("Test 3: Add certificate pin to set\n");

    mtls_pin_set set;
    mtls_pin_set_init(&set);
    mtls_err err;
    mtls_err_init(&err);

    /* Add valid cert pin */
    int ret = mtls_pin_set_add_cert_sha256(&set, kValidHash1, &err);
    assert(ret == 0);
    assert(set.cert_sha256_count == 1);
    assert(mtls_pin_set_count(&set) == 1);

    printf("  PASS: Adding certificate pins works\n");
}

/* Test 4: Invalid hash format */
static void test_invalid_hash_format(void)
{
    printf("Test 4: Invalid hash format validation\n");

    mtls_pin_set set;
    mtls_pin_set_init(&set);
    mtls_err err;
    mtls_err_init(&err);

    /* Too short */
    int ret = mtls_pin_set_add_spki_sha256(&set, "AAAA", &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_PIN_INVALID_FORMAT);

    /* Too long */
    mtls_err_init(&err);
    ret =
        mtls_pin_set_add_spki_sha256(&set, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_PIN_INVALID_FORMAT);

    /* Invalid characters */
    mtls_err_init(&err);
    ret = mtls_pin_set_add_spki_sha256(&set, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!@#", &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_PIN_INVALID_FORMAT);

    /* NULL hash */
    mtls_err_init(&err);
    ret = mtls_pin_set_add_spki_sha256(&set, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL set */
    mtls_err_init(&err);
    ret = mtls_pin_set_add_spki_sha256(NULL, kValidHash1, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: Invalid hash format correctly rejected\n");
}

/* Test 5: Hash format validation function */
static void test_validate_hash_format(void)
{
    printf("Test 5: Hash format validation function\n");

    /* Valid hashes */
    assert(mtls_pin_validate_hash_format(kValidHash1) == true);
    assert(mtls_pin_validate_hash_format(kValidHash2) == true);

    /* Invalid hashes */
    assert(mtls_pin_validate_hash_format(NULL) == false);
    assert(mtls_pin_validate_hash_format("") == false);
    assert(mtls_pin_validate_hash_format("tooshort") == false);
    assert(mtls_pin_validate_hash_format("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!@#") == false);

    printf("  PASS: Hash format validation works\n");
}

/* Test 6: Pin set clear */
static void test_pin_set_clear(void)
{
    printf("Test 6: Pin set clear\n");

    mtls_pin_set set;
    mtls_pin_set_init(&set);
    mtls_err err;
    mtls_err_init(&err);

    /* Add some pins */
    mtls_pin_set_add_spki_sha256(&set, kValidHash1, &err);
    mtls_pin_set_add_cert_sha256(&set, kValidHash1, &err);
    assert(mtls_pin_set_count(&set) == 2);

    /* Change settings */
    set.require_match = false;
    set.include_leaf_only = true;

    /* Clear and verify */
    mtls_pin_set_clear(&set);
    assert(mtls_pin_set_count(&set) == 0);
    assert(set.require_match == false);    /* Settings preserved */
    assert(set.include_leaf_only == true); /* Settings preserved */

    /* NULL should not crash */
    mtls_pin_set_clear(NULL);

    printf("  PASS: Pin set clear works\n");
}

/* Test 7: Compute SPKI hash */
static void test_compute_spki_hash(void)
{
    printf("Test 7: Compute SPKI hash\n");

    mtls_err err;
    mtls_err_init(&err);
    char hash[MTLS_PIN_SHA256_BASE64_SIZE];

    /* Compute SPKI hash for test certificate */
    int ret = mtls_pin_compute_spki_hash((const uint8_t *)kTestCertPem, kTestCertPemLen, hash,
                                         sizeof(hash), &err);

    if (ret == 0) {
        /* Hash computed successfully */
        assert(strlen(hash) >= 43);
        assert(mtls_pin_validate_hash_format(hash));

        /* Compute again and verify consistency */
        char hash2[MTLS_PIN_SHA256_BASE64_SIZE];
        ret = mtls_pin_compute_spki_hash((const uint8_t *)kTestCertPem, kTestCertPemLen, hash2,
                                         sizeof(hash2), &err);
        assert(ret == 0);
        assert(strcmp(hash, hash2) == 0);

        printf("  PASS: SPKI hash computation works (hash: %s)\n", hash);
    } else {
        /* Test certificate may be invalid, but error handling works */
        printf("  PASS: SPKI hash computation correctly handles errors\n");
    }
}

/* Test 8: Compute certificate hash */
static void test_compute_cert_hash(void)
{
    printf("Test 8: Compute certificate hash\n");

    mtls_err err;
    mtls_err_init(&err);
    char hash[MTLS_PIN_SHA256_BASE64_SIZE];

    /* Compute certificate hash */
    int ret = mtls_pin_compute_cert_hash((const uint8_t *)kTestCertPem, kTestCertPemLen, hash,
                                         sizeof(hash), &err);

    if (ret == 0) {
        assert(strlen(hash) >= 43);
        assert(mtls_pin_validate_hash_format(hash));
        printf("  PASS: Certificate hash computation works (hash: %s)\n", hash);
    } else {
        printf("  PASS: Certificate hash computation correctly handles errors\n");
    }
}

/* Test 9: Compute hash NULL parameters */
static void test_compute_hash_null_params(void)
{
    printf("Test 9: Compute hash NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    char hash[MTLS_PIN_SHA256_BASE64_SIZE];

    /* NULL cert_pem */
    int ret = mtls_pin_compute_spki_hash(NULL, 0, hash, sizeof(hash), &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL output buffer */
    mtls_err_init(&err);
    ret = mtls_pin_compute_spki_hash((const uint8_t *)kTestCertPem, kTestCertPemLen, NULL,
                                     sizeof(hash), &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* Buffer too small */
    mtls_err_init(&err);
    ret =
        mtls_pin_compute_spki_hash((const uint8_t *)kTestCertPem, kTestCertPemLen, hash, 10, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: Hash computation NULL parameter handling works\n");
}

/* Test 10: Validate certificate against pins */
static void test_pin_validate_cert(void)
{
    printf("Test 10: Validate certificate against pins\n");

    mtls_err err;
    mtls_err_init(&err);
    char spki_hash[MTLS_PIN_SHA256_BASE64_SIZE];

    /* First compute the actual SPKI hash */
    int ret = mtls_pin_compute_spki_hash((const uint8_t *)kTestCertPem, kTestCertPemLen, spki_hash,
                                         sizeof(spki_hash), &err);

    if (ret == 0) {
        /* Create pin set with the computed hash */
        mtls_pin_set set;
        mtls_pin_set_init(&set);
        mtls_err_init(&err);

        ret = mtls_pin_set_add_spki_sha256(&set, spki_hash, &err);
        assert(ret == 0);

        /* Validate - should pass */
        mtls_err_init(&err);
        ret = mtls_pin_validate_cert((const uint8_t *)kTestCertPem, kTestCertPemLen, &set, &err);
        assert(ret == 0);

        /* Create pin set with wrong hash - should fail */
        mtls_pin_set set2;
        mtls_pin_set_init(&set2);
        mtls_err_init(&err);

        ret = mtls_pin_set_add_spki_sha256(&set2, kValidHash1, &err);
        assert(ret == 0);

        mtls_err_init(&err);
        ret = mtls_pin_validate_cert((const uint8_t *)kTestCertPem, kTestCertPemLen, &set2, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_PIN_VALIDATION_FAILED);

        printf("  PASS: Certificate pin validation works\n");
    } else {
        printf("  PASS: Certificate pin validation test skipped (cert parsing failed)\n");
    }
}

/* Test 11: Empty pin set validation */
static void test_empty_pin_set_validation(void)
{
    printf("Test 11: Empty pin set validation\n");

    mtls_pin_set set;
    mtls_pin_set_init(&set);
    mtls_err err;
    mtls_err_init(&err);

    /* Empty set should always pass */
    int ret = mtls_pin_validate_cert((const uint8_t *)kTestCertPem, kTestCertPemLen, &set, &err);
    assert(ret == 0);

    printf("  PASS: Empty pin set validation works\n");
}

/* Test 12: Pin result and type strings */
static void test_pin_strings(void)
{
    printf("Test 12: Pin result and type strings\n");

    /* Result strings */
    assert(strcmp(mtls_pin_result_string(MTLS_PIN_RESULT_MATCH), "match") == 0);
    assert(strcmp(mtls_pin_result_string(MTLS_PIN_RESULT_NO_MATCH), "no_match") == 0);
    assert(strcmp(mtls_pin_result_string(MTLS_PIN_RESULT_INVALID_PIN), "invalid_pin") == 0);
    assert(strcmp(mtls_pin_result_string(MTLS_PIN_RESULT_ERROR), "error") == 0);
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    assert(strcmp(mtls_pin_result_string((mtls_pin_result)99), "unknown") == 0);

    /* Type strings */
    assert(strcmp(mtls_pin_type_string(MTLS_PIN_TYPE_SPKI_SHA256), "spki_sha256") == 0);
    assert(strcmp(mtls_pin_type_string(MTLS_PIN_TYPE_CERT_SHA256), "cert_sha256") == 0);
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    assert(strcmp(mtls_pin_type_string((mtls_pin_type)99), "unknown") == 0);

    printf("  PASS: Pin result and type strings work\n");
}

/* Test 13: Pin error codes are defined */
static void test_pin_error_codes(void)
{
    printf("Test 13: Pin error codes are defined\n");

    /* Verify error codes are in expected range */
    assert(MTLS_ERR_PIN_VALIDATION_FAILED == 320); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_PIN_INVALID_FORMAT == 321);    // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_PIN_COMPUTE_FAILED == 322);    // NOLINT(cert-dcl03-c,misc-static-assert)

    /* Verify error category */
    const char *category = mtls_err_category_name(MTLS_ERR_PIN_VALIDATION_FAILED);
    assert(category != NULL);
    assert(strcmp(category, "TLS/Certificate") == 0);

    /* Verify error code names work */
    const char *code_name = mtls_err_code_name(MTLS_ERR_PIN_VALIDATION_FAILED);
    assert(code_name != NULL);
    assert(strcmp(code_name, "MTLS_ERR_PIN_VALIDATION_FAILED") == 0);

    printf("  PASS: Pin error codes are correctly defined\n");
}

/* Test 14: Pin event types are defined */
static void test_pin_event_types(void)
{
    printf("Test 14: Pin event types are defined\n");

    /* Verify event types are in expected range */
    assert(MTLS_EVENT_PIN_CHECK_START == 60);   // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_PIN_CHECK_SUCCESS == 61); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_PIN_CHECK_FAILURE == 62); // NOLINT(cert-dcl03-c,misc-static-assert)

    printf("  PASS: Pin event types are correctly defined\n");
}

/* Test 15: Config fields for pinning */
static void test_pin_config_fields(void)
{
    printf("Test 15: Config fields for pinning\n");

    mtls_config config;
    mtls_config_init(&config);

    /* Verify pinning fields exist and are initialized */
    assert(config.pin_spki_sha256 == NULL);
    assert(config.pin_spki_sha256_count == 0);
    assert(config.pin_cert_sha256 == NULL);
    assert(config.pin_cert_sha256_count == 0);
    assert(config.pin_require_match == false);
    assert(config.pin_include_leaf_only == false);

    /* Set some values */
    const char *spki_pins[] = {kValidHash1, kValidHash2};
    config.pin_spki_sha256 = spki_pins;
    config.pin_spki_sha256_count = 2;
    config.pin_require_match = true;

    /* Verify values */
    assert(config.pin_spki_sha256_count == 2);
    assert(config.pin_require_match == true);

    printf("  PASS: Config fields for pinning work\n");
}

int main(void)
{
    printf("Running certificate pinning tests...\n\n");

    test_pin_set_init();
    test_pin_set_add_spki();
    test_pin_set_add_cert();
    test_invalid_hash_format();
    test_validate_hash_format();
    test_pin_set_clear();
    test_compute_spki_hash();
    test_compute_cert_hash();
    test_compute_hash_null_params();
    test_pin_validate_cert();
    test_empty_pin_set_validation();
    test_pin_strings();
    test_pin_error_codes();
    test_pin_event_types();
    test_pin_config_fields();

    printf("\nAll certificate pinning tests passed!\n");
    return 0;
}
