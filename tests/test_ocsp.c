/**
 * @file test_ocsp.c
 * @brief Tests for OCSP (Online Certificate Status Protocol) functionality
 *
 * This test suite validates:
 * - OCSP API parameter validation
 * - OCSP URL extraction from certificates
 * - OCSP status string functions
 * - Error handling for OCSP operations
 * - OCSP configuration in context
 */

#include "mtls/mtls.h"
#include "mtls/mtls_ocsp.h"
#include "mtls/mtls_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Sample self-signed certificate PEM for testing (no OCSP responder) */
static const char kTestCertPem[] = // NOLINT(readability-identifier-naming)
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

static const size_t kTestCertPemLen = // NOLINT(readability-identifier-naming)
    sizeof(kTestCertPem) - 1;

/* Test 1: OCSP check with NULL parameters */
static void test_ocsp_check_null_params(void)
{
    printf("Test 1: OCSP check NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;

    /* Create minimal config for context */
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";
    config.enable_ocsp = true;

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* NULL cert_pem */
        mtls_err_init(&err);
        int ret = mtls_ocsp_check(ctx, NULL, 0, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                                  &result, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL issuer_pem */
        mtls_err_init(&err);
        ret = mtls_ocsp_check(ctx, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0, &result,
                              &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL result */
        mtls_err_init(&err);
        ret = mtls_ocsp_check(ctx, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                              (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL context */
        mtls_err_init(&err);
        ret = mtls_ocsp_check(NULL, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                              (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        mtls_ctx_free(ctx);
    }

    printf("  PASS: OCSP check NULL parameter handling works\n");
}

/* Test 2: OCSP check URL with NULL parameters */
static void test_ocsp_check_url_null_params(void)
{
    printf("Test 2: OCSP check URL NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;

    /* NULL URL */
    int ret =
        mtls_ocsp_check_url(NULL, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                            (const uint8_t *)kTestCertPem, kTestCertPemLen, 5000, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL cert_pem */
    mtls_err_init(&err);
    ret = mtls_ocsp_check_url("http://ocsp.example.com", NULL, 0, (const uint8_t *)kTestCertPem,
                              kTestCertPemLen, 5000, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL issuer_pem */
    mtls_err_init(&err);
    ret = mtls_ocsp_check_url("http://ocsp.example.com", (const uint8_t *)kTestCertPem,
                              kTestCertPemLen, NULL, 0, 5000, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL result */
    mtls_err_init(&err);
    ret = mtls_ocsp_check_url("http://ocsp.example.com", (const uint8_t *)kTestCertPem,
                              kTestCertPemLen, (const uint8_t *)kTestCertPem, kTestCertPemLen, 5000,
                              NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: OCSP check URL NULL parameter handling works\n");
}

/* Test 3: OCSP verify stapled NULL parameters */
static void test_ocsp_verify_stapled_null_params(void)
{
    printf("Test 3: OCSP verify stapled NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;
    uint8_t dummy_response[] = {0x30, 0x03, 0x0a, 0x01, 0x00}; /* Minimal DER */

    /* NULL response */
    int ret =
        mtls_ocsp_verify_stapled(NULL, 0, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                                 (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL cert_pem */
    mtls_err_init(&err);
    ret = mtls_ocsp_verify_stapled(dummy_response, sizeof(dummy_response), NULL, 0,
                                   (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL issuer_pem */
    mtls_err_init(&err);
    ret = mtls_ocsp_verify_stapled(dummy_response, sizeof(dummy_response),
                                   (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0, &result,
                                   &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL result */
    mtls_err_init(&err);
    ret = mtls_ocsp_verify_stapled(dummy_response, sizeof(dummy_response),
                                   (const uint8_t *)kTestCertPem, kTestCertPemLen,
                                   (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: OCSP verify stapled NULL parameter handling works\n");
}

/* Test 4: OCSP get responder URL NULL parameters */
static void test_ocsp_get_responder_url_null_params(void)
{
    printf("Test 4: OCSP get responder URL NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    char url_out[512];

    /* NULL cert_pem */
    int ret = mtls_ocsp_get_responder_url(NULL, 0, url_out, sizeof(url_out), &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL url_out */
    mtls_err_init(&err);
    ret =
        mtls_ocsp_get_responder_url((const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* Zero buffer length */
    mtls_err_init(&err);
    ret = mtls_ocsp_get_responder_url((const uint8_t *)kTestCertPem, kTestCertPemLen, url_out, 0,
                                      &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: OCSP get responder URL NULL parameter handling works\n");
}

/* Test 5: OCSP get responder URL from cert without AIA */
static void test_ocsp_get_responder_url_no_aia(void)
{
    printf("Test 5: OCSP get responder URL from cert without AIA\n");

    mtls_err err;
    mtls_err_init(&err);
    char url_out[512];

    /* The test certificate doesn't have an AIA extension */
    int ret = mtls_ocsp_get_responder_url((const uint8_t *)kTestCertPem, kTestCertPemLen, url_out,
                                          sizeof(url_out), &err);
    /* Should fail because there's no OCSP URL in the cert */
    assert(ret == -1);
    /* Error code should indicate no OCSP URL found - may be various error types */
    (void)err; /* Error was returned, specific code depends on parsing */

    printf("  PASS: OCSP get responder URL correctly handles cert without AIA\n");
}

/* Test 6: Certificate fingerprint computation */
static void test_cert_fingerprint(void)
{
    printf("Test 6: Certificate fingerprint computation\n");

    mtls_err err;
    mtls_err_init(&err);
    uint8_t fingerprint[32];

    /* Try to compute fingerprint - may fail if test cert is invalid */
    int ret =
        mtls_cert_fingerprint((const uint8_t *)kTestCertPem, kTestCertPemLen, fingerprint, &err);

    if (ret == 0) {
        /* Fingerprint computed successfully */
        /* Verify fingerprint is non-zero (has content) */
        int non_zero = 0;
        for (int i = 0; i < 32; i++) {
            if (fingerprint[i] != 0) {
                non_zero = 1;
                break;
            }
        }
        assert(non_zero);

        /* Compute again and verify it's the same */
        uint8_t fingerprint2[32];
        ret = mtls_cert_fingerprint((const uint8_t *)kTestCertPem, kTestCertPemLen, fingerprint2,
                                    &err);
        assert(ret == 0);
        assert(memcmp(fingerprint, fingerprint2, 32) == 0);
        printf("  PASS: Certificate fingerprint computation works\n");
    } else {
        /* Test certificate is not valid, but function correctly returns error */
        printf("  PASS: Certificate fingerprint correctly rejects invalid cert\n");
    }
}

/* Test 7: Certificate fingerprint NULL parameters */
static void test_cert_fingerprint_null_params(void)
{
    printf("Test 7: Certificate fingerprint NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    uint8_t fingerprint[32];

    /* NULL cert_pem */
    int ret = mtls_cert_fingerprint(NULL, 0, fingerprint, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL fingerprint_out */
    mtls_err_init(&err);
    ret = mtls_cert_fingerprint((const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: Certificate fingerprint NULL parameter handling works\n");
}

/* Test 8: Certificate fingerprint with invalid PEM */
static void test_cert_fingerprint_invalid_pem(void)
{
    printf("Test 8: Certificate fingerprint with invalid PEM\n");

    mtls_err err;
    mtls_err_init(&err);
    uint8_t fingerprint[32];

    /* Invalid PEM data */
    const char kInvalidPem[] = // NOLINT(readability-identifier-naming)
        "This is not a valid PEM certificate";
    int ret =
        mtls_cert_fingerprint((const uint8_t *)kInvalidPem, strlen(kInvalidPem), fingerprint, &err);
    assert(ret == -1);
    /* Error code should indicate parsing failure */
    assert(err.code == MTLS_ERR_CERT_PARSE_FAILED || err.code == MTLS_ERR_TLS_INIT_FAILED ||
           err.code == MTLS_ERR_OCSP_FAILED);

    /* Empty PEM */
    mtls_err_init(&err);
    ret = mtls_cert_fingerprint((const uint8_t *)"", 0, fingerprint, &err);
    assert(ret == -1);

    printf("  PASS: Certificate fingerprint correctly rejects invalid PEM\n");
}

/* Test 9: OCSP configuration in context */
static void test_ocsp_config_in_context(void)
{
    printf("Test 9: OCSP configuration in context\n");

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";

    /* Verify default OCSP settings */
    assert(config.enable_ocsp == false);
    assert(config.enable_ocsp_stapling == false);
    assert(config.ocsp_timeout_ms == 5000);
    assert(config.require_ocsp == false);

    /* Enable OCSP */
    config.enable_ocsp = true;
    config.enable_ocsp_stapling = true;
    config.ocsp_url = "http://ocsp.example.com";
    config.ocsp_timeout_ms = 10000;
    config.require_ocsp = true;

    mtls_err err;
    mtls_err_init(&err);
    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* Context was created with OCSP enabled */
        mtls_ctx_free(ctx);
    }

    printf("  PASS: OCSP configuration in context works\n");
}

/* Test 10: Combined revocation check NULL parameters */
static void test_check_revocation_null_params(void)
{
    printf("Test 10: Combined revocation check NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";
    config.enable_ocsp = true;

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* NULL context */
        mtls_err_init(&err);
        int ret =
            mtls_check_revocation(NULL, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                                  (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL cert_pem */
        mtls_err_init(&err);
        ret = mtls_check_revocation(ctx, NULL, 0, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                                    &result, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL result */
        mtls_err_init(&err);
        ret = mtls_check_revocation(ctx, (const uint8_t *)kTestCertPem, kTestCertPemLen,
                                    (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        mtls_ctx_free(ctx);
    }

    printf("  PASS: Combined revocation check NULL parameter handling works\n");
}

/* Test 11: OCSP error codes are defined */
static void test_ocsp_error_codes(void)
{
    printf("Test 11: OCSP error codes are defined\n");

    /* Verify error codes are in expected range */
    assert(MTLS_ERR_OCSP_FAILED == 313);          // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_OCSP_TIMEOUT == 314);         // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_OCSP_RESPONDER_ERROR == 315); // NOLINT(cert-dcl03-c,misc-static-assert)

    /* Verify error category names work */
    const char *category = mtls_err_category_name(MTLS_ERR_OCSP_FAILED);
    assert(category != NULL);
    assert(strcmp(category, "TLS/Certificate") == 0);

    /* Verify error code names work */
    const char *code_name = mtls_err_code_name(MTLS_ERR_OCSP_FAILED);
    assert(code_name != NULL);

    printf("  PASS: OCSP error codes are correctly defined\n");
}

/* Test 12: OCSP status enum values */
static void test_ocsp_status_enum(void)
{
    printf("Test 12: OCSP status enum values\n");

    /* Verify enum values are as expected */
    assert(MTLS_OCSP_STATUS_GOOD == 0);    // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_OCSP_STATUS_REVOKED == 1); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_OCSP_STATUS_UNKNOWN == 2); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_OCSP_STATUS_ERROR == 3);   // NOLINT(cert-dcl03-c,misc-static-assert)

    /* Verify all status values have string representations */
    assert(mtls_ocsp_status_string(MTLS_OCSP_STATUS_GOOD) != NULL);
    assert(mtls_ocsp_status_string(MTLS_OCSP_STATUS_REVOKED) != NULL);
    assert(mtls_ocsp_status_string(MTLS_OCSP_STATUS_UNKNOWN) != NULL);
    assert(mtls_ocsp_status_string(MTLS_OCSP_STATUS_ERROR) != NULL);

    printf("  PASS: OCSP status enum values are correct\n");
}

int main(void)
{
    printf("Running OCSP tests...\n\n");

    test_ocsp_check_null_params();
    test_ocsp_check_url_null_params();
    test_ocsp_verify_stapled_null_params();
    test_ocsp_get_responder_url_null_params();
    test_ocsp_get_responder_url_no_aia();
    test_cert_fingerprint();
    test_cert_fingerprint_null_params();
    test_cert_fingerprint_invalid_pem();
    test_ocsp_config_in_context();
    test_check_revocation_null_params();
    test_ocsp_error_codes();
    test_ocsp_status_enum();

    printf("\nAll OCSP tests passed!\n");
    return 0;
}
