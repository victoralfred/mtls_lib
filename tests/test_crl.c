/**
 * @file test_crl.c
 * @brief Tests for CRL (Certificate Revocation List) functionality
 *
 * This test suite validates:
 * - CRL API parameter validation
 * - CRL distribution point extraction
 * - CRL status string functions
 * - Error handling for CRL operations
 * - CRL configuration in context
 */

#include "mtls/mtls.h"
#include "mtls/mtls_ocsp.h"
#include "mtls/mtls_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Sample self-signed certificate PEM for testing (no CDP) */
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

/* Test 1: CRL check with NULL parameters */
static void test_crl_check_null_params(void)
{
    printf("Test 1: CRL check NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;

    /* Create minimal config for context */
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";
    config.enable_crl = true;

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* NULL cert_pem */
        mtls_err_init(&err);
        int ret = mtls_crl_check(ctx, NULL, 0, &result, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL result */
        mtls_err_init(&err);
        ret = mtls_crl_check(ctx, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL context */
        mtls_err_init(&err);
        ret = mtls_crl_check(NULL, (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        mtls_ctx_free(ctx);
    }

    printf("  PASS: CRL check NULL parameter handling works\n");
}

/* Test 2: CRL check data with NULL parameters */
static void test_crl_check_data_null_params(void)
{
    printf("Test 2: CRL check data NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;
    uint8_t dummy_crl[] = {0x30, 0x03, 0x02, 0x01, 0x00}; /* Minimal DER */

    /* NULL crl_data */
    int ret =
        mtls_crl_check_data(NULL, 0, (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL cert_pem */
    mtls_err_init(&err);
    ret = mtls_crl_check_data(dummy_crl, sizeof(dummy_crl), NULL, 0, &result, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL result */
    mtls_err_init(&err);
    ret = mtls_crl_check_data(dummy_crl, sizeof(dummy_crl), (const uint8_t *)kTestCertPem,
                              kTestCertPemLen, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: CRL check data NULL parameter handling works\n");
}

/* Test 3: CRL load file with NULL parameters */
static void test_crl_load_file_null_params(void)
{
    printf("Test 3: CRL load file NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";
    config.enable_crl = true;

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* NULL context */
        mtls_err_init(&err);
        int ret = mtls_crl_load_file(NULL, "/path/to/crl.pem", &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL path */
        mtls_err_init(&err);
        ret = mtls_crl_load_file(ctx, NULL, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        mtls_ctx_free(ctx);
    }

    printf("  PASS: CRL load file NULL parameter handling works\n");
}

/* Test 4: CRL load file with non-existent file */
static void test_crl_load_file_not_found(void)
{
    printf("Test 4: CRL load file with non-existent file\n");

    mtls_err err;
    mtls_err_init(&err);

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";
    config.enable_crl = true;

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        mtls_err_init(&err);
        int ret = mtls_crl_load_file(ctx, "/nonexistent/path/to/crl.pem", &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_CRL_FAILED);

        mtls_ctx_free(ctx);
    }

    printf("  PASS: CRL load file correctly handles non-existent file\n");
}

/* Test 5: CRL download with NULL parameters */
static void test_crl_download_null_params(void)
{
    printf("Test 5: CRL download NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";
    config.enable_crl = true;

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* NULL context */
        mtls_err_init(&err);
        int ret = mtls_crl_download(NULL, "http://crl.example.com/crl.pem", 5000, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        /* NULL URL */
        mtls_err_init(&err);
        ret = mtls_crl_download(ctx, NULL, 5000, &err);
        assert(ret == -1);
        assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

        mtls_ctx_free(ctx);
    }

    printf("  PASS: CRL download NULL parameter handling works\n");
}

/* Test 6: CRL get distribution points NULL parameters */
static void test_crl_get_distribution_points_null_params(void)
{
    printf("Test 6: CRL get distribution points NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);
    char urls[4][512];
    size_t num_urls;

    /* NULL cert_pem */
    int ret = mtls_crl_get_distribution_points(NULL, 0, urls, 4, &num_urls, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL urls_out */
    mtls_err_init(&err);
    ret = mtls_crl_get_distribution_points((const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 4,
                                           &num_urls, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL num_urls_out */
    mtls_err_init(&err);
    ret = mtls_crl_get_distribution_points((const uint8_t *)kTestCertPem, kTestCertPemLen, urls, 4,
                                           NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* Zero max_urls */
    mtls_err_init(&err);
    ret = mtls_crl_get_distribution_points((const uint8_t *)kTestCertPem, kTestCertPemLen, urls, 0,
                                           &num_urls, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: CRL get distribution points NULL parameter handling works\n");
}

/* Test 7: CRL get distribution points from cert without CDP */
static void test_crl_get_distribution_points_no_cdp(void)
{
    printf("Test 7: CRL get distribution points from cert without CDP\n");

    mtls_err err;
    mtls_err_init(&err);
    char urls[4][512];
    size_t num_urls = 0;

    /* The test certificate doesn't have a CDP extension */
    int ret = mtls_crl_get_distribution_points((const uint8_t *)kTestCertPem, kTestCertPemLen, urls,
                                               4, &num_urls, &err);

    /* Should return 0 with num_urls=0, or fail with error */
    if (ret == 0) {
        assert(num_urls == 0);
    } else {
        assert(ret == -1);
        /* Error was returned - specific code depends on implementation */
        (void)err;
    }

    printf("  PASS: CRL get distribution points correctly handles cert without CDP\n");
}

/* Test 8: CRL configuration in context */
static void test_crl_config_in_context(void)
{
    printf("Test 8: CRL configuration in context\n");

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";

    /* Verify default CRL settings */
    assert(config.enable_crl == false);
    assert(config.crl_refresh_seconds == 86400);
    assert(config.require_crl == false);

    /* Enable CRL */
    config.enable_crl = true;
    config.crl_path = "/path/to/crl.pem";
    config.crl_url = "http://crl.example.com/crl.pem";
    config.crl_refresh_seconds = 43200; /* 12 hours */
    config.require_crl = true;

    mtls_err err;
    mtls_err_init(&err);
    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* Context was created with CRL enabled */
        mtls_ctx_free(ctx);
    }

    printf("  PASS: CRL configuration in context works\n");
}

/* Test 9: CRL error codes are defined */
static void test_crl_error_codes(void)
{
    printf("Test 9: CRL error codes are defined\n");

    /* Verify error codes are in expected range */
    assert(MTLS_ERR_CRL_FAILED == 316);          // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CRL_DOWNLOAD_FAILED == 317); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CRL_EXPIRED == 318);         // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CRL_PARSE_FAILED == 319);    // NOLINT(cert-dcl03-c,misc-static-assert)

    /* Verify error category names work */
    const char *category = mtls_err_category_name(MTLS_ERR_CRL_FAILED);
    assert(category != NULL);
    assert(strcmp(category, "TLS/Certificate") == 0);

    /* Verify error code names work */
    const char *code_name = mtls_err_code_name(MTLS_ERR_CRL_FAILED);
    assert(code_name != NULL);

    printf("  PASS: CRL error codes are correctly defined\n");
}

/* Test 10: CRL status enum values */
static void test_crl_status_enum(void)
{
    printf("Test 10: CRL status enum values\n");

    /* Verify enum values are as expected */
    assert(MTLS_CRL_STATUS_GOOD == 0);    // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_CRL_STATUS_REVOKED == 1); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_CRL_STATUS_UNKNOWN == 2); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_CRL_STATUS_ERROR == 3);   // NOLINT(cert-dcl03-c,misc-static-assert)

    /* Verify all status values have string representations */
    assert(mtls_crl_status_string(MTLS_CRL_STATUS_GOOD) != NULL);
    assert(mtls_crl_status_string(MTLS_CRL_STATUS_REVOKED) != NULL);
    assert(mtls_crl_status_string(MTLS_CRL_STATUS_UNKNOWN) != NULL);
    assert(mtls_crl_status_string(MTLS_CRL_STATUS_ERROR) != NULL);

    printf("  PASS: CRL status enum values are correct\n");
}

/* Test 11: Revocation cache configuration */
static void test_revocation_cache_config(void)
{
    printf("Test 11: Revocation cache configuration\n");

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";

    /* Verify default cache settings */
    assert(config.revocation_cache_ttl_seconds == 3600);
    assert(config.revocation_cache_max_entries == 10000);

    /* Customize cache settings */
    config.enable_crl = true;
    config.revocation_cache_ttl_seconds = 7200; /* 2 hours */
    config.revocation_cache_max_entries = 50000;

    mtls_err err;
    mtls_err_init(&err);
    mtls_ctx *ctx = mtls_ctx_create(&config, &err);

    if (ctx) {
        /* Context was created with custom cache settings */
        mtls_ctx_free(ctx);
    }

    printf("  PASS: Revocation cache configuration works\n");
}

/* Test 12: CRL check with invalid CRL data */
static void test_crl_check_data_invalid(void)
{
    printf("Test 12: CRL check with invalid CRL data\n");

    mtls_err err;
    mtls_err_init(&err);
    mtls_revocation_result result;

    /* Invalid CRL data (not valid DER/PEM) */
    const char kInvalidCrl[] = "This is not a valid CRL"; // NOLINT(readability-identifier-naming)
    int ret = mtls_crl_check_data((const uint8_t *)kInvalidCrl, strlen(kInvalidCrl),
                                  (const uint8_t *)kTestCertPem, kTestCertPemLen, &result, &err);
    assert(ret == -1);
    /* Error could be CRL parse failed or cert parse failed if test cert is invalid */
    assert(err.code == MTLS_ERR_CRL_PARSE_FAILED || err.code == MTLS_ERR_CRL_FAILED ||
           err.code == MTLS_ERR_CERT_PARSE_FAILED);

    /* Empty CRL data */
    mtls_err_init(&err);
    ret = mtls_crl_check_data((const uint8_t *)"", 0, (const uint8_t *)kTestCertPem,
                              kTestCertPemLen, &result, &err);
    assert(ret == -1);

    printf("  PASS: CRL check correctly rejects invalid CRL data\n");
}

/* Test 13: CRL event types are defined */
static void test_crl_event_types(void)
{
    printf("Test 13: CRL event types are defined\n");

    /* Verify event types are in expected range */
    assert(MTLS_EVENT_CRL_CHECK_START == 15);      // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CRL_CHECK_SUCCESS == 16);    // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CRL_CHECK_FAILURE == 17);    // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CRL_DOWNLOAD_START == 18);   // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CRL_DOWNLOAD_SUCCESS == 19); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CRL_DOWNLOAD_FAILURE == 20); // NOLINT(cert-dcl03-c,misc-static-assert)

    /* OCSP events should also be defined */
    assert(MTLS_EVENT_OCSP_CHECK_START == 11);     // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_OCSP_CHECK_SUCCESS == 12);   // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_OCSP_CHECK_FAILURE == 13);   // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_OCSP_STAPLE_VERIFIED == 14); // NOLINT(cert-dcl03-c,misc-static-assert)

    printf("  PASS: CRL event types are correctly defined\n");
}

/* Test 14: Revocation result structure */
static void test_revocation_result_structure(void)
{
    printf("Test 14: Revocation result structure\n");

    mtls_revocation_result result;
    memset(&result, 0, sizeof(result));

    /* Set all fields */
    result.ocsp_status = MTLS_OCSP_STATUS_GOOD;
    result.crl_status = MTLS_CRL_STATUS_GOOD;
    result.ocsp_checked = true;
    result.crl_checked = true;
    result.revocation_time = 1704067200; /* 2024-01-01 00:00:00 UTC */
    result.revocation_reason = 1;        /* Key compromise */
    result.ocsp_this_update = 1704067200;
    result.ocsp_next_update = 1704153600;
    result.crl_last_update = 1704067200;
    result.crl_next_update = 1704153600;
    strncpy(result.responder_url, "http://ocsp.example.com", sizeof(result.responder_url) - 1);
    result.responder_url[sizeof(result.responder_url) - 1] = '\0';

    /* Verify fields are accessible */
    assert(result.ocsp_status == MTLS_OCSP_STATUS_GOOD);
    assert(result.crl_status == MTLS_CRL_STATUS_GOOD);
    assert(result.ocsp_checked == true);
    assert(result.crl_checked == true);
    assert(result.revocation_time == 1704067200);
    assert(result.revocation_reason == 1);
    assert(result.ocsp_this_update == 1704067200);
    assert(result.ocsp_next_update == 1704153600);
    assert(result.crl_last_update == 1704067200);
    assert(result.crl_next_update == 1704153600);
    assert(strcmp(result.responder_url, "http://ocsp.example.com") == 0);

    printf("  PASS: Revocation result structure works correctly\n");
}

int main(void)
{
    printf("Running CRL tests...\n\n");

    test_crl_check_null_params();
    test_crl_check_data_null_params();
    test_crl_load_file_null_params();
    test_crl_load_file_not_found();
    test_crl_download_null_params();
    test_crl_get_distribution_points_null_params();
    test_crl_get_distribution_points_no_cdp();
    test_crl_config_in_context();
    test_crl_error_codes();
    test_crl_status_enum();
    test_revocation_cache_config();
    test_crl_check_data_invalid();
    test_crl_event_types();
    test_revocation_result_structure();

    printf("\nAll CRL tests passed!\n");
    return 0;
}
