/**
 * @file test_ct.c
 * @brief Tests for Certificate Transparency (CT) functionality
 *
 * This test suite validates:
 * - CT log list management
 * - SCT parsing and extraction
 * - SCT validation
 * - Error handling
 */

#include "mtls/mtls.h"
#include "mtls/mtls_ct.h"
#include "mtls/mtls_error.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Sample log ID (32 bytes, all zeros for testing) */
// NOLINTNEXTLINE(readability-identifier-naming)
static const uint8_t kTestLogId[MTLS_CT_LOG_ID_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

/* Sample public key DER (minimal for testing) */
// NOLINTNEXTLINE(readability-identifier-naming)
static const uint8_t kTestPubKeyDer[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                         0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                         0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

// NOLINTNEXTLINE(readability-identifier-naming)
static const size_t kTestPubKeyDerLen = sizeof(kTestPubKeyDer);

/* Test 1: CT log list initialization */
static void test_ct_log_list_init(void)
{
    printf("Test 1: CT log list initialization\n");

    mtls_ct_log_list list;
    mtls_ct_log_list_init(&list);

    assert(list.log_count == 0);
    assert(mtls_ct_log_list_count(&list) == 0);

    /* NULL should not crash */
    mtls_ct_log_list_init(NULL);

    printf("  PASS: CT log list initialization works\n");
}

/* Test 2: Add log to list */
static void test_ct_log_list_add(void)
{
    printf("Test 2: Add log to list\n");

    mtls_ct_log_list list;
    mtls_ct_log_list_init(&list);
    mtls_err err;
    mtls_err_init(&err);

    /* Add a log */
    int ret = mtls_ct_log_list_add(&list, kTestLogId, "Test Log", kTestPubKeyDer, kTestPubKeyDerLen,
                                   MTLS_CT_LOG_STATUS_USABLE, &err);
    assert(ret == 0);
    assert(list.log_count == 1);
    assert(mtls_ct_log_list_count(&list) == 1);

    /* Verify log data */
    assert(memcmp(list.logs[0].log_id, kTestLogId, MTLS_CT_LOG_ID_SIZE) == 0);
    assert(strcmp(list.logs[0].description, "Test Log") == 0);
    assert(list.logs[0].status == MTLS_CT_LOG_STATUS_USABLE);
    assert(list.logs[0].public_key_der_len == kTestPubKeyDerLen);

    /* Clean up */
    mtls_ct_log_list_free(&list);

    printf("  PASS: Adding logs works\n");
}

/* Test 3: Find log in list */
static void test_ct_log_list_find(void)
{
    printf("Test 3: Find log in list\n");

    mtls_ct_log_list list;
    mtls_ct_log_list_init(&list);
    mtls_err err;
    mtls_err_init(&err);

    /* Add a log */
    mtls_ct_log_list_add(&list, kTestLogId, "Test Log", kTestPubKeyDer, kTestPubKeyDerLen,
                         MTLS_CT_LOG_STATUS_USABLE, &err);

    /* Find it */
    const mtls_ct_log *found = mtls_ct_log_list_find(&list, kTestLogId);
    assert(found != NULL);
    assert(memcmp(found->log_id, kTestLogId, MTLS_CT_LOG_ID_SIZE) == 0);
    assert(strcmp(found->description, "Test Log") == 0);

    /* Search for non-existent log */
    uint8_t fake_id[MTLS_CT_LOG_ID_SIZE] = {0xff};
    const mtls_ct_log *not_found = mtls_ct_log_list_find(&list, fake_id);
    assert(not_found == NULL);

    /* Clean up */
    mtls_ct_log_list_free(&list);

    printf("  PASS: Finding logs works\n");
}

/* Test 4: Clear and free log list */
static void test_ct_log_list_clear(void)
{
    printf("Test 4: Clear and free log list\n");

    mtls_ct_log_list list;
    mtls_ct_log_list_init(&list);
    mtls_err err;
    mtls_err_init(&err);

    /* Add some logs */
    mtls_ct_log_list_add(&list, kTestLogId, "Test Log 1", kTestPubKeyDer, kTestPubKeyDerLen,
                         MTLS_CT_LOG_STATUS_USABLE, &err);

    uint8_t log_id2[MTLS_CT_LOG_ID_SIZE];
    memset(log_id2, 0xAA, MTLS_CT_LOG_ID_SIZE);
    mtls_ct_log_list_add(&list, log_id2, "Test Log 2", kTestPubKeyDer, kTestPubKeyDerLen,
                         MTLS_CT_LOG_STATUS_READONLY, &err);

    assert(list.log_count == 2);

    /* Clear */
    mtls_ct_log_list_clear(&list);
    assert(list.log_count == 0);

    /* NULL should not crash */
    mtls_ct_log_list_clear(NULL);
    mtls_ct_log_list_free(NULL);

    printf("  PASS: Clear and free works\n");
}

/* Test 5: NULL parameter handling */
static void test_ct_null_params(void)
{
    printf("Test 5: NULL parameter handling\n");

    mtls_err err;
    mtls_err_init(&err);

    /* mtls_ct_log_list_add with NULL params */
    int ret = mtls_ct_log_list_add(NULL, kTestLogId, "Test", kTestPubKeyDer, kTestPubKeyDerLen,
                                   MTLS_CT_LOG_STATUS_USABLE, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    mtls_ct_log_list list;
    mtls_ct_log_list_init(&list);

    mtls_err_init(&err);
    ret = mtls_ct_log_list_add(&list, NULL, "Test", kTestPubKeyDer, kTestPubKeyDerLen,
                               MTLS_CT_LOG_STATUS_USABLE, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    mtls_err_init(&err);
    ret = mtls_ct_log_list_add(&list, kTestLogId, "Test", NULL, 0, MTLS_CT_LOG_STATUS_USABLE, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* mtls_ct_log_list_find with NULL params */
    assert(mtls_ct_log_list_find(NULL, kTestLogId) == NULL);
    assert(mtls_ct_log_list_find(&list, NULL) == NULL);

    /* mtls_ct_log_list_count with NULL */
    assert(mtls_ct_log_list_count(NULL) == 0);

    printf("  PASS: NULL parameter handling works\n");
}

/* Test 6: SCT extraction from cert without SCTs */
static void test_ct_extract_scts_no_scts(void)
{
    printf("Test 6: SCT extraction from cert without SCTs\n");

    mtls_sct scts[MTLS_CT_MAX_SCTS];
    size_t sct_count = 0;
    mtls_err err;
    mtls_err_init(&err);

    /* Test certificate doesn't have SCTs embedded */
    int ret = mtls_ct_extract_scts_from_cert((const uint8_t *)kTestCertPem, kTestCertPemLen, scts,
                                             MTLS_CT_MAX_SCTS, &sct_count, &err);

    /* Result depends on whether cert can be parsed - test cert may be minimal */
    if (ret == 0) {
        /* If parsed successfully, should have 0 SCTs */
        assert(sct_count == 0);
        printf("  PASS: SCT extraction with no SCTs works (cert parsed)\n");
    } else {
        /* Cert parsing failed - still validates error handling works */
        assert(err.code == MTLS_ERR_CT_VALIDATION_FAILED);
        printf("  PASS: SCT extraction correctly handles unparseable certs\n");
    }
}

/* Test 7: SCT extraction NULL parameters */
static void test_ct_extract_scts_null_params(void)
{
    printf("Test 7: SCT extraction NULL parameter handling\n");

    mtls_sct scts[MTLS_CT_MAX_SCTS];
    size_t sct_count = 0;
    mtls_err err;
    mtls_err_init(&err);

    /* NULL cert_pem */
    int ret = mtls_ct_extract_scts_from_cert(NULL, 0, scts, MTLS_CT_MAX_SCTS, &sct_count, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL scts */
    mtls_err_init(&err);
    ret = mtls_ct_extract_scts_from_cert((const uint8_t *)kTestCertPem, kTestCertPemLen, NULL,
                                         MTLS_CT_MAX_SCTS, &sct_count, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL sct_count */
    mtls_err_init(&err);
    ret = mtls_ct_extract_scts_from_cert((const uint8_t *)kTestCertPem, kTestCertPemLen, scts,
                                         MTLS_CT_MAX_SCTS, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: SCT extraction NULL parameter handling works\n");
}

/* Test 8: SCT validation with empty list */
static void test_ct_validate_scts_empty(void)
{
    printf("Test 8: SCT validation with empty SCT list\n");

    mtls_ct_log_list log_list;
    mtls_ct_log_list_init(&log_list);
    mtls_ct_report report;
    mtls_err err;
    mtls_err_init(&err);

    /* Empty SCT list should return NO_SCTS */
    mtls_ct_result result =
        mtls_ct_validate_scts(NULL, 0, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0,
                              &log_list, 2, false, &report, &err);
    assert(result == MTLS_CT_RESULT_ERROR);

    /* With non-NULL scts but 0 count */
    mtls_sct scts[1];
    mtls_err_init(&err);
    result = mtls_ct_validate_scts(scts, 0, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0,
                                   &log_list, 2, false, &report, &err);
    assert(result == MTLS_CT_RESULT_NO_SCTS);
    assert(err.code == MTLS_ERR_CT_NO_SCTS);

    printf("  PASS: SCT validation with empty list works\n");
}

/* Test 9: CT result string functions */
static void test_ct_result_strings(void)
{
    printf("Test 9: CT result string functions\n");

    /* CT result strings */
    assert(strcmp(mtls_ct_result_string(MTLS_CT_RESULT_VALID), "Valid") == 0);
    assert(strcmp(mtls_ct_result_string(MTLS_CT_RESULT_NO_SCTS), "No SCTs") == 0);
    assert(strcmp(mtls_ct_result_string(MTLS_CT_RESULT_INSUFFICIENT), "Insufficient SCTs") == 0);
    assert(strcmp(mtls_ct_result_string(MTLS_CT_RESULT_INVALID), "Invalid") == 0);
    assert(strcmp(mtls_ct_result_string(MTLS_CT_RESULT_ERROR), "Error") == 0);
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    assert(strcmp(mtls_ct_result_string((mtls_ct_result)99), "Unknown") == 0);

    /* SCT validation result strings */
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_VALID), "Valid") == 0);
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_INVALID_SIGNATURE),
                  "Invalid signature") == 0);
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_UNKNOWN_LOG), "Unknown log") == 0);
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_INVALID_TIMESTAMP),
                  "Invalid timestamp") == 0);
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_INVALID_VERSION), "Invalid version") ==
           0);
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_PARSE_ERROR), "Parse error") == 0);
    assert(strcmp(mtls_sct_validation_result_string(MTLS_SCT_LOG_DISQUALIFIED),
                  "Log disqualified") == 0);

    /* SCT source strings */
    assert(strcmp(mtls_sct_source_string(MTLS_SCT_SOURCE_EMBEDDED), "Embedded") == 0);
    assert(strcmp(mtls_sct_source_string(MTLS_SCT_SOURCE_TLS_EXTENSION), "TLS extension") == 0);
    assert(strcmp(mtls_sct_source_string(MTLS_SCT_SOURCE_OCSP), "OCSP") == 0);

    /* Log status strings */
    assert(strcmp(mtls_ct_log_status_string(MTLS_CT_LOG_STATUS_UNKNOWN), "Unknown") == 0);
    assert(strcmp(mtls_ct_log_status_string(MTLS_CT_LOG_STATUS_USABLE), "Usable") == 0);
    assert(strcmp(mtls_ct_log_status_string(MTLS_CT_LOG_STATUS_READONLY), "Read-only") == 0);
    assert(strcmp(mtls_ct_log_status_string(MTLS_CT_LOG_STATUS_RETIRED), "Retired") == 0);
    assert(strcmp(mtls_ct_log_status_string(MTLS_CT_LOG_STATUS_DISQUALIFIED), "Disqualified") == 0);

    printf("  PASS: CT result string functions work\n");
}

/* Test 10: Compute log ID */
static void test_ct_compute_log_id(void)
{
    printf("Test 10: Compute log ID\n");

    uint8_t log_id[MTLS_CT_LOG_ID_SIZE];
    mtls_err err;
    mtls_err_init(&err);

    /* Compute log ID */
    int ret = mtls_ct_compute_log_id(kTestPubKeyDer, kTestPubKeyDerLen, log_id, &err);
    assert(ret == 0);

    /* Compute again and verify consistency */
    uint8_t log_id2[MTLS_CT_LOG_ID_SIZE];
    ret = mtls_ct_compute_log_id(kTestPubKeyDer, kTestPubKeyDerLen, log_id2, &err);
    assert(ret == 0);
    assert(memcmp(log_id, log_id2, MTLS_CT_LOG_ID_SIZE) == 0);

    /* NULL parameters */
    mtls_err_init(&err);
    ret = mtls_ct_compute_log_id(NULL, 0, log_id, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    mtls_err_init(&err);
    ret = mtls_ct_compute_log_id(kTestPubKeyDer, kTestPubKeyDerLen, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: Compute log ID works\n");
}

/* Test 11: Log ID to base64 */
static void test_ct_log_id_to_base64(void)
{
    printf("Test 11: Log ID to base64\n");

    char base64[MTLS_CT_LOG_ID_BASE64_SIZE];

    /* Convert log ID to base64 */
    int ret = mtls_ct_log_id_to_base64(kTestLogId, base64, sizeof(base64));
    assert(ret == 0);

    /* Base64 output should be valid */
    assert(strlen(base64) > 0);
    assert(strlen(base64) <= 44); /* Base64 of 32 bytes */

    /* NULL parameters */
    ret = mtls_ct_log_id_to_base64(NULL, base64, sizeof(base64));
    assert(ret == -1);

    ret = mtls_ct_log_id_to_base64(kTestLogId, NULL, sizeof(base64));
    assert(ret == -1);

    printf("  PASS: Log ID to base64 works\n");
}

/* Test 12: CT error codes are defined */
static void test_ct_error_codes(void)
{
    printf("Test 12: CT error codes are defined\n");

    /* Verify error codes are in expected range */
    assert(MTLS_ERR_CT_VALIDATION_FAILED == 323); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CT_NO_SCTS == 324);           // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CT_INSUFFICIENT_SCTS == 325); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CT_INVALID_SCT == 326);       // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CT_UNKNOWN_LOG == 327);       // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_ERR_CT_LOG_LIST_PARSE == 328);    // NOLINT(cert-dcl03-c,misc-static-assert)

    /* Verify error category */
    const char *category = mtls_err_category_name(MTLS_ERR_CT_VALIDATION_FAILED);
    assert(category != NULL);
    assert(strcmp(category, "TLS/Certificate") == 0);

    /* Verify error code names work */
    assert(strcmp(mtls_err_code_name(MTLS_ERR_CT_VALIDATION_FAILED),
                  "MTLS_ERR_CT_VALIDATION_FAILED") == 0);
    assert(strcmp(mtls_err_code_name(MTLS_ERR_CT_NO_SCTS), "MTLS_ERR_CT_NO_SCTS") == 0);
    assert(strcmp(mtls_err_code_name(MTLS_ERR_CT_INSUFFICIENT_SCTS),
                  "MTLS_ERR_CT_INSUFFICIENT_SCTS") == 0);
    assert(strcmp(mtls_err_code_name(MTLS_ERR_CT_INVALID_SCT), "MTLS_ERR_CT_INVALID_SCT") == 0);
    assert(strcmp(mtls_err_code_name(MTLS_ERR_CT_UNKNOWN_LOG), "MTLS_ERR_CT_UNKNOWN_LOG") == 0);
    assert(strcmp(mtls_err_code_name(MTLS_ERR_CT_LOG_LIST_PARSE), "MTLS_ERR_CT_LOG_LIST_PARSE") ==
           0);

    printf("  PASS: CT error codes are correctly defined\n");
}

/* Test 13: CT event types are defined */
static void test_ct_event_types(void)
{
    printf("Test 13: CT event types are defined\n");

    /* Verify event types are in expected range */
    assert(MTLS_EVENT_CT_CHECK_START == 80);   // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CT_CHECK_SUCCESS == 81); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CT_CHECK_FAILURE == 82); // NOLINT(cert-dcl03-c,misc-static-assert)
    assert(MTLS_EVENT_CT_SCT_VALIDATED == 83); // NOLINT(cert-dcl03-c,misc-static-assert)

    printf("  PASS: CT event types are correctly defined\n");
}

/* Test 14: Config fields for CT */
static void test_ct_config_fields(void)
{
    printf("Test 14: Config fields for CT\n");

    mtls_config config;
    mtls_config_init(&config);

    /* Verify CT fields exist and are initialized */
    assert(config.enable_ct == false);
    assert(config.require_ct == false);
    assert(config.ct_min_scts == 0);
    assert(config.ct_log_list_path == NULL);
    assert(config.ct_log_list_json == NULL);
    assert(config.ct_log_list_json_len == 0);
    assert(config.ct_allow_unknown_logs == false);

    /* Set some values */
    config.enable_ct = true;
    config.require_ct = true;
    config.ct_min_scts = 2;
    config.ct_log_list_path = "/path/to/logs.json";
    config.ct_allow_unknown_logs = true;

    /* Verify values */
    assert(config.enable_ct == true);
    assert(config.require_ct == true);
    assert(config.ct_min_scts == 2);
    assert(strcmp(config.ct_log_list_path, "/path/to/logs.json") == 0);
    assert(config.ct_allow_unknown_logs == true);

    printf("  PASS: Config fields for CT work\n");
}

/* Test 15: SCT validation with known log */
static void test_ct_validate_sct_known_log(void)
{
    printf("Test 15: SCT validation with known log\n");

    /* Create log list with our test log */
    mtls_ct_log_list log_list;
    mtls_ct_log_list_init(&log_list);
    mtls_err err;
    mtls_err_init(&err);

    mtls_ct_log_list_add(&log_list, kTestLogId, "Test Log", kTestPubKeyDer, kTestPubKeyDerLen,
                         MTLS_CT_LOG_STATUS_USABLE, &err);

    /* Create an SCT pointing to our test log */
    mtls_sct sct;
    memset(&sct, 0, sizeof(sct));
    sct.version = MTLS_SCT_VERSION_V1;
    memcpy(sct.log_id, kTestLogId, MTLS_CT_LOG_ID_SIZE);
    sct.timestamp = 1700000000000ULL; /* Some timestamp */
    sct.source = MTLS_SCT_SOURCE_EMBEDDED;

    /* Validate SCT */
    mtls_err_init(&err);
    mtls_sct_validation_result result = mtls_ct_validate_sct(
        &sct, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0, &log_list, &err);

    assert(result == MTLS_SCT_VALID);
    assert(sct.validation_result == MTLS_SCT_VALID);

    /* Clean up */
    mtls_ct_log_list_free(&log_list);

    printf("  PASS: SCT validation with known log works\n");
}

/* Test 16: SCT validation with unknown log */
static void test_ct_validate_sct_unknown_log(void)
{
    printf("Test 16: SCT validation with unknown log\n");

    /* Create empty log list */
    mtls_ct_log_list log_list;
    mtls_ct_log_list_init(&log_list);
    mtls_err err;
    mtls_err_init(&err);

    /* Create an SCT pointing to unknown log */
    mtls_sct sct;
    memset(&sct, 0, sizeof(sct));
    sct.version = MTLS_SCT_VERSION_V1;
    memcpy(sct.log_id, kTestLogId, MTLS_CT_LOG_ID_SIZE);
    sct.timestamp = 1700000000000ULL;
    sct.source = MTLS_SCT_SOURCE_EMBEDDED;

    /* Validate SCT - should fail with unknown log */
    mtls_sct_validation_result result = mtls_ct_validate_sct(
        &sct, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0, &log_list, &err);

    assert(result == MTLS_SCT_UNKNOWN_LOG);
    assert(sct.validation_result == MTLS_SCT_UNKNOWN_LOG);

    printf("  PASS: SCT validation with unknown log works\n");
}

/* Test 17: Validate multiple SCTs */
static void test_ct_validate_multiple_scts(void)
{
    printf("Test 17: Validate multiple SCTs\n");

    /* Create log list with test log */
    mtls_ct_log_list log_list;
    mtls_ct_log_list_init(&log_list);
    mtls_err err;
    mtls_err_init(&err);

    mtls_ct_log_list_add(&log_list, kTestLogId, "Test Log", kTestPubKeyDer, kTestPubKeyDerLen,
                         MTLS_CT_LOG_STATUS_USABLE, &err);

    /* Create multiple SCTs */
    mtls_sct scts[3];
    memset(scts, 0, sizeof(scts));

    for (int i = 0; i < 3; i++) {
        scts[i].version = MTLS_SCT_VERSION_V1;
        memcpy(scts[i].log_id, kTestLogId, MTLS_CT_LOG_ID_SIZE);
        scts[i].timestamp = 1700000000000ULL + (uint64_t)i;
        scts[i].source = MTLS_SCT_SOURCE_EMBEDDED;
    }

    /* Validate with min_valid_scts = 2 */
    mtls_ct_report report;
    mtls_err_init(&err);
    mtls_ct_result result =
        mtls_ct_validate_scts(scts, 3, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0,
                              &log_list, 2, false, &report, &err);

    assert(result == MTLS_CT_RESULT_VALID);
    assert(report.valid_sct_count == 3);
    assert(report.embedded_sct_count == 3);

    /* Validate with min_valid_scts = 4 - should fail */
    mtls_err_init(&err);
    result = mtls_ct_validate_scts(scts, 3, (const uint8_t *)kTestCertPem, kTestCertPemLen, NULL, 0,
                                   &log_list, 4, false, &report, &err);

    assert(result == MTLS_CT_RESULT_INSUFFICIENT);
    assert(err.code == MTLS_ERR_CT_INSUFFICIENT_SCTS);

    /* Clean up */
    mtls_ct_log_list_free(&log_list);

    printf("  PASS: Multiple SCT validation works\n");
}

/* Test 17: mtls_ct_extract_scts_from_conn NULL parameter rejection */
static void test_ct_extract_conn_null_params(void)
{
    printf("Test 17: mtls_ct_extract_scts_from_conn NULL parameter rejection\n");

    mtls_sct scts[MTLS_CT_MAX_SCTS];
    size_t sct_count = 0;
    mtls_err err;
    mtls_err_init(&err);

    /* NULL conn */
    int ret = mtls_ct_extract_scts_from_conn(NULL, scts, MTLS_CT_MAX_SCTS, &sct_count, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL scts — use a non-NULL sentinel; the function checks scts before dereferencing conn */
    uintptr_t sentinel_val = 1U;
    mtls_conn *dummy_ptr = (mtls_conn *)sentinel_val; /* NOLINT(performance-no-int-to-ptr) */
    mtls_err_init(&err);
    ret = mtls_ct_extract_scts_from_conn(dummy_ptr, NULL, MTLS_CT_MAX_SCTS, &sct_count, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL sct_count */
    mtls_err_init(&err);
    ret = mtls_ct_extract_scts_from_conn(dummy_ptr, scts, MTLS_CT_MAX_SCTS, NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: mtls_ct_extract_scts_from_conn rejects NULL parameters\n");
}

/* Test 18: mtls_ct_validate_conn NULL parameter rejection */
static void test_ct_validate_conn_null_params(void)
{
    printf("Test 18: mtls_ct_validate_conn NULL parameter rejection\n");

    mtls_ct_log_list log_list;
    mtls_ct_log_list_init(&log_list);
    mtls_ct_report report;
    mtls_err err;
    mtls_err_init(&err);

    /* NULL conn */
    int ret = mtls_ct_validate_conn(NULL, &log_list, 1, false, &report, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL log_list — use a non-NULL sentinel pointer */
    uintptr_t sentinel_val2 = 1U;
    mtls_conn *dummy_ptr2 = (mtls_conn *)sentinel_val2; /* NOLINT(performance-no-int-to-ptr) */
    mtls_err_init(&err);
    ret = mtls_ct_validate_conn(dummy_ptr2, NULL, 1, false, &report, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: mtls_ct_validate_conn rejects NULL parameters\n");
}

int main(void)
{
    printf("Running Certificate Transparency tests...\n\n");

    test_ct_log_list_init();
    test_ct_log_list_add();
    test_ct_log_list_find();
    test_ct_log_list_clear();
    test_ct_null_params();
    test_ct_extract_scts_no_scts();
    test_ct_extract_scts_null_params();
    test_ct_validate_scts_empty();
    test_ct_result_strings();
    test_ct_compute_log_id();
    test_ct_log_id_to_base64();
    test_ct_error_codes();
    test_ct_event_types();
    test_ct_config_fields();
    test_ct_validate_sct_known_log();
    test_ct_validate_sct_unknown_log();
    test_ct_validate_multiple_scts();
    test_ct_extract_conn_null_params();
    test_ct_validate_conn_null_params();

    printf("\nAll Certificate Transparency tests passed!\n");
    return 0;
}
