/**
 * @file test_hsm.c
 * @brief Unit tests for HSM integration
 *
 * Tests HSM API functions, error handling, and type utilities.
 * Note: Full integration tests require SoftHSM2 to be installed and configured.
 */

// NOLINTBEGIN(cert-err33-c,clang-analyzer-optin.core.EnumCastOutOfRange)

#include "mtls/mtls_error.h"
#include "mtls/mtls_hsm.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name)                          \
    do {                                    \
        printf("  Testing: %s... ", #name); \
        fflush(stdout);                     \
    } while (0)

#define PASS()            \
    do {                  \
        printf("PASS\n"); \
        tests_passed++;   \
    } while (0)

#define FAIL(msg)                  \
    do {                           \
        printf("FAIL: %s\n", msg); \
        tests_failed++;            \
    } while (0)

/* Test HSM type name function */
static void test_hsm_type_name(void)
{
    TEST(mtls_hsm_type_name);

    const char *name;

    name = mtls_hsm_type_name(MTLS_HSM_NONE);
    if (strcmp(name, "none") != 0) {
        FAIL("MTLS_HSM_NONE name mismatch");
        return;
    }

    name = mtls_hsm_type_name(MTLS_HSM_PKCS11);
    if (strcmp(name, "pkcs11") != 0) {
        FAIL("MTLS_HSM_PKCS11 name mismatch");
        return;
    }

    name = mtls_hsm_type_name(MTLS_HSM_ENGINE);
    if (strcmp(name, "engine") != 0) {
        FAIL("MTLS_HSM_ENGINE name mismatch");
        return;
    }

    name = mtls_hsm_type_name((mtls_hsm_type)999);
    if (strcmp(name, "unknown") != 0) {
        FAIL("Unknown type name mismatch");
        return;
    }

    PASS();
}

/* Test HSM config initialization */
static void test_hsm_config_init(void)
{
    TEST(mtls_hsm_config_init);

    mtls_hsm_config config;
    memset(&config, 0xFF, sizeof(config)); /* Fill with junk */

    mtls_hsm_config_init(&config);

    if (config.type != MTLS_HSM_NONE) {
        FAIL("Default type should be NONE");
        return;
    }

    if (config.operation_timeout_ms != 30000) {
        FAIL("Default operation timeout should be 30000");
        return;
    }

    if (config.login_timeout_ms != 10000) {
        FAIL("Default login timeout should be 10000");
        return;
    }

    if (config.module_path != NULL || config.slot_id != NULL || config.key_id != NULL ||
        config.pin != NULL) {
        FAIL("Pointer fields should be NULL");
        return;
    }

    PASS();
}

/* Test NULL config init */
static void test_hsm_config_init_null(void)
{
    TEST(mtls_hsm_config_init_null);

    /* Should not crash with NULL */
    mtls_hsm_config_init(NULL);

    PASS();
}

/* Test HSM init with NULL arguments */
static void test_hsm_init_null_args(void)
{
    TEST(mtls_hsm_init_null_args);

    mtls_hsm_ctx *ctx = NULL;
    mtls_hsm_config config;
    mtls_err err;

    mtls_hsm_config_init(&config);
    mtls_err_init(&err);

    /* NULL ctx */
    int result = mtls_hsm_init(NULL, &config, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    /* NULL config */
    mtls_err_init(&err);
    result = mtls_hsm_init(&ctx, NULL, &err);
    if (result != -1) {
        FAIL("Should fail with NULL config");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test PKCS#11 init without module path */
static void test_hsm_init_pkcs11_no_module(void)
{
    TEST(mtls_hsm_init_pkcs11_no_module);

    mtls_hsm_ctx *ctx = NULL;
    mtls_hsm_config config;
    mtls_err err;

    mtls_hsm_config_init(&config);
    mtls_err_init(&err);

    config.type = MTLS_HSM_PKCS11;
    /* No module_path set */

    int result = mtls_hsm_init(&ctx, &config, &err);
    if (result != -1) {
        FAIL("Should fail without module path");
        mtls_hsm_free(ctx);
        return;
    }
    if (err.code != MTLS_ERR_INVALID_CONFIG) {
        FAIL("Error code should be INVALID_CONFIG");
        return;
    }

    PASS();
}

/* Test PKCS#11 init with nonexistent module */
static void test_hsm_init_pkcs11_bad_module(void)
{
    TEST(mtls_hsm_init_pkcs11_bad_module);

    mtls_hsm_ctx *ctx = NULL;
    mtls_hsm_config config;
    mtls_err err;

    mtls_hsm_config_init(&config);
    mtls_err_init(&err);

    config.type = MTLS_HSM_PKCS11;
    config.module_path = "/nonexistent/path/to/module.so";

    int result = mtls_hsm_init(&ctx, &config, &err);
    if (result != -1) {
        FAIL("Should fail with bad module path");
        mtls_hsm_free(ctx);
        return;
    }
    if (err.code != MTLS_ERR_HSM_MODULE_NOT_FOUND) {
        FAIL("Error code should be HSM_MODULE_NOT_FOUND");
        return;
    }

    PASS();
}

/* Test ENGINE init without engine ID */
static void test_hsm_init_engine_no_id(void)
{
    TEST(mtls_hsm_init_engine_no_id);

    mtls_hsm_ctx *ctx = NULL;
    mtls_hsm_config config;
    mtls_err err;

    mtls_hsm_config_init(&config);
    mtls_err_init(&err);

    config.type = MTLS_HSM_ENGINE;
    /* No engine_id set */

    int result = mtls_hsm_init(&ctx, &config, &err);
    if (result != -1) {
        FAIL("Should fail without engine ID");
        mtls_hsm_free(ctx);
        return;
    }
    if (err.code != MTLS_ERR_INVALID_CONFIG) {
        FAIL("Error code should be INVALID_CONFIG");
        return;
    }

    PASS();
}

/* Test ENGINE init with nonexistent engine */
static void test_hsm_init_engine_bad_id(void)
{
    TEST(mtls_hsm_init_engine_bad_id);

    mtls_hsm_ctx *ctx = NULL;
    mtls_hsm_config config;
    mtls_err err;

    mtls_hsm_config_init(&config);
    mtls_err_init(&err);

    config.type = MTLS_HSM_ENGINE;
    config.engine_id = "nonexistent_engine_12345";

    int result = mtls_hsm_init(&ctx, &config, &err);
    if (result != -1) {
        FAIL("Should fail with bad engine ID");
        mtls_hsm_free(ctx);
        return;
    }
    if (err.code != MTLS_ERR_HSM_MODULE_NOT_FOUND) {
        FAIL("Error code should be HSM_MODULE_NOT_FOUND");
        return;
    }

    PASS();
}

/* Test HSM free with NULL */
static void test_hsm_free_null(void)
{
    TEST(mtls_hsm_free_null);

    /* Should not crash with NULL */
    mtls_hsm_free(NULL);

    PASS();
}

/* Test HSM list slots with NULL context */
static void test_hsm_list_slots_null(void)
{
    TEST(mtls_hsm_list_slots_null);

    mtls_hsm_slot_info slots[10];
    size_t count;
    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_list_slots(NULL, slots, 10, &count, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM list keys with NULL context */
static void test_hsm_list_keys_null(void)
{
    TEST(mtls_hsm_list_keys_null);

    mtls_hsm_key_info keys[10];
    size_t count;
    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_list_keys(NULL, keys, 10, &count, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM get info with NULL context */
static void test_hsm_get_info_null(void)
{
    TEST(mtls_hsm_get_info_null);

    char desc[256];
    char version[32];
    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_get_info(NULL, desc, version, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM open session with NULL context */
static void test_hsm_open_session_null(void)
{
    TEST(mtls_hsm_open_session_null);

    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_open_session(NULL, "0", &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM login with NULL context */
static void test_hsm_login_null(void)
{
    TEST(mtls_hsm_login_null);

    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_login(NULL, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM logout with NULL context */
static void test_hsm_logout_null(void)
{
    TEST(mtls_hsm_logout_null);

    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_logout(NULL, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM close session with NULL context */
static void test_hsm_close_session_null(void)
{
    TEST(mtls_hsm_close_session_null);

    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_close_session(NULL, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM load private key with NULL context */
static void test_hsm_load_private_key_null(void)
{
    TEST(mtls_hsm_load_private_key_null);

    void *pkey;
    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_load_private_key(NULL, NULL, &pkey, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM load certificate with NULL context */
static void test_hsm_load_certificate_null(void)
{
    TEST(mtls_hsm_load_certificate_null);

    void *cert;
    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_load_certificate(NULL, NULL, &cert, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM configure SSL_CTX with NULL context */
static void test_hsm_configure_ssl_ctx_null(void)
{
    TEST(mtls_hsm_configure_ssl_ctx_null);

    mtls_err err;
    mtls_err_init(&err);

    /* Fake SSL_CTX pointer - not actually used due to NULL ctx check */
    void *fake_ctx = (void *)0x12345678;

    int result = mtls_hsm_configure_ssl_ctx(NULL, fake_ctx, &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM generate random with NULL context */
static void test_hsm_generate_random_null(void)
{
    TEST(mtls_hsm_generate_random_null);

    uint8_t buf[32];
    mtls_err err;
    mtls_err_init(&err);

    int result = mtls_hsm_generate_random(NULL, buf, sizeof(buf), &err);
    if (result != -1) {
        FAIL("Should fail with NULL ctx");
        return;
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        FAIL("Error code should be INVALID_ARGUMENT");
        return;
    }

    PASS();
}

/* Test HSM test connection with invalid config */
static void test_hsm_test_connection_invalid(void)
{
    TEST(mtls_hsm_test_connection_invalid);

    mtls_hsm_config config;
    mtls_err err;

    mtls_hsm_config_init(&config);
    mtls_err_init(&err);

    /* PKCS#11 without module path */
    config.type = MTLS_HSM_PKCS11;
    int result = mtls_hsm_test_connection(&config, &err);
    if (result != -1) {
        FAIL("Should fail with invalid config");
        return;
    }

    PASS();
}

/* Test HSM set PIN callback with NULL context */
static void test_hsm_set_pin_callback_null(void)
{
    TEST(mtls_hsm_set_pin_callback_null);

    /* Should not crash with NULL */
    mtls_hsm_set_pin_callback(NULL, NULL, NULL);

    PASS();
}

/* Test HSM error codes are properly defined */
static void test_hsm_error_codes(void)
{
    TEST(hsm_error_codes);

    /* Check that HSM error codes are in config category (1xx) */
    if (MTLS_ERR_HSM_INIT_FAILED != 111) {
        FAIL("HSM_INIT_FAILED should be 111");
        return;
    }
    if (MTLS_ERR_HSM_PIN_REQUIRED != 112) {
        FAIL("HSM_PIN_REQUIRED should be 112");
        return;
    }
    if (MTLS_ERR_HSM_PIN_INVALID != 113) {
        FAIL("HSM_PIN_INVALID should be 113");
        return;
    }
    if (MTLS_ERR_HSM_KEY_NOT_FOUND != 114) {
        FAIL("HSM_KEY_NOT_FOUND should be 114");
        return;
    }
    if (MTLS_ERR_HSM_OPERATION_FAILED != 115) {
        FAIL("HSM_OPERATION_FAILED should be 115");
        return;
    }
    if (MTLS_ERR_HSM_SLOT_NOT_FOUND != 116) {
        FAIL("HSM_SLOT_NOT_FOUND should be 116");
        return;
    }
    if (MTLS_ERR_HSM_MODULE_NOT_FOUND != 117) {
        FAIL("HSM_MODULE_NOT_FOUND should be 117");
        return;
    }

    /* Verify error codes are in config category */
    if (!mtls_err_is_config(MTLS_ERR_HSM_INIT_FAILED)) {
        FAIL("HSM errors should be in config category");
        return;
    }

    PASS();
}

/* Test HSM error code names */
static void test_hsm_error_code_names(void)
{
    TEST(hsm_error_code_names);

    const char *name;

    name = mtls_err_code_name(MTLS_ERR_HSM_INIT_FAILED);
    if (strcmp(name, "MTLS_ERR_HSM_INIT_FAILED") != 0) {
        FAIL("HSM_INIT_FAILED name mismatch");
        return;
    }

    name = mtls_err_code_name(MTLS_ERR_HSM_PIN_REQUIRED);
    if (strcmp(name, "MTLS_ERR_HSM_PIN_REQUIRED") != 0) {
        FAIL("HSM_PIN_REQUIRED name mismatch");
        return;
    }

    name = mtls_err_code_name(MTLS_ERR_HSM_PIN_INVALID);
    if (strcmp(name, "MTLS_ERR_HSM_PIN_INVALID") != 0) {
        FAIL("HSM_PIN_INVALID name mismatch");
        return;
    }

    name = mtls_err_code_name(MTLS_ERR_HSM_KEY_NOT_FOUND);
    if (strcmp(name, "MTLS_ERR_HSM_KEY_NOT_FOUND") != 0) {
        FAIL("HSM_KEY_NOT_FOUND name mismatch");
        return;
    }

    name = mtls_err_code_name(MTLS_ERR_HSM_OPERATION_FAILED);
    if (strcmp(name, "MTLS_ERR_HSM_OPERATION_FAILED") != 0) {
        FAIL("HSM_OPERATION_FAILED name mismatch");
        return;
    }

    name = mtls_err_code_name(MTLS_ERR_HSM_SLOT_NOT_FOUND);
    if (strcmp(name, "MTLS_ERR_HSM_SLOT_NOT_FOUND") != 0) {
        FAIL("HSM_SLOT_NOT_FOUND name mismatch");
        return;
    }

    name = mtls_err_code_name(MTLS_ERR_HSM_MODULE_NOT_FOUND);
    if (strcmp(name, "MTLS_ERR_HSM_MODULE_NOT_FOUND") != 0) {
        FAIL("HSM_MODULE_NOT_FOUND name mismatch");
        return;
    }

    PASS();
}

int main(void)
{
    printf("HSM Integration Tests\n");
    printf("=====================\n\n");

    /* Type and config tests */
    test_hsm_type_name();
    test_hsm_config_init();
    test_hsm_config_init_null();

    /* Init tests */
    test_hsm_init_null_args();
    test_hsm_init_pkcs11_no_module();
    test_hsm_init_pkcs11_bad_module();
    test_hsm_init_engine_no_id();
    test_hsm_init_engine_bad_id();
    test_hsm_free_null();

    /* NULL context tests */
    test_hsm_list_slots_null();
    test_hsm_list_keys_null();
    test_hsm_get_info_null();
    test_hsm_open_session_null();
    test_hsm_login_null();
    test_hsm_logout_null();
    test_hsm_close_session_null();
    test_hsm_load_private_key_null();
    test_hsm_load_certificate_null();
    test_hsm_configure_ssl_ctx_null();
    test_hsm_generate_random_null();
    test_hsm_test_connection_invalid();
    test_hsm_set_pin_callback_null();

    /* Error code tests */
    test_hsm_error_codes();
    test_hsm_error_code_names();

    printf("\n=====================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}

// NOLINTEND(cert-err33-c,clang-analyzer-optin.core.EnumCastOutOfRange)
