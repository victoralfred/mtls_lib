/**
 * @file test_pool.c
 * @brief Tests for connection pool functionality
 *
 * This test suite validates:
 * - Pool configuration initialization and validation
 * - Pool lifecycle (create, destroy)
 * - Error code names
 * - Utility functions
 * - NULL safety
 *
 * Note: Full integration tests requiring network connections
 * are in a separate test suite.
 */

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _POSIX_C_SOURCE 200809L

#include "mtls/mtls.h"
#include "mtls/mtls_error.h"
#include "mtls/mtls_pool.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test 1: Pool config initialization */
static void test_config_init(void)
{
    printf("Test 1: Pool config initialization\n");

    mtls_pool_config config;
    mtls_pool_config_init(&config);

    assert(config.min_connections == MTLS_POOL_DEFAULT_MIN_CONNECTIONS);
    assert(config.max_connections == MTLS_POOL_DEFAULT_MAX_CONNECTIONS);
    assert(config.idle_timeout_ms == MTLS_POOL_DEFAULT_IDLE_TIMEOUT_MS);
    assert(config.max_lifetime_ms == MTLS_POOL_DEFAULT_MAX_LIFETIME_MS);
    assert(config.acquire_timeout_ms == MTLS_POOL_DEFAULT_ACQUIRE_TIMEOUT_MS);
    assert(config.health_check_interval_ms == MTLS_POOL_DEFAULT_HEALTH_CHECK_INTERVAL_MS);
    assert(config.pre_connect == false);
    assert(config.validate_on_acquire == true);
    assert(config.validate_on_release == false);

    printf("  PASS: Config initialization works\n");
}

/* Test 2: Pool config validation */
static void test_config_validation(void)
{
    printf("Test 2: Pool config validation\n");

    mtls_pool_config config;
    mtls_err err;
    mtls_err_init(&err);

    /* Valid config */
    mtls_pool_config_init(&config);
    int ret = mtls_pool_config_validate(&config, &err);
    assert(ret == 0);

    /* Invalid: min > max */
    config.min_connections = 20;
    config.max_connections = 10;
    mtls_err_init(&err);
    ret = mtls_pool_config_validate(&config, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_CONFIG);

    /* Invalid: max = 0 */
    config.min_connections = 0;
    config.max_connections = 0;
    mtls_err_init(&err);
    ret = mtls_pool_config_validate(&config, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_CONFIG);

    /* NULL config */
    mtls_err_init(&err);
    ret = mtls_pool_config_validate(NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    printf("  PASS: Config validation works\n");
}

/* Test 3: Pool create with NULL arguments */
static void test_create_null_args(void)
{
    printf("Test 3: Pool create with NULL arguments\n");

    mtls_pool *pool = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* NULL pool output */
    int ret = mtls_pool_create(NULL, NULL, "localhost:443", NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL context */
    mtls_err_init(&err);
    ret = mtls_pool_create(&pool, NULL, "localhost:443", NULL, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);
    assert(pool == NULL);

    /* NULL address - can't test easily without valid context */

    printf("  PASS: NULL argument handling works\n");
}

/* Test 4: Pool state strings */
static void test_state_strings(void)
{
    printf("Test 4: Pool state strings\n");

    assert(strcmp(mtls_pool_state_string(MTLS_POOL_STATE_RUNNING), "running") == 0);
    assert(strcmp(mtls_pool_state_string(MTLS_POOL_STATE_CLOSING), "closing") == 0);
    assert(strcmp(mtls_pool_state_string(MTLS_POOL_STATE_CLOSED), "closed") == 0);
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange) - testing unknown value
    assert(strcmp(mtls_pool_state_string((mtls_pool_state)99), "unknown") == 0);

    printf("  PASS: State strings work\n");
}

/* Test 5: Pooled connection state strings */
static void test_pooled_conn_state_strings(void)
{
    printf("Test 5: Pooled connection state strings\n");

    assert(strcmp(mtls_pooled_conn_state_string(MTLS_POOLED_CONN_IDLE), "idle") == 0);
    assert(strcmp(mtls_pooled_conn_state_string(MTLS_POOLED_CONN_IN_USE), "in_use") == 0);
    assert(strcmp(mtls_pooled_conn_state_string(MTLS_POOLED_CONN_CLOSED), "closed") == 0);
    assert(strcmp(mtls_pooled_conn_state_string(MTLS_POOLED_CONN_UNHEALTHY), "unhealthy") == 0);
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange) - testing unknown value
    assert(strcmp(mtls_pooled_conn_state_string((mtls_pooled_conn_state)99), "unknown") == 0);

    printf("  PASS: Pooled connection state strings work\n");
}

/* Test 6: Error code names */
static void test_error_code_names(void)
{
    printf("Test 6: Error code names\n");

    const char *name = mtls_err_code_name(MTLS_ERR_POOL_EXHAUSTED);
    assert(name != NULL);
    assert(strcmp(name, "MTLS_ERR_POOL_EXHAUSTED") == 0);

    name = mtls_err_code_name(MTLS_ERR_POOL_ACQUIRE_TIMEOUT);
    assert(name != NULL);
    assert(strcmp(name, "MTLS_ERR_POOL_ACQUIRE_TIMEOUT") == 0);

    name = mtls_err_code_name(MTLS_ERR_POOL_CLOSED);
    assert(name != NULL);
    assert(strcmp(name, "MTLS_ERR_POOL_CLOSED") == 0);

    name = mtls_err_code_name(MTLS_ERR_CONN_UNHEALTHY);
    assert(name != NULL);
    assert(strcmp(name, "MTLS_ERR_CONN_UNHEALTHY") == 0);

    printf("  PASS: Error code names work\n");
}

/* Test 7: Error categories */
static void test_error_categories(void)
{
    printf("Test 7: Error categories\n");

    /* Pool errors should be in network category (2xx) */
    assert(mtls_err_is_network(MTLS_ERR_POOL_EXHAUSTED) == true);
    assert(mtls_err_is_network(MTLS_ERR_POOL_ACQUIRE_TIMEOUT) == true);
    assert(mtls_err_is_network(MTLS_ERR_POOL_CLOSED) == true);
    assert(mtls_err_is_network(MTLS_ERR_CONN_UNHEALTHY) == true);

    /* Should not be in other categories */
    assert(mtls_err_is_config(MTLS_ERR_POOL_EXHAUSTED) == false);
    assert(mtls_err_is_tls(MTLS_ERR_POOL_EXHAUSTED) == false);
    assert(mtls_err_is_io(MTLS_ERR_POOL_EXHAUSTED) == false);

    printf("  PASS: Error categories work\n");
}

/* Test 8: NULL safety for pool functions */
static void test_null_safety(void)
{
    printf("Test 8: NULL safety\n");

    /* These should not crash */
    mtls_pool_config_init(NULL);
    mtls_pool_destroy(NULL);
    mtls_pool_discard(NULL, NULL);
    mtls_pool_reset_stats(NULL);

    /* These should return safe defaults/errors */
    assert(mtls_pool_get_state(NULL) == MTLS_POOL_STATE_CLOSED);
    assert(mtls_pool_health_check(NULL) == 0);
    assert(mtls_pool_cleanup(NULL) == 0);
    assert(mtls_pool_get_stats(NULL, NULL) == -1);
    assert(mtls_pool_release(NULL, NULL) == -1);
    assert(mtls_pool_acquire(NULL, 0, NULL) == NULL);
    assert(mtls_pool_close(NULL, 0) == -1);

    printf("  PASS: NULL safety works\n");
}

/* Test 9: Pool stats structure */
static void test_stats_structure(void)
{
    printf("Test 9: Pool stats structure\n");

    mtls_pool_stats stats;
    memset(&stats, 0xFF, sizeof(stats)); /* Fill with non-zero */

    /* Verify fields exist and can be accessed */
    stats.total_connections = 0;
    stats.active_connections = 0;
    stats.idle_connections = 0;
    stats.in_use_connections = 0;
    stats.total_acquires = 0;
    stats.total_releases = 0;
    stats.acquire_timeouts = 0;
    stats.failed_connects = 0;
    stats.health_checks = 0;
    stats.unhealthy_closed = 0;
    stats.idle_closed = 0;
    stats.lifetime_closed = 0;
    stats.wait_time_total_ms = 0;
    stats.wait_time_max_ms = 0;

    /* Verify all fields are zeroed */
    assert(stats.total_connections == 0);
    assert(stats.wait_time_max_ms == 0);

    printf("  PASS: Stats structure is valid\n");
}

/* Test 10: Default constant values */
static void test_default_constants(void)
{
    printf("Test 10: Default constant values\n");

    /* Verify constants are sensible - use static_assert for compile-time checks */
    _Static_assert(MTLS_POOL_DEFAULT_MIN_CONNECTIONS >= 0, "Min connections must be >= 0");
    _Static_assert(MTLS_POOL_DEFAULT_MAX_CONNECTIONS >= MTLS_POOL_DEFAULT_MIN_CONNECTIONS,
                   "Max must be >= min");
    _Static_assert(MTLS_POOL_DEFAULT_IDLE_TIMEOUT_MS > 0, "Idle timeout must be > 0");
    _Static_assert(MTLS_POOL_DEFAULT_MAX_LIFETIME_MS > 0, "Max lifetime must be > 0");
    _Static_assert(MTLS_POOL_DEFAULT_ACQUIRE_TIMEOUT_MS > 0, "Acquire timeout must be > 0");
    _Static_assert(MTLS_POOL_DEFAULT_HEALTH_CHECK_INTERVAL_MS > 0,
                   "Health check interval must be > 0");
    _Static_assert(MTLS_POOL_MAX_ADDR_LEN >= 64, "Max addr len must be >= 64");

    printf("  PASS: Default constants are valid\n");
}

int main(void)
{
    printf("=== Connection Pool Tests ===\n\n");

    test_config_init();
    test_config_validation();
    test_create_null_args();
    test_state_strings();
    test_pooled_conn_state_strings();
    test_error_code_names();
    test_error_categories();
    test_null_safety();
    test_stats_structure();
    test_default_constants();

    printf("\n=== All Connection Pool Tests PASSED ===\n");
    return 0;
}
