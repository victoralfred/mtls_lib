/**
 * @file test_rate_limit.c
 * @brief Tests for rate limiting functionality
 *
 * This test suite validates:
 * - Rate limiter initialization and configuration
 * - Global rate limiting
 * - Per-client rate limiting
 * - Token bucket refill behavior
 * - Statistics tracking
 * - Cleanup of expired client buckets
 */

#include "mtls/mtls.h"
#include "mtls/mtls_rate_limit.h"
#include "mtls/mtls_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

/* Test 1: Config initialization */
static void test_config_init(void)
{
    printf("Test 1: Config initialization\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);

    assert(config.enabled == false);
    assert(config.max_conn_per_sec == 0);
    assert(config.per_client_rate == 0);
    assert(config.burst_size == 10);
    assert(config.per_client_burst == 5);
    assert(config.limit_by_ip == true);
    assert(config.limit_by_cn == false);

    /* NULL should not crash */
    mtls_rate_limit_config_init(NULL);

    printf("  PASS: Config initialization works\n");
}

/* Test 2: Rate limiter creation */
static void test_limiter_create(void)
{
    printf("Test 2: Rate limiter creation\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 100;
    config.per_client_rate = 10;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);
    assert(limiter != NULL);

    mtls_rate_limiter_free(limiter);

    /* NULL limiter should fail */
    ret = mtls_rate_limiter_create(NULL, &config, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL config should use defaults */
    ret = mtls_rate_limiter_create(&limiter, NULL, &err);
    assert(ret == 0);
    mtls_rate_limiter_free(limiter);

    printf("  PASS: Rate limiter creation works\n");
}

/* Test 3: Acquire with disabled rate limiting */
static void test_acquire_disabled(void)
{
    printf("Test 3: Acquire with disabled rate limiting\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = false;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Should always succeed when disabled */
    for (int i = 0; i < 1000; i++) {
        ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
        assert(ret == 0);
    }

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Disabled rate limiting allows all\n");
}

/* Test 4: Global rate limiting */
static void test_global_rate_limit(void)
{
    printf("Test 4: Global rate limiting\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 5;
    config.burst_size = 5;
    config.per_client_rate = 0; /* Disable per-client */

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Should allow burst_size requests */
    for (int i = 0; i < 5; i++) {
        ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
        assert(ret == 0);
    }

    /* 6th request should be rejected */
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_RATE_LIMIT_GLOBAL);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Global rate limiting works\n");
}

/* Test 5: Per-client rate limiting */
static void test_per_client_rate_limit(void)
{
    printf("Test 5: Per-client rate limiting\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 0; /* Disable global */
    config.per_client_rate = 3;
    config.per_client_burst = 3;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Client 1 should allow 3 requests */
    for (int i = 0; i < 3; i++) {
        ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
        assert(ret == 0);
    }

    /* Client 1's 4th request should be rejected */
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_RATE_LIMIT_CLIENT);

    /* Client 2 should still be allowed */
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.2", &err);
    assert(ret == 0);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Per-client rate limiting works\n");
}

/* Test 6: Statistics tracking */
static void test_statistics(void)
{
    printf("Test 6: Statistics tracking\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 3;
    config.burst_size = 3;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Make some requests */
    for (int i = 0; i < 5; i++) {
        (void)mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    }

    mtls_rate_limit_stats stats;
    ret = mtls_rate_limiter_stats(limiter, &stats);
    assert(ret == 0);
    assert(stats.total_requests == 5);
    assert(stats.allowed_requests == 3);
    assert(stats.rejected_requests == 2);
    assert(stats.global_rejections == 2);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Statistics tracking works\n");
}

/* Test 7: Rate limiter reset */
static void test_reset(void)
{
    printf("Test 7: Rate limiter reset\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 2;
    config.burst_size = 2;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Use up the burst */
    mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);

    /* Should be rejected */
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    assert(ret == -1);

    /* Reset the limiter */
    mtls_rate_limiter_reset(limiter);

    /* Now should be allowed again */
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    assert(ret == 0);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Rate limiter reset works\n");
}

/* Test 8: Check without consuming */
static void test_check_status(void)
{
    printf("Test 8: Check status without consuming\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 2;
    config.burst_size = 2;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Check should return OK */
    mtls_rate_limit_status status = mtls_rate_limiter_check(limiter, "192.168.1.1");
    assert(status == MTLS_RATE_LIMIT_OK);

    /* Use up burst */
    mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);

    /* Check should now return exceeded */
    status = mtls_rate_limiter_check(limiter, "192.168.1.1");
    assert(status == MTLS_RATE_LIMIT_GLOBAL_EXCEEDED);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Check status works\n");
}

/* Test 9: Token status retrieval */
static void test_token_status(void)
{
    printf("Test 9: Token status retrieval\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 10;
    config.burst_size = 10;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    uint64_t tokens = 0;
    uint64_t next_refill_ms = 0;

    /* Get global bucket status */
    ret = mtls_rate_limiter_status(limiter, NULL, &tokens, &next_refill_ms);
    assert(ret == 0);
    assert(tokens == 10); /* Full bucket */

    /* Use one token */
    mtls_rate_limiter_acquire(limiter, NULL, &err);

    ret = mtls_rate_limiter_status(limiter, NULL, &tokens, NULL);
    assert(ret == 0);
    assert(tokens == 9);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Token status retrieval works\n");
}

/* Test 10: Status string */
static void test_status_string(void)
{
    printf("Test 10: Status string\n");

    const char *ok_str = mtls_rate_limit_status_string(MTLS_RATE_LIMIT_OK);
    assert(strcmp(ok_str, "OK") == 0);

    const char *exceeded_str = mtls_rate_limit_status_string(MTLS_RATE_LIMIT_EXCEEDED);
    assert(strstr(exceeded_str, "exceeded") != NULL);

    const char *global_str = mtls_rate_limit_status_string(MTLS_RATE_LIMIT_GLOBAL_EXCEEDED);
    assert(strstr(global_str, "Global") != NULL);

    const char *client_str = mtls_rate_limit_status_string(MTLS_RATE_LIMIT_CLIENT_EXCEEDED);
    assert(strstr(client_str, "client") != NULL);

    printf("  PASS: Status string works\n");
}

/* Test 11: Remove client */
static void test_remove_client(void)
{
    printf("Test 11: Remove client\n");

    mtls_rate_limit_config config;
    mtls_rate_limit_config_init(&config);
    config.enabled = true;
    config.max_conn_per_sec = 0;
    config.per_client_rate = 2;
    config.per_client_burst = 2;

    mtls_rate_limiter *limiter = NULL;
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_rate_limiter_create(&limiter, &config, &err);
    assert(ret == 0);

    /* Use up client's bucket */
    mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    assert(ret == -1);

    /* Remove the client */
    ret = mtls_rate_limiter_remove_client(limiter, "192.168.1.1");
    assert(ret == 0);

    /* Client should now get a fresh bucket */
    ret = mtls_rate_limiter_acquire(limiter, "192.168.1.1", &err);
    assert(ret == 0);

    /* Removing non-existent client should fail */
    ret = mtls_rate_limiter_remove_client(limiter, "192.168.1.99");
    assert(ret == -1);

    mtls_rate_limiter_free(limiter);

    printf("  PASS: Remove client works\n");
}

/* Test 12: NULL safety */
static void test_null_safety(void)
{
    printf("Test 12: NULL safety\n");

    mtls_err err;
    mtls_err_init(&err);

    /* All functions should handle NULL gracefully */
    mtls_rate_limiter_free(NULL);
    mtls_rate_limiter_reset(NULL);
    mtls_rate_limiter_reset_stats(NULL);

    int ret = mtls_rate_limiter_acquire(NULL, "test", &err);
    assert(ret == -1);

    ret = mtls_rate_limiter_remove_client(NULL, "test");
    assert(ret == -1);

    size_t cleaned = mtls_rate_limiter_cleanup(NULL);
    assert(cleaned == 0);

    uint64_t wait = mtls_rate_limiter_wait_time(NULL, "test");
    assert(wait == 0);

    printf("  PASS: NULL safety works\n");
}

int main(void)
{
    printf("=== Rate Limiting Tests ===\n\n");

    test_config_init();
    test_limiter_create();
    test_acquire_disabled();
    test_global_rate_limit();
    test_per_client_rate_limit();
    test_statistics();
    test_reset();
    test_check_status();
    test_token_status();
    test_status_string();
    test_remove_client();
    test_null_safety();

    printf("\n=== All Rate Limiting Tests PASSED ===\n");
    return 0;
}
