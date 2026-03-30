/**
 * @file test_deadline.c
 * @brief Tests for deadline handling functionality
 *
 * This test suite validates:
 * - Deadline context creation and destruction
 * - Timeout calculation and remaining time
 * - Cancellation handling
 * - Child deadline contexts
 * - NULL safety
 */

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _POSIX_C_SOURCE 200809L

#include "mtls/mtls.h"
#include "mtls/mtls_deadline.h"
#include "mtls/mtls_error.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test 1: Deadline context creation with absolute timestamp */
static void test_create_absolute(void)
{
    printf("Test 1: Deadline context creation (absolute)\n");

    mtls_deadline_ctx *ctx = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create deadline 10 seconds from now using monotonic clock */
    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    uint64_t deadline_us =
        ((uint64_t)ts_now.tv_sec * 1000000ULL) + ((uint64_t)ts_now.tv_nsec / 1000ULL) + 10000000ULL;

    int ret = mtls_deadline_ctx_create(&ctx, deadline_us, &err);
    assert(ret == 0);
    assert(ctx != NULL);
    assert(mtls_deadline_ctx_get_deadline(ctx) == deadline_us);

    /* Should not be expired yet */
    assert(mtls_deadline_ctx_is_expired(ctx) == false);
    assert(mtls_deadline_ctx_is_cancelled(ctx) == false);

    /* Remaining time should be approximately 10 seconds (10000ms) */
    int64_t remaining = mtls_deadline_ctx_remaining_ms(ctx);
    assert(remaining > 9000 && remaining <= 10000);

    mtls_deadline_ctx_destroy(ctx);

    printf("  PASS: Absolute deadline creation works\n");
}

/* Test 2: Deadline context creation with timeout */
static void test_create_with_timeout(void)
{
    printf("Test 2: Deadline context creation (timeout)\n");

    mtls_deadline_ctx *ctx = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create deadline 5 seconds from now */
    int ret = mtls_deadline_ctx_create_with_timeout(&ctx, 5000, &err);
    assert(ret == 0);
    assert(ctx != NULL);

    /* Should not be expired yet */
    assert(mtls_deadline_ctx_is_expired(ctx) == false);

    /* Remaining time should be approximately 5 seconds */
    int64_t remaining = mtls_deadline_ctx_remaining_ms(ctx);
    assert(remaining > 4900 && remaining <= 5000);

    mtls_deadline_ctx_destroy(ctx);

    printf("  PASS: Timeout-based deadline creation works\n");
}

/* Test 3: Deadline expiration */
static void test_expiration(void)
{
    printf("Test 3: Deadline expiration\n");

    mtls_deadline_ctx *ctx = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create deadline 100ms from now */
    int ret = mtls_deadline_ctx_create_with_timeout(&ctx, 100, &err);
    assert(ret == 0);
    assert(mtls_deadline_ctx_is_expired(ctx) == false);

    /* Wait for deadline to expire */
    struct timespec ts_sleep = {.tv_sec = 0, .tv_nsec = 150000000}; /* 150ms */
    nanosleep(&ts_sleep, NULL);

    /* Now should be expired */
    assert(mtls_deadline_ctx_is_expired(ctx) == true);
    assert(mtls_deadline_ctx_remaining_ms(ctx) == 0);

    mtls_deadline_ctx_destroy(ctx);

    printf("  PASS: Deadline expiration works\n");
}

/* Test 4: Cancellation */
static void test_cancellation(void)
{
    printf("Test 4: Cancellation\n");

    mtls_deadline_ctx *ctx = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create deadline 10 seconds from now */
    int ret = mtls_deadline_ctx_create_with_timeout(&ctx, 10000, &err);
    assert(ret == 0);

    /* Should not be cancelled */
    assert(mtls_deadline_ctx_is_cancelled(ctx) == false);
    assert(mtls_deadline_ctx_remaining_ms(ctx) > 0);

    /* Cancel the context */
    mtls_deadline_ctx_cancel(ctx);

    /* Now should be cancelled */
    assert(mtls_deadline_ctx_is_cancelled(ctx) == true);
    assert(mtls_deadline_ctx_is_expired(ctx) == true);
    assert(mtls_deadline_ctx_remaining_ms(ctx) == -1);

    mtls_deadline_ctx_destroy(ctx);

    printf("  PASS: Cancellation works\n");
}

/* Test 5: Child deadline context */
static void test_child_context(void)
{
    printf("Test 5: Child deadline context\n");

    mtls_deadline_ctx *parent = NULL;
    mtls_deadline_ctx *child = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create parent deadline 10 seconds from now */
    int ret = mtls_deadline_ctx_create_with_timeout(&parent, 10000, &err);
    assert(ret == 0);

    /* Create child that inherits parent deadline */
    ret = mtls_deadline_ctx_create_child(&child, parent, 0, &err);
    assert(ret == 0);

    /* Child should have same deadline */
    assert(mtls_deadline_ctx_get_deadline(child) == mtls_deadline_ctx_get_deadline(parent));

    /* Child should not be cancelled */
    assert(mtls_deadline_ctx_is_cancelled(child) == false);

    /* Cancel parent */
    mtls_deadline_ctx_cancel(parent);

    /* Child should detect parent cancellation */
    assert(mtls_deadline_ctx_is_cancelled(child) == true);
    assert(mtls_deadline_ctx_remaining_ms(child) == -1);

    mtls_deadline_ctx_destroy(child);
    mtls_deadline_ctx_destroy(parent);

    printf("  PASS: Child deadline context works\n");
}

/* Test 6: Child with shorter timeout */
static void test_child_shorter_timeout(void)
{
    printf("Test 6: Child with shorter timeout\n");

    mtls_deadline_ctx *parent = NULL;
    mtls_deadline_ctx *child = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create parent deadline 10 seconds from now */
    int ret = mtls_deadline_ctx_create_with_timeout(&parent, 10000, &err);
    assert(ret == 0);

    /* Create child with 5 second timeout (shorter than parent) */
    ret = mtls_deadline_ctx_create_child(&child, parent, 5000, &err);
    assert(ret == 0);

    /* Child deadline should be earlier */
    assert(mtls_deadline_ctx_get_deadline(child) < mtls_deadline_ctx_get_deadline(parent));

    /* Child remaining time should be approximately 5 seconds */
    int64_t child_remaining = mtls_deadline_ctx_remaining_ms(child);
    assert(child_remaining > 4900 && child_remaining <= 5000);

    mtls_deadline_ctx_destroy(child);
    mtls_deadline_ctx_destroy(parent);

    printf("  PASS: Child with shorter timeout works\n");
}

/* Test 7: NULL safety */
static void test_null_safety(void)
{
    printf("Test 7: NULL safety\n");

    mtls_err err;
    mtls_err_init(&err);

    /* NULL context pointer should fail */
    int ret = mtls_deadline_ctx_create(NULL, 1000, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    mtls_err_init(&err);
    ret = mtls_deadline_ctx_create_with_timeout(NULL, 1000, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL parent should fail */
    mtls_deadline_ctx *child = NULL;
    mtls_err_init(&err);
    ret = mtls_deadline_ctx_create_child(&child, NULL, 1000, &err);
    assert(ret == -1);
    assert(err.code == MTLS_ERR_INVALID_ARGUMENT);

    /* NULL context to destroy should not crash */
    mtls_deadline_ctx_destroy(NULL);

    /* NULL context to cancel should not crash */
    mtls_deadline_ctx_cancel(NULL);

    /* NULL context queries should return safe defaults */
    assert(mtls_deadline_ctx_remaining_ms(NULL) == 0);
    assert(mtls_deadline_ctx_is_expired(NULL) == true);
    assert(mtls_deadline_ctx_is_cancelled(NULL) == false);
    assert(mtls_deadline_ctx_get_deadline(NULL) == 0);

    printf("  PASS: NULL safety works\n");
}

/* Test 8: Error code names */
static void test_error_code_names(void)
{
    printf("Test 8: Error code names\n");

    const char *deadline_exceeded = mtls_err_code_name(MTLS_ERR_DEADLINE_EXCEEDED);
    assert(deadline_exceeded != NULL);
    assert(strcmp(deadline_exceeded, "MTLS_ERR_DEADLINE_EXCEEDED") == 0);

    const char *cancelled = mtls_err_code_name(MTLS_ERR_CANCELLED);
    assert(cancelled != NULL);
    assert(strcmp(cancelled, "MTLS_ERR_CANCELLED") == 0);

    printf("  PASS: Error code names work\n");
}

/* Test 9: Error categories */
static void test_error_categories(void)
{
    printf("Test 9: Error categories\n");

    /* Deadline errors should be in I/O category */
    assert(mtls_err_is_io(MTLS_ERR_DEADLINE_EXCEEDED) == true);
    assert(mtls_err_is_io(MTLS_ERR_CANCELLED) == true);

    /* Should not be in other categories */
    assert(mtls_err_is_config(MTLS_ERR_DEADLINE_EXCEEDED) == false);
    assert(mtls_err_is_network(MTLS_ERR_DEADLINE_EXCEEDED) == false);
    assert(mtls_err_is_tls(MTLS_ERR_DEADLINE_EXCEEDED) == false);

    printf("  PASS: Error categories work\n");
}

/* Test 10: Zero timeout */
static void test_zero_timeout(void)
{
    printf("Test 10: Zero timeout\n");

    mtls_deadline_ctx *ctx = NULL;
    mtls_err err;
    mtls_err_init(&err);

    /* Create deadline with 0 timeout (already expired) */
    int ret = mtls_deadline_ctx_create_with_timeout(&ctx, 0, &err);
    assert(ret == 0);

    /* Should be expired immediately */
    assert(mtls_deadline_ctx_is_expired(ctx) == true);
    assert(mtls_deadline_ctx_remaining_ms(ctx) == 0);

    mtls_deadline_ctx_destroy(ctx);

    printf("  PASS: Zero timeout works\n");
}

int main(void)
{
    printf("=== Deadline Handling Tests ===\n\n");

    test_create_absolute();
    test_create_with_timeout();
    test_expiration();
    test_cancellation();
    test_child_context();
    test_child_shorter_timeout();
    test_null_safety();
    test_error_code_names();
    test_error_categories();
    test_zero_timeout();

    printf("\n=== All Deadline Handling Tests PASSED ===\n");
    return 0;
}
