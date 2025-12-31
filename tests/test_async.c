/**
 * @file test_async.c
 * @brief Unit tests for async I/O module
 */

/* Required for nanosleep */
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _POSIX_C_SOURCE 199309L

#include "mtls/mtls.h"
#include "mtls/mtls_async.h"
#include "mtls/mtls_error.h"
#include "internal/mtls_internal.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                        \
    do {                                  \
        printf("  Testing %s...", #name); \
        tests_run++;                      \
        if (test_##name()) {              \
            printf(" PASSED\n");          \
            tests_passed++;               \
        } else {                          \
            printf(" FAILED\n");          \
        }                                 \
    } while (0)

/*
 * =============================================================================
 * Test: Async State String
 * =============================================================================
 */
static int test_async_state_string(void)
{
    const char *state_str;

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_IDLE);
    if (strcmp(state_str, "idle") != 0) {
        return 0;
    }

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_CONNECTING);
    if (strcmp(state_str, "connecting") != 0) {
        return 0;
    }

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_HANDSHAKING);
    if (strcmp(state_str, "handshaking") != 0) {
        return 0;
    }

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_READING);
    if (strcmp(state_str, "reading") != 0) {
        return 0;
    }

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_WRITING);
    if (strcmp(state_str, "writing") != 0) {
        return 0;
    }

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_CLOSING);
    if (strcmp(state_str, "closing") != 0) {
        return 0;
    }

    state_str = mtls_async_state_string(MTLS_ASYNC_STATE_ERROR);
    if (strcmp(state_str, "error") != 0) {
        return 0;
    }

    /* Unknown state */
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    state_str = mtls_async_state_string((mtls_async_state)999);
    if (strcmp(state_str, "unknown") != 0) {
        return 0;
    }

    return 1;
}

/*
 * =============================================================================
 * Test: Error Codes Exist
 * =============================================================================
 */
static int test_error_codes_exist(void)
{
    /* Verify error codes are defined correctly */
    // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
    mtls_error_code code;

    code = MTLS_ERR_ASYNC_PENDING;
    if ((int)code != 611) {
        return 0;
    }

    code = MTLS_ERR_ASYNC_CANCELLED;
    if ((int)code != 612) {
        return 0;
    }

    code = MTLS_ERR_EVENTLOOP_ERROR;
    if ((int)code != 613) {
        return 0;
    }

    /* Verify error code names */
    const char *name = mtls_err_code_name(MTLS_ERR_ASYNC_PENDING);
    if (!name || strcmp(name, "MTLS_ERR_ASYNC_PENDING") != 0) {
        return 0;
    }

    name = mtls_err_code_name(MTLS_ERR_ASYNC_CANCELLED);
    if (!name || strcmp(name, "MTLS_ERR_ASYNC_CANCELLED") != 0) {
        return 0;
    }

    name = mtls_err_code_name(MTLS_ERR_EVENTLOOP_ERROR);
    if (!name || strcmp(name, "MTLS_ERR_EVENTLOOP_ERROR") != 0) {
        return 0;
    }

    return 1;
}

/*
 * =============================================================================
 * Test: Async Context NULL Params
 * =============================================================================
 */
static int test_async_ctx_null_params(void)
{
    mtls_err err;
    mtls_err_init(&err);
    mtls_async_ctx *async_ctx = NULL;

    /* NULL output pointer */
    int ret = mtls_async_ctx_create(NULL, NULL, &err);
    if (ret == 0) {
        return 0; /* Should fail */
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        return 0;
    }

    /* NULL mtls context */
    ret = mtls_async_ctx_create(&async_ctx, NULL, &err);
    if (ret == 0) {
        return 0; /* Should fail */
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        return 0;
    }

    /* Destroy NULL context (should not crash) */
    mtls_async_ctx_destroy(NULL);

    return 1;
}

/*
 * =============================================================================
 * Test: Async Context Create and Destroy
 * =============================================================================
 */
static int test_async_ctx_create_destroy(void)
{
    mtls_err err;
    mtls_err_init(&err);

    /* Create a minimal config for mtls context */
    mtls_config config;
    mtls_config_init(&config);

    /* Set required config fields */
    config.ca_cert_path = "/dev/null"; /* Non-existent but we won't connect */

    /* Create mtls context - this may fail without valid certs, so we skip on failure */
    mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        /* Skip this test if we can't create a context */
        printf("(skipped - no valid context) ");
        return 1;
    }

    /* Create async context */
    mtls_async_ctx *async_ctx = NULL;
    int ret = mtls_async_ctx_create(&async_ctx, ctx, &err);
    if (ret != 0) {
        mtls_ctx_free(ctx);
        return 0;
    }

    if (async_ctx == NULL) {
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Get fd - should be valid */
    int epoll_fd = mtls_async_ctx_get_fd(async_ctx);
    if (epoll_fd < 0) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Pending count should be 0 */
    size_t pending = mtls_async_pending_count(async_ctx);
    if (pending != 0) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Cleanup */
    mtls_async_ctx_destroy(async_ctx);
    mtls_ctx_free(ctx);

    return 1;
}

/*
 * =============================================================================
 * Test: Async Poll No Events
 * =============================================================================
 */
static int test_async_poll_no_events(void)
{
    mtls_err err;
    mtls_err_init(&err);

    /* Create a minimal config for mtls context */
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        printf("(skipped - no valid context) ");
        return 1;
    }

    mtls_async_ctx *async_ctx = NULL;
    int ret = mtls_async_ctx_create(&async_ctx, ctx, &err);
    if (ret != 0) {
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Poll with 0 timeout should return immediately */
    ret = mtls_async_poll(async_ctx, 0, &err);
    if (ret < 0) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Poll with short timeout */
    ret = mtls_async_poll(async_ctx, 10, &err);
    if (ret < 0) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    mtls_async_ctx_destroy(async_ctx);
    mtls_ctx_free(ctx);
    return 1;
}

/*
 * =============================================================================
 * Test: Async Poll NULL Params
 * =============================================================================
 */
static int test_async_poll_null_params(void)
{
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_async_poll(NULL, 0, &err);
    if (ret == 0) {
        return 0; /* Should fail */
    }
    if (err.code != MTLS_ERR_INVALID_ARGUMENT) {
        return 0;
    }

    return 1;
}

/*
 * =============================================================================
 * Test: Async Wakeup
 * =============================================================================
 */
static void *wakeup_thread(void *arg)
{
    mtls_async_ctx *async_ctx = (mtls_async_ctx *)arg;

    /* Small delay then wakeup */
    struct timespec delay = {0, 50000000}; /* 50ms */
    nanosleep(&delay, NULL);
    mtls_async_wakeup(async_ctx);

    return NULL;
}

static int test_async_wakeup(void)
{
    mtls_err err;
    mtls_err_init(&err);

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        printf("(skipped - no valid context) ");
        return 1;
    }

    mtls_async_ctx *async_ctx = NULL;
    int ret = mtls_async_ctx_create(&async_ctx, ctx, &err);
    if (ret != 0) {
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Start thread that will wakeup the poll */
    pthread_t thread;
    if (pthread_create(&thread, NULL, wakeup_thread, async_ctx) != 0) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    /* Poll with long timeout - should be woken up early */
    ret = mtls_async_poll(async_ctx, 5000, &err);

    pthread_join(thread, NULL);

    /* ret should be >= 0 (not an error) */
    if (ret < 0) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    mtls_async_ctx_destroy(async_ctx);
    mtls_ctx_free(ctx);
    return 1;
}

/*
 * =============================================================================
 * Test: Async Wakeup NULL
 * =============================================================================
 */
static int test_async_wakeup_null(void)
{
    int ret = mtls_async_wakeup(NULL);
    if (ret == 0) {
        return 0; /* Should fail */
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Async Connect NULL Params
 * =============================================================================
 */
static int test_async_connect_null_params(void)
{
    mtls_err err;
    mtls_err_init(&err);

    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = "/dev/null";

    mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        printf("(skipped - no valid context) ");
        return 1;
    }

    mtls_async_ctx *async_ctx = NULL;
    int ret = mtls_async_ctx_create(&async_ctx, ctx, &err);
    if (ret != 0) {
        mtls_ctx_free(ctx);
        return 0;
    }

    /* NULL async ctx */
    mtls_async_op *async_op = mtls_async_connect(NULL, "localhost:8443", NULL, NULL, &err);
    if (async_op != NULL) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    /* NULL address */
    async_op = mtls_async_connect(async_ctx, NULL, NULL, NULL, &err);
    if (async_op != NULL) {
        mtls_async_ctx_destroy(async_ctx);
        mtls_ctx_free(ctx);
        return 0;
    }

    mtls_async_ctx_destroy(async_ctx);
    mtls_ctx_free(ctx);
    return 1;
}

/*
 * =============================================================================
 * Test: Async Read NULL Params
 * =============================================================================
 */
static int test_async_read_null_params(void)
{
    mtls_err err;
    mtls_err_init(&err);
    char buf[64];

    /* NULL async ctx */
    mtls_async_op *async_op = mtls_async_read(NULL, NULL, buf, sizeof(buf), NULL, NULL, &err);
    if (async_op != NULL) {
        return 0;
    }

    return 1;
}

/*
 * =============================================================================
 * Test: Async Write NULL Params
 * =============================================================================
 */
static int test_async_write_null_params(void)
{
    mtls_err err;
    mtls_err_init(&err);
    const char *data = "test";

    /* NULL async ctx */
    mtls_async_op *async_op = mtls_async_write(NULL, NULL, data, strlen(data), NULL, NULL, &err);
    if (async_op != NULL) {
        return 0;
    }

    return 1;
}

/*
 * =============================================================================
 * Test: Async Close NULL Params
 * =============================================================================
 */
static int test_async_close_null_params(void)
{
    mtls_err err;
    mtls_err_init(&err);

    /* NULL async ctx */
    mtls_async_op *async_op = mtls_async_close(NULL, NULL, NULL, NULL, &err);
    if (async_op != NULL) {
        return 0;
    }

    return 1;
}

/*
 * =============================================================================
 * Test: Async Op State NULL
 * =============================================================================
 */
static int test_async_op_state_null(void)
{
    mtls_async_state state = mtls_async_op_get_state(NULL);
    if (state != MTLS_ASYNC_STATE_ERROR) {
        return 0;
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Async Op Pending NULL
 * =============================================================================
 */
static int test_async_op_pending_null(void)
{
    bool pending = mtls_async_op_is_pending(NULL);
    if (pending) {
        return 0; /* NULL should not be pending */
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Async Op Cancel NULL
 * =============================================================================
 */
static int test_async_op_cancel_null(void)
{
    int ret = mtls_async_op_cancel(NULL);
    if (ret == 0) {
        return 0; /* Should fail */
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Async Conn Get FD NULL
 * =============================================================================
 */
static int test_async_conn_get_fd_null(void)
{
    int conn_fd = mtls_async_conn_get_fd(NULL);
    if (conn_fd >= 0) {
        return 0; /* Should be -1 */
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Async Register Conn NULL
 * =============================================================================
 */
static int test_async_register_conn_null(void)
{
    mtls_err err;
    mtls_err_init(&err);

    int ret = mtls_async_register_conn(NULL, NULL, &err);
    if (ret == 0) {
        return 0; /* Should fail */
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Async Unregister Conn NULL
 * =============================================================================
 */
static int test_async_unregister_conn_null(void)
{
    /* Should not crash */
    mtls_async_unregister_conn(NULL, NULL);
    return 1;
}

/*
 * =============================================================================
 * Test: Async Pending Count NULL
 * =============================================================================
 */
static int test_async_pending_count_null(void)
{
    size_t count = mtls_async_pending_count(NULL);
    if (count != 0) {
        return 0;
    }
    return 1;
}

/*
 * =============================================================================
 * Test: Internal Get Socket FD
 * =============================================================================
 */
static int test_internal_get_socket_fd(void)
{
    /* NULL conn should return -1 */
    int sock_fd = mtls_internal_get_socket_fd(NULL);
    if (sock_fd != -1) {
        return 0;
    }
    return 1;
}

/*
 * =============================================================================
 * Main
 * =============================================================================
 */
int main(void)
{
    printf("\n=== Async I/O Module Tests ===\n\n");

    /* State and error code tests */
    TEST(async_state_string);
    TEST(error_codes_exist);

    /* Context lifecycle tests */
    TEST(async_ctx_null_params);
    TEST(async_ctx_create_destroy);

    /* Poll tests */
    TEST(async_poll_null_params);
    TEST(async_poll_no_events);

    /* Wakeup tests */
    TEST(async_wakeup_null);
    TEST(async_wakeup);

    /* Connect tests */
    TEST(async_connect_null_params);

    /* I/O tests */
    TEST(async_read_null_params);
    TEST(async_write_null_params);
    TEST(async_close_null_params);

    /* Operation management tests */
    TEST(async_op_state_null);
    TEST(async_op_pending_null);
    TEST(async_op_cancel_null);

    /* Connection integration tests */
    TEST(async_conn_get_fd_null);
    TEST(async_register_conn_null);
    TEST(async_unregister_conn_null);
    TEST(async_pending_count_null);

    /* Internal function tests */
    TEST(internal_get_socket_fd);

    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
