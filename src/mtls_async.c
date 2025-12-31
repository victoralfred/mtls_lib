/**
 * @file mtls_async.c
 * @brief Asynchronous I/O implementation for mTLS connections
 *
 * This module provides non-blocking, event-driven I/O operations using
 * platform-specific event notification mechanisms:
 * - Linux: epoll
 * - macOS/BSD: kqueue (TODO)
 * - Windows: IOCP (TODO)
 */

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _POSIX_C_SOURCE 200809L
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _GNU_SOURCE

#include "mtls/mtls_async.h"
#include "mtls/mtls.h"
#include "mtls/mtls_error.h"
#include "internal/mtls_internal.h"
#include "internal/platform.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#    include <sys/epoll.h>
#    include <sys/eventfd.h>
#    define MTLS_USE_EPOLL 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#    include <sys/event.h>
#    define MTLS_USE_KQUEUE 1
#else
#    error "Unsupported platform for async I/O"
#endif

/*
 * =============================================================================
 * Internal Types
 * =============================================================================
 */

/**
 * Operation type
 */
typedef enum {
    ASYNC_OP_CONNECT = 0,
    ASYNC_OP_READ = 1,
    ASYNC_OP_WRITE = 2,
    ASYNC_OP_CLOSE = 3
} async_op_type;

/**
 * Async operation entry
 */
struct mtls_async_op {
    async_op_type type;         /**< Operation type */
    mtls_async_state state;     /**< Current state */
    struct mtls_async_ctx *ctx; /**< Owning context */
    struct mtls_conn *conn;     /**< Connection (may be NULL for connect) */
    int socket_fd;              /**< Socket file descriptor */

    /* Operation-specific data */
    union {
        struct {
            char *addr;                     /**< Address string (owned) */
            mtls_async_connect_cb callback; /**< Connect callback */
        } connect;
        struct {
            void *buf;                 /**< Buffer for read */
            size_t len;                /**< Buffer length */
            mtls_async_io_cb callback; /**< I/O callback */
        } read;
        struct {
            const void *buf;           /**< Buffer for write */
            size_t len;                /**< Data length */
            size_t written;            /**< Bytes written so far */
            mtls_async_io_cb callback; /**< I/O callback */
        } write;
        struct {
            mtls_async_close_cb callback; /**< Close callback */
        } close;
    } data;

    void *userdata; /**< User context */

    struct mtls_async_op *next; /**< Next in list */
    struct mtls_async_op *prev; /**< Previous in list */
};

/**
 * Async context structure
 */
struct mtls_async_ctx {
    struct mtls_ctx *mtls_ctx; /**< mTLS context */

#if defined(MTLS_USE_EPOLL)
    int epoll_fd;  /**< epoll file descriptor */
    int wakeup_fd; /**< eventfd for wakeup */
#elif defined(MTLS_USE_KQUEUE)
    int kqueue_fd;      /**< kqueue file descriptor */
    int wakeup_pipe[2]; /**< pipe for wakeup */
#endif

    /* Operation list */
    mtls_async_op *ops_head; /**< Head of operations list */
    mtls_async_op *ops_tail; /**< Tail of operations list */
    size_t ops_count;        /**< Number of pending operations */

    /* Synchronization */
    pthread_mutex_t lock; /**< Context lock */
    bool destroyed;       /**< Destruction flag */
};

/*
 * =============================================================================
 * Internal Helpers
 * =============================================================================
 */

/**
 * Create a new async operation
 */
static mtls_async_op *async_op_create(mtls_async_ctx *ctx, async_op_type type)
{
    mtls_async_op *async_op = calloc(1, sizeof(mtls_async_op));
    if (!async_op) {
        return NULL;
    }

    async_op->type = type;
    async_op->state = MTLS_ASYNC_STATE_IDLE;
    async_op->ctx = ctx;
    async_op->socket_fd = -1;

    return async_op;
}

/**
 * Destroy an async operation
 */
static void async_op_destroy(mtls_async_op *async_op)
{
    if (!async_op) {
        return;
    }

    /* Free operation-specific resources */
    if (async_op->type == ASYNC_OP_CONNECT && async_op->data.connect.addr) {
        free(async_op->data.connect.addr);
    }

    free(async_op);
}

/**
 * Add operation to context list
 */
static void ctx_add_op(mtls_async_ctx *ctx, mtls_async_op *async_op)
{
    async_op->next = NULL;
    async_op->prev = ctx->ops_tail;

    if (ctx->ops_tail) {
        ctx->ops_tail->next = async_op;
    } else {
        ctx->ops_head = async_op;
    }
    ctx->ops_tail = async_op;
    ctx->ops_count++;
}

/**
 * Remove operation from context list
 */
static void ctx_remove_op(mtls_async_ctx *ctx, mtls_async_op *async_op)
{
    if (async_op->prev) {
        async_op->prev->next = async_op->next;
    } else {
        ctx->ops_head = async_op->next;
    }

    if (async_op->next) {
        async_op->next->prev = async_op->prev;
    } else {
        ctx->ops_tail = async_op->prev;
    }

    async_op->next = NULL;
    async_op->prev = NULL;
    ctx->ops_count--;
}

/**
 * Find operation by socket fd
 */
static mtls_async_op *ctx_find_op_by_fd(mtls_async_ctx *ctx, int socket_fd)
{
    // NOLINTNEXTLINE(readability-identifier-length) - op is clear in loop context
    for (mtls_async_op *op = ctx->ops_head; op; op = op->next) {
        if (op->socket_fd == socket_fd) {
            return op;
        }
    }
    return NULL;
}

#if defined(MTLS_USE_EPOLL)
/**
 * Register fd with epoll
 */
static int epoll_register(mtls_async_ctx *ctx, int socket_fd, uint32_t events, mtls_err *err)
{
    struct epoll_event epoll_ev;
    epoll_ev.events = events;
    epoll_ev.data.fd = socket_fd;

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, socket_fd, &epoll_ev) == -1) {
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "Failed to add fd to epoll");
        return -1;
    }
    return 0;
}

/**
 * Unregister fd from epoll
 */
static void epoll_unregister(mtls_async_ctx *ctx, int socket_fd)
{
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, socket_fd, NULL);
}
#endif

/**
 * Emit async event
 */
static void emit_async_event(mtls_async_ctx *ctx, mtls_event_type type, struct mtls_conn *conn,
                             mtls_error_code code)
{
    if (!ctx || !ctx->mtls_ctx) {
        return;
    }

    /* Stack-allocated buffer for remote address */
    char addr_buf[128];
    addr_buf[0] = '\0';

    mtls_event event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.error_code = code;
    event.timestamp_us = platform_get_time_us();
    event.conn = conn;

    if (conn) {
        if (mtls_get_remote_addr(conn, addr_buf, sizeof(addr_buf)) == 0 && addr_buf[0] != '\0') {
            event.remote_addr = addr_buf;
        }
    }

    mtls_emit_event(ctx->mtls_ctx, &event);
}

/*
 * =============================================================================
 * Public API - Context Lifecycle
 * =============================================================================
 */

int mtls_async_ctx_create(mtls_async_ctx **async_ctx, struct mtls_ctx *ctx, mtls_err *err)
{
    if (!async_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "async_ctx is NULL");
        return -1;
    }

    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "mTLS context is NULL");
        return -1;
    }

    *async_ctx = NULL;

    mtls_async_ctx *actx = calloc(1, sizeof(mtls_async_ctx));
    if (!actx) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate async context");
        return -1;
    }

    actx->mtls_ctx = ctx;

#if defined(MTLS_USE_EPOLL)
    /* Create epoll instance */
    actx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (actx->epoll_fd == -1) {
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "Failed to create epoll instance");
        free(actx);
        return -1;
    }

    /* Create eventfd for wakeup */
    actx->wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (actx->wakeup_fd == -1) {
        close(actx->epoll_fd);
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "Failed to create eventfd");
        free(actx);
        return -1;
    }

    /* Register wakeup fd */
    struct epoll_event wakeup_ev;
    wakeup_ev.events = EPOLLIN;
    wakeup_ev.data.fd = actx->wakeup_fd;
    if (epoll_ctl(actx->epoll_fd, EPOLL_CTL_ADD, actx->wakeup_fd, &wakeup_ev) == -1) {
        close(actx->wakeup_fd);
        close(actx->epoll_fd);
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "Failed to register wakeup fd");
        free(actx);
        return -1;
    }
#elif defined(MTLS_USE_KQUEUE)
    /* Create kqueue instance */
    actx->kqueue_fd = kqueue();
    if (actx->kqueue_fd == -1) {
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "Failed to create kqueue");
        free(actx);
        return -1;
    }

    /* Create wakeup pipe */
    if (pipe(actx->wakeup_pipe) == -1) {
        close(actx->kqueue_fd);
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "Failed to create wakeup pipe");
        free(actx);
        return -1;
    }
#endif

    if (pthread_mutex_init(&actx->lock, NULL) != 0) {
#if defined(MTLS_USE_EPOLL)
        close(actx->wakeup_fd);
        close(actx->epoll_fd);
#elif defined(MTLS_USE_KQUEUE)
        close(actx->wakeup_pipe[0]);
        close(actx->wakeup_pipe[1]);
        close(actx->kqueue_fd);
#endif
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Failed to initialize mutex");
        free(actx);
        return -1;
    }

    *async_ctx = actx;
    return 0;
}

void mtls_async_ctx_destroy(mtls_async_ctx *async_ctx)
{
    if (!async_ctx) {
        return;
    }

    pthread_mutex_lock(&async_ctx->lock);
    async_ctx->destroyed = true;

    /* Cancel all pending operations */
    // NOLINTNEXTLINE(readability-identifier-length) - op is clear in loop context
    mtls_async_op *op = async_ctx->ops_head;
    while (op) {
        mtls_async_op *next = op->next;
        op->state = MTLS_ASYNC_STATE_ERROR;

#if defined(MTLS_USE_EPOLL)
        if (op->socket_fd >= 0) {
            epoll_unregister(async_ctx, op->socket_fd);
        }
#endif

        /* Invoke callback with cancellation error */
        mtls_err err;
        mtls_err_init(&err);
        MTLS_ERR_SET(&err, MTLS_ERR_ASYNC_CANCELLED, "Async context destroyed");

        switch (op->type) {
        case ASYNC_OP_CONNECT:
            if (op->data.connect.callback) {
                op->data.connect.callback(NULL, &err, op->userdata);
            }
            break;
        case ASYNC_OP_READ:
            if (op->data.read.callback) {
                op->data.read.callback(op->conn, -1, &err, op->userdata);
            }
            break;
        case ASYNC_OP_WRITE:
            if (op->data.write.callback) {
                op->data.write.callback(op->conn, -1, &err, op->userdata);
            }
            break;
        case ASYNC_OP_CLOSE:
            if (op->data.close.callback) {
                op->data.close.callback(&err, op->userdata);
            }
            break;
        }

        async_op_destroy(op);
        op = next;
    }

    async_ctx->ops_head = NULL;
    async_ctx->ops_tail = NULL;
    async_ctx->ops_count = 0;

    pthread_mutex_unlock(&async_ctx->lock);

#if defined(MTLS_USE_EPOLL)
    close(async_ctx->wakeup_fd);
    close(async_ctx->epoll_fd);
#elif defined(MTLS_USE_KQUEUE)
    close(async_ctx->wakeup_pipe[0]);
    close(async_ctx->wakeup_pipe[1]);
    close(async_ctx->kqueue_fd);
#endif

    pthread_mutex_destroy(&async_ctx->lock);
    free(async_ctx);
}

// cppcheck-suppress constParameterPointer
int mtls_async_ctx_get_fd(mtls_async_ctx *async_ctx)
{
    if (!async_ctx) {
        return -1;
    }

#if defined(MTLS_USE_EPOLL)
    return async_ctx->epoll_fd;
#elif defined(MTLS_USE_KQUEUE)
    return async_ctx->kqueue_fd;
#else
    return -1;
#endif
}

/*
 * =============================================================================
 * Public API - Event Loop
 * =============================================================================
 */

#if defined(MTLS_USE_EPOLL)
/**
 * Process a single epoll event
 */
// NOLINTNEXTLINE(readability-identifier-length) - ev is standard naming for epoll events
static void process_epoll_event(mtls_async_ctx *ctx, struct epoll_event *ev)
{
    int socket_fd = ev->data.fd;

    /* Handle wakeup event */
    if (socket_fd == ctx->wakeup_fd) {
        uint64_t val;
        // NOLINTNEXTLINE(bugprone-unused-return-value) - we just drain the eventfd
        (void)read(ctx->wakeup_fd, &val, sizeof(val));
        return;
    }

    pthread_mutex_lock(&ctx->lock);
    // NOLINTNEXTLINE(readability-identifier-length) - op is standard naming for operations
    mtls_async_op *op = ctx_find_op_by_fd(ctx, socket_fd);
    if (!op) {
        pthread_mutex_unlock(&ctx->lock);
        return;
    }

    mtls_err err;
    mtls_err_init(&err);

    switch (op->type) {
    case ASYNC_OP_CONNECT: {
        /* Check for connection completion */
        int sock_err = 0;
        socklen_t sock_err_len = sizeof(sock_err);
        if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_len) == -1 ||
            sock_err != 0) {
            /* Connection failed */
            op->state = MTLS_ASYNC_STATE_ERROR;
            epoll_unregister(ctx, socket_fd);
            ctx_remove_op(ctx, op);
            pthread_mutex_unlock(&ctx->lock);

            MTLS_ERR_SET(&err, MTLS_ERR_CONNECT_FAILED, "Async connect failed");
            emit_async_event(ctx, MTLS_EVENT_ASYNC_CONNECT_FAILURE, NULL, MTLS_ERR_CONNECT_FAILED);
            if (op->data.connect.callback) {
                op->data.connect.callback(NULL, &err, op->userdata);
            }
            close(socket_fd);
            async_op_destroy(op);
            return;
        }

        /* Connection succeeded, now do TLS handshake */
        op->state = MTLS_ASYNC_STATE_HANDSHAKING;

        /* Create mTLS connection from socket */
        struct mtls_conn *conn = mtls_connect(ctx->mtls_ctx, op->data.connect.addr, &err);
        epoll_unregister(ctx, socket_fd);
        ctx_remove_op(ctx, op);
        pthread_mutex_unlock(&ctx->lock);

        if (!conn) {
            emit_async_event(ctx, MTLS_EVENT_ASYNC_CONNECT_FAILURE, NULL, err.code);
            if (op->data.connect.callback) {
                op->data.connect.callback(NULL, &err, op->userdata);
            }
        } else {
            emit_async_event(ctx, MTLS_EVENT_ASYNC_CONNECT_SUCCESS, conn, MTLS_OK);
            if (op->data.connect.callback) {
                op->data.connect.callback(conn, NULL, op->userdata);
            }
        }
        async_op_destroy(op);
        return;
    }

    case ASYNC_OP_READ: {
        if (ev->events & (EPOLLERR | EPOLLHUP)) {
            op->state = MTLS_ASYNC_STATE_ERROR;
            epoll_unregister(ctx, socket_fd);
            ctx_remove_op(ctx, op);
            pthread_mutex_unlock(&ctx->lock);

            MTLS_ERR_SET(&err, MTLS_ERR_READ_FAILED, "Read error");
            if (op->data.read.callback) {
                op->data.read.callback(op->conn, -1, &err, op->userdata);
            }
            async_op_destroy(op);
            return;
        }

        /* Perform read */
        ssize_t bytes = mtls_read(op->conn, op->data.read.buf, op->data.read.len, &err);
        epoll_unregister(ctx, socket_fd);
        ctx_remove_op(ctx, op);
        pthread_mutex_unlock(&ctx->lock);

        if (op->data.read.callback) {
            if (bytes < 0) {
                op->data.read.callback(op->conn, bytes, &err, op->userdata);
            } else {
                op->data.read.callback(op->conn, bytes, NULL, op->userdata);
            }
        }
        async_op_destroy(op);
        return;
    }

    case ASYNC_OP_WRITE: {
        if (ev->events & (EPOLLERR | EPOLLHUP)) {
            op->state = MTLS_ASYNC_STATE_ERROR;
            epoll_unregister(ctx, socket_fd);
            ctx_remove_op(ctx, op);
            pthread_mutex_unlock(&ctx->lock);

            MTLS_ERR_SET(&err, MTLS_ERR_WRITE_FAILED, "Write error");
            if (op->data.write.callback) {
                op->data.write.callback(op->conn, -1, &err, op->userdata);
            }
            async_op_destroy(op);
            return;
        }

        /* Perform write */
        const char *buf = (const char *)op->data.write.buf + op->data.write.written;
        size_t remaining = op->data.write.len - op->data.write.written;
        ssize_t bytes = mtls_write(op->conn, buf, remaining, &err);

        if (bytes < 0) {
            epoll_unregister(ctx, socket_fd);
            ctx_remove_op(ctx, op);
            pthread_mutex_unlock(&ctx->lock);

            if (op->data.write.callback) {
                op->data.write.callback(op->conn, -1, &err, op->userdata);
            }
            async_op_destroy(op);
            return;
        }

        op->data.write.written += (size_t)bytes;
        if (op->data.write.written >= op->data.write.len) {
            /* Write complete */
            epoll_unregister(ctx, socket_fd);
            ctx_remove_op(ctx, op);
            pthread_mutex_unlock(&ctx->lock);

            if (op->data.write.callback) {
                op->data.write.callback(op->conn, (ssize_t)op->data.write.written, NULL,
                                        op->userdata);
            }
            async_op_destroy(op);
            return;
        }

        /* More to write, keep waiting */
        pthread_mutex_unlock(&ctx->lock);
        return;
    }

    case ASYNC_OP_CLOSE: {
        mtls_close(op->conn);
        epoll_unregister(ctx, socket_fd);
        ctx_remove_op(ctx, op);
        pthread_mutex_unlock(&ctx->lock);

        if (op->data.close.callback) {
            op->data.close.callback(NULL, op->userdata);
        }
        async_op_destroy(op);
        return;
    }
    }

    pthread_mutex_unlock(&ctx->lock);
}
#endif

int mtls_async_poll(mtls_async_ctx *async_ctx, int timeout_ms, mtls_err *err)
{
    if (!async_ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "async_ctx is NULL");
        return -1;
    }

#if defined(MTLS_USE_EPOLL)
    struct epoll_event events[64];
    int nevents = epoll_wait(async_ctx->epoll_fd, events, 64, timeout_ms);

    if (nevents == -1) {
        if (errno == EINTR) {
            return 0; /* Interrupted, not an error */
        }
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "epoll_wait failed");
        return -1;
    }

    for (int i = 0; i < nevents; i++) {
        process_epoll_event(async_ctx, &events[i]);
    }

    return nevents;
#elif defined(MTLS_USE_KQUEUE)
    struct kevent events[64];
    struct timespec ts;
    struct timespec *tsp = NULL;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }

    int nevents = kevent(async_ctx->kqueue_fd, NULL, 0, events, 64, tsp);
    if (nevents == -1) {
        if (errno == EINTR) {
            return 0;
        }
        MTLS_ERR_SET(err, MTLS_ERR_EVENTLOOP_ERROR, "kevent failed");
        return -1;
    }

    /* TODO: Process kqueue events */
    return nevents;
#else
    MTLS_ERR_SET(err, MTLS_ERR_NOT_IMPLEMENTED, "Async I/O not implemented for this platform");
    return -1;
#endif
}

int mtls_async_wakeup(mtls_async_ctx *async_ctx)
{
    if (!async_ctx) {
        return -1;
    }

#if defined(MTLS_USE_EPOLL)
    uint64_t val = 1;
    if (write(async_ctx->wakeup_fd, &val, sizeof(val)) == -1) {
        return -1;
    }
    return 0;
#elif defined(MTLS_USE_KQUEUE)
    char dummy = 1;
    if (write(async_ctx->wakeup_pipe[1], &dummy, 1) == -1) {
        return -1;
    }
    return 0;
#else
    return -1;
#endif
}

// cppcheck-suppress constParameterPointer ; mutex lock requires non-const
size_t mtls_async_pending_count(mtls_async_ctx *async_ctx)
{
    if (!async_ctx) {
        return 0;
    }

    pthread_mutex_lock(&async_ctx->lock);
    size_t count = async_ctx->ops_count;
    pthread_mutex_unlock(&async_ctx->lock);

    return count;
}

/*
 * =============================================================================
 * Public API - Async Operations
 * =============================================================================
 */

mtls_async_op *mtls_async_connect(mtls_async_ctx *async_ctx, const char *addr,
                                  mtls_async_connect_cb callback, void *userdata, mtls_err *err)
{
    if (!async_ctx || !addr) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    pthread_mutex_lock(&async_ctx->lock);

    if (async_ctx->destroyed) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_ASYNC_CANCELLED, "Context is destroyed");
        return NULL;
    }

    // NOLINTNEXTLINE(readability-identifier-length) - op is standard naming for operations
    mtls_async_op *op = async_op_create(async_ctx, ASYNC_OP_CONNECT);
    if (!op) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate operation");
        return NULL;
    }

    op->data.connect.addr = strdup(addr);
    if (!op->data.connect.addr) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate address");
        return NULL;
    }

    op->data.connect.callback = callback;
    op->userdata = userdata;
    op->state = MTLS_ASYNC_STATE_CONNECTING;

    /* Parse address and create non-blocking socket */
    mtls_addr parsed_addr;
    if (platform_parse_addr(addr, &parsed_addr, err) != 0) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        return NULL;
    }

    int domain = (parsed_addr.addr.sa.sa_family == AF_INET6) ? AF_INET6 : AF_INET;
    mtls_socket_t sock = platform_socket_create(domain, SOCK_STREAM, 0, err);
    if (sock == MTLS_INVALID_SOCKET) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        return NULL;
    }

    if (platform_socket_set_nonblocking(sock, true, err) != 0) {
        platform_socket_close(sock);
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        return NULL;
    }

    op->socket_fd = sock;

    /* Start async connect */
    int ret = connect(sock, &parsed_addr.addr.sa, parsed_addr.len);
    if (ret == -1 && errno != EINPROGRESS) {
        platform_socket_close(sock);
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_CONNECT_FAILED, "Connect failed");
        return NULL;
    }

#if defined(MTLS_USE_EPOLL)
    if (epoll_register(async_ctx, sock, EPOLLOUT | EPOLLET, err) != 0) {
        platform_socket_close(sock);
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        return NULL;
    }
#endif

    ctx_add_op(async_ctx, op);
    emit_async_event(async_ctx, MTLS_EVENT_ASYNC_CONNECT_START, NULL, MTLS_OK);

    pthread_mutex_unlock(&async_ctx->lock);
    return op;
}

mtls_async_op *mtls_async_read(mtls_async_ctx *async_ctx, struct mtls_conn *conn, void *buf,
                               size_t len, mtls_async_io_cb callback, void *userdata, mtls_err *err)
{
    if (!async_ctx || !conn || !buf || len == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    pthread_mutex_lock(&async_ctx->lock);

    if (async_ctx->destroyed) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_ASYNC_CANCELLED, "Context is destroyed");
        return NULL;
    }

    // NOLINTNEXTLINE(readability-identifier-length) - op is standard naming for operations
    mtls_async_op *op = async_op_create(async_ctx, ASYNC_OP_READ);
    if (!op) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate operation");
        return NULL;
    }

    op->conn = conn;
    op->data.read.buf = buf;
    op->data.read.len = len;
    op->data.read.callback = callback;
    op->userdata = userdata;
    op->state = MTLS_ASYNC_STATE_READING;

    /* Get socket fd from connection */
    int socket_fd = mtls_async_conn_get_fd(conn);
    if (socket_fd < 0) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid connection");
        return NULL;
    }
    op->socket_fd = socket_fd;

#if defined(MTLS_USE_EPOLL)
    if (epoll_register(async_ctx, socket_fd, EPOLLIN | EPOLLET, err) != 0) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        return NULL;
    }
#endif

    ctx_add_op(async_ctx, op);
    pthread_mutex_unlock(&async_ctx->lock);

    return op;
}

mtls_async_op *mtls_async_write(mtls_async_ctx *async_ctx, struct mtls_conn *conn, const void *buf,
                                size_t len, mtls_async_io_cb callback, void *userdata,
                                mtls_err *err)
{
    if (!async_ctx || !conn || !buf || len == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    pthread_mutex_lock(&async_ctx->lock);

    if (async_ctx->destroyed) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_ASYNC_CANCELLED, "Context is destroyed");
        return NULL;
    }

    // NOLINTNEXTLINE(readability-identifier-length) - op is standard naming for operations
    mtls_async_op *op = async_op_create(async_ctx, ASYNC_OP_WRITE);
    if (!op) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate operation");
        return NULL;
    }

    op->conn = conn;
    op->data.write.buf = buf;
    op->data.write.len = len;
    op->data.write.written = 0;
    op->data.write.callback = callback;
    op->userdata = userdata;
    op->state = MTLS_ASYNC_STATE_WRITING;

    /* Get socket fd from connection */
    int socket_fd = mtls_async_conn_get_fd(conn);
    if (socket_fd < 0) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid connection");
        return NULL;
    }
    op->socket_fd = socket_fd;

#if defined(MTLS_USE_EPOLL)
    if (epoll_register(async_ctx, socket_fd, EPOLLOUT | EPOLLET, err) != 0) {
        async_op_destroy(op);
        pthread_mutex_unlock(&async_ctx->lock);
        return NULL;
    }
#endif

    ctx_add_op(async_ctx, op);
    pthread_mutex_unlock(&async_ctx->lock);

    return op;
}

mtls_async_op *mtls_async_close(mtls_async_ctx *async_ctx, struct mtls_conn *conn,
                                mtls_async_close_cb callback, void *userdata, mtls_err *err)
{
    if (!async_ctx || !conn) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    pthread_mutex_lock(&async_ctx->lock);

    if (async_ctx->destroyed) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_ASYNC_CANCELLED, "Context is destroyed");
        return NULL;
    }

    // NOLINTNEXTLINE(readability-identifier-length) - op is standard naming for operations
    mtls_async_op *op = async_op_create(async_ctx, ASYNC_OP_CLOSE);
    if (!op) {
        pthread_mutex_unlock(&async_ctx->lock);
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate operation");
        return NULL;
    }

    op->conn = conn;
    op->data.close.callback = callback;
    op->userdata = userdata;
    op->state = MTLS_ASYNC_STATE_CLOSING;

    int socket_fd = mtls_async_conn_get_fd(conn);
    op->socket_fd = socket_fd;

#if defined(MTLS_USE_EPOLL)
    if (socket_fd >= 0) {
        if (epoll_register(async_ctx, socket_fd, EPOLLOUT | EPOLLET, err) != 0) {
            async_op_destroy(op);
            pthread_mutex_unlock(&async_ctx->lock);
            return NULL;
        }
    }
#endif

    ctx_add_op(async_ctx, op);
    pthread_mutex_unlock(&async_ctx->lock);

    return op;
}

/*
 * =============================================================================
 * Public API - Operation Management
 * =============================================================================
 */

int mtls_async_op_cancel(mtls_async_op *async_op)
{
    if (!async_op || !async_op->ctx) {
        return -1;
    }

    mtls_async_ctx *ctx = async_op->ctx;
    pthread_mutex_lock(&ctx->lock);

    if (async_op->state == MTLS_ASYNC_STATE_ERROR || async_op->state == MTLS_ASYNC_STATE_IDLE) {
        pthread_mutex_unlock(&ctx->lock);
        return -1; /* Already completed */
    }

    async_op->state = MTLS_ASYNC_STATE_ERROR;

#if defined(MTLS_USE_EPOLL)
    if (async_op->socket_fd >= 0) {
        epoll_unregister(ctx, async_op->socket_fd);
    }
#endif

    ctx_remove_op(ctx, async_op);
    pthread_mutex_unlock(&ctx->lock);

    /* Invoke callback with cancellation error */
    mtls_err err;
    mtls_err_init(&err);
    MTLS_ERR_SET(&err, MTLS_ERR_ASYNC_CANCELLED, "Operation cancelled");
    emit_async_event(ctx, MTLS_EVENT_ASYNC_OP_CANCELLED, async_op->conn, MTLS_ERR_ASYNC_CANCELLED);

    switch (async_op->type) {
    case ASYNC_OP_CONNECT:
        if (async_op->data.connect.callback) {
            async_op->data.connect.callback(NULL, &err, async_op->userdata);
        }
        if (async_op->socket_fd >= 0) {
            close(async_op->socket_fd);
        }
        break;
    case ASYNC_OP_READ:
        if (async_op->data.read.callback) {
            async_op->data.read.callback(async_op->conn, -1, &err, async_op->userdata);
        }
        break;
    case ASYNC_OP_WRITE:
        if (async_op->data.write.callback) {
            async_op->data.write.callback(async_op->conn, -1, &err, async_op->userdata);
        }
        break;
    case ASYNC_OP_CLOSE:
        if (async_op->data.close.callback) {
            async_op->data.close.callback(&err, async_op->userdata);
        }
        break;
    }

    async_op_destroy(async_op);
    return 0;
}

// cppcheck-suppress constParameterPointer
mtls_async_state mtls_async_op_get_state(mtls_async_op *async_op)
{
    if (!async_op) {
        return MTLS_ASYNC_STATE_ERROR;
    }
    return async_op->state;
}

// cppcheck-suppress constParameterPointer
bool mtls_async_op_is_pending(mtls_async_op *async_op)
{
    if (!async_op) {
        return false;
    }

    mtls_async_state state = async_op->state;
    return state != MTLS_ASYNC_STATE_IDLE && state != MTLS_ASYNC_STATE_ERROR;
}

/*
 * =============================================================================
 * Public API - Connection Integration
 * =============================================================================
 */

// cppcheck-suppress constParameterPointer
int mtls_async_conn_get_fd(struct mtls_conn *conn)
{
    if (!conn) {
        return -1;
    }

    /* Access the internal socket fd */
    /* Note: This requires access to the connection structure internals */
    return mtls_internal_get_socket_fd(conn);
}

// cppcheck-suppress constParameterPointer ; modifies epoll registration
int mtls_async_register_conn(mtls_async_ctx *async_ctx, struct mtls_conn *conn, mtls_err *err)
{
    if (!async_ctx || !conn) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    int socket_fd = mtls_async_conn_get_fd(conn);
    if (socket_fd < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid connection");
        return -1;
    }

    /* Set socket to non-blocking */
    if (platform_socket_set_nonblocking(socket_fd, true, err) != 0) {
        return -1;
    }

    return 0;
}

void mtls_async_unregister_conn(mtls_async_ctx *async_ctx, struct mtls_conn *conn)
{
    if (!async_ctx || !conn) {
        return;
    }

    int socket_fd = mtls_async_conn_get_fd(conn);
    if (socket_fd < 0) {
        return;
    }

    pthread_mutex_lock(&async_ctx->lock);

    /* Cancel any pending operations on this connection */
    // NOLINTNEXTLINE(readability-identifier-length) - op is standard naming for operations
    mtls_async_op *op = async_ctx->ops_head;
    while (op) {
        mtls_async_op *next = op->next;
        if (op->conn == conn || op->socket_fd == socket_fd) {
#if defined(MTLS_USE_EPOLL)
            epoll_unregister(async_ctx, op->socket_fd);
#endif
            ctx_remove_op(async_ctx, op);

            /* Invoke callback with cancellation */
            mtls_err err;
            mtls_err_init(&err);
            MTLS_ERR_SET(&err, MTLS_ERR_ASYNC_CANCELLED, "Connection unregistered");

            switch (op->type) {
            case ASYNC_OP_CONNECT:
                if (op->data.connect.callback) {
                    op->data.connect.callback(NULL, &err, op->userdata);
                }
                break;
            case ASYNC_OP_READ:
                if (op->data.read.callback) {
                    op->data.read.callback(op->conn, -1, &err, op->userdata);
                }
                break;
            case ASYNC_OP_WRITE:
                if (op->data.write.callback) {
                    op->data.write.callback(op->conn, -1, &err, op->userdata);
                }
                break;
            case ASYNC_OP_CLOSE:
                if (op->data.close.callback) {
                    op->data.close.callback(&err, op->userdata);
                }
                break;
            }

            async_op_destroy(op);
        }
        op = next;
    }

    pthread_mutex_unlock(&async_ctx->lock);
}

/*
 * =============================================================================
 * Public API - Utility Functions
 * =============================================================================
 */

const char *mtls_async_state_string(mtls_async_state state)
{
    switch (state) {
    case MTLS_ASYNC_STATE_IDLE:
        return "idle";
    case MTLS_ASYNC_STATE_CONNECTING:
        return "connecting";
    case MTLS_ASYNC_STATE_HANDSHAKING:
        return "handshaking";
    case MTLS_ASYNC_STATE_READING:
        return "reading";
    case MTLS_ASYNC_STATE_WRITING:
        return "writing";
    case MTLS_ASYNC_STATE_CLOSING:
        return "closing";
    case MTLS_ASYNC_STATE_ERROR:
        return "error";
    default:
        return "unknown";
    }
}
