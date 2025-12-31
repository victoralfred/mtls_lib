/**
 * @file mtls_types.h
 * @brief Core type definitions for the mTLS library
 *
 * This header defines fundamental types, constants, and platform abstractions
 * used throughout the mTLS library.
 */

#ifndef MTLS_TYPES_H
#define MTLS_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* POSIX types for ssize_t */
#if defined(_WIN32)
#    include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#    include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * Annex K-like bounds-checked helpers
 * =============================================================================
 *
 * Some static analyzers flag raw memset/memcpy usage as "insecure".
 * Provide a small, portable, bounds-checked alternative.
 *
 * This is NOT the optional C11 Annex K memset_s; it is a project-local helper.
 * Returns 0 on success, non-zero on invalid arguments.
 */
static inline int mtls_memset_s(void *dest, size_t destsz, int value, size_t count)
{
    if (dest == NULL) {
        return -1;
    }
    if (count > destsz) {
        return -1;
    }

    volatile unsigned char *ptr = (volatile unsigned char *)dest;
    for (size_t i = 0; i < count; i++) {
        ptr[i] = (unsigned char)value;
    }
    return 0;
}

static inline int mtls_memcpy_s(void *dest, size_t destsz, const void *src, size_t count)
{
    if (dest == NULL || src == NULL) {
        return -1;
    }
    if (count > destsz) {
        return -1;
    }

    unsigned char *dest_bytes = (unsigned char *)dest;
    const unsigned char *src_bytes = (const unsigned char *)src;
    for (size_t i = 0; i < count; i++) {
        dest_bytes[i] = src_bytes[i];
    }
    return 0;
}

/*
 * API visibility macros
 *
 * For Windows: Only use dllexport/dllimport for shared libraries (DLLs)
 * For static libraries, no decoration is needed
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#    if defined(MTLS_SHARED_LIB)
/* Building or using a DLL */
#        ifdef MTLS_BUILDING_LIB
#            define MTLS_API __declspec(dllexport)
#        else
#            define MTLS_API __declspec(dllimport)
#        endif
#    else
/* Static library - no special decoration needed */
#        define MTLS_API
#    endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#    define MTLS_API __attribute__((visibility("default")))
#else
#    define MTLS_API
#endif

/*
 * Version information
 * Provided as both macros (for preprocessor use) and enum (for type safety)
 */
enum { MTLS_VERSION_MAJOR = 0, MTLS_VERSION_MINOR = 1, MTLS_VERSION_PATCH = 0 };

#define MTLS_VERSION_STRING "0.1.0"

/*
 * TLS version constants
 */
typedef enum mtls_tls_version {
    MTLS_TLS_1_2 = 0x0303, /* TLS 1.2 */
    MTLS_TLS_1_3 = 0x0304  /* TLS 1.3 */
} mtls_tls_version;

/*
 * Connection state
 */
typedef enum mtls_conn_state {
    MTLS_CONN_STATE_NONE = 0,    /* Not initialized */
    MTLS_CONN_STATE_CONNECTING,  /* TCP connection in progress */
    MTLS_CONN_STATE_HANDSHAKING, /* TLS handshake in progress */
    MTLS_CONN_STATE_ESTABLISHED, /* Connected and verified */
    MTLS_CONN_STATE_CLOSING,     /* Shutdown in progress */
    MTLS_CONN_STATE_CLOSED,      /* Connection closed */
    MTLS_CONN_STATE_ERROR        /* Error state */
} mtls_conn_state;

/*
 * Event types for observability
 */
typedef enum mtls_event_type {
    /* Connection events (1-10) */
    MTLS_EVENT_CONNECT_START = 1,
    MTLS_EVENT_CONNECT_SUCCESS = 2,
    MTLS_EVENT_CONNECT_FAILURE = 3,
    MTLS_EVENT_HANDSHAKE_START = 4,
    MTLS_EVENT_HANDSHAKE_SUCCESS = 5,
    MTLS_EVENT_HANDSHAKE_FAILURE = 6,
    MTLS_EVENT_READ = 7,
    MTLS_EVENT_WRITE = 8,
    MTLS_EVENT_CLOSE = 9,
    MTLS_EVENT_KILL_SWITCH_TRIGGERED = 10,

    /* OCSP/CRL events (11-20) */
    MTLS_EVENT_OCSP_CHECK_START = 11,
    MTLS_EVENT_OCSP_CHECK_SUCCESS = 12,
    MTLS_EVENT_OCSP_CHECK_FAILURE = 13,
    MTLS_EVENT_OCSP_STAPLE_VERIFIED = 14,
    MTLS_EVENT_CRL_CHECK_START = 15,
    MTLS_EVENT_CRL_CHECK_SUCCESS = 16,
    MTLS_EVENT_CRL_CHECK_FAILURE = 17,
    MTLS_EVENT_CRL_DOWNLOAD_START = 18,
    MTLS_EVENT_CRL_DOWNLOAD_SUCCESS = 19,
    MTLS_EVENT_CRL_DOWNLOAD_FAILURE = 20,

    /* Rate limiting events (21-23) */
    MTLS_EVENT_RATE_LIMIT_CHECK = 21,
    MTLS_EVENT_RATE_LIMIT_EXCEEDED = 22,
    MTLS_EVENT_RATE_LIMIT_ALLOWED = 23,

    /* Deadline events (30-31) */
    MTLS_EVENT_DEADLINE_START = 30,
    MTLS_EVENT_DEADLINE_EXCEEDED = 31,

    /* Certificate pinning events (60-62) */
    MTLS_EVENT_PIN_CHECK_START = 60,
    MTLS_EVENT_PIN_CHECK_SUCCESS = 61,
    MTLS_EVENT_PIN_CHECK_FAILURE = 62,

    /* HSM events (70-73) */
    MTLS_EVENT_HSM_INIT_START = 70,
    MTLS_EVENT_HSM_INIT_SUCCESS = 71,
    MTLS_EVENT_HSM_INIT_FAILURE = 72,
    MTLS_EVENT_HSM_KEY_LOADED = 73,

    /* Certificate Transparency events (80-83) */
    MTLS_EVENT_CT_CHECK_START = 80,
    MTLS_EVENT_CT_CHECK_SUCCESS = 81,
    MTLS_EVENT_CT_CHECK_FAILURE = 82,
    MTLS_EVENT_CT_SCT_VALIDATED = 83
} mtls_event_type;

/*
 * Opaque handle types
 */
typedef struct mtls_ctx mtls_ctx;
typedef struct mtls_conn mtls_conn;
typedef struct mtls_listener mtls_listener;

/*
 * Peer identity information
 * Size limits for identity fields
 */
enum {
    MTLS_MAX_COMMON_NAME_LEN = 256,
    MTLS_MAX_SPIFFE_ID_LEN = 512,
    MTLS_MAX_SAN_LEN = 256,
    /*
     * Identity comparison limits
     * Enforce a hard upper bound on identity length to prevent:
     * - Resource exhaustion attacks
     * - Comparison bypass attacks via oversized strings
     * - Timing analysis on unbounded comparisons
     * Identities exceeding this limit are rejected with MTLS_ERR_IDENTITY_TOO_LONG
     */
    MTLS_MAX_IDENTITY_LEN = 10000
};

typedef struct mtls_peer_identity {
    char common_name[MTLS_MAX_COMMON_NAME_LEN];
    char **sans; /* Subject Alternative Names */
    size_t san_count;
    char spiffe_id[MTLS_MAX_SPIFFE_ID_LEN];
    time_t cert_not_before;
    time_t cert_not_after;
} mtls_peer_identity;

/*
 * Event structure for observability callbacks
 *
 * IMPORTANT: All pointers in this structure (remote_addr, conn) are only
 * valid for the duration of the callback. Do NOT store these pointers
 * for later use - copy the data if persistence is needed. The remote_addr
 * string is allocated on the stack and will be invalid after the callback
 * returns.
 */
typedef struct mtls_event {
    mtls_event_type type;
    const char *remote_addr; /* Remote address - valid only during callback */
    mtls_conn *conn;         /* Connection handle (if applicable) */
    int error_code;          /* Error code (if applicable) */
    uint64_t timestamp_us;   /* Microseconds since epoch */
    uint64_t duration_us;    /* Duration in microseconds (for completed ops) */
    size_t bytes;            /* Bytes transferred (for I/O events) */
} mtls_event;

/*
 * Callback function types
 */
typedef void (*mtls_event_callback)(const mtls_event *event, void *userdata);

/*
 * Observer configuration
 */
typedef struct mtls_observers {
    mtls_event_callback on_event;
    void *userdata;
} mtls_observers;

/*
 * Default timeout values (milliseconds)
 */
enum {
    MTLS_DEFAULT_CONNECT_TIMEOUT_MS = 30000, /* 30 seconds */
    MTLS_DEFAULT_READ_TIMEOUT_MS = 60000,    /* 60 seconds */
    MTLS_DEFAULT_WRITE_TIMEOUT_MS = 60000    /* 60 seconds */
};

/*
 * Buffer size limits
 */
enum {
    MTLS_MAX_READ_BUFFER_SIZE = 16 * 1024, /* 16 KB */
    MTLS_MAX_WRITE_BUFFER_SIZE = 16 * 1024 /* 16 KB */
};

#ifdef __cplusplus
}
#endif

#endif /* MTLS_TYPES_H */
