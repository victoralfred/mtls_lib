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
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * API visibility macros
 *
 * For Windows: Only use dllexport/dllimport for shared libraries (DLLs)
 * For static libraries, no decoration is needed
 */
#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(MTLS_SHARED_LIB)
        /* Building or using a DLL */
        #ifdef MTLS_BUILDING_LIB
            #define MTLS_API __declspec(dllexport)
        #else
            #define MTLS_API __declspec(dllimport)
        #endif
    #else
        /* Static library - no special decoration needed */
        #define MTLS_API
    #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define MTLS_API __attribute__((visibility("default")))
#else
    #define MTLS_API
#endif

/*
 * Version information
 * Provided as both macros (for preprocessor use) and enum (for type safety)
 */
enum {
    MTLS_VERSION_MAJOR = 0,
    MTLS_VERSION_MINOR = 1,
    MTLS_VERSION_PATCH = 0
};

#define MTLS_VERSION_STRING "0.1.0"

/*
 * TLS version constants
 */
typedef enum mtls_tls_version {
    MTLS_TLS_1_2 = 0x0303,  /* TLS 1.2 */
    MTLS_TLS_1_3 = 0x0304   /* TLS 1.3 */
} mtls_tls_version;

/*
 * Connection state
 */
typedef enum mtls_conn_state {
    MTLS_CONN_STATE_NONE = 0,       /* Not initialized */
    MTLS_CONN_STATE_CONNECTING,     /* TCP connection in progress */
    MTLS_CONN_STATE_HANDSHAKING,    /* TLS handshake in progress */
    MTLS_CONN_STATE_ESTABLISHED,    /* Connected and verified */
    MTLS_CONN_STATE_CLOSING,        /* Shutdown in progress */
    MTLS_CONN_STATE_CLOSED,         /* Connection closed */
    MTLS_CONN_STATE_ERROR           /* Error state */
} mtls_conn_state;

/*
 * Event types for observability
 */
typedef enum mtls_event_type {
    MTLS_EVENT_CONNECT_START = 1,
    MTLS_EVENT_CONNECT_SUCCESS,
    MTLS_EVENT_CONNECT_FAILURE,
    MTLS_EVENT_HANDSHAKE_START,
    MTLS_EVENT_HANDSHAKE_SUCCESS,
    MTLS_EVENT_HANDSHAKE_FAILURE,
    MTLS_EVENT_READ,
    MTLS_EVENT_WRITE,
    MTLS_EVENT_CLOSE,
    MTLS_EVENT_KILL_SWITCH_TRIGGERED
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
    char** sans;                    /* Subject Alternative Names */
    size_t san_count;
    char spiffe_id[MTLS_MAX_SPIFFE_ID_LEN];
    time_t cert_not_before;
    time_t cert_not_after;
} mtls_peer_identity;

/*
 * Event structure for observability callbacks
 */
typedef struct mtls_event {
    mtls_event_type type;
    const char* remote_addr;        /* Remote address (if applicable) */
    mtls_conn* conn;                /* Connection handle (if applicable) */
    int error_code;                 /* Error code (if applicable) */
    uint64_t timestamp_us;          /* Microseconds since epoch */
    uint64_t duration_us;           /* Duration in microseconds (for completed ops) */
    size_t bytes;                   /* Bytes transferred (for I/O events) */
} mtls_event;

/*
 * Callback function types
 */
typedef void (*mtls_event_callback)(const mtls_event* event, void* userdata);

/*
 * Observer configuration
 */
typedef struct mtls_observers {
    mtls_event_callback on_event;
    void* userdata;
} mtls_observers;

/*
 * Default timeout values (milliseconds)
 */
#define MTLS_DEFAULT_CONNECT_TIMEOUT_MS  30000  /* 30 seconds */
#define MTLS_DEFAULT_READ_TIMEOUT_MS     60000  /* 60 seconds */
#define MTLS_DEFAULT_WRITE_TIMEOUT_MS    60000  /* 60 seconds */

/*
 * Buffer size limits
 */
#define MTLS_MAX_READ_BUFFER_SIZE  (16 * 1024)  /* 16 KB */
#define MTLS_MAX_WRITE_BUFFER_SIZE (16 * 1024)  /* 16 KB */

#ifdef __cplusplus
}
#endif

#endif /* MTLS_TYPES_H */
