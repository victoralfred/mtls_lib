/**
 * @file mtls_error.h
 * @brief Error handling for the mTLS library
 *
 * This header defines error codes and error handling structures.
 * Error codes are categorized by type for easier debugging and handling.
 */

#ifndef MTLS_ERROR_H
#define MTLS_ERROR_H

#include "mtls_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Error code categories:
 *   0       = Success
 *   1xx     = Configuration errors
 *   2xx     = Connection/network errors
 *   3xx     = TLS/certificate errors
 *   4xx     = Identity/policy errors
 *   5xx     = Policy/kill-switch errors
 *   6xx     = I/O errors
 *   9xx     = Internal/unknown errors
 */
typedef enum mtls_error_code {
    /* Success */
    MTLS_OK = 0,

    /* Configuration errors (1xx) */
    MTLS_ERR_INVALID_CONFIG = 100,
    MTLS_ERR_INVALID_ARGUMENT = 101,
    MTLS_ERR_CA_CERT_NOT_FOUND = 102,
    MTLS_ERR_CERT_NOT_FOUND = 103,
    MTLS_ERR_KEY_NOT_FOUND = 104,
    MTLS_ERR_CA_CERT_PARSE_FAILED = 105,
    MTLS_ERR_CERT_PARSE_FAILED = 106,
    MTLS_ERR_KEY_PARSE_FAILED = 107,
    MTLS_ERR_CERT_KEY_MISMATCH = 108,
    MTLS_ERR_OUT_OF_MEMORY = 109,
    MTLS_ERR_CTX_NOT_INITIALIZED = 110,

    /* Connection/network errors (2xx) */
    MTLS_ERR_CONNECT_FAILED = 200,
    MTLS_ERR_CONNECT_TIMEOUT = 201,
    MTLS_ERR_DNS_FAILED = 202,
    MTLS_ERR_SOCKET_CREATE_FAILED = 203,
    MTLS_ERR_SOCKET_BIND_FAILED = 204,
    MTLS_ERR_SOCKET_LISTEN_FAILED = 205,
    MTLS_ERR_ACCEPT_FAILED = 206,
    MTLS_ERR_CONNECTION_REFUSED = 207,
    MTLS_ERR_NETWORK_UNREACHABLE = 208,
    MTLS_ERR_HOST_UNREACHABLE = 209,
    MTLS_ERR_ADDRESS_IN_USE = 210,
    MTLS_ERR_INVALID_ADDRESS = 211,

    /* TLS/certificate errors (3xx) */
    MTLS_ERR_TLS_INIT_FAILED = 300,
    MTLS_ERR_TLS_HANDSHAKE_FAILED = 301,
    MTLS_ERR_TLS_VERSION_MISMATCH = 302,
    MTLS_ERR_TLS_CIPHER_MISMATCH = 303,
    MTLS_ERR_CERT_EXPIRED = 304,
    MTLS_ERR_CERT_NOT_YET_VALID = 305,
    MTLS_ERR_CERT_REVOKED = 306,
    MTLS_ERR_CERT_UNTRUSTED = 307,
    MTLS_ERR_CERT_CHAIN_TOO_LONG = 308,
    MTLS_ERR_CERT_SIGNATURE_INVALID = 309,
    MTLS_ERR_NO_PEER_CERT = 310,
    MTLS_ERR_HOSTNAME_MISMATCH = 311,
    MTLS_ERR_TLS_SHUTDOWN_FAILED = 312,

    /* Identity/verification errors (4xx) */
    MTLS_ERR_IDENTITY_MISMATCH = 400,
    MTLS_ERR_SAN_NOT_ALLOWED = 401,
    MTLS_ERR_SPIFFE_PARSE_FAILED = 402,
    MTLS_ERR_CN_NOT_ALLOWED = 403,
    MTLS_ERR_NO_ALLOWED_IDENTITY = 404,

    /* Policy errors (5xx) */
    MTLS_ERR_KILL_SWITCH_ENABLED = 500,
    MTLS_ERR_POLICY_DENIED = 501,
    MTLS_ERR_CONNECTION_NOT_ALLOWED = 502,

    /* I/O errors (6xx) */
    MTLS_ERR_READ_FAILED = 600,
    MTLS_ERR_WRITE_FAILED = 601,
    MTLS_ERR_CONNECTION_CLOSED = 602,
    MTLS_ERR_CONNECTION_RESET = 603,
    MTLS_ERR_READ_TIMEOUT = 604,
    MTLS_ERR_WRITE_TIMEOUT = 605,
    MTLS_ERR_WOULD_BLOCK = 606,
    MTLS_ERR_PARTIAL_WRITE = 607,
    MTLS_ERR_EOF = 608,

    /* Internal/unknown errors (9xx) */
    MTLS_ERR_INTERNAL = 900,
    MTLS_ERR_NOT_IMPLEMENTED = 901,
    MTLS_ERR_UNKNOWN = 999
} mtls_error_code;

/*
 * Error message buffer size
 */
#define MTLS_ERR_MESSAGE_SIZE 256

/*
 * Error structure with context
 */
typedef struct mtls_err {
    mtls_error_code code;           /* Primary error code */
    char message[MTLS_ERR_MESSAGE_SIZE];  /* Human-readable message */
    int os_errno;                   /* OS error code (errno) */
    unsigned long ssl_err;          /* SSL library error code */
    const char* file;               /* Source file (debug) */
    int line;                       /* Source line (debug) */
} mtls_err;

/*
 * Initialize an error structure
 */
MTLS_API void mtls_err_init(mtls_err* err);

/*
 * Clear an error structure
 */
MTLS_API void mtls_err_clear(mtls_err* err);

/*
 * Set error with formatted message
 */
MTLS_API void mtls_err_set(mtls_err* err, mtls_error_code code, const char* fmt, ...);

/*
 * Set error with file/line information (internal use)
 */
MTLS_API void mtls_err_set_internal(mtls_err* err, mtls_error_code code,
                                     const char* file, int line,
                                     const char* fmt, ...);

/*
 * Get human-readable error code name
 */
MTLS_API const char* mtls_err_code_name(mtls_error_code code);

/*
 * Get human-readable error category name
 */
MTLS_API const char* mtls_err_category_name(mtls_error_code code);

/*
 * Format error to string buffer
 */
MTLS_API int mtls_err_format(const mtls_err* err, char* buf, size_t buf_size);

/*
 * Check if error is a specific category
 */
static inline bool mtls_err_is_config(mtls_error_code code) {
    return code >= 100 && code < 200;
}

static inline bool mtls_err_is_network(mtls_error_code code) {
    return code >= 200 && code < 300;
}

static inline bool mtls_err_is_tls(mtls_error_code code) {
    return code >= 300 && code < 400;
}

static inline bool mtls_err_is_identity(mtls_error_code code) {
    return code >= 400 && code < 500;
}

static inline bool mtls_err_is_policy(mtls_error_code code) {
    return code >= 500 && code < 600;
}

static inline bool mtls_err_is_io(mtls_error_code code) {
    return code >= 600 && code < 700;
}

static inline bool mtls_err_is_recoverable(mtls_error_code code) {
    /* Timeouts and would-block are recoverable */
    return code == MTLS_ERR_CONNECT_TIMEOUT ||
           code == MTLS_ERR_READ_TIMEOUT ||
           code == MTLS_ERR_WRITE_TIMEOUT ||
           code == MTLS_ERR_WOULD_BLOCK;
}

/*
 * Macro for setting errors with file/line info
 */
#define MTLS_ERR_SET(err, code, ...) \
    mtls_err_set_internal((err), (code), __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* MTLS_ERROR_H */
