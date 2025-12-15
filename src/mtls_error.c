/**
 * @file mtls_error.c
 * @brief Error handling implementation
 */

#include "mtls/mtls_error.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void mtls_err_init(mtls_err* err) {
    if (!err) return;

    memset(err, 0, sizeof(*err));
    err->code = MTLS_OK;
}

void mtls_err_clear(mtls_err* err) {
    mtls_err_init(err);
}

void mtls_err_set(mtls_err* err, mtls_error_code code, const char* fmt, ...) {
    if (!err) return;

    err->code = code;
    err->file = NULL;
    err->line = 0;

    if (fmt) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(err->message, MTLS_ERR_MESSAGE_SIZE, fmt, args);
        va_end(args);
        err->message[MTLS_ERR_MESSAGE_SIZE - 1] = '\0';  /* Ensure null termination */
    } else {
        const char* code_name = mtls_err_code_name(code);
        size_t code_len = strlen(code_name);
        size_t copy_len = (code_len < MTLS_ERR_MESSAGE_SIZE - 1) ? code_len : MTLS_ERR_MESSAGE_SIZE - 1;
        memcpy(err->message, code_name, copy_len);
        err->message[copy_len] = '\0';  /* Ensure null termination */
    }
}

void mtls_err_set_internal(mtls_err* err, mtls_error_code code,
                           const char* file, int line,
                           const char* fmt, ...) {
    if (!err) return;

    err->code = code;
    err->file = file;
    err->line = line;

    if (fmt) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(err->message, MTLS_ERR_MESSAGE_SIZE, fmt, args);
        va_end(args);
        err->message[MTLS_ERR_MESSAGE_SIZE - 1] = '\0';  /* Ensure null termination */
    } else {
        const char* code_name = mtls_err_code_name(code);
        size_t code_len = strlen(code_name);
        size_t copy_len = (code_len < MTLS_ERR_MESSAGE_SIZE - 1) ? code_len : MTLS_ERR_MESSAGE_SIZE - 1;
        memcpy(err->message, code_name, copy_len);
        err->message[copy_len] = '\0';  /* Ensure null termination */
    }
}

const char* mtls_err_code_name(mtls_error_code code) {
    switch (code) {
        case MTLS_OK: return "MTLS_OK";

        /* Configuration errors */
        case MTLS_ERR_INVALID_CONFIG: return "MTLS_ERR_INVALID_CONFIG";
        case MTLS_ERR_INVALID_ARGUMENT: return "MTLS_ERR_INVALID_ARGUMENT";
        case MTLS_ERR_CA_CERT_NOT_FOUND: return "MTLS_ERR_CA_CERT_NOT_FOUND";
        case MTLS_ERR_CERT_NOT_FOUND: return "MTLS_ERR_CERT_NOT_FOUND";
        case MTLS_ERR_KEY_NOT_FOUND: return "MTLS_ERR_KEY_NOT_FOUND";
        case MTLS_ERR_CA_CERT_PARSE_FAILED: return "MTLS_ERR_CA_CERT_PARSE_FAILED";
        case MTLS_ERR_CERT_PARSE_FAILED: return "MTLS_ERR_CERT_PARSE_FAILED";
        case MTLS_ERR_KEY_PARSE_FAILED: return "MTLS_ERR_KEY_PARSE_FAILED";
        case MTLS_ERR_CERT_KEY_MISMATCH: return "MTLS_ERR_CERT_KEY_MISMATCH";
        case MTLS_ERR_OUT_OF_MEMORY: return "MTLS_ERR_OUT_OF_MEMORY";
        case MTLS_ERR_CTX_NOT_INITIALIZED: return "MTLS_ERR_CTX_NOT_INITIALIZED";

        /* Connection errors */
        case MTLS_ERR_CONNECT_FAILED: return "MTLS_ERR_CONNECT_FAILED";
        case MTLS_ERR_CONNECT_TIMEOUT: return "MTLS_ERR_CONNECT_TIMEOUT";
        case MTLS_ERR_DNS_FAILED: return "MTLS_ERR_DNS_FAILED";
        case MTLS_ERR_SOCKET_CREATE_FAILED: return "MTLS_ERR_SOCKET_CREATE_FAILED";
        case MTLS_ERR_SOCKET_BIND_FAILED: return "MTLS_ERR_SOCKET_BIND_FAILED";
        case MTLS_ERR_SOCKET_LISTEN_FAILED: return "MTLS_ERR_SOCKET_LISTEN_FAILED";
        case MTLS_ERR_ACCEPT_FAILED: return "MTLS_ERR_ACCEPT_FAILED";
        case MTLS_ERR_CONNECTION_REFUSED: return "MTLS_ERR_CONNECTION_REFUSED";
        case MTLS_ERR_NETWORK_UNREACHABLE: return "MTLS_ERR_NETWORK_UNREACHABLE";
        case MTLS_ERR_HOST_UNREACHABLE: return "MTLS_ERR_HOST_UNREACHABLE";
        case MTLS_ERR_ADDRESS_IN_USE: return "MTLS_ERR_ADDRESS_IN_USE";
        case MTLS_ERR_INVALID_ADDRESS: return "MTLS_ERR_INVALID_ADDRESS";

        /* TLS errors */
        case MTLS_ERR_TLS_INIT_FAILED: return "MTLS_ERR_TLS_INIT_FAILED";
        case MTLS_ERR_TLS_HANDSHAKE_FAILED: return "MTLS_ERR_TLS_HANDSHAKE_FAILED";
        case MTLS_ERR_TLS_VERSION_MISMATCH: return "MTLS_ERR_TLS_VERSION_MISMATCH";
        case MTLS_ERR_TLS_CIPHER_MISMATCH: return "MTLS_ERR_TLS_CIPHER_MISMATCH";
        case MTLS_ERR_CERT_EXPIRED: return "MTLS_ERR_CERT_EXPIRED";
        case MTLS_ERR_CERT_NOT_YET_VALID: return "MTLS_ERR_CERT_NOT_YET_VALID";
        case MTLS_ERR_CERT_REVOKED: return "MTLS_ERR_CERT_REVOKED";
        case MTLS_ERR_CERT_UNTRUSTED: return "MTLS_ERR_CERT_UNTRUSTED";
        case MTLS_ERR_CERT_CHAIN_TOO_LONG: return "MTLS_ERR_CERT_CHAIN_TOO_LONG";
        case MTLS_ERR_CERT_SIGNATURE_INVALID: return "MTLS_ERR_CERT_SIGNATURE_INVALID";
        case MTLS_ERR_NO_PEER_CERT: return "MTLS_ERR_NO_PEER_CERT";
        case MTLS_ERR_HOSTNAME_MISMATCH: return "MTLS_ERR_HOSTNAME_MISMATCH";
        case MTLS_ERR_TLS_SHUTDOWN_FAILED: return "MTLS_ERR_TLS_SHUTDOWN_FAILED";

        /* Identity errors */
        case MTLS_ERR_IDENTITY_MISMATCH: return "MTLS_ERR_IDENTITY_MISMATCH";
        case MTLS_ERR_SAN_NOT_ALLOWED: return "MTLS_ERR_SAN_NOT_ALLOWED";
        case MTLS_ERR_SPIFFE_PARSE_FAILED: return "MTLS_ERR_SPIFFE_PARSE_FAILED";
        case MTLS_ERR_CN_NOT_ALLOWED: return "MTLS_ERR_CN_NOT_ALLOWED";
        case MTLS_ERR_NO_ALLOWED_IDENTITY: return "MTLS_ERR_NO_ALLOWED_IDENTITY";
        case MTLS_ERR_IDENTITY_TOO_LONG: return "MTLS_ERR_IDENTITY_TOO_LONG";

        /* Policy errors */
        case MTLS_ERR_KILL_SWITCH_ENABLED: return "MTLS_ERR_KILL_SWITCH_ENABLED";
        case MTLS_ERR_POLICY_DENIED: return "MTLS_ERR_POLICY_DENIED";
        case MTLS_ERR_CONNECTION_NOT_ALLOWED: return "MTLS_ERR_CONNECTION_NOT_ALLOWED";

        /* I/O errors */
        case MTLS_ERR_READ_FAILED: return "MTLS_ERR_READ_FAILED";
        case MTLS_ERR_WRITE_FAILED: return "MTLS_ERR_WRITE_FAILED";
        case MTLS_ERR_CONNECTION_CLOSED: return "MTLS_ERR_CONNECTION_CLOSED";
        case MTLS_ERR_CONNECTION_RESET: return "MTLS_ERR_CONNECTION_RESET";
        case MTLS_ERR_READ_TIMEOUT: return "MTLS_ERR_READ_TIMEOUT";
        case MTLS_ERR_WRITE_TIMEOUT: return "MTLS_ERR_WRITE_TIMEOUT";
        case MTLS_ERR_WOULD_BLOCK: return "MTLS_ERR_WOULD_BLOCK";
        case MTLS_ERR_PARTIAL_WRITE: return "MTLS_ERR_PARTIAL_WRITE";
        case MTLS_ERR_EOF: return "MTLS_ERR_EOF";

        /* Internal errors */
        case MTLS_ERR_INTERNAL: return "MTLS_ERR_INTERNAL";
        case MTLS_ERR_NOT_IMPLEMENTED: return "MTLS_ERR_NOT_IMPLEMENTED";
        case MTLS_ERR_UNKNOWN: return "MTLS_ERR_UNKNOWN";

        default: return "MTLS_ERR_UNKNOWN";
    }
}

const char* mtls_err_category_name(mtls_error_code code) {
    if (code == MTLS_OK) return "Success";
    if (mtls_err_is_config(code)) return "Configuration";
    if (mtls_err_is_network(code)) return "Network";
    if (mtls_err_is_tls(code)) return "TLS/Certificate";
    if (mtls_err_is_identity(code)) return "Identity";
    if (mtls_err_is_policy(code)) return "Policy";
    if (mtls_err_is_io(code)) return "I/O";
    return "Internal";
}

int mtls_err_format(const mtls_err* err, char* buf, size_t buf_size) {
    if (!err || !buf || buf_size == 0) {
        return -1;
    }

    int written = 0;

    /* Format: [Category] ERROR_CODE: message */
    written = snprintf(buf, buf_size, "[%s] %s: %s",
                      mtls_err_category_name(err->code),
                      mtls_err_code_name(err->code),
                      err->message[0] ? err->message : "No details");

    /* Add OS errno if present */
    if (err->os_errno != 0 && written > 0 && (size_t)written < buf_size) {
        written += snprintf(buf + written, buf_size - written,
                           " (errno=%d)", err->os_errno);
    }

    /* Add SSL error if present */
    if (err->ssl_err != 0 && written > 0 && (size_t)written < buf_size) {
        written += snprintf(buf + written, buf_size - written,
                           " (ssl_err=0x%lx)", err->ssl_err);
    }

    /* Add file/line in debug builds */
#ifdef MTLS_DEBUG
    if (err->file && written > 0 && (size_t)written < buf_size) {
        written += snprintf(buf + written, buf_size - written,
                           " at %s:%d", err->file, err->line);
    }
#endif

    return written;
}
