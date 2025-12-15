/**
 * @file platform.h
 * @brief Platform-specific socket and networking abstractions
 *
 * This header provides a consistent interface for socket operations across
 * Linux, macOS, and Windows platforms.
 */

#ifndef MTLS_PLATFORM_H
#define MTLS_PLATFORM_H

#include "mtls/mtls_types.h"
#include "mtls/mtls_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Platform-specific socket handle type
 */
#if defined(MTLS_PLATFORM_WINDOWS)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET mtls_socket_t;
    #define MTLS_INVALID_SOCKET INVALID_SOCKET
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    typedef int mtls_socket_t;
    #define MTLS_INVALID_SOCKET (-1)
#endif

/*
 * Address structure (platform-independent)
 */
typedef struct mtls_addr {
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_storage ss;
    } addr;
    socklen_t len;
} mtls_addr;

/*
 * Initialize platform networking (e.g., WSAStartup on Windows)
 */
int platform_init(void);

/*
 * Cleanup platform networking (e.g., WSACleanup on Windows)
 */
void platform_cleanup(void);

/*
 * Create a socket
 */
mtls_socket_t platform_socket_create(int domain, int type, int protocol, mtls_err* err);

/*
 * Close a socket
 */
void platform_socket_close(mtls_socket_t sock);

/*
 * Set socket to non-blocking mode
 */
int platform_socket_set_nonblocking(mtls_socket_t sock, bool nonblocking, mtls_err* err);

/*
 * Set socket timeout for read operations
 */
int platform_socket_set_recv_timeout(mtls_socket_t sock, uint32_t timeout_ms, mtls_err* err);

/*
 * Set socket timeout for write operations
 */
int platform_socket_set_send_timeout(mtls_socket_t sock, uint32_t timeout_ms, mtls_err* err);

/*
 * Set SO_REUSEADDR option
 */
int platform_socket_set_reuseaddr(mtls_socket_t sock, bool enable, mtls_err* err);

/*
 * Bind socket to address
 */
int platform_socket_bind(mtls_socket_t sock, const mtls_addr* addr, mtls_err* err);

/*
 * Listen on socket
 */
int platform_socket_listen(mtls_socket_t sock, int backlog, mtls_err* err);

/*
 * Accept incoming connection
 */
mtls_socket_t platform_socket_accept(mtls_socket_t sock, mtls_addr* addr, mtls_err* err);

/*
 * Connect to remote address
 */
int platform_socket_connect(mtls_socket_t sock, const mtls_addr* addr,
                            uint32_t timeout_ms, mtls_err* err);

/*
 * Read from socket
 */
ssize_t platform_socket_read(mtls_socket_t sock, void* buf, size_t len, mtls_err* err);

/*
 * Write to socket
 */
ssize_t platform_socket_write(mtls_socket_t sock, const void* buf, size_t len, mtls_err* err);

/*
 * Shutdown socket (for graceful close)
 */
int platform_socket_shutdown(mtls_socket_t sock, int how, mtls_err* err);

/*
 * Parse address string (e.g., "host:port" or "[::1]:8080")
 */
int platform_parse_addr(const char* addr_str, mtls_addr* addr, mtls_err* err);

/*
 * Format address to string
 */
int platform_format_addr(const mtls_addr* addr, char* buf, size_t buf_len);

/*
 * Get last socket error code
 */
int platform_get_socket_error(void);

/*
 * Convert socket error to mtls_error_code
 */
mtls_error_code platform_socket_error_to_mtls(int socket_err);

/*
 * Get monotonic time in microseconds (for timing/metrics)
 */
uint64_t platform_get_time_us(void);

/*
 * Secure memory zeroing (prevents compiler optimization)
 */
void platform_secure_zero(void* ptr, size_t len);

/*
 * Constant-time memory comparison (prevents timing attacks)
 *
 * Compares two memory regions in constant time, regardless of where
 * the first difference occurs. Use this for comparing secrets, hashes,
 * or other security-sensitive data.
 *
 * @param a First memory region
 * @param b Second memory region
 * @param len Length to compare
 * @return 0 if equal, non-zero if different
 */
int platform_consttime_memcmp(const void* a, const void* b, size_t len);

/*
 * Constant-time string comparison (prevents timing attacks)
 *
 * Compares two null-terminated strings in constant time. The comparison
 * continues through the full length of the longer string to avoid timing
 * leaks about string length or position of differences.
 *
 * @param a First string
 * @param b Second string
 * @return 0 if equal, non-zero if different
 */
int platform_consttime_strcmp(const char* a, const char* b);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_PLATFORM_H */
