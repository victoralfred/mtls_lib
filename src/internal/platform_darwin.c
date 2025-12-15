/**
 * @file platform_darwin.c
 * @brief macOS-specific platform implementation
 */

#define _POSIX_C_SOURCE 200809L

#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>

int platform_init(void) {
    /* No initialization needed on Linux */
    return 0;
}

void platform_cleanup(void) {
    /* No cleanup needed on Linux */
}

mtls_socket_t platform_socket_create(int domain, int type, int protocol, mtls_err* err) {
    mtls_socket_t sock = socket(domain, type, protocol);
    if (sock == MTLS_INVALID_SOCKET) {
        MTLS_ERR_SET(err, MTLS_ERR_SOCKET_CREATE_FAILED,
                     "Failed to create socket: %s", strerror(errno));
        if (err) err->os_errno = errno;
    }
    return sock;
}

void platform_socket_close(mtls_socket_t sock) {
    if (sock != MTLS_INVALID_SOCKET) {
        close(sock);
    }
}

int platform_socket_set_nonblocking(mtls_socket_t sock, bool nonblocking, mtls_err* err) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to get socket flags: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    if (nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    if (fcntl(sock, F_SETFL, flags) == -1) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set socket flags: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

int platform_socket_set_recv_timeout(mtls_socket_t sock, uint32_t timeout_ms, mtls_err* err) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set recv timeout: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

int platform_socket_set_send_timeout(mtls_socket_t sock, uint32_t timeout_ms, mtls_err* err) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set send timeout: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

int platform_socket_set_reuseaddr(mtls_socket_t sock, bool enable, mtls_err* err) {
    int opt = enable ? 1 : 0;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set SO_REUSEADDR: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

int platform_socket_bind(mtls_socket_t sock, const mtls_addr* addr, mtls_err* err) {
    if (bind(sock, &addr->addr.sa, addr->len) < 0) {
        MTLS_ERR_SET(err, platform_socket_error_to_mtls(errno),
                     "Failed to bind socket: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

int platform_socket_listen(mtls_socket_t sock, int backlog, mtls_err* err) {
    if (listen(sock, backlog) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_SOCKET_LISTEN_FAILED,
                     "Failed to listen on socket: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

mtls_socket_t platform_socket_accept(mtls_socket_t sock, mtls_addr* addr, mtls_err* err) {
    addr->len = sizeof(addr->addr.ss);
    mtls_socket_t client = accept(sock, &addr->addr.sa, &addr->len);

    if (client == MTLS_INVALID_SOCKET) {
        MTLS_ERR_SET(err, MTLS_ERR_ACCEPT_FAILED,
                     "Failed to accept connection: %s", strerror(errno));
        if (err) err->os_errno = errno;
    }

    return client;
}

int platform_socket_connect(mtls_socket_t sock, const mtls_addr* addr,
                            uint32_t timeout_ms, mtls_err* err) {
    int ret;

    if (timeout_ms > 0) {
        /* Set non-blocking for timeout */
        if (platform_socket_set_nonblocking(sock, true, err) < 0) {
            return -1;
        }

        ret = connect(sock, &addr->addr.sa, addr->len);

        if (ret < 0 && errno != EINPROGRESS) {
            MTLS_ERR_SET(err, platform_socket_error_to_mtls(errno),
                         "Connect failed: %s", strerror(errno));
            if (err) err->os_errno = errno;
            return -1;
        }

        if (ret < 0) {
            /* Use select to wait for connection with timeout */
            fd_set write_fds;
            struct timeval tv;

            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            ret = select(sock + 1, NULL, &write_fds, NULL, &tv);

            if (ret == 0) {
                MTLS_ERR_SET(err, MTLS_ERR_CONNECT_TIMEOUT, "Connection timed out");
                return -1;
            } else if (ret < 0) {
                MTLS_ERR_SET(err, MTLS_ERR_CONNECT_FAILED,
                             "Select failed: %s", strerror(errno));
                if (err) err->os_errno = errno;
                return -1;
            }

            /* Check for connection error */
            int sock_err = 0;
            socklen_t len = sizeof(sock_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_err, &len) < 0) {
                MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                             "getsockopt failed: %s", strerror(errno));
                if (err) err->os_errno = errno;
                return -1;
            }

            if (sock_err != 0) {
                MTLS_ERR_SET(err, platform_socket_error_to_mtls(sock_err),
                             "Connection failed: %s", strerror(sock_err));
                if (err) err->os_errno = sock_err;
                return -1;
            }
        }

        /* Set back to blocking */
        platform_socket_set_nonblocking(sock, false, NULL);
    } else {
        /* Blocking connect */
        ret = connect(sock, &addr->addr.sa, addr->len);
        if (ret < 0) {
            MTLS_ERR_SET(err, platform_socket_error_to_mtls(errno),
                         "Connect failed: %s", strerror(errno));
            if (err) err->os_errno = errno;
            return -1;
        }
    }

    return 0;
}

ssize_t platform_socket_read(mtls_socket_t sock, void* buf, size_t len, mtls_err* err) {
    ssize_t n = read(sock, buf, len);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            MTLS_ERR_SET(err, MTLS_ERR_READ_TIMEOUT, "Read timed out");
        } else {
            MTLS_ERR_SET(err, MTLS_ERR_READ_FAILED,
                         "Read failed: %s", strerror(errno));
        }
        if (err) err->os_errno = errno;
    }

    return n;
}

ssize_t platform_socket_write(mtls_socket_t sock, const void* buf, size_t len, mtls_err* err) {
    ssize_t n = write(sock, buf, len);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            MTLS_ERR_SET(err, MTLS_ERR_WRITE_TIMEOUT, "Write timed out");
        } else {
            MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED,
                         "Write failed: %s", strerror(errno));
        }
        if (err) err->os_errno = errno;
    }

    return n;
}

int platform_socket_shutdown(mtls_socket_t sock, int how, mtls_err* err) {
    if (shutdown(sock, how) < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Shutdown failed: %s", strerror(errno));
        if (err) err->os_errno = errno;
        return -1;
    }

    return 0;
}

int platform_parse_addr(const char* addr_str, mtls_addr* addr, mtls_err* err) {
    if (!addr_str || !addr) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    /* Validate input length to prevent DoS */
    size_t addr_str_len = strlen(addr_str);
    if (addr_str_len == 0 || addr_str_len > 512) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Address string too long");
        return -1;
    }

    char host[256];
    char port[16];
    const char* colon;

    /* Handle IPv6 addresses [::1]:port */
    if (addr_str[0] == '[') {
        const char* bracket = strchr(addr_str, ']');
        if (!bracket) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS,
                         "Invalid IPv6 address format");
            return -1;
        }

        size_t host_len = bracket - addr_str - 1;
        if (host_len >= sizeof(host)) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Hostname too long");
            return -1;
        }

        memcpy(host, addr_str + 1, host_len);
        host[host_len] = '\0';

        colon = bracket + 1;
        if (*colon == ':') {
            size_t port_len = strlen(colon + 1);
            size_t copy_len = (port_len < sizeof(port) - 1) ? port_len : sizeof(port) - 1;
            memcpy(port, colon + 1, copy_len);
            port[copy_len] = '\0';  /* Ensure null termination */
        } else {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS,
                         "Missing port in address");
            return -1;
        }
    } else {
        /* IPv4 or hostname */
        colon = strrchr(addr_str, ':');
        if (!colon) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS,
                         "Missing port in address");
            return -1;
        }

        size_t host_len = colon - addr_str;
        if (host_len >= sizeof(host)) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Hostname too long");
            return -1;
        }

        memcpy(host, addr_str, host_len);
        host[host_len] = '\0';

        size_t port_len = strlen(colon + 1);
        size_t copy_len = (port_len < sizeof(port) - 1) ? port_len : sizeof(port) - 1;
        memcpy(port, colon + 1, copy_len);
        port[copy_len] = '\0';  /* Ensure null termination */
    }

    /* Validate port number */
    char* port_end;
    unsigned long port_num = strtoul(port, &port_end, 10);
    if (*port_end != '\0' || port_num == 0 || port_num > 65535) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Invalid port number");
        return -1;
    }

    /* Resolve address */
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_DNS_FAILED,
                     "DNS resolution failed: %s", gai_strerror(ret));
        return -1;
    }

    /* Use first result */
    memcpy(&addr->addr, result->ai_addr, result->ai_addrlen);
    addr->len = result->ai_addrlen;

    freeaddrinfo(result);
    return 0;
}

int platform_format_addr(const mtls_addr* addr, char* buf, size_t buf_len) {
    char host[INET6_ADDRSTRLEN];
    uint16_t port;

    if (addr->addr.sa.sa_family == AF_INET) {
        inet_ntop(AF_INET, &addr->addr.sin.sin_addr, host, sizeof(host));
        port = ntohs(addr->addr.sin.sin_port);
        snprintf(buf, buf_len, "%s:%u", host, port);
    } else if (addr->addr.sa.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &addr->addr.sin6.sin6_addr, host, sizeof(host));
        port = ntohs(addr->addr.sin6.sin6_port);
        snprintf(buf, buf_len, "[%s]:%u", host, port);
    } else {
        return -1;
    }

    return 0;
}

int platform_get_socket_error(void) {
    return errno;
}

mtls_error_code platform_socket_error_to_mtls(int socket_err) {
    switch (socket_err) {
        case ECONNREFUSED:
            return MTLS_ERR_CONNECTION_REFUSED;
        case ENETUNREACH:
            return MTLS_ERR_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:
            return MTLS_ERR_HOST_UNREACHABLE;
        case EADDRINUSE:
            return MTLS_ERR_ADDRESS_IN_USE;
        case ETIMEDOUT:
            return MTLS_ERR_CONNECT_TIMEOUT;
        case ECONNRESET:
            return MTLS_ERR_CONNECTION_RESET;
        default:
            return MTLS_ERR_CONNECT_FAILED;
    }
}

uint64_t platform_get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

void platform_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;

    /* Use explicit_bzero if available, otherwise volatile */
#ifdef __GLIBC__
    explicit_bzero(ptr, len);
#else
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

int platform_consttime_memcmp(const void* a, const void* b, size_t len) {
    if (!a || !b) {
        /* If either pointer is NULL, fall back to regular comparison */
        return (a == b) ? 0 : 1;
    }

    const volatile unsigned char* pa = (const volatile unsigned char*)a;
    const volatile unsigned char* pb = (const volatile unsigned char*)b;
    unsigned char diff = 0;

    /* XOR all bytes and accumulate differences */
    for (size_t i = 0; i < len; i++) {
        diff |= (pa[i] ^ pb[i]);
    }

    /* Return 0 if all bytes were equal, non-zero otherwise */
    return diff;
}

int platform_consttime_strcmp(const char* a, const char* b) {
    if (!a || !b) {
        /* If either pointer is NULL, fall back to pointer comparison */
        return (a == b) ? 0 : 1;
    }

    /* Enforce hard upper bound on identity length.
     * Identities exceeding MTLS_MAX_IDENTITY_LEN are rejected
     * to prevent resource exhaustion and comparison bypasses.
     * Return -1 to signal error (caller must check for MTLS_ERR_IDENTITY_TOO_LONG) */
    size_t len_a = strnlen(a, MTLS_MAX_IDENTITY_LEN + 1);
    size_t len_b = strnlen(b, MTLS_MAX_IDENTITY_LEN + 1);

    if (len_a > MTLS_MAX_IDENTITY_LEN || len_b > MTLS_MAX_IDENTITY_LEN) {
        /* Error: string exceeds maximum allowed length */
        return -1;
    }

    const volatile unsigned char* pa = (const volatile unsigned char*)a;
    const volatile unsigned char* pb = (const volatile unsigned char*)b;
    unsigned char diff = 0;
    size_t i = 0;

    /* Compare characters until we reach the end of both strings.
     * We've already verified lengths are within bounds, so this is safe. */
    while (1) {
        unsigned char ca = pa[i];
        unsigned char cb = pb[i];

        /* XOR the characters to accumulate differences */
        diff |= (ca ^ cb);

        /* If both strings have ended, break */
        if (ca == 0 && cb == 0) {
            break;
        }

        /* If only one string has ended, the diff will already be non-zero,
         * but we continue to avoid timing leaks about string length */
        i++;
    }

    return diff;
}
