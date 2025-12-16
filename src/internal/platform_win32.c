/**
 * @file platform_win32.c
 * @brief Windows-specific platform implementation
 */

#include "platform.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static WSADATA wsa_data;
static int wsa_initialized = 0;

int platform_init(void) {
    if (wsa_initialized) {
        return 0;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }

    wsa_initialized = 1;
    return 0;
}

void platform_cleanup(void) {
    if (wsa_initialized) {
        WSACleanup();
        wsa_initialized = 0;
    }
}

mtls_socket_t platform_socket_create(int domain, int type, int protocol, mtls_err* err) {
    mtls_socket_t sock = socket(domain, type, protocol);
    if (sock == MTLS_INVALID_SOCKET) {
        MTLS_ERR_SET(err, MTLS_ERR_SOCKET_CREATE_FAILED,
                     "Failed to create socket: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
    }
    return sock;
}

void platform_socket_close(mtls_socket_t sock) {
    if (sock != MTLS_INVALID_SOCKET) {
        closesocket(sock);
    }
}

int platform_socket_set_nonblocking(mtls_socket_t sock, bool nonblocking, mtls_err* err) {
    u_long mode = nonblocking ? 1 : 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set non-blocking mode: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
        return -1;
    }
    return 0;
}

int platform_socket_set_recv_timeout(mtls_socket_t sock, uint32_t timeout_ms, mtls_err* err) {
    (void)timeout_ms; /* Parameter used in timeout assignment */
    DWORD timeout = timeout_ms;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set recv timeout: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
        return -1;
    }
    return 0;
}

int platform_socket_set_send_timeout(mtls_socket_t sock, uint32_t timeout_ms, mtls_err* err) {
    (void)timeout_ms; /* Parameter used in timeout assignment */
    DWORD timeout = timeout_ms;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set send timeout: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
        return -1;
    }
    return 0;
}

int platform_socket_set_reuseaddr(mtls_socket_t sock, bool enable, mtls_err* err) {
    int opt = enable ? 1 : 0;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Failed to set SO_REUSEADDR: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
        return -1;
    }
    return 0;
}

int platform_socket_bind(mtls_socket_t sock, const mtls_addr* addr, mtls_err* err) {
    if (bind(sock, &addr->addr.sa, addr->len) != 0) {
        int wsa_err = WSAGetLastError();
        MTLS_ERR_SET(err, platform_socket_error_to_mtls(wsa_err),
                     "Failed to bind socket: %d", wsa_err);
        if (err) {
            err->os_errno = wsa_err;
        }
        return -1;
    }
    return 0;
}

int platform_socket_listen(mtls_socket_t sock, int backlog, mtls_err* err) {
    if (listen(sock, backlog) != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_SOCKET_LISTEN_FAILED,
                     "Failed to listen on socket: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
        return -1;
    }
    return 0;
}

mtls_socket_t platform_socket_accept(mtls_socket_t sock, mtls_addr* addr, mtls_err* err) {
    int len = sizeof(addr->addr.ss);
    mtls_socket_t client = accept(sock, &addr->addr.sa, &len);
    addr->len = len;

    if (client == MTLS_INVALID_SOCKET) {
        MTLS_ERR_SET(err, MTLS_ERR_ACCEPT_FAILED,
                     "Failed to accept connection: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
    }

    return client;
}

int platform_socket_connect(mtls_socket_t sock, const mtls_addr* addr,
                            uint32_t timeout_ms, mtls_err* err) {
    int ret = 0;

    if (timeout_ms > 0) {
        /* Set non-blocking for timeout */
        if (platform_socket_set_nonblocking(sock, true, err) < 0) {
            return -1;
        }

        ret = connect(sock, &addr->addr.sa, addr->len);

        if (ret == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            int wsa_err = WSAGetLastError();
            MTLS_ERR_SET(err, platform_socket_error_to_mtls(wsa_err),
                         "Connect failed: %d", wsa_err);
            if (err) {
                err->os_errno = wsa_err;
            }
            return -1;
        }

        if (ret == SOCKET_ERROR) {
            /* Use select to wait for connection with timeout */
            fd_set write_fds;
            struct timeval time_val;

            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            time_val.tv_sec = timeout_ms / 1000;
            time_val.tv_usec = (timeout_ms % 1000) * 1000;

            ret = select(0, NULL, &write_fds, NULL, &time_val);

            if (ret == 0) {
                MTLS_ERR_SET(err, MTLS_ERR_CONNECT_TIMEOUT, "Connection timed out");
                return -1;
            }
            if (ret == SOCKET_ERROR) {
                MTLS_ERR_SET(err, MTLS_ERR_CONNECT_FAILED,
                             "Select failed: %d", WSAGetLastError());
                if (err) {
                    err->os_errno = WSAGetLastError();
                }
                return -1;
            }

            /* Check for connection error */
            int sock_err = 0;
            int len = sizeof(sock_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&sock_err, &len) != 0) {
                MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                             "getsockopt failed: %d", WSAGetLastError());
                if (err) {
                    err->os_errno = WSAGetLastError();
                }
                return -1;
            }

            if (sock_err != 0) {
                MTLS_ERR_SET(err, platform_socket_error_to_mtls(sock_err),
                             "Connection failed: %d", sock_err);
                if (err) {
                    err->os_errno = sock_err;
                }
                return -1;
            }
        }

        /* Set back to blocking */
        platform_socket_set_nonblocking(sock, false, NULL);
    } else {
        /* Blocking connect */
        ret = connect(sock, &addr->addr.sa, addr->len);
        if (ret == SOCKET_ERROR) {
            int wsa_err = WSAGetLastError();
            MTLS_ERR_SET(err, platform_socket_error_to_mtls(wsa_err),
                     "Connect failed: %d", wsa_err);
            if (err) {
                err->os_errno = wsa_err;
            }
            return -1;
        }
    }

    return 0;
}

ssize_t platform_socket_read(mtls_socket_t sock, void* buf, size_t len, mtls_err* err) {
    int bytes_read = recv(sock, (char*)buf, (int)len, 0);

    if (bytes_read == SOCKET_ERROR) {
        int wsa_err = WSAGetLastError();
        if (wsa_err == WSAETIMEDOUT || wsa_err == WSAEWOULDBLOCK) {
            MTLS_ERR_SET(err, MTLS_ERR_READ_TIMEOUT, "Read timed out");
        } else {
            MTLS_ERR_SET(err, MTLS_ERR_READ_FAILED, "Read failed: %d", wsa_err);
        }
        if (err) {
            err->os_errno = wsa_err;
        }
        return -1;
    }

    return bytes_read;
}

ssize_t platform_socket_write(mtls_socket_t sock, const void* buf, size_t len, mtls_err* err) {
    int bytes_sent = send(sock, (const char*)buf, (int)len, 0);

    if (bytes_sent == SOCKET_ERROR) {
        int wsa_err = WSAGetLastError();
        if (wsa_err == WSAETIMEDOUT || wsa_err == WSAEWOULDBLOCK) {
            MTLS_ERR_SET(err, MTLS_ERR_WRITE_TIMEOUT, "Write timed out");
        } else {
            MTLS_ERR_SET(err, MTLS_ERR_WRITE_FAILED, "Write failed: %d", wsa_err);
        }
        if (err) {
            err->os_errno = wsa_err;
        }
        return -1;
    }

    return bytes_sent;
}

int platform_socket_shutdown(mtls_socket_t sock, int how, mtls_err* err) {
    if (shutdown(sock, how) == SOCKET_ERROR) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL,
                     "Shutdown failed: %d", WSAGetLastError());
        if (err) {
            err->os_errno = WSAGetLastError();
        }
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
    const char* colon = NULL;

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
            strncpy_s(port, sizeof(port), colon + 1, _TRUNCATE);
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

        strncpy_s(port, sizeof(port), colon + 1, _TRUNCATE);
    }

    /* Validate port number */
    char* port_end = NULL;
    unsigned long port_num = strtoul(port, &port_end, 10);
    if (*port_end != '\0' || port_num == 0 || port_num > 65535) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ADDRESS, "Invalid port number");
        return -1;
    }

    /* Resolve address */
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        MTLS_ERR_SET(err, MTLS_ERR_DNS_FAILED,
                     "DNS resolution failed: %d", ret);
        return -1;
    }

    /* Use first result */
    memcpy(&addr->addr, result->ai_addr, result->ai_addrlen);
    addr->len = (socklen_t)result->ai_addrlen;

    freeaddrinfo(result);
    return 0;
}

int platform_format_addr(const mtls_addr* addr, char* buf, size_t buf_len) {
    char host[INET6_ADDRSTRLEN];
    uint16_t port;

    if (addr->addr.sa.sa_family == AF_INET) {
        InetNtopA(AF_INET, &addr->addr.sin.sin_addr, host, sizeof(host));
        port = ntohs(addr->addr.sin.sin_port);
        _snprintf_s(buf, buf_len, _TRUNCATE, "%s:%u", host, port);
    } else if (addr->addr.sa.sa_family == AF_INET6) {
        InetNtopA(AF_INET6, &addr->addr.sin6.sin6_addr, host, sizeof(host));
        port = ntohs(addr->addr.sin6.sin6_port);
        _snprintf_s(buf, buf_len, _TRUNCATE, "[%s]:%u", host, port);
    } else {
        return -1;
    }

    return 0;
}

int platform_get_socket_error(void) {
    return WSAGetLastError();
}

mtls_error_code platform_socket_error_to_mtls(int socket_err) {
    switch (socket_err) {
        case WSAECONNREFUSED:
            return MTLS_ERR_CONNECTION_REFUSED;
        case WSAENETUNREACH:
            return MTLS_ERR_NETWORK_UNREACHABLE;
        case WSAEHOSTUNREACH:
            return MTLS_ERR_HOST_UNREACHABLE;
        case WSAEADDRINUSE:
            return MTLS_ERR_ADDRESS_IN_USE;
        case WSAETIMEDOUT:
            return MTLS_ERR_CONNECT_TIMEOUT;
        case WSAECONNRESET:
            return MTLS_ERR_CONNECTION_RESET;
        default:
            return MTLS_ERR_CONNECT_FAILED;
    }
}

uint64_t platform_get_time_us(void) {
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000ULL) / frequency.QuadPart);
}

void platform_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }
    SecureZeroMemory(ptr, len);
}

int platform_consttime_memcmp(const void* lhs, const void* rhs, size_t len) {
    if (!lhs || !rhs) {
        /* If either pointer is NULL, fall back to regular comparison */
        return (lhs == rhs) ? 0 : 1;
    }

    const volatile unsigned char* lhs_bytes = (const volatile unsigned char*)lhs;
    const volatile unsigned char* rhs_bytes = (const volatile unsigned char*)rhs;
    unsigned char diff = 0;

    /* XOR all bytes and accumulate differences */
    for (size_t i = 0; i < len; i++) {
        diff |= (lhs_bytes[i] ^ rhs_bytes[i]);
    }

    /* Return 0 if all bytes were equal, non-zero otherwise */
    return diff;
}

int platform_consttime_strcmp(const char* lhs, const char* rhs) {
    if (!lhs || !rhs) {
        /* If either pointer is NULL, fall back to pointer comparison */
        return (lhs == rhs) ? 0 : 1;
    }

    /* Enforce hard upper bound on identity length.
     * Identities exceeding MTLS_MAX_IDENTITY_LEN are rejected
     * to prevent resource exhaustion and comparison bypasses.
     * Return -1 to signal error (caller must check for MTLS_ERR_IDENTITY_TOO_LONG) */
    size_t len_lhs = strnlen(lhs, MTLS_MAX_IDENTITY_LEN + 1);
    size_t len_rhs = strnlen(rhs, MTLS_MAX_IDENTITY_LEN + 1);

    if (len_lhs > MTLS_MAX_IDENTITY_LEN || len_rhs > MTLS_MAX_IDENTITY_LEN) {
        /* Error: string exceeds maximum allowed length */
        return -1;
    }

    const volatile unsigned char* lhs_bytes = (const volatile unsigned char*)lhs;
    const volatile unsigned char* rhs_bytes = (const volatile unsigned char*)rhs;
    unsigned char diff = 0;

    /* Determine the maximum length we need to compare (including null terminator).
     * We iterate up to max_len+1 to compare the null terminators as well. */
    size_t max_len = (len_lhs > len_rhs) ? len_lhs : len_rhs;

    /* Constant-time comparison: iterate a fixed number of times based on the
     * longer string. For shorter string, we virtually pad with zeros.
     * This prevents timing attacks based on string length. */
    for (size_t i = 0; i <= max_len; i++) {
        /* Read character from left string, or 0 if past its end */
        unsigned char clhs = (i <= len_lhs) ? lhs_bytes[i] : 0;

        /* Read character from right string, or 0 if past its end */
        unsigned char crhs = (i <= len_rhs) ? rhs_bytes[i] : 0;

        /* XOR the characters to accumulate differences */
        diff |= (clhs ^ crhs);
    }

    return diff;
}
