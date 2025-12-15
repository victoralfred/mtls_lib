/**
 * @file cert_reload_demo.c
 * @brief Demonstrates hot certificate reloading without downtime
 *
 * Shows how to reload server certificates dynamically without restarting
 * the process or closing existing connections. Useful for certificate
 * rotation in long-running services.
 *
 * Usage:
 *   ./cert_reload_demo <bind_address> <ca_cert> <server_cert> <server_key>
 *
 * Example:
 *   ./cert_reload_demo 0.0.0.0:8443 ca.pem server.pem server.key
 *
 * Control:
 *   - SIGUSR1: Reload certificates from disk (POSIX only)
 *   - SIGINT/SIGTERM: Graceful shutdown
 *
 * Certificate Rotation:
 *   1. Replace certificate files on disk (atomic rename recommended)
 *   2. Send SIGUSR1 signal: kill -USR1 <pid> (POSIX only)
 *   3. Server reloads without dropping connections
 *
 * Note: On Windows, SIGUSR1 is not available. Use Ctrl+C to stop.
 */

#ifndef _WIN32
#define _DEFAULT_SOURCE
#endif

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/* Platform-specific includes and definitions */
#ifdef _WIN32
    #include <windows.h>
    #define sleep_ms(ms) Sleep(ms)
    #define get_process_id() GetCurrentProcessId()
    /* Windows doesn't have SIGUSR1 */
    #ifndef SIGUSR1
        #define SIGUSR1 -1
    #endif
#else
    #include <unistd.h>
    #define sleep_ms(ms) usleep((ms) * 1000)
    #define get_process_id() getpid()
#endif

#define BUFFER_SIZE 4096

static volatile int keep_running = 1;
static volatile int reload_requested = 0;
static mtls_ctx* global_ctx = NULL;

#ifndef _WIN32
static void signal_handler_reload(int signum) {
    (void)signum;
    printf("\n[SIGNAL] Received SIGUSR1 - Certificate reload requested\n");
    reload_requested = 1;
}
#endif

static void signal_handler_shutdown(int signum) {
    (void)signum;
    printf("\n[SIGNAL] Received shutdown signal\n");
    keep_running = 0;
}

static void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s <bind:port> <ca_cert> <server_cert> <server_key>\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key\n",
            prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Certificate rotation:\n");
    fprintf(stderr, "  1. Update certificate files on disk\n");
    fprintf(stderr, "  2. kill -USR1 <pid>\n");
    fprintf(stderr, "  3. Server reloads without downtime\n");
    fprintf(stderr, "\n");
}

static void print_cert_info(mtls_ctx* ctx) {
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Certificate Status\n");
    printf("═══════════════════════════════════════════════════════\n");

    /* Note: In a real implementation, you might want to extract and display
     * certificate details like serial number, expiry, etc. For this demo,
     * we just show that the reload function was called successfully. */

    (void)ctx; /* Suppress unused warning */

    time_t now = time(NULL);
#ifdef _WIN32
    char time_buf[26];
    ctime_s(time_buf, sizeof(time_buf), &now);
    printf("  Last check: %s", time_buf);
#else
    printf("  Last check: %s", ctime(&now));
#endif
    printf("═══════════════════════════════════════════════════════\n");
    printf("\n");
}

static void handle_reload(mtls_ctx* ctx) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  RELOADING CERTIFICATES\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("\n");

    mtls_err err;
    mtls_err_init(&err);

    printf("[1/3] Reading new certificates from disk...\n");
    int result = mtls_ctx_reload_certs(ctx, &err);

    if (result == 0) {
        printf("[2/3] Validating new certificates...\n");
        printf("[3/3] Installing new certificates...\n");
        printf("\n");
        printf("✓ Certificate reload SUCCESSFUL\n");
        printf("  • New connections will use updated certificates\n");
        printf("  • Existing connections remain active\n");
        printf("  • No downtime occurred\n");
        printf("\n");
        print_cert_info(ctx);
    } else {
        printf("\n");
        fprintf(stderr, "✗ Certificate reload FAILED\n");
        fprintf(stderr, "  Error: %s\n", err.message);
        fprintf(stderr, "  • Server continues with old certificates\n");
        fprintf(stderr, "  • Check certificate files and try again\n");
        fprintf(stderr, "\n");
    }
}

static void handle_client(mtls_conn* conn, int conn_num) {
    mtls_err err;
    mtls_err_init(&err);

    printf("\n[Connection #%d] New client connected\n", conn_num);

    /* Get peer identity */
    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) == 0) {
        printf("  Peer: %s\n", identity.common_name);

        /* Check certificate validity and TTL */
        if (mtls_is_peer_cert_valid(&identity)) {
            int64_t ttl = mtls_get_cert_ttl_seconds(&identity);
            if (ttl > 0) {
                int days = (int)(ttl / 86400);
                int hours = (int)((ttl % 86400) / 3600);
                printf("  Cert expires in: %d days, %d hours\n", days, hours);
            } else {
                printf("  Cert expires in: %lld seconds\n", (long long)ttl);
            }
        } else {
            fprintf(stderr, "  ⚠ WARNING: Client certificate is expired or invalid!\n");
        }

        mtls_free_peer_identity(&identity);
    }

    /* Receive data */
    char buffer[BUFFER_SIZE];
    ssize_t received = mtls_read(conn, buffer, sizeof(buffer) - 1, &err);
    if (received > 0) {
        buffer[received] = '\0';
        printf("  Received: \"%s\"\n", buffer);

        /* Send response (limit echo to avoid truncation) */
        time_t now = time(NULL);

        /* Get time string (ctime_s on Windows, ctime on POSIX) */
        const char* time_str;
#ifdef _WIN32
        char time_buf[26];
        ctime_s(time_buf, sizeof(time_buf), &now);
        time_str = time_buf;
#else
        time_str = ctime(&now);
#endif

        /* Use fixed-size echo buffer to avoid format truncation warnings */
        /* Max echo size: BUFFER_SIZE - ("Echo from cert_reload_demo: " + "\nServer time: " + ctime (26 chars) + null) */
        /* 4096 - (29 + 14 + 26 + 1) = 4096 - 70 = 4026 */
        char safe_echo[4026];
        size_t buffer_len = strlen(buffer);
        size_t copy_len = buffer_len < sizeof(safe_echo) - 1 ? buffer_len : sizeof(safe_echo) - 1;
        memcpy(safe_echo, buffer, copy_len);
        safe_echo[copy_len] = '\0';

        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "Echo from cert_reload_demo: %s\nServer time: %s",
                 safe_echo, time_str);

        ssize_t sent = mtls_write(conn, response, strlen(response), &err);
        if (sent > 0) {
            printf("  Sent: %zd bytes\n", sent);
        } else {
            fprintf(stderr, "  ✗ Write failed: %s\n", err.message);
        }
    } else if (received == 0) {
        printf("  Client closed connection\n");
    } else {
        fprintf(stderr, "  ✗ Read failed: %s\n", err.message);
    }

    printf("[Connection #%d] Completed\n", conn_num);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char* bind_addr = argv[1];
    const char* ca_cert = argv[2];
    const char* server_cert = argv[3];
    const char* server_key = argv[4];

    /* Setup signal handlers */
    signal(SIGINT, signal_handler_shutdown);
    signal(SIGTERM, signal_handler_shutdown);
#ifndef _WIN32
    signal(SIGUSR1, signal_handler_reload);
#endif

    printf("═══════════════════════════════════════════════════════\n");
    printf("  mTLS Certificate Reload Demo\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Library: %s\n", mtls_version());
    printf("  PID: %lu\n", (unsigned long)get_process_id());
    printf("  Binding: %s\n", bind_addr);
    printf("═══════════════════════════════════════════════════════\n");
    printf("\n");

    /* Create mTLS configuration */
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = ca_cert;
    config.cert_path = server_cert;
    config.key_path = server_key;
    config.require_client_cert = true;
    config.min_tls_version = MTLS_TLS_1_2;

    mtls_err err;
    mtls_err_init(&err);

    /* Validate configuration */
    if (mtls_config_validate(&config, &err) != 0) {
        fprintf(stderr, "✗ Configuration validation failed: %s\n", err.message);
        return 1;
    }

    /* Create context */
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "✗ Failed to create context: %s\n", err.message);
        return 1;
    }

    global_ctx = ctx;
    printf("✓ Context created\n");
    print_cert_info(ctx);

    /* Create listener */
    mtls_listener* listener = mtls_listen(ctx, bind_addr, &err);
    if (!listener) {
        fprintf(stderr, "✗ Failed to listen: %s\n", err.message);
        mtls_ctx_free(ctx);
        return 1;
    }

    printf("✓ Listening on %s\n", bind_addr);
    printf("\n");
#ifndef _WIN32
    printf("Hot reload instructions:\n");
    printf("  1. Update certificates: cp new-server.pem %s\n", server_cert);
    printf("  2. Trigger reload: kill -USR1 %lu\n", (unsigned long)get_process_id());
    printf("  3. Verify: New connections use updated cert\n");
    printf("\n");
    printf("Shutdown: kill -INT %lu\n", (unsigned long)get_process_id());
#else
    printf("Note: Certificate reload via signal not available on Windows\n");
    printf("Shutdown: Press Ctrl+C\n");
#endif
    printf("\n");
    printf("Waiting for connections...\n");

    int connection_count = 0;
    int reload_count = 0;

    /* Accept loop */
    while (keep_running) {
        /* Check if reload was requested */
        if (reload_requested) {
            reload_requested = 0;
            reload_count++;
            printf("\n[RELOAD #%d]\n", reload_count);
            handle_reload(ctx);
            printf("Ready for connections...\n");
        }

        /* Set a timeout for accept to allow checking reload flag */
        /* Note: In a real implementation, you might use select/poll/epoll
         * for better control. For this demo, we use a simple approach. */

        mtls_err_init(&err);
        mtls_conn* conn = mtls_accept(listener, &err);

        if (!conn) {
            if (!keep_running) {
                break;
            }

            /* For this demo, we just continue on errors */
            /* In production, you'd want better error handling */
            if (err.code != MTLS_ERR_UNKNOWN) {
                fprintf(stderr, "✗ Accept failed: %s\n", err.message);
            }
            sleep_ms(100); /* 100ms to avoid tight loop */
            continue;
        }

        connection_count++;
        handle_client(conn, connection_count);
        mtls_close(conn);
    }

    printf("\n[SHUTDOWN] Cleaning up...\n");
    mtls_listener_close(listener);
    mtls_ctx_free(ctx);
    global_ctx = NULL;

    printf("✓ Server stopped cleanly\n");
    printf("  Total connections: %d\n", connection_count);
    printf("  Certificate reloads: %d\n", reload_count);

    return 0;
}
