/**
 * @file kill_switch_demo.c
 * @brief Demonstrates emergency kill switch functionality
 *
 * Shows how to dynamically enable/disable the kill switch to block
 * all new connections in emergency situations without stopping the process.
 *
 * Usage:
 *   ./kill_switch_demo <bind_address> <ca_cert> <server_cert> <server_key>
 *
 * Example:
 *   ./kill_switch_demo 0.0.0.0:8443 ca.pem server.pem server.key
 *
 * Control:
 *   - SIGUSR1: Enable kill switch (block new connections) - POSIX only
 *   - SIGUSR2: Disable kill switch (allow new connections) - POSIX only
 *   - SIGINT/SIGTERM: Graceful shutdown
 *
 * Note: On Windows, SIGUSR1/SIGUSR2 are not available. Use Ctrl+C to stop.
 */

#ifndef _WIN32
#define _DEFAULT_SOURCE
#endif

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* Platform-specific includes and definitions */
#ifdef _WIN32
    #include <windows.h>
    #define sleep_ms(ms) Sleep(ms)
    #define get_process_id() GetCurrentProcessId()
    /* Windows doesn't have SIGUSR1/SIGUSR2 */
    #ifndef SIGUSR1
        #define SIGUSR1 -1
    #endif
    #ifndef SIGUSR2
        #define SIGUSR2 -1
    #endif
#else
    #include <unistd.h>
    #define sleep_ms(ms) usleep((ms) * 1000)
    #define get_process_id() getpid()
#endif

#define BUFFER_SIZE 4096

static volatile int keep_running = 1;
static mtls_ctx* global_ctx = NULL;

static void print_kill_switch_status(mtls_ctx* ctx) {
    bool enabled = mtls_ctx_is_kill_switch_enabled(ctx);
    printf("\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  KILL SWITCH STATUS: %s\n", enabled ? "🔴 ENABLED (BLOCKING)" : "🟢 DISABLED (ACCEPTING)");
    printf("═══════════════════════════════════════════════════════\n");
    printf("\n");
}

static void signal_handler_enable_kill_switch(int signum) {
    (void)signum;
    if (global_ctx) {
        printf("\n[SIGNAL] Received SIGUSR1 - Enabling kill switch...\n");
        mtls_ctx_set_kill_switch(global_ctx, true);
        print_kill_switch_status(global_ctx);
        printf("[EMERGENCY] All new connections will be REJECTED!\n");
        printf("[INFO] Existing connections remain active.\n");
        printf("[INFO] Send SIGUSR2 to re-enable connections.\n\n");
    }
}

static void signal_handler_disable_kill_switch(int signum) {
    (void)signum;
    if (global_ctx) {
        printf("\n[SIGNAL] Received SIGUSR2 - Disabling kill switch...\n");
        mtls_ctx_set_kill_switch(global_ctx, false);
        print_kill_switch_status(global_ctx);
        printf("[RECOVERY] Server is now accepting new connections.\n\n");
    }
}

static void signal_handler_shutdown(int signum) {
    (void)signum;
    printf("\n[SIGNAL] Received shutdown signal - Gracefully stopping...\n");
    keep_running = 0;
}

static void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s <bind:port> <ca_cert> <server_cert> <server_key>\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key\n",
            prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Control signals:\n");
    fprintf(stderr, "  kill -USR1 <pid>  Enable kill switch (block new connections)\n");
    fprintf(stderr, "  kill -USR2 <pid>  Disable kill switch (allow new connections)\n");
    fprintf(stderr, "  kill -INT <pid>   Graceful shutdown\n");
    fprintf(stderr, "\n");
}

static void handle_client(mtls_conn* conn, int conn_num) {
    mtls_err err;
    mtls_err_init(&err);

    printf("\n[Connection #%d] Handling client...\n", conn_num);

    /* Get remote address */
    char remote_addr[256];
    if (mtls_get_remote_addr(conn, remote_addr, sizeof(remote_addr)) == 0) {
        printf("  Remote: %s\n", remote_addr);
    }

    /* Get peer identity */
    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) == 0) {
        printf("  Peer: %s\n", identity.common_name);

        if (mtls_has_spiffe_id(&identity)) {
            printf("  SPIFFE: %s\n", identity.spiffe_id);
        }

        mtls_free_peer_identity(&identity);
    }

    /* Receive and echo data */
    char buffer[BUFFER_SIZE];
    ssize_t received = mtls_read(conn, buffer, sizeof(buffer) - 1, &err);
    if (received > 0) {
        buffer[received] = '\0';
        printf("  Received: \"%s\"\n", buffer);

        /* Echo back with status (limit echo to avoid truncation warning) */
        bool kill_switch = mtls_ctx_is_kill_switch_enabled(global_ctx);
        const char* status = kill_switch ? "ENABLED" : "DISABLED";

        /* Use fixed-size echo buffer to avoid format truncation warnings */
        /* Max echo size: BUFFER_SIZE - ("Echo: " + "\nKill switch: DISABLED\n" + null) = 4096 - 31 = 4065 */
        char safe_echo[4065];
        size_t buffer_len = strlen(buffer);
        size_t copy_len = buffer_len < sizeof(safe_echo) - 1 ? buffer_len : sizeof(safe_echo) - 1;
        memcpy(safe_echo, buffer, copy_len);
        safe_echo[copy_len] = '\0';

        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "Echo: %s\nKill switch: %s\n",
                 safe_echo,
                 status);

        ssize_t sent = mtls_write(conn, response, strlen(response), &err);
        if (sent > 0) {
            printf("  Sent: %zd bytes\n", sent);
        } else {
            fprintf(stderr, "  ✗ Write failed: %s\n", err.message);
        }
    } else if (received == 0) {
        printf("  Connection closed by client\n");
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
    signal(SIGUSR1, signal_handler_enable_kill_switch);
    signal(SIGUSR2, signal_handler_disable_kill_switch);
#endif

    printf("═══════════════════════════════════════════════════════\n");
    printf("  mTLS Kill Switch Demo\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Library: %s\n", mtls_version());
    printf("  PID: %lu\n", (unsigned long)get_process_id());
    printf("  Binding: %s\n", bind_addr);
    printf("═══════════════════════════════════════════════════════\n");

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

    /* Start with kill switch disabled */
    mtls_ctx_set_kill_switch(ctx, false);
    print_kill_switch_status(ctx);

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
    printf("Control signals:\n");
    printf("  kill -USR1 %lu  # Enable kill switch\n", (unsigned long)get_process_id());
    printf("  kill -USR2 %lu  # Disable kill switch\n", (unsigned long)get_process_id());
    printf("  kill -INT %lu   # Shutdown\n", (unsigned long)get_process_id());
#else
    printf("Note: Kill switch signals not available on Windows\n");
    printf("Shutdown: Press Ctrl+C\n");
#endif
    printf("\n");
    printf("Waiting for connections...\n");

    int connection_count = 0;

    /* Accept loop */
    while (keep_running) {
        mtls_err_init(&err);
        mtls_conn* conn = mtls_accept(listener, &err);

        if (!conn) {
            /* Check if failure was due to kill switch */
            if (err.code == MTLS_ERR_KILL_SWITCH_ENABLED) {
                fprintf(stderr, "\n[BLOCKED] Connection rejected - Kill switch is ENABLED\n");
#ifndef _WIN32
                fprintf(stderr, "          Send SIGUSR2 to re-enable connections\n\n");
#else
                fprintf(stderr, "          Kill switch is active\n\n");
#endif

                /* Brief sleep to avoid tight loop */
                sleep_ms(100); /* 100ms */
                continue;
            }

            /* Check if we're shutting down */
            if (!keep_running) {
                break;
            }

            fprintf(stderr, "✗ Accept failed: %s\n", err.message);
            fprintf(stderr, "  Error code: %s\n", mtls_err_code_name(err.code));
            continue;
        }

        connection_count++;
        printf("\n[ACCEPTED] New connection (#%d)\n", connection_count);

        /* Handle the client */
        handle_client(conn, connection_count);

        /* Close connection */
        mtls_close(conn);
    }

    printf("\n[SHUTDOWN] Cleaning up...\n");
    mtls_listener_close(listener);
    mtls_ctx_free(ctx);
    global_ctx = NULL;

    printf("✓ Server stopped cleanly\n");
    printf("  Total connections handled: %d\n", connection_count);

    return 0;
}
