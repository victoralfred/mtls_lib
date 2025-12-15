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
 *   - SIGUSR1: Enable kill switch (block new connections)
 *   - SIGUSR2: Disable kill switch (allow new connections)
 *   - SIGINT/SIGTERM: Graceful shutdown
 */

#define _DEFAULT_SOURCE

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

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
        char response[BUFFER_SIZE];
        bool kill_switch = mtls_ctx_is_kill_switch_enabled(global_ctx);
        const char* status = kill_switch ? "ENABLED" : "DISABLED";
        size_t prefix_len = strlen("Echo: \nKill switch: \n") + strlen(status);
        size_t max_echo = sizeof(response) - prefix_len - 1;

        /* Temporarily truncate buffer if needed for safe snprintf */
        if (strlen(buffer) > max_echo) {
            buffer[max_echo] = '\0';
        }

        snprintf(response, sizeof(response),
                 "Echo: %s\nKill switch: %s\n",
                 buffer,
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
    signal(SIGUSR1, signal_handler_enable_kill_switch);
    signal(SIGUSR2, signal_handler_disable_kill_switch);

    printf("═══════════════════════════════════════════════════════\n");
    printf("  mTLS Kill Switch Demo\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Library: %s\n", mtls_version());
    printf("  PID: %d\n", getpid());
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
    printf("Control signals:\n");
    printf("  kill -USR1 %d  # Enable kill switch\n", getpid());
    printf("  kill -USR2 %d  # Disable kill switch\n", getpid());
    printf("  kill -INT %d   # Shutdown\n", getpid());
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
                fprintf(stderr, "          Send SIGUSR2 to re-enable connections\n\n");

                /* Brief sleep to avoid tight loop */
                usleep(100000); /* 100ms */
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
