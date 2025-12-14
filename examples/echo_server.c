/**
 * @file echo_server.c
 * @brief Echo server with SAN-based authorization
 *
 * Demonstrates:
 * - Allowed SAN list configuration
 * - Per-connection authorization
 * - Certificate information logging
 * - Graceful shutdown
 * - Statistics tracking
 *
 * Usage:
 *   ./echo_server <bind:port> <ca_cert> <server_cert> <server_key>
 */

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define BUFFER_SIZE 4096

/* Server statistics */
struct server_stats {
    int total_connections;
    int successful_auth;
    int failed_auth;
    size_t bytes_received;
    size_t bytes_sent;
};

static volatile int keep_running = 1;
static struct server_stats stats = {0};

static void signal_handler(int signum) {
    (void)signum;
    printf("\n\nReceived shutdown signal...\n");
    keep_running = 0;
}

static void print_stats(void) {
    printf("\n┌─ Server Statistics ────────────────────┐\n");
    printf("│ Total Connections:    %-15d │\n", stats.total_connections);
    printf("│ Successful Auth:      %-15d │\n", stats.successful_auth);
    printf("│ Failed Auth:          %-15d │\n", stats.failed_auth);
    printf("│ Bytes Received:       %-15zu │\n", stats.bytes_received);
    printf("│ Bytes Sent:           %-15zu │\n", stats.bytes_sent);
    printf("└────────────────────────────────────────┘\n");
}

static int authorize_client(mtls_conn* conn, const char** allowed_sans,
                              size_t allowed_count) {
    mtls_err err;
    mtls_err_init(&err);

    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) != 0) {
        fprintf(stderr, "  ✗ Failed to get peer identity\n");
        return 0;
    }

    printf("  Client CN: %s\n", identity.common_name);

    /* Check SANs against allowed list */
    int authorized = 0;
    for (size_t i = 0; i < identity.san_count; i++) {
        for (size_t j = 0; j < allowed_count; j++) {
            if (strcmp(identity.sans[i], allowed_sans[j]) == 0) {
                printf("  ✓ Authorized: %s\n", identity.sans[i]);
                authorized = 1;
                break;
            }
        }
        if (authorized) break;
    }

    if (!authorized) {
        printf("  ✗ Client NOT authorized\n");
        printf("  Client SANs:\n");
        for (size_t i = 0; i < identity.san_count; i++) {
            printf("    - %s\n", identity.sans[i]);
        }
    }

    /* Log certificate expiry */
    if (mtls_is_peer_cert_valid(&identity)) {
        int64_t ttl_days = mtls_get_cert_ttl_seconds(&identity) / 86400;
        if (ttl_days < 30) {
            printf("  ⚠ Client cert expires in %ld days\n", ttl_days);
        }
    } else {
        printf("  ⚠ Client certificate is EXPIRED\n");
    }

    mtls_free_peer_identity(&identity);
    return authorized;
}

static void handle_client(mtls_conn* conn, const char** allowed_sans,
                           size_t allowed_count) {
    mtls_err err;
    mtls_err_init(&err);

    char remote_addr[256];
    if (mtls_get_remote_addr(conn, remote_addr, sizeof(remote_addr)) == 0) {
        printf("  Remote: %s\n", remote_addr);
    }

    /* Authorization check */
    if (!authorize_client(conn, allowed_sans, allowed_count)) {
        stats.failed_auth++;
        const char* denied = "403 Forbidden: Not authorized\n";
        mtls_write(conn, denied, strlen(denied), &err);
        return;
    }

    stats.successful_auth++;

    /* Echo loop */
    printf("  Starting echo service...\n");
    char buffer[BUFFER_SIZE];
    int messages = 0;

    while (1) {
        ssize_t received = mtls_read(conn, buffer, sizeof(buffer), &err);
        if (received > 0) {
            stats.bytes_received += (size_t)received;
            messages++;
            printf("  ← Received %zd bytes (message #%d)\n", received, messages);

            /* Echo back */
            ssize_t sent = mtls_write(conn, buffer, (size_t)received, &err);
            if (sent > 0) {
                stats.bytes_sent += (size_t)sent;
                printf("  → Echoed %zd bytes\n", sent);
            } else {
                fprintf(stderr, "  ✗ Write failed: %s\n", err.message);
                break;
            }
        } else if (received == 0) {
            printf("  Connection closed by client\n");
            break;
        } else {
            fprintf(stderr, "  ✗ Read failed: %s\n", err.message);
            break;
        }
    }

    printf("  Session: %d messages echoed\n", messages);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <bind:port> <ca_cert> <server_cert> <server_key>\n",
                argv[0]);
        return 1;
    }

    const char* bind_addr = argv[1];
    const char* ca_cert = argv[2];
    const char* server_cert = argv[3];
    const char* server_key = argv[4];

    printf("╔═══════════════════════════════════════╗\n");
    printf("║    mTLS Echo Server                   ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Configure allowed client identities */
    const char* allowed_client_sans[] = {
        "client.example.com",
        "*.clients.example.com",
        "spiffe://example.com/client/*",
        "localhost"  /* For testing */
    };
    size_t allowed_count = sizeof(allowed_client_sans) / sizeof(allowed_client_sans[0]);

    printf("→ Configured allowed clients:\n");
    for (size_t i = 0; i < allowed_count; i++) {
        printf("  • %s\n", allowed_client_sans[i]);
    }
    printf("\n");

    mtls_err err;
    mtls_err_init(&err);

    /* Configure context */
    mtls_config config;
    mtls_config_init(&config);

    config.ca_cert_path = ca_cert;
    config.cert_path = server_cert;
    config.key_path = server_key;
    config.min_tls_version = MTLS_TLS_1_2;
    config.require_client_cert = true;

    /* Create context */
    printf("→ Creating server context...\n");
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "✗ Context creation failed: %s\n", err.message);
        return 1;
    }
    printf("  ✓ Context created\n\n");

    /* Create listener */
    printf("→ Starting listener on %s...\n", bind_addr);
    mtls_listener* listener = mtls_listen(ctx, bind_addr, &err);
    if (!listener) {
        fprintf(stderr, "✗ Listener creation failed: %s\n", err.message);
        mtls_ctx_free(ctx);
        return 1;
    }
    printf("  ✓ Listening for connections\n");
    printf("  Press Ctrl+C to stop\n\n");

    /* Accept loop */
    time_t start_time = time(NULL);

    while (keep_running) {
        printf("═══════════════════════════════════════\n");
        printf("Waiting for client...\n");

        mtls_conn* conn = mtls_accept(listener, &err);
        if (!conn) {
            if (keep_running) {
                fprintf(stderr, "✗ Accept failed: %s\n", err.message);
            }
            continue;
        }

        stats.total_connections++;
        printf("✓ Client #%d connected\n", stats.total_connections);

        /* Handle client */
        handle_client(conn, allowed_client_sans, allowed_count);

        /* Cleanup */
        mtls_close(conn);
        printf("Connection closed\n\n");
    }

    /* Shutdown */
    time_t end_time = time(NULL);
    int uptime = (int)(end_time - start_time);

    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║    Server Shutdown                    ║\n");
    printf("╚═══════════════════════════════════════╝\n");

    print_stats();

    printf("\n  Uptime: %d seconds (%d minutes)\n", uptime, uptime / 60);

    mtls_listener_close(listener);
    mtls_ctx_free(ctx);

    return 0;
}
