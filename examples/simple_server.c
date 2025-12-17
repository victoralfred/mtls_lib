/**
 * @file simple_server.c
 * @brief Simple mTLS server example
 *
 * Demonstrates basic server that accepts mTLS connections.
 *
 * Usage:
 *   ./simple_server <bind_address> <ca_cert> <server_cert> <server_key>
 *
 * Example:
 *   ./simple_server 0.0.0.0:8443 ca.pem server.pem server.key
 */

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define BUFFER_SIZE 4096

static volatile int keep_running = 1;

static void signal_handler(int signum) {
    (void)signum;
    keep_running = 0;
}

static void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s <bind:port> <ca_cert> <server_cert> <server_key>\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key\n",
            prog_name);
    fprintf(stderr, "\n");
}

static void handle_client(mtls_conn* conn) {
    mtls_err err;
    mtls_err_init(&err);

    /* Get remote address */
    char remote_addr[256];
    if (mtls_get_remote_addr(conn, remote_addr, sizeof(remote_addr)) == 0) {
        printf("  Remote address: %s\n", remote_addr);
    }

    /* Get peer identity */
    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) == 0) {
        printf("  Peer CN: %s\n", identity.common_name);

        if (identity.san_count > 0) {
            printf("  Peer SANs: ");
            for (size_t i = 0; i < identity.san_count; i++) {
                printf("%s%s", i > 0 ? ", " : "", identity.sans[i]);
            }
            printf("\n");
        }

        if (mtls_has_spiffe_id(&identity)) {
            printf("  SPIFFE ID: %s\n", identity.spiffe_id);
        }

        /* Get organization info */
        char org[256];
        if (mtls_get_peer_organization(conn, org, sizeof(org)) == 0) {
            printf("  Organization: %s\n", org);
        }

        mtls_free_peer_identity(&identity);
    }

    /* Receive data */
    char buffer[BUFFER_SIZE];
    ssize_t received = mtls_read(conn, buffer, sizeof(buffer) - 1, &err);
    if (received > 0) {
        buffer[received] = '\0';
        printf("  Received: \"%s\"\n", buffer);

        /* Echo back */
        const char* response = "Hello from mTLS server!\n";
        ssize_t sent = mtls_write(conn, response, strlen(response), &err);
        if (sent > 0) {
            printf("  Sent response: %zd bytes\n", sent);
        } else {
            fprintf(stderr, "  ✗ Write failed: %s\n", err.message);
        }
    } else if (received == 0) {
        printf("  Connection closed by client\n");
    } else {
        fprintf(stderr, "  ✗ Read failed: %s\n", err.message);
    }
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

    printf("===========================================\n");
    printf("  mTLS Simple Server\n");
    printf("  Library version: %s\n", mtls_version());
    printf("===========================================\n\n");

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize error structure */
    mtls_err err;
    mtls_err_init(&err);

    /* Create and configure context */
    mtls_config config;
    mtls_config_init(&config);

    config.ca_cert_path = ca_cert;
    config.cert_path = server_cert;
    config.key_path = server_key;
    config.min_tls_version = MTLS_TLS_1_2;
    config.require_client_cert = true;  /* Enforce mutual TLS */

    /* Validate configuration before creating context */
    if (mtls_config_validate(&config, &err) != 0) {
        fprintf(stderr, "✗ Configuration validation failed: %s\n", err.message);
        return 1;
    }

    printf("[1/2] Creating mTLS context...\n");
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "✗ Failed to create context: %s\n", err.message);
        return 1;
    }
    printf("  ✓ Context created\n\n");

    /* Create listener */
    printf("[2/2] Starting listener on %s...\n", bind_addr);
    mtls_listener* listener = mtls_listen(ctx, bind_addr, &err);
    if (!listener) {
        fprintf(stderr, "✗ Failed to create listener: %s\n", err.message);
        mtls_ctx_free(ctx);
        return 1;
    }
    printf("  ✓ Listening for connections\n");
    printf("  Press Ctrl+C to stop\n\n");

    /* Accept connections */
    int connection_count = 0;
    while (keep_running) {
        printf("-------------------------------------------\n");
        printf("Waiting for client connection...\n");

        mtls_conn* conn = mtls_accept(listener, &err);
        if (!conn) {
            if (keep_running) {
                fprintf(stderr, "✗ Accept failed: %s\n", err.message);
            }
            continue;
        }

        connection_count++;
        printf("✓ Client connected (#%d)\n", connection_count);

        /* Handle the client */
        handle_client(conn);

        /* Close connection */
        mtls_close(conn);
        printf("Connection closed\n\n");
    }

    printf("\n");
    printf("===========================================\n");
    printf("  Server shutting down\n");
    printf("  Total connections: %d\n", connection_count);
    printf("===========================================\n");

    /* Cleanup */
    mtls_listener_close(listener);
    mtls_ctx_free(ctx);

    return 0;
}
