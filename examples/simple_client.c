/**
 * @file simple_client.c
 * @brief Simple mTLS client example
 *
 * Demonstrates basic client connection with mutual TLS authentication.
 *
 * Usage:
 *   ./simple_client <server_address> <ca_cert> <client_cert> <client_key>
 *
 * Example:
 *   ./simple_client localhost:8443 ca.pem client.pem client.key
 */

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096

static void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s <server:port> <ca_cert> <client_cert> <client_key>\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s localhost:8443 certs/ca.pem certs/client.pem certs/client.key\n",
            prog_name);
    fprintf(stderr, "\n");
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char* server_addr = argv[1];
    const char* ca_cert = argv[2];
    const char* client_cert = argv[3];
    const char* client_key = argv[4];

    printf("===========================================\n");
    printf("  mTLS Simple Client\n");
    printf("===========================================\n\n");

    /* Initialize error structure */
    mtls_err err;
    mtls_err_init(&err);

    /* Create and configure context */
    mtls_config config;
    mtls_config_init(&config);

    config.ca_cert_path = ca_cert;
    config.cert_path = client_cert;
    config.key_path = client_key;
    config.min_tls_version = MTLS_TLS_1_2;
    config.verify_hostname = true;
    config.connect_timeout_ms = 10000;  /* 10 seconds */

    printf("[1/4] Creating mTLS context...\n");
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "✗ Failed to create context: %s\n", err.message);
        return 1;
    }
    printf("  ✓ Context created\n\n");

    /* Connect to server */
    printf("[2/4] Connecting to %s...\n", server_addr);
    mtls_conn* conn = mtls_connect(ctx, server_addr, &err);
    if (!conn) {
        fprintf(stderr, "✗ Connection failed: %s\n", err.message);
        if (err.ssl_err) {
            fprintf(stderr, "  SSL error code: 0x%lx\n", err.ssl_err);
        }
        mtls_ctx_free(ctx);
        return 1;
    }
    printf("  ✓ Connected successfully\n\n");

    /* Get peer identity */
    printf("[3/4] Verifying peer identity...\n");
    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) == 0) {
        printf("  Common Name: %s\n", identity.common_name);
        printf("  SANs: %zu\n", identity.san_count);
        for (size_t i = 0; i < identity.san_count; i++) {
            printf("    - %s\n", identity.sans[i]);
        }

        if (mtls_has_spiffe_id(&identity)) {
            printf("  SPIFFE ID: %s\n", identity.spiffe_id);
        }

        /* Check certificate validity */
        if (mtls_is_peer_cert_valid(&identity)) {
            int64_t ttl = mtls_get_cert_ttl_seconds(&identity);
            printf("  Certificate: Valid (expires in %ld days)\n", ttl / 86400);
        } else {
            printf("  Certificate: ⚠ EXPIRED or NOT YET VALID\n");
        }

        mtls_free_peer_identity(&identity);
    } else {
        fprintf(stderr, "  ⚠ Could not retrieve peer identity\n");
    }
    printf("\n");

    /* Send a message */
    printf("[4/4] Exchanging data...\n");
    const char* message = "Hello from mTLS client!\n";
    ssize_t sent = mtls_write(conn, message, strlen(message), &err);
    if (sent < 0) {
        fprintf(stderr, "✗ Write failed: %s\n", err.message);
    } else {
        printf("  ✓ Sent %zd bytes\n", sent);
    }

    /* Receive response */
    char buffer[BUFFER_SIZE];
    ssize_t received = mtls_read(conn, buffer, sizeof(buffer) - 1, &err);
    if (received > 0) {
        buffer[received] = '\0';
        printf("  ✓ Received %zd bytes:\n", received);
        printf("  \"%s\"\n", buffer);
    } else if (received == 0) {
        printf("  Connection closed by peer\n");
    } else {
        fprintf(stderr, "✗ Read failed: %s\n", err.message);
    }

    printf("\n");
    printf("===========================================\n");
    printf("  Client session complete\n");
    printf("===========================================\n");

    /* Cleanup */
    mtls_close(conn);
    mtls_ctx_free(ctx);

    return 0;
}
