/**
 * @file advanced_client.c
 * @brief Advanced mTLS client with identity validation
 *
 * Demonstrates:
 * - SAN validation with allowed list
 * - SPIFFE ID verification
 * - Certificate expiration monitoring
 * - Error handling best practices
 * - Kill-switch demonstration
 *
 * Usage:
 *   ./advanced_client <server:port> <ca_cert> <client_cert> <client_key>
 */

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#define BUFFER_SIZE 4096
#define CERT_EXPIRY_WARNING_DAYS 30

static void print_error_details(const mtls_err* err) {
    char err_buf[512];
    mtls_err_format(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "%s\n", err_buf);

    /* Print error code name and category */
    const char* code_name = mtls_err_code_name(err->code);
    const char* category = mtls_err_category_name(err->code);

    if (code_name) {
        fprintf(stderr, "  Error code: %s\n", code_name);
    }
    if (category) {
        fprintf(stderr, "  Category: %s\n", category);
    }
}

static void print_peer_info(mtls_conn* conn) {
    mtls_err err;
    mtls_err_init(&err);

    printf("\n┌─ Peer Information ─────────────────────┐\n");

    /* Get addresses */
    char remote_addr[256], local_addr[256];
    if (mtls_get_remote_addr(conn, remote_addr, sizeof(remote_addr)) == 0) {
        printf("│ Remote: %-30s │\n", remote_addr);
    }
    if (mtls_get_local_addr(conn, local_addr, sizeof(local_addr)) == 0) {
        printf("│ Local:  %-30s │\n", local_addr);
    }

    /* Get peer identity */
    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) != 0) {
        printf("│ ✗ Failed to get peer identity        │\n");
        printf("└────────────────────────────────────────┘\n");
        return;
    }

    printf("│                                        │\n");
    printf("│ Common Name: %-23s│\n", identity.common_name);

    /* Print SANs */
    if (identity.san_count > 0) {
        printf("│                                        │\n");
        printf("│ Subject Alternative Names:             │\n");
        for (size_t i = 0; i < identity.san_count && i < 5; i++) {
            printf("│   • %-34s│\n", identity.sans[i]);
        }
        if (identity.san_count > 5) {
            printf("│   ... and %zu more                     │\n", identity.san_count - 5);
        }
    }

    /* Print SPIFFE ID */
    if (mtls_has_spiffe_id(&identity)) {
        printf("│                                        │\n");
        printf("│ SPIFFE ID:                             │\n");
        printf("│   %s\n", identity.spiffe_id);
    }

    /* Print organization info */
    char org[256], ou[256];
    if (mtls_get_peer_organization(conn, org, sizeof(org)) == 0) {
        printf("│                                        │\n");
        printf("│ Organization: %-22s│\n", org);
    }
    if (mtls_get_peer_org_unit(conn, ou, sizeof(ou)) == 0) {
        printf("│ Org Unit:     %-22s│\n", ou);
    }

    /* Certificate validity */
    printf("│                                        │\n");
    if (mtls_is_peer_cert_valid(&identity)) {
        int64_t ttl = mtls_get_cert_ttl_seconds(&identity);
        int64_t days = ttl / 86400;

        printf("│ Certificate Status: VALID              │\n");
        printf("│ Expires in: %" PRId64 " days (%" PRId64 " hours)     │\n", days, ttl / 3600);

        if (days < CERT_EXPIRY_WARNING_DAYS) {
            printf("│ ⚠ WARNING: Certificate expiring soon! │\n");
        }
    } else {
        printf("│ Certificate Status: ✗ INVALID/EXPIRED  │\n");
    }

    /* Print validity period */
    char time_buf[64];
    const struct tm* tm_ptr;

#ifdef _WIN32
    /* Use localtime_s on Windows to avoid deprecation warning */
    struct tm tm_info;
    localtime_s(&tm_info, &identity.cert_not_before);
    tm_ptr = &tm_info;
#else
    tm_ptr = localtime(&identity.cert_not_before);
#endif
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_ptr);
    printf("│ Valid from: %-24s│\n", time_buf);

#ifdef _WIN32
    localtime_s(&tm_info, &identity.cert_not_after);
    tm_ptr = &tm_info;
#else
    tm_ptr = localtime(&identity.cert_not_after);
#endif
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_ptr);
    printf("│ Valid to:   %-24s│\n", time_buf);

    printf("└────────────────────────────────────────┘\n\n");

    mtls_free_peer_identity(&identity);
}

static int validate_server_identity(mtls_conn* conn, const char** allowed_sans,
                                      size_t allowed_count) {
    mtls_err err;
    mtls_err_init(&err);

    mtls_peer_identity identity;
    if (mtls_get_peer_identity(conn, &identity, &err) != 0) {
        fprintf(stderr, "✗ Failed to get peer identity for validation\n");
        return -1;
    }

    /* Use built-in SAN validation function */
    bool validated = mtls_validate_peer_sans(&identity, allowed_sans, allowed_count);

    if (validated) {
        /* Find which SAN matched (for informative output) */
        for (size_t i = 0; i < identity.san_count; i++) {
            for (size_t j = 0; j < allowed_count; j++) {
                if (strcmp(identity.sans[i], allowed_sans[j]) == 0) {
                    printf("✓ Server identity validated: %s\n", identity.sans[i]);
                    break;
                }
            }
        }
    } else {
        fprintf(stderr, "✗ Server identity NOT in allowed list!\n");
        fprintf(stderr, "  Server SANs:\n");
        for (size_t i = 0; i < identity.san_count; i++) {
            fprintf(stderr, "    - %s\n", identity.sans[i]);
        }
        fprintf(stderr, "  Allowed SANs:\n");
        for (size_t i = 0; i < allowed_count; i++) {
            fprintf(stderr, "    - %s\n", allowed_sans[i]);
        }
    }

    mtls_free_peer_identity(&identity);
    return validated ? 0 : -1;
}

int main(int argc, const char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <server:port> <ca_cert> <client_cert> <client_key>\n",
                argv[0]);
        return 1;
    }

    const char* server_addr = argv[1];
    const char* ca_cert = argv[2];
    const char* client_cert = argv[3];
    const char* client_key = argv[4];

    printf("╔═══════════════════════════════════════╗\n");
    printf("║    Advanced mTLS Client Example      ║\n");
    printf("║    Library: %-25s ║\n", mtls_version());
    printf("╚═══════════════════════════════════════╝\n\n");

    mtls_err err;
    mtls_err_init(&err);

    /* Configure allowed server identities */
    const char* allowed_server_sans[] = {
        "localhost",
        "127.0.0.1",
        "*.example.com",
        "spiffe://example.com/service/api"
    };
    size_t allowed_count = sizeof(allowed_server_sans) / sizeof(allowed_server_sans[0]);

    /* Create configuration */
    mtls_config config;
    mtls_config_init(&config);

    config.ca_cert_path = ca_cert;
    config.cert_path = client_cert;
    config.key_path = client_key;
    config.min_tls_version = MTLS_TLS_1_3;  /* Prefer TLS 1.3 */
    config.verify_hostname = true;
    config.connect_timeout_ms = 5000;
    config.read_timeout_ms = 10000;
    config.write_timeout_ms = 10000;

    /* Validate configuration */
    if (mtls_config_validate(&config, &err) != 0) {
        fprintf(stderr, "✗ Configuration validation failed:\n");
        print_error_details(&err);
        return 1;
    }

    /* Create context */
    printf("→ Creating mTLS context...\n");
    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, "✗ Context creation failed:\n");
        print_error_details(&err);
        return 1;
    }
    printf("  ✓ Context created (TLS 1.3 preferred)\n\n");

    /* Connect */
    printf("→ Connecting to %s...\n", server_addr);
    mtls_conn* conn = mtls_connect(ctx, server_addr, &err);
    if (!conn) {
        fprintf(stderr, "✗ Connection failed:\n");
        print_error_details(&err);
        mtls_ctx_free(ctx);
        return 1;
    }
    printf("  ✓ TLS handshake complete\n");

    /* Validate server identity */
    printf("\n→ Validating server identity...\n");
    if (validate_server_identity(conn, allowed_server_sans, allowed_count) != 0) {
        fprintf(stderr, "\n✗ Server identity validation FAILED\n");
        fprintf(stderr, "  Closing connection for security\n");
        mtls_close(conn);
        mtls_ctx_free(ctx);
        return 1;
    }

    /* Print peer information */
    print_peer_info(conn);

    /* Send test data */
    printf("→ Sending test message...\n");
    const char* message = "Advanced mTLS client test message\n";
    ssize_t sent = mtls_write(conn, message, strlen(message), &err);
    if (sent < 0) {
        fprintf(stderr, "✗ Write failed:\n");
        print_error_details(&err);
    } else {
        printf("  ✓ Sent %zd bytes\n", sent);
    }

    /* Receive response */
    printf("\n→ Receiving response...\n");
    char buffer[BUFFER_SIZE];
    ssize_t received = mtls_read(conn, buffer, sizeof(buffer) - 1, &err);
    if (received > 0) {
        buffer[received] = '\0';
        printf("  ✓ Received %zd bytes:\n", received);
        printf("  ┌────────────────────────────────────┐\n");
        printf("  │ %s", buffer);
        printf("  └────────────────────────────────────┘\n");
    } else if (received == 0) {
        printf("  Connection closed by peer\n");
    } else {
        fprintf(stderr, "✗ Read failed:\n");
        print_error_details(&err);
    }

    /* Check connection state */
    mtls_conn_state state = mtls_get_state(conn);
    printf("\n→ Connection state: ");
    switch (state) {
        case MTLS_CONN_STATE_ESTABLISHED:
            printf("ESTABLISHED\n");
            break;
        case MTLS_CONN_STATE_CLOSED:
            printf("CLOSED\n");
            break;
        default:
            printf("OTHER (%d)\n", state);
            break;
    }

    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║    Session Complete                   ║\n");
    printf("╚═══════════════════════════════════════╝\n");

    /* Cleanup */
    mtls_close(conn);
    mtls_ctx_free(ctx);

    return 0;
}
