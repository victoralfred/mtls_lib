/**
 * @file observability_demo.c
 * @brief Demonstration of mTLS observability layer
 *
 * This example shows how to:
 * - Register event observers
 * - Track connection lifecycle events
 * - Monitor I/O operations
 * - Collect metrics (connection counts, bytes transferred, durations)
 * - Detect and respond to kill-switch events
 */

#include "mtls/mtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>

/* Certificate paths */
#define CA_CERT     "../certs/ca-cert.pem"
#define SERVER_CERT "../certs/server-cert.pem"
#define SERVER_KEY  "../certs/server-key.pem"
#define CLIENT_CERT "../certs/client-cert.pem"
#define CLIENT_KEY  "../certs/client-key.pem"

/* ANSI color codes for pretty output */
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

/* Metrics structure */
typedef struct {
    atomic_uint_fast64_t total_connections;
    atomic_uint_fast64_t successful_connections;
    atomic_uint_fast64_t failed_connections;
    atomic_uint_fast64_t total_bytes_read;
    atomic_uint_fast64_t total_bytes_written;
    atomic_uint_fast64_t total_handshake_time_us;
    atomic_uint_fast64_t total_connection_time_us;
    atomic_uint_fast32_t active_connections;
    atomic_uint_fast32_t kill_switch_blocks;
    pthread_mutex_t lock;
} metrics;

static void metrics_init(metrics* m) {
    memset(m, 0, sizeof(*m));
    atomic_init(&m->total_connections, 0);
    atomic_init(&m->successful_connections, 0);
    atomic_init(&m->failed_connections, 0);
    atomic_init(&m->total_bytes_read, 0);
    atomic_init(&m->total_bytes_written, 0);
    atomic_init(&m->total_handshake_time_us, 0);
    atomic_init(&m->total_connection_time_us, 0);
    atomic_init(&m->active_connections, 0);
    atomic_init(&m->kill_switch_blocks, 0);
    pthread_mutex_init(&m->lock, NULL);
}

static void metrics_free(metrics* m) {
    pthread_mutex_destroy(&m->lock);
}

static void metrics_print(metrics* m, const char* label) {
    uint64_t total_conn = atomic_load(&m->total_connections);
    uint64_t success_conn = atomic_load(&m->successful_connections);
    uint64_t failed_conn = atomic_load(&m->failed_connections);
    uint64_t bytes_read = atomic_load(&m->total_bytes_read);
    uint64_t bytes_written = atomic_load(&m->total_bytes_written);
    uint64_t handshake_time = atomic_load(&m->total_handshake_time_us);
    uint64_t connection_time = atomic_load(&m->total_connection_time_us);
    uint32_t active_conn = atomic_load(&m->active_connections);
    uint32_t kill_switch = atomic_load(&m->kill_switch_blocks);

    printf("\n" COLOR_BOLD COLOR_CYAN "┌─────────────────────────────────────────┐\n");
    printf("│  %s Metrics%-*s│\n", label, (int)(32 - strlen(label)), "");
    printf("├─────────────────────────────────────────┤" COLOR_RESET "\n");

    printf(COLOR_GREEN "│  Total Connections:      %-14" PRIu64 " │\n" COLOR_RESET, total_conn);
    printf(COLOR_GREEN "│  Successful:             %-14" PRIu64 " │\n" COLOR_RESET, success_conn);
    printf(COLOR_RED   "│  Failed:                 %-14" PRIu64 " │\n" COLOR_RESET, failed_conn);
    printf(COLOR_YELLOW "│  Active:                 %-14u │\n" COLOR_RESET, active_conn);
    printf(COLOR_BLUE  "│  Total Bytes Read:       %-14" PRIu64 " │\n" COLOR_RESET, bytes_read);
    printf(COLOR_BLUE  "│  Total Bytes Written:    %-14" PRIu64 " │\n" COLOR_RESET, bytes_written);

    if (success_conn > 0) {
        uint64_t avg_handshake = handshake_time / success_conn;
        uint64_t avg_connection = connection_time / success_conn;
        printf(COLOR_MAGENTA "│  Avg Handshake Time:     %-10" PRIu64 " us │\n" COLOR_RESET, avg_handshake);
        printf(COLOR_MAGENTA "│  Avg Connection Time:    %-10" PRIu64 " us │\n" COLOR_RESET, avg_connection);
    }

    if (kill_switch > 0) {
        printf(COLOR_RED COLOR_BOLD "│  Kill Switch Blocks:     %-14u │\n" COLOR_RESET, kill_switch);
    }

    printf(COLOR_BOLD COLOR_CYAN "└─────────────────────────────────────────┘" COLOR_RESET "\n\n");
}

static const char* event_type_name(mtls_event_type type) {
    switch (type) {
        case MTLS_EVENT_CONNECT_START: return "CONNECT_START";
        case MTLS_EVENT_CONNECT_SUCCESS: return "CONNECT_SUCCESS";
        case MTLS_EVENT_CONNECT_FAILURE: return "CONNECT_FAILURE";
        case MTLS_EVENT_HANDSHAKE_START: return "HANDSHAKE_START";
        case MTLS_EVENT_HANDSHAKE_SUCCESS: return "HANDSHAKE_SUCCESS";
        case MTLS_EVENT_HANDSHAKE_FAILURE: return "HANDSHAKE_FAILURE";
        case MTLS_EVENT_READ: return "READ";
        case MTLS_EVENT_WRITE: return "WRITE";
        case MTLS_EVENT_CLOSE: return "CLOSE";
        case MTLS_EVENT_KILL_SWITCH_TRIGGERED: return "KILL_SWITCH";
        default: return "UNKNOWN";
    }
}

static const char* event_color(mtls_event_type type) {
    switch (type) {
        case MTLS_EVENT_CONNECT_START:
        case MTLS_EVENT_HANDSHAKE_START:
            return COLOR_YELLOW;
        case MTLS_EVENT_CONNECT_SUCCESS:
        case MTLS_EVENT_HANDSHAKE_SUCCESS:
            return COLOR_GREEN;
        case MTLS_EVENT_CONNECT_FAILURE:
        case MTLS_EVENT_HANDSHAKE_FAILURE:
            return COLOR_RED;
        case MTLS_EVENT_READ:
            return COLOR_BLUE;
        case MTLS_EVENT_WRITE:
            return COLOR_CYAN;
        case MTLS_EVENT_CLOSE:
            return COLOR_MAGENTA;
        case MTLS_EVENT_KILL_SWITCH_TRIGGERED:
            return COLOR_RED COLOR_BOLD;
        default:
            return COLOR_RESET;
    }
}

/* Event callback for metrics collection */
static void metrics_event_callback(const mtls_event* event, void* userdata) {
    metrics* m = (metrics*)userdata;

    /* Print event */
    printf("%s[EVENT]%s %s%-20s%s",
           COLOR_BOLD, COLOR_RESET,
           event_color(event->type),
           event_type_name(event->type),
           COLOR_RESET);

    if (event->remote_addr) {
        printf(" | addr: %s%-15s%s", COLOR_CYAN, event->remote_addr, COLOR_RESET);
    }

    if (event->bytes > 0) {
        printf(" | bytes: %s%zu%s", COLOR_BLUE, event->bytes, COLOR_RESET);
    }

    if (event->duration_us > 0) {
        printf(" | duration: %s%lu us%s", COLOR_MAGENTA,
               (unsigned long)event->duration_us, COLOR_RESET);
    }

    if (event->error_code != 0) {
        printf(" | %serror: %d%s", COLOR_RED, event->error_code, COLOR_RESET);
    }

    printf("\n");

    /* Update metrics */
    switch (event->type) {
        case MTLS_EVENT_CONNECT_START:
            atomic_fetch_add(&m->total_connections, 1);
            atomic_fetch_add(&m->active_connections, 1);
            break;

        case MTLS_EVENT_CONNECT_SUCCESS:
            atomic_fetch_add(&m->successful_connections, 1);
            atomic_fetch_add(&m->total_connection_time_us, event->duration_us);
            break;

        case MTLS_EVENT_CONNECT_FAILURE:
            atomic_fetch_add(&m->failed_connections, 1);
            atomic_fetch_sub(&m->active_connections, 1);
            break;

        case MTLS_EVENT_HANDSHAKE_SUCCESS:
            atomic_fetch_add(&m->total_handshake_time_us, event->duration_us);
            break;

        case MTLS_EVENT_READ:
            atomic_fetch_add(&m->total_bytes_read, event->bytes);
            break;

        case MTLS_EVENT_WRITE:
            atomic_fetch_add(&m->total_bytes_written, event->bytes);
            break;

        case MTLS_EVENT_CLOSE:
            atomic_fetch_sub(&m->active_connections, 1);
            break;

        case MTLS_EVENT_KILL_SWITCH_TRIGGERED:
            atomic_fetch_add(&m->kill_switch_blocks, 1);
            break;

        default:
            break;
    }
}

/* Server thread */
typedef struct {
    const char* bind_addr;
    int num_clients;
    metrics* server_metrics;
} server_args;

static void* server_thread(void* arg) {
    server_args* args = (server_args*)arg;
    mtls_err err;

    /* Create server context */
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = CA_CERT;
    config.cert_path = SERVER_CERT;
    config.key_path = SERVER_KEY;

    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, COLOR_RED "[Server] Failed to create context: %s\n" COLOR_RESET,
                err.message);
        return NULL;
    }

    /* Register metrics observer */
    mtls_observers observers = {
        .on_event = metrics_event_callback,
        .userdata = args->server_metrics
    };
    mtls_set_observers(ctx, &observers);

    printf(COLOR_GREEN COLOR_BOLD "\n[Server] Starting on %s\n" COLOR_RESET, args->bind_addr);

    /* Start listener */
    mtls_listener* listener = mtls_listen(ctx, args->bind_addr, &err);
    if (!listener) {
        fprintf(stderr, COLOR_RED "[Server] Failed to listen: %s\n" COLOR_RESET, err.message);
        mtls_ctx_free(ctx);
        return NULL;
    }

    printf(COLOR_GREEN "[Server] Listening for %d clients...\n" COLOR_RESET, args->num_clients);

    /* Accept and echo */
    for (int i = 0; i < args->num_clients; i++) {
        mtls_conn* conn = mtls_accept(listener, &err);
        if (!conn) {
            fprintf(stderr, COLOR_RED "[Server] Failed to accept: %s\n" COLOR_RESET, err.message);
            continue;
        }

        printf(COLOR_GREEN "[Server] Accepted client %d\n" COLOR_RESET, i + 1);

        /* Echo loop */
        char buffer[256];
        ssize_t n;
        while ((n = mtls_read(conn, buffer, sizeof(buffer), &err)) > 0) {
            mtls_write(conn, buffer, (size_t)n, &err);

            /* Check if it's the termination message */
            if (n >= 4 && memcmp(buffer, "QUIT", 4) == 0) {
                printf(COLOR_YELLOW "[Server] Client requested disconnect\n" COLOR_RESET);
                break;
            }
        }

        mtls_close(conn);
    }

    mtls_listener_close(listener);
    mtls_ctx_free(ctx);

    printf(COLOR_GREEN COLOR_BOLD "[Server] Shutdown complete\n" COLOR_RESET);
    return NULL;
}

/* Client operations */
static void run_client(const char* server_addr, metrics* client_metrics) {
    mtls_err err;

    /* Create client context */
    mtls_config config;
    mtls_config_init(&config);
    config.ca_cert_path = CA_CERT;
    config.cert_path = CLIENT_CERT;
    config.key_path = CLIENT_KEY;

    mtls_ctx* ctx = mtls_ctx_create(&config, &err);
    if (!ctx) {
        fprintf(stderr, COLOR_RED "[Client] Failed to create context: %s\n" COLOR_RESET,
                err.message);
        return;
    }

    /* Register metrics observer */
    mtls_observers observers = {
        .on_event = metrics_event_callback,
        .userdata = client_metrics
    };
    mtls_set_observers(ctx, &observers);

    printf(COLOR_BLUE COLOR_BOLD "\n[Client] Connecting to %s\n" COLOR_RESET, server_addr);

    /* Connect */
    mtls_conn* conn = mtls_connect(ctx, server_addr, &err);
    if (!conn) {
        fprintf(stderr, COLOR_RED "[Client] Failed to connect: %s\n" COLOR_RESET, err.message);
        mtls_ctx_free(ctx);
        return;
    }

    printf(COLOR_GREEN "[Client] Connected successfully!\n" COLOR_RESET);

    /* Send and receive messages */
    const char* messages[] = {
        "Hello, mTLS!",
        "Testing observability...",
        "Event tracking works!",
        "QUIT"
    };

    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        size_t msg_len = strlen(messages[i]);

        printf(COLOR_CYAN "[Client] Sending: \"%s\"\n" COLOR_RESET, messages[i]);
        ssize_t written = mtls_write(conn, messages[i], msg_len, &err);
        if (written < 0) {
            fprintf(stderr, COLOR_RED "[Client] Write failed: %s\n" COLOR_RESET, err.message);
            break;
        }

        /* Don't read response for QUIT message */
        if (i == sizeof(messages) / sizeof(messages[0]) - 1) {
            break;
        }

        char buffer[256];
        ssize_t n = mtls_read(conn, buffer, sizeof(buffer), &err);
        if (n > 0) {
            printf(COLOR_GREEN "[Client] Received: \"%.*s\"\n" COLOR_RESET, (int)n, buffer);
        } else if (n < 0) {
            fprintf(stderr, COLOR_RED "[Client] Read failed: %s\n" COLOR_RESET, err.message);
            break;
        }
    }

    mtls_close(conn);
    mtls_ctx_free(ctx);

    printf(COLOR_BLUE COLOR_BOLD "[Client] Disconnected\n" COLOR_RESET);
}

int main(void) {
    printf(COLOR_BOLD COLOR_CYAN);
    printf("========================================\n");
    printf("  mTLS Observability Demo\n");
    printf("========================================\n");
    printf(COLOR_RESET);
    printf("\nThis demo shows real-time event tracking\n");
    printf("and metrics collection for mTLS operations.\n");

    /* Initialize metrics */
    metrics server_metrics, client_metrics;
    metrics_init(&server_metrics);
    metrics_init(&client_metrics);

    /* Start server thread */
    server_args args = {
        .bind_addr = "127.0.0.1:8444",
        .num_clients = 1,
        .server_metrics = &server_metrics
    };

    pthread_t server_tid;
    if (pthread_create(&server_tid, NULL, server_thread, &args) != 0) {
        fprintf(stderr, COLOR_RED "Failed to create server thread\n" COLOR_RESET);
        return 1;
    }

    /* Give server time to start */
    sleep(1);

    /* Run client */
    run_client("127.0.0.1:8444", &client_metrics);

    /* Wait for server to finish */
    pthread_join(server_tid, NULL);

    /* Print final metrics */
    printf("\n" COLOR_BOLD "=== Final Metrics ===\n" COLOR_RESET);
    metrics_print(&server_metrics, "Server");
    metrics_print(&client_metrics, "Client");

    /* Cleanup */
    metrics_free(&server_metrics);
    metrics_free(&client_metrics);

    printf(COLOR_GREEN COLOR_BOLD "\n✓ Demo completed successfully!\n" COLOR_RESET);
    printf("\nKey takeaways:\n");
    printf("  • All connection events are tracked in real-time\n");
    printf("  • Handshake and connection durations are measured\n");
    printf("  • I/O operations report byte counts\n");
    printf("  • Metrics can be aggregated for monitoring\n");
    printf("  • Kill-switch events are detected automatically\n\n");

    return 0;
}
