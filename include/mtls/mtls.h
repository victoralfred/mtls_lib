/**
 * @file mtls.h
 * @brief Main public API for the mTLS library
 *
 * This is the primary header file that applications should include.
 * It provides a minimal, secure, and auditable mTLS transport layer.
 *
 * THREAD SAFETY:
 *
 * - mtls_ctx: Thread-safe for concurrent use after creation. The context
 *   is effectively immutable once created, except for:
 *   - mtls_ctx_set_kill_switch(): Uses atomic operations, thread-safe
 *   - mtls_ctx_reload_certs(): Should not be called concurrently with itself
 *   - mtls_set_observers(): NOT thread-safe; must be called before connections
 *
 * - mtls_conn: NOT thread-safe. Each connection should be used from a single
 *   thread at a time. However, different connections can be used concurrently
 *   from different threads.
 *
 * - mtls_listener: NOT thread-safe. Use one listener per thread or protect
 *   with external synchronization.
 *
 * - Event callbacks: May be invoked concurrently from multiple threads if
 *   multiple connections are active. Callback implementations must be
 *   thread-safe. See mtls_internal.h for detailed requirements.
 */

#ifndef MTLS_H
#define MTLS_H

#include <stdint.h>
#if defined(_WIN32)
#    include <BaseTsd.h>
#else
#    include <sys/types.h>
#endif

#include "mtls_types.h"
#include "mtls_error.h"
#include "mtls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * Context Management
 * =============================================================================
 */

/**
 * Create a new mTLS context
 *
 * The context holds TLS configuration and can be shared across multiple
 * connections. It is thread-safe for reading after creation (immutable).
 *
 * @param config Configuration (will be copied)
 * @param err Error structure to populate on failure
 * @return Context handle on success, NULL on failure
 */
MTLS_API mtls_ctx *mtls_ctx_create(const mtls_config *config, mtls_err *err);

/**
 * Free an mTLS context
 *
 * Closes all associated connections and frees resources.
 * After this call, the context handle is invalid.
 *
 * @param ctx Context to free
 */
MTLS_API void mtls_ctx_free(mtls_ctx *ctx);

/**
 * Reload certificates in a context
 *
 * Atomically reloads certificates from the paths specified in the original
 * configuration. Useful for certificate rotation without restart.
 *
 * @param ctx Context
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_ctx_reload_certs(mtls_ctx *ctx, mtls_err *err);

/**
 * Enable or disable kill-switch
 *
 * When enabled, all new connections will fail immediately.
 * Existing connections are not affected.
 *
 * @param ctx Context
 * @param enabled true to enable, false to disable
 */
MTLS_API void mtls_ctx_set_kill_switch(mtls_ctx *ctx, bool enabled);

/**
 * Check if kill-switch is enabled
 *
 * @param ctx Context
 * @return true if enabled, false otherwise
 */
MTLS_API bool mtls_ctx_is_kill_switch_enabled(const mtls_ctx *ctx);

/*
 * =============================================================================
 * Client Connections
 * =============================================================================
 */

/**
 * Connect to a remote server
 *
 * Establishes a TCP connection and performs TLS handshake with mutual
 * authentication. This is a blocking call.
 *
 * @param ctx Context
 * @param addr Address in format "host:port" (e.g., "example.com:443")
 * @param err Error structure to populate on failure
 * @return Connection handle on success, NULL on failure
 */
MTLS_API mtls_conn *mtls_connect(mtls_ctx *ctx, const char *addr, mtls_err *err);

/*
 * =============================================================================
 * Server Connections
 * =============================================================================
 */

/**
 * Create a listener for incoming connections
 *
 * Binds to a local address and listens for incoming connections.
 *
 * @param ctx Context
 * @param bind_addr Address to bind to (e.g., "0.0.0.0:8443" or "[::]:8443")
 * @param err Error structure to populate on failure
 * @return Listener handle on success, NULL on failure
 */
MTLS_API mtls_listener *mtls_listen(mtls_ctx *ctx, const char *bind_addr, mtls_err *err);

/**
 * Accept an incoming connection
 *
 * Blocks until a client connects, then performs TLS handshake with mutual
 * authentication. This is a blocking call.
 *
 * @param listener Listener
 * @param err Error structure to populate on failure
 * @return Connection handle on success, NULL on failure
 */
MTLS_API mtls_conn *mtls_accept(mtls_listener *listener, mtls_err *err);

/**
 * Shutdown a listener
 *
 * Closes the listening socket to interrupt any pending Accept() calls.
 * Does not free the listener memory. Call mtls_listener_close() after
 * all Accept() calls have returned to free the listener.
 *
 * This function is safe to call from a different thread while Accept()
 * is blocking. The Accept() call will return with an error.
 *
 * @param listener Listener to shutdown
 */
MTLS_API void mtls_listener_shutdown(mtls_listener *listener);

/**
 * Close a listener
 *
 * Stops accepting new connections and frees the listener memory.
 * Does not affect existing connections.
 *
 * For safe shutdown with concurrent Accept() calls:
 * 1. Call mtls_listener_shutdown() to close the socket
 * 2. Wait for all Accept() calls to return
 * 3. Call mtls_listener_close() to free the listener
 *
 * @param listener Listener to close
 */
MTLS_API void mtls_listener_close(mtls_listener *listener);

/*
 * =============================================================================
 * Connection I/O
 * =============================================================================
 */

/**
 * Read data from a connection
 *
 * Blocking read. Returns when data is available or an error occurs.
 *
 * @param conn Connection
 * @param buffer Buffer to read into
 * @param len Maximum number of bytes to read
 * @param err Error structure to populate on failure
 * @return Number of bytes read on success, -1 on failure, 0 on EOF
 */
MTLS_API ssize_t mtls_read(mtls_conn *conn, void *buffer, size_t len, mtls_err *err);

/**
 * Write data to a connection
 *
 * Blocking write. Returns when all data is written or an error occurs.
 *
 * @param conn Connection
 * @param buffer Buffer to write from
 * @param len Number of bytes to write
 * @param err Error structure to populate on failure
 * @return Number of bytes written on success, -1 on failure
 */
MTLS_API ssize_t mtls_write(mtls_conn *conn, const void *buffer, size_t len, mtls_err *err);

/**
 * Close a connection
 *
 * Performs TLS shutdown and closes the underlying socket.
 * After this call, the connection handle is invalid.
 *
 * @param conn Connection to close
 */
MTLS_API void mtls_close(mtls_conn *conn);

/*
 * =============================================================================
 * Connection State & Identity
 * =============================================================================
 */

/**
 * Get connection state
 *
 * @param conn Connection
 * @return Current connection state
 */
MTLS_API mtls_conn_state mtls_get_state(const mtls_conn *conn);

/**
 * Get peer identity information
 *
 * Retrieves the identity of the remote peer from the verified certificate.
 * The returned identity is valid until the connection is closed or
 * mtls_free_peer_identity() is called.
 *
 * @param conn Connection
 * @param identity Structure to populate
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_peer_identity(mtls_conn *conn, mtls_peer_identity *identity, mtls_err *err);

/**
 * Free peer identity resources
 *
 * Frees the dynamically allocated SAN array in peer identity.
 *
 * @param identity Identity structure to free
 */
MTLS_API void mtls_free_peer_identity(mtls_peer_identity *identity);

/**
 * Check if peer certificate is currently valid
 *
 * Verifies that the current time is within the certificate's validity period.
 *
 * @param identity Peer identity
 * @return true if certificate is valid, false if expired or not yet valid
 */
MTLS_API bool mtls_is_peer_cert_valid(const mtls_peer_identity *identity);

/**
 * Get time until certificate expiration
 *
 * @param identity Peer identity
 * @return Seconds until expiration, or -1 if already expired
 */
MTLS_API int64_t mtls_get_cert_ttl_seconds(const mtls_peer_identity *identity);

/**
 * Check if identity has a SPIFFE ID
 *
 * @param identity Peer identity
 * @return true if SPIFFE ID is present, false otherwise
 */
MTLS_API bool mtls_has_spiffe_id(const mtls_peer_identity *identity);

/**
 * Validate peer SANs against an allowed list
 *
 * Checks if at least one SAN from the peer certificate matches at least one
 * pattern in the allowed list. Supports exact matching, wildcard DNS matching
 * (*.example.com), and SPIFFE ID matching.
 *
 * This function is useful for implementing custom SAN validation logic after
 * connection establishment, or for validating connections that were accepted
 * without pre-configured allowed_sans in the context.
 *
 * @param identity Peer identity
 * @param allowed_sans Array of allowed SAN patterns
 * @param allowed_sans_count Number of allowed SANs
 * @return true if at least one SAN matches, false otherwise
 */
MTLS_API bool mtls_validate_peer_sans(const mtls_peer_identity *identity, const char **allowed_sans,
                                      size_t allowed_sans_count);

/**
 * Extract organization from peer certificate
 *
 * Extracts the Organization (O) field from the peer certificate subject.
 *
 * @param conn Connection
 * @param org_buf Buffer to store organization string
 * @param org_buf_len Length of organization buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_peer_organization(mtls_conn *conn, char *org_buf, size_t org_buf_len);

/**
 * Extract organizational unit from peer certificate
 *
 * Extracts the Organizational Unit (OU) field from the peer certificate subject.
 *
 * @param conn Connection
 * @param ou_buf Buffer to store organizational unit string
 * @param ou_buf_len Length of organizational unit buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_peer_org_unit(mtls_conn *conn, char *ou_buf, size_t ou_buf_len);

/**
 * Get remote address
 *
 * @param conn Connection
 * @param addr_buf Buffer to store address string
 * @param addr_buf_len Length of address buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_remote_addr(const mtls_conn *conn, char *addr_buf, size_t addr_buf_len);

/**
 * Get local address
 *
 * @param conn Connection
 * @param addr_buf Buffer to store address string
 * @param addr_buf_len Length of address buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_local_addr(const mtls_conn *conn, char *addr_buf, size_t addr_buf_len);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/* ============================================================================
 * Observability API
 * ============================================================================
 */

/**
 * Set event observers for the context
 *
 * Registers callback functions that will be invoked for various events:
 * - Connection lifecycle (connect, handshake, close)
 * - I/O operations (read, write)
 * - Policy decisions (kill-switch, identity validation)
 * - Errors and failures
 *
 * Thread safety: The callback will be invoked synchronously from the thread
 * that triggers the event. The callback must be thread-safe if the context
 * is used from multiple threads. The context lock is NOT held during callback
 * invocation, so the callback can safely call mTLS API functions.
 *
 * @param ctx Context
 * @param observers Observer configuration (copied internally), or NULL to disable
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_set_observers(mtls_ctx *ctx, const mtls_observers *observers);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * Get library version string
 *
 * @return Version string (e.g., "0.1.0")
 */
MTLS_API const char *mtls_version(void);

/**
 * Get library version components
 *
 * @param major Output for major version
 * @param minor Output for minor version
 * @param patch Output for patch version
 */
MTLS_API void mtls_version_components(int *major, int *minor, int *patch);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_H */
