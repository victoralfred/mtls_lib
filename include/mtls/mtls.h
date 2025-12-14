/**
 * @file mtls.h
 * @brief Main public API for the mTLS library
 *
 * This is the primary header file that applications should include.
 * It provides a minimal, secure, and auditable mTLS transport layer.
 */

#ifndef MTLS_H
#define MTLS_H

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
MTLS_API mtls_ctx* mtls_ctx_create(const mtls_config* config, mtls_err* err);

/**
 * Free an mTLS context
 *
 * Closes all associated connections and frees resources.
 * After this call, the context handle is invalid.
 *
 * @param ctx Context to free
 */
MTLS_API void mtls_ctx_free(mtls_ctx* ctx);

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
MTLS_API int mtls_ctx_reload_certs(mtls_ctx* ctx, mtls_err* err);

/**
 * Enable or disable kill-switch
 *
 * When enabled, all new connections will fail immediately.
 * Existing connections are not affected.
 *
 * @param ctx Context
 * @param enabled true to enable, false to disable
 */
MTLS_API void mtls_ctx_set_kill_switch(mtls_ctx* ctx, bool enabled);

/**
 * Check if kill-switch is enabled
 *
 * @param ctx Context
 * @return true if enabled, false otherwise
 */
MTLS_API bool mtls_ctx_is_kill_switch_enabled(const mtls_ctx* ctx);

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
MTLS_API mtls_conn* mtls_connect(mtls_ctx* ctx, const char* addr, mtls_err* err);

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
MTLS_API mtls_listener* mtls_listen(mtls_ctx* ctx, const char* bind_addr, mtls_err* err);

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
MTLS_API mtls_conn* mtls_accept(mtls_listener* listener, mtls_err* err);

/**
 * Close a listener
 *
 * Stops accepting new connections. Does not affect existing connections.
 *
 * @param listener Listener to close
 */
MTLS_API void mtls_listener_close(mtls_listener* listener);

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
MTLS_API ssize_t mtls_read(mtls_conn* conn, void* buffer, size_t len, mtls_err* err);

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
MTLS_API ssize_t mtls_write(mtls_conn* conn, const void* buffer, size_t len, mtls_err* err);

/**
 * Close a connection
 *
 * Performs TLS shutdown and closes the underlying socket.
 * After this call, the connection handle is invalid.
 *
 * @param conn Connection to close
 */
MTLS_API void mtls_close(mtls_conn* conn);

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
MTLS_API mtls_conn_state mtls_get_state(const mtls_conn* conn);

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
MTLS_API int mtls_get_peer_identity(mtls_conn* conn,
                                     mtls_peer_identity* identity,
                                     mtls_err* err);

/**
 * Free peer identity resources
 *
 * Frees the dynamically allocated SAN array in peer identity.
 *
 * @param identity Identity structure to free
 */
MTLS_API void mtls_free_peer_identity(mtls_peer_identity* identity);

/**
 * Get remote address
 *
 * @param conn Connection
 * @param addr_buf Buffer to store address string
 * @param addr_buf_len Length of address buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_remote_addr(const mtls_conn* conn,
                                   char* addr_buf,
                                   size_t addr_buf_len);

/**
 * Get local address
 *
 * @param conn Connection
 * @param addr_buf Buffer to store address string
 * @param addr_buf_len Length of address buffer
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_get_local_addr(const mtls_conn* conn,
                                  char* addr_buf,
                                  size_t addr_buf_len);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * Get library version string
 *
 * @return Version string (e.g., "0.1.0")
 */
MTLS_API const char* mtls_version(void);

/**
 * Get library version components
 *
 * @param major Output for major version
 * @param minor Output for minor version
 * @param patch Output for patch version
 */
MTLS_API void mtls_version_components(int* major, int* minor, int* patch);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_H */
