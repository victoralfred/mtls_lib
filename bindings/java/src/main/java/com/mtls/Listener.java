package com.mtls;

/**
 * An mTLS listener for accepting incoming connections.
 *
 * Implements AutoCloseable for automatic resource management.
 *
 * <p>Example usage:
 * <pre>{@code
 * Config config = new Config.Builder()
 *     .caCertFile("ca.pem")
 *     .certFile("server.pem", "server.key")
 *     .requireClientCert(true)
 *     .build();
 *
 * try (Context ctx = new Context(config);
 *      Listener listener = ctx.listen("0.0.0.0:8443")) {
 *     while (true) {
 *         try (Connection conn = listener.accept()) {
 *             // Handle connection...
 *         }
 *     }
 * }
 * }</pre>
 */
public class Listener implements AutoCloseable {
    private long nativeHandle;
    private final String address;
    private boolean closed = false;

    /**
     * Package-private constructor called from Context.
     */
    Listener(long nativeHandle, String address) {
        this.nativeHandle = nativeHandle;
        this.address = address;
    }

    /**
     * Accepts an incoming connection.
     *
     * This method blocks until a client connects and completes the TLS handshake.
     *
     * @return a new Connection
     * @throws MtlsException if accept fails
     */
    public synchronized Connection accept() throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Listener is closed");
        }
        long connectionHandle = nativeAccept(nativeHandle);
        return new Connection(connectionHandle);
    }

    /**
     * Accepts an incoming connection with a timeout.
     *
     * @param timeoutMs timeout in milliseconds, or 0 for no timeout
     * @return a new Connection
     * @throws MtlsException if accept fails or times out
     */
    public synchronized Connection accept(int timeoutMs) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Listener is closed");
        }
        if (timeoutMs < 0) {
            throw new IllegalArgumentException("Timeout must be non-negative");
        }
        long connectionHandle = nativeAcceptTimeout(nativeHandle, timeoutMs);
        return new Connection(connectionHandle);
    }

    /**
     * Shuts down the listener.
     *
     * This stops the listener from accepting new connections.
     * Existing connections are not affected.
     */
    public synchronized void shutdown() {
        if (!closed && nativeHandle != 0) {
            nativeShutdown(nativeHandle);
        }
    }

    /**
     * Gets the address the listener is bound to.
     *
     * @return the bind address
     */
    public String getAddress() {
        return address;
    }

    /**
     * Checks if the listener is closed.
     *
     * @return true if closed
     */
    public synchronized boolean isClosed() {
        return closed;
    }

    /**
     * Closes the listener and releases all resources.
     */
    @Override
    public synchronized void close() {
        if (!closed && nativeHandle != 0) {
            nativeClose(nativeHandle);
            nativeHandle = 0;
            closed = true;
        }
    }

    // Native methods
    private native long nativeAccept(long listenerHandle) throws MtlsException;
    private native long nativeAcceptTimeout(long listenerHandle, int timeoutMs) throws MtlsException;
    private native void nativeShutdown(long listenerHandle);
    private native void nativeClose(long listenerHandle);
}
