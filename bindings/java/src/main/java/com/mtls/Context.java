package com.mtls;

/**
 * mTLS context for creating connections and listeners.
 *
 * The context holds the TLS configuration and can be used to create
 * multiple connections or listeners. It is thread-safe and can be
 * shared across threads.
 *
 * <p>Example usage:
 * <pre>{@code
 * Config config = new Config.Builder()
 *     .caCertFile("ca.pem")
 *     .certFile("client.pem", "client.key")
 *     .build();
 *
 * try (Context ctx = new Context(config)) {
 *     Connection conn = ctx.connect("server.example.com:8443");
 *     // Use connection...
 * }
 * }</pre>
 */
public class Context implements AutoCloseable {
    static {
        // Load the native library
        System.loadLibrary("mtls_jni");
    }

    private long nativeHandle;
    private boolean closed = false;

    /**
     * Creates a new mTLS context from the given configuration.
     *
     * @param config the configuration
     * @throws MtlsException if context creation fails
     */
    public Context(Config config) throws MtlsException {
        if (config == null) {
            throw new IllegalArgumentException("Config cannot be null");
        }
        config.validate();
        this.nativeHandle = nativeCreate(config);
    }

    /**
     * Connects to a remote mTLS server.
     *
     * The address should be in the format "host:port".
     *
     * @param address the server address
     * @return a new Connection
     * @throws MtlsException if connection fails
     */
    public Connection connect(String address) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Context is closed");
        }
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Address cannot be null or empty");
        }
        long connectionHandle = nativeConnect(nativeHandle, address);
        return new Connection(connectionHandle);
    }

    /**
     * Creates a listener bound to the given address.
     *
     * The address should be in the format "host:port" or ":port".
     *
     * @param address the bind address
     * @return a new Listener
     * @throws MtlsException if listener creation fails
     */
    public Listener listen(String address) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Context is closed");
        }
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Address cannot be null or empty");
        }
        long listenerHandle = nativeListen(nativeHandle, address);
        return new Listener(listenerHandle, address);
    }

    /**
     * Enables or disables the kill switch.
     *
     * When enabled, all new connections will fail immediately.
     * Existing connections are not affected. Use this for emergency shutdown scenarios.
     *
     * @param enabled true to enable kill switch, false to disable
     */
    public void setKillSwitch(boolean enabled) {
        if (!closed) {
            nativeSetKillSwitch(nativeHandle, enabled);
        }
    }

    /**
     * Checks if the kill switch is currently enabled.
     *
     * @return true if kill switch is enabled
     */
    public boolean isKillSwitchEnabled() {
        if (closed) {
            return false;
        }
        return nativeIsKillSwitchEnabled(nativeHandle);
    }

    /**
     * Closes the context and releases all resources.
     *
     * After calling this method, the context cannot be used anymore.
     */
    @Override
    public synchronized void close() {
        if (!closed && nativeHandle != 0) {
            nativeFree(nativeHandle);
            nativeHandle = 0;
            closed = true;
        }
    }

    /**
     * Checks if the context is closed.
     *
     * @return true if closed
     */
    public boolean isClosed() {
        return closed;
    }

    // Native methods
    private native long nativeCreate(Config config) throws MtlsException;
    private native long nativeConnect(long contextHandle, String address) throws MtlsException;
    private native long nativeListen(long contextHandle, String address) throws MtlsException;
    private native void nativeSetKillSwitch(long contextHandle, boolean enabled);
    private native boolean nativeIsKillSwitchEnabled(long contextHandle);
    private native void nativeFree(long contextHandle);

    /**
     * Returns the library version string.
     *
     * @return the version string
     */
    public static native String getVersion();

    /**
     * Returns the library version components.
     *
     * @return an array [major, minor, patch]
     */
    public static native int[] getVersionComponents();
}
