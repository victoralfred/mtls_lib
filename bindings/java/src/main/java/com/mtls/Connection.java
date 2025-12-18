package com.mtls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An mTLS connection for client-server communication.
 *
 * Provides read and write operations over a mutual TLS connection.
 * Implements AutoCloseable for automatic resource management.
 *
 * <p>Example usage:
 * <pre>{@code
 * try (Connection conn = ctx.connect("server:8443")) {
 *     conn.write("Hello, server!".getBytes());
 *     byte[] response = conn.read(1024);
 * }
 * }</pre>
 */
public class Connection implements AutoCloseable {
    private long nativeHandle;
    private boolean closed = false;
    private final ConnectionInputStream inputStream;
    private final ConnectionOutputStream outputStream;

    /**
     * Connection state enumeration.
     */
    public enum State {
        CONNECTING(0),
        HANDSHAKE(1),
        ESTABLISHED(2),
        CLOSING(3),
        CLOSED(4),
        ERROR(5);

        private final int value;

        State(int value) {
            this.value = value;
        }

        public static State fromValue(int value) {
            for (State state : values()) {
                if (state.value == value) {
                    return state;
                }
            }
            return ERROR;
        }
    }

    /**
     * Package-private constructor called from Context.
     */
    Connection(long nativeHandle) {
        this.nativeHandle = nativeHandle;
        this.inputStream = new ConnectionInputStream();
        this.outputStream = new ConnectionOutputStream();
    }

    /**
     * Writes data to the connection.
     *
     * @param data the data to write
     * @return the number of bytes written
     * @throws MtlsException if write fails
     */
    public int write(byte[] data) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Connection is closed");
        }
        if (data == null || data.length == 0) {
            return 0;
        }
        return nativeWrite(nativeHandle, data, 0, data.length);
    }

    /**
     * Writes a portion of the data buffer to the connection.
     *
     * @param data the data buffer
     * @param offset the offset in the buffer
     * @param length the number of bytes to write
     * @return the number of bytes written
     * @throws MtlsException if write fails
     */
    public int write(byte[] data, int offset, int length) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Connection is closed");
        }
        if (data == null || length == 0) {
            return 0;
        }
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IndexOutOfBoundsException("Invalid offset or length");
        }
        return nativeWrite(nativeHandle, data, offset, length);
    }

    /**
     * Reads data from the connection.
     *
     * @param maxBytes the maximum number of bytes to read
     * @return the data read
     * @throws MtlsException if read fails
     */
    public byte[] read(int maxBytes) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Connection is closed");
        }
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        return nativeRead(nativeHandle, maxBytes);
    }

    /**
     * Reads data into the provided buffer.
     *
     * @param buffer the buffer to read into
     * @return the number of bytes read, or -1 on EOF
     * @throws MtlsException if read fails
     */
    public int read(byte[] buffer) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Connection is closed");
        }
        if (buffer == null || buffer.length == 0) {
            return 0;
        }
        return nativeReadInto(nativeHandle, buffer, 0, buffer.length);
    }

    /**
     * Reads data into a portion of the provided buffer.
     *
     * @param buffer the buffer to read into
     * @param offset the offset in the buffer
     * @param length the maximum number of bytes to read
     * @return the number of bytes read, or -1 on EOF
     * @throws MtlsException if read fails
     */
    public int read(byte[] buffer, int offset, int length) throws MtlsException {
        if (closed) {
            throw new IllegalStateException("Connection is closed");
        }
        if (buffer == null || length == 0) {
            return 0;
        }
        if (offset < 0 || length < 0 || offset + length > buffer.length) {
            throw new IndexOutOfBoundsException("Invalid offset or length");
        }
        return nativeReadInto(nativeHandle, buffer, offset, length);
    }

    /**
     * Returns the connection state.
     *
     * @return the current state
     */
    public State getState() {
        if (closed) {
            return State.CLOSED;
        }
        return State.fromValue(nativeGetState(nativeHandle));
    }

    /**
     * Checks if the connection is established.
     *
     * @return true if established
     */
    public boolean isEstablished() {
        return getState() == State.ESTABLISHED;
    }

    /**
     * Gets the peer's identity from their certificate.
     *
     * @return the peer identity, or null if not available
     */
    public PeerIdentity getPeerIdentity() {
        if (closed) {
            return null;
        }
        return nativeGetPeerIdentity(nativeHandle);
    }

    /**
     * Gets the remote address of the connection.
     *
     * @return the remote address (e.g., "192.168.1.1:443"), or null if not available
     */
    public String getRemoteAddress() {
        if (closed) {
            return null;
        }
        return nativeGetRemoteAddress(nativeHandle);
    }

    /**
     * Gets the local address of the connection.
     *
     * @return the local address (e.g., "192.168.1.2:54321"), or null if not available
     */
    public String getLocalAddress() {
        if (closed) {
            return null;
        }
        return nativeGetLocalAddress(nativeHandle);
    }

    /**
     * Returns an InputStream for reading from this connection.
     *
     * @return an InputStream
     */
    public InputStream getInputStream() {
        return inputStream;
    }

    /**
     * Returns an OutputStream for writing to this connection.
     *
     * @return an OutputStream
     */
    public OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * Closes the connection and releases all resources.
     */
    @Override
    public synchronized void close() {
        if (!closed && nativeHandle != 0) {
            nativeClose(nativeHandle);
            nativeHandle = 0;
            closed = true;
        }
    }

    /**
     * Checks if the connection is closed.
     *
     * @return true if closed
     */
    public boolean isClosed() {
        return closed;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    // Native methods
    private native int nativeWrite(long connectionHandle, byte[] data, int offset, int length) throws MtlsException;
    private native byte[] nativeRead(long connectionHandle, int maxBytes) throws MtlsException;
    private native int nativeReadInto(long connectionHandle, byte[] buffer, int offset, int length) throws MtlsException;
    private native int nativeGetState(long connectionHandle);
    private native PeerIdentity nativeGetPeerIdentity(long connectionHandle);
    private native String nativeGetRemoteAddress(long connectionHandle);
    private native String nativeGetLocalAddress(long connectionHandle);
    private native void nativeClose(long connectionHandle);

    /**
     * InputStream wrapper for Connection.
     */
    private class ConnectionInputStream extends InputStream {
        @Override
        public int read() throws IOException {
            byte[] buf = new byte[1];
            int n = read(buf, 0, 1);
            return (n == 1) ? (buf[0] & 0xFF) : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            try {
                return Connection.this.read(b, off, len);
            } catch (MtlsException e) {
                throw new IOException("mTLS read failed", e);
            }
        }

        @Override
        public void close() throws IOException {
            Connection.this.close();
        }
    }

    /**
     * OutputStream wrapper for Connection.
     */
    private class ConnectionOutputStream extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            byte[] buf = new byte[] { (byte) b };
            write(buf, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                int written = 0;
                while (written < len) {
                    int n = Connection.this.write(b, off + written, len - written);
                    if (n <= 0) {
                        throw new IOException("Write failed: no bytes written");
                    }
                    written += n;
                }
            } catch (MtlsException e) {
                throw new IOException("mTLS write failed", e);
            }
        }

        @Override
        public void close() throws IOException {
            Connection.this.close();
        }
    }
}
