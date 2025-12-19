package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Connection.State and other non-native Connection methods.
 */
class ConnectionTest {

    @Test
    @DisplayName("State enum values are defined correctly")
    void testStateEnumValues() {
        assertEquals(0, Connection.State.CONNECTING.ordinal());
        assertEquals(1, Connection.State.HANDSHAKE.ordinal());
        assertEquals(2, Connection.State.ESTABLISHED.ordinal());
        assertEquals(3, Connection.State.CLOSING.ordinal());
        assertEquals(4, Connection.State.CLOSED.ordinal());
        assertEquals(5, Connection.State.ERROR.ordinal());
    }

    @Test
    @DisplayName("State.fromValue converts integer to enum correctly")
    void testStateFromValue() {
        assertEquals(Connection.State.CONNECTING, Connection.State.fromValue(0));
        assertEquals(Connection.State.HANDSHAKE, Connection.State.fromValue(1));
        assertEquals(Connection.State.ESTABLISHED, Connection.State.fromValue(2));
        assertEquals(Connection.State.CLOSING, Connection.State.fromValue(3));
        assertEquals(Connection.State.CLOSED, Connection.State.fromValue(4));
        assertEquals(Connection.State.ERROR, Connection.State.fromValue(5));
    }

    @Test
    @DisplayName("State.fromValue returns ERROR for invalid values")
    void testStateFromValueInvalid() {
        assertEquals(Connection.State.ERROR, Connection.State.fromValue(-1));
        assertEquals(Connection.State.ERROR, Connection.State.fromValue(999));
        assertEquals(Connection.State.ERROR, Connection.State.fromValue(Integer.MAX_VALUE));
    }

    @Test
    @DisplayName("Connection state names are descriptive")
    void testStateNames() {
        assertEquals("CONNECTING", Connection.State.CONNECTING.name());
        assertEquals("HANDSHAKE", Connection.State.HANDSHAKE.name());
        assertEquals("ESTABLISHED", Connection.State.ESTABLISHED.name());
        assertEquals("CLOSING", Connection.State.CLOSING.name());
        assertEquals("CLOSED", Connection.State.CLOSED.name());
        assertEquals("ERROR", Connection.State.ERROR.name());
    }

    @Test
    @DisplayName("All State enum values can be retrieved")
    void testAllStateValues() {
        Connection.State[] states = Connection.State.values();
        assertEquals(6, states.length);
        assertArrayEquals(new Connection.State[]{
                Connection.State.CONNECTING,
                Connection.State.HANDSHAKE,
                Connection.State.ESTABLISHED,
                Connection.State.CLOSING,
                Connection.State.CLOSED,
                Connection.State.ERROR
        }, states);
    }

    @Test
    @DisplayName("State enum can be used in switch statements")
    void testStateInSwitch() {
        Connection.State state = Connection.State.ESTABLISHED;

        String result = switch (state) {
            case CONNECTING -> "connecting";
            case HANDSHAKE -> "handshake";
            case ESTABLISHED -> "established";
            case CLOSING -> "closing";
            case CLOSED -> "closed";
            case ERROR -> "error";
        };

        assertEquals("established", result);
    }

    @Test
    @DisplayName("State enum equality works correctly")
    void testStateEquality() {
        Connection.State state1 = Connection.State.ESTABLISHED;
        Connection.State state2 = Connection.State.ESTABLISHED;
        Connection.State state3 = Connection.State.CLOSED;

        assertEquals(state1, state2);
        assertNotEquals(state1, state3);
        assertSame(state1, state2); // Enums are singletons
    }

    // Note: Tests for actual Connection operations (read, write, etc.) require
    // native library initialization and actual TLS connections, which are better
    // suited for integration tests rather than unit tests.
}
