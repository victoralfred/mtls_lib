package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for MtlsException and error categorization.
 */
class MtlsExceptionTest {

    @Test
    @DisplayName("Exception stores error code and message correctly")
    void testExceptionBasicProperties() {
        MtlsException ex = new MtlsException("Connection failed", 201);

        assertEquals(201, ex.getErrorCode());
        assertEquals("Connection failed", ex.getMessage());
    }

    @Test
    @DisplayName("Exception can store a cause")
    void testExceptionWithCause() {
        Throwable cause = new RuntimeException("Root cause");
        MtlsException ex = new MtlsException("Wrapped error", 301, cause);

        assertEquals(301, ex.getErrorCode());
        assertEquals("Wrapped error", ex.getMessage());
        assertSame(cause, ex.getCause());
    }

    @Test
    @DisplayName("Config errors are categorized correctly (100-199)")
    void testConfigErrorCategory() {
        MtlsException ex = new MtlsException("Config error", 150);

        assertEquals(MtlsException.ErrorCategory.CONFIG, ex.getCategory());
        assertTrue(ex.isConfigError());
        assertFalse(ex.isNetworkError());
        assertFalse(ex.isTlsError());
    }

    @Test
    @DisplayName("Network errors are categorized correctly (200-299)")
    void testNetworkErrorCategory() {
        MtlsException ex = new MtlsException("Network error", 250);

        assertEquals(MtlsException.ErrorCategory.NETWORK, ex.getCategory());
        assertTrue(ex.isNetworkError());
        assertFalse(ex.isConfigError());
        assertFalse(ex.isTlsError());
    }

    @Test
    @DisplayName("TLS errors are categorized correctly (300-399)")
    void testTlsErrorCategory() {
        MtlsException ex = new MtlsException("TLS error", 350);

        assertEquals(MtlsException.ErrorCategory.TLS, ex.getCategory());
        assertTrue(ex.isTlsError());
        assertFalse(ex.isNetworkError());
        assertFalse(ex.isIdentityError());
    }

    @Test
    @DisplayName("Identity errors are categorized correctly (400-499)")
    void testIdentityErrorCategory() {
        MtlsException ex = new MtlsException("Identity error", 450);

        assertEquals(MtlsException.ErrorCategory.IDENTITY, ex.getCategory());
        assertTrue(ex.isIdentityError());
        assertFalse(ex.isTlsError());
        assertFalse(ex.isPolicyError());
    }

    @Test
    @DisplayName("Policy errors are categorized correctly (500-599)")
    void testPolicyErrorCategory() {
        MtlsException ex = new MtlsException("Policy error", 550);

        assertEquals(MtlsException.ErrorCategory.POLICY, ex.getCategory());
        assertTrue(ex.isPolicyError());
        assertFalse(ex.isIdentityError());
        assertFalse(ex.isIoError());
    }

    @Test
    @DisplayName("I/O errors are categorized correctly (600-699)")
    void testIoErrorCategory() {
        MtlsException ex = new MtlsException("I/O error", 650);

        assertEquals(MtlsException.ErrorCategory.IO, ex.getCategory());
        assertTrue(ex.isIoError());
        assertFalse(ex.isPolicyError());
        assertFalse(ex.isNetworkError());
    }

    @Test
    @DisplayName("Unknown errors are categorized as UNKNOWN")
    void testUnknownErrorCategory() {
        MtlsException ex = new MtlsException("Unknown error", 999);

        assertEquals(MtlsException.ErrorCategory.UNKNOWN, ex.getCategory());
        assertFalse(ex.isConfigError());
        assertFalse(ex.isNetworkError());
        assertFalse(ex.isTlsError());
    }

    @Test
    @DisplayName("Error category boundary values")
    void testCategoryBoundaries() {
        // Test boundary values for each category
        assertEquals(MtlsException.ErrorCategory.CONFIG,
                new MtlsException("", 100).getCategory());
        assertEquals(MtlsException.ErrorCategory.CONFIG,
                new MtlsException("", 199).getCategory());

        assertEquals(MtlsException.ErrorCategory.NETWORK,
                new MtlsException("", 200).getCategory());
        assertEquals(MtlsException.ErrorCategory.NETWORK,
                new MtlsException("", 299).getCategory());

        assertEquals(MtlsException.ErrorCategory.TLS,
                new MtlsException("", 300).getCategory());
        assertEquals(MtlsException.ErrorCategory.TLS,
                new MtlsException("", 399).getCategory());
    }

    @Test
    @DisplayName("toString includes all relevant information")
    void testToString() {
        MtlsException ex = new MtlsException("Test error", 201);
        String str = ex.toString();

        assertTrue(str.contains("201"));
        assertTrue(str.contains("NETWORK"));
        assertTrue(str.contains("Test error"));
    }

    @Test
    @DisplayName("ErrorCategory enum has correct methods")
    void testErrorCategoryMethods() {
        assertTrue(MtlsException.ErrorCategory.CONFIG.isConfig());
        assertFalse(MtlsException.ErrorCategory.CONFIG.isNetwork());

        assertTrue(MtlsException.ErrorCategory.NETWORK.isNetwork());
        assertFalse(MtlsException.ErrorCategory.NETWORK.isTls());

        assertTrue(MtlsException.ErrorCategory.TLS.isTls());
        assertFalse(MtlsException.ErrorCategory.TLS.isIdentity());

        assertTrue(MtlsException.ErrorCategory.IDENTITY.isIdentity());
        assertFalse(MtlsException.ErrorCategory.IDENTITY.isPolicy());

        assertTrue(MtlsException.ErrorCategory.POLICY.isPolicy());
        assertFalse(MtlsException.ErrorCategory.POLICY.isIo());

        assertTrue(MtlsException.ErrorCategory.IO.isIo());
        assertFalse(MtlsException.ErrorCategory.IO.isConfig());
    }

    @Test
    @DisplayName("ErrorCategory.fromCode handles edge cases")
    void testFromCodeEdgeCases() {
        assertEquals(MtlsException.ErrorCategory.UNKNOWN,
                MtlsException.ErrorCategory.fromCode(-1));
        assertEquals(MtlsException.ErrorCategory.UNKNOWN,
                MtlsException.ErrorCategory.fromCode(0));
        assertEquals(MtlsException.ErrorCategory.UNKNOWN,
                MtlsException.ErrorCategory.fromCode(99));
        assertEquals(MtlsException.ErrorCategory.UNKNOWN,
                MtlsException.ErrorCategory.fromCode(700));
        assertEquals(MtlsException.ErrorCategory.UNKNOWN,
                MtlsException.ErrorCategory.fromCode(Integer.MAX_VALUE));
    }
}
