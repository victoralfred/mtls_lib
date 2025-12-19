package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Integration tests that require native library to be loaded.
 *
 * These tests are only run when the system property "mtls.native.test" is set to "true".
 *
 * Run with: mvn test -Dmtls.native.test=true
 */
@EnabledIfSystemProperty(named = "mtls.native.test", matches = "true",
        disabledReason = "Native library integration tests disabled by default")
class IntegrationTest {

    @Test
    @DisplayName("Native library can be loaded")
    void testNativeLibraryLoading() {
        try {
            System.loadLibrary("mtls_jni");
        } catch (UnsatisfiedLinkError e) {
            fail("Failed to load native library: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("Can retrieve library version")
    void testGetVersion() {
        assumeNativeLibraryAvailable();

        String version = Context.getVersion();
        assertNotNull(version);
        assertFalse(version.isEmpty());
        assertTrue(version.matches("\\d+\\.\\d+\\.\\d+"),
                "Version should match pattern X.Y.Z");
    }

    @Test
    @DisplayName("Can retrieve version components")
    void testGetVersionComponents() {
        assumeNativeLibraryAvailable();

        int[] components = Context.getVersionComponents();
        assertNotNull(components);
        assertEquals(3, components.length);
        assertTrue(components[0] >= 0, "Major version should be non-negative");
        assertTrue(components[1] >= 0, "Minor version should be non-negative");
        assertTrue(components[2] >= 0, "Patch version should be non-negative");
    }

    @Test
    @DisplayName("Context creation fails with invalid config")
    void testContextCreationFailsWithInvalidConfig() {
        assumeNativeLibraryAvailable();

        Config config = new Config.Builder()
                .caCertFile("/nonexistent/ca.pem")
                .build();

        assertThrows(MtlsException.class, () -> new Context(config));
    }

    @Test
    @DisplayName("Context creation requires valid config")
    void testContextCreationRequiresValidConfig() {
        assumeNativeLibraryAvailable();

        // This should fail because the certificate file doesn't exist
        Config config = new Config.Builder()
                .caCertFile("/tmp/nonexistent_ca_file_12345.pem")
                .build();

        MtlsException exception = assertThrows(MtlsException.class,
                () -> new Context(config));

        // Should be a config or TLS error
        assertTrue(exception.isConfigError() || exception.isTlsError(),
                "Should be a config or TLS error, got: " + exception.getCategory());
    }

    /**
     * Helper method to check if native library is available.
     */
    private void assumeNativeLibraryAvailable() {
        try {
            System.loadLibrary("mtls_jni");
        } catch (UnsatisfiedLinkError e) {
            assumeTrue(false, "Native library not available: " + e.getMessage());
        }
    }
}
