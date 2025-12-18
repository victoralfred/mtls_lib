package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Config and ConfigBuilder.
 */
class ConfigTest {

    @Test
    @DisplayName("Builder creates valid config with file-based certificates")
    void testBuilderWithFiles() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .certFile("cert.pem", "key.pem")
                .build();

        assertNotNull(config);
        assertEquals("ca.pem", config.getCaCertFile());
        assertEquals("cert.pem", config.getCertFile());
        assertEquals("key.pem", config.getKeyFile());
    }

    @Test
    @DisplayName("Builder creates valid config with PEM-based certificates")
    void testBuilderWithPem() {
        byte[] caPem = "CA PEM DATA".getBytes();
        byte[] certPem = "CERT PEM DATA".getBytes();
        byte[] keyPem = "KEY PEM DATA".getBytes();

        Config config = new Config.Builder()
                .caCertPem(caPem)
                .certPem(certPem, keyPem)
                .build();

        assertNotNull(config);
        assertArrayEquals(caPem, config.getCaCertPem());
        assertArrayEquals(certPem, config.getCertPem());
        assertArrayEquals(keyPem, config.getKeyPem());
    }

    @Test
    @DisplayName("Builder sets TLS versions correctly")
    void testTlsVersions() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .minTlsVersion(Config.TlsVersion.TLS_1_2)
                .maxTlsVersion(Config.TlsVersion.TLS_1_3)
                .build();

        assertEquals(Config.TlsVersion.TLS_1_2, config.getMinTlsVersion());
        assertEquals(Config.TlsVersion.TLS_1_3, config.getMaxTlsVersion());
    }

    @Test
    @DisplayName("Builder sets boolean flags correctly")
    void testBooleanFlags() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .requireClientCert(true)
                .verifyHostname(false)
                .build();

        assertTrue(config.isRequireClientCert());
        assertFalse(config.isVerifyHostname());
    }

    @Test
    @DisplayName("Builder sets allowed SANs correctly")
    void testAllowedSans() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .allowedSans("*.example.com", "service.local")
                .addAllowedSan("spiffe://example.com/service")
                .build();

        assertEquals(3, config.getAllowedSans().size());
        assertTrue(config.getAllowedSans().contains("*.example.com"));
        assertTrue(config.getAllowedSans().contains("service.local"));
        assertTrue(config.getAllowedSans().contains("spiffe://example.com/service"));
    }

    @Test
    @DisplayName("Builder sets timeout values correctly")
    void testTimeouts() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .connectTimeoutMs(10000)
                .readTimeoutMs(20000)
                .writeTimeoutMs(15000)
                .build();

        assertEquals(10000, config.getConnectTimeoutMs());
        assertEquals(20000, config.getReadTimeoutMs());
        assertEquals(15000, config.getWriteTimeoutMs());
    }

    @Test
    @DisplayName("Validation fails when CA cert is missing")
    void testValidationFailsWithoutCaCert() {
        Config.Builder builder = new Config.Builder()
                .certFile("cert.pem", "key.pem");

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    @DisplayName("Validation fails when cert and key are mismatched")
    void testValidationFailsWithMismatchedCertKey() {
        Config.Builder builder = new Config.Builder()
                .caCertFile("ca.pem")
                .certFile("cert.pem", null);

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    @DisplayName("Validation fails with negative timeouts")
    void testValidationFailsWithNegativeTimeouts() {
        Config.Builder builder = new Config.Builder()
                .caCertFile("ca.pem")
                .connectTimeoutMs(-1);

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    @DisplayName("Builder allows method chaining")
    void testBuilderChaining() {
        Config.Builder builder = new Config.Builder();

        Config config = builder
                .caCertFile("ca.pem")
                .certFile("cert.pem", "key.pem")
                .requireClientCert(true)
                .verifyHostname(true)
                .connectTimeoutMs(5000)
                .build();

        assertNotNull(config);
    }

    @Test
    @DisplayName("Default values are set correctly")
    void testDefaultValues() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .build();

        assertEquals(Config.TlsVersion.TLS_1_2, config.getMinTlsVersion());
        assertEquals(Config.TlsVersion.TLS_1_3, config.getMaxTlsVersion());
        assertFalse(config.isRequireClientCert());
        assertTrue(config.isVerifyHostname());
        assertEquals(5000, config.getConnectTimeoutMs());
        assertEquals(30000, config.getReadTimeoutMs());
        assertEquals(30000, config.getWriteTimeoutMs());
        assertTrue(config.getAllowedSans().isEmpty());
    }

    @Test
    @DisplayName("TLS version enum values are correct")
    void testTlsVersionEnumValues() {
        assertEquals(0, Config.TlsVersion.TLS_1_2.getValue());
        assertEquals(1, Config.TlsVersion.TLS_1_3.getValue());
    }

    @Test
    @DisplayName("Config is immutable after building")
    void testConfigImmutability() {
        Config config = new Config.Builder()
                .caCertFile("ca.pem")
                .allowedSans("*.example.com")
                .build();

        // Get the list and try to modify it
        var sans = config.getAllowedSans();
        assertThrows(UnsupportedOperationException.class, () -> sans.add("hacker.com"));

        // Original config should be unchanged
        assertEquals(1, config.getAllowedSans().size());
    }
}
