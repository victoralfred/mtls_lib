package com.mtls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PeerIdentity.
 */
class PeerIdentityTest {

    @Test
    @DisplayName("PeerIdentity stores basic properties correctly")
    void testBasicProperties() {
        List<String> sans = Arrays.asList("example.com", "*.example.com");
        long now = Instant.now().getEpochSecond();
        long future = now + 3600; // 1 hour from now

        PeerIdentity identity = new PeerIdentity(
                "CN=example.com",
                sans,
                "spiffe://example.com/service",
                now,
                future
        );

        assertEquals("CN=example.com", identity.getCommonName());
        assertEquals(2, identity.getSubjectAltNames().size());
        assertTrue(identity.getSubjectAltNames().contains("example.com"));
        assertEquals("spiffe://example.com/service", identity.getSpiffeId());
        assertEquals(now, identity.getNotBefore().getEpochSecond());
        assertEquals(future, identity.getNotAfter().getEpochSecond());
    }

    @Test
    @DisplayName("PeerIdentity validates time correctly")
    void testTimeValidation() {
        long past = Instant.now().getEpochSecond() - 3600; // 1 hour ago
        long future = Instant.now().getEpochSecond() + 3600; // 1 hour from now

        // Valid certificate (current time is between notBefore and notAfter)
        PeerIdentity validIdentity = new PeerIdentity(
                "CN=valid",
                Arrays.asList("valid.com"),
                null,
                past,
                future
        );
        assertTrue(validIdentity.isValid());

        // Expired certificate
        long longAgo = Instant.now().getEpochSecond() - 7200; // 2 hours ago
        PeerIdentity expiredIdentity = new PeerIdentity(
                "CN=expired",
                Arrays.asList("expired.com"),
                null,
                longAgo,
                past
        );
        assertFalse(expiredIdentity.isValid());

        // Not yet valid certificate
        long farFuture = Instant.now().getEpochSecond() + 7200; // 2 hours from now
        PeerIdentity futureIdentity = new PeerIdentity(
                "CN=future",
                Arrays.asList("future.com"),
                null,
                future,
                farFuture
        );
        assertFalse(futureIdentity.isValid());
    }

    @Test
    @DisplayName("PeerIdentity calculates TTL correctly")
    void testTtlCalculation() {
        long now = Instant.now().getEpochSecond();
        long future = now + 3600; // 1 hour from now

        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList("test.com"),
                null,
                now,
                future
        );

        long ttl = identity.getTtlSeconds();
        assertTrue(ttl > 0 && ttl <= 3600, "TTL should be between 0 and 3600");

        // Expired certificate should have negative TTL
        long past = now - 3600;
        PeerIdentity expiredIdentity = new PeerIdentity(
                "CN=expired",
                Arrays.asList("expired.com"),
                null,
                past - 3600,
                past
        );
        assertTrue(expiredIdentity.getTtlSeconds() < 0, "Expired cert should have negative TTL");
    }

    @Test
    @DisplayName("PeerIdentity checks SPIFFE ID presence")
    void testSpiffeIdPresence() {
        // With SPIFFE ID
        PeerIdentity withSpiffe = new PeerIdentity(
                "CN=service",
                Arrays.asList("service.example.com"),
                "spiffe://example.com/service",
                0,
                Long.MAX_VALUE
        );
        assertTrue(withSpiffe.hasSpiffeId());

        // Without SPIFFE ID
        PeerIdentity withoutSpiffe = new PeerIdentity(
                "CN=service",
                Arrays.asList("service.example.com"),
                null,
                0,
                Long.MAX_VALUE
        );
        assertFalse(withoutSpiffe.hasSpiffeId());

        // With empty SPIFFE ID
        PeerIdentity emptySpiffe = new PeerIdentity(
                "CN=service",
                Arrays.asList("service.example.com"),
                "",
                0,
                Long.MAX_VALUE
        );
        assertFalse(emptySpiffe.hasSpiffeId());
    }

    @Test
    @DisplayName("matchesSan performs exact matching")
    void testExactSanMatching() {
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList("example.com", "test.local", "service.example.com"),
                null,
                0,
                Long.MAX_VALUE
        );

        assertTrue(identity.matchesSan("example.com"));
        assertTrue(identity.matchesSan("test.local"));
        assertTrue(identity.matchesSan("service.example.com"));
        assertFalse(identity.matchesSan("other.com"));
        assertFalse(identity.matchesSan("sub.example.com"));
    }

    @Test
    @DisplayName("matchesSan performs wildcard matching")
    void testWildcardSanMatching() {
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList("example.com", "foo.example.com", "bar.example.com"),
                null,
                0,
                Long.MAX_VALUE
        );

        // Wildcard pattern should match subdomains
        assertTrue(identity.matchesSan("*.example.com"));

        // But not the domain itself
        assertFalse(identity.matchesSan("*.other.com"));
    }

    @Test
    @DisplayName("matchesSan handles edge cases")
    void testSanMatchingEdgeCases() {
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList("example.com"),
                null,
                0,
                Long.MAX_VALUE
        );

        assertFalse(identity.matchesSan(null));
        assertFalse(identity.matchesSan(""));
    }

    @Test
    @DisplayName("SANs list is immutable")
    void testSansImmutability() {
        List<String> originalSans = Arrays.asList("example.com", "test.com");
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                originalSans,
                null,
                0,
                Long.MAX_VALUE
        );

        List<String> retrievedSans = identity.getSubjectAltNames();
        assertThrows(UnsupportedOperationException.class,
                () -> retrievedSans.add("hacker.com"));

        // Original should be unchanged
        assertEquals(2, identity.getSubjectAltNames().size());
    }

    @Test
    @DisplayName("toString provides useful information")
    void testToString() {
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList("example.com", "test.com"),
                "spiffe://example.com/test",
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond() + 3600
        );

        String str = identity.toString();
        assertTrue(str.contains("CN=test"));
        assertTrue(str.contains("sans=2"));
        assertTrue(str.contains("spiffeId=spiffe://example.com/test"));
        assertTrue(str.contains("valid="));
        assertTrue(str.contains("ttl="));
    }

    @Test
    @DisplayName("PeerIdentity handles empty SANs list")
    void testEmptySansList() {
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList(),
                null,
                0,
                Long.MAX_VALUE
        );

        assertNotNull(identity.getSubjectAltNames());
        assertEquals(0, identity.getSubjectAltNames().size());
        assertFalse(identity.matchesSan("any.com"));
    }

    @Test
    @DisplayName("Instant conversion from Unix timestamps works correctly")
    void testInstantConversion() {
        long unixTimestamp = 1640000000L; // Dec 20, 2021
        PeerIdentity identity = new PeerIdentity(
                "CN=test",
                Arrays.asList("test.com"),
                null,
                unixTimestamp,
                unixTimestamp + 3600
        );

        assertEquals(unixTimestamp, identity.getNotBefore().getEpochSecond());
        assertEquals(unixTimestamp + 3600, identity.getNotAfter().getEpochSecond());
    }

    @Test
    @DisplayName("Wildcard matching works with actual SAN values")
    void testWildcardMatchingWithSanValues() {
        // Identity with a wildcard SAN
        PeerIdentity identity = new PeerIdentity(
                "CN=*.example.com",
                Arrays.asList("*.example.com"),
                null,
                0,
                Long.MAX_VALUE
        );

        // Should match the wildcard pattern itself
        assertTrue(identity.matchesSan("*.example.com"));

        // Should NOT match specific subdomains (the pattern matches the SAN, not evaluates it)
        assertFalse(identity.matchesSan("foo.example.com"));
    }
}
