package com.mtls;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Peer identity information extracted from the peer's certificate.
 *
 * Contains the Common Name, Subject Alternative Names (SANs), SPIFFE ID,
 * and certificate validity period.
 */
public class PeerIdentity {
    private final String commonName;
    private final List<String> subjectAltNames;
    private final String spiffeId;
    private final Instant notBefore;
    private final Instant notAfter;

    /**
     * Constructs a PeerIdentity.
     *
     * @param commonName the Common Name from the certificate
     * @param subjectAltNames list of Subject Alternative Names
     * @param spiffeId the SPIFFE ID (if present in URI SANs)
     * @param notBefore certificate validity start time (Unix timestamp in seconds)
     * @param notAfter certificate validity end time (Unix timestamp in seconds)
     */
    public PeerIdentity(String commonName, List<String> subjectAltNames,
                       String spiffeId, long notBefore, long notAfter) {
        this.commonName = commonName;
        this.subjectAltNames = new ArrayList<>(subjectAltNames);
        this.spiffeId = spiffeId;
        this.notBefore = Instant.ofEpochSecond(notBefore);
        this.notAfter = Instant.ofEpochSecond(notAfter);
    }

    /**
     * Returns the Common Name (CN) from the certificate.
     *
     * @return the common name, or null if not present
     */
    public String getCommonName() {
        return commonName;
    }

    /**
     * Returns the Subject Alternative Names (SANs) from the certificate.
     *
     * @return unmodifiable list of SANs
     */
    public List<String> getSubjectAltNames() {
        return Collections.unmodifiableList(subjectAltNames);
    }

    /**
     * Returns the SPIFFE ID extracted from URI SANs.
     *
     * @return the SPIFFE ID, or null if not present
     */
    public String getSpiffeId() {
        return spiffeId;
    }

    /**
     * Returns the certificate's "not before" time.
     *
     * @return the start of validity period
     */
    public Instant getNotBefore() {
        return notBefore;
    }

    /**
     * Returns the certificate's "not after" time.
     *
     * @return the end of validity period
     */
    public Instant getNotAfter() {
        return notAfter;
    }

    /**
     * Checks if the certificate is currently valid based on time.
     *
     * @return true if current time is within certificate validity period
     */
    public boolean isValid() {
        Instant now = Instant.now();
        return now.isAfter(notBefore) && now.isBefore(notAfter);
    }

    /**
     * Returns the time-to-live (TTL) in seconds until the certificate expires.
     *
     * @return TTL in seconds, or negative if expired
     */
    public long getTtlSeconds() {
        return notAfter.getEpochSecond() - Instant.now().getEpochSecond();
    }

    /**
     * Checks if the identity has a SPIFFE ID.
     *
     * @return true if a SPIFFE ID is present
     */
    public boolean hasSpiffeId() {
        return spiffeId != null && !spiffeId.isEmpty();
    }

    /**
     * Checks if any of the SANs or the SPIFFE ID match the given pattern.
     *
     * Supports:
     * - Exact matches
     * - DNS wildcard patterns (*.example.com)
     * - SPIFFE ID wildcard patterns (spiffe://example.com/*)
     *
     * @param pattern the pattern to match against
     * @return true if any SAN or SPIFFE ID matches the pattern
     */
    public boolean matchesSan(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return false;
        }

        // Check SANs
        for (String san : subjectAltNames) {
            if (matchesSanPattern(san, pattern)) {
                return true;
            }
        }

        // Also check SPIFFE ID (similar to Go implementation)
        if (spiffeId != null && !spiffeId.isEmpty()) {
            if (matchesSanPattern(spiffeId, pattern)) {
                return true;
            }
        }

        return false;
    }

    private boolean matchesSanPattern(String san, String pattern) {
        // Exact match
        if (san.equals(pattern)) {
            return true;
        }

        // DNS wildcard match (*.example.com matches foo.example.com)
        if (pattern.length() > 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            if (san.length() <= suffix.length()) {
                return false;
            }
            // Check that SAN ends with suffix and has at least one character before it
            if (san.endsWith(suffix)) {
                String prefix = san.substring(0, san.length() - suffix.length());
                // Single-level wildcard: prefix should not contain dots
                return !prefix.contains(".");
            }
            return false;
        }

        // SPIFFE ID wildcard match (spiffe://example.com/* matches spiffe://example.com/service)
        if (pattern.length() > 2 && pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2); // "spiffe://example.com"
            if (san.length() < prefix.length()) {
                return false;
            }
            // Check if SAN starts with the prefix
            if (!san.startsWith(prefix)) {
                return false;
            }
            // For SPIFFE IDs, the remaining part after the prefix should be a valid path
            // (starts with / and contains no wildcards)
            String remaining = san.substring(prefix.length());
            if (remaining.isEmpty()) {
                // Wildcard pattern requires a path component
                // Exact match (no path) should be handled by exact match logic, not wildcard
                return false;
            }
            // Must start with / for valid SPIFFE ID path
            return remaining.startsWith("/");
        }

        return false;
    }

    @Override
    public String toString() {
        return String.format("PeerIdentity[cn=%s, sans=%d, spiffeId=%s, valid=%s, ttl=%ds]",
                commonName, subjectAltNames.size(), spiffeId, isValid(), getTtlSeconds());
    }
}
