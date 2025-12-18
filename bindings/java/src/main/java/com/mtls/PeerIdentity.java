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
     * Checks if any of the SANs match the given pattern.
     *
     * Supports exact matches and wildcard DNS patterns (*.example.com).
     *
     * @param pattern the pattern to match against
     * @return true if any SAN matches the pattern
     */
    public boolean matchesSan(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return false;
        }

        for (String san : subjectAltNames) {
            if (matchesSanPattern(san, pattern)) {
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

        // Wildcard DNS match (*.example.com matches foo.example.com)
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            return san.endsWith(suffix);
        }

        return false;
    }

    @Override
    public String toString() {
        return String.format("PeerIdentity[cn=%s, sans=%d, spiffeId=%s, valid=%s, ttl=%ds]",
                commonName, subjectAltNames.size(), spiffeId, isValid(), getTtlSeconds());
    }
}
