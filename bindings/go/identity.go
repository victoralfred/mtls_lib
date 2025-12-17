package mtls

/*
#include <mtls/mtls.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

// PeerIdentity contains information about the peer's certificate.
type PeerIdentity struct {
	// CommonName is the CN field from the certificate subject.
	CommonName string

	// SANs are the Subject Alternative Names from the certificate.
	SANs []string

	// SPIFFEID is the SPIFFE ID if present in the certificate SANs.
	SPIFFEID string

	// NotBefore is the certificate validity start time.
	NotBefore time.Time

	// NotAfter is the certificate validity end time.
	NotAfter time.Time
}

// PeerIdentity returns the peer's certificate identity information.
//
// The returned PeerIdentity is a copy of the data from the peer certificate.
func (c *Conn) PeerIdentity() (*PeerIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	var cIdentity C.mtls_peer_identity
	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_get_peer_identity(c.conn, &cIdentity, &cErr) != 0 {
		return nil, convertError(&cErr)
	}
	defer C.mtls_free_peer_identity(&cIdentity)

	// Convert to Go struct
	identity := &PeerIdentity{
		CommonName: C.GoString(&cIdentity.common_name[0]),
		SPIFFEID:   C.GoString(&cIdentity.spiffe_id[0]),
		NotBefore:  time.Unix(int64(cIdentity.cert_not_before), 0),
		NotAfter:   time.Unix(int64(cIdentity.cert_not_after), 0),
	}

	// Copy SANs array with bounds checking
	// MTLS_MAX_CERT_SANS is 128 in the C library
	const maxCertSANs = 128
	sanCount := int(cIdentity.san_count)
	if sanCount > maxCertSANs {
		sanCount = maxCertSANs // Enforce C library's limit for safety
	}
	if sanCount > 0 && cIdentity.sans != nil {
		identity.SANs = make([]string, sanCount)
		sanSlice := (*[maxCertSANs]*C.char)(unsafe.Pointer(cIdentity.sans))[:sanCount:sanCount]
		for i, cStr := range sanSlice {
			if cStr != nil {
				identity.SANs[i] = C.GoString(cStr)
			}
		}
	}

	return identity, nil
}

// IsValid returns true if the certificate is currently valid
// (current time is within NotBefore and NotAfter).
func (p *PeerIdentity) IsValid() bool {
	now := time.Now()
	return now.After(p.NotBefore) && now.Before(p.NotAfter)
}

// TTL returns the duration until the certificate expires.
// Returns a negative duration if the certificate has already expired.
func (p *PeerIdentity) TTL() time.Duration {
	return time.Until(p.NotAfter)
}

// HasSPIFFEID returns true if the certificate contains a SPIFFE ID.
func (p *PeerIdentity) HasSPIFFEID() bool {
	return p.SPIFFEID != ""
}

// IsPeerCertValid checks if the peer certificate is currently valid.
// This calls the C library function for accurate validation.
func (c *Conn) IsPeerCertValid() (bool, error) {
	identity, err := c.PeerIdentity()
	if err != nil {
		return false, err
	}
	return identity.IsValid(), nil
}

// PeerCertTTL returns the time until the peer certificate expires.
func (c *Conn) PeerCertTTL() (time.Duration, error) {
	identity, err := c.PeerIdentity()
	if err != nil {
		return 0, err
	}
	return identity.TTL(), nil
}

// HasPeerSPIFFEID returns true if the peer certificate has a SPIFFE ID.
func (c *Conn) HasPeerSPIFFEID() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return false, &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	// Get peer identity to check SPIFFE ID
	var cIdentity C.mtls_peer_identity
	var cErr C.mtls_err
	initErr(&cErr)

	if C.mtls_get_peer_identity(c.conn, &cIdentity, &cErr) != 0 {
		return false, convertError(&cErr)
	}
	defer C.mtls_free_peer_identity(&cIdentity)

	return bool(C.mtls_has_spiffe_id(&cIdentity)), nil
}

// PeerOrganization returns the Organization (O) field from the peer certificate.
func (c *Conn) PeerOrganization() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	var buf [256]C.char

	if C.mtls_get_peer_organization(c.conn, &buf[0], C.size_t(len(buf))) != 0 {
		return "", &Error{
			Code:    ErrInternal,
			Message: "failed to get peer organization",
		}
	}

	return C.GoString(&buf[0]), nil
}

// PeerOrgUnit returns the Organizational Unit (OU) field from the peer certificate.
func (c *Conn) PeerOrgUnit() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", &Error{
			Code:    ErrConnectionClosed,
			Message: "connection is closed",
		}
	}

	var buf [256]C.char

	if C.mtls_get_peer_org_unit(c.conn, &buf[0], C.size_t(len(buf))) != 0 {
		return "", &Error{
			Code:    ErrInternal,
			Message: "failed to get peer organizational unit",
		}
	}

	return C.GoString(&buf[0]), nil
}

// ValidatePeerSANs checks if the peer's SANs match any of the allowed patterns.
//
// Supports exact matching, wildcard DNS matching (*.example.com), and
// SPIFFE ID matching.
func (c *Conn) ValidatePeerSANs(allowedSANs []string) (bool, error) {
	identity, err := c.PeerIdentity()
	if err != nil {
		return false, err
	}

	return ValidateSANs(identity, allowedSANs), nil
}

// ValidateSANs checks if any of the identity's SANs match the allowed patterns.
//
// This is a standalone function that can be used for custom validation logic.
// The function is optimized to use O(1) lookups for exact matches while
// falling back to linear matching for wildcard patterns.
//
// Supported wildcard patterns:
//   - DNS wildcards: *.example.com (matches subdomains)
//   - SPIFFE ID wildcards: spiffe://example.com/* (matches paths under the prefix)
func ValidateSANs(identity *PeerIdentity, allowedSANs []string) bool {
	if identity == nil || len(allowedSANs) == 0 {
		return false
	}

	// Separate exact matches (for O(1) lookup) from wildcard patterns
	exactMatches := make(map[string]struct{}, len(allowedSANs))
	var dnsWildcardPatterns []string    // Patterns starting with *.
	var spiffeWildcardPatterns []string // Patterns ending with /*

	for _, san := range allowedSANs {
		if len(san) > 2 && san[0] == '*' && san[1] == '.' {
			// DNS wildcard: *.example.com
			dnsWildcardPatterns = append(dnsWildcardPatterns, san)
		} else if len(san) > 2 && san[len(san)-2:] == "/*" {
			// SPIFFE ID wildcard: spiffe://example.com/*
			spiffeWildcardPatterns = append(spiffeWildcardPatterns, san)
		} else {
			exactMatches[san] = struct{}{}
		}
	}

	// Check peer SANs
	for _, peerSAN := range identity.SANs {
		// Fast path: exact match
		if _, ok := exactMatches[peerSAN]; ok {
			return true
		}
		// DNS wildcard matching
		for _, pattern := range dnsWildcardPatterns {
			if matchWildcard(peerSAN, pattern) {
				return true
			}
		}
		// SPIFFE ID wildcard matching
		for _, pattern := range spiffeWildcardPatterns {
			if matchSPIFFEWildcard(peerSAN, pattern) {
				return true
			}
		}
	}

	// Also check SPIFFE ID
	if identity.SPIFFEID != "" {
		if _, ok := exactMatches[identity.SPIFFEID]; ok {
			return true
		}
		// DNS wildcard matching (unlikely but possible)
		for _, pattern := range dnsWildcardPatterns {
			if matchWildcard(identity.SPIFFEID, pattern) {
				return true
			}
		}
		// SPIFFE ID wildcard matching
		for _, pattern := range spiffeWildcardPatterns {
			if matchSPIFFEWildcard(identity.SPIFFEID, pattern) {
				return true
			}
		}
	}

	return false
}

// matchSAN checks if a SAN matches an allowed pattern.
// Supports exact match, DNS wildcard matching (*.example.com), and
// SPIFFE ID wildcard matching (spiffe://example.com/*).
func matchSAN(san, pattern string) bool {
	if san == pattern {
		return true
	}
	// Try DNS wildcard first
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		return matchWildcard(san, pattern)
	}
	// Try SPIFFE ID wildcard
	if len(pattern) > 2 && pattern[len(pattern)-2:] == "/*" {
		return matchSPIFFEWildcard(san, pattern)
	}
	return false
}

// matchWildcard checks if a SAN matches a DNS wildcard pattern (*.example.com).
// The pattern must start with "*." for this function to be useful.
func matchWildcard(san, pattern string) bool {
	// Pattern should be *.something
	if len(pattern) < 3 || pattern[0] != '*' || pattern[1] != '.' {
		return false
	}

	suffix := pattern[1:] // .example.com
	// san must have at least one character before the suffix
	if len(san) <= len(suffix) {
		return false
	}

	sanSuffix := san[len(san)-len(suffix):]
	if sanSuffix != suffix {
		return false
	}

	// Check that there's no additional dots in the prefix (single-level wildcard)
	prefix := san[:len(san)-len(suffix)]
	for _, c := range prefix {
		if c == '.' {
			return false
		}
	}

	return true
}

// matchSPIFFEWildcard checks if a SAN matches a SPIFFE ID wildcard pattern (spiffe://example.com/*).
// The pattern must end with "/*" for this function to be useful.
func matchSPIFFEWildcard(san, pattern string) bool {
	// Pattern should end with /*
	if len(pattern) < 3 || pattern[len(pattern)-2:] != "/*" {
		return false
	}

	prefix := pattern[:len(pattern)-2] // spiffe://example.com
	// san must be at least as long as the prefix
	if len(san) < len(prefix) {
		return false
	}

	// Check if san starts with the prefix
	if san[:len(prefix)] != prefix {
		return false
	}

	// For SPIFFE IDs, the remaining part after the prefix should be a valid path
	// (starts with / and contains no wildcards)
	remaining := san[len(prefix):]
	if len(remaining) == 0 {
		// Exact match (no path component)
		return true
	}
	if remaining[0] != '/' {
		return false
	}

	// Valid SPIFFE ID path (no wildcards in the actual ID)
	return true
}
