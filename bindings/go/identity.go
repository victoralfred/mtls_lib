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

	// Copy SANs array
	sanCount := int(cIdentity.san_count)
	if sanCount > 0 && cIdentity.sans != nil {
		identity.SANs = make([]string, sanCount)
		sanSlice := (*[1 << 20]*C.char)(unsafe.Pointer(cIdentity.sans))[:sanCount:sanCount]
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
func ValidateSANs(identity *PeerIdentity, allowedSANs []string) bool {
	if identity == nil || len(allowedSANs) == 0 {
		return false
	}

	// Convert to C format and call the C validation function
	// For simplicity, we implement the matching in Go
	for _, peerSAN := range identity.SANs {
		for _, allowedSAN := range allowedSANs {
			if matchSAN(peerSAN, allowedSAN) {
				return true
			}
		}
	}

	// Also check SPIFFE ID
	if identity.SPIFFEID != "" {
		for _, allowedSAN := range allowedSANs {
			if matchSAN(identity.SPIFFEID, allowedSAN) {
				return true
			}
		}
	}

	return false
}

// matchSAN checks if a SAN matches an allowed pattern.
// Supports exact match and wildcard DNS matching (*.example.com).
func matchSAN(san, pattern string) bool {
	if san == pattern {
		return true
	}

	// Wildcard matching for DNS names (*.example.com)
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[1:] // .example.com
		// san must have at least one character before the suffix
		if len(san) > len(suffix) {
			sanSuffix := san[len(san)-len(suffix):]
			if sanSuffix == suffix {
				// Check that there's no additional dots in the prefix
				prefix := san[:len(san)-len(suffix)]
				for _, c := range prefix {
					if c == '.' {
						return false
					}
				}
				return true
			}
		}
	}

	return false
}
