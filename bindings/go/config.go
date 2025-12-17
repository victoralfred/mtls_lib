package mtls

/*
#include <stdlib.h>
#include <string.h>
#include <mtls/mtls.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

// Config holds the configuration for creating an mTLS context.
//
// Certificates can be loaded from:
//   - File paths (CACertPath, CertPath, KeyPath)
//   - In-memory PEM data (CACertPEM, CertPEM, KeyPEM)
//
// If both path and PEM are provided, PEM takes precedence.
type Config struct {
	// CA certificate (required)
	CACertPath string // Path to CA certificate file
	CACertPEM  []byte // CA certificate in PEM format

	// Client/server certificate (required for mTLS)
	CertPath string // Path to certificate file
	CertPEM  []byte // Certificate in PEM format

	// Private key (required for mTLS)
	KeyPath string // Path to private key file
	KeyPEM  []byte // Private key in PEM format

	// CRL path for certificate revocation checking (optional)
	CRLPath string

	// AllowedSANs restricts peer certificates to those with matching
	// Subject Alternative Names. Supports exact matching, wildcard DNS
	// matching (*.example.com), and SPIFFE ID matching.
	AllowedSANs []string

	// TLS version settings
	MinTLSVersion TLSVersion // Minimum TLS version (default: TLS12)
	MaxTLSVersion TLSVersion // Maximum TLS version (default: TLS13)

	// Timeouts
	ConnectTimeout time.Duration // Connection timeout (default: 30s)
	ReadTimeout    time.Duration // Read timeout (default: 60s)
	WriteTimeout   time.Duration // Write timeout (default: 60s)

	// Security controls
	KillSwitchEnabled bool // Emergency kill-switch (fail all connections)
	RequireClientCert bool // Require client certificate (server mode, default: true)
	VerifyHostname    bool // Verify hostname against certificate (default: true)

	// OCSP settings (optional)
	EnableOCSP bool // Enable OCSP stapling
}

// DefaultConfig returns a Config with secure default values.
//
// Defaults:
//   - MinTLSVersion: TLS12
//   - MaxTLSVersion: TLS13
//   - ConnectTimeout: 30 seconds
//   - ReadTimeout: 60 seconds
//   - WriteTimeout: 60 seconds
//   - RequireClientCert: true
//   - VerifyHostname: true
func DefaultConfig() *Config {
	return &Config{
		MinTLSVersion:     TLS12,
		MaxTLSVersion:     TLS13,
		ConnectTimeout:    30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		RequireClientCert: true,
		VerifyHostname:    true,
	}
}

// toC converts a Go Config to a C mtls_config.
// The caller must call freeConfigC when done with the C config.
func (c *Config) toC() (*C.mtls_config, []unsafe.Pointer) {
	var cConfig C.mtls_config
	C.mtls_config_init(&cConfig)

	// Track allocated memory for cleanup
	var allocations []unsafe.Pointer

	// CA certificate - copy PEM data to C memory to avoid CGo pointer rule violation
	if len(c.CACertPEM) > 0 {
		caCertCopy := C.malloc(C.size_t(len(c.CACertPEM)))
		allocations = append(allocations, caCertCopy)
		C.memcpy(caCertCopy, unsafe.Pointer(&c.CACertPEM[0]), C.size_t(len(c.CACertPEM)))
		cConfig.ca_cert_pem = (*C.uint8_t)(caCertCopy)
		cConfig.ca_cert_pem_len = C.size_t(len(c.CACertPEM))
	} else if c.CACertPath != "" {
		cStr := C.CString(c.CACertPath)
		allocations = append(allocations, unsafe.Pointer(cStr))
		cConfig.ca_cert_path = cStr
	}

	// Client certificate - copy PEM data to C memory
	if len(c.CertPEM) > 0 {
		certCopy := C.malloc(C.size_t(len(c.CertPEM)))
		allocations = append(allocations, certCopy)
		C.memcpy(certCopy, unsafe.Pointer(&c.CertPEM[0]), C.size_t(len(c.CertPEM)))
		cConfig.cert_pem = (*C.uint8_t)(certCopy)
		cConfig.cert_pem_len = C.size_t(len(c.CertPEM))
	} else if c.CertPath != "" {
		cStr := C.CString(c.CertPath)
		allocations = append(allocations, unsafe.Pointer(cStr))
		cConfig.cert_path = cStr
	}

	// Private key - copy PEM data to C memory
	if len(c.KeyPEM) > 0 {
		keyCopy := C.malloc(C.size_t(len(c.KeyPEM)))
		allocations = append(allocations, keyCopy)
		C.memcpy(keyCopy, unsafe.Pointer(&c.KeyPEM[0]), C.size_t(len(c.KeyPEM)))
		cConfig.key_pem = (*C.uint8_t)(keyCopy)
		cConfig.key_pem_len = C.size_t(len(c.KeyPEM))
	} else if c.KeyPath != "" {
		cStr := C.CString(c.KeyPath)
		allocations = append(allocations, unsafe.Pointer(cStr))
		cConfig.key_path = cStr
	}

	// CRL path
	if c.CRLPath != "" {
		cStr := C.CString(c.CRLPath)
		allocations = append(allocations, unsafe.Pointer(cStr))
		cConfig.crl_path = cStr
	}

	// Allowed SANs
	if len(c.AllowedSANs) > 0 {
		sanArray := C.malloc(C.size_t(len(c.AllowedSANs)) * C.size_t(unsafe.Sizeof((*C.char)(nil))))
		allocations = append(allocations, sanArray)

		sanPtrs := (*[1 << 30]*C.char)(sanArray)[:len(c.AllowedSANs):len(c.AllowedSANs)]
		for i, san := range c.AllowedSANs {
			cStr := C.CString(san)
			allocations = append(allocations, unsafe.Pointer(cStr))
			sanPtrs[i] = cStr
		}

		cConfig.allowed_sans = (**C.char)(sanArray)
		cConfig.allowed_sans_count = C.size_t(len(c.AllowedSANs))
	}

	// TLS versions
	if c.MinTLSVersion != 0 {
		cConfig.min_tls_version = C.mtls_tls_version(c.MinTLSVersion)
	}
	if c.MaxTLSVersion != 0 {
		cConfig.max_tls_version = C.mtls_tls_version(c.MaxTLSVersion)
	}

	// Timeouts (convert to milliseconds)
	if c.ConnectTimeout > 0 {
		cConfig.connect_timeout_ms = C.uint32_t(c.ConnectTimeout.Milliseconds())
	}
	if c.ReadTimeout > 0 {
		cConfig.read_timeout_ms = C.uint32_t(c.ReadTimeout.Milliseconds())
	}
	if c.WriteTimeout > 0 {
		cConfig.write_timeout_ms = C.uint32_t(c.WriteTimeout.Milliseconds())
	}

	// Security controls
	cConfig.kill_switch_enabled = C.bool(c.KillSwitchEnabled)
	cConfig.require_client_cert = C.bool(c.RequireClientCert)
	cConfig.verify_hostname = C.bool(c.VerifyHostname)
	cConfig.enable_ocsp = C.bool(c.EnableOCSP)

	return &cConfig, allocations
}

// freeConfigC frees all memory allocated for a C config.
func freeConfigC(allocations []unsafe.Pointer) {
	for _, ptr := range allocations {
		C.free(ptr)
	}
}
