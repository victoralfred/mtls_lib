package mtls

import (
	"testing"
)

// TestOCSPCheckURLEmptyPEM verifies OCSPCheckURL returns an error for empty PEM.
func TestOCSPCheckURLEmptyPEM(t *testing.T) {
	_, err := OCSPCheckURL("http://ocsp.example.com", nil, []byte("issuer"), 0)
	if err == nil {
		t.Error("expected error for empty certPEM")
	}
}

// TestGetOCSPResponderURLEmpty verifies that GetOCSPResponderURL returns error for empty PEM.
func TestGetOCSPResponderURLEmpty(t *testing.T) {
	_, err := GetOCSPResponderURL(nil)
	if err == nil {
		t.Error("expected error for nil certPEM")
	}
}

// TestCRLStatusConstants verifies CRL status constants have expected values.
func TestCRLStatusConstants(t *testing.T) {
	if CRLStatusGood != 0 {
		t.Errorf("CRLStatusGood = %d, want 0", CRLStatusGood)
	}
	if CRLStatusRevoked != 1 {
		t.Errorf("CRLStatusRevoked = %d, want 1", CRLStatusRevoked)
	}
}

// TestOCSPStatusConstants verifies OCSP status constants have expected values.
func TestOCSPStatusConstants(t *testing.T) {
	if OCSPStatusGood != 0 {
		t.Errorf("OCSPStatusGood = %d, want 0", OCSPStatusGood)
	}
	if OCSPStatusRevoked != 1 {
		t.Errorf("OCSPStatusRevoked = %d, want 1", OCSPStatusRevoked)
	}
}

// TestOCSPCheckNilContext verifies OCSPCheck on a nil context errors correctly.
func TestOCSPCheckNilContext(t *testing.T) {
	ctx := &Context{}
	_, err := ctx.OCSPCheck([]byte("cert"), []byte("issuer"))
	if err == nil {
		t.Error("expected error for nil C context")
	}
}
