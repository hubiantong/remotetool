package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"remotetool/internal/identity"
	"remotetool/internal/transport"
)

// hubLeafDER returns the leaf certificate DER of a freshly generated device
// identity, standing in for a self-signed hub certificate.
func hubLeafDER(t *testing.T) []byte {
	t.Helper()
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	cert := id.TLSCertificate()
	if len(cert.Certificate) == 0 {
		t.Fatal("identity has no certificate")
	}
	return cert.Certificate[0]
}

// TestVerifyHubFingerprint: the hub pin wrapper accepts the matching
// fingerprint (case-insensitive, optional "sha256:" prefix) and rejects
// wrong or missing certificates with a clear error.
func TestVerifyHubFingerprint(t *testing.T) {
	der := hubLeafDER(t)
	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])

	if err := verifyHubFingerprint(fp, [][]byte{der}); err != nil {
		t.Errorf("correct fingerprint rejected: %v", err)
	}
	if err := verifyHubFingerprint("sha256:"+strings.ToUpper(fp), [][]byte{der}); err != nil {
		t.Errorf("prefixed/uppercase fingerprint rejected: %v", err)
	}

	wrong := strings.Repeat("ab", 32)
	err := verifyHubFingerprint(wrong, [][]byte{der})
	if err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	if !strings.Contains(err.Error(), "hub certificate fingerprint mismatch") {
		t.Errorf("error = %v, want fingerprint mismatch message", err)
	}
	if !strings.Contains(err.Error(), fp) {
		t.Errorf("error = %v, want it to name the actual fingerprint %s", err, fp)
	}

	if err := verifyHubFingerprint(fp, nil); err == nil {
		t.Error("empty certificate chain accepted")
	}
}

// TestCertBindingSymmetry: CertBinding is symmetric (CertBinding(a, b) ==
// CertBinding(b, a)) and differs for different certificate pairs.
func TestCertBindingSymmetry(t *testing.T) {
	a := hubLeafDER(t)
	b := hubLeafDER(t)

	ab := transport.CertBinding(a, b)
	if !bytes.Equal(ab, transport.CertBinding(b, a)) {
		t.Error("CertBinding(a, b) != CertBinding(b, a)")
	}
	if bytes.Equal(ab, transport.CertBinding(a, a)) {
		t.Error("CertBinding equal for different inputs")
	}
	if len(ab) != sha256.Size {
		t.Errorf("CertBinding length = %d, want %d", len(ab), sha256.Size)
	}
}
