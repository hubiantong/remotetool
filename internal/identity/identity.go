// Package identity manages the device Ed25519 identity, the self-signed
// device certificate and peer certificate pinning.
//
// Design notes: the device id is the first 8 bytes of SHA-256 over the raw
// Ed25519 public key (16 hex chars). Every QUIC connection is mutually
// authenticated with the self-signed device certificate; the receiving side
// recomputes the id from the leaf public key and looks it up in its pin set.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Fingerprint derives the device id from an Ed25519 public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Identity is this device's long-term key material.
type Identity struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	ID   string
	der  []byte
}

// LoadOrCreate reads identity.key from dir or creates a new one.
func LoadOrCreate(dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "identity.key")
	var seed []byte
	if b, err := os.ReadFile(keyPath); err == nil {
		seed = make([]byte, hex.DecodedLen(len(b)))
		if _, err := hex.Decode(seed, trimSpace(b)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", keyPath, err)
		}
	} else if os.IsNotExist(err) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity key has wrong size: %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	id := &Identity{Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}
	id.ID = Fingerprint(id.Pub)
	der, err := selfSign(priv)
	if err != nil {
		return nil, err
	}
	id.der = der
	return id, nil
}

func trimSpace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\n', '\r', '\t':
		default:
			out = append(out, c)
		}
	}
	return out
}

func selfSign(priv ed25519.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"remotetool"}, CommonName: "rtd"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"rtd.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// TLSCertificate returns the TLS certificate presenting the device identity.
func (id *Identity) TLSCertificate() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{id.der}, PrivateKey: id.Priv}
}

// VerifyFunc validates a peer leaf certificate by recomputing its device id
// and delegating to verify. The certificate must be self-signed Ed25519.
// Validity period / CA constraints are intentionally NOT checked: device
// identities are long-lived (NotAfter +20y) and every peer cert is
// self-signed — authentication comes from the pinned pubkey (verify) or the
// pairing code plus channel binding, never from a WebPKI-style chain.
func VerifyFunc(rawCerts [][]byte, verify func(id string, pub ed25519.PublicKey) error) error {
	if len(rawCerts) == 0 {
		return errors.New("peer presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}
	if err := leaf.CheckSignatureFrom(leaf); err != nil {
		return errors.New("peer certificate is not self-signed")
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("peer key is not ed25519")
	}
	if verify == nil {
		return nil
	}
	return verify(Fingerprint(pub), pub)
}

// TLSConfig builds the mutual-TLS config used by both dialer and listener.
// verify may be nil (pairing mode: any self-signed peer accepted; the pairing
// code + channel binding provide authentication instead).
func (id *Identity) TLSConfig(verify func(id string, pub ed25519.PublicKey) error) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.TLSCertificate()},
		NextProtos:   []string{"rtd/1"},
		MinVersion:   tls.VersionTLS13,
		// Mutual auth: both sides always present the device certificate.
		ClientAuth: tls.RequireAnyClientCert,
		// Pinning replaces CA validation entirely.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error { return VerifyFunc(rawCerts, verify) },
	}
}
