package identity

import (
	"bytes"
	"crypto/elliptic"
	"testing"
)

func runPairing(t *testing.T, pwA, pwB, bindA, bindB []byte) (proverErr, verifierErr error) {
	t.Helper()
	prover, err := NewSPAKE2(RoleProver, pwA, []byte("aaaa"), []byte("bbbb"), bindA)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSPAKE2(RoleVerifier, pwB, []byte("aaaa"), []byte("bbbb"), bindB)
	if err != nil {
		t.Fatal(err)
	}
	xa, _ := prover.CreateShare()
	yb, _ := verifier.CreateShare()
	ca, err := prover.Finish(yb)
	proverErr = err
	cb, err := verifier.Finish(xa)
	verifierErr = err
	if proverErr != nil || verifierErr != nil {
		return
	}
	proverErr = prover.VerifyConfirm(cb)
	verifierErr = verifier.VerifyConfirm(ca)
	return
}

func TestSPAKE2Roundtrip(t *testing.T) {
	pa, va := runPairing(t, []byte("123456"), []byte("123456"), []byte("ch1"), []byte("ch1"))
	if pa != nil || va != nil {
		t.Fatalf("pairing failed: prover=%v verifier=%v", pa, va)
	}
}

func TestSPAKE2WrongPassword(t *testing.T) {
	pa, va := runPairing(t, []byte("123456"), []byte("654321"), []byte("ch1"), []byte("ch1"))
	if pa == nil && va == nil {
		t.Fatal("expected confirmation failure on password mismatch")
	}
}

func TestSPAKE2MITMChannelBindMismatch(t *testing.T) {
	// A MITM terminates two separate TLS channels, so each side computes a
	// different channel binding. Key confirmation must fail even with the
	// correct password on both sides.
	pa, va := runPairing(t, []byte("123456"), []byte("123456"), []byte("channel-A"), []byte("channel-B"))
	if pa == nil && va == nil {
		t.Fatal("expected confirmation failure when channel bindings differ")
	}
}

func TestSPAKE2InvalidPeerShare(t *testing.T) {
	sp, _ := NewSPAKE2(RoleProver, []byte("123456"), []byte("a"), []byte("b"), []byte("c"))
	_, _ = sp.CreateShare()
	if _, err := sp.Finish([]byte("not a point")); err == nil {
		t.Fatal("expected error on garbage share")
	}
}

func TestPairingCodeFormat(t *testing.T) {
	for i := 0; i < 100; i++ {
		c := NewPairingCode()
		if len(c) != 6 {
			t.Fatalf("bad code %q", c)
		}
	}
}

func TestConstantsDeterministic(t *testing.T) {
	mx, my := hashToPoint("rtd/spake2/M")
	if !p256.IsOnCurve(mx, my) {
		t.Fatal("M not on curve")
	}
	m2x, m2y := hashToPoint("rtd/spake2/M")
	if mx.Cmp(m2x) != 0 || my.Cmp(m2y) != 0 {
		t.Fatal("hashToPoint not deterministic")
	}
	if bytes.Equal(elliptic.Marshal(p256, p256Mx, p256My), elliptic.Marshal(p256, p256Nx, p256Ny)) {
		t.Fatal("M and N must differ")
	}
}
