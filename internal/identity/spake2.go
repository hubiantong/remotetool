package identity

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// SPAKE2 (P-256) with key confirmation, used to authenticate the first
// pairing between two devices that share a short numeric code.
//
// Construction follows the symmetric SPAKE2 used by agl/spake2 and
// python-spake2: both sides derive w = H(password), exchange X = xG + wM /
// Y = yG + wN and compute the shared point K = xyG. Point constants M and N
// are derived at init time via try-and-increment SHA-256 (fixed, so neither
// party can influence them per session).
//
// Channel binding: each side mixes *its own TLS channel exporter* into the
// transcript. On a direct connection both exporters are equal; a machine-in-
// the-middle terminating two TLS channels produces different values, so key
// confirmation fails and the relay attack is rejected.

var (
	p256          = elliptic.P256()
	p256Mx, p256My = hashToPoint("rtd/spake2/M")
	p256Nx, p256Ny = hashToPoint("rtd/spake2/N")
)

// Role selects which side of SPAKE2 we run.
type Role byte

const (
	RoleProver   Role = 'A' // initiates the pairing (enters the code)
	RoleVerifier Role = 'B' // generated the code
)

// SPAKE2 is a single pairing handshake in progress.
type SPAKE2 struct {
	role     Role
	w        *big.Int
	x        *big.Int
	idA, idB []byte
	share    []byte
	channel  []byte
	key      []byte
}

// NewSPAKE2 starts a handshake. idA/idB are the two device ids (initiator
// first) and channelBind is the local TLS exporter material.
func NewSPAKE2(role Role, password, idA, idB, channelBind []byte) (*SPAKE2, error) {
	if len(password) == 0 {
		return nil, errors.New("empty pairing password")
	}
	w := hashToScalar("rtd/spake2/w", password, idA, idB)
	n := p256.Params().N
	x, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, err
	}
	if x.Sign() == 0 {
		x = big.NewInt(1)
	}
	return &SPAKE2{role: role, w: w, x: x, idA: idA, idB: idB, channel: channelBind}, nil
}

// CreateShare produces the public share X (prover) or Y (verifier).
func (s *SPAKE2) CreateShare() ([]byte, error) {
	px, py := p256.ScalarBaseMult(s.x.Bytes())
	var cx, cy *big.Int
	if s.role == RoleProver {
		cx, cy = p256Mx, p256My
	} else {
		cx, cy = p256Nx, p256Ny
	}
	ax, ay := p256.ScalarMult(cx, cy, s.w.Bytes())
	sx, sy := p256.Add(px, py, ax, ay)
	s.share = elliptic.Marshal(p256, sx, sy)
	return append([]byte(nil), s.share...), nil
}

// Finish takes the peer share, derives the shared secret and returns the
// confirmation tag to send to the peer.
func (s *SPAKE2) Finish(peerShare []byte) (confirm []byte, err error) {
	px, py := elliptic.Unmarshal(p256, peerShare)
	if px == nil || !p256.IsOnCurve(px, py) {
		return nil, errors.New("peer share is not a valid P-256 point")
	}
	// Subtract our mask point: S = peer - w*(M or N).
	var cx, cy *big.Int
	if s.role == RoleProver {
		cx, cy = p256Nx, p256Ny // prover removes w*N from Y
	} else {
		cx, cy = p256Mx, p256My // verifier removes w*M from X
	}
	mx, my := p256.ScalarMult(cx, cy, s.w.Bytes())
	mx, my = negate(mx, my)
	sx, sy := p256.Add(px, py, mx, my)
	zx, zy := p256.ScalarMult(sx, sy, s.x.Bytes())
	if zx.Sign() == 0 && zy.Sign() == 0 {
		return nil, errors.New("spake2 produced identity point (wrong password?)")
	}

	// Transcript: idA, idB, M, N, X (prover share), Y (verifier share), Z, channel bind.
	proverShare := s.share
	verifierShare := peerShare
	if s.role == RoleVerifier {
		proverShare, verifierShare = verifierShare, proverShare
	}
	mx2, my2 := p256Mx, p256My
	nx2, ny2 := p256Nx, p256Ny
	tt := sha256.New()
	writeField(tt, s.idA)
	writeField(tt, s.idB)
	writeField(tt, elliptic.Marshal(p256, mx2, my2))
	writeField(tt, elliptic.Marshal(p256, nx2, ny2))
	writeField(tt, proverShare)
	writeField(tt, verifierShare)
	writeField(tt, elliptic.Marshal(p256, zx, zy))
	writeField(tt, s.channel)

	sum := sha256.Sum256(tt.Sum(nil))
	s.key = sum[:]
	label := []byte{byte(s.role)}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("rtd/spake2/confirm/"))
	mac.Write(label)
	return mac.Sum(nil), nil
}

// VerifyConfirm checks the peer's confirmation tag.
func (s *SPAKE2) VerifyConfirm(tag []byte) error {
	if s.key == nil {
		return errors.New("spake2 not finished")
	}
	peerRole := byte(RoleProver)
	if s.role == RoleProver {
		peerRole = byte(RoleVerifier)
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("rtd/spake2/confirm/"))
	mac.Write([]byte{peerRole})
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return errors.New("pairing code mismatch (confirmation failed)")
	}
	return nil
}

// SharedKey returns the derived secret (for tests / future use).
func (s *SPAKE2) SharedKey() []byte { return s.key }

func negate(x, y *big.Int) (*big.Int, *big.Int) {
	p := p256.Params().P
	ny := new(big.Int).Sub(p, y)
	ny.Mod(ny, p)
	return new(big.Int).Set(x), ny
}

func writeField(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

func hashToScalar(label string, parts ...[]byte) *big.Int {
	n := p256.Params().N
	for i := uint32(0); ; i++ {
		h := sha256.New()
		_, _ = h.Write([]byte(label))
		for _, p := range parts {
			writeField(h, p)
		}
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], i)
		_, _ = h.Write(c[:])
		x := new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), n)
		if x.Sign() != 0 {
			return x
		}
	}
}

func hashToPoint(label string) (x, y *big.Int) {
	p := p256.Params().P
	b := p256.Params().B
	three := big.NewInt(3)
	one := big.NewInt(1)
	two := big.NewInt(2)
	four := big.NewInt(4)
	for i := uint32(0); ; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], i)
		h := sha256.Sum256(append([]byte(label), ib[:]...))
		xx := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), p)
		rhs := new(big.Int).Mul(xx, xx)
		rhs.Mod(rhs, p)
		rhs.Mul(rhs, xx)
		rhs.Mod(rhs, p)
		t := new(big.Int).Mul(three, xx)
		t.Mod(t, p)
		rhs.Sub(rhs, t)
		rhs.Mod(rhs, p)
		rhs.Add(rhs, b)
		rhs.Mod(rhs, p)
		// Legendre symbol: rhs^((p-1)/2) == 1 means quadratic residue.
		e := new(big.Int).Sub(p, one)
		e.Div(e, two)
		ls := new(big.Int).Exp(rhs, e, p)
		if ls.Cmp(one) != 0 {
			continue
		}
		// p % 4 == 3 for P-256: y = rhs^((p+1)/4).
		e2 := new(big.Int).Add(p, one)
		e2.Div(e2, four)
		yy := new(big.Int).Exp(rhs, e2, p)
		chk := new(big.Int).Mul(yy, yy)
		chk.Mod(chk, p)
		if chk.Cmp(rhs) == 0 {
			return xx, yy
		}
	}
}

// NewPairingCode returns a random 6-digit pairing code.
func NewPairingCode() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	return fmt.Sprintf("%06d", n)
}
