// Package transport wraps the multiplexed encrypted transport. QUIC today;
// the Conn/Stream interfaces keep a TCP+TLS+smux backend possible if a
// platform (e.g. Android) ever needs it.
package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"remotetool/internal/identity"
)

// Stream is one multiplexed logical stream.
type Stream interface {
	io.Reader
	io.Writer
	Close() error
}

// Conn is one authenticated connection to a peer device.
type Conn interface {
	Open() (Stream, error)
	Accept() (Stream, error)
	// RemoteID is the pinned device id of the peer.
	RemoteID() string
	// RemotePub is the peer's Ed25519 public key from its certificate.
	RemotePub() ed25519.PublicKey
	// ChannelBinding returns a value that is equal on both ends of a direct
	// connection but differs across a machine-in-the-middle (derived from
	// the two leaf certificates). Used by the pairing handshake.
	ChannelBinding() []byte
	RemoteAddr() net.Addr
	Close() error
}

// Listener accepts incoming peer connections.
type Listener interface {
	Accept() (Conn, error)
	Addr() net.Addr
	Close() error
}

const (
	keepAlivePeriod = 15 * time.Second
	maxIdleTimeout  = 90 * time.Second
)

func qcfg() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:       keepAlivePeriod,
		MaxIdleTimeout:        maxIdleTimeout,
		MaxIncomingStreams:    512,
		MaxIncomingUniStreams: 512,
	}
}

type quicConn struct {
	c    *quic.Conn
	id   string
	own  []byte // our leaf certificate DER (for channel binding)
}

func (q *quicConn) Open() (Stream, error) {
	s, err := q.c.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return quicStream{s}, nil
}

func (q *quicConn) Accept() (Stream, error) {
	s, err := q.c.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return quicStream{s}, nil
}

func (q *quicConn) RemoteID() string    { return q.id }
func (q *quicConn) RemoteAddr() net.Addr { return q.c.RemoteAddr() }
func (q *quicConn) Close() error        { return q.c.CloseWithError(quic.ApplicationErrorCode(0), "closed") }

func (q *quicConn) RemotePub() ed25519.PublicKey {
	st := q.c.ConnectionState()
	if len(st.TLS.PeerCertificates) == 0 {
		return nil
	}
	pub, _ := st.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return pub
}

func (q *quicConn) ChannelBinding() []byte {
	st := q.c.ConnectionState()
	var own, peer []byte
	own = q.own
	if len(st.TLS.PeerCertificates) > 0 {
		peer = st.TLS.PeerCertificates[0].Raw
	}
	return certBinding(own, peer)
}

// certBinding is symmetric: equal for both ends of a direct connection,
// different across a MITM (the peer certificate differs on each leg).
func certBinding(own, peer []byte) []byte {
	a, b := string(own), string(peer)
	if a > b {
		a, b = b, a
	}
	h := sha256.New()
	_, _ = h.Write([]byte("rtd/cb/v1"))
	_, _ = h.Write([]byte(a))
	_, _ = h.Write([]byte(b))
	return h.Sum(nil)
}

type quicStream struct{ s *quic.Stream }

func (q quicStream) Read(p []byte) (int, error)  { return q.s.Read(p) }
func (q quicStream) Write(p []byte) (int, error) { return q.s.Write(p) }
func (q quicStream) Close() error                { return q.s.Close() }

func peerID(c *quic.Conn) (string, error) {
	st := c.ConnectionState()
	certs := st.TLS.PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("peer sent no certificate")
	}
	pub, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("peer key is not ed25519")
	}
	return identity.Fingerprint(pub), nil
}

// Dial connects to a peer. tlsCfg must come from identity.TLSConfig.
func Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (Conn, error) {
	c, err := quic.DialAddr(ctx, addr, tlsCfg, qcfg())
	if err != nil {
		return nil, err
	}
	id, err := peerID(c)
	if err != nil {
		_ = c.CloseWithError(quic.ApplicationErrorCode(0), "bad identity")
		return nil, err
	}
	return &quicConn{c: c, id: id, own: ownLeaf(tlsCfg)}, nil
}

// ownLeaf extracts our leaf certificate DER from the TLS config.
func ownLeaf(tlsCfg *tls.Config) []byte {
	if tlsCfg == nil || len(tlsCfg.Certificates) == 0 || len(tlsCfg.Certificates[0].Certificate) == 0 {
		return nil
	}
	return tlsCfg.Certificates[0].Certificate[0]
}

// Listen serves incoming peer connections.
func Listen(addr string, tlsCfg *tls.Config) (Listener, error) {
	l, err := quic.ListenAddr(addr, tlsCfg, qcfg())
	if err != nil {
		return nil, err
	}
	return &quicListener{l: l, own: ownLeaf(tlsCfg)}, nil
}

type quicListener struct {
	l   *quic.Listener
	own []byte
}

func (q *quicListener) Accept() (Conn, error) {
	c, err := q.l.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	id, err := peerID(c)
	if err != nil {
		_ = c.CloseWithError(quic.ApplicationErrorCode(0), "bad identity")
		return nil, err
	}
	return &quicConn{c: c, id: id, own: q.own}, nil
}

func (q *quicListener) Addr() net.Addr { return q.l.Addr() }
func (q *quicListener) Close() error   { return q.l.Close() }
