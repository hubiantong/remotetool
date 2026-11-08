package session

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// queuedStream is an in-memory transport.Stream pre-loaded with an encoded
// data header; Reads serve it then block until Close (io.EOF).
type queuedStream struct {
	in      []byte
	mu      sync.Mutex
	closed  bool
	closeCh chan struct{}
}

var _ transport.Stream = (*queuedStream)(nil)

func newQueuedStream(ch proto.Chan, h *proto.DataHeader) *queuedStream {
	var buf bytes.Buffer
	if err := proto.WriteDataHeader(&buf, ch, h); err != nil {
		panic(err) // bytes.Buffer writes never fail
	}
	return &queuedStream{in: buf.Bytes(), closeCh: make(chan struct{})}
}

func (s *queuedStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.in) > 0 {
			n := copy(p, s.in)
			s.in = s.in[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, errors.New("closed")
		}
		ch := s.closeCh
		s.mu.Unlock()
		<-ch
	}
}

func (s *queuedStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *queuedStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.closeCh)
	}
	return nil
}

func (s *queuedStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// fakeConn feeds dispatchLoop a fixed queue of streams.
type fakeConn struct {
	mu     sync.Mutex
	queue  []transport.Stream
	sig    chan struct{}
	closed bool
}

var _ transport.Conn = (*fakeConn)(nil)

func newFakeConn() *fakeConn { return &fakeConn{sig: make(chan struct{})} }

func (c *fakeConn) queueStream(s transport.Stream) {
	c.mu.Lock()
	c.queue = append(c.queue, s)
	c.mu.Unlock()
	close(c.sig)
	c.sig = make(chan struct{})
}

func (c *fakeConn) Accept() (transport.Stream, error) {
	for {
		c.mu.Lock()
		if len(c.queue) > 0 {
			s := c.queue[0]
			c.queue = c.queue[1:]
			c.mu.Unlock()
			return s, nil
		}
		if c.closed {
			c.mu.Unlock()
			return nil, errors.New("conn closed")
		}
		sig := c.sig
		c.mu.Unlock()
		<-sig
	}
}

func (c *fakeConn) Open() (transport.Stream, error) { return nil, errors.New("not used") }
func (c *fakeConn) RemoteID() string                { return "devA" }
func (c *fakeConn) RemotePub() ed25519.PublicKey    { return nil }
func (c *fakeConn) ChannelBinding() []byte          { return nil }
func (c *fakeConn) RemoteAddr() net.Addr            { return nil }
func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.sig)
	}
	return nil
}

// capFeature counts the streams dispatchLoop hands it and blocks every
// handler until released, so the per-peer accounting can be observed
// mid-flight.
type capFeature struct {
	mu      sync.Mutex
	count   int
	release chan struct{}
}

func (f *capFeature) Name() string                        { return "cap" }
func (f *capFeature) Chan() proto.Chan                    { return proto.ChanFile }
func (f *capFeature) AttachRPC(_ *Peer, _ *proto.RPCConn) {}

func (f *capFeature) HandleStream(_ *Peer, _ proto.Chan, _ *proto.DataHeader, s transport.Stream) {
	f.mu.Lock()
	f.count++
	f.mu.Unlock()
	<-f.release
	_ = s.Close()
}

func (f *capFeature) seen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

// TestDispatchLoopPeerStreamCap: while maxPeerStreams handlers are still
// running, further streams from the same peer are rejected (closed without
// reaching the feature) and the counter accounts exactly maxPeerStreams; once
// the handlers finish, the accounting drains back to zero.
func TestDispatchLoopPeerStreamCap(t *testing.T) {
	m, _ := newTestManager(t)
	f := &capFeature{release: make(chan struct{})}
	m.AddFeature(f)

	fc := newFakeConn()
	p := &Peer{ID: "devA", conn: fc, mgr: m}
	go m.dispatchLoop(p)

	total := maxPeerStreams + 2
	streams := make([]*queuedStream, 0, total)
	for i := 0; i < total; i++ {
		hs := newQueuedStream(proto.ChanFile, &proto.DataHeader{XferID: fmt.Sprint(i)})
		streams = append(streams, hs)
		fc.queueStream(hs)
	}

	waitFor(t, "maxPeerStreams streams to reach the feature", func() bool {
		return f.seen() == maxPeerStreams
	})
	for i, hs := range streams[maxPeerStreams:] {
		id := maxPeerStreams + i
		waitFor(t, fmt.Sprintf("over-limit stream %d to be closed", id), hs.isClosed)
	}
	if got := p.activeStreams.Load(); got != maxPeerStreams {
		t.Fatalf("activeStreams = %d, want %d", got, maxPeerStreams)
	}

	close(f.release)
	waitFor(t, "stream accounting to drain to zero", func() bool {
		return p.activeStreams.Load() == 0
	})
	_ = fc.Close() // stop dispatchLoop
}
