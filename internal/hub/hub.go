// Package hub implements the self-hosted rendezvous + relay server.
//
// Privacy model: the hub only sees device ids and encrypted bytes. Peer
// sessions relayed through it carry an inner TLS 1.3 layer with the peers'
// pinned device certificates, so the hub (its operator included) cannot
// read relayed traffic.
package hub

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

const relayWaitTimeout = 15 * time.Second

const (
	// maxPendingRelays caps concurrently pending relay handshakes; excess
	// relay requests are rejected outright.
	maxPendingRelays = 1024
	// earlyTTL / earlyReapInterval: early entries older than earlyTTL are
	// reaped every earlyReapInterval, releasing their held streams.
	earlyTTL          = time.Minute
	earlyReapInterval = time.Minute
	// maxDevices caps concurrently registered devices; excess registrations
	// are rejected.
	maxDevices = 256
	// resolve rate limit per registered device: a tiny token bucket refilled
	// at resolveRate tokens/s with burst capacity resolveBurst.
	resolveRate  = 10.0
	resolveBurst = 20
)

// ---- u32-length JSON framing shared by hub and client ----

func WriteMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func ReadMsg(r io.Reader, v any) error {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 1<<20 {
		return fmt.Errorf("hub message too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// ---- protocol types ----

type RegParams struct {
	Token string `json:"token"`
	ID    string `json:"id"`
}
type RegResult struct {
	Addr string `json:"addr"`
}
type ResolveParams struct {
	ID string `json:"id"`
}
type ResolveResult struct {
	Found bool   `json:"found"`
	Addr  string `json:"addr,omitempty"`
}
type RelayParams struct {
	Dst   string `json:"dst"`
	Token string `json:"token"`
}

// StreamHeader is the first JSON on every relay data stream (requester and
// acceptor both carry the same token so the hub can pair them).
type StreamHeader struct {
	Token string `json:"token"`
	Dst   string `json:"dst,omitempty"` // set by the requester only
}

// RelayIncoming is the notify sent to the destination device.
type RelayIncoming struct {
	Src   string `json:"src"`
	Token string `json:"token"`
}

// ---- server ----

type devConn struct {
	conn transport.Conn
	ctl  *proto.RPCConn
	addr string

	// resolve token bucket (resolveRate/s refill, burst resolveBurst) so one
	// device cannot hammer the hub's resolve endpoint.
	rmu     sync.Mutex
	tokens  float64
	lastRef time.Time
}

// allowResolve reports whether another resolve request fits the rate limit.
func (d *devConn) allowResolve() bool {
	now := time.Now()
	d.rmu.Lock()
	defer d.rmu.Unlock()
	if d.lastRef.IsZero() {
		d.lastRef = now
		d.tokens = resolveBurst
	}
	d.tokens += now.Sub(d.lastRef).Seconds() * resolveRate
	if d.tokens > resolveBurst {
		d.tokens = resolveBurst
	}
	d.lastRef = now
	if d.tokens < 1 {
		return false
	}
	d.tokens--
	return true
}

// earlyEntry caches relay streams that arrive before the requester's "relay"
// RPC registers the pending slot. The janitor (and startRelay) unlink entries
// and then mark them closed under mu; the flag (instead of closing the
// channel) makes send-on-closed panics impossible while still letting senders
// holding a stale pointer discard their stream deterministically instead of
// buffering it into an entry nobody will ever read.
type earlyEntry struct {
	mu      sync.Mutex
	closed  bool
	ch      chan transport.Stream
	created time.Time
}

func newEarlyEntry() *earlyEntry {
	return &earlyEntry{ch: make(chan transport.Stream, 2), created: time.Now()}
}

// offer buffers st unless the entry was unlinked (closed) or its buffer is
// full. Returns false when st was not taken.
func (e *earlyEntry) offer(st transport.Stream) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	select {
	case e.ch <- st:
		return true
	default:
		return false
	}
}

// take drains and returns all buffered streams.
func (e *earlyEntry) take() []transport.Stream {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []transport.Stream
	for {
		select {
		case st := <-e.ch:
			out = append(out, st)
		default:
			return out
		}
	}
}

// Server is the hub.
type Server struct {
	Token string
	Log   *slog.Logger

	mu           sync.Mutex
	devices      map[string]*devConn
	pending      sync.Map     // token -> chan transport.Stream (buffer 2)
	pendingCount atomic.Int64 // number of entries in pending
	early        sync.Map     // token -> *earlyEntry, streams arriving before the relay RPC
}

// NewServer builds a hub with the given shared token (empty = open to any
// device; not recommended for public hubs).
func NewServer(token string, log *slog.Logger) *Server {
	return &Server{Token: token, Log: log, devices: map[string]*devConn{}}
}

// Run serves until the listener fails.
func (s *Server) Run(ln transport.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go s.reapLoop(done)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

// reapLoop drops expired early entries every earlyReapInterval.
func (s *Server) reapLoop(done <-chan struct{}) {
	// Long-lived background goroutine: log and die instead of crashing the
	// whole hub.
	defer func() {
		if r := recover(); r != nil {
			s.Log.Error("hub goroutine panic", "where", "reapLoop", "panic", r)
		}
	}()
	t := time.NewTicker(earlyReapInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s.reapEarly()
		}
	}
}

// reapEarly unlinks early entries older than earlyTTL and closes the streams
// they still hold. The channel is never closed, so a sender holding a stale
// pointer cannot panic; the closed flag makes it drop the stream instead.
func (s *Server) reapEarly() {
	now := time.Now()
	s.early.Range(func(key, value any) bool {
		if e := value.(*earlyEntry); now.Sub(e.created) < earlyTTL {
			return true
		}
		// CompareAndDelete so a fresh entry re-created for the same token
		// after our snapshot is left alone.
		if !s.early.CompareAndDelete(key, value) {
			return true
		}
		e := value.(*earlyEntry)
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		for _, st := range e.take() {
			_ = st.Close()
		}
		return true
	})
}

// unlinkEarly removes token's early entry from the map and marks it closed so
// senders still holding the old pointer discard their streams. Returns nil if
// there is no entry.
func (s *Server) unlinkEarly(token string) *earlyEntry {
	v, ok := s.early.LoadAndDelete(token)
	if !ok {
		return nil
	}
	e := v.(*earlyEntry)
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	return e
}

// serveConn handles one device connection until it drops. Spawned per
// accepted connection, so a panic here must not take down the hub.
func (s *Server) serveConn(conn transport.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.Log.Error("hub goroutine panic", "where", "serveConn", "panic", r)
		}
	}()
	defer conn.Close()
	ctl, err := conn.Accept()
	if err != nil {
		return
	}
	rc := proto.NewRPCConn(ctl)
	var dev *devConn

	rc.Handle("reg", func(params json.RawMessage) (any, error) {
		var p RegParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if s.Token != "" && p.Token != s.Token {
			return nil, fmt.Errorf("bad hub token")
		}
		if p.ID != conn.RemoteID() {
			return nil, fmt.Errorf("registered id does not match certificate")
		}
		dev = &devConn{conn: conn, ctl: rc, addr: conn.RemoteAddr().String()}
		s.mu.Lock()
		// Re-registering a known id replaces its entry and never counts
		// against the cap, so reconnects keep working at capacity.
		if _, known := s.devices[p.ID]; !known && len(s.devices) >= maxDevices {
			s.mu.Unlock()
			return nil, fmt.Errorf("too many devices")
		}
		s.devices[p.ID] = dev
		s.mu.Unlock()
		s.Log.Info("device registered", "id", p.ID, "addr", dev.addr)
		return RegResult{Addr: dev.addr}, nil
	})
	rc.Handle("resolve", func(params json.RawMessage) (any, error) {
		var p ResolveParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if dev == nil {
			return nil, fmt.Errorf("register first")
		}
		if !dev.allowResolve() {
			return nil, fmt.Errorf("slow down")
		}
		s.mu.Lock()
		d := s.devices[p.ID]
		s.mu.Unlock()
		if d == nil {
			return ResolveResult{Found: false}, nil
		}
		return ResolveResult{Found: true, Addr: d.addr}, nil
	})
	rc.Handle("relay", func(params json.RawMessage) (any, error) {
		var p RelayParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if dev == nil {
			return nil, fmt.Errorf("register first")
		}
		return nil, s.startRelay(dev, p)
	})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error("hub goroutine panic", "where", "rpcServe", "panic", r)
			}
		}()
		rc.Serve()
	}()

	for {
		st, err := conn.Accept()
		if err != nil {
			break
		}
		var h StreamHeader
		if err := ReadMsg(st, &h); err != nil || h.Token == "" {
			_ = st.Close()
			continue
		}
		if ch, ok := s.pending.Load(h.Token); ok {
			select {
			case ch.(chan transport.Stream) <- st:
			default:
				_ = st.Close()
			}
			continue
		}
		// Early arrival: the requester's stream may reach us before its
		// "relay" RPC registers the pending slot. Cache it. LoadOrStore is
		// atomic against the janitor's CompareAndDelete: after a deletion the
		// sender gets (or creates) a fresh entry, never a closed one.
		e, _ := s.early.LoadOrStore(h.Token, newEarlyEntry())
		if !e.(*earlyEntry).offer(st) {
			_ = st.Close()
		}
	}

	if dev != nil {
		s.mu.Lock()
		if cur := s.devices[conn.RemoteID()]; cur == dev {
			delete(s.devices, conn.RemoteID())
		}
		s.mu.Unlock()
		s.Log.Info("device left", "id", conn.RemoteID())
	}
}

// startRelay waits for both relay streams (requester + destination), pairs
// them and pipes ciphertext.
func (s *Server) startRelay(src *devConn, p RelayParams) error {
	if p.Token == "" || p.Dst == "" || p.Dst == src.conn.RemoteID() {
		return fmt.Errorf("bad relay request")
	}
	s.mu.Lock()
	dst := s.devices[p.Dst]
	s.mu.Unlock()
	if dst == nil {
		return fmt.Errorf("destination %s not online", p.Dst)
	}
	if s.pendingCount.Add(1) > maxPendingRelays {
		s.pendingCount.Add(-1)
		return fmt.Errorf("too many pending relays")
	}
	// Every path below (success, timeout, notify error) drops the pending
	// slot and rebalances the counter.
	defer func() {
		s.pending.Delete(p.Token)
		s.pendingCount.Add(-1)
	}()
	ch := make(chan transport.Stream, 2)
	s.pending.Store(p.Token, ch)
	// Drain any streams that arrived before this RPC.
	if e := s.unlinkEarly(p.Token); e != nil {
		for _, st := range e.take() {
			select {
			case ch <- st:
			default:
				_ = st.Close() // pending buffer full: drop rather than block
			}
		}
	}

	if err := dst.ctl.Notify("relay.incoming", RelayIncoming{Src: src.conn.RemoteID(), Token: p.Token}); err != nil {
		return fmt.Errorf("notify destination: %w", err)
	}
	var streams [2]transport.Stream
	for i := 0; i < 2; i++ {
		select {
		case st := <-ch:
			streams[i] = st
		case <-time.After(relayWaitTimeout):
			for _, st := range streams {
				if st != nil {
					_ = st.Close()
				}
			}
			return fmt.Errorf("relay handshake incomplete (destination may be unreachable)")
		}
	}
	s.Log.Info("relay established", "src", src.conn.RemoteID(), "dst", p.Dst)
	go s.pipeRelay(streams[0], streams[1])
	return nil
}

// pipeRelay pipes ciphertext between the two relay streams until both copy
// directions finish. Runs on its own goroutine per relay.
func (s *Server) pipeRelay(a, b transport.Stream) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }() // buffered: never blocks
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error("hub goroutine panic", "where", "pipeRelay copy", "panic", r)
			}
		}()
		_, _ = io.Copy(b, a)
	}()
	go func() {
		defer func() { done <- struct{}{} }() // buffered: never blocks
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error("hub goroutine panic", "where", "pipeRelay copy", "panic", r)
			}
		}()
		_, _ = io.Copy(a, b)
	}()
	<-done
	<-done
}
