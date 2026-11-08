// Package hub implements the self-hosted rendezvous + relay server.
//
// Privacy model: the hub only sees device ids and encrypted bytes. Peer
// sessions relayed through it carry an inner TLS 1.3 layer with the peers'
// pinned device certificates, so the hub (its operator included) cannot
// read relayed traffic.
package hub

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

const relayWaitTimeout = 15 * time.Second

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

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
}

// Server is the hub.
type Server struct {
	Token string
	Log   *slog.Logger

	mu      sync.Mutex
	devices map[string]*devConn
	pending sync.Map // token -> chan transport.Stream (buffer 2)
	early   sync.Map // token -> chan transport.Stream, streams arriving before the relay RPC
}

// NewServer builds a hub with the given shared token (empty = open to any
// device; not recommended for public hubs).
func NewServer(token string, log *slog.Logger) *Server {
	return &Server{Token: token, Log: log, devices: map[string]*devConn{}}
}

// Run serves until the listener fails.
func (s *Server) Run(ln transport.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn transport.Conn) {
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

	go rc.Serve()

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
		// "relay" RPC registers the pending slot. Cache it.
		v, _ := s.early.LoadOrStore(h.Token, make(chan transport.Stream, 2))
		select {
		case v.(chan transport.Stream) <- st:
		default:
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
	ch := make(chan transport.Stream, 2)
	s.pending.Store(p.Token, ch)
	// Drain any streams that arrived before this RPC.
	if v, ok := s.early.Load(p.Token); ok {
		s.early.Delete(p.Token)
	drain:
		for {
			select {
			case st := <-v.(chan transport.Stream):
				ch <- st
			default:
				break drain
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
	go pipeRelay(streams[0], streams[1])
	return nil
}

func pipeRelay(a, b transport.Stream) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
	<-done
}
