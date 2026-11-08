// Package fwd implements persistent TCP port forwarding between paired
// devices, similar to SSH tunnels:
//
//	Mode "L": this device listens; accepted connections dial the target
//	          through the peer (peer dials targetHost:targetPort).
//	Mode "R": the peer listens; accepted connections are streamed back here
//	          and this device dials the target.
//
// Rules persist in config.json and re-apply automatically whenever the peer
// reconnects.
package fwd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/proto"
	"remotetool/internal/session"
	"remotetool/internal/transport"
)

// Service is the port-forwarding feature.
type Service struct {
	log   *slog.Logger
	store *config.Store

	mu         sync.Mutex
	listeners  map[string]*ruleListener // ruleID -> active listener on THIS device
	lookupPeer LookupPeerFn
}

type ruleListener struct {
	Rule  config.FwdRule
	ln    net.Listener
	peer  *session.Peer // peer to stream back to (mode R) or toward (mode L)
	done  chan struct{}
}

// NewService builds the fwd feature.
func NewService(log *slog.Logger, store *config.Store) *Service {
	return &Service{log: log, store: store, listeners: map[string]*ruleListener{}}
}

func (s *Service) Name() string   { return "fwd" }
func (s *Service) Chan() proto.Chan { return proto.ChanFwd }

type listenParams struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// AttachRPC registers fwd control methods.
func (s *Service) AttachRPC(peer *session.Peer, rc *proto.RPCConn) {
	rc.Handle("fwd.listen", func(params json.RawMessage) (any, error) {
		var p listenParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if p.Port <= 0 || p.Port > 65535 {
			return nil, fmt.Errorf("bad port %d", p.Port)
		}
		if err := s.listenRemote(peer, p.ID, p.Host, p.Port); err != nil {
			return nil, err
		}
		return nil, nil
	})
	rc.Handle("fwd.unlisten", func(params json.RawMessage) (any, error) {
		var p listenParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		s.stopListener(p.ID)
		return nil, nil
	})
}

// HandleStream pipes one forwarded connection.
//   - Header.Dial set: peer asks us to dial (mode L target side).
//   - Header.RuleID set: peer's remote listener hands the connection to us
//     (mode R rule owner side).
func (s *Service) HandleStream(peer *session.Peer, _ proto.Chan, h *proto.DataHeader, st transport.Stream) {
	defer st.Close()
	var target string
	if h.Dial != "" {
		target = h.Dial
	} else if h.RuleID != "" {
		rule, ok := s.ruleByID(h.RuleID)
		if !ok {
			return
		}
		target = net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.TargetPort))
	} else {
		return
	}
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "tcp", target)
	if err != nil {
		s.log.Warn("fwd dial failed", "target", target, "err", err)
		return
	}
	defer conn.Close()
	pipe(st, conn)
}

func pipe(a io.ReadWriteCloser, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); _ = a.Close(); _ = b.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); _ = a.Close(); _ = b.Close(); done <- struct{}{} }()
	<-done
	<-done
}

func (s *Service) ruleByID(id string) (config.FwdRule, bool) {
	for _, r := range s.store.Get().FwdRules {
		if r.ID == id {
			return r, true
		}
	}
	return config.FwdRule{}, false
}

// listenRemote starts a listener that streams accepted connections back to
// the requesting peer (mode R).
func (s *Service) listenRemote(peer *session.Peer, id, host string, port int) error {
	if host == "" {
		host = "127.0.0.1"
	}
	s.mu.Lock()
	if _, ok := s.listeners[id]; ok {
		s.mu.Unlock()
		return nil // already listening
	}
	s.mu.Unlock()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	rl := &ruleListener{
		Rule: config.FwdRule{ID: id, Mode: "R", ListenHost: host, ListenPort: port},
		ln:   ln, peer: peer, done: make(chan struct{}),
	}
	s.mu.Lock()
	s.listeners[id] = rl
	s.mu.Unlock()
	go s.acceptLoop(rl, true)
	s.log.Info("remote forward listening", "rule", id, "addr", addr)
	return nil
}

// ApplyRule starts a rule for a connected peer (mode L here, mode R remote).
func (s *Service) ApplyRule(rule config.FwdRule, peer *session.Peer) error {
	switch rule.Mode {
	case "L":
		host := rule.ListenHost
		if host == "" {
			host = "127.0.0.1"
		}
		s.mu.Lock()
		if _, ok := s.listeners[rule.ID]; ok {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		addr := net.JoinHostPort(host, strconv.Itoa(rule.ListenPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		rl := &ruleListener{Rule: rule, ln: ln, peer: peer, done: make(chan struct{})}
		s.mu.Lock()
		s.listeners[rule.ID] = rl
		s.mu.Unlock()
		go s.acceptLoop(rl, false)
		s.log.Info("local forward listening", "rule", rule.ID, "addr", addr, "target", rule.TargetHost, "port", rule.TargetPort)
		return nil
	case "R":
		host := rule.ListenHost
		if host == "" {
			host = "127.0.0.1"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return peer.RPC(ctx, "fwd.listen", listenParams{ID: rule.ID, Host: host, Port: rule.ListenPort}, nil)
	default:
		return fmt.Errorf("unknown mode %q", rule.Mode)
	}
}

// StopRule tears a rule down (local listener and/or remote listener).
func (s *Service) StopRule(rule config.FwdRule) {
	s.stopListener(rule.ID)
	if rule.Mode == "R" {
		if peer, ok := s.findPeer(rule.PeerID); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = peer.RPC(ctx, "fwd.unlisten", listenParams{ID: rule.ID}, nil)
		}
	}
}

func (s *Service) stopListener(id string) {
	s.mu.Lock()
	rl, ok := s.listeners[id]
	delete(s.listeners, id)
	s.mu.Unlock()
	if ok {
		_ = rl.ln.Close()
		close(rl.done)
	}
}

// ListenerRules returns the ids of rules currently listening locally.
func (s *Service) ActiveRules() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for id := range s.listeners {
		out[id] = true
	}
	return out
}

func (s *Service) findPeer(peerID string) (*session.Peer, bool) {
	if peerID == "" {
		return nil, false
	}
	s.mu.Lock()
	fn := s.lookupPeer
	s.mu.Unlock()
	if fn == nil {
		return nil, false
	}
	return fn(peerID)
}

func (s *Service) acceptLoop(rl *ruleListener, streamBack bool) {
	for {
		conn, err := rl.ln.Accept()
		if err != nil {
			return
		}
		go s.handleAccepted(rl, conn, streamBack)
	}
}

func (s *Service) handleAccepted(rl *ruleListener, conn net.Conn, streamBack bool) {
	defer conn.Close()
	var hdr proto.DataHeader
	if streamBack {
		hdr = proto.DataHeader{RuleID: rl.Rule.ID}
	} else {
		hdr = proto.DataHeader{Dial: net.JoinHostPort(rl.Rule.TargetHost, strconv.Itoa(rl.Rule.TargetPort))}
	}
	st, err := rl.peer.OpenData(proto.ChanFwd, &hdr)
	if err != nil {
		s.log.Warn("fwd open stream failed", "rule", rl.Rule.ID, "err", err)
		return
	}
	defer st.Close()
	pipe(st, conn)
}

// LookupPeerFn resolves a peer id to a connected peer.
type LookupPeerFn func(peerID string) (*session.Peer, bool)

// SetLookupPeer wires the session manager in (avoids an import cycle).
func (s *Service) SetLookupPeer(fn LookupPeerFn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookupPeer = fn
}
