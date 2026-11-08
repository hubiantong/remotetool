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
	grants     map[string]*grantEntry   // ruleID -> dial consent granted by a rule owner (mode L)
	peerGen    map[string]uint64        // peerID -> current connection generation
	lookupPeer LookupPeerFn
}

type ruleListener struct {
	Rule config.FwdRule
	ln   net.Listener
	peer *session.Peer // peer to stream toward (mode L) or back from (mode R)
}

// grantEntry is the dial consent a rule owner registered on this device via
// fwd.grant (mode L target side): the peer may dial exactly this target when
// it streams in a connection carrying the rule id. Grants are bound to the
// owning connection generation and dropped when it closes.
type grantEntry struct {
	TargetHost string
	TargetPort int
	PeerID     string
	gen        uint64
}

// grantParams registers dial consent on the peer (mode L owner -> target).
type grantParams struct {
	ID         string `json:"id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
}

// maxGrants caps the dial-consent table per device.
const maxGrants = 256

// dialTimeout bounds the outbound dial for every forwarded connection.
const dialTimeout = 10 * time.Second

// NewService builds the fwd feature.
func NewService(log *slog.Logger, store *config.Store) *Service {
	return &Service{log: log, store: store, listeners: map[string]*ruleListener{}, grants: map[string]*grantEntry{}, peerGen: map[string]uint64{}}
}

func (s *Service) Name() string     { return "fwd" }
func (s *Service) Chan() proto.Chan { return proto.ChanFwd }

type listenParams struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// AttachRPC registers fwd control methods.
func (s *Service) AttachRPC(peer *session.Peer, rc *proto.RPCConn) {
	// Generation counter per peer: grants (and their cleanup watchers) are
	// tagged with it so a late-firing watcher of an old connection cannot
	// wipe grants registered by the reconnect.
	gen := s.nextGen(peer.ID)
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
		// Only the connection that created a listener may tear it down;
		// foreign or unknown ids are ignored (no existence leak).
		s.stopListenerFor(peer, p.ID)
		return nil, nil
	})
	rc.Handle("fwd.grant", func(params json.RawMessage) (any, error) {
		var p grantParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if p.ID == "" {
			return nil, fmt.Errorf("missing rule id")
		}
		if p.TargetPort <= 0 || p.TargetPort > 65535 {
			return nil, fmt.Errorf("bad port %d", p.TargetPort)
		}
		if err := s.addGrant(p.ID, peer.ID, p.TargetHost, p.TargetPort, gen); err != nil {
			return nil, err
		}
		return nil, nil
	})
	// Grants are consent tied to a live connection: drop this generation's
	// grants when the peer disconnects (peer.ID is the pinned remote id).
	go func(peerID string, gen uint64) {
		<-rc.Done()
		s.dropGrantsGen(peerID, gen)
	}(peer.ID, gen)
}

// HandleStream pipes one forwarded connection. The dial target never travels
// on the wire; a header's RuleID resolves to a dial target only via
//   - the grant table (consent registered by the rule owner via fwd.grant,
//     mode L target side), or
//   - our own config rules bound to the calling peer (mode R owner side).
//
// Anything else — including the legacy Header.Dial, which made every paired
// device an open proxy — is rejected and the stream closed.
func (s *Service) HandleStream(peer *session.Peer, _ proto.Chan, h *proto.DataHeader, st transport.Stream) {
	defer st.Close()
	if h.Dial != "" {
		// Legacy peers put the raw dial target on the wire. Old peers are
		// incompatible by design and ship with the new version.
		s.log.Warn("legacy fwd dial rejected", "peer", peer.ID, "dial", h.Dial)
		return
	}
	if h.RuleID == "" {
		return
	}
	var target string
	if g, ok := s.grantByID(h.RuleID); ok && g.PeerID == peer.ID {
		// Mode L target side: dial what the rule owner granted.
		target = net.JoinHostPort(g.TargetHost, strconv.Itoa(g.TargetPort))
	} else if rule, ok := s.ruleByID(h.RuleID); ok && rule.PeerID == peer.ID && rule.Mode == "R" {
		// Mode R owner side: our rule's remote listener streams back.
		target = net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.TargetPort))
	} else {
		s.log.Warn("fwd stream rejected", "peer", peer.ID, "rule", h.RuleID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
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

// nextGen bumps and returns the connection generation for peerID. Called on
// every AttachRPC (once per connection): grants of older generations belong
// to dead connections and are pruned here and now.
func (s *Service) nextGen(peerID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerGen[peerID]++
	gen := s.peerGen[peerID]
	for id, g := range s.grants {
		if g.PeerID == peerID && g.gen != gen {
			delete(s.grants, id)
		}
	}
	return gen
}

// addGrant records dial consent granted by a rule owner on this device.
func (s *Service) addGrant(id, peerID, targetHost string, targetPort int, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[id]; !ok && len(s.grants) >= maxGrants {
		return fmt.Errorf("too many fwd grants")
	}
	s.grants[id] = &grantEntry{TargetHost: targetHost, TargetPort: targetPort, PeerID: peerID, gen: gen}
	return nil
}

// dropGrantsGen removes the grants of one connection generation (its
// connection closed). Newer grants for the same peer survive.
func (s *Service) dropGrantsGen(peerID string, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.PeerID == peerID && g.gen == gen {
			delete(s.grants, id)
		}
	}
}

func (s *Service) grantByID(id string) (grantEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return grantEntry{}, false
	}
	return *g, true
}

// loopbackAllowed enforces the loopback-only default for forward listeners:
// binding a non-loopback address requires AllowNonLoopbackFwd in the config.
func loopbackAllowed(host string, allowNonLoopback bool) error {
	if allowNonLoopback {
		return nil
	}
	if host == "" || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("non-loopback listen host %q refused (set allow_non_loopback_fwd to allow)", host)
}

// listenRemote starts a listener that streams accepted connections back to
// the requesting peer (mode R).
func (s *Service) listenRemote(peer *session.Peer, id, host string, port int) error {
	if host == "" {
		host = "127.0.0.1"
	}
	if err := loopbackAllowed(host, s.store.Get().AllowNonLoopbackFwd); err != nil {
		return err
	}
	s.mu.Lock()
	var stale *ruleListener
	if rl, ok := s.listeners[id]; ok {
		if rl.peer == peer {
			s.mu.Unlock()
			return nil // already listening for this connection
		}
		if rl.peer.ID != peer.ID {
			s.mu.Unlock()
			// A different device is squatting on this id; refuse without
			// disturbing its listener.
			return fmt.Errorf("listener id already in use")
		}
		// Listener left over from a previous connection of the same device:
		// replace it, or accepted conns would stream over the dead peer.
		delete(s.listeners, id)
		stale = rl
	}
	s.mu.Unlock()
	if stale != nil {
		_ = stale.ln.Close()
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	rl := &ruleListener{
		Rule: config.FwdRule{ID: id, Mode: "R", ListenHost: host, ListenPort: port, PeerID: peer.ID},
		ln:   ln, peer: peer,
	}
	s.mu.Lock()
	s.listeners[id] = rl
	s.mu.Unlock()
	go s.acceptLoop(rl)
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
		if err := loopbackAllowed(host, s.store.Get().AllowNonLoopbackFwd); err != nil {
			return err
		}
		// The target no longer travels on data-stream headers: register the
		// dial consent on the peer before listening locally. The grant is
		// (re-)sent on every re-apply because a reconnecting peer drops its
		// grants, so rules keep working across reconnects.
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := peer.RPC(ctx, "fwd.grant", grantParams{ID: rule.ID, TargetHost: rule.TargetHost, TargetPort: rule.TargetPort}, nil); err != nil {
			return fmt.Errorf("grant target on peer: %w", err)
		}
		s.mu.Lock()
		var stale *ruleListener
		if rl, ok := s.listeners[rule.ID]; ok {
			if rl.peer == peer {
				s.mu.Unlock()
				return nil // already listening for this connection
			}
			if rl.peer.ID != peer.ID {
				s.mu.Unlock()
				// A different device is squatting on this id; refuse without
				// disturbing its listener.
				return fmt.Errorf("listener id already in use")
			}
			// Replace a listener left over from a previous connection of the
			// same device.
			delete(s.listeners, rule.ID)
			stale = rl
		}
		s.mu.Unlock()
		if stale != nil {
			_ = stale.ln.Close()
		}
		addr := net.JoinHostPort(host, strconv.Itoa(rule.ListenPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		rl := &ruleListener{Rule: rule, ln: ln, peer: peer}
		s.mu.Lock()
		s.listeners[rule.ID] = rl
		s.mu.Unlock()
		go s.acceptLoop(rl)
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

// stopListenerFor stops the listener only if it was created by this peer's
// connection (the fwd.unlisten RPC path). Foreign or unknown ids are ignored
// without revealing which ids exist.
func (s *Service) stopListenerFor(peer *session.Peer, id string) {
	s.mu.Lock()
	rl, ok := s.listeners[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	if rl.peer != peer {
		s.mu.Unlock()
		s.log.Warn("fwd.unlisten for foreign listener refused", "rule", id, "peer", peer.ID)
		return
	}
	delete(s.listeners, id)
	s.mu.Unlock()
	_ = rl.ln.Close() // acceptLoop ends via the listener close
}

func (s *Service) stopListener(id string) {
	s.mu.Lock()
	rl, ok := s.listeners[id]
	delete(s.listeners, id)
	s.mu.Unlock()
	if ok {
		_ = rl.ln.Close() // acceptLoop ends via the listener close
	}
}

// StopAll closes every local rule listener (daemon exit), so the accept
// loops exit and nothing holds ports open. Listeners the PEER opened for our
// mode R rules are not unlisted via RPC here: the peer tears them down when
// our connection drops.
func (s *Service) StopAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.listeners))
	for id := range s.listeners {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.stopListener(id)
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

func (s *Service) acceptLoop(rl *ruleListener) {
	for {
		conn, err := rl.ln.Accept()
		if err != nil {
			return
		}
		go s.handleAccepted(rl, conn)
	}
}

func (s *Service) handleAccepted(rl *ruleListener, conn net.Conn) {
	defer conn.Close()
	// The dial target never travels on the wire: both modes carry only the
	// rule id. The receiving side resolves the target itself — mode L via the
	// grant the owner registered, mode R via the owner's own config rule.
	hdr := proto.DataHeader{RuleID: rl.Rule.ID}
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
