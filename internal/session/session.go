// Package session manages authenticated peer connections: dialing, the hello
// handshake, RPC dispatch and data-stream routing to feature services.
package session

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/identity"
	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

// hello is exchanged via the "hello" RPC method on connect.
type hello struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Caps []string `json:"caps"`
}

// Peer is one connected remote device.
type Peer struct {
	ID   string
	Name string
	Caps []string
	Addr string

	conn transport.Conn
	rpc  *proto.RPCConn
	mgr  *Manager
}

// RPC issues a control request to the peer.
func (p *Peer) RPC(ctx context.Context, method string, params, result any) error {
	return p.rpc.Call(ctx, method, params, result)
}

// Notify sends an unsolicited message to the peer.
func (p *Peer) Notify(method string, params any) error {
	return p.rpc.Notify(method, params)
}

// OpenData opens a typed data stream to the peer.
func (p *Peer) OpenData(ch proto.Chan, h *proto.DataHeader) (transport.Stream, error) {
	s, err := p.conn.Open()
	if err != nil {
		return nil, err
	}
	if err := proto.WriteDataHeader(s, ch, h); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Conn exposes the underlying transport connection (used by the pairing
// service for channel binding and certificate access).
func (p *Peer) Conn() transport.Conn { return p.conn }

func (p *Peer) shutdown() {
	_ = p.rpc.Close()
	_ = p.conn.Close()
}

// Feature is a capability service attached to every peer session.
type Feature interface {
	Name() string
	// Chan is the data-stream channel type this feature owns.
	Chan() proto.Chan
	// AttachRPC registers control methods on a new peer connection.
	AttachRPC(p *Peer, rc *proto.RPCConn)
	HandleStream(p *Peer, ch proto.Chan, h *proto.DataHeader, s transport.Stream)
}

// Event describes a manager-level state change for the UI.
type Event struct {
	Type   string `json:"type"` // peer_up, peer_down
	PeerID string `json:"peer_id,omitempty"`
	Data   any    `json:"data,omitempty"`
}

// Manager owns all peer connections.
type Manager struct {
	id    *identity.Identity
	store *config.Store
	log   *slog.Logger

	mu       sync.Mutex
	conns    map[string]*Peer
	cand     map[string]map[string]bool // peer id -> known addresses
	features []Feature
	hooks    []func(Event)
	dialing  map[string]*dialCall

	// onUnpaired handles a connection from a device that is not paired
	// (the pairing service takes over).
	onUnpaired func(conn transport.Conn)

	// pairAttach installs pair.request/pair.confirm handlers on every control
	// stream, so pairing also works between devices that are already paired
	// (re-pairing). Called before Serve on both paths.
	pairAttach func(conn transport.Conn, rc *proto.RPCConn)

	// hub is the optional self-hosted rendezvous/relay client.
	hub *HubClient
}

// SetHub wires the hub client (optional; enables WAN reachability).
func (m *Manager) SetHub(h *HubClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hub = h
}

// OnUnpaired installs the handler for connections from unpaired devices.
func (m *Manager) OnUnpaired(fn func(conn transport.Conn)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onUnpaired = fn
}

// OnPairSession installs handlers added to every new control stream.
func (m *Manager) OnPairSession(fn func(conn transport.Conn, rc *proto.RPCConn)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pairAttach = fn
}

type dialCall struct {
	done chan struct{}
	peer *Peer
	err  error
}

func NewManager(id *identity.Identity, store *config.Store, log *slog.Logger) *Manager {
	return &Manager{
		id:      id,
		store:   store,
		log:     log,
		conns:   map[string]*Peer{},
		cand:    map[string]map[string]bool{},
		dialing: map[string]*dialCall{},
	}
}

// AddFeature registers a capability service; attached to every peer session.
func (m *Manager) AddFeature(f Feature) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.features = append(m.features, f)
}

// OnEvent subscribes to manager events.
func (m *Manager) OnEvent(fn func(Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, fn)
}

func (m *Manager) emit(ev Event) {
	m.mu.Lock()
	hooks := append([]func(Event){}, m.hooks...)
	m.mu.Unlock()
	for _, h := range hooks {
		h(ev)
	}
}

func (m *Manager) caps() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.features))
	for _, f := range m.features {
		out = append(out, f.Name())
	}
	return out
}

// AddCandidate records a reachable address for a peer (mDNS / hub / manual).
func (m *Manager) AddCandidate(peerID, addr string) {
	if peerID == m.id.ID {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.cand[peerID]
	if set == nil {
		set = map[string]bool{}
		m.cand[peerID] = set
	}
	set[addr] = true
}

// Candidates lists known addresses for a peer, last successful one first.
func (m *Manager) Candidates(peerID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for a := range m.cand[peerID] {
		out = append(out, a)
	}
	return out
}

// Connected returns all currently connected peers.
func (m *Manager) Connected() []*Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Peer, 0, len(m.conns))
	for _, p := range m.conns {
		out = append(out, p)
	}
	return out
}

// Get returns the connected peer, if any.
func (m *Manager) Get(peerID string) (*Peer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.conns[peerID]
	return p, ok
}

// Connect ensures a peer is connected, single-flighting concurrent dials.
func (m *Manager) Connect(ctx context.Context, peerID string) (*Peer, error) {
	if p, ok := m.Get(peerID); ok {
		return p, nil
	}
	m.mu.Lock()
	if dc, ok := m.dialing[peerID]; ok {
		m.mu.Unlock()
		select {
		case <-dc.done:
			if dc.err != nil {
				return nil, dc.err
			}
			return dc.peer, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	dc := &dialCall{done: make(chan struct{})}
	m.dialing[peerID] = dc
	m.mu.Unlock()

	p, err := m.dialPeer(ctx, peerID)
	dc.peer, dc.err = p, err
	close(dc.done)

	m.mu.Lock()
	delete(m.dialing, peerID)
	m.mu.Unlock()
	return p, err
}

func (m *Manager) pinVerify() func(string, ed25519.PublicKey) error {
	store := m.store
	return func(id string, pub ed25519.PublicKey) error {
		p, ok := store.Peer(id)
		if !ok {
			return fmt.Errorf("unknown device %s", id)
		}
		if string(p.PubKey) != string(pub) {
			return fmt.Errorf("device %s key mismatch (possible attack)", id)
		}
		return nil
	}
}

func (m *Manager) dialPeer(ctx context.Context, peerID string) (*Peer, error) {
	peer, ok := m.store.Peer(peerID)
	if !ok {
		return nil, fmt.Errorf("not paired with %s", peerID)
	}
	var addrs []string
	if peer.LastAddr != "" {
		addrs = append(addrs, peer.LastAddr)
	}
	addrs = append(addrs, m.Candidates(peerID)...)
	m.mu.Lock()
	hub := m.hub
	m.mu.Unlock()
	if hub != nil {
		if a, ok := hub.Resolve(ctx, peerID); ok {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no known address for %s (%s)", peer.Name, peerID)
	}
	var lastErr error
	for _, a := range addrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(a, fmt.Sprint(config.DefaultListenPort))
		}
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		conn, err := transport.Dial(dctx, a, m.id.TLSConfig(m.pinVerify()))
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if conn.RemoteID() != peerID {
			_ = conn.Close()
			return nil, fmt.Errorf("address %s serves device %s, expected %s", a, conn.RemoteID(), peerID)
		}
		p, err := m.dialHandshake(conn, a)
		if err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		return p, nil
	}
	if lastErr == nil {
		lastErr = errors.New("unreachable")
	}
	// Direct dialing failed: fall back to the hub relay (end-to-end
	// encrypted, the hub only pipes ciphertext).
	if hub != nil {
		conn, err := hub.Relay(ctx, peerID)
		if err != nil {
			return nil, fmt.Errorf("connect %s: %w (relay: %v)", peer.Name, lastErr, err)
		}
		if conn.RemoteID() != peerID {
			_ = conn.Close()
			return nil, fmt.Errorf("relay served device %s, expected %s", conn.RemoteID(), peerID)
		}
		p, err := m.dialHandshake(conn, "relay")
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("connect %s via relay: %w", peer.Name, err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("connect %s: %w", peer.Name, lastErr)
}

// ServeListener accepts inbound pin-verified connections forever. Pairing
// runs on a separate short-lived listener (pair service).
func (m *Manager) ServeListener(l transport.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			m.log.Info("listener stopped", "err", err)
			return
		}
		if _, ok := m.store.Peer(conn.RemoteID()); !ok {
			m.mu.Lock()
			fn := m.onUnpaired
			m.mu.Unlock()
			if fn == nil {
				m.log.Warn("rejected unpaired device", "id", conn.RemoteID())
				_ = conn.Close()
				continue
			}
			go fn(conn)
			continue
		}
		if _, err := m.acceptHandshake(conn, conn.RemoteAddr().String()); err != nil {
			m.log.Warn("inbound handshake failed", "id", conn.RemoteID(), "err", err)
			_ = conn.Close()
		}
	}
}

// ConnectAddr dials a specific address expecting any already-paired peer.
// Used by the web "connect by address" fast path.
func (m *Manager) ConnectAddr(ctx context.Context, addr string) (*Peer, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, fmt.Sprint(config.DefaultListenPort))
	}
	dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := transport.Dial(dctx, addr, m.id.TLSConfig(m.pinVerify()))
	if err != nil {
		return nil, err
	}
	p, err := m.dialHandshake(conn, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return p, nil
}

func (m *Manager) myHello() hello {
	return hello{ID: m.id.ID, Name: m.store.Get().Name, Caps: m.caps()}
}

// dialHandshake: we opened the connection, we open the control stream and
// initiate hello.
func (m *Manager) dialHandshake(conn transport.Conn, addr string) (*Peer, error) {
	ctl, err := conn.Open()
	if err != nil {
		return nil, err
	}
	rc := proto.NewRPCConn(ctl)
	go rc.Serve()
	rc.Handle("hello", func(params json.RawMessage) (any, error) {
		return m.myHello(), nil
	})
	var their hello
	if err := rc.Call(context.Background(), "hello", m.myHello(), &their); err != nil {
		_ = ctl.Close()
		return nil, fmt.Errorf("hello: %w", err)
	}
	return m.register(conn, rc, addr, their), nil
}

// acceptHandshake: peer dialed us; accept the control stream and answer.
func (m *Manager) acceptHandshake(conn transport.Conn, addr string) (*Peer, error) {
	ctl, err := conn.Accept()
	if err != nil {
		return nil, err
	}
	rc := proto.NewRPCConn(ctl)
	var their hello
	rc.Handle("hello", func(params json.RawMessage) (any, error) {
		if err := json.Unmarshal(params, &their); err != nil {
			return nil, err
		}
		return m.myHello(), nil
	})
	m.mu.Lock()
	pa := m.pairAttach
	m.mu.Unlock()
	if pa != nil {
		pa(conn, rc)
	}
	// Wait for the dialer's hello (handler runs on the Serve goroutine).
	done := make(chan struct{})
	rc.OnNotify = func(string, json.RawMessage) {}
	go func() {
		rc.Serve()
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if their.ID != "" {
			break
		}
		select {
		case <-done:
			return nil, errors.New("connection closed during hello")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if their.ID == "" {
		return nil, errors.New("hello timeout")
	}
	return m.register(conn, rc, addr, their), nil
}

// register wires a verified connection into the manager and starts its
// data-stream dispatch loop.
func (m *Manager) register(conn transport.Conn, rc *proto.RPCConn, addr string, their hello) *Peer {
	peerID := conn.RemoteID()
	p := &Peer{ID: peerID, Name: their.Name, Caps: their.Caps, Addr: addr, conn: conn, rpc: rc, mgr: m}

	m.mu.Lock()
	features := append([]Feature{}, m.features...)
	pa := m.pairAttach
	if old, ok := m.conns[peerID]; ok && old != p {
		// Glare or reconnect: keep the newest connection.
		m.mu.Unlock()
		old.shutdown()
		m.mu.Lock()
	}
	m.conns[peerID] = p
	m.mu.Unlock()
	for _, f := range features {
		f.AttachRPC(p, rc)
	}
	if pa != nil {
		pa(conn, rc)
	}
	m.store.TouchPeer(peerID, addr)

	go func() {
		<-rc.Done()
		m.mu.Lock()
		if cur, ok := m.conns[peerID]; ok && cur == p {
			delete(m.conns, peerID)
		}
		m.mu.Unlock()
		m.emit(Event{Type: "peer_down", PeerID: peerID})
	}()
	go m.dispatchLoop(p)
	m.emit(Event{Type: "peer_up", PeerID: peerID, Data: map[string]any{"name": p.Name}})
	m.log.Info("peer connected", "id", peerID, "name", p.Name, "addr", addr)
	return p
}

// dispatchLoop accepts data streams and routes them to features.
func (m *Manager) dispatchLoop(p *Peer) {
	for {
		s, err := p.conn.Accept()
		if err != nil {
			return
		}
		ch, hdr, err := proto.ReadDataHeader(s)
		if err != nil {
			_ = s.Close()
			continue
		}
		m.mu.Lock()
		features := append([]Feature{}, m.features...)
		m.mu.Unlock()
		handled := false
		for _, f := range features {
			if f.Chan() == ch {
				handled = true
				go func() {
					defer func() {
						if r := recover(); r != nil {
							m.log.Error("feature handler panic", "feature", f.Name(), "panic", r)
							_ = s.Close()
						}
					}()
					f.HandleStream(p, ch, hdr, s)
				}()
				break
			}
		}
		if !handled {
			m.log.Warn("no handler for data stream", "chan", ch)
			_ = s.Close()
		}
	}
}

// Disconnect closes the connection to a peer.
func (m *Manager) Disconnect(peerID string) {
	if p, ok := m.Get(peerID); ok {
		p.shutdown()
	}
}
