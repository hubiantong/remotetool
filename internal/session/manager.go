// Package session manages authenticated peer connections: dialing, the hello
// handshake, RPC dispatch and data-stream routing to feature services.
package session

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
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

	// activeStreams counts this peer's concurrent data streams (bounded by
	// maxPeerStreams) so one device cannot eat the whole connection quota.
	activeStreams atomic.Int32

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
	p, err := m.dialHandshake(ctx, conn, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return p, nil
}

func (m *Manager) myHello() hello {
	return hello{ID: m.id.ID, Name: m.store.Get().Name, Caps: m.caps()}
}

// maxPeerStreams caps one peer's concurrent data streams (ChanFile/ChanFwd/
// ChanTerm all flow through dispatchLoop), so a single device cannot eat the
// connection's whole stream quota (512).
const maxPeerStreams = 64

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
				if p.activeStreams.Add(1) > maxPeerStreams {
					p.activeStreams.Add(-1)
					m.log.Warn("peer stream limit reached", "peer", p.ID, "chan", ch)
					_ = s.Close()
					break
				}
				go func() {
					defer p.activeStreams.Add(-1)
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
