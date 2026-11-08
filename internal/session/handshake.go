package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

// helloRPCTimeout bounds the dialer's hello RPC: a dead peer must error in
// 10s instead of hanging on the caller's possibly deadline-less context.
// Package-level var so tests can shorten it.
var helloRPCTimeout = 10 * time.Second

// dialHandshake: we opened the connection, we open the control stream and
// initiate hello.
func (m *Manager) dialHandshake(ctx context.Context, conn transport.Conn, addr string) (*Peer, error) {
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
	hctx, cancel := context.WithTimeout(ctx, helloRPCTimeout)
	defer cancel()
	if err := rc.Call(hctx, "hello", m.myHello(), &their); err != nil {
		_ = ctl.Close()
		return nil, fmt.Errorf("hello: %w", err)
	}
	return m.register(conn, rc, addr, their), nil
}

// helloTimeout bounds how long acceptHandshake waits for the dialer's hello.
// Package-level var so tests can shorten it.
var helloTimeout = 10 * time.Second

// acceptHandshake: peer dialed us; accept the control stream and answer.
func (m *Manager) acceptHandshake(conn transport.Conn, addr string) (*Peer, error) {
	ctl, err := conn.Accept()
	if err != nil {
		return nil, err
	}
	rc := proto.NewRPCConn(ctl)
	// The handler runs on the Serve goroutine; hand the hello over through a
	// channel instead of writing a shared variable (data race with the wait
	// below).
	helloCh := make(chan hello, 1)
	rc.Handle("hello", func(params json.RawMessage) (any, error) {
		var h hello
		if err := json.Unmarshal(params, &h); err != nil {
			return nil, err
		}
		if h.ID == "" {
			return nil, errors.New("empty hello id")
		}
		select {
		case helloCh <- h:
		default:
		}
		return m.myHello(), nil
	})
	m.mu.Lock()
	pa := m.pairAttach
	m.mu.Unlock()
	if pa != nil {
		pa(conn, rc)
	}
	// Wait for the dialer's hello.
	done := make(chan struct{})
	rc.OnNotify = func(string, json.RawMessage) {}
	go func() {
		rc.Serve()
		close(done)
	}()
	var their hello
	select {
	case their = <-helloCh:
	case <-done:
		// The handler may have delivered just before Serve returned.
		select {
		case their = <-helloCh:
		default:
			return nil, errors.New("connection closed during hello")
		}
	case <-time.After(helloTimeout):
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
