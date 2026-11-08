package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/transport"
)

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
		p, err := m.dialHandshake(ctx, conn, a)
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
		p, err := m.dialHandshake(ctx, conn, "relay")
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("connect %s via relay: %w", peer.Name, err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("connect %s: %w", peer.Name, lastErr)
}
