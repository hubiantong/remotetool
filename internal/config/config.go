// Package config persists daemon configuration and the paired-peer registry.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	// DefaultListenPort is the QUIC data-plane port.
	DefaultListenPort = 27183
	// DefaultWebPort is the local Web UI port.
	DefaultWebPort = 27180
)

// FwdRule is one persisted port-forwarding rule.
type FwdRule struct {
	ID         string `json:"id"`
	PeerID     string `json:"peer_id"`
	Mode       string `json:"mode"` // "L": listen here, dial target via peer; "R": peer listens, we dial target
	ListenHost string `json:"listen_host,omitempty"`
	ListenPort int    `json:"listen_port"`
	TargetHost string `json:"target_host,omitempty"`
	TargetPort int    `json:"target_port"`
}

// Peer is a paired remote device. PubKey pins its Ed25519 identity.
type Peer struct {
	ID       string    `json:"id"` // hex device id
	Name     string    `json:"name"`
	PubKey   []byte    `json:"pubkey"`
	Caps     []string  `json:"caps,omitempty"`
	AddedAt  time.Time `json:"added_at"`
	LastAddr string    `json:"last_addr,omitempty"`
	LastSeen time.Time `json:"last_seen,omitempty"`
}

// Config is config.json.
type Config struct {
	Name       string    `json:"name"`
	ListenPort int       `json:"listen_port"`
	WebPort    int       `json:"web_port"`
	WebToken   string    `json:"web_token"`
	HubAddr    string    `json:"hub_addr,omitempty"` // self-hosted hub (signaling + encrypted relay)
	HubToken   string    `json:"hub_token,omitempty"`
	FwdRules   []FwdRule `json:"fwd_rules,omitempty"`
}

// Store owns the config directory: config.json + peers.json.
type Store struct {
	mu    sync.Mutex
	dir   string
	cfg   Config
	peers map[string]Peer
}

// DefaultDir returns the per-user config directory.
func DefaultDir() string {
	if d := os.Getenv("RT_HOME"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if ad := os.Getenv("APPDATA"); ad != "" {
			return filepath.Join(ad, "remotetool")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "remotetool")
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "remotetool")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "remotetool")
}

// Open loads (or initializes) the store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, peers: map[string]Peer{}}
	if err := s.loadConfig(); err != nil {
		return nil, err
	}
	if err := s.loadPeers(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) loadConfig() error {
	path := filepath.Join(s.dir, "config.json")
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		host, _ := os.Hostname()
		s.cfg = Config{
			Name:       host,
			ListenPort: DefaultListenPort,
			WebPort:    DefaultWebPort,
			WebToken:   randHex(16),
		}
		return s.saveLocked()
	case err != nil:
		return err
	}
	if err := json.Unmarshal(b, &s.cfg); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if s.cfg.Name == "" {
		host, _ := os.Hostname()
		s.cfg.Name = host
	}
	if s.cfg.ListenPort == 0 {
		s.cfg.ListenPort = DefaultListenPort
	}
	if s.cfg.WebPort == 0 {
		s.cfg.WebPort = DefaultWebPort
	}
	if s.cfg.WebToken == "" {
		s.cfg.WebToken = randHex(16)
	}
	return s.saveLocked()
}

func (s *Store) loadPeers() error {
	path := filepath.Join(s.dir, "peers.json")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []Peer
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	for _, p := range list {
		s.peers[p.ID] = p
	}
	return nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, "config.json"), b)
}

func (s *Store) savePeersLocked() error {
	list := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		list = append(list, p)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, "peers.json"), b)
}

// Get returns a copy of the current config.
func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfg
	return c
}

// Update applies fn to the config and persists it.
func (s *Store) Update(fn func(c *Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cfg)
	return s.saveLocked()
}

// Peers returns all paired peers.
func (s *Store) Peers() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	return out
}

// Peer looks up a paired peer by device id.
func (s *Store) Peer(id string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[id]
	return p, ok
}

// UpsertPeer adds or updates a paired peer.
func (s *Store) UpsertPeer(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		return fmt.Errorf("peer id required")
	}
	if old, ok := s.peers[p.ID]; ok && p.AddedAt.IsZero() {
		p.AddedAt = old.AddedAt
	}
	if p.AddedAt.IsZero() {
		p.AddedAt = time.Now()
	}
	s.peers[p.ID] = p
	return s.savePeersLocked()
}

// RemovePeer unpairs a device.
func (s *Store) RemovePeer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, id)
	return s.savePeersLocked()
}

// TouchPeer records a successful connection.
func (s *Store) TouchPeer(id, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[id]
	if !ok {
		return
	}
	p.LastAddr = addr
	p.LastSeen = time.Now()
	s.peers[id] = p
	_ = s.savePeersLocked()
}

func atomicWrite(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
