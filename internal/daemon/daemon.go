// Package daemon wires everything together: listener, session manager,
// feature services, discovery, pairing and the web UI.
package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/discover"
	"remotetool/internal/filex"
	"remotetool/internal/fwd"
	"remotetool/internal/identity"
	"remotetool/internal/session"
	"remotetool/internal/term"
	"remotetool/internal/transport"
	"remotetool/internal/web"
)

// Options overrides config defaults (from CLI flags).
type Options struct {
	Home       string
	Name       string
	ListenPort int
	WebPort    int
	Verbose    bool
}

// Daemon is the running rtd instance.
type Daemon struct {
	store *config.Store
	id    *identity.Identity
	log   *slog.Logger
	mgr   *session.Manager
	term  *term.Service
	filex *filex.Service
	fwd   *fwd.Service
	pair  *PairService
	mdns  *discover.MDNS

	events    *web.EventHub
	hubMu     sync.Mutex
	hubClient *session.HubClient
}

// EventHub is re-exported from the web package.
type EventHub = web.EventHub

// NewEventHub builds the broadcast hub.
func NewEventHub() *EventHub { return web.NewEventHub() }

// New builds the daemon (without starting it).
func New(opts Options) (*Daemon, error) {
	home := opts.Home
	if home == "" {
		home = config.DefaultDir()
	}
	store, err := config.Open(home)
	if err != nil {
		return nil, err
	}
	if opts.Name != "" {
		_ = store.Update(func(c *config.Config) { c.Name = opts.Name })
	}
	if opts.ListenPort != 0 {
		_ = store.Update(func(c *config.Config) { c.ListenPort = opts.ListenPort })
	}
	if opts.WebPort != 0 {
		_ = store.Update(func(c *config.Config) { c.WebPort = opts.WebPort })
	}

	log, logClose, err := makeLogger(home, opts.Verbose)
	if err != nil {
		return nil, err
	}
	id, err := identity.LoadOrCreate(home)
	if err != nil {
		return nil, err
	}
	log.Info("device identity", "id", id.ID, "name", store.Get().Name)

	hub := NewEventHub()
	mgr := session.NewManager(id, store, log)

	d := &Daemon{store: store, id: id, log: log, mgr: mgr, events: hub}
	d.term = term.NewService(log)
	d.filex = filex.NewService(log)
	d.fwd = fwd.NewService(log, store)
	d.pair = NewPairService(id, store, log)

	mgr.AddFeature(d.term)
	mgr.AddFeature(d.filex)
	mgr.AddFeature(d.fwd)
	mgr.OnUnpaired(d.pair.HandleUnpairedConn)
	mgr.OnPairSession(d.pair.AttachPairHandlers)
	mgr.OnEvent(func(ev session.Event) {
		hub.Publish(ev.Type, ev.PeerID, ev.Data)
		if ev.Type == "peer_up" {
			go d.applyRules(ev.PeerID)
		}
	})
	d.filex.OnProgress(func(p filex.Progress) {
		hub.Publish("xfer", p.PeerID, p)
	})
	d.fwd.SetLookupPeer(mgr.Get)
	_ = logClose
	return d, nil
}

func makeLogger(home string, verbose bool) (*slog.Logger, func(), error) {
	f, err := os.OpenFile(filepath.Join(home, "rtd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	w := io.MultiWriter(os.Stderr, f)
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
	return slog.New(h), func() { _ = f.Close() }, nil
}

// Store exposes the config store (for CLI-compatible tooling).
func (d *Daemon) Store() *config.Store { return d.store }

// ID returns the device id.
func (d *Daemon) ID() string { return d.id.ID }

// Run starts every component and blocks until ctx is done.
func (d *Daemon) Run(ctx context.Context) error {
	cfg := d.store.Get()

	ln, err := transport.Listen(net.JoinHostPort("0.0.0.0", strconv.Itoa(cfg.ListenPort)), d.id.TLSConfig(nil))
	if err != nil {
		return fmt.Errorf("listen :%d: %w", cfg.ListenPort, err)
	}
	d.log.Info("listening", "port", cfg.ListenPort, "web", cfg.WebPort)
	go d.mgr.ServeListener(ln)

	// Optional self-hosted hub (signaling + encrypted relay for WAN).
	d.applyHub(ctx, cfg.HubAddr, cfg.HubToken)

	// LAN discovery.
	mdns, err := discover.Start(d.log, d.id.ID, cfg.Name, cfg.ListenPort, func(e discover.Entry) {
		d.mgr.AddCandidate(e.ID, e.Addr)
	})
	if err != nil {
		d.log.Warn("mdns unavailable", "err", err)
	} else {
		d.mdns = mdns
	}
	defer func() {
		if d.mdns != nil {
			d.mdns.Close()
		}
	}()

	// Web UI.
	api := d.webAPI()
	ws := web.NewServer(d.log, cfg.WebToken, api, d.events)
	webErr := make(chan error, 1)
	go func() {
		webErr <- ws.Run(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.WebPort)))
	}()

	d.log.Info("web ui", "url", fmt.Sprintf("http://127.0.0.1:%d/?t=%s", cfg.WebPort, cfg.WebToken))
	select {
	case <-ctx.Done():
		d.log.Info("shutting down")
		_ = ln.Close()
		// Order matters: kill PTYs first so no child shell outlives the
		// daemon, then abort in-flight transfers, then close local forward
		// listeners. The web server stops via its own ctx (3s grace).
		d.term.Shutdown()
		d.filex.CancelAll()
		d.fwd.StopAll()
		return nil
	case err := <-webErr:
		return err
	}
}

// applyHub (re)connects the hub client after a config change.
func (d *Daemon) applyHub(ctx context.Context, addr, token string) {
	d.hubMu.Lock()
	old := d.hubClient
	d.hubClient = nil
	d.hubMu.Unlock()
	if old != nil {
		old.Close()
	}
	if addr == "" {
		d.mgr.SetHub(nil)
		return
	}
	hc := session.NewHubClient(d.id, d.mgr, addr, token, d.store.Get().HubPubkey, d.log)
	d.mgr.SetHub(hc)
	d.hubMu.Lock()
	d.hubClient = hc
	d.hubMu.Unlock()
	go func() {
		if err := hc.Ensure(ctx); err != nil {
			d.log.Warn("hub connect failed", "addr", addr, "err", err)
		}
	}()
}

// applyRules starts all persisted fwd rules belonging to a connected peer.
func (d *Daemon) applyRules(peerID string) {
	peer, ok := d.mgr.Get(peerID)
	if !ok {
		return
	}
	for _, r := range d.store.Get().FwdRules {
		if r.PeerID != peerID {
			continue
		}
		if err := d.fwd.ApplyRule(r, peer); err != nil {
			d.log.Warn("apply fwd rule failed", "rule", r.ID, "err", err)
		}
	}
}

// Connect dials a paired peer (used by web API).
func (d *Daemon) Connect(ctx context.Context, peerID string) (*session.Peer, error) {
	return d.mgr.Connect(ctx, peerID)
}

func (d *Daemon) resolvePeerArg(arg string) (*session.Peer, error) {
	// Accept id, name prefix or exact name.
	peers := d.store.Peers()
	var byName *config.Peer
	for i := range peers {
		if peers[i].ID == arg {
			return d.mgr.Connect(context.Background(), peers[i].ID)
		}
		if peers[i].Name == arg {
			byName = &peers[i]
		}
	}
	if byName != nil {
		return d.mgr.Connect(context.Background(), byName.ID)
	}
	for i := range peers {
		if len(peers[i].ID) >= len(arg) && peers[i].ID[:len(arg)] == arg {
			return d.mgr.Connect(context.Background(), peers[i].ID)
		}
	}
	return nil, fmt.Errorf("no paired device matches %q", arg)
}

// ConnectedView is the web's view of a live connection.
type ConnectedView struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Addr string   `json:"addr"`
	Caps []string `json:"caps"`
}

func (d *Daemon) connectedViews() []ConnectedView {
	out := []ConnectedView{}
	for _, p := range d.mgr.Connected() {
		out = append(out, ConnectedView{ID: p.ID, Name: p.Name, Addr: p.Addr, Caps: p.Caps})
	}
	return out
}

func (d *Daemon) discovered() []discover.Entry {
	out := []discover.Entry{}
	if d.mdns == nil {
		return out
	}
	for _, e := range d.mdns.Known() {
		if _, paired := d.store.Peer(e.ID); !paired {
			out = append(out, e)
		}
	}
	return out
}

// maxFwdRulesPerPeer caps port-forwarding rules per peer device.
const maxFwdRulesPerPeer = 32

// webAPI builds the function-table the HTTP layer calls into.
func (d *Daemon) webAPI() *web.API {
	return &web.API{
		Status: func() any {
			cfg := d.store.Get()
			code, expires, _ := d.pair.CurrentInvite()
			return map[string]any{
				"id":         d.id.ID,
				"name":       cfg.Name,
				"port":       cfg.ListenPort,
				"web_port":   cfg.WebPort,
				"connected":  d.connectedViews(),
				"peers":      d.store.Peers(),
				"discovered": d.discovered(),
				"invite":     inviteView(code, expires),
				"hub_addr":   cfg.HubAddr,
			}
		},
		SetName: func(name string) error {
			return d.store.Update(func(c *config.Config) { c.Name = name })
		},
		SetHub: func(addr, token string) error {
			err := d.store.Update(func(c *config.Config) {
				c.HubAddr = addr
				c.HubToken = token
			})
			if err != nil {
				return err
			}
			d.applyHub(context.Background(), addr, token)
			return nil
		},
		Peers: func() any { return d.store.Peers() },
		RemovePeer: func(id string) error {
			d.mgr.Disconnect(id)
			return d.store.RemovePeer(id)
		},
		ConnectPeer: func(ctx context.Context, id string) error {
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			_, err := d.mgr.Connect(cctx, id)
			return err
		},
		DisconnectPeer: d.mgr.Disconnect,
		CreateInvite:   d.pair.CreateInvite,
		PairConnect: func(ctx context.Context, addr, code string) (any, error) {
			// Fast path: already paired and reachable — just connect.
			if p, err := d.mgr.ConnectAddr(ctx, addr); err == nil {
				peer, _ := d.store.Peer(p.ID)
				return peer, nil
			}
			return d.pair.PairWith(ctx, addr, code)
		},
		ListDir: func(ctx context.Context, peerArg, path string) (any, error) {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return nil, err
			}
			return d.filex.ListDir(ctx, peer, path)
		},
		Mkdir: func(ctx context.Context, peerArg, path string) error {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return err
			}
			return d.filex.Mkdir(ctx, peer, path)
		},
		Rename: func(ctx context.Context, peerArg, from, to string) error {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return err
			}
			return d.filex.Rename(ctx, peer, from, to)
		},
		Remove: func(ctx context.Context, peerArg, path string, recursive bool) error {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return err
			}
			return d.filex.Remove(ctx, peer, path, recursive)
		},
		Push: func(ctx context.Context, peerArg, local, remote, conflict string) (string, error) {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return "", err
			}
			fi, statErr := os.Stat(local)
			if statErr == nil && fi.IsDir() {
				// Directory push fans out to one transfer per file; there is
				// no single id, so it cannot be cancelled by id (the empty id
				// is not registered by the web layer).
				go func() {
					if err := d.filex.PushDir(ctx, peer, local, remote, conflict, nil); err != nil {
						d.log.Warn("push failed", "err", err)
					}
				}()
				return "", nil
			}
			// Pre-generate the id so the HTTP response can carry it at once
			// and /api/xfer/cancel can cancel via the handler ctx.
			id := filex.NewXferID()
			go func() {
				if _, err := d.filex.PushFile(ctx, peer, local, remote, conflict, id, nil); err != nil {
					d.log.Warn("push failed", "id", id, "err", err)
				}
			}()
			return id, nil
		},
		Pull: func(ctx context.Context, peerArg, remote, local, conflict string) (string, error) {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return "", err
			}
			id := filex.NewXferID()
			go func() {
				if _, err := d.filex.PullFile(ctx, peer, remote, local, conflict, id, nil); err != nil {
					d.log.Warn("pull failed", "id", id, "err", err)
				}
			}()
			return id, nil
		},
		FwdRules: func() any { return d.store.Get().FwdRules },
		FwdAdd: func(rule config.FwdRule) error {
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("f%d", time.Now().UnixNano())
			}
			// Per-device cap: one peer cannot fill the config with rules.
			n := 0
			for _, r := range d.store.Get().FwdRules {
				if r.PeerID == rule.PeerID {
					n++
				}
			}
			if n >= maxFwdRulesPerPeer {
				return fmt.Errorf("too many fwd rules for this device (max %d)", maxFwdRulesPerPeer)
			}
			if err := d.store.AddFwdRule(rule); err != nil {
				return err
			}
			if peer, ok := d.mgr.Get(rule.PeerID); ok {
				if err := d.fwd.ApplyRule(rule, peer); err != nil {
					return err
				}
			}
			return nil
		},
		FwdRemove: func(id string) error {
			var rule config.FwdRule
			found := false
			for _, r := range d.store.Get().FwdRules {
				if r.ID == id {
					rule, found = r, true
					break
				}
			}
			if !found {
				return nil
			}
			// Mutate the store only through its API: Get() returns a copy, so
			// the old in-place filter-rewrite here corrupted s.cfg.
			if err := d.store.RemoveFwdRule(id); err != nil {
				return err
			}
			d.fwd.StopRule(rule)
			return nil
		},
		FwdActive: d.fwd.ActiveRules,
		TermDial: func(peerArg string, cols, rows uint16, sessionID uint64) (io.ReadWriteCloser, uint64, func(uint16, uint16) error, error) {
			peer, err := d.resolvePeerArg(peerArg)
			if err != nil {
				return nil, 0, nil, err
			}
			var cs *term.ClientSession
			if sessionID != 0 {
				cs, err = term.ClientAttach(peer, sessionID)
			} else {
				cs, err = term.ClientStart(context.Background(), peer, cols, rows, "", "")
			}
			if err != nil {
				return nil, 0, nil, err
			}
			return cs, cs.ID, cs.Resize, nil
		},
	}
}

func inviteView(code string, expires time.Time) any {
	if code == "" {
		return nil
	}
	return map[string]any{"code": code, "expires": expires.UnixMilli()}
}
