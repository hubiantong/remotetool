// Package web serves the local admin UI and REST/WebSocket/SSE APIs.
// It listens on 127.0.0.1 only and requires the per-device web token.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"remotetool/internal/config"
)

//go:embed all:webdist
var webdistFS embed.FS

// webdist is the embedded UI file tree.
var webdist, _ = fs.Sub(webdistFS, "webdist")

// EventHub broadcasts daemon events to SSE subscribers. For xfer events it
// also remembers the latest event per transfer id (bounded), so a subscriber
// that attaches after a short transfer finished still sees its terminal
// state — the CLI's watchProgress would otherwise wait forever for a "done"
// event that was published before it connected.
type EventHub struct {
	mu        sync.Mutex
	subs      map[chan []byte]struct{}
	last      map[string][]byte // xfer id -> latest marshaled event
	lastOrder []string          // insertion order for bounded eviction
}

// maxTrackedXfers bounds the last-event cache.
const maxTrackedXfers = 512

// NewEventHub builds an empty hub.
func NewEventHub() *EventHub { return &EventHub{subs: map[chan []byte]struct{}{}} }

// MarshalEvent encodes one event for the stream.
func MarshalEvent(eventType, peerID string, data any) []byte {
	b, _ := json.Marshal(map[string]any{"type": eventType, "peer_id": peerID, "data": data})
	return b
}

// Publish drops the event into every subscriber (non-blocking) and, for xfer
// events, records the latest event per transfer id.
func (h *EventHub) Publish(eventType, peerID string, data any) {
	b := MarshalEvent(eventType, peerID, data)
	h.mu.Lock()
	defer h.mu.Unlock()
	if eventType == "xfer" {
		var probe struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &probe) == nil && probe.Data.ID != "" {
			h.rememberLocked(probe.Data.ID, b)
		}
	}
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
		}
	}
}

// rememberLocked stores the latest event for one xfer id (h.mu held).
func (h *EventHub) rememberLocked(id string, b []byte) {
	if h.last == nil {
		h.last = map[string][]byte{}
	}
	if _, exists := h.last[id]; !exists {
		if len(h.last) >= maxTrackedXfers {
			// Evict the oldest tracked transfer.
			if len(h.lastOrder) > 0 {
				old := h.lastOrder[0]
				h.lastOrder = h.lastOrder[1:]
				delete(h.last, old)
			}
		}
		h.lastOrder = append(h.lastOrder, id)
	}
	h.last[id] = b
}

// lastXfer returns the latest event recorded for a transfer id.
func (h *EventHub) lastXfer(id string) ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.last[id]
	return b, ok
}

// Subscribe registers a subscriber; the returned func unsubscribes.
func (h *EventHub) Subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// API is the function-table implemented by the daemon.
type API struct {
	Status         func() any
	SetName        func(name string) error
	SetHub         func(addr, token string) error
	Peers          func() any
	RemovePeer     func(id string) error
	ConnectPeer    func(ctx context.Context, id string) error
	DisconnectPeer func(id string)
	CreateInvite   func() (string, time.Time, error)
	PairConnect    func(ctx context.Context, addr, code string) (any, error)

	ListDir func(ctx context.Context, peerArg, path string) (any, error)
	Mkdir   func(ctx context.Context, peerArg, path string) error
	Rename  func(ctx context.Context, peerArg, from, to string) error
	Remove  func(ctx context.Context, peerArg, path string, recursive bool) error
	// Push/Pull start a transfer and return its id promptly so the handler can
	// answer before the transfer finishes; the transfer itself runs under the
	// given ctx and must stop when it is cancelled (see /api/xfer/cancel).
	// For Push, src is the local path and dst the remote path; for Pull the
	// order is reversed.
	Push func(ctx context.Context, peerArg, src, dst, conflict string) (string, error)
	Pull func(ctx context.Context, peerArg, src, dst, conflict string) (string, error)

	FwdRules  func() any
	FwdAdd    func(rule config.FwdRule) error
	FwdRemove func(id string) error
	FwdActive func() map[string]bool

	// TermDial opens (or attaches to) a remote terminal session and returns
	// the byte pipe, the session id and a resize callback.
	TermDial func(peerArg string, cols, rows uint16, sessionID uint64) (io.ReadWriteCloser, uint64, func(uint16, uint16) error, error)
}

// Server is the HTTP layer.
type Server struct {
	log     *slog.Logger
	token   string
	api     *API
	hub     *EventHub
	webPort string // actual listen port, set by Run

	xferMu      sync.Mutex
	xferCancels map[string]context.CancelFunc // lazily initialized in trackXfer
}

// NewServer builds the web server.
func NewServer(log *slog.Logger, token string, api *API, hub *EventHub) *Server {
	return &Server{log: log, token: token, api: api, hub: hub}
}

// Run blocks serving until ctx is done.
func (s *Server) Run(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", s.auth(s.apiHandler))
	mux.Handle("/api/term/ws", s.authHandler(s.wsOrigin(websocket.Handler(s.termWS))))
	mux.HandleFunc("/api/events", s.auth(s.events))
	mux.HandleFunc("/", s.static)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// Remember the port actually bound: addr may use :0, and the WS Origin
	// check must match what the browser really talks to.
	if _, port, perr := net.SplitHostPort(ln.Addr().String()); perr == nil {
		s.webPort = port
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shctx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-RT-Token")
		if tok == "" {
			tok = r.URL.Query().Get("t")
		}
		if tok == "" {
			if c, err := r.Cookie("rt_token"); err == nil {
				tok = c.Value
			}
		}
		if tok != s.token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) authHandler(next http.Handler) http.Handler {
	return s.auth(next.ServeHTTP)
}

// wsOrigin guards the terminal WebSocket against cross-site WebSocket
// hijacking: any web page the operator visits could otherwise open a terminal
// on the local daemon, because browsers attach loopback credentials
// automatically and the same-origin policy does not govern WebSocket
// upgrades. Browsers always send Origin on the handshake; an empty Origin
// means a non-browser client (CLI, termprobe) and is allowed.
func (s *Server) wsOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && !s.sameOrigin(origin) {
			http.Error(w, "cross-origin websocket refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether origin points at this server's own loopback
// address and port (http or https).
func (s *Server) sameOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	if host != "127.0.0.1" && !strings.EqualFold(host, "localhost") {
		return false
	}
	port := u.Port()
	if port == "" {
		// A portless loopback origin cannot come from a browser (browsers
		// always send the port unless it is the scheme default, and this
		// server never listens on 80/443). It is the signature of the
		// repo's own x/net/websocket CLI clients (e.g. termprobe), which
		// dial with "http://127.0.0.1" — accept it like an empty Origin.
		return true
	}
	return port == s.webPort
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	// Token handoff for the SPA: /?t=<token> seeds the rt_token cookie (which
	// the auth middleware reads back) and 302s to the clean URL so the token
	// does not linger in the address bar or browser history. A wrong token
	// must not serve the UI.
	if t := r.URL.Query().Get("t"); t != "" {
		if t != s.token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "rt_token",
			Value:    s.token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		// path.Clean keeps the redirect target local: a path like //host
		// would otherwise be treated as protocol-relative by browsers.
		http.Redirect(w, r, path.Clean("/"+r.URL.Path), http.StatusFound)
		return
	}
	file := strings.TrimPrefix(r.URL.Path, "/")
	if file == "" {
		file = "index.html"
	}
	b, err := fs.ReadFile(webdist, file)
	if err != nil {
		// SPA fallback.
		b, err = fs.ReadFile(webdist, "index.html")
		if err != nil {
			http.Error(w, "ui missing", http.StatusInternalServerError)
			return
		}
		file = "index.html"
	}
	switch {
	case strings.HasSuffix(file, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(file, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(file, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(file, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(file, ".woff2"):
		w.Header().Set("Content-Type", "font/woff2")
	}
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

// ------------------------------------------------------------- handlers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readBody[T any](w http.ResponseWriter, r *http.Request) (*T, error) {
	var v T
	// Cap decoded bodies so a stray client cannot make the daemon buffer
	// unbounded JSON.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

func errJSON(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// apiHandler is the top-level /api/ router: it delegates by resource prefix
// to the per-resource dispatchers (api_peer.go, api_file.go, api_fwd.go,
// api_term.go). Every dispatcher ends in http.NotFound for unmatched paths
// or methods, so behavior is identical to the previous single switch; the
// dispatchers are mutually exclusive by prefix and peerAPI also covers the
// default case for unknown /api/ paths.
func (s *Server) apiHandler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/api/fs/") || strings.HasPrefix(p, "/api/xfer/"):
		s.fileAPI(w, r)
	case p == "/api/fwd" || strings.HasPrefix(p, "/api/fwd/"):
		s.fwdAPI(w, r)
	case strings.HasPrefix(p, "/api/term/"):
		// /api/term/ws never reaches here (the mux routes it to termWS);
		// termAPI 404s the rest, as the old switch's default did.
		s.termAPI(w, r)
	default:
		s.peerAPI(w, r)
	}
}

// events streams daemon events as SSE.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no streaming", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, unsub := s.hub.Subscribe()
	defer unsub()
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")
	fl.Flush()
	// A client may attach after its transfer already finished (the CLI
	// subscribes only once the push/pull call returned): replay the latest
	// recorded event for the requested transfer so it sees the terminal
	// state instead of waiting forever.
	if id := r.URL.Query().Get("xfer"); id != "" {
		if b, ok := s.hub.lastXfer(id); ok {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case b := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

// termWS bridges a browser xterm.js WebSocket to a remote PTY.
func (s *Server) termWS(wsconn *websocket.Conn) {
	q := wsconn.Request().URL.Query()
	peerArg := q.Get("peer")
	sessionID := uint64(0)
	_, _ = fmt.Sscanf(q.Get("session"), "%d", &sessionID)
	var cols, rows uint16
	_, _ = fmt.Sscanf(q.Get("cols"), "%d", &cols)
	_, _ = fmt.Sscanf(q.Get("rows"), "%d", &rows)

	stream, _, resize, err := s.api.TermDial(peerArg, cols, rows, sessionID)
	if err != nil {
		_, _ = wsconn.Write([]byte("terminal error: " + err.Error()))
		_ = wsconn.Close()
		return
	}
	defer stream.Close()

	done := make(chan struct{}, 2)
	// remote -> browser (binary frames)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 16<<10)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				wsconn.PayloadType = websocket.BinaryFrame
				if _, werr := wsconn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// browser -> remote; text frames are JSON resize commands
	go func() {
		defer func() { done <- struct{}{} }()
		var msg []byte
		for {
			if err := websocket.Message.Receive(wsconn, &msg); err != nil {
				return
			}
			if len(msg) > 0 && msg[0] == '{' {
				var cmd struct {
					Cols uint16 `json:"cols"`
					Rows uint16 `json:"rows"`
				}
				if json.Unmarshal(msg, &cmd) == nil && cmd.Cols > 0 && cmd.Rows > 0 {
					_ = resize(cmd.Cols, cmd.Rows)
					continue
				}
			}
			if _, err := stream.Write(msg); err != nil {
				return
			}
		}
	}()
	<-done
	_ = wsconn.Close()
}
