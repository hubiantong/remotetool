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
	"net/http"
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

// EventHub broadcasts daemon events to SSE subscribers.
type EventHub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

// NewEventHub builds an empty hub.
func NewEventHub() *EventHub { return &EventHub{subs: map[chan []byte]struct{}{}} }

// MarshalEvent encodes one event for the stream.
func MarshalEvent(eventType, peerID string, data any) []byte {
	b, _ := json.Marshal(map[string]any{"type": eventType, "peer_id": peerID, "data": data})
	return b
}

// Publish drops the event into every subscriber (non-blocking).
func (h *EventHub) Publish(eventType, peerID string, data any) {
	b := MarshalEvent(eventType, peerID, data)
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
		}
	}
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
	Push    func(ctx context.Context, peerArg, local, remote, conflict string) error
	Pull    func(ctx context.Context, peerArg, remote, local, conflict string) error

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
	log   *slog.Logger
	token string
	api   *API
	hub   *EventHub
}

// NewServer builds the web server.
func NewServer(log *slog.Logger, token string, api *API, hub *EventHub) *Server {
	return &Server{log: log, token: token, api: api, hub: hub}
}

// Run blocks serving until ctx is done.
func (s *Server) Run(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", s.auth(s.apiHandler))
	mux.Handle("/api/term/ws", s.authHandler(websocket.Handler(s.termWS)))
	mux.HandleFunc("/api/events", s.auth(s.events))
	mux.HandleFunc("/", s.static)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	b, err := fs.ReadFile(webdist, path)
	if err != nil {
		// SPA fallback.
		b, err = fs.ReadFile(webdist, "index.html")
		if err != nil {
			http.Error(w, "ui missing", http.StatusInternalServerError)
			return
		}
		path = "index.html"
	}
	switch {
	case strings.HasSuffix(path, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(path, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(path, ".woff2"):
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

func readBody[T any](r *http.Request) (*T, error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

func errJSON(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) apiHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch {
	case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
		writeJSON(w, s.api.Status())

	case r.URL.Path == "/api/name" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Name string `json:"name"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if err := s.api.SetName(body.Name); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/hub" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Addr  string `json:"addr"`
			Token string `json:"token"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if err := s.api.SetHub(strings.TrimSpace(body.Addr), strings.TrimSpace(body.Token)); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/pair/invite" && r.Method == http.MethodPost:
		code, expires, err := s.api.CreateInvite()
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]any{"code": code, "expires": expires.UnixMilli()})

	case r.URL.Path == "/api/pair/connect" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Addr string `json:"addr"`
			Code string `json:"code"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		peer, err := s.api.PairConnect(cctx, body.Addr, body.Code)
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "peer": peer})

	case r.URL.Path == "/api/peers/connect" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			ID string `json:"id"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := s.api.ConnectPeer(cctx, body.ID); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/peers/disconnect" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			ID string `json:"id"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		s.api.DisconnectPeer(body.ID)
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/peers/remove" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			ID string `json:"id"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if err := s.api.RemovePeer(body.ID); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/fs/list" && r.Method == http.MethodGet:
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		res, err := s.api.ListDir(cctx, r.URL.Query().Get("peer"), r.URL.Query().Get("path"))
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, res)

	case r.URL.Path == "/api/fs/mkdir" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Peer string `json:"peer"`
			Path string `json:"path"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := s.api.Mkdir(cctx, body.Peer, body.Path); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/fs/rename" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Peer string `json:"peer"`
			From string `json:"from"`
			To   string `json:"to"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := s.api.Rename(cctx, body.Peer, body.From, body.To); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/fs/remove" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Peer      string `json:"peer"`
			Path      string `json:"path"`
			Recursive bool   `json:"recursive"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := s.api.Remove(cctx, body.Peer, body.Path, body.Recursive); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/xfer/push" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Peer     string `json:"peer"`
			Local    string `json:"local"`
			Remote   string `json:"remote"`
			Conflict string `json:"conflict"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		// Validate connectivity synchronously, then transfer in background.
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if _, err := s.api.ListDir(cctx, body.Peer, "."); err != nil {
			cancel()
			errJSON(w, err)
			return
		}
		cancel()
		go func() {
			bg, bgCancel := context.WithTimeout(context.Background(), 24*time.Hour)
			defer bgCancel()
			if err := s.api.Push(bg, body.Peer, body.Local, body.Remote, body.Conflict); err != nil {
				s.log.Warn("push failed", "err", err)
			}
		}()
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/xfer/pull" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Peer     string `json:"peer"`
			Remote   string `json:"remote"`
			Local    string `json:"local"`
			Conflict string `json:"conflict"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if _, err := s.api.ListDir(cctx, body.Peer, "."); err != nil {
			cancel()
			errJSON(w, err)
			return
		}
		cancel()
		go func() {
			bg, bgCancel := context.WithTimeout(context.Background(), 24*time.Hour)
			defer bgCancel()
			if err := s.api.Pull(bg, body.Peer, body.Remote, body.Local, body.Conflict); err != nil {
				s.log.Warn("pull failed", "err", err)
			}
		}()
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/fwd" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{"rules": s.api.FwdRules(), "active": s.api.FwdActive()})

	case r.URL.Path == "/api/fwd/add" && r.Method == http.MethodPost:
		body, err := readBody[config.FwdRule](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if err := s.api.FwdAdd(*body); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/fwd/remove" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			ID string `json:"id"`
		}](r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if err := s.api.FwdRemove(body.ID); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.NotFound(w, r)
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
