package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// fileAPI serves the remote filesystem browser (/api/fs/*) and the file
// transfers (/api/xfer/*), including the transfer-cancel registry. Unmatched
// paths or methods fall through to http.NotFound, as they did in the
// original single switch.
func (s *Server) fileAPI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch {
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
		}](w, r)
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
		}](w, r)
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
		}](w, r)
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
		}](w, r)
		if err != nil {
			errJSON(w, err)
			return
		}
		// Fail fast on a bad local source instead of surfacing the error much
		// later through the daemon log.
		fi, statErr := os.Stat(body.Local)
		if statErr != nil {
			errJSON(w, fmt.Errorf("local source %q: %w", body.Local, statErr))
			return
		}
		if !fi.Mode().IsRegular() {
			errJSON(w, fmt.Errorf("local source %q is not a regular file", body.Local))
			return
		}
		// Validate connectivity synchronously, then start the transfer.
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err = s.api.ListDir(cctx, body.Peer, ".")
		cancel()
		if err != nil {
			errJSON(w, err)
			return
		}
		// The transfer runs under a cancellable context so /api/xfer/cancel
		// can stop it; the API implementation starts the transfer, returns its
		// id promptly and honours ctx cancellation.
		bg, bgCancel := context.WithTimeout(context.Background(), 24*time.Hour)
		id, err := s.api.Push(bg, body.Peer, body.Local, body.Remote, body.Conflict)
		if err != nil {
			bgCancel()
			errJSON(w, err)
			return
		}
		s.trackXfer(bg, id, bgCancel)
		writeJSON(w, map[string]any{"ok": true, "id": id})

	case r.URL.Path == "/api/xfer/pull" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Peer     string `json:"peer"`
			Remote   string `json:"remote"`
			Local    string `json:"local"`
			Conflict string `json:"conflict"`
		}](w, r)
		if err != nil {
			errJSON(w, err)
			return
		}
		// Fail fast when the local destination directory is missing.
		dir := filepath.Dir(body.Local)
		if fi, statErr := os.Stat(dir); statErr != nil || !fi.IsDir() {
			errJSON(w, fmt.Errorf("local destination directory %q does not exist", dir))
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err = s.api.ListDir(cctx, body.Peer, ".")
		cancel()
		if err != nil {
			errJSON(w, err)
			return
		}
		bg, bgCancel := context.WithTimeout(context.Background(), 24*time.Hour)
		id, err := s.api.Pull(bg, body.Peer, body.Remote, body.Local, body.Conflict)
		if err != nil {
			bgCancel()
			errJSON(w, err)
			return
		}
		s.trackXfer(bg, id, bgCancel)
		writeJSON(w, map[string]any{"ok": true, "id": id})

	case r.URL.Path == "/api/xfer/cancel" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			ID string `json:"id"`
		}](w, r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if !s.cancelXfer(body.ID) {
			http.Error(w, `{"error":"unknown transfer id"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.NotFound(w, r)
	}
}

// trackXfer registers a running transfer's cancel func under its id so
// /api/xfer/cancel can stop it. The entry is dropped once the transfer
// context completes (explicit cancel, error path or the 24h timeout), so
// the registry cannot grow without bound.
func (s *Server) trackXfer(ctx context.Context, id string, cancel context.CancelFunc) {
	if id == "" {
		// No id to register (e.g. a directory push fans out without a single
		// id): leave it running uncancellable and let the 24h timeout release
		// the context.
		return
	}
	s.xferMu.Lock()
	if s.xferCancels == nil {
		s.xferCancels = make(map[string]context.CancelFunc)
	}
	s.xferCancels[id] = cancel
	s.xferMu.Unlock()
	context.AfterFunc(ctx, func() { s.untrackXfer(id) })
}

func (s *Server) untrackXfer(id string) {
	s.xferMu.Lock()
	delete(s.xferCancels, id)
	s.xferMu.Unlock()
}

// cancelXfer cancels a registered transfer; ok reports whether the id was known.
func (s *Server) cancelXfer(id string) bool {
	s.xferMu.Lock()
	cancel, ok := s.xferCancels[id]
	delete(s.xferCancels, id)
	s.xferMu.Unlock()
	if ok {
		cancel()
	}
	return ok
}
