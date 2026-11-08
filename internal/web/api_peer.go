package web

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// peerAPI serves the device and peer resources: status, name, hub, pairing
// and peer connect/disconnect/remove. Unmatched paths or methods fall
// through to http.NotFound, as they did in the original single switch.
func (s *Server) peerAPI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch {
	case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
		writeJSON(w, s.api.Status())

	case r.URL.Path == "/api/name" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			Name string `json:"name"`
		}](w, r)
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
		}](w, r)
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
		}](w, r)
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
		}](w, r)
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
		}](w, r)
		if err != nil {
			errJSON(w, err)
			return
		}
		s.api.DisconnectPeer(body.ID)
		writeJSON(w, map[string]bool{"ok": true})

	case r.URL.Path == "/api/peers/remove" && r.Method == http.MethodPost:
		body, err := readBody[struct {
			ID string `json:"id"`
		}](w, r)
		if err != nil {
			errJSON(w, err)
			return
		}
		if err := s.api.RemovePeer(body.ID); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.NotFound(w, r)
	}
}
