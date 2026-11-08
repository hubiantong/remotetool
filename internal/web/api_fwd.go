package web

import (
	"net/http"

	"remotetool/internal/config"
)

// fwdAPI serves the port-forwarding rules (/api/fwd*). Unmatched paths or
// methods fall through to http.NotFound, as they did in the original single
// switch.
func (s *Server) fwdAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/fwd" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{"rules": s.api.FwdRules(), "active": s.api.FwdActive()})

	case r.URL.Path == "/api/fwd/add" && r.Method == http.MethodPost:
		body, err := readBody[config.FwdRule](w, r)
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
		}](w, r)
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
