package web

import "net/http"

// termAPI serves terminal-related REST routes. There are none: the terminal
// is WebSocket-only and /api/term/ws is routed by the mux straight to
// termWS, so every request that reaches this dispatcher is answered with
// http.NotFound — exactly what the original single switch's default branch
// did for these paths.
func (s *Server) termAPI(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
