package routes

// A genuine net/http file that both registers a route and reads request
// headers. The route must be reported; the header names must not be — a
// `Header.Get("Authorization")` call is a header read, not a registration.

import (
	"net/http"
)

func RegisterSession(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/session", handleSession)
	mux.HandleFunc("GET /api/session/{id}", handleSessionByID)
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Authorization")
	_ = r.Header.Get("Content-Type")
	_ = r.Header.Get("X-Request-Id")
	_ = r.URL.Query().Get("redirect")
	w.WriteHeader(http.StatusNoContent)
}

func handleSessionByID(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("If-None-Match")
	w.WriteHeader(http.StatusOK)
}
