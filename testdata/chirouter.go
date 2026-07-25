package routes

// A chi router. `r.Get("/api/things")` is a route registration; the
// `.Header.Get(...)` calls in the same file use the same call shape but are
// header reads, and must not become endpoints.

import (
	"net/http"
	"net/mail"

	"github.com/go-chi/chi/v5"
)

func Mount(r chi.Router) {
	r.Get("/api/things", listThings)
	r.Post("/api/things", createThings)
	r.Route("/api/admin", func(sub chi.Router) {
		sub.Get("/audit", auditThings)
	})
}

func listThings(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Accept")
	w.WriteHeader(http.StatusOK)
}

func createThings(w http.ResponseWriter, r *http.Request) {
	msg, err := mail.ReadMessage(r.Body)
	if err == nil {
		_ = msg.Header.Get("Subject")
		_ = msg.Header.Get("Content-Type")
	}
	w.WriteHeader(http.StatusCreated)
}

func auditThings(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
