package routes

import (
	"net/http"
)

// HTTP endpoints — triggers ATTACK-001 and ATTACK-002.
func SetupRoutes() {
	http.HandleFunc("/api/users", handleUsers)
	http.HandleFunc("/api/orders", handleOrders)

	// Admin endpoint — triggers ATTACK-003.
	http.HandleFunc("/admin/dashboard", handleAdmin)
	http.HandleFunc("/debug/pprof", handleDebug)
	http.HandleFunc("/internal/metrics", handleMetrics)
}

// File upload — triggers ATTACK-004.
func handleUpload(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("document")
	_ = file
}

func handleUsers(w http.ResponseWriter, r *http.Request) {}
func handleOrders(w http.ResponseWriter, r *http.Request) {}
func handleAdmin(w http.ResponseWriter, r *http.Request)  {}
func handleDebug(w http.ResponseWriter, r *http.Request)  {}
func handleMetrics(w http.ResponseWriter, r *http.Request) {}
