package testonly

// A test fixture that spins up a real route. It is not deployed attack surface,
// so it is silent by default and only reported when the caller opts in with
// include_tests.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFixtureServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/fixture/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fixture/token") //nolint:noctx // fixture
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}
