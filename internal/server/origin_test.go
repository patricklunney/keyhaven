package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyhaven/keyhaven/internal/config"
)

func TestIsSameOrigin(t *testing.T) {
	s := &Server{cfg: &config.Config{Issuer: "https://id.example.com"}}
	cases := []struct {
		name, origin, fetchSite string
		want                    bool
	}{
		{"matching origin", "https://id.example.com", "", true},
		{"form POST under strict referrer policy", "null", "same-origin", true},
		{"null origin from another site", "null", "cross-site", false},
		{"null origin, no fetch metadata", "null", "", false},
		{"null origin, same-site sibling", "null", "same-site", false},
		{"other origin", "https://evil.example", "same-origin", false},
		{"missing origin", "", "same-origin", false},
		{"http downgrade", "http://id.example.com", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/logout", nil)
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", c.fetchSite)
		}
		if got := s.isSameOrigin(r); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReferrerPolicyKeepsFormOrigins(t *testing.T) {
	s := &Server{cfg: &config.Config{Issuer: "https://id.example.com"}}
	rec := httptest.NewRecorder()
	s.securityHeaders(nopHandler{}).ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	// "no-referrer" makes browsers send Origin: null on form POSTs (logout, admin forms).
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin", got)
	}
}

type nopHandler struct{}

func (nopHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
