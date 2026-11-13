package server

import (
	"net/http/httptest"
	"testing"

	"github.com/keyhaven/keyhaven/internal/store"
)

func TestAllowClientOrigin(t *testing.T) {
	public := &store.Client{RedirectURIs: []string{"https://pics.example.com/", "http://localhost:8090/cb"}}
	confidential := &store.Client{SecretHash: []byte("x"), RedirectURIs: []string{"https://app.example.com/cb"}}
	cases := []struct {
		name   string
		client *store.Client
		origin string
		want   string
	}{
		{"public client, registered origin", public, "https://pics.example.com", "https://pics.example.com"},
		{"public client, registered localhost origin with port", public, "http://localhost:8090", "http://localhost:8090"},
		{"public client, foreign origin", public, "https://evil.example", ""},
		{"public client, scheme mismatch", public, "http://pics.example.com", ""},
		{"public client, no origin (server-to-server)", public, "", ""},
		{"confidential client never gets CORS", confidential, "https://app.example.com", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/token", nil)
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		w := httptest.NewRecorder()
		allowClientOrigin(w, r, c.client)
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != c.want {
			t.Errorf("%s: ACAO = %q, want %q", c.name, got, c.want)
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("%s: credentials must never be allowed", c.name)
		}
		if w.Header().Get("Vary") != "Origin" {
			t.Errorf("%s: missing Vary: Origin", c.name)
		}
	}
}
