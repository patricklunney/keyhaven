package server

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	ok := []string{
		"https://app.example.com/cb", "https://app.example.com:8443/cb?x=1",
		"http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb",
		"com.example.app:/callback",
	}
	bad := []string{
		"", "/relative", "http://app.example.com/cb", "https://app.example.com/cb#frag",
		"javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "myapp:/cb",
		"https://user:pass@app.example.com/cb", "https:///nohost", "http://localhost.evil.com/cb",
	}
	for _, u := range ok {
		if err := ValidateRedirectURI(u); err != nil {
			t.Errorf("%q should be valid: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := ValidateRedirectURI(u); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
	if _, err := ParseRedirectURIs("  \n ", true); err == nil {
		t.Error("empty required list should fail")
	}
	got, err := ParseRedirectURIs("https://a.example/cb\nhttps://a.example/cb  https://b.example/cb", true)
	if err != nil || len(got) != 2 {
		t.Errorf("dedupe failed: %v %v", got, err)
	}
}

func TestSafeAdminPath(t *testing.T) {
	for _, p := range []string{"/admin", "/admin/users", "/admin/users?q=a"} {
		if !safeAdminPath(p) {
			t.Errorf("%q should be allowed", p)
		}
	}
	for _, p := range []string{"", "/", "/account", "//evil.example", "/admin//evil", "/administrator", "/admin\\evil", "https://evil/admin"} {
		if safeAdminPath(p) {
			t.Errorf("%q should be refused", p)
		}
	}
}
