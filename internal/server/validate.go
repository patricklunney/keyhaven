package server

import (
	"fmt"
	"net/url"
	"strings"
)

const maxRedirectURIs = 20

// ValidateRedirectURI enforces OAuth 2.1 / RFC 8252 rules for registered
// redirect URIs: https with a host; http only on loopback; or a reverse-domain
// private-use scheme for native apps (e.g. com.example.app:/callback).
func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("%q is not an absolute URI", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%q must not contain a fragment (#)", raw)
	}
	if u.User != nil {
		return fmt.Errorf("%q must not contain credentials", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("%q has no host", raw)
		}
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("%q must use https (http is allowed only for localhost)", raw)
	case "javascript", "data", "file", "vbscript", "blob", "about":
		return fmt.Errorf("%q uses a forbidden scheme", raw)
	}
	if !strings.Contains(u.Scheme, ".") {
		return fmt.Errorf("%q: custom schemes must be reverse-domain style, e.g. com.example.app:/callback", raw)
	}
	return nil
}

// ParseRedirectURIs splits a newline/space separated list, removes duplicates
// and validates every entry.
func ParseRedirectURIs(text string, required bool) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Fields(text) {
		if seen[f] {
			continue
		}
		seen[f] = true
		if err := ValidateRedirectURI(f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if required && len(out) == 0 {
		return nil, fmt.Errorf("at least one redirect URI is required")
	}
	if len(out) > maxRedirectURIs {
		return nil, fmt.Errorf("at most %d URIs are allowed", maxRedirectURIs)
	}
	return out, nil
}
