// Package config loads Keyhaven configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Issuer is the public origin of this server, e.g. https://id.example.com.
	// It is used as the OIDC issuer, the WebAuthn origin and to build all URLs.
	Issuer        string
	ListenAddr    string
	DatabaseURL   string
	RPID          string
	RPDisplayName string
	RPOrigins     []string

	// SigningKeyPEM is a PKCS#8 / SEC1 PEM encoded P-256 private key used to sign tokens.
	SigningKeyPEM string

	AllowSignup     bool
	SessionTTL      time.Duration
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration

	// AdminReauth is the maximum session age allowed for the admin console;
	// older sessions must sign in again with a passkey.
	AdminReauth time.Duration

	// Dev relaxes a few production requirements (http issuer, ephemeral signing key).
	Dev bool
}

// SecureCookies reports whether cookies must carry the Secure attribute.
func (c *Config) SecureCookies() bool { return strings.HasPrefix(c.Issuer, "https://") }

func Load() (*Config, error) {
	c := &Config{
		Issuer:          strings.TrimSuffix(os.Getenv("KEYHAVEN_ISSUER"), "/"),
		ListenAddr:      env("KEYHAVEN_LISTEN_ADDR", ":8080"),
		RPDisplayName:   env("KEYHAVEN_RP_DISPLAY_NAME", "Keyhaven"),
		SigningKeyPEM:   os.Getenv("KEYHAVEN_SIGNING_KEY"),
		Dev:             envBool("KEYHAVEN_DEV", false),
		AllowSignup:     envBool("KEYHAVEN_ALLOW_SIGNUP", true),
		SessionTTL:      envDuration("KEYHAVEN_SESSION_TTL", 12*time.Hour),
		AccessTokenTTL:  envDuration("KEYHAVEN_ACCESS_TOKEN_TTL", 15*time.Minute),
		IDTokenTTL:      envDuration("KEYHAVEN_ID_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL: envDuration("KEYHAVEN_REFRESH_TOKEN_TTL", 30*24*time.Hour),
		AdminReauth:     envDuration("KEYHAVEN_ADMIN_REAUTH", time.Hour),
	}

	if c.Issuer == "" {
		return nil, errors.New("KEYHAVEN_ISSUER is required (e.g. https://id.example.com)")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("KEYHAVEN_ISSUER must be a bare origin like https://id.example.com, got %q", c.Issuer)
	}
	if u.Scheme != "https" && !c.Dev {
		return nil, errors.New("KEYHAVEN_ISSUER must use https (set KEYHAVEN_DEV=true for local http)")
	}

	c.RPID = env("KEYHAVEN_RP_ID", u.Hostname())
	c.RPOrigins = []string{c.Issuer}
	if extra := os.Getenv("KEYHAVEN_RP_EXTRA_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				c.RPOrigins = append(c.RPOrigins, o)
			}
		}
	}

	c.DatabaseURL, err = databaseURL()
	if err != nil {
		return nil, err
	}
	if c.SigningKeyPEM == "" && !c.Dev {
		return nil, errors.New("KEYHAVEN_SIGNING_KEY is required (generate one with `keyhaven genkey`)")
	}
	return c, nil
}

// DatabaseURLFromEnv returns the database URL without loading the rest of the config.
// Used by CLI subcommands that only need the database.
func DatabaseURLFromEnv() (string, error) { return databaseURL() }

// databaseURL uses KEYHAVEN_DATABASE_URL, or assembles one from DB_* variables.
// The DB_* form lets ECS inject the password from the RDS-managed secret.
func databaseURL() (string, error) {
	if v := os.Getenv("KEYHAVEN_DATABASE_URL"); v != "" {
		return v, nil
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		return "", errors.New("set KEYHAVEN_DATABASE_URL or DB_HOST/DB_USER/DB_PASSWORD/DB_NAME")
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD")),
		Host:     host + ":" + env("DB_PORT", "5432"),
		Path:     "/" + env("DB_NAME", "keyhaven"),
		RawQuery: "sslmode=" + env("DB_SSLMODE", "require"),
	}
	return u.String(), nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}
