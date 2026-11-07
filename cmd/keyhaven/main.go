// Command keyhaven is an open source passkey-first identity provider:
// a FIDO2/WebAuthn relying party plus an OpenID Connect provider.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/keyhaven/keyhaven/internal/config"
	"github.com/keyhaven/keyhaven/internal/server"
	"github.com/keyhaven/keyhaven/internal/store"
	"github.com/keyhaven/keyhaven/internal/tokens"
)

const usage = `keyhaven — passkey identity provider (FIDO2 + OpenID Connect)

Usage:
  keyhaven serve                       Run the HTTP server (applies migrations first)
  keyhaven migrate                     Apply database migrations and exit
  keyhaven genkey                      Print a new ES256 signing key (PEM)
  keyhaven healthcheck                 Exit 0 if the local server's /healthz is OK (container health checks)
  keyhaven client create [flags]       Register an OIDC client
      --name NAME                      Display name (required)
      --redirect-uri URI               Allowed redirect URI (repeatable, required)
      --post-logout-uri URI            Allowed post-logout redirect URI (repeatable)
      --public                         Public client (SPA/native): no secret, PKCE only
  keyhaven client list                 List OIDC clients
  keyhaven client delete ID            Delete an OIDC client
  keyhaven user list                   List users
  keyhaven user promote USERNAME       Grant the administrator role (access to /admin)
  keyhaven user demote USERNAME        Remove the administrator role
  keyhaven user delete ID              Delete a user and all their passkeys

Configuration is read from environment variables; see README.md.
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(log)
	case "migrate":
		err = withStore(func(ctx context.Context, st *store.Store) error { return st.Migrate(ctx) })
	case "healthcheck":
		err = healthcheck()
	case "genkey":
		var k string
		if k, err = tokens.GenerateKeyPEM(); err == nil {
			fmt.Print(k)
		}
	case "client":
		err = clientCmd(os.Args[2:])
	case "user":
		err = userCmd(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := openStoreWithRetry(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	keyPEM := cfg.SigningKeyPEM
	if keyPEM == "" {
		log.Warn("KEYHAVEN_SIGNING_KEY not set; using an ephemeral key (dev mode only — tokens will not survive restarts)")
		if keyPEM, err = tokens.GenerateKeyPEM(); err != nil {
			return err
		}
	}
	signer, err := tokens.NewSigner(keyPEM)
	if err != nil {
		return err
	}

	srv, err := server.New(cfg, st, signer, log)
	if err != nil {
		return err
	}

	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.Cleanup(ctx); err != nil && ctx.Err() == nil {
					log.Error("cleanup", "err", err)
				}
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("keyhaven listening", "addr", cfg.ListenAddr, "issuer", cfg.Issuer, "rp_id", cfg.RPID)
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

// openStoreWithRetry waits for the database (useful when RDS or docker-compose
// Postgres is still starting).
func openStoreWithRetry(ctx context.Context, dsn string, log *slog.Logger) (*store.Store, error) {
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	for attempt := 1; ; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = st.Ping(pingCtx)
		cancel()
		if err == nil {
			return st, nil
		}
		if attempt >= 30 || ctx.Err() != nil {
			st.Close()
			return nil, fmt.Errorf("database unreachable: %w", err)
		}
		log.Warn("waiting for database", "attempt", attempt, "err", err)
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	}
}

func withStore(fn func(context.Context, *store.Store) error) error {
	dsn, err := config.DatabaseURLFromEnv()
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	return fn(ctx, st)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func clientCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: keyhaven client create|list|delete")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("client create", flag.ContinueOnError)
		name := fs.String("name", "", "client display name")
		public := fs.Bool("public", false, "public client (no secret)")
		var redirects, postLogout multiFlag
		fs.Var(&redirects, "redirect-uri", "allowed redirect URI (repeatable)")
		fs.Var(&postLogout, "post-logout-uri", "allowed post-logout redirect URI (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" || len(redirects) == 0 {
			return errors.New("--name and at least one --redirect-uri are required")
		}
		for _, u := range append(append([]string{}, redirects...), postLogout...) {
			if err := server.ValidateRedirectURI(u); err != nil {
				return err
			}
		}
		return withStore(func(ctx context.Context, st *store.Store) error {
			c, secret, err := st.CreateClient(ctx, *name, redirects, postLogout, *public)
			if err != nil {
				return err
			}
			fmt.Printf("client_id:     %s\n", c.ID)
			if secret != "" {
				fmt.Printf("client_secret: %s\n\nStore the secret now; it cannot be shown again.\n", secret)
			} else {
				fmt.Println("client type:   public (use PKCE, no secret)")
			}
			return nil
		})
	case "list":
		return withStore(func(ctx context.Context, st *store.Store) error {
			cs, err := st.ListClients(ctx)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tTYPE\tREDIRECT URIS")
			for _, c := range cs {
				typ := "confidential"
				if c.Public() {
					typ = "public"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Name, typ, strings.Join(c.RedirectURIs, " "))
			}
			return tw.Flush()
		})
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: keyhaven client delete ID")
		}
		return withStore(func(ctx context.Context, st *store.Store) error { return st.DeleteClient(ctx, args[1]) })
	}
	return fmt.Errorf("unknown client subcommand %q", args[0])
}

func userCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: keyhaven user list|delete")
	}
	switch args[0] {
	case "list":
		return withStore(func(ctx context.Context, st *store.Store) error {
			us, _, err := st.SearchUsers(ctx, "", 100000, 0)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tUSERNAME\tDISPLAY NAME\tADMIN\tPASSKEYS\tCREATED")
			for _, u := range us {
				admin := ""
				if u.IsAdmin {
					admin = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", u.ID, u.Username, u.DisplayName, admin, u.Passkeys, u.CreatedAt.Format(time.RFC3339))
			}
			return tw.Flush()
		})
	case "promote", "demote":
		if len(args) != 2 {
			return fmt.Errorf("usage: keyhaven user %s USERNAME", args[0])
		}
		grant := args[0] == "promote"
		return withStore(func(ctx context.Context, st *store.Store) error {
			u, err := st.GetUserByUsername(ctx, args[1])
			if err != nil {
				return fmt.Errorf("user %q: %w", args[1], err)
			}
			if err := st.SetAdmin(ctx, u.ID, grant); err != nil {
				return err
			}
			action := "admin.user.promote"
			if !grant {
				action = "admin.user.demote"
			}
			_ = st.AddAudit(ctx, store.AuditEvent{ActorName: "cli", Action: action, TargetType: "user", TargetID: u.ID, TargetName: u.Username})
			if grant {
				fmt.Printf("%s is now an administrator. Sign in at <issuer>/admin\n", u.Username)
			} else {
				fmt.Printf("%s is no longer an administrator.\n", u.Username)
			}
			return nil
		})
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: keyhaven user delete ID")
		}
		return withStore(func(ctx context.Context, st *store.Store) error { return st.DeleteUser(ctx, args[1]) })
	}
	return fmt.Errorf("unknown user subcommand %q", args[0])
}

// healthcheck probes the local server. The image has no shell or curl, so ECS
// container health checks run this instead (needed when there's no load
// balancer doing health checks).
func healthcheck() error {
	addr := os.Getenv("KEYHAVEN_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", res.StatusCode)
	}
	return nil
}
