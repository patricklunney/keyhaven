# Keyhaven: passkey identity provider for OpenID Connect and SAML

An open source, **passkey-first identity provider**: a FIDO2 / WebAuthn server, an
OpenID Connect provider and an optional SAML 2.0 identity provider in one small Go binary,
with Terraform to run it on **AWS ECS Fargate**.

Users sign up and sign in with passkeys only (Touch ID, Face ID, Windows Hello, Android,
YubiKeys and other security keys). Your applications sign users in with standard OpenID Connect, so
they work with any OIDC library (NextAuth/Auth.js, Spring Security, `oauth2-proxy`,
AWS ALB/Cognito federation, Grafana, etc.). Apps that only speak SAML can use the SAML 2.0
endpoints instead.

## Features

**FIDO2 / WebAuthn relying party**
- Passkey registration and username-less (discoverable) sign-in
- User verification required: the passkey is a full, phishing-resistant credential on its own
- Multiple passkeys per account; add, list and remove them (removing the last one is blocked)
- An email address is required on every account (unique, not verified). Accounts created before this rule are asked to add one at their next sign-in, before they continue to any app
- Signature-counter clone detection (sign-in is rejected if a counter goes backwards)
- Built on [`go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn)

**OpenID Connect provider**
- Authorization code flow with **mandatory PKCE (S256)** for every client, per OAuth 2.1
- Confidential clients (`client_secret_basic`, `client_secret_post`) and public clients (SPA/native)
- ES256-signed ID tokens and RFC 9068 JWT access tokens; JWKS published
- Refresh tokens (via the `offline_access` scope) that rotate on every use
- Discovery, `userinfo`, RP-initiated logout (`end_session`), `prompt=none|login`
- RFC 9207 `iss` parameter on authorization responses

**Admin console** (`/admin`)
- Onboard applications through a guided form. The client secret is shown once, alongside copy-paste integration settings
- Edit redirect URIs, rotate secrets, delete applications
- Browse and search all users, inspect their passkeys, sign them out everywhere, grant or remove admin, delete accounts
- Dashboard with counts and recent activity, plus a filterable audit log of sign-ups, sign-ins and every admin action
- Only administrators can get in, and they must have signed in with a passkey within the last hour. Every change is CSRF-protected, and the system refuses to remove its last administrator

**SAML 2.0 identity provider** (optional)
- SP-initiated web SSO for apps that speak SAML instead of OpenID Connect: HTTP-Redirect and HTTP-POST bindings, with the Response and Assertion both signed (RSA-SHA256)
- Metadata at `/saml/metadata`; apps are managed in the admin console (**SAML apps**) or with `keyhaven saml-app`
- NameID can be the persistent Keyhaven user ID or the username. The assertion also carries the attributes `uid`, `username`, `displayName` and `email`

**Operations**
- Stateless app tasks; all state lives in Postgres, so it scales out horizontally
- Migrations run automatically at startup (guarded by an advisory lock)
- Structured JSON logs, `/healthz`, graceful shutdown on SIGTERM
- Distroless, non-root, read-only-filesystem container

## Architecture

```mermaid
flowchart LR
  U[Browser / passkey] -->|HTTPS| WAF[AWS WAF]
  RP[Your apps<br/>OIDC clients] -->|HTTPS| WAF
  WAF --> ALB[Application Load Balancer<br/>TLS 1.2+/1.3, ACM cert]
  subgraph VPC
    subgraph Private subnets
      ALB --> T1[Fargate task<br/>keyhaven]
      ALB --> T2[Fargate task<br/>keyhaven]
      T1 --> DB[(RDS Postgres 17<br/>encrypted, TLS enforced)]
      T2 --> DB
    end
  end
  SM[Secrets Manager<br/>signing key, DB password] -. injected at start .-> T1
  SM -.-> T2
  ECR[ECR] -. image .-> T1
```

| Path | Purpose |
|---|---|
| `cmd/keyhaven` | CLI: `serve`, `migrate`, `genkey`, `client …`, `user …` |
| `internal/server` | HTTP handlers: WebAuthn, OIDC, user pages and the admin console |
| `internal/store` | Postgres persistence and embedded SQL migrations |
| `internal/tokens` | ES256 JWT signing and verification, JWKS |
| `web/` | Embedded HTML templates, CSS and the WebAuthn browser client |
| `deploy/terraform` | VPC, ALB, ACM, ECS Fargate, RDS, Secrets Manager, ECR, WAF |

## Run locally

With Docker:

```sh
docker compose up --build
open http://localhost:8080        # create an account with a passkey
```

Without Docker (Go 1.27+ and PostgreSQL installed, e.g. `brew install postgresql@17`):

```sh
make db      # starts a local Postgres in .devdb/ (port 55433)
make run     # http://localhost:8080
```

> Browsers allow WebAuthn on `http://localhost`. Anywhere else requires HTTPS, and the
> RP ID must be a domain name, not an IP address.

Then make your account an administrator and open the admin console:

```sh
make admin NAME=<your-username>
open http://localhost:8080/admin
```

### Tests

```sh
go test ./...    # unit tests
make e2e         # end-to-end tests against the keyhaven_test database from `make db`
```

The end-to-end tests (`internal/server/e2e_test.go`) use a software FIDO2 authenticator
to drive the real handlers through these steps: sign-up, sign-in, authorize → code → token →
userinfo, and refresh rotation. It also checks the attack cases: wrong PKCE verifier, reused
code, wrong client secret, cloned authenticator, cross-origin POST, unregistered redirect
URI, and an ID token presented as an access token. A second test covers the admin console:
access control, onboarding, secret rotation, user management, re-authentication, unsafe redirects
and the audit log. **The tests drop and recreate the `public` schema, so point them only at a
throwaway database.**

## Configuration

All configuration comes from environment variables.

| Variable | Default | Description |
|---|---|---|
| `KEYHAVEN_ISSUER` | — (required) | Public origin, e.g. `https://id.example.com`. Used as the OIDC issuer and the WebAuthn origin. |
| `KEYHAVEN_SIGNING_KEY` | — (required unless dev) | P-256 private key PEM. Generate with `keyhaven genkey`. |
| `KEYHAVEN_DATABASE_URL` | — | Postgres URL. Alternatively set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSLMODE`. |
| `KEYHAVEN_RP_ID` | issuer host | WebAuthn RP ID. Set it to a parent domain (e.g. `example.com`) so passkeys also work on sibling subdomains. **Changing it later invalidates every existing passkey.** |
| `KEYHAVEN_RP_DISPLAY_NAME` | `Keyhaven` | Name shown on pages and in passkey prompts |
| `KEYHAVEN_RP_EXTRA_ORIGINS` | — | Extra comma-separated WebAuthn origins |
| `KEYHAVEN_ALLOW_SIGNUP` | `true` | Allow self-service account creation |
| `KEYHAVEN_SESSION_TTL` | `12h` | Browser session lifetime at the IdP |
| `KEYHAVEN_ACCESS_TOKEN_TTL` | `15m` | |
| `KEYHAVEN_ID_TOKEN_TTL` | `15m` | |
| `KEYHAVEN_REFRESH_TOKEN_TTL` | `720h` | |
| `KEYHAVEN_ADMIN_REAUTH` | `1h` | Maximum session age for the admin console; older sessions must sign in with a passkey again |
| `KEYHAVEN_LISTEN_ADDR` | `:8080` | |
| `KEYHAVEN_DEV` | `false` | Allows an `http://` issuer and an ephemeral signing key. Never use in production. |

## Admin console

Administrators manage Keyhaven at `https://<your-domain>/admin`.

**Bootstrapping the first administrator.** Sign up normally with a passkey, then grant the role from the
CLI. On Fargate, run it as a one-off task (see [Admin tasks on Fargate](#admin-tasks-on-fargate)):

```sh
keyhaven user promote <username>
```

After that, admins can promote others from the console. To lock sign-up down to people you've
invited, set `allow_signup = false` once your admins exist.

| Page | What you can do |
|---|---|
| Dashboard | Counts of users, applications, passkeys and active sessions; newest users; recent activity |
| Applications | Onboard an app (web app with a secret, or a public SPA/native app using PKCE); view integration settings; edit redirect URIs; rotate the secret; delete |
| Users | Search and page through all users; view a user's passkeys and activity; sign them out everywhere; remove a passkey; grant or remove admin; delete the account |
| Audit log | Every sign-up, sign-in, blocked sign-in, passkey change and admin action, with actor, target, details and IP |

Safeguards: admins can't delete or demote themselves, the last administrator can't be removed, and
destructive actions require typing the user's or application's name to confirm.

## SAML

Keyhaven can also act as a SAML 2.0 identity provider. Sign-in is started by the app (SP-initiated), the
user signs in with a passkey, and Keyhaven posts a signed assertion back to the app.

**Enable it**
```sh
# terraform.tfvars: enable_saml = true
terraform -chdir=deploy/terraform apply -target=aws_secretsmanager_secret.saml_key
make saml-key            # RSA-3072 key + 10-year certificate, piped straight into Secrets Manager
terraform -chdir=deploy/terraform apply
```
Locally, set `KEYHAVEN_SAML_KEY="$(go run ./cmd/keyhaven saml-keygen)"` before `make run`.

**Register an app** under **Admin → SAML apps → Add a SAML app**, with its entity ID, ACS URL(s) and NameID
format. Then give the app Keyhaven's metadata URL (`<issuer>/saml/metadata`), or its entity ID
(`<issuer>/saml`), SSO URL (`<issuer>/saml/sso`) and certificate.

**Try it with the bundled test app**
```sh
go run ./cmd/samltest-sp -idp https://id.example.com
# register entity ID http://localhost:8091/saml/metadata, ACS http://localhost:8091/saml/acs
open http://localhost:8091
```
The test app uses an independent SAML library (`gosaml2`) to verify Keyhaven's signature, audience and
timing, then shows the NameID and attributes it received.

**Security model**
- **Trust comes from registration.** Assertions go only to an app's pre-registered entity ID and exact
  ACS URLs (https, or http on localhost). Requests from unknown apps, for unregistered ACS URLs, addressed to
  another IdP, older than 5 minutes, or asking for an unsupported binding are refused with an error page.
  Keyhaven never posts to an unvalidated URL.
- **Keyhaven only signs.** It never verifies untrusted XML signatures, which avoids the XML
  signature-wrapping attack class. Signing uses `goxmldsig` v1.6.1, which includes the CVE-2026-33487 fix.
  The `crewjam/saml` framework is deliberately not used (advisory GO-2026-6909, active release churn).
- **Hardened parsing.** Every element is matched by its full namespace, DTDs are refused, and the request and
  its inflated (DEFLATE) size are capped at 64 KB.
- **Short-lived assertions.** Assertions last 5 minutes and are bound to the request (`InResponseTo`), the
  ACS URL (`Recipient`) and the app (`Audience`). `ForceAuthn` requires a fresh passkey sign-in;
  `IsPassive` gets a signed `NoPassive` failure instead of a login page.
- **CSP.** The page that auto-posts the response may submit only to that app's ACS origin.
- **Audit.** Every SAML sign-in and SAML app change is recorded.

**Not supported (yet):** IdP-initiated SSO (it's off on purpose), Single Logout, encrypted assertions, signed
AuthnRequests, and the artifact binding. With the HTTP-POST *request* binding, browsers don't send the
`SameSite=Lax` session cookie on the cross-site POST, so users may be asked to sign in again; HTTP-Redirect
apps reuse the existing session.

## Connect an application

Discovery document: `https://id.example.com/.well-known/openid-configuration`

1. Register the client in the admin console under **Applications → Add an application** (or with the CLI,
   locally or as a one-off ECS task):
   ```sh
   keyhaven client create --name "My App" \
     --redirect-uri https://app.example.com/callback \
     --post-logout-uri https://app.example.com/
   ```
   Add `--public` for SPAs and native apps; public clients get no secret and rely on PKCE.
2. Configure your OIDC library with the issuer, `client_id`, `client_secret` and scopes
   `openid profile` (add `offline_access` for refresh tokens).
3. Make sure PKCE (S256) is enabled in the library. Keyhaven rejects requests without it.

ID token / userinfo claims: `sub` (stable opaque user ID), and with the `profile` scope also
`name` and `preferred_username`. The `amr` claim is `["hwk","user"]`.

## Deploy to AWS Fargate

Prerequisites: an AWS account, a Route 53 hosted zone for your domain, Terraform ≥ 1.6,
Docker with buildx, and the AWS CLI.

```sh
cd deploy/terraform
cp example.tfvars terraform.tfvars      # set domain_name, hosted_zone_id, region
terraform init

# 1. Create the image repository first
terraform apply -target=aws_ecr_repository.this
REPO=$(terraform output -raw ecr_repository_url)

# 2. Build and push an arm64 image (tasks run on Graviton)
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
docker buildx build --platform linux/arm64 -t "$REPO:v0.1.0" --push ../..

# 3. Create everything else
terraform apply
```

After about 10–15 minutes (most of it RDS and certificate validation), `https://<domain_name>` is live.

**What gets created:** a VPC across 2 AZs with private subnets for the tasks and database,
NAT for outbound traffic, an ALB with an ACM certificate (HTTP → HTTPS redirect, TLS 1.3 policy, invalid
headers dropped), Route 53 A/AAAA aliases, an ECS cluster with Container Insights, a
Fargate service (desired 2, CPU autoscaling, deployment circuit breaker with rollback),
RDS Postgres 17 (encrypted, TLS enforced, automated backups, master password managed by
RDS in Secrets Manager), the signing key in Secrets Manager, ECR with immutable tags and scan-on-push,
and a WAF with AWS managed rules and a per-IP rate limit.

### Deploying a new version

```sh
docker buildx build --platform linux/arm64 -t "$REPO:v0.2.0" --push .
terraform apply -var image_tag=v0.2.0
```

ECS performs a rolling deployment and rolls back automatically if new tasks fail
health checks.

### Admin tasks on Fargate

The image has no shell, so admin commands run as one-off tasks using the service's task
definition and network:

```sh
terraform output -raw register_client_command   # prints a ready-to-edit aws ecs run-task command
```

The client secret is printed to the task's CloudWatch logs (`/ecs/keyhaven`). Copy it
out, then delete that log stream. Other commands work the same way: `user promote USERNAME`,
`client list`, `client delete ID`, `user list`, `user delete ID`. Once an administrator exists, the
admin console covers all of these.

### Signing key

By default Terraform generates the ES256 key and stores it in Secrets Manager, which
means the key **is also in Terraform state**. Use an encrypted S3 backend with
restricted access (see `versions.tf`). To keep the key out of state, set
`generate_signing_key = false` and populate the secret yourself:

```sh
aws secretsmanager put-secret-value --secret-id keyhaven/signing-key \
  --secret-string "$(keyhaven genkey)"
```

### Cost

Approximate monthly cost in us-east-1 at light traffic, from AWS list prices. Check the
[AWS Pricing Calculator](https://calculator.aws/) for current figures.

| Resource | POC (`poc.tfvars.example`) | Budget (`budget.tfvars.example`) | Default | Hardened (`example.tfvars`) |
|---|---|---|---|---|
| NAT gateway(s) + IP | — | — | ~$37 | ~$74 (one per AZ) |
| Ingress | ~$0–1 (API Gateway, Cloud Map) | ~$30 (load balancer) | ~$30 | ~$30 |
| Fargate tasks (0.25 vCPU / 0.5 GB, ARM) | ~$6 (1 Spot task + public IP) | ~$11 (1 task + public IP) | ~$14.50 (2 tasks) | ~$14.50 (2 tasks) |
| RDS Postgres db.t4g.micro + 20 GB | ~$14 | ~$14 | ~$14 | ~$28 (Multi-AZ) |
| WAF | — | — | ~$8 | ~$8 |
| Logs, Secrets Manager, ECR, DNS | ~$2 | ~$4–6 | ~$4–6 | ~$4–6 |
| **Total** | **~$22 (~$4 paused)** | **~$60** | **~$105–115** | **~$160** |

Traffic adds little: each sign-in costs a fraction of a cent, and autoscaling adds about $7 per extra task.

**`cost_optimized = true`** removes the NAT gateway, the biggest fixed cost. Tasks run in
the public subnets with public IPs instead, so they can reach ECR, Secrets Manager and CloudWatch
directly. Their security group still accepts traffic only from the load balancer, and the
database stays in private subnets with no internet route. The trade-offs: tasks have public IPs
(unreachable, but visible), and outbound traffic leaves from task IPs rather than one stable NAT
address, which matters only if something downstream allowlists your IP.

### Proof of concept (`poc.tfvars.example`)

The cheapest setup that still runs on your own domain with HTTPS:

- **No load balancer:** `ingress = "api_gateway"` puts an API Gateway HTTP API in front of the
  tasks, reaching them through a VPC link and AWS Cloud Map service discovery. You pay per
  request (about $1 per million) instead of about $30/month. ECS checks task health itself
  with `keyhaven healthcheck` and replaces a task that fails it. Cloud Map health gating isn't
  enabled; with a single task it would make no difference. The default `execute-api` URL is disabled, so the issuer domain is the only way in.
- **Fargate Spot:** `fargate_spot = true` runs one task about 70% cheaper. AWS can reclaim it
  with 2 minutes' notice; ECS starts a replacement automatically, with a short outage.
- No NAT gateway, no WAF (HTTP APIs can't use one; API Gateway throttling limits request rates
  instead), Container Insights off, 7-day logs, 1 day of database backups, and deletion
  protection off so `terraform destroy` removes everything.

**Deploy order for the POC.** `poc.tfvars.example` sets `generate_signing_key = false`, which keeps the
token-signing key out of Terraform state. The key has to exist before the service starts:

```sh
cd deploy/terraform
terraform apply -target=aws_ecr_repository.this -target=aws_secretsmanager_secret.signing_key
ko build ./cmd/keyhaven --bare --tags v0.1.0     # with KO_DOCKER_REPO=<ecr_repository_url>; see .ko.yaml
make -C ../.. signing-key                        # generates the key straight into Secrets Manager
terraform apply                                  # everything else
```

**POC security posture.** Nothing is reachable from the internet except API Gateway on your HTTPS
domain: there are no open security-group rules, the database is private and encrypted, and the
default `execute-api` URL is disabled. Tasks run read-only, as a non-root user, with every Linux
capability dropped. API Gateway access logs (`/apigateway/keyhaven`) record each caller's real IP.
Known POC trade-offs:
- **Shared throttle:** the 5 requests/second limit applies to all callers together, so one client
  can slow the service for everyone. It also caps the cost of a flood.
- **No WAF.**
- **Open sign-up:** set `allow_signup = false` once your accounts exist.
- **Unverified database certificate:** the database connection is encrypted with TLS, but the
  server certificate isn't verified (`sslmode=require`).

**Pause between demos.** Most of the remaining cost is the database and the task. Pausing stops
both, bringing the cost to about $4/month:

```sh
make poc-pause    # scale to 0 tasks, stop the database
make poc-resume   # start the database, bring the task back (~5 minutes)
make poc-status
```

AWS restarts a stopped RDS instance automatically after 7 days, so pause again if you're away longer.
A later `terraform apply` restores the normal task count.

`budget.tfvars.example` combines `cost_optimized` with one task and no WAF. One task means brief downtime when
a task restarts or deploys, and no WAF means no per-IP rate limit in front of sign-in.

## Security notes

- **Passkey-only.** There are no passwords to phish or stuff. Account recovery is
  "add a second passkey" (synced passkeys from Apple, Google or 1Password cover most users). An
  admin can delete an account with `keyhaven user delete` so the user can register again.
- **CSRF:** cookies are `__Host-`, `HttpOnly`, `Secure` and `SameSite=Lax`, and every state-changing
  browser endpoint also requires a matching `Origin` header.
- **Stored secrets are hashed:** sessions, authorization codes, refresh tokens and client
  secrets are stored as SHA-256 hashes of 256-bit random values.
- **Single use:** authorization codes and WebAuthn challenges are consumed atomically
  (`DELETE … RETURNING`), so a replay always fails, even across tasks.
- **Strict CSP** (no inline script), `frame-ancestors 'none'` and HSTS.
- The database connection uses `sslmode=require`. That encrypts the connection inside the VPC but does not
  verify the RDS certificate; add the RDS CA bundle to the image and use `verify-full` if your
  threat model requires it.

## Limitations / roadmap

Not implemented yet. Contributions welcome:

- Email verification (email is required but not verified; apps get `email_verified: false`), SCIM provisioning
- Signing-key rotation with multiple published keys
- Back-channel logout, token revocation (RFC 7009) and introspection (RFC 7662) endpoints
- Attestation verification against the FIDO Metadata Service (MDS3) to restrict authenticator models
- Pushed authorization requests (PAR), DPoP

## License

MIT. See [LICENSE](LICENSE).
