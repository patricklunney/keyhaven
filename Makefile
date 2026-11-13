.PHONY: build test e2e run db db-stop admin tf-validate poc-pause poc-resume poc-status signing-key saml-key

PG_BIN  ?= $(shell pg_config --bindir 2>/dev/null || echo /opt/homebrew/opt/postgresql@17/bin)
DEV_DB  ?= postgres://postgres@localhost:55433/keyhaven?sslmode=disable
TEST_DB ?= postgres://postgres@localhost:55433/keyhaven_test?sslmode=disable

build:
	go build -o bin/keyhaven ./cmd/keyhaven

test:
	go vet ./...
	go test ./...

# End-to-end tests. They wipe TEST_DB, so never point it at real data.
e2e:
	KEYHAVEN_TEST_DATABASE_URL="$(TEST_DB)" go test -count=1 -v ./internal/...

# Local dev server on http://localhost:8080 (run `make db` first).
run:
	KEYHAVEN_ISSUER=http://localhost:8080 KEYHAVEN_DEV=true KEYHAVEN_DATABASE_URL="$(DEV_DB)" go run ./cmd/keyhaven serve

# Local Postgres in .devdb/ (gitignored), with dev and test databases.
db:
	@if [ ! -d .devdb/pgdata ]; then \
		$(PG_BIN)/initdb -D .devdb/pgdata -U postgres --auth=trust >/dev/null; fi
	@$(PG_BIN)/pg_ctl -D .devdb/pgdata status >/dev/null 2>&1 || \
		$(PG_BIN)/pg_ctl -D .devdb/pgdata -o "-p 55433 -k ''" -l .devdb/pg.log start >/dev/null
	@sleep 1
	@$(PG_BIN)/createdb -h localhost -p 55433 -U postgres keyhaven 2>/dev/null || true
	@$(PG_BIN)/createdb -h localhost -p 55433 -U postgres keyhaven_test 2>/dev/null || true
	@echo "Postgres running on localhost:55433"

db-stop:
	$(PG_BIN)/pg_ctl -D .devdb/pgdata stop

# Make a local user an administrator: make admin NAME=yourusername
admin:
	@test -n "$(NAME)" || (echo "usage: make admin NAME=<username>"; exit 2)
	KEYHAVEN_DATABASE_URL="$(DEV_DB)" go run ./cmd/keyhaven user promote "$(NAME)"

tf-validate:
	cd deploy/terraform && terraform fmt -check -recursive && terraform init -backend=false -input=false >/dev/null && terraform validate

# Proof-of-concept deployments: stop paying for compute and the database between demos.
poc-pause:
	scripts/poc.sh pause

poc-resume:
	scripts/poc.sh resume

poc-status:
	scripts/poc.sh status

# Generate the token-signing key straight into Secrets Manager (when generate_signing_key = false).
signing-key:
	scripts/signing-key.sh

# Generate the SAML signing key + certificate straight into Secrets Manager (enable_saml = true).
saml-key:
	scripts/saml-key.sh
