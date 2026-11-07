.PHONY: build test e2e run tf-validate

build:
	go build -o bin/keyhaven ./cmd/keyhaven

test:
	go vet ./...
	go test ./...

# Requires a throwaway database: make e2e DB=postgres://localhost:5432/keyhaven_test?sslmode=disable
e2e:
	KEYHAVEN_TEST_DATABASE_URL="$(DB)" go test -count=1 -v ./internal/server/

run:
	KEYHAVEN_ISSUER=http://localhost:8080 KEYHAVEN_DEV=true go run ./cmd/keyhaven serve

tf-validate:
	cd deploy/terraform && terraform fmt -check -recursive && terraform init -backend=false -input=false >/dev/null && terraform validate
