SHELL := /bin/bash
COMPOSE := docker compose

.DEFAULT_GOAL := help

## ---------------------------------------------------------------------------
## Infrastructure
## ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.env: ## Create .env from the example if missing
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example")

.PHONY: up
up: .env ## Start the whole stack (idempotent)
	$(COMPOSE) up -d --remove-orphans
	@$(MAKE) --no-print-directory bao-init
	@$(MAKE) --no-print-directory status

.PHONY: down
down: ## Stop the stack, keep volumes
	$(COMPOSE) down --remove-orphans

.PHONY: nuke
nuke: ## Stop the stack AND destroy all data volumes
	$(COMPOSE) down -v --remove-orphans

.PHONY: restart
restart: down up ## Full restart

.PHONY: status
status: ## Health of every container
	@$(COMPOSE) ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'

.PHONY: logs
logs: ## Tail all logs
	$(COMPOSE) logs -f --tail=100

.PHONY: config
config: .env ## Render the fully-resolved compose file
	$(COMPOSE) config

.PHONY: pull
pull: .env ## Pull all pinned images
	$(COMPOSE) pull

## ---------------------------------------------------------------------------
## Shells & consoles
## ---------------------------------------------------------------------------

.PHONY: migrate
migrate: ## Apply pending migrations (embedded in cmd/migrate)
	@go run ./cmd/migrate -cmd up

.PHONY: migrate-down
migrate-down: ## Roll back one migration
	@go run ./cmd/migrate -cmd down

.PHONY: migrate-status
migrate-status: ## Show applied and pending migrations
	@go run ./cmd/migrate -cmd status

.PHONY: migrate-new
migrate-new: ## Create a migration: make migrate-new NAME=add_widgets
	@test -n "$(NAME)" || { echo "  usage: make migrate-new NAME=add_widgets"; exit 1; }
	@next=$$(printf '%05d' $$(( $$(ls cmd/migrate/migrations 2>/dev/null | sed -n 's/^0*\([0-9]*\)_.*/\1/p' | sort -n | tail -1) + 1 ))); \
	 f="cmd/migrate/migrations/$${next}_$(NAME).sql"; \
	 printf -- '-- +goose Up\n-- +goose StatementBegin\n\n-- +goose StatementEnd\n\n-- +goose Down\n-- +goose StatementBegin\n\n-- +goose StatementEnd\n' > $$f; \
	 echo "  created $$f"

.PHONY: migrate-check
migrate-check: ## Verify migrations are append-only (replaces Atlas checksums)
	@bash scripts/check_migrations.sh

.PHONY: psql
psql: ## psql into the read model
	$(COMPOSE) exec postgres psql -U $${POSTGRES_USER:-chronos} -d $${POSTGRES_DB:-chronos}

.PHONY: valkey-cli
valkey-cli: ## valkey-cli shell
	$(COMPOSE) exec valkey valkey-cli

.PHONY: temporal-cli
temporal-cli: ## Temporal admin-tools shell (profile: tools)
	$(COMPOSE) --profile tools run --rm temporal-admin-tools bash

.PHONY: check-centrifugo
check-centrifugo: ## Validate the Centrifugo config file
	$(COMPOSE) run --rm --no-deps centrifugo centrifugo checkconfig --config /centrifugo/config.json

## ---------------------------------------------------------------------------
## Smoke tests
## ---------------------------------------------------------------------------

.PHONY: smoke
smoke: ## Hit every service's health/UI endpoint
	@bash scripts/smoke.sh

## ---------------------------------------------------------------------------
## API — schema, codegen and documentation (CONVENTIONS §7.1, ADR-007)
## ---------------------------------------------------------------------------

.PHONY: proto
proto: ## Generate Go + Connect from proto
	buf generate

.PHONY: proto-lint
proto-lint: ## Lint proto, including mandatory doc comments
	buf lint

.PHONY: proto-breaking
proto-breaking: ## Fail on a breaking API change vs the main branch
	@buf breaking --against '.git#branch=main,subdir=.' 2>/dev/null \
		|| buf breaking --against '.git#ref=HEAD~1,subdir=.' 2>/dev/null \
		|| echo "  (no baseline yet — first commit)"

.PHONY: api-docs
api-docs: ## Generate OpenAPI, the gRPC descriptor set and the error catalogue
	@buf generate --template buf.gen.openapi.yaml --path proto/chronos/system
	@go run ./internal/tools/gendocs
	@echo "  wrote docs/api/chronos-openapi.yaml"
	@buf generate --template buf.gen.docs.yaml
	@echo "  wrote docs/api/grpc.html (human-readable gRPC reference)"
	@buf build -o docs/api/descriptor.binpb
	@echo "  wrote docs/api/descriptor.binpb (gRPC, for grpcurl/Postman without reflection)"
	@$(MAKE) --no-print-directory docs-assets

.PHONY: docs-assets
docs-assets: ## Copy generated artifacts into the docs binary for embedding
	@mkdir -p cmd/apidocs/assets/proto
	@cp docs/api/chronos-openapi.yaml cmd/apidocs/assets/openapi.yaml
	@cp docs/api/errors.md docs/api/descriptor.binpb docs/api/grpc.html cmd/apidocs/assets/
	@rsync -a --delete --include='*/' --include='*.proto' --exclude='*' proto/ cmd/apidocs/assets/proto/
	@echo "  embedded assets refreshed (cmd/apidocs/assets)"

.PHONY: run
run: ## Run the tenant API against the local stack
	@echo "  api        http://localhost:$${API_PORT:-8090}"
	@echo "  healthz    http://localhost:$${API_PORT:-8090}/healthz"
	@echo "  readyz     http://localhost:$${API_PORT:-8090}/readyz"
	@go run ./cmd/api -addr :$${API_PORT:-8090}

.PHONY: projector
projector: ## Run the projector against the local stack
	@echo "  healthz    http://localhost:$${PROJECTOR_PORT:-8093}/healthz"
	@echo "  readyz     http://localhost:$${PROJECTOR_PORT:-8093}/readyz"
	@go run ./cmd/projector -addr :$${PROJECTOR_PORT:-8093}

.PHONY: projector-list
projector-list: ## List every registered projection
	@go run ./cmd/projector -list

.PHONY: projector-rebuild
projector-rebuild: ## Rebuild one projection from zero: make projector-rebuild NAME=identity_users
	@test -n "$(NAME)" || { echo "NAME is required, e.g. make projector-rebuild NAME=identity_users"; exit 1; }
	@go run ./cmd/projector -rebuild $(NAME)

.PHONY: worker
worker: ## Run the reactors (email, push, workflows) against the local stack
	@echo "  healthz    http://localhost:$${WORKER_PORT:-8094}/healthz"
	@go run ./cmd/worker -addr :$${WORKER_PORT:-8094}

.PHONY: worker-list
worker-list: ## List every registered reactor
	@go run ./cmd/worker -list

.PHONY: worker-stats
worker-stats: ## Queue depth and parked count per reactor
	@go run ./cmd/worker -stats

.PHONY: worker-replay
worker-replay: ## Return a reactor's parked events to the live queue: make worker-replay NAME=welcome_email
	@test -n "$(NAME)" || { echo "NAME is required, e.g. make worker-replay NAME=welcome_email"; exit 1; }
	@go run ./cmd/worker -replay-parked $(NAME)

.PHONY: status
status-api: ## Call GetStatus over HTTP/JSON
	@curl -s -X POST http://localhost:$${API_PORT:-8090}/chronos.system.v1.SystemService/GetStatus \
		-H 'Content-Type: application/json' -d '{}' | python3 -m json.tool

.PHONY: docs-serve
docs-serve: ## Run the API documentation server (foreground)
	@echo "  reference  http://localhost:$${DOCS_PORT:-8091}/reference"
	@echo "  index      http://localhost:$${DOCS_PORT:-8091}/"
	@go run ./cmd/apidocs -addr :$${DOCS_PORT:-8091}

.PHONY: docs-open
docs-open: ## Run the docs server and open the reference in a browser
	@( sleep 1; open "http://localhost:$${DOCS_PORT:-8091}/reference" ) &
	@$(MAKE) --no-print-directory docs-serve

.PHONY: grpc-ui
grpc-ui: ## Interactive gRPC console against a running cmd/api
	@curl -sf http://localhost:$${API_PORT:-8090}/healthz >/dev/null 2>&1 \
		|| { echo "  cmd/api is not responding on :$${API_PORT:-8090} — start it with 'make run'"; exit 1; }
	@test -f docs/api/descriptor.binpb || $(MAKE) --no-print-directory api-docs
	@echo "  console  http://localhost:$${GRPCUI_PORT:-8092}"
	@echo "  target   localhost:$${API_PORT:-8090}  (via descriptor set — works with reflection disabled)"
	@if command -v grpcui >/dev/null; then \
		grpcui -plaintext -protoset docs/api/descriptor.binpb \
			-port $${GRPCUI_PORT:-8092} localhost:$${API_PORT:-8090}; \
	else \
		echo "  (grpcui not installed — running it with 'go run', first start is slow)"; \
		go run github.com/fullstorydev/grpcui/cmd/grpcui@latest -plaintext \
			-protoset docs/api/descriptor.binpb \
			-port $${GRPCUI_PORT:-8092} localhost:$${API_PORT:-8090}; \
	fi

.PHONY: vendor-refresh
vendor-refresh: ## Re-download the embedded API reference bundle
	@curl -sL -o cmd/apidocs/assets/vendor/scalar.js https://cdn.jsdelivr.net/npm/@scalar/api-reference
	@echo "  refreshed cmd/apidocs/assets/vendor/scalar.js ($$(du -h cmd/apidocs/assets/vendor/scalar.js | cut -f1))"

.PHONY: api
api: proto proto-lint api-docs ## Everything schema-driven, regenerated

## ---------------------------------------------------------------------------
## Go
## ---------------------------------------------------------------------------

.PHONY: build
build: ## Build every binary into bin/
	@mkdir -p bin
	go build -o bin/ ./cmd/...

.PHONY: test
test: ## Run all tests
	go test ./... -race -count=1

.PHONY: bench
bench: ## Benchmarks with allocation reporting (ADR-038)
	go test ./... -run=XXX -bench=. -benchmem

.PHONY: bao-init
bao-init: ## Mount the transit engine and create the KEK (ADR-028); idempotent
	@bash scripts/bootstrap_openbao.sh

.PHONY: proto-thirdparty-check
proto-thirdparty-check: ## Fail if a vendored third-party proto drifts from the pinned server
	@bash scripts/check_thirdparty_protos.sh

.PHONY: proto-thirdparty
proto-thirdparty: ## Regenerate clients for third-party protos (ADR-037)
	buf generate --template buf.gen.centrifugo.yaml third_party
	@# OpenFGA's official Go SDK is OpenAPI-generated and speaks HTTP only, so
	@# ADR-037 means generating a gRPC client. --path openfga keeps the AuthZEN
	@# service and the transitive well-known protos out of our tree.
	buf generate buf.build/openfga/api --template buf.gen.openfga.yaml --path openfga

.PHONY: sqlc
sqlc: ## Regenerate query code from db/query/**.sql
	sqlc generate

.PHONY: sqlc-check
sqlc-check: ## Fail if generated query code is stale, or a query no longer matches the schema
	@sqlc diff >/dev/null 2>&1 || { \
		echo "generated query code is out of date, or a query no longer matches the schema"; \
		echo "run: make sqlc"; sqlc diff; exit 1; }
	@echo "  sqlc OK"

.PHONY: sql-check
sql-check: ## Fail if SQL appears in Go source outside the kernel carve-out (CONVENTIONS §8)
	@bash scripts/check_sql.sh

.PHONY: bench-integration
bench-integration: ## Benchmarks that need the live stack (make up first)
	go test -tags=integration ./... -run=XXX -bench=. -benchmem -benchtime=2000x

.PHONY: leaks
leaks: ## Run tests with goroutine-leak detection (Go 1.26)
	go test ./... -race -count=1 -gcflags=all=-d=checkptr

.PHONY: test-integration
test-integration: ## Integration tests against the running stack (make up first)
	go test -tags=integration ./... -count=1

.PHONY: cover
cover: ## Test with coverage summary
	go test ./... -race -count=1 -coverprofile=/tmp/chronos.cover
	@go tool cover -func=/tmp/chronos.cover | tail -1

.PHONY: lint
lint: ## golangci-lint, including the depguard import contract (CONVENTIONS §2)
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format in place
	gofmt -w . && go mod tidy

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted — CI must VERIFY, never rewrite
	@unformatted="$$(gofmt -l . | grep -v '^cmd/apidocs/assets/' || true)"; \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt'd:"; echo "$$unformatted"; \
		echo "run: make fmt"; exit 1; \
	fi
	@cp go.mod /tmp/go.mod.ci && cp go.sum /tmp/go.sum.ci && go mod tidy; \
	if ! diff -q go.mod /tmp/go.mod.ci >/dev/null || ! diff -q go.sum /tmp/go.sum.ci >/dev/null; then \
		cp /tmp/go.mod.ci go.mod; cp /tmp/go.sum.ci go.sum; \
		echo "go.mod/go.sum are not tidy; run: make fmt"; exit 1; \
	fi
	@echo "  formatting OK"

.PHONY: check
check: fmt-check proto-lint proto-breaking api-validate proto-thirdparty-check migrate-check sqlc-check sql-check lint test ## Everything CI runs

.PHONY: api-validate
api-validate: ## Validate the generated OpenAPI spec is complete and non-empty
	@python3 scripts/check_openapi.py

## ---------------------------------------------------------------------------
## Telemetry
## ---------------------------------------------------------------------------

.PHONY: dashboards
dashboards: ## Regenerate Grafana dashboards from scripts/gen_dashboards.py
	@python3 scripts/gen_dashboards.py
	@echo "  (Grafana reloads provisioned dashboards within 30s)"

.PHONY: dashboards-check
dashboards-check: ## Run every dashboard query against live Prometheus
	@python3 scripts/check_dashboards.py

.PHONY: traces
traces: ## Show services currently reporting traces to Tempo
	@curl -s "http://localhost:$${TEMPO_PORT:-3200}/api/v2/search/tag/.service.name/values" \
		| python3 -c "import sys,json; v=json.load(sys.stdin).get('tagValues',[]); \
print('\n'.join('  '+x['value'] for x in v) if v else '  (no traces received yet)')" \
		2>/dev/null || echo "  (Tempo unreachable on $${TEMPO_PORT:-3200})"

.PHONY: urls
urls: ## Print every local endpoint
	@echo "-- go services"
	@echo "  API (grpc+http/json) http://localhost:$${API_PORT:-8090}"
	@echo "  Liveness             http://localhost:$${API_PORT:-8090}/healthz"
	@echo "  Readiness            http://localhost:$${API_PORT:-8090}/readyz"
	@echo "-- api documentation  (make docs-serve)"
	@echo "  Reference (Scalar)   http://localhost:$${DOCS_PORT:-8091}/reference"
	@echo "  Index                http://localhost:$${DOCS_PORT:-8091}/"
	@echo "  OpenAPI spec         http://localhost:$${DOCS_PORT:-8091}/openapi.yaml"
	@echo "  gRPC descriptor set  http://localhost:$${DOCS_PORT:-8091}/descriptor.binpb"
	@echo "  Proto sources        http://localhost:$${DOCS_PORT:-8091}/proto/"
	@echo "  Error catalogue      http://localhost:$${DOCS_PORT:-8091}/errors.md"
	@echo "  gRPC console         http://localhost:$${GRPCUI_PORT:-8092}   (make grpc-ui)"
	@echo "-- web UIs"
	@echo "  Grafana              http://localhost:$${GRAFANA_PORT:-3001}"
	@echo "  Prometheus           http://localhost:$${PROMETHEUS_PORT:-9090}"
	@echo "  Temporal UI          http://localhost:$${TEMPORAL_UI_PORT:-8233}"
	@echo "  Centrifugo Admin     http://localhost:$${CENTRIFUGO_PORT:-8000}"
	@echo "  Mailpit UI           http://localhost:$${MAILPIT_UI_PORT:-8025}"
	@echo "  SeaweedFS Filer      http://localhost:$${SEAWEEDFS_FILER_PORT:-8888}"
	@echo "  SeaweedFS Master     http://localhost:$${SEAWEEDFS_MASTER_PORT:-9333}"
	@echo "  KurrentDB (cluster)  http://localhost:$${KURRENTDB_PORT:-2113}/ui/cluster  [thin; use Navigator]"
	@echo "-- gRPC"
	@echo "  KurrentDB            kurrentdb://localhost:$${KURRENTDB_PORT:-2113}?tls=false"
	@echo "  OpenFGA              localhost:$${OPENFGA_GRPC_PORT:-8081}"
	@echo "  Temporal             localhost:$${TEMPORAL_PORT:-7233}"
	@echo "  Centrifugo           localhost:$${CENTRIFUGO_GRPC_PORT:-10000}"
	@echo "  SeaweedFS master     localhost:$${SEAWEEDFS_MASTER_GRPC_PORT:-19333}"
	@echo "  SeaweedFS filer      localhost:$${SEAWEEDFS_FILER_GRPC_PORT:-18888}"
	@echo "  SeaweedFS s3         localhost:$${SEAWEEDFS_S3_GRPC_PORT:-18333}"
	@echo "-- HTTP / wire"
	@echo "  OpenFGA HTTP API     http://localhost:$${OPENFGA_HTTP_PORT:-8080}"
	@echo "  SeaweedFS S3         http://localhost:$${SEAWEEDFS_S3_PORT:-8333}"
	@echo "  PostgreSQL           localhost:$${POSTGRES_PORT:-5432}"
	@echo "  Valkey               localhost:$${VALKEY_PORT:-6379}"
	@echo "  Mailpit SMTP         localhost:$${MAILPIT_SMTP_PORT:-1025}"
	@echo "-- metrics (/metrics)"
	@echo "  kurrentdb   :$${KURRENTDB_PORT:-2113}   openfga  :$${OPENFGA_METRICS_PORT:-2112}   centrifugo :$${CENTRIFUGO_PORT:-8000}"
	@echo "  temporal    :$${TEMPORAL_METRICS_PORT:-9091}   seaweedfs:$${SEAWEEDFS_METRICS_PORT:-9327}   mailpit    :$${MAILPIT_UI_PORT:-8025}"
	@echo "  postgres    :$${POSTGRES_EXPORTER_PORT:-9187}   valkey   :$${VALKEY_EXPORTER_PORT:-9121}"

.PHONY: targets
targets: ## Show Prometheus scrape target health
	@curl -s http://localhost:$${PROMETHEUS_PORT:-9090}/api/v1/targets \
		| python3 -c "import sys,json;[print(f\"  {t['health']:8s} {t['labels']['job']:20s} {t['scrapeUrl']}\") for t in sorted(json.load(sys.stdin)['data']['activeTargets'], key=lambda x: x['labels']['job'])]"
