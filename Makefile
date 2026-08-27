SHELL := /bin/bash
COMPOSE := docker compose

## ---------------------------------------------------------------------------
## Build identity and release channel (docs/VERSIONING.md)
## ---------------------------------------------------------------------------

# The version is the git tag, and nothing else is allowed to disagree with it.
# `--always` keeps an untagged checkout answerable, `--dirty` refuses to let a
# build made from uncommitted code claim to be the release it was cut from.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)

# One symbol, stamped once, read by every binary in ./cmd/... — see
# internal/platform/buildinfo for why this is not three per-main variables.
BUILDINFO := github.com/chronos/chronos-go/internal/platform/buildinfo
LDFLAGS   := -X $(BUILDINFO).version=$(VERSION) -X $(BUILDINFO).commit=$(COMMIT)

# Pinned at the invocation, so there is no install step and no version that
# depends on what a machine happens to have on its PATH.
CHANGIE := go run github.com/miniscruff/changie@v1.26.0

# Chronos is an UNSTABLE ALPHA. Every release carries a prerelease marker, so a
# bare v0.2.0 cannot be cut by accident and nothing downstream can mistake a
# build for a supported one. Semver puts v0.2.0-alpha below v0.2.0, and below
# v0.2.0-alpha.1 — verified against golang.org/x/mod/semver, because `sort -V`
# orders it the other way and agreeing with `sort -V` here would be wrong.
#
# It is a CHANNEL LABEL, not a counter. The base version already moves every
# release — the fragment kinds decide it — so v0.2.0-alpha, v0.3.0-alpha,
# v0.4.0-alpha. A counter that incremented alongside a moving base would mean
# nothing. Use PRERELEASE=alpha.2 only to re-cut the SAME base version.
#
# Emptying this default is the deliberate act of declaring the product beta or
# stable. It is not a cleanup. See docs/VERSIONING.md §3.
PRERELEASE ?= alpha
PRERELEASE_FLAG := $(if $(PRERELEASE),-p $(PRERELEASE),)

# `auto` derives the bump from the fragment kinds, which is what almost every
# release wants. Override it for a release whose number is a decision rather
# than a consequence — the FIRST one especially: with no prior version a lone
# `Fixed` fragment computes v0.0.1, and `make release BUMP=v0.1.0` says what was
# meant instead.
BUMP ?= auto

.DEFAULT_GOAL := help

## ---------------------------------------------------------------------------
## Infrastructure
## ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

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
	@# The baseline is SELECTED first, and buf then runs exactly once, unguarded.
	@#
	@# The previous form was a `||` chain ending in `echo`, which made this recipe
	@# incapable of failing: buf's non-zero exit fell through to the echo, the echo
	@# succeeded, and `make check` reported success on a breaking change. `2>/dev/null`
	@# hid the diagnosis on the way past. Verified by renaming a message that exists
	@# in the baseline — buf printed the error, the recipe printed "(no baseline yet)",
	@# and make exited 0.
	@#
	@# "no baseline" and "breaking change detected" are different answers and must not
	@# share an exit code. Only the first is benign.
	@if git rev-parse --verify --quiet main >/dev/null 2>&1; then \
		buf breaking --against '.git#branch=main,subdir=.'; \
	elif git rev-parse --verify --quiet HEAD~1 >/dev/null 2>&1; then \
		buf breaking --against '.git#ref=HEAD~1,subdir=.'; \
	else \
		echo "  (no baseline yet — first commit)"; \
	fi

.PHONY: api-docs
api-docs: ## Generate the REST/OpenAPI reference and the error catalogue
	@# gendocs FIRST: it writes docs/api/openapi.errors.yaml, which the OpenAPI
	@# run below merges in as `override=`. Reversed, the spec publishes whatever
	@# reason enum the previous build left behind.
	@go run ./internal/tools/gendocs
	@# The INPUT is `proto`, not the workspace. The operator plane is a second buf
	@# module (proto-operator/) and must never reach the published REST reference:
	@# a document listing /chronos.operator.v1.OperatorService/… advertises the
	@# shape of the cross-tenant surface to every reader of our public API docs.
	@# TestTheOperatorPlaneIsNotInThePublishedSpec fails if this input is widened.
	@buf generate --template buf.gen.openapi.yaml proto
	@# fixopenapi LAST, and never by hand: it writes the properties protobuf
	@# cannot express — additionalProperties, $$ref annotations hoisted into allOf,
	@# the Connect protocol's own parameters, and the request-body examples it
	@# assembles from the field examples the .proto already declares. It is
	@# forbidden from inventing a bound on a chronos.* field, which is what keeps
	@# `make api-validate` measuring the schema rather than measuring this step.
	@go run ./internal/tools/fixopenapi
	@echo "  wrote docs/api/chronos-openapi.yaml"
	@$(MAKE) --no-print-directory docs-assets

.PHONY: docs-assets
docs-assets: ## Copy generated artifacts into the docs binary for embedding
	@mkdir -p cmd/apidocs/assets/proto
	@cp docs/api/chronos-openapi.yaml cmd/apidocs/assets/openapi.yaml
	@cp docs/api/errors.md cmd/apidocs/assets/
	@rsync -a --delete --include='*/' --include='*.proto' --exclude='*' proto/ cmd/apidocs/assets/proto/
	@echo "  embedded assets refreshed (cmd/apidocs/assets)"

.PHONY: run
run: ## Run the tenant API against the local stack
	@echo "  api        http://localhost:$${API_PORT:-8090}"
	@echo "  healthz    http://localhost:$${API_PORT:-8090}/healthz"
	@echo "  readyz     http://localhost:$${API_PORT:-8090}/readyz"
	@go run -ldflags "$(LDFLAGS)" ./cmd/api -addr :$${API_PORT:-8090}

.PHONY: dev-api dev-worker dev-projector
dev-api: ## Hot-reload cmd/api (air)
	@air -c .air/api.toml

dev-worker: ## Hot-reload cmd/worker (air)
	@air -c .air/worker.toml

dev-projector: ## Hot-reload cmd/projector (air)
	@air -c .air/projector.toml

.PHONY: projector
projector: ## Run the projector against the local stack
	@echo "  healthz    http://localhost:$${PROJECTOR_PORT:-8093}/healthz"
	@echo "  readyz     http://localhost:$${PROJECTOR_PORT:-8093}/readyz"
	@go run -ldflags "$(LDFLAGS)" ./cmd/projector -addr :$${PROJECTOR_PORT:-8093}

.PHONY: projector-list
projector-list: ## List every registered projection
	@go run -ldflags "$(LDFLAGS)" ./cmd/projector -list

.PHONY: projector-rebuild
projector-rebuild: ## Rebuild one projection from zero: make projector-rebuild NAME=identity_users
	@test -n "$(NAME)" || { echo "NAME is required, e.g. make projector-rebuild NAME=identity_users"; exit 1; }
	@go run -ldflags "$(LDFLAGS)" ./cmd/projector -rebuild $(NAME)

.PHONY: worker
worker: ## Run the reactors (email, push, workflows) against the local stack
	@echo "  healthz    http://localhost:$${WORKER_PORT:-8094}/healthz"
	@go run -ldflags "$(LDFLAGS)" ./cmd/worker -addr :$${WORKER_PORT:-8094}

.PHONY: worker-list
worker-list: ## List every registered reactor
	@go run -ldflags "$(LDFLAGS)" ./cmd/worker -list

.PHONY: worker-stats
worker-stats: ## Queue depth and parked count per reactor
	@go run -ldflags "$(LDFLAGS)" ./cmd/worker -stats

.PHONY: worker-replay
worker-replay: ## Return a reactor's parked events to the live queue: make worker-replay NAME=welcome_email
	@test -n "$(NAME)" || { echo "NAME is required, e.g. make worker-replay NAME=welcome_email"; exit 1; }
	@go run -ldflags "$(LDFLAGS)" ./cmd/worker -replay-parked $(NAME)

.PHONY: status
status-api: ## Call GetStatus over HTTP/JSON
	@go run ./internal/tools/obsprobe status

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
	@# Driven by the server's REFLECTION service, not by a generated descriptor
	@# set. Reflection is a runtime capability of cmd/api; the descriptor set was
	@# a documentation artifact, and the published documentation is REST only.
	@# Against a deployment with reflection disabled, generate from proto/ instead.
	@curl -sf http://localhost:$${API_PORT:-8090}/healthz >/dev/null 2>&1 \
		|| { echo "  cmd/api is not responding on :$${API_PORT:-8090} — start it with 'make run'"; exit 1; }
	@echo "  console  http://localhost:$${GRPCUI_PORT:-8092}"
	@echo "  target   localhost:$${API_PORT:-8090}  (via server reflection)"
	@if command -v grpcui >/dev/null; then \
		grpcui -plaintext -port $${GRPCUI_PORT:-8092} localhost:$${API_PORT:-8090}; \
	else \
		echo "  (grpcui not installed — running it with 'go run', first start is slow)"; \
		go run github.com/fullstorydev/grpcui/cmd/grpcui@latest -plaintext \
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
	go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

.PHONY: test
test: ## Run all tests
	go test ./... -race -count=1

.PHONY: bench
bench: ## Benchmarks with allocation reporting (ADR-038)
	go test ./... -run=XXX -bench=. -benchmem

## ---------------------------------------------------------------------------
## Versioning and the changelog (docs/VERSIONING.md)
## ---------------------------------------------------------------------------

.PHONY: version
version: ## Print the version, commit and release channel this tree would build as
	@echo "  version   $(VERSION)"
	@echo "  commit    $(COMMIT)"
	@next=$$($(CHANGIE) next $(BUMP) $(PRERELEASE_FLAG) 2>/dev/null) && echo "  next      $$next" || echo "  next      (no unreleased fragments)"
	@echo "  channel   $(if $(PRERELEASE),UNSTABLE — every release is tagged -$(PRERELEASE),STABLE — no prerelease marker)"

.PHONY: changelog-new
changelog-new: ## Describe a customer-visible change (interactive, or KIND= DOMAIN= BODY=)
	@if [ -n "$(BODY)" ]; then \
		test -n "$(KIND)"   || { echo "KIND is required, e.g. KIND=Added";       exit 1; }; \
		test -n "$(DOMAIN)" || { echo "DOMAIN is required, e.g. DOMAIN=billing"; exit 1; }; \
		$(CHANGIE) new -i=false -k "$(KIND)" -m "Domain=$(DOMAIN)" -b "$(BODY)"; \
	else \
		$(CHANGIE) new; \
	fi
	@$(MAKE) --no-print-directory changelog-check

.PHONY: changelog-check
changelog-check: ## Validate every unreleased fragment against .changie.yaml
	@go run ./internal/tools/checkchangelog

.PHONY: release-input
release-input: ## Every commit since the last tag, and what a customer can see in it
	@go run ./internal/tools/checkchangelog -list

.PHONY: changelog-preview
changelog-preview: ## Show the release notes the current fragments would produce
	@$(CHANGIE) batch $(BUMP) $(PRERELEASE_FLAG) --dry-run

.PHONY: release
release: ## Assemble the next release: CHANGELOG.md and .changes/vX.Y.Z.md. No commit, no tag.
	@# A release is assembled from COMMITTED code — except for the entries being
	@# written for this very release. The procedure writes those into
	@# .changes/unreleased/ minutes earlier (docs/VERSIONING.md §4), so a guard
	@# that refused them would refuse every release it exists to protect.
	@dirty=$$(git status --porcelain -- ':!.changes/unreleased'); \
	 test -z "$$dirty" || { \
		echo "the working tree is dirty; a release is assembled from committed code:"; \
		echo "$$dirty"; exit 1; }
	@go run ./internal/tools/checkchangelog -coverage
	@$(CHANGIE) batch $(BUMP) $(PRERELEASE_FLAG)
	@$(CHANGIE) merge
	@echo
	@echo "  assembled $$($(CHANGIE) latest)"
	@echo "  review    git diff"
	@echo "  then      make release-tag"

# The tag CARRIES the release notes, rather than pointing at a commit that
# happens to contain them. `git show <tag>`, `git tag -n99` and every UI that
# reads an annotation then answer "what is in this release?" without a checkout.
#
# --cleanup=verbatim is not optional here. `git tag -F` defaults to
# --cleanup=strip, which deletes every line beginning with '#' as a comment —
# and the notes are Markdown, so that silently ate `## v0.1.0-alpha.1` and
# `### Fixed` and left a tag annotated with one bare bullet.
.PHONY: release-tag
release-tag: ## Commit the assembled release and tag it, notes and all. Does NOT push.
	@v=$$($(CHANGIE) latest); \
	 test -n "$$v" || { echo "nothing assembled; run: make release"; exit 1; }; \
	 test -f ".changes/$$v.md" || { echo "no release notes at .changes/$$v.md"; exit 1; }; \
	 if git rev-parse --verify "$$v" >/dev/null 2>&1; then echo "$$v is already tagged"; exit 1; fi; \
	 git add CHANGELOG.md .changes && \
	 git commit -m "release: $$v" && \
	 git tag -a "$$v" --cleanup=verbatim -F ".changes/$$v.md" && \
	 echo "  tagged $$v — publish with: git push origin main --follow-tags"

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

.PHONY: operator
operator: ## Provision the FIRST operator, then run the back-office plane
	@echo "The operator plane needs an operator before anybody can sign in, and the"
	@echo "first one cannot be created through an RPC — every method on that plane"
	@echo "needs a session, and there is nobody to sign in as (ADR-024)."
	@echo ""
	@echo "  go run ./internal/tools/provisionoperator \\"
	@echo "      -email you@example.com \\"
	@echo "      -provider-subject <the IdP's sub for you> \\"
	@echo "      -role operator_admin"
	@echo ""
	@echo "Then start the plane. It REFUSES to start misconfigured rather than"
	@echo "degrading: see OPERATOR_* in .env.example for what it needs."
	@echo ""
	@echo "  go run ./cmd/operator"

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
	@set -a; [ -f .env ] && . ./.env; set +a; \
	go test -tags=integration ./... -run=XXX -bench=. -benchmem -benchtime=2000x

.PHONY: leaks
leaks: ## Goroutine-leak detection: Go 1.27's `goroutineleak` profile
	@# WHAT THIS USED TO RUN, AND WHY IT WAS A LIE
	@#
	@# Until Go 1.27 this target ran `-gcflags=all=-d=checkptr`. That is
	@# unsafe.Pointer arithmetic checking. It has never detected a goroutine
	@# leak, could not detect one in principle, and would have passed with every
	@# goroutine in the process stranded — while its name told anyone reading the
	@# Makefile that the codebase was checked for leaks. It now lives under
	@# `make checkptr`, where its name matches what it does; that check has real
	@# value, it is simply a different check.
	@#
	@# WHAT IT RUNS NOW
	@#
	@# Go 1.27 promoted the `goroutineleak` profile to general availability: it is
	@# in runtime/pprof, and the GOEXPERIMENT that gated it in 1.26 is deleted
	@# (`GOEXPERIMENT=goroutineleakprofile go env` now fails with "unknown
	@# GOEXPERIMENT", which is how to tell the two toolchains apart). It reports
	@# goroutines blocked on a concurrency primitive no live goroutine can reach
	@# again. internal/platform/obs.GoroutineLeaks collects it, and a TestMain in
	@# each package below fails the package when the count is non-zero.
	@#
	@# TWO LIMITS, STATED RATHER THAN HIDDEN
	@#
	@# 1. The profile is REACHABILITY-based, so it misses a goroutine parked on a
	@#    channel held by a package-level variable, or on one living in a runnable
	@#    goroutine's locals. Both are verified in obs/leak_test.go rather than
	@#    quoted from a release note. A clean run means "nothing is provably
	@#    stranded", never "nothing is stuck".
	@# 2. There is no `go test` flag for it, and the profile is process-global
	@#    while `go test ./...` gives every package its own process. So detection
	@#    is per-package opt-in via TestMain, and THE PACKAGES LISTED BELOW ARE
	@#    THE ONLY ONES CHECKED. Adding a package here without adding its TestMain
	@#    checks nothing and says nothing — which is the failure mode this target
	@#    is being repaired from, so do both or neither.
	CHRONOS_LEAKCHECK=1 go test -race -count=1 \
		./internal/server/connect/... \
		./cmd/api/...

.PHONY: checkptr
checkptr: ## unsafe.Pointer arithmetic checking (what `leaks` ran under the wrong name)
	@# Rebuilds every package with the checkptr instrumentation, so it is slow and
	@# deliberately not part of `make check`. It catches pointer arithmetic that
	@# produces an address outside the original allocation, and conversions
	@# through unsafe.Pointer that violate the unsafe.Pointer rules — real
	@# defects, none of them a goroutine leak.
	go test ./... -race -count=1 -gcflags=all=-d=checkptr

.PHONY: test-integration
test-integration: ## Integration tests against the running stack (make up first)
	@# .env is SOURCED, because these tests read credentials from the environment
	@# and half of them fail without it in a way that looks like a code defect:
	@# `failed SASL auth: FATAL: password authentication failed for user
	@# "chronos_app"`. The piivault and centrifugo suites read POSTGRES_APP_PASSWORD
	@# and the Centrifugo API key directly, while others build their own harness —
	@# so a bare `go test -tags=integration ./...` fails 13 tests in two packages
	@# while the rest pass, which reads as "those two packages are broken".
	@#
	@# Guarded on the file existing so this still runs in an environment that
	@# supplies the variables some other way (CI does).
	@#
	@# -timeout 20m matches CI. The identity suite alone is ~240s and growing, and
	@# go test's 10-minute default kills the binary with a bare "signal: terminated"
	@# and no failing test name, which reads as a crash rather than a timeout.
	@#
	@# -p 1 runs ONE package at a time, and it is not a performance knob. These
	@# suites share one database, one event store and one authorization graph, so
	@# the default (a package per core) has them contending for global state that
	@# is global on purpose: a projection rebuild takes a single-writer advisory
	@# lease, and a concurrent package taking the same lease fails with
	@# `cannot rebuild while another instance is running it` — a correct refusal,
	@# reported as a test failure. Reservation and idempotency suites collide the
	@# same way on rows keyed by address.
	@#
	@# The failures it produces are the worst kind: they name a real invariant,
	@# they pass on a re-run in isolation, and so they train people to re-run
	@# rather than read. Serialising is the honest fix; making the assertions
	@# tolerant would delete the invariant instead of the contention.
	@set -a; [ -f .env ] && . ./.env; set +a; \
	go test -tags=integration ./... -count=1 -timeout 20m -p 1

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
check: fmt-check proto-lint proto-breaking api-validate authz-check proto-thirdparty-check migrate-check sqlc-check sql-check changelog-check lint vet-integration test ## Everything CI runs

.PHONY: vet-integration
vet-integration: ## Type-check the integration-tagged tests without running them
	@# `go test`, `go build` and `golangci-lint` all skip files behind
	@# `//go:build integration`, so nothing in `make check` ever COMPILED them.
	@# A change to an interface therefore broke three integration files while every
	@# gate stayed green: a stub missing a new method, a test calling a use case
	@# whose signature had grown a field, and two fakes panicking on a call the
	@# flow had newly acquired. All three were invisible until someone happened to
	@# run the integration suite against live infrastructure.
	@#
	@# This compiles them and runs vet. It needs NO running stack — it never
	@# executes a test — so it belongs in the fast gate rather than beside
	@# `test-integration`.
	@go vet -tags=integration ./...
	@echo "  integration-tagged tests compile"

.PHONY: authz-model
authz-model: ## Render the authorization model from the module fragments
	@# The DEPLOYED model is built from the fragments directly; this artifact is
	@# what a reviewer reads before a model deploy, which access.md §10 calls the
	@# highest-blast-radius deploy in the system. A diff of Go struct literals
	@# spread across modules is not something anyone can judge.
	@go run ./internal/tools/genauthzmodel

.PHONY: authz-deploy
authz-deploy: ## Provision the OpenFGA store and deploy the model, printing the ids to pin
	@# NOT part of `make check` and never run by the server. A process that
	@# provisions its own authorization store answers every check against whatever
	@# store it just created — point it at the wrong endpoint and it makes an EMPTY
	@# one, then denies everything while reporting itself healthy.
	@#
	@# .env is sourced for OPENFGA_PRESHARED_KEY, the same way test-integration
	@# does, and guarded on the file existing so an environment that supplies the
	@# variables some other way still works.
	@set -a; [ -f .env ] && . ./.env; set +a; \
	go run ./internal/tools/deployauthzmodel

.PHONY: authz-check
authz-check: ## Fail if the rendered model has fallen behind the fragments
	@# Two copies of one fact drift, and this drift is silent in the worst
	@# direction: the file that gets REVIEWED stops describing the model that gets
	@# DEPLOYED. Same guard `api-validate` puts on the OpenAPI document.
	@go run ./internal/tools/genauthzmodel -check

.PHONY: api-validate
api-validate: ## Validate the generated OpenAPI spec is complete and non-empty
	@# A Go program: the YAML parser and the protobuf descriptors are compiled in,
	@# so there is no runtime to bootstrap and nothing that can skip. Its Python
	@# predecessor exited 0 whenever PyYAML was absent — which was everywhere it
	@# ran, CI included — so this gate passed for its entire life without once
	@# parsing the spec. That is how 20 operations shipped with no operationId.
	@go run ./internal/tools/checkopenapi

## ---------------------------------------------------------------------------
## Telemetry
## ---------------------------------------------------------------------------

.PHONY: dashboards
dashboards: ## Regenerate Grafana dashboards from internal/tools/gendashboards
	@go run ./internal/tools/gendashboards
	@echo "  (Grafana reloads provisioned dashboards within 30s)"

.PHONY: dashboards-check
dashboards-check: ## Run every dashboard query against live Prometheus
	@# Built rather than `go run`: the tool exits with the NUMBER of dead
	@# expressions, and `go run` collapses any non-zero child status to 1.
	@go build -o bin/checkdashboards ./internal/tools/checkdashboards && ./bin/checkdashboards

.PHONY: traces
traces: ## Show services currently reporting traces to Tempo
	@go run ./internal/tools/obsprobe traces

.PHONY: urls
urls: ## Print every local endpoint
	@echo "-- go services"
	@echo "  API (grpc+http/json) http://localhost:$${API_PORT:-8090}"
	@echo "  Liveness             http://localhost:$${API_PORT:-8090}/healthz"
	@echo "  Readiness            http://localhost:$${API_PORT:-8090}/readyz"
	@echo "  Operator plane       http://localhost:$${OPERATOR_PORT:-8095}   (cmd/operator; internal only)"
	@echo "-- api documentation  (make docs-serve)"
	@echo "  Reference (Scalar)   http://localhost:$${DOCS_PORT:-8091}/reference"
	@echo "  Index                http://localhost:$${DOCS_PORT:-8091}/"
	@echo "  OpenAPI spec         http://localhost:$${DOCS_PORT:-8091}/openapi.yaml"
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
	@go run ./internal/tools/obsprobe targets
