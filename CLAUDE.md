# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### CLI (Go)
```bash
go build -o runveil ./cmd/runveil  # Build CLI binary
go run ./cmd/runveil scan --help   # Run CLI directly
go run ./cmd/runveil version       # Print version + build metadata
go install github.com/mdfaisal1/runveil/cmd/runveil@latest  # Install from source
```

Version/commit/date are injected via ldflags into `cli/cmd` package vars (see
`version.go`); a plain build reports `dev`.

### API Service (Go)
```bash
go run ./services/api              # Start API on :8080 (from repo root)
```

### Dashboard (Angular) — from `dashboard/runveil-dashboard/`
```bash
npm start                          # Dev server with proxy to localhost:8080
npm run build                      # Production build → dist/runveil-dashboard
npm test                           # Run unit tests (Karma)
```

### Agent (Rust) — from `agent/runveil-agent/`
```bash
cargo build --release
```

### Local Infrastructure
**Postgres is host-installed, NOT Docker.** Runveil connects to your system
PostgreSQL on `localhost:5432` (no Docker PG dependency). One-time setup:
```bash
# As a Postgres superuser (psql):
CREATE USER runveil WITH PASSWORD 'runveil';
CREATE DATABASE runveil OWNER runveil;
# then apply migrations:
runveil migrate up
```
Docker Compose only brings up the auxiliary infra:
```bash
cd deploy/compose && docker compose up -d    # Start Neo4j + NATS (no Postgres)
```

### Docker Images (production)
```bash
# API — build context is the REPO ROOT (single Go module):
docker build -f services/api/Dockerfile -t runveil-api .
# Reaches host Postgres via host.docker.internal (RUNTIME_NET=internal):
docker run --rm -p 8080:8080 -e RUNTIME_NET=internal \
  -e PG_URL_INTERNAL='postgres://runveil:runveil@host.docker.internal:5432/runveil?sslmode=disable' \
  runveil-api

# UI — Angular build served by nginx; proxies /v1 + /health to API_UPSTREAM:
docker build -t runveil-ui dashboard/runveil-dashboard
docker run --rm -p 4200:80 -e API_UPSTREAM=http://host.docker.internal:8080 runveil-ui
```
On Linux add `--add-host=host.docker.internal:host-gateway` to the `run` commands.

### Database Migrations (Goose, via CLI)
```bash
runveil migrate up                 # Apply all pending migrations
runveil migrate status             # Check migration state
```

### API Keys (Goose-style direct-to-Postgres, via CLI)
```bash
runveil keys create --project <slug> --name ci-github   # Mint a key (printed once)
```

## Architecture

Runveil is a **vulnerability scanning and tracking platform** with four distinct components:

### CLI (`/cli`)
Cobra-based CLI that scans `package-lock.json` files against the [OSV API](https://osv.dev/). Key commands: `scan`, `findings`, `evidence` (runtime-evidence summary for a finding), `doctor` (connectivity check), `migrate`, `keys`, `version`. Scan results can be output as JSON/Markdown or posted to the API. Supports policy gating via `--fail-on critical|high|medium|low`. When posting to the API, the CLI sends `Authorization: Bearer $RUNVEIL_API_TOKEN`.

### API Service (`/services/api`)
Gin HTTP server on `:8080`. Handlers are flat files at the package root — `ingest.go`, `findings.go`, `projects.go`, `runtime.go`, `auth.go`, `hotspots.go`, `evidence.go`, `notifications.go`, `risk.go`. Key routes:
- `POST /v1/projects/:slug/scans/ingest` — receive scan results from CLI **(requires API key)**
- `POST /v1/projects/:slug/runtime/observe` — receive runtime observations from agent (requires `X-Runveil-Token`)
- `GET /v1/projects/:slug/findings` — query stored findings
- `GET /v1/projects/:slug/hotspots` — risk-ranked findings (latest scan)
Requires `POSTGRES_URL` env var. Shared infra lives in `/pkg/infra`.

**Authentication (v1).** Two independent credential paths:
- **API keys** (`api_keys` table, migration 0010) — minted by `runveil keys create`, SHA-256-hashed at rest, `rv_`-prefixed. The `requireAPIKey` middleware in `auth.go` guards **only `scans/ingest`** (the CLI-only, data-integrity-critical route). Read endpoints, `PUT settings`, and project-create are **intentionally still open** — the Angular dashboard is a browser client with no credential and only issues GETs. Locking those is a follow-on that requires the dashboard to ship a credential.
- **Runtime token** (`projects.runtime_token`) — separate, used only by the Rust agent on `runtime/observe`. Deliberately not folded into `api_keys`.

### Dashboard (`/dashboard/runveil-dashboard`)
Angular 19 standalone app. Routes: `/projects` → `/projects/:slug` → `/projects/:slug/findings`. API calls go through the proxy configured in `proxy.conf.json` (→ `http://localhost:8080`). Uses TailwindCSS for styling. Angular services in `src/app/core/`.

### Runtime Agent (`/agent/runveil-agent`)
Rust binary that reads a JSON file of observed packages and posts them to the API's `/runtime/observe` endpoint. Requires `--project-slug`, `--api-base`, `--runtime-token`, `--packages-file` flags.

### Shared Packages (`/pkg`)
- `pkg/infra` — config parsing from env vars, PostgreSQL connection (`db.go`), OSV HTTP client (`osvclient.go`), Neo4j and NATS connectors
- `pkg/kv1` — event handling primitives

### Infrastructure (`/deploy/compose`)
Docker Compose brings up PostgreSQL 16, Neo4j 5.23, and NATS 2.10. SQL migrations (Goose format) live in `deploy/compose/migrations/postgres/`. Dev connection strings are in `.env.development` at the repo root.

## Go Workspace

The repo is a **single Go module** (`github.com/mdfaisal1/runveil`) rooted at the repo root. The CLI entrypoint is `./cmd/runveil`, cobra commands live in `./cli/cmd`, shared infra in `./pkg`, and the API in `./services/api`. Run `go build ./...` / `go test ./...` from the repo root.
