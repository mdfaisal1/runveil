# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### CLI (Go)
```bash
go build -o runveil ./cmd/runveil  # Build CLI binary
go run ./cmd/runveil scan --help   # Run CLI directly
go install github.com/mdfaisal1/runveil/cmd/runveil@latest  # Install from source
```

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
```bash
cd deploy/compose && docker compose up -d    # Start Postgres, Neo4j, NATS
```

### Database Migrations (Goose, via CLI)
```bash
runveil migrate up                 # Apply all pending migrations
runveil migrate status             # Check migration state
```

## Architecture

Runveil is a **vulnerability scanning and tracking platform** with four distinct components:

### CLI (`/cli`)
Cobra-based CLI that scans `package-lock.json` files against the [OSV API](https://osv.dev/). Key commands: `scan`, `findings`, `doctor` (connectivity check), `migrate`. Scan results can be output as JSON/Markdown or posted to the API. Supports policy gating via `--fail-on critical|high|medium|low`.

### API Service (`/services/api`)
Gin HTTP server on `:8080`. Handlers are flat files at the package root — `ingest.go`, `findings.go`, `projects.go`, `runtime.go`. Key routes:
- `POST /v1/projects/:slug/ingest` — receive scan results from CLI
- `POST /v1/projects/:slug/runtime/observe` — receive runtime observations from agent
- `GET /v1/projects/:slug/findings` — query stored findings
Requires `POSTGRES_URL` env var. Shared infra lives in `/pkg/infra`.

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
