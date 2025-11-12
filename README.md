# Runveil

> **Motto:** *See the risk. Fix the risk. Ship with confidence.*

Runveil is a developer‑first risk graph for your code and supply chain. It ingests scans/SBOMs, normalizes them in Postgres, projects relationships in Neo4j, and exposes a clean API/CLI for “what to fix next”.

---

## What it is (at a glance)
- **API (Go)** – REST (Gin) for ingest/read.
- **CLI (Go)** – `doctor`, `migrate`, ingest helpers.
- **Agent (Rust)** – performance‑critical parsers & SBOM helpers (optional, used for high‑throughput ingestion and future on‑host sensors).
- **Datastores** – PostgreSQL 16 (truth), Neo4j 5 (relationships).
- **Messaging** – NATS in dev → **Kafka** in prod.
- **One command dev** – `docker compose up -d`.

---

## Architecture (short)
```
CLI (Go) ──> API (Go) ──writes──> Postgres
                       └─events──> NATS/Kafka ──> Rust Agent (normalize/parse) ──> Postgres + Neo4j
                                                          Neo4j <── graph build / queries
```
Tables today: `projects`, `packages`, `findings`, `scans`, `vulnerabilities` (+ `goose_db_version`).

---

## Tech
| Layer | Primary | Notes |
|---|---|---|
| API/CLI | Go 1.25+ | Gin, stdlib, Goose for SQL migrations |
| Agent | **Rust 1.79+** | Async (Tokio), `serde`/`reqwest`; compiled binary used by API for heavy parsing (SBOM, OSV, lockfiles) |
| DB | PostgreSQL 16 | Source of truth |
| Graph | Neo4j 5 | Impact/radius queries |
| Bus | NATS (dev) | Kafka planned for scale |

---

## Current status
- ✅ Workspace set up (`go.work`), compose for Postgres/Neo4j/NATS
- ✅ Migrations: `0001_init.sql`, `0002_core_scan_model.sql`
- ✅ API `/health`, ingest route scaffold
- ✅ CLI `migrate up`, `doctor`
- 🛠️ Rust agent: parsers & SBOM helpers in progress
- 🔜 Graph build + reachability queries
- 🔜 UI/Dashboard + CI integrations

---

## Local development (2 minutes)

### 1) Infra
```bash
# Windows (cmd)
set COMPOSE_PROJECT_NAME=runveil && cd deploy\compose && docker compose up -d

# macOS/Linux
export COMPOSE_PROJECT_NAME=runveil && cd deploy/compose && docker compose up -d
```

### 2) DB & checks (CLI – Go)
```bash
# from repo root
go build -o runveil ./cli

# Windows
set RUNTIME_NET=host
set POSTGRES_URL=postgres://runveil:runveil@localhost:5432/runveil?sslmode=disable
set NEO4J_URL=bolt://localhost:7687
set NATS_URL=nats://localhost:4222
.
unveil migrate up && .
unveil doctor

# macOS/Linux
export RUNTIME_NET=host POSTGRES_URL=postgres://runveil:runveil@localhost:5432/runveil?sslmode=disable NEO4J_URL=bolt://localhost:7687 NATS_URL=nats://localhost:4222
./runveil migrate up && ./runveil doctor
```

### 3) API (Go)
```bash
# Windows
cd services\api && go build -o runveil-api.exe && .
unveil-api.exe
# macOS/Linux
cd services/api && go build -o runveil-api && ./runveil-api

# Check
curl http://localhost:8080/health   # {"ok":true}
```

### 4) Agent (Rust) *(optional)*
```
# Windows (PowerShell)
cd agent
rustup toolchain install stable
cargo build --release

# binary will be used by API for heavy parsing tasks
```

**Defaults**
- DB: `runveil:runveil@localhost:5432/runveil`
- Neo4j: `bolt://localhost:7687` (`neo4j` / `runveil`)
- Bus: `nats://localhost:4222` (Kafka later)
- Admin (local): `runveil_admin`

---

## Why Runveil (short)
- **Graph‑native** risk views → understand blast radius.
- **Fast & local** → minimal deps, quick CLI.
- **Open & composable** → Go + Rust, SQL you can read.
- **Incremental** → start with ingest; add graph, CI gates later.

---

## Roadmap (high level)
- **Ingest**: OSV/CVE, SBOM (CycloneDX), lockfiles (npm/go/pip).
- **Graph**: build pipeline & reachability queries in Neo4j.
- **Prioritization**: exploitability + business context.
- **CI/CD**: PR comments/gates; notifications/webhooks.
- **Messaging**: switch to **Kafka** for prod scale.
- **UI**: dashboard + team workflow.

---

## License
Apache-2.0 (see [LICENSE](./LICENSE)).
