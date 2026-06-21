<h1 align="center">Runveil</h1>

<p align="center"><strong>Security that sees what actually runs.</strong></p>

<p align="center">
Runtime-native vulnerability intelligence for Node.js. Runveil flags only the
vulnerabilities that are actually <em>reachable</em> in your code — so you fix the
short list that matters instead of drowning in <code>npm audit</code> noise.
</p>

---

## The problem

`npm audit`, Dependabot, and Snyk free flag every CVE in your dependency tree —
including the large majority that sit in **dev-only tooling** or code paths your app
never runs. Developers either chase ghosts or learn to ignore the scanner entirely.

Runveil prioritizes **reachable** risk over theoretical risk:

```text
npm audit:  187 issues   ─────►   Runveil:  6 reachable
```

It classifies every vulnerable package and pushes the dormant ones (dev-only build/test
tooling that never ships) out of the way, so the list you act on is the list that
actually affects production.

## What a scan looks like

![Runveil scanning a real Angular project: 3 reachable of 297, 98% noise reduced](website/demo.gif)

A real run against this repo's Angular dashboard — **968 packages, 65 vulnerability
findings, 3 reachable** (the rest dormant dev-only tooling that never ships):

```console
$ rv scan ./package-lock.json --fail-on high
🔎 Scanning 968 packages from: ./package-lock.json
! 65 vulnerabilities found across dependencies
REACHABLE FINDINGS (3 of 65)
  * @angular/compiler  HIGH  XSS in i18n attribute bindings
  * @angular/core      HIGH  XSS in i18n attribute bindings
  * @angular/core      HIGH  i18n Cross-Site Scripting

📊 3 reachable of 65 total  ·  62 dormant (dev-only) hidden  ·  95% noise reduced
⛔ policy: max reachable severity HIGH ≥ high → exit 3
```

> **How "reachable" is decided.** Runveil v1 uses static reachability from the
> lockfile: a finding is **reachable** when its package is part of your *production*
> dependency tree, and **dormant** when it is dev-only (npm's `dev` flag). Connect the
> [runtime agent](#runtime-agent-optional) and reachability is further confirmed by
> live evidence of what actually executes.

---

## Install

With a Go toolchain (1.23+):

```bash
go install github.com/mdfaisal1/runveil/cmd/runveil@latest
```

This puts a `runveil` binary in `$(go env GOPATH)/bin` — add that to your `PATH`, then:

```bash
runveil --help
```

<details>
<summary>Build from source (for contributors)</summary>

```bash
git clone https://github.com/mdfaisal1/runveil.git
cd runveil
go build -o runveil ./cmd/runveil   # Windows: go build -o runveil.exe ./cmd/runveil
```
</details>

## Quickstart

Scan any Node.js project's `package-lock.json` (npm lockfile v2/v3):

```bash
runveil scan path/to/package-lock.json
```

- `--format json|md` — output format (default `json`)
- `--out <file>` — write the report to a file instead of stdout

```bash
# A human-readable Markdown report, reachable issues first
runveil scan package-lock.json --format md --out runveil-report.md
```

Every report leads with the headline that matters — **X reachable of Y total** — and
lists reachable findings before dormant ones.

## Use it in CI

`--fail-on` gates the build on the **maximum reachable severity** — a wall of dormant
dev-only CVEs will *not* fail your pipeline:

```bash
runveil scan package-lock.json --fail-on high
```

Valid values: `none | low | medium | high | critical` (default `none`). The command
exits non-zero (code `3`) when a reachable finding meets or exceeds the threshold.

See [.github/workflows/runveil-scan.yml](.github/workflows/runveil-scan.yml) for a
copy-paste GitHub Action, and [docs/ci.md](docs/ci.md) for GitLab/Jenkins snippets.

## Commands

| Command | What it does |
| --- | --- |
| `runveil scan <lockfile>` | Scan a `package-lock.json`, classify reachable vs dormant |
| `runveil findings --project <slug>` | Fetch stored findings from the API (incl. runtime evidence) |
| `runveil migrate up\|status` | Apply / inspect database migrations |
| `runveil doctor` | Check connectivity to Postgres / Neo4j / NATS |

Run `runveil <command> --help` for full flag documentation.

---

## Hosted layer (optional)

The CLI is the product and runs entirely locally. An optional API + dashboard store
scan history, surface runtime evidence, and show reachable/dormant trends across a team.

### Local development

Bring up the backing services (Postgres, Neo4j, NATS):

```bash
cd deploy/compose
export COMPOSE_PROJECT_NAME=runveil   # Windows: set COMPOSE_PROJECT_NAME=runveil
docker compose up -d
```

Apply migrations and start the API:

```bash
runveil migrate up
export POSTGRES_URL="postgres://runveil:runveil@localhost:5432/runveil?sslmode=disable"
cd services/api && go run .          # serves on :8080
curl http://localhost:8080/health    # -> {"ok":true}
```

Post a scan to a project:

```bash
runveil scan path/to/package-lock.json --project my-service --post
```

The dashboard (Angular) lives in [dashboard/runveil-dashboard](dashboard/runveil-dashboard);
run `npm start` from that folder to develop against the local API.

### Runtime agent (optional)

The Rust agent in [agent/runveil-agent](agent/runveil-agent) reports packages observed
executing at runtime to `/v1/projects/:slug/runtime/observe`, upgrading findings to
confirmed-reachable with live evidence (`evidence_count`, `last_seen_at`).

---

## Architecture

```
CLI (Go)  ──scan──►  OSV API                 ┌─ Postgres (findings, evidence)
   │                                          │
   └──post──►  API (Go, :8080)  ──────────────┼─ Neo4j   (reachability graph — WIP)
                    ▲                          └─ NATS    (event plumbing)
                    │
  Runtime agent (Rust) ──runtime evidence──────┘     Dashboard (Angular) ──► API
```

See [CLAUDE.md](CLAUDE.md) for a fuller component breakdown.

## Status & roadmap

Runveil is in active development. The current focus (per the project roadmap) is making
the **free CLI's reachability undeniably useful** — the open-source on-ramp — before any
hosted/team features. Phases: static scanner ✅ → runtime intelligence (in progress) →
hotspots & risk scoring → team features.

## License

See [LICENSE](LICENSE).
