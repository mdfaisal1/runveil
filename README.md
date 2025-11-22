## Runveil CLI

The Runveil CLI scans a Node.js project (`package-lock.json`) for known vulnerabilities using OSV, and can optionally post the results to a Runveil API backend.

### Install / Build

```bash
# From repo root
go build -o runveil ./cli
```

On Windows, you can copy the binary somewhere on your PATH, for example:

```text
C:\tools\runveil\runveil.exe
```

and create a simple alias:

```bat
:: C:\tools\runveil\rv.bat
@echo off
runveil %*
```

Now you can use `rv` instead of `runveil`:

```bash
rv --help
```

---

### Start local infra (Postgres, Neo4j, NATS)

```bash
cd deploy/compose
export COMPOSE_PROJECT_NAME=runveil   # on Windows: set COMPOSE_PROJECT_NAME=runveil
docker compose up -d
```

Check services:

```bash
docker compose ps
```

You should see `runveil-postgres`, `runveil-neo4j`, `runveil-nats` running.

---

### Run database migrations

From repo root:

```bash
runveil migrate up
runveil migrate status
```

This applies all Goose migrations (including `0003_add_scan_report_json.sql`) to the `runveil` Postgres database.

---

### Connectivity check

```bash
runveil doctor
```

This verifies connectivity to:

- Postgres (`postgres://runveil:runveil@localhost:5432/runveil`)
- Neo4j (`bolt://localhost:7687`)
- NATS (`nats://localhost:4222`)

You should see a ✅ summary if all backends are reachable.

---

### Scan a Node.js project (local only)

From anywhere:

```bash
rv scan D:\path\to\project\package-lock.json --format md --out runveil-scan.md
```

or, in generic form:

```bash
runveil scan /path/to/package-lock.json --format md --out runveil-scan.md
```

- `--format md|json` (default `json`)
- `--out` writes to a file (otherwise prints to stdout)

The Markdown report includes:

- Total findings
- Max severity
- A table of packages, versions, vuln IDs and summaries.

---

### CI-style policy gating (`--fail-on`)

To fail the build if any vulnerability meets or exceeds a severity:

```bash
runveil scan package-lock.json --format json --fail-on low
```

Valid values: `none|low|medium|high|critical` (default `none`).

Example (GitHub Actions):

```yaml
- name: Run Runveil scan
  run: |
    go build -o runveil ./cli
    ./runveil scan package-lock.json --format json --fail-on high
```

If the maximum severity is `high` or `critical`, the command exits with a non-zero code and the pipeline fails.

---

### Run the API locally & post scan results

Start the API (from repo root):

```bash
# Configure Postgres URL
export POSTGRES_URL="postgres://runveil:runveil@localhost:5432/runveil?sslmode=disable"
# Windows (CMD): set POSTGRES_URL=...

cd services/api
go run .
```

Health check:

```bash
curl http://localhost:8080/health
# -> {"ok":true}
```

Now run a scan and post the result:

```bash
runveil scan path/to/package-lock.json \
  --format json \
  --project my-service \
  --post
```

This will:

- Create / update a `projects` row (`slug = my-service`)
- Insert a `scans` row with the JSON report in `report_json`

You should see:

```text
✅ Posted scan to Runveil API.
```
