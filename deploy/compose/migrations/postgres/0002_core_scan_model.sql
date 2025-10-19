-- +goose Up
-- Core schema for storing scan results

-- A scan run for a project (one CLI invocation / pipeline job)
CREATE TABLE IF NOT EXISTS scans (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status       TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  source       TEXT,                       -- e.g., "cli", "github-action", "gitlab-ci"
  lockfile_path TEXT,                      -- optional: path of scanned lockfile
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_project_started
  ON scans(project_id, started_at DESC);

-- Packages detected in a given scan
CREATE TABLE IF NOT EXISTS packages (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id    UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ecosystem  TEXT NOT NULL,                -- npm, pypi, maven, cargo, etc.
  name       TEXT NOT NULL,
  version    TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (scan_id, ecosystem, name, version)
);

CREATE INDEX IF NOT EXISTS idx_packages_scan ON packages(scan_id);

-- Canonical vulnerability record (dedup across scans)
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source       TEXT NOT NULL,              -- "osv", "nvd"
  vuln_id      TEXT NOT NULL,              -- e.g., "GHSA-xxxx", "CVE-2024-xxxx", "OSV-2024-xxxx"
  summary      TEXT,
  severity     TEXT,                       -- store normalized (e.g., "LOW|MEDIUM|HIGH|CRITICAL") or CVSS vector separately later
  published_at TIMESTAMPTZ,
  modified_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_vuln_id ON vulnerabilities(vuln_id);

-- Join: which package instances are affected by which vulnerability, plus reachability
CREATE TABLE IF NOT EXISTS findings (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  package_id       UUID NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
  vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  reachable        BOOLEAN NOT NULL DEFAULT false,   -- set by runtime agent later
  fixed_version    TEXT,                             -- suggested fix (if any)
  introduced_via   TEXT,                             -- optional: path/dep tree info
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (package_id, vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_pkg ON findings(package_id);
CREATE INDEX IF NOT EXISTS idx_findings_vuln ON findings(vulnerability_id);

-- +goose Down
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS packages;
DROP TABLE IF EXISTS scans;
