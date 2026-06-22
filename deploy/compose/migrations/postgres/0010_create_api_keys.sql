-- +goose Up
-- API keys for authenticating non-browser clients (CLI, CI) against the API.
--
-- Keys are minted by `runveil keys create` and shown to the operator exactly
-- once. We never store the plaintext: key_hash is the SHA-256 of the full key
-- ("rv_<base64url>"), and key_prefix is the first few chars for display only.
--
-- This is intentionally separate from projects.runtime_token (which the Rust
-- agent uses): folding the two together would be migration risk for no v1 gain.
--
-- scope is stored now (cheap to add, painful later) but only minimally
-- enforced in v1 — the one locked route is scans/ingest.
CREATE TABLE IF NOT EXISTS api_keys (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id   UUID REFERENCES projects(id) ON DELETE CASCADE, -- NULL = not scoped to one project
  name         TEXT,                                           -- human label, e.g. "ci-github"
  key_hash     TEXT NOT NULL UNIQUE,                           -- sha256(plaintext), hex
  key_prefix   TEXT NOT NULL,                                  -- e.g. "rv_AbC3" for display
  scope        TEXT NOT NULL DEFAULT 'ingest',                 -- 'ingest' | 'read' | 'admin'
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_project ON api_keys(project_id);

-- +goose Down
DROP TABLE IF EXISTS api_keys;
