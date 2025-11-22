-- +goose Up
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS first_seen_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_seen_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS evidence_count  BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE findings
  DROP COLUMN IF EXISTS first_seen_at,
  DROP COLUMN IF EXISTS last_seen_at,
  DROP COLUMN IF EXISTS evidence_count;
