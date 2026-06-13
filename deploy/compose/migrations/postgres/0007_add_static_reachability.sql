-- +goose Up
-- Static reachability from the scan (before any runtime evidence):
--   is_dev    = vulnerable package is dev-only (npm "dev"/"devOptional") → dormant
--   is_direct = listed directly in the project's dependencies
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS is_dev    BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS is_direct BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE findings
  DROP COLUMN IF EXISTS is_dev,
  DROP COLUMN IF EXISTS is_direct;
