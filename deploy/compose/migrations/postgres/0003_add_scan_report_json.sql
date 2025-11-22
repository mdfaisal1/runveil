-- +goose Up
ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS report_json JSONB;

-- +goose Down
ALTER TABLE scans
  DROP COLUMN IF EXISTS report_json;
