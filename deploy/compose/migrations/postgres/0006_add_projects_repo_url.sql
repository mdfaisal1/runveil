-- +goose Up
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS repo_url TEXT;

-- +goose Down
ALTER TABLE projects
  DROP COLUMN IF EXISTS repo_url;