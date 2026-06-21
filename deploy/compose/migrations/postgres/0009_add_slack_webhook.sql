-- +goose Up
-- Per-project Slack Incoming Webhook URL. When set, Runveil posts a message when
-- a NEW reachable HIGH/CRITICAL finding appears for the project.
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT;

-- +goose Down
ALTER TABLE projects
  DROP COLUMN IF EXISTS slack_webhook_url;
