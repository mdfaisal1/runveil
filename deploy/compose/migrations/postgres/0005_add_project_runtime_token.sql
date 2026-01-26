-- +goose Up
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS runtime_token UUID;

-- Give every existing project a token
UPDATE projects
SET runtime_token = gen_random_uuid()
WHERE runtime_token IS NULL;

-- Make it required for new rows
ALTER TABLE projects
  ALTER COLUMN runtime_token SET NOT NULL,
  ALTER COLUMN runtime_token SET DEFAULT gen_random_uuid();

-- +goose Down
ALTER TABLE projects
  DROP COLUMN IF EXISTS runtime_token;
