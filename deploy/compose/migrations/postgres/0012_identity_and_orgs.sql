-- +goose Up
-- Phase 4 foundation: identity (users), multi-tenancy (organizations), membership
-- with roles (RBAC), and browser sessions. Projects and API keys are scoped to an
-- organization. Existing data is backfilled into a single "default" org so nothing
-- breaks during the transition.

CREATE TABLE IF NOT EXISTS organizations (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL,
  name          TEXT NOT NULL DEFAULT '',
  password_hash TEXT,                        -- NULL for SSO-only accounts
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Case-insensitive unique email (we lowercase at the app layer too).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));

-- Membership + role. RBAC roles ranked owner > admin > member > viewer.
CREATE TABLE IF NOT EXISTS org_members (
  org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','member','viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);

-- Browser sessions. token_hash is sha256(cookie value); plaintext is never stored.
-- org_id is the session's *current* org (a user may belong to several).
CREATE TABLE IF NOT EXISTS sessions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash   TEXT NOT NULL UNIQUE,
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id       UUID REFERENCES organizations(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Tenancy: projects and api_keys belong to an org.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill: everything that exists today belongs to the default org.
INSERT INTO organizations (slug, name) VALUES ('default', 'Default Organization')
  ON CONFLICT (slug) DO NOTHING;
UPDATE projects  SET org_id = (SELECT id FROM organizations WHERE slug = 'default') WHERE org_id IS NULL;
UPDATE api_keys  SET org_id = (SELECT id FROM organizations WHERE slug = 'default') WHERE org_id IS NULL;

-- Now that every project has an org, make it mandatory.
ALTER TABLE projects ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);

-- +goose Down
DROP INDEX IF EXISTS idx_api_keys_org;
DROP INDEX IF EXISTS idx_projects_org;
ALTER TABLE api_keys DROP COLUMN IF EXISTS org_id;
ALTER TABLE projects DROP COLUMN IF EXISTS org_id;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS org_members;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;
