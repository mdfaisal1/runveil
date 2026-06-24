-- +goose Up
-- Append-only audit log of security-relevant actions, scoped per organization.
--
-- Append-only is enforced by convention in v1: the API exposes no update/delete
-- for these rows. (DB-level REVOKE UPDATE,DELETE / triggers is the hardened
-- version and a known follow-up.) Every row belongs to an org — events that
-- can't be attributed to one (e.g. failed logins for unknown emails) are NOT
-- recorded here; they go to app logs only.
--
-- actor_label is a snapshot (email at event time, "api-key:<prefix>", or
-- "system") so the trail stays readable even after a user is renamed/deleted.
CREATE TABLE IF NOT EXISTS audit_log (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,  -- NULL for api-key/system actors
  actor_label   TEXT NOT NULL,
  action        TEXT NOT NULL,                                 -- e.g. "member.role_changed"
  target        TEXT,                                          -- subject: email / slug / etc.
  metadata      JSONB,                                         -- extra detail (from/to role, etc.)
  ip            TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_log(org_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS audit_log;
