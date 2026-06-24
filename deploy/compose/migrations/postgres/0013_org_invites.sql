-- +goose Up
-- Invites let an admin add a teammate who doesn't have an account yet. Existing
-- users are added to org_members directly; unknown emails get a tokenized invite
-- that's redeemed at signup (joining this org instead of creating a new one).
--
-- The granted role lives on the invite row and is applied at redemption — never
-- taken from the redeeming request body.
CREATE TABLE IF NOT EXISTS org_invites (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member','viewer')),
  token_hash  TEXT NOT NULL UNIQUE,
  invited_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_org_invites_org ON org_invites(org_id);
-- At most one pending invite per email per org.
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invites_pending
  ON org_invites (org_id, lower(email)) WHERE accepted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS org_invites;
