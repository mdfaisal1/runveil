-- +goose Up
-- Per-org OIDC SSO. Each org registers its IdP keyed by an email domain; login
-- maps domain -> provider -> org. A user's external identity (provider, subject)
-- links to a Runveil user; we only auto-link to an existing password account when
-- the IdP asserts email_verified for a matching email (anti-takeover).

CREATE TABLE IF NOT EXISTS oidc_providers (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain        TEXT NOT NULL,                       -- email domain, e.g. "acme.com"
  issuer        TEXT NOT NULL,                       -- OIDC issuer URL (discovery base)
  client_id     TEXT NOT NULL,
  client_secret TEXT NOT NULL,                       -- NOTE: plaintext in v1; encrypt/KMS in prod
  default_role  TEXT NOT NULL DEFAULT 'member' CHECK (default_role IN ('admin','member','viewer')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- A domain maps to exactly one provider/org globally.
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_providers_domain ON oidc_providers (lower(domain));
-- One provider per org (v1: a single IdP per org).
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_providers_org ON oidc_providers (org_id);

CREATE TABLE IF NOT EXISTS user_identities (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id UUID NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
  subject     TEXT NOT NULL,                         -- OIDC 'sub'
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);

-- Short-lived CSRF/nonce store for the authorization-code flow.
CREATE TABLE IF NOT EXISTS oidc_states (
  state       TEXT PRIMARY KEY,
  provider_id UUID NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
  nonce       TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS oidc_states;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS oidc_providers;
