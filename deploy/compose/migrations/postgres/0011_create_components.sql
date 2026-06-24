-- +goose Up
-- Components (a.k.a. services) model the parts of a project that are scanned
-- independently — e.g. each service/app/lib in a monorepo with its own lockfile.
--
-- These are *manifest-declared*: a component must be registered (via the API /
-- dashboard) before a scan can attach to it. A scan with no component_id is a
-- project-level scan (the pre-components behavior), so existing data is unaffected.
CREATE TABLE IF NOT EXISTS components (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key        TEXT NOT NULL,                       -- slug within the project, e.g. "api", "web"
  name       TEXT NOT NULL,                       -- human label, e.g. "Checkout API"
  kind       TEXT NOT NULL DEFAULT 'service',     -- 'service' | 'app' | 'library' | ...
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, key)
);

CREATE INDEX IF NOT EXISTS idx_components_project ON components(project_id);

-- A scan optionally belongs to one component. ON DELETE SET NULL so removing a
-- component reverts its scans to project-level rather than destroying history.
ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS component_id UUID REFERENCES components(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_scans_component ON scans(component_id);

-- +goose Down
ALTER TABLE scans DROP COLUMN IF EXISTS component_id;
DROP TABLE IF EXISTS components;
