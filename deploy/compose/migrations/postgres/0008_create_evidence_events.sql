-- +goose Up
-- Individual runtime evidence observations (the per-event log behind the
-- denormalized counters on findings). One row per observed package per observe call.
CREATE TABLE IF NOT EXISTS evidence_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id      UUID REFERENCES findings(id) ON DELETE CASCADE,  -- nullable: raw events
  package_name    TEXT NOT NULL,
  package_version TEXT NOT NULL,
  environment     TEXT,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata        JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_events_finding ON evidence_events (finding_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_events_project ON evidence_events (project_id, occurred_at DESC);

-- +goose Down
DROP TABLE IF EXISTS evidence_events;
