-- +goose Up
-- Harden audit_log into a true append-only, lifecycle-independent record.
--
-- 1) Drop the org/user foreign keys. An audit trail must SURVIVE deletion of the
--    thing it logs — if deleting an org cascaded away its audit rows, we'd erase
--    the very evidence the log exists to keep. actor_label already snapshots the
--    actor, so the columns stay as plain UUIDs (no referential coupling). This
--    also means deleting an org/user no longer touches audit_log, so the
--    UPDATE/DELETE-blocking trigger below can't break those cascades.
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_org_id_fkey;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_actor_user_id_fkey;

-- 2) Block UPDATE and DELETE at the database, so even direct SQL can't rewrite or
--    erase history. INSERT remains allowed.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only (% is not permitted)', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS audit_log_no_mutate ON audit_log;
CREATE TRIGGER audit_log_no_mutate
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- +goose Down
-- Reverting only removes the immutability guard. The lifecycle FKs are
-- intentionally NOT restored: re-adding them could fail on rows whose org/user
-- has since been deleted, and would reintroduce the cascade-erases-audit hole.
DROP TRIGGER IF EXISTS audit_log_no_mutate ON audit_log;
DROP FUNCTION IF EXISTS audit_log_immutable();
