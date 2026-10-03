-- Explicit PostgreSQL-only migration. The caller pins and locks the resolved memory schema.
CREATE OR REPLACE FUNCTION prime_memory_guard_write_after_unsent_closure()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $prime_memory_guard$
DECLARE
  closed boolean;
BEGIN
  IF TG_LEVEL <> 'ROW' OR TG_WHEN <> 'BEFORE'
    OR TG_TABLE_NAME NOT IN ('prime_memory_intents', 'prime_memory_effects', 'prime_memory_replay_fences')
    OR TG_OP NOT IN ('INSERT', 'UPDATE') THEN
    RAISE EXCEPTION 'prime_memory_writer_guard_context_invalid';
  END IF;
  IF current_setting('session_replication_role') <> 'origin'
    OR current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'prime_memory_writer_guard_session_invalid';
  END IF;
  IF NEW.owner_subject IS NULL OR NEW.operation_id IS NULL THEN
    RAISE EXCEPTION 'prime_memory_writer_guard_binding_invalid';
  END IF;
  IF TG_OP = 'UPDATE' AND (OLD.owner_subject IS DISTINCT FROM NEW.owner_subject
    OR OLD.operation_id IS DISTINCT FROM NEW.operation_id) THEN
    RAISE EXCEPTION 'prime_memory_writer_guard_key_immutable';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.owner_subject, 0));
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.prime_memory_unsent_closures WHERE owner_subject=$1 AND operation_id=$2)', TG_TABLE_SCHEMA)
    INTO closed USING NEW.owner_subject, NEW.operation_id;
  IF closed THEN
    RAISE EXCEPTION 'prime_memory_writer_closed';
  END IF;
  RETURN NEW;
END;
$prime_memory_guard$;

CREATE OR REPLACE FUNCTION prime_memory_guard_unsent_closure_immutable()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $prime_memory_guard$
DECLARE
  occupied boolean;
BEGIN
  IF TG_LEVEL = 'STATEMENT' AND TG_WHEN = 'BEFORE'
    AND TG_TABLE_NAME = 'prime_memory_unsent_closures' AND TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'prime_memory_writer_closure_immutable';
  END IF;
  IF TG_LEVEL <> 'ROW' OR TG_WHEN <> 'BEFORE'
    OR TG_TABLE_NAME <> 'prime_memory_unsent_closures'
    OR TG_OP NOT IN ('INSERT', 'UPDATE', 'DELETE') THEN
    RAISE EXCEPTION 'prime_memory_closure_guard_context_invalid';
  END IF;
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'prime_memory_writer_closure_immutable';
  END IF;
  IF current_setting('session_replication_role') <> 'origin'
    OR current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'prime_memory_closure_guard_session_invalid';
  END IF;
  IF NEW.owner_subject IS NULL OR NEW.operation_id IS NULL THEN
    RAISE EXCEPTION 'prime_memory_closure_guard_binding_invalid';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.owner_subject, 0));
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2) OR EXISTS (SELECT 1 FROM %I.prime_memory_effects WHERE owner_subject=$1 AND operation_id=$2) OR EXISTS (SELECT 1 FROM %I.prime_memory_replay_fences WHERE owner_subject=$1 AND operation_id=$2)', TG_TABLE_SCHEMA, TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
    INTO occupied USING NEW.owner_subject, NEW.operation_id;
  IF occupied THEN
    RAISE EXCEPTION 'prime_memory_writer_closure_occupied';
  END IF;
  RETURN NEW;
END;
$prime_memory_guard$;

DROP TRIGGER IF EXISTS prime_memory_intents_unsent_guard ON prime_memory_intents;
CREATE TRIGGER prime_memory_intents_unsent_guard
  BEFORE INSERT OR UPDATE ON prime_memory_intents
  FOR EACH ROW EXECUTE FUNCTION prime_memory_guard_write_after_unsent_closure();
DROP TRIGGER IF EXISTS prime_memory_effects_unsent_guard ON prime_memory_effects;
CREATE TRIGGER prime_memory_effects_unsent_guard
  BEFORE INSERT OR UPDATE ON prime_memory_effects
  FOR EACH ROW EXECUTE FUNCTION prime_memory_guard_write_after_unsent_closure();
DROP TRIGGER IF EXISTS prime_memory_replay_fences_unsent_guard ON prime_memory_replay_fences;
CREATE TRIGGER prime_memory_replay_fences_unsent_guard
  BEFORE INSERT OR UPDATE ON prime_memory_replay_fences
  FOR EACH ROW EXECUTE FUNCTION prime_memory_guard_write_after_unsent_closure();
DROP TRIGGER IF EXISTS prime_memory_unsent_closures_immutable_guard ON prime_memory_unsent_closures;
CREATE TRIGGER prime_memory_unsent_closures_immutable_guard
  BEFORE INSERT OR UPDATE OR DELETE ON prime_memory_unsent_closures
  FOR EACH ROW EXECUTE FUNCTION prime_memory_guard_unsent_closure_immutable();
DROP TRIGGER IF EXISTS prime_memory_unsent_closures_truncate_guard ON prime_memory_unsent_closures;
CREATE TRIGGER prime_memory_unsent_closures_truncate_guard
  BEFORE TRUNCATE ON prime_memory_unsent_closures
  FOR EACH STATEMENT EXECUTE FUNCTION prime_memory_guard_unsent_closure_immutable();
