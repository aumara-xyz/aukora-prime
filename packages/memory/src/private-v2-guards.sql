-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Explicit installation on pre-existing, separately provisioned tables only.
-- The installer pins their namespace/OIDs; it never creates schemas, identities,
-- metadata, tables, roles, permissions or the original writer-closure guards.
CREATE OR REPLACE FUNCTION prime_memory_private_v2_metadata_immutable()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog
AS $prime_private_v2_guard$
BEGIN
  IF TG_TABLE_NAME <> 'prime_memory_logical_store' OR TG_WHEN <> 'BEFORE'
    OR NOT ((TG_LEVEL = 'ROW' AND TG_OP IN ('INSERT','UPDATE','DELETE'))
      OR (TG_LEVEL = 'STATEMENT' AND TG_OP = 'TRUNCATE')) THEN
    RAISE EXCEPTION 'prime_memory_private_v2_metadata_context_invalid';
  END IF;
  RAISE EXCEPTION 'prime_memory_private_v2_metadata_immutable';
END;
$prime_private_v2_guard$;

CREATE OR REPLACE FUNCTION prime_memory_private_v2_workflow_immutable()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog
AS $prime_private_v2_guard$
BEGIN
  IF TG_LEVEL = 'STATEMENT' AND TG_WHEN = 'BEFORE'
    AND TG_TABLE_NAME = 'prime_runtime_workflows' AND TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_workflow_immutable';
  END IF;
  IF TG_LEVEL <> 'ROW' OR TG_WHEN <> 'BEFORE'
    OR TG_TABLE_NAME <> 'prime_runtime_workflows'
    OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
    RAISE EXCEPTION 'prime_memory_private_v2_workflow_context_invalid';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_workflow_immutable';
  END IF;
  IF current_setting('session_replication_role') <> 'origin'
    OR current_setting('transaction_isolation') <> 'read committed'
    OR current_setting('transaction_read_only') <> 'off' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_workflow_session_invalid';
  END IF;
  IF NEW.owner_subject IS NULL OR NEW.owner_subject = '' OR NEW.owner_id IS NULL OR NEW.owner_id = ''
    OR NEW.task_id IS NULL OR NEW.task_id = '' OR NEW.operation_id IS NULL OR NEW.operation_id = ''
    OR NEW.operation_digest IS NULL OR NEW.operation_digest !~ '^sha256:[a-f0-9]{64}$'
    OR NEW.action_type IS NULL OR NEW.action_type NOT IN ('memory.save','memory.forget')
    OR NEW.phase IS NULL OR NEW.phase NOT IN ('proposed','attempted','known_unsent','saved','forgotten')
    OR NEW.created_at IS NULL OR NEW.created_at !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
    OR (NEW.idempotency_key_sha256 IS NOT NULL AND NEW.idempotency_key_sha256 !~ '^[a-f0-9]{64}$')
    OR (NEW.request_id IS NULL) <> (NEW.request_digest IS NULL)
    OR (NEW.request_id IS NOT NULL AND NEW.request_id = '')
    OR (NEW.request_digest IS NOT NULL AND NEW.request_digest !~ '^sha256:[a-f0-9]{64}$')
    OR (NEW.receipt_digest IS NOT NULL AND NEW.receipt_digest !~ '^sha256:[a-f0-9]{64}$')
    OR (NEW.record_id IS NOT NULL AND NEW.record_id = '')
    OR (NEW.action_type = 'memory.forget' AND (NEW.idempotency_key_sha256 IS NOT NULL OR NEW.record_id IS NULL))
    OR (NEW.phase = 'saved' AND NEW.action_type <> 'memory.save')
    OR (NEW.phase = 'forgotten' AND NEW.action_type <> 'memory.forget')
    OR (NEW.phase IN ('saved','forgotten') AND (NEW.record_id IS NULL OR NEW.request_id IS NULL OR NEW.receipt_digest IS NULL))
    OR (NEW.phase IN ('proposed','attempted','known_unsent') AND (NEW.request_id IS NOT NULL OR NEW.receipt_digest IS NOT NULL)) THEN
    RAISE EXCEPTION 'prime_memory_private_v2_workflow_binding_invalid';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.owner_subject, 0));
  IF TG_OP = 'UPDATE' THEN
    IF OLD.owner_subject IS DISTINCT FROM NEW.owner_subject OR OLD.owner_id IS DISTINCT FROM NEW.owner_id
      OR OLD.task_id IS DISTINCT FROM NEW.task_id OR OLD.operation_id IS DISTINCT FROM NEW.operation_id
      OR OLD.operation_digest IS DISTINCT FROM NEW.operation_digest OR OLD.action_type IS DISTINCT FROM NEW.action_type
      OR OLD.idempotency_key_sha256 IS DISTINCT FROM NEW.idempotency_key_sha256
      OR OLD.created_at IS DISTINCT FROM NEW.created_at
      OR (OLD.record_id IS NOT NULL AND OLD.record_id IS DISTINCT FROM NEW.record_id)
      OR (OLD.request_id IS NOT NULL AND OLD.request_id IS DISTINCT FROM NEW.request_id)
      OR (OLD.request_digest IS NOT NULL AND OLD.request_digest IS DISTINCT FROM NEW.request_digest)
      OR (OLD.receipt_digest IS NOT NULL AND OLD.receipt_digest IS DISTINCT FROM NEW.receipt_digest) THEN
      RAISE EXCEPTION 'prime_memory_private_v2_workflow_immutable';
    END IF;
    IF OLD.phase = NEW.phase THEN
      IF OLD IS DISTINCT FROM NEW THEN
        RAISE EXCEPTION 'prime_memory_private_v2_workflow_idempotency_conflict';
      END IF;
    ELSIF NOT ((OLD.phase = 'proposed' AND NEW.phase = 'attempted')
      OR (OLD.phase = 'attempted' AND NEW.phase IN ('known_unsent','saved','forgotten'))) THEN
      RAISE EXCEPTION 'prime_memory_private_v2_workflow_regression';
    END IF;
  END IF;
  RETURN NEW;
END;
$prime_private_v2_guard$;

CREATE OR REPLACE FUNCTION prime_memory_private_v2_progress_immutable()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog
AS $prime_private_v2_guard$
DECLARE
  p jsonb;
  prior jsonb;
  names text[];
  prior_stage integer;
  next_stage integer;
BEGIN
  IF TG_LEVEL = 'STATEMENT' AND TG_WHEN = 'BEFORE'
    AND TG_TABLE_NAME = 'prime_runtime_workflow_closure_progress_v2' AND TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_immutable';
  END IF;
  IF TG_LEVEL <> 'ROW' OR TG_WHEN <> 'BEFORE'
    OR TG_TABLE_NAME <> 'prime_runtime_workflow_closure_progress_v2'
    OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_context_invalid';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_immutable';
  END IF;
  IF current_setting('session_replication_role') <> 'origin'
    OR current_setting('transaction_isolation') <> 'read committed'
    OR current_setting('transaction_read_only') <> 'off' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_session_invalid';
  END IF;
  IF NEW.owner_subject IS NULL OR NEW.owner_subject = '' OR NEW.owner_id IS NULL OR NEW.owner_id = ''
    OR NEW.task_id IS NULL OR NEW.task_id = '' OR NEW.operation_id IS NULL OR NEW.operation_id = ''
    OR NEW.progress_bytes IS NULL OR octet_length(NEW.progress_bytes) NOT BETWEEN 1 AND 67108864
    OR NEW.progress_digest IS NULL OR NEW.progress_digest !~ '^sha256:[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_binding_invalid';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.owner_subject, 0));
  p := convert_from(NEW.progress_bytes, 'UTF8')::jsonb;
  IF jsonb_typeof(p) <> 'object' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_shape_invalid';
  END IF;
  SELECT array_agg(key ORDER BY key COLLATE "C") INTO names FROM jsonb_object_keys(p) AS x(key);
  IF names IS DISTINCT FROM ARRAY['authority','closing_authorization_epoch','closure_attempt_id',
    'expected_authority_store_id','expected_memory_store_id','idempotency_key_sha256','kind','memory','reference','stage','version']
    OR p->'version' IS DISTINCT FROM '2'::jsonb OR p->>'kind' IS DISTINCT FROM 'prime-runtime-unsent-closure-progress/v2'
    OR jsonb_typeof(p->'closure_attempt_id') IS DISTINCT FROM 'string' OR p->>'closure_attempt_id' !~ '^sha256:[a-f0-9]{64}$'
    OR jsonb_typeof(p->'expected_authority_store_id') IS DISTINCT FROM 'string' OR p->>'expected_authority_store_id' !~ '^[a-f0-9]{64}$'
    OR jsonb_typeof(p->'expected_memory_store_id') IS DISTINCT FROM 'string' OR p->>'expected_memory_store_id' !~ '^[a-f0-9]{64}$'
    OR jsonb_typeof(p->'closing_authorization_epoch') IS DISTINCT FROM 'number'
    OR p->>'closing_authorization_epoch' !~ '^(0|[1-9][0-9]*)$'
    OR (p->>'closing_authorization_epoch')::numeric > 9007199254740991
    OR NOT (p->'idempotency_key_sha256' = 'null'::jsonb OR (jsonb_typeof(p->'idempotency_key_sha256') = 'string'
      AND p->>'idempotency_key_sha256' ~ '^[a-f0-9]{64}$'))
    OR jsonb_typeof(p->'reference') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p->'stage') IS DISTINCT FROM 'string'
    OR p->>'stage' NOT IN ('started','authority_confirmed','memory_confirmed','complete') THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_shape_invalid';
  END IF;
  SELECT array_agg(key ORDER BY key COLLATE "C") INTO names FROM jsonb_object_keys(p->'reference') AS x(key);
  IF names IS DISTINCT FROM ARRAY['action_type','operation_digest','operation_id','owner_id','owner_subject','task_id']
    OR jsonb_typeof(p->'reference'->'owner_subject') IS DISTINCT FROM 'string'
    OR jsonb_typeof(p->'reference'->'owner_id') IS DISTINCT FROM 'string'
    OR jsonb_typeof(p->'reference'->'task_id') IS DISTINCT FROM 'string'
    OR jsonb_typeof(p->'reference'->'operation_id') IS DISTINCT FROM 'string'
    OR jsonb_typeof(p->'reference'->'action_type') IS DISTINCT FROM 'string'
    OR p->'reference'->>'owner_subject' IS DISTINCT FROM NEW.owner_subject
    OR p->'reference'->>'owner_id' IS DISTINCT FROM NEW.owner_id
    OR p->'reference'->>'task_id' IS DISTINCT FROM NEW.task_id
    OR p->'reference'->>'operation_id' IS DISTINCT FROM NEW.operation_id
    OR jsonb_typeof(p->'reference'->'operation_digest') IS DISTINCT FROM 'string'
    OR p->'reference'->>'operation_digest' !~ '^sha256:[a-f0-9]{64}$'
    OR p->'reference'->>'action_type' NOT IN ('memory.save','memory.forget') THEN
    RAISE EXCEPTION 'prime_memory_private_v2_progress_reference_invalid';
  END IF;
  IF p->>'stage' = 'started' THEN
    IF p->'authority' IS DISTINCT FROM 'null'::jsonb OR p->'memory' IS DISTINCT FROM 'null'::jsonb THEN
      RAISE EXCEPTION 'prime_memory_private_v2_progress_stage_invalid';
    END IF;
  ELSE
    IF jsonb_typeof(p->'authority') IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'prime_memory_private_v2_progress_authority_invalid';
    END IF;
    SELECT array_agg(key ORDER BY key COLLATE "C") INTO names FROM jsonb_object_keys(p->'authority') AS x(key);
    IF names IS DISTINCT FROM ARRAY['closure','closure_digest']
      OR jsonb_typeof(p->'authority'->'closure') IS DISTINCT FROM 'object'
      OR jsonb_typeof(p->'authority'->'closure_digest') IS DISTINCT FROM 'string'
      OR p->'authority'->>'closure_digest' !~ '^sha256:[a-f0-9]{64}$' THEN
      RAISE EXCEPTION 'prime_memory_private_v2_progress_authority_invalid';
    END IF;
    IF p->>'stage' = 'authority_confirmed' THEN
      IF p->'memory' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'prime_memory_private_v2_progress_stage_invalid';
      END IF;
    ELSE
      IF jsonb_typeof(p->'memory') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'prime_memory_private_v2_progress_memory_invalid';
      END IF;
      SELECT array_agg(key ORDER BY key COLLATE "C") INTO names FROM jsonb_object_keys(p->'memory') AS x(key);
      IF names IS DISTINCT FROM ARRAY['closure','closure_digest','completion','completion_digest']
        OR jsonb_typeof(p->'memory'->'closure') IS DISTINCT FROM 'object'
        OR jsonb_typeof(p->'memory'->'completion') IS DISTINCT FROM 'object'
        OR jsonb_typeof(p->'memory'->'closure_digest') IS DISTINCT FROM 'string'
        OR p->'memory'->>'closure_digest' !~ '^sha256:[a-f0-9]{64}$'
        OR jsonb_typeof(p->'memory'->'completion_digest') IS DISTINCT FROM 'string'
        OR p->'memory'->>'completion_digest' !~ '^sha256:[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'prime_memory_private_v2_progress_memory_invalid';
      END IF;
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    prior := convert_from(OLD.progress_bytes, 'UTF8')::jsonb;
    IF OLD.owner_subject IS DISTINCT FROM NEW.owner_subject OR OLD.owner_id IS DISTINCT FROM NEW.owner_id
      OR OLD.task_id IS DISTINCT FROM NEW.task_id OR OLD.operation_id IS DISTINCT FROM NEW.operation_id
      OR (prior - ARRAY['stage','authority','memory']) IS DISTINCT FROM (p - ARRAY['stage','authority','memory'])
      OR (prior->'authority' <> 'null'::jsonb AND prior->'authority' IS DISTINCT FROM p->'authority')
      OR (prior->'memory' <> 'null'::jsonb AND prior->'memory' IS DISTINCT FROM p->'memory') THEN
      RAISE EXCEPTION 'prime_memory_private_v2_progress_immutable';
    END IF;
    prior_stage := array_position(ARRAY['started','authority_confirmed','memory_confirmed','complete'],prior->>'stage');
    next_stage := array_position(ARRAY['started','authority_confirmed','memory_confirmed','complete'],p->>'stage');
    IF prior_stage = next_stage THEN
      IF OLD.progress_bytes IS DISTINCT FROM NEW.progress_bytes OR OLD.progress_digest IS DISTINCT FROM NEW.progress_digest THEN
        RAISE EXCEPTION 'prime_memory_private_v2_progress_idempotency_conflict';
      END IF;
    ELSIF prior_stage IS NULL OR next_stage <> prior_stage + 1 THEN
      RAISE EXCEPTION 'prime_memory_private_v2_progress_regression';
    END IF;
  END IF;
  RETURN NEW;
END;
$prime_private_v2_guard$;

CREATE OR REPLACE FUNCTION prime_memory_private_v2_journal_correlated()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog
AS $prime_private_v2_guard$
DECLARE
  workflow record;
  progress bytea;
  p jsonb;
  closure bytea;
  closure_hash text;
BEGIN
  IF TG_LEVEL <> 'ROW' OR TG_WHEN <> 'AFTER' OR TG_OP NOT IN ('INSERT','UPDATE')
    OR TG_TABLE_NAME NOT IN ('prime_runtime_workflows','prime_runtime_workflow_closure_progress_v2') THEN
    RAISE EXCEPTION 'prime_memory_private_v2_journal_context_invalid';
  END IF;
  IF current_setting('session_replication_role') <> 'origin'
    OR current_setting('transaction_isolation') <> 'read committed'
    OR current_setting('transaction_read_only') <> 'off' THEN
    RAISE EXCEPTION 'prime_memory_private_v2_journal_session_invalid';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.owner_subject, 0));
  EXECUTE format('SELECT owner_subject,owner_id,task_id,operation_id,operation_digest,action_type,idempotency_key_sha256,phase FROM %I.prime_runtime_workflows WHERE owner_subject=$1 AND operation_id=$2',TG_TABLE_SCHEMA)
    INTO STRICT workflow USING NEW.owner_subject,NEW.operation_id;
  EXECUTE format('SELECT progress_bytes FROM %I.prime_runtime_workflow_closure_progress_v2 WHERE owner_subject=$1 AND operation_id=$2',TG_TABLE_SCHEMA)
    INTO progress USING NEW.owner_subject,NEW.operation_id;
  IF progress IS NULL THEN
    IF workflow.phase = 'known_unsent' THEN
      RAISE EXCEPTION 'prime_memory_private_v2_completion_missing';
    END IF;
    RETURN NULL;
  END IF;
  p := convert_from(progress, 'UTF8')::jsonb;
  IF workflow.owner_id IS DISTINCT FROM p->'reference'->>'owner_id'
    OR workflow.task_id IS DISTINCT FROM p->'reference'->>'task_id'
    OR workflow.operation_digest IS DISTINCT FROM p->'reference'->>'operation_digest'
    OR workflow.action_type IS DISTINCT FROM p->'reference'->>'action_type'
    OR workflow.idempotency_key_sha256 IS DISTINCT FROM p->>'idempotency_key_sha256'
    OR (p->>'stage' = 'complete' AND workflow.phase <> 'known_unsent')
    OR (p->>'stage' <> 'complete' AND workflow.phase <> 'attempted') THEN
    RAISE EXCEPTION 'prime_memory_private_v2_journal_correlation_invalid';
  END IF;
  IF p->>'stage' IN ('memory_confirmed','complete') THEN
    EXECUTE format('SELECT closure_bytes,closure_digest FROM %I.prime_memory_unsent_closures WHERE owner_subject=$1 AND operation_id=$2',TG_TABLE_SCHEMA)
      INTO STRICT closure,closure_hash USING NEW.owner_subject,NEW.operation_id;
    IF closure_hash IS DISTINCT FROM p->'memory'->>'closure_digest'
      OR convert_from(closure,'UTF8')::jsonb IS DISTINCT FROM p->'memory'->'closure'
      OR p->'memory'->'closure'->'version' IS DISTINCT FROM '2'::jsonb
      OR p->'memory'->'closure'->>'store_id' IS DISTINCT FROM p->>'expected_memory_store_id' THEN
      RAISE EXCEPTION 'prime_memory_private_v2_memory_correlation_invalid';
    END IF;
  END IF;
  RETURN NULL;
END;
$prime_private_v2_guard$;

DROP TRIGGER IF EXISTS prime_memory_private_v2_metadata_row_guard ON prime_memory_logical_store;
CREATE TRIGGER prime_memory_private_v2_metadata_row_guard BEFORE INSERT OR UPDATE OR DELETE
  ON prime_memory_logical_store FOR EACH ROW EXECUTE FUNCTION prime_memory_private_v2_metadata_immutable();
DROP TRIGGER IF EXISTS prime_memory_private_v2_metadata_truncate_guard ON prime_memory_logical_store;
CREATE TRIGGER prime_memory_private_v2_metadata_truncate_guard BEFORE TRUNCATE
  ON prime_memory_logical_store FOR EACH STATEMENT EXECUTE FUNCTION prime_memory_private_v2_metadata_immutable();
DROP TRIGGER IF EXISTS prime_memory_private_v2_workflow_row_guard ON prime_runtime_workflows;
CREATE TRIGGER prime_memory_private_v2_workflow_row_guard BEFORE INSERT OR UPDATE OR DELETE
  ON prime_runtime_workflows FOR EACH ROW EXECUTE FUNCTION prime_memory_private_v2_workflow_immutable();
DROP TRIGGER IF EXISTS prime_memory_private_v2_workflow_truncate_guard ON prime_runtime_workflows;
CREATE TRIGGER prime_memory_private_v2_workflow_truncate_guard BEFORE TRUNCATE
  ON prime_runtime_workflows FOR EACH STATEMENT EXECUTE FUNCTION prime_memory_private_v2_workflow_immutable();
DROP TRIGGER IF EXISTS prime_memory_private_v2_progress_row_guard ON prime_runtime_workflow_closure_progress_v2;
CREATE TRIGGER prime_memory_private_v2_progress_row_guard BEFORE INSERT OR UPDATE OR DELETE
  ON prime_runtime_workflow_closure_progress_v2 FOR EACH ROW EXECUTE FUNCTION prime_memory_private_v2_progress_immutable();
DROP TRIGGER IF EXISTS prime_memory_private_v2_progress_truncate_guard ON prime_runtime_workflow_closure_progress_v2;
CREATE TRIGGER prime_memory_private_v2_progress_truncate_guard BEFORE TRUNCATE
  ON prime_runtime_workflow_closure_progress_v2 FOR EACH STATEMENT EXECUTE FUNCTION prime_memory_private_v2_progress_immutable();
DROP TRIGGER IF EXISTS prime_memory_private_v2_workflow_correlation_guard ON prime_runtime_workflows;
CREATE CONSTRAINT TRIGGER prime_memory_private_v2_workflow_correlation_guard AFTER INSERT OR UPDATE
  ON prime_runtime_workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION prime_memory_private_v2_journal_correlated();
DROP TRIGGER IF EXISTS prime_memory_private_v2_progress_correlation_guard ON prime_runtime_workflow_closure_progress_v2;
CREATE CONSTRAINT TRIGGER prime_memory_private_v2_progress_correlation_guard AFTER INSERT OR UPDATE
  ON prime_runtime_workflow_closure_progress_v2 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION prime_memory_private_v2_journal_correlated();
