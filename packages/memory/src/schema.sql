CREATE TABLE IF NOT EXISTS prime_memory_records (
  owner_subject text NOT NULL, record_id text NOT NULL, revision integer NOT NULL CHECK (revision > 0),
  canonical_bytes bytea NOT NULL, original_sha256 text NOT NULL, record_format text NOT NULL,
  canonicalizer text NOT NULL, task_id text NOT NULL, scope text NOT NULL, privacy text NOT NULL CHECK (privacy IN ('local','private','exportable')),
  tier text NOT NULL CHECK (tier IN ('remembered','approved')), statement text NOT NULL,
  chain_domain text NOT NULL CHECK (chain_domain IN ('remembered','approved','legacy-presplit')),
  chain_sequence integer NOT NULL, source_digest text, grants_authority boolean NOT NULL DEFAULT false CHECK (NOT grants_authority),
  PRIMARY KEY (owner_subject,record_id,revision)
);
CREATE TABLE IF NOT EXISTS prime_memory_events (
  owner_subject text NOT NULL, sha256 text NOT NULL, bytes bytea NOT NULL, PRIMARY KEY(owner_subject,sha256)
);
CREATE TABLE IF NOT EXISTS prime_memory_heads (
  owner_subject text NOT NULL, chain_domain text NOT NULL, sequence integer NOT NULL, hash text NOT NULL,
  PRIMARY KEY(owner_subject,chain_domain)
);
CREATE TABLE IF NOT EXISTS prime_memory_chain (
  owner_subject text NOT NULL, chain_domain text NOT NULL, sequence integer NOT NULL,
  bytes bytea NOT NULL, hash text NOT NULL, prev text NOT NULL, PRIMARY KEY(owner_subject,chain_domain,sequence)
);
CREATE TABLE IF NOT EXISTS prime_memory_requests (
  owner_subject text NOT NULL, idempotency_key text NOT NULL, request_digest text NOT NULL,
  record_id text NOT NULL, revision integer NOT NULL, PRIMARY KEY(owner_subject,idempotency_key)
);
CREATE TABLE IF NOT EXISTS prime_memory_outbox (
  owner_subject text NOT NULL, record_id text NOT NULL, revision integer NOT NULL,
  target text NOT NULL, generation text NOT NULL, operation text NOT NULL CHECK (operation IN ('index','remove')),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','indexed','failed')),
  attempts integer NOT NULL DEFAULT 0, last_error text,
  PRIMARY KEY(owner_subject,record_id,revision,target,generation,operation)
);
CREATE TABLE IF NOT EXISTS prime_memory_fts (
  owner_subject text NOT NULL, record_id text NOT NULL, revision integer NOT NULL,
  target text NOT NULL, generation text NOT NULL, scope text NOT NULL, privacy text NOT NULL,
  statement text NOT NULL, document tsvector GENERATED ALWAYS AS (to_tsvector('simple',statement)) STORED,
  PRIMARY KEY(owner_subject,record_id,revision,target,generation)
);
CREATE INDEX IF NOT EXISTS prime_memory_fts_document ON prime_memory_fts USING gin(document);
CREATE INDEX IF NOT EXISTS prime_memory_fts_owner ON prime_memory_fts(owner_subject,scope,privacy);
CREATE TABLE IF NOT EXISTS prime_memory_tombstones (
  owner_subject text NOT NULL, record_id text NOT NULL, bytes bytea NOT NULL, sha256 text NOT NULL,
  PRIMARY KEY(owner_subject,record_id)
);
CREATE TABLE IF NOT EXISTS prime_memory_controls (
  owner_subject text NOT NULL, scope text NOT NULL, bytes bytea NOT NULL, PRIMARY KEY(owner_subject,scope)
);
CREATE TABLE IF NOT EXISTS prime_memory_snapshots (
  owner_subject text NOT NULL, digest text NOT NULL, manifest_bytes bytea NOT NULL, PRIMARY KEY(owner_subject,digest)
);
CREATE TABLE IF NOT EXISTS prime_memory_originals (
  owner_subject text NOT NULL, snapshot_digest text NOT NULL, logical_path text NOT NULL,
  bytes bytea NOT NULL, sha256 text NOT NULL, metadata_bytes bytea NOT NULL,
  PRIMARY KEY(owner_subject,snapshot_digest,logical_path)
);
CREATE TABLE IF NOT EXISTS prime_memory_quarantine (
  owner_subject text NOT NULL, snapshot_digest text NOT NULL, logical_path text NOT NULL,
  reason text NOT NULL, PRIMARY KEY(owner_subject,snapshot_digest,logical_path)
);
CREATE TABLE IF NOT EXISTS prime_memory_redactions (
  owner_subject text NOT NULL, record_id text NOT NULL, revision integer NOT NULL, bytes bytea NOT NULL,
  PRIMARY KEY(owner_subject,record_id,revision)
);
CREATE TABLE IF NOT EXISTS prime_memory_effects (
  owner_subject text NOT NULL, operation_id text NOT NULL, operation_digest text NOT NULL,
  grant_id text NOT NULL, action text NOT NULL, result_bytes bytea NOT NULL,
  request_id text NOT NULL UNIQUE, request_digest text NOT NULL, request_bytes bytea NOT NULL, receipt_bytes bytea NOT NULL,
  operation_bytes bytea NOT NULL, grant_bytes bytea NOT NULL,
  PRIMARY KEY(owner_subject,operation_id), UNIQUE(grant_id)
);
CREATE TABLE IF NOT EXISTS prime_memory_purges (
  owner_subject text NOT NULL, operation_id text NOT NULL, bytes bytea NOT NULL,
  PRIMARY KEY(owner_subject,operation_id)
);
CREATE TABLE IF NOT EXISTS prime_memory_intents (
  owner_subject text NOT NULL, operation_id text NOT NULL, operation_digest text NOT NULL,
  grant_bytes bytea NOT NULL, operation_bytes bytea NOT NULL, request_id text NOT NULL UNIQUE,
  request_digest text NOT NULL, request_bytes bytea NOT NULL,
  PRIMARY KEY(owner_subject,operation_id)
);
