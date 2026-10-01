# Genuine C/D private-worker PostgreSQL fixture

This source-only helper supports the smallest synthetic join of actual C approval proofs, D's private memory worker, and durable PostgreSQL storage. It contains no authority stand-in, worker controller, credential discovery, process control, or PostgreSQL lifecycle action. H owns protected staging, assigned UIDs, configuration, and test-process start/stop. The exclusive PostgreSQL operator owns cluster start/restart/stop and the creation/deletion of precisely the two admin-marked synthetic schemas.

The helper is `packages/memory/test/worker-postgres-fixture.mjs`. Its exports are:

```js
planWorkerPostgresFixture({ config, statePath })
validateWorkerPostgresFixture(fixture, config)
createWorkerPostgresPool({ config, fixture, schema: 'source' | 'restore', memoryUid })
initializeWorkerPostgresSchema({ config, fixture, schema: 'source' | 'restore', memoryUid })
validateWorkerPostgresSaveExpectation(expected, fixture)
verifyWorkerPostgresSave({ pool, fixture, expected, project: false })
workerPostgresSchemaPlan({ config, fixture, action: 'create' | 'drop' })
expectedWorkerCaptureDigests({ config, fixture, owner: 'primary' | 'secondary', host, extraction, idempotencyKey })
```

The only permitted configuration is the following closed object. `max` is an integer from 1 through 4.

```json
{"host":"/run/aukora-prime/postgres","port":55434,"database":"aukora_prime_synthetic","user":"prime_memory","max":4,"connectionTimeoutMillis":5000}
```

`planWorkerPostgresFixture` neither imports `pg` nor connects. It durably writes the closed, immutable fixture to an absolute `statePath` in an existing real directory, and the operator create plan to `statePath + '.schema-create-plan.json'`. Both files use mode 0600 and exclusive publication. Its return is `{fixture,state_path,schema_plan_path,plan,PostgreSQL_connected:false}`. It does not replace an existing state/plan.

The fixture has exactly these fields:

```js
{
  version: 1,
  kind: 'prime-memory-private-worker-pg-fixture/v1',
  synthetic_fixture: true,
  run_id: '<24 lowercase hexadecimal characters>',
  config_sha256: '<64 lowercase hexadecimal characters>',
  source_schema: 'prime_memory_operator_' + run_id + '_source',
  restore_schema: 'prime_memory_operator_' + run_id + '_restore',
  owners: {
    primary: {
      owner_id: 'synthetic-owner:' + run_id,
      owner_subject: 'aukora:1:' + sha256('synthetic-owner:' + run_id),
      task_id: 'synthetic-pg-task:' + run_id,
      conversation_id: 'synthetic-pg-conversation:' + run_id
    },
    secondary: {
      owner_id: 'synthetic-other-owner:' + run_id,
      owner_subject: 'aukora:1:' + sha256('synthetic-other-owner:' + run_id),
      task_id: 'synthetic-pg-other-task:' + run_id,
      conversation_id: 'synthetic-pg-other-conversation:' + run_id
    }
  },
  agent_id: 'synthetic-agent',
  schema_plan_sha256: '<64 lowercase hexadecimal characters>'
}
```

SHA-256 inputs use UTF-8; configuration and schema-plan hashes use the owned donor `canonicalJSON` profile. Every generated identifier, exact schema name, and digest is rederived by validation. The source contains no passkey private keys, proofs, signing counters, IPC secrets, or source-event bytes in this state. Controller-owned secrets stay in its private runtime descriptor files. A synthetic label supplies no approval authority.

The create plan is exactly the existing `schemaLifecyclePlan` grammar, projected from this fixture with `authority_fixture:'production-C-private-IPC-synthetic-passkey'`. Its schema marker remains `prime-memory-operator-pg-synthetic/v1`, matching the exclusive operator and `checkMarker`. The operator must create only the two listed schemas, retain schema and marker ownership, grant `prime_memory` only `USAGE,CREATE` in these two schemas, and grant `SELECT` alone on each marker. Do not grant database CREATE/TEMP, schema ownership, passwords, TCP access, or elevated role capabilities. This helper does not execute CREATE/DROP SCHEMA or role changes. `workerPostgresSchemaPlan({config,fixture,action:'drop'})` validates and returns the exact pure drop plan after H's actual verification; the exclusive operator must check the exact markers before dropping those names. The function emits a plan and does not establish that execution or verification occurred.

Before importing the driver, the pool factory requires the positive explicitly assigned memory UID to equal both the actual and effective process UID. It refuses every `PG`-prefixed environment variable and all configuration additions, including passwords/SSL overrides. It resolves only `pg` version 8.16.3 inside the Prime source closure, supplies a password callback that always refuses, and uses the exact Unix socket. It verifies PostgreSQL 16, `fsync=on`, `full_page_writes=on`, no database CREATE/TEMP or elevated role, exact operator-owned read-only marker, and exact scoped `search_path`. A factory failure closes its pool.

Table migration is a separate explicit call to `initializeWorkerPostgresSchema` under the assigned memory UID, after the exclusive operator has created and marked that selected schema. D's existing `migrate` issues its bounded table/index DDL only in the exact schema; no database/schema lifecycle operation occurs. The helper closes its pool and returns initialization checks. Afterwards the private memory worker is configured with **`initializeSchema:false`** and receives a pool created by this factory. Do not enable worker migration or broaden privileges to make startup work.

The host controller builds the following closed save expectation only from the genuine, authenticated private-worker IPC save/reconcile response, independently retained original-bytes/head observations, and the actual C settlement response. It must never accept this object from a guest as proof of settlement.

```js
{
  version: 1,
  owner: 'primary', // or 'secondary'
  operation_id: '<nonempty string, maximum 128 code units>',
  operation_digest: 'sha256:<64 lowercase hex>',
  record_id: 'rem:<64 lowercase hex>',
  canonical_sha256: '<64 lowercase hex>',
  retained_head: '<64 lowercase hex>',
  storage_status: 'saved',
  index_status: 'pending', // or 'failed', 'indexed', 'searchable'
  receipt: {
    request_id: '<lowercase UUIDv4>',
    request_digest: 'sha256:<64 lowercase hex>',
    receipt_digest: 'sha256:<64 lowercase hex>',
    grant_id: '<nonempty string, maximum 256 code units>',
    result_digest: 'sha256:<64 lowercase hex>'
  },
  settlement_binding: {
    authority_settlement: 'completed',
    reconciliation_required: false,
    receipt_digest: '<same receipt_digest as receipt>'
  }
}
```

`verifyWorkerPostgresSave` accepts only a pool tagged by the factory and rechecks its UID, fixture, endpoint, and marker. It loads the fixed Prime-local `packages/contracts/src/runtime.mjs`, refusing a resolved path outside this Prime source root rather than trying a global or ancestor package fallback. It reads the actual D effect and durable intent, verifies the frozen operation/grant/MemoryRecord contracts, recomputes the full operation digest and domain-separated request/result/receipt digests, and checks distinct owner ID/subject, owner task, exact original record bytes/ID, request/grant/receipt bindings, and the approved literal statement/attribution against the original record through D's unchanged `validateCaptureReview` helper. This fixed fixture requires the original saved result to have `storage_status:'saved',index_status:'pending'`; current projection status is checked separately. It calls genuine D `status` and `cite` at the independently retained head. It does not call C reserve/dispatch/settlement/reconciliation, and does not save again.

By default verification is read-only. Optional `project:true` calls D's existing owner-locked `drainOutbox` once from this memory-UID host helper before checking the requested final index status. This creates no guest HTTP route. Supply the expected post-projection status, usually `searchable`. The original committed save receipt retains its factual saved/pending result; rebuilding FTS does not rewrite that receipt. A later private-worker read confirms the persisted projection after reopen/restart.

The helper returns only IDs, digests, status booleans, citation verdict/head, and check names. It never returns canonical record bytes or source plaintext. Its report explicitly has `authority_settlement_independently_verified:false`: comparison to the controller's settlement binding is not an independent test of C. Bridge/H's real proof and private IPC evidence must establish C's completed lifecycle separately. The restore schema is reserved for separately approved synthetic restore qualification; this save verifier requires an actual `memory.save` effect and does not mislabel a restore receipt as a save.

Source guard tests do not demonstrate PostgreSQL or distinct-UID acceptance. Actual protected execution, genuine C proofs/private IPC, cluster restart, and exclusive-operator cleanup remain H/operator responsibilities. No private owner enrollment or memory import is enabled by this fixture.

`expectedWorkerCaptureDigests` is a pure helper for the private synthetic controller's signer fence. It rederives the expected full capture hash from the controller's independently immutable host/extraction/key definitions. Its return is exactly `{capture_sha256,idempotency_key_sha256,statement,attributed_to}`; it provides no heads, proof, authorization, note-builder output, or new record ID. The controller compares these four values with the worker's actual prepared operation before signing. The unchanged browser helper continues comparing the visible literal and independently retained draft; it does not reconstruct the private capture hash.

The capture helper accepts only fixture owner ID/subject/task, optional matching conversation, `scope:'owner'`, `privacy:'local'`, `attributedTo:'owner'`, absent/false pause and off-the-record flags, absent/null evidence and body, and absent/exact `{by:'prime.capture/v1'}` origin. Host fields form a closed whitelist. `source` is exactly `{sessionId,seq,at,sha256}` with a canonical UTC seconds instant and nonnegative safe-integer sequence. `events` contains 1–8 Buffer/Uint8Array values, each 1–65536 bytes; the source digest must select a parsed event whose text is nonempty and whose sequence/instant match. Event bytes are copied and hashed exactly, including the original trailing LF. No source-span, control, nondefault origin, or evidence override is accepted in this bounded fixture.

Extraction contains precisely `category,statement,validFrom,observedAt,confidence,sensitivity`, optionally `links`. Literal validation reuses the unchanged D capture-review bounds; decimal confidence from 0 through 1 remains in the private donor JSON profile. Optional links contain at most 16 closed `{relation,id}` entries. The idempotency key is a nonempty string of at most 1024 code units. No field is normalized or supplied from a proposed operation. The preimage matches current D `captureContext` exactly:

```js
{input: extraction, subject: owner.owner_subject, task: owner.task_id, source: host.source,
 evidence: null, attribution: 'owner', scope: 'owner', privacy: 'local',
 origin: {by:'prime.capture/v1'}, bodyAtCapture: null, events: eventByteSha256s}
```

The capture hash is SHA-256 of UTF-8 donor `canonicalJSON(preimage)`, and the key hash is SHA-256 of the original UTF-8 key. This narrowly fixed synthetic preimage is source-only; it does not extend the production bridge's public API or confer owner authority.
