# Operator-managed PostgreSQL synthetic acceptance

`operator-postgres.mjs` operates only on the explicitly supplied disposable `aukora_prime_synthetic` database. It plans two unique, marked schemas. The exclusive PG operator owns schema creation and deletion. The memory role uses only tables and transactions inside those exact schemas. The runner never creates/drops schemas, initializes, starts, stops, or restarts PostgreSQL, changes accounts or permissions, opens TCP connections, discovers credentials, or accesses a VM.

The harness requires Node 22.19 or later and the declared `pg` **8.16.3** dependency physically inside the deployed Prime source closure. Symlinks or module resolution outside Prime are refused. The connection expects local peer authentication; any password request is refused instead of using environment credentials or pgpass. The authority is a private toy fixture, not production C; a pass proves PostgreSQL storage behavior and D's fixture protocol only.

Write the following closed JSON config to an absolute task-owned file. Extra keys, passwords, connection strings, different hosts, databases, users, or ports are refused.

```json
{"host":"/run/aukora-prime/postgres","port":55434,"database":"aukora_prime_synthetic","user":"prime_memory","max":4,"connectionTimeoutMillis":5000}
```

Run each command as the authorized memory worker account using the same two absolute task-owned paths. `STATE_JSON` must initially be absent and its parent must exist without a symlink. `plan` requires no driver or database connection. It creates the closed planned state plus `STATE_JSON.schema-create-plan.json` naming the exact two schemas, immutable run marker and narrowly scoped privileges.

```text
node packages/memory/test/operator-postgres.mjs plan CONFIG_JSON STATE_JSON
# Exclusive PG operator creates only the two schemas in the plan and their read-only markers.
node packages/memory/test/operator-postgres.mjs prepare CONFIG_JSON STATE_JSON
# The operator restarts the isolated disposable PostgreSQL cluster here.
node packages/memory/test/operator-postgres.mjs verify CONFIG_JSON STATE_JSON
node packages/memory/test/operator-postgres.mjs cleanup-plan CONFIG_JSON STATE_JSON
# Exclusive PG operator validates markers, then drops only the two schemas in the cleanup plan.
```

The exclusive operator creates both schemas with an administrative owner, never `prime_memory`. In each schema it creates `prime_operator_fixture_marker(run_id text PRIMARY KEY, fixture_kind text NOT NULL)` owned by the operator and inserts the plan's one exact `{run_id,fixture_kind}` row. It grants `prime_memory` only `USAGE,CREATE` on those exact two schemas and `SELECT` on their exact marker tables. No database CREATE/TEMP, superuser, schema ownership, marker mutation or wildcard grants are required or permitted. The runner checks these role/ownership/marker boundaries before table migration. The operator must not alter the existing grants on unrelated schemas.

Prepare checks both pre-created markers and the original plan commitment. It does not create schemas or grant privileges. It explicitly selects every column of the new `prime_memory_replay_fences` table after bounded migration and requires it empty for this fresh synthetic owner. It creates `STATE_JSON.anchors.json` with the complete eight-table control bundle, distinct owner ID/subject and authorization epoch observed from the registered fixture before exporting its snapshot; preserve this task-owned fixture file through verification.

Prepare checks three concurrent calls with one exact approved synthetic operation produce one record and one effect; saved and pending index states remain distinct; an injected FTS projection failure leaves the record saved; retry becomes searchable; citations preserve exact original bytes; and owner filtering rejects another synthetic owner. All SQL uses actual PostgreSQL tables and transactions.

Verify requires a later PostgreSQL postmaster start time. A new Node process checks durable bytes, FTS, citations, owner filtering, and reconciliation of the committed receipt without reserve or dispatch. It verifies a Prime export against separately retained control/heads and restores into the fresh marked schema with an explicit toy host provider. The result labels `control_retention_profile:'explicit-toy-host-provider/not-production-file-reader'` and `new_replay_fence_schema_checked:true`. This is a synthetic anchor fixture, not owner enrollment, production authority or qualification of the independent file publisher/read boundary. See [the retention protocol](../CONTROL_RETENTION.md) for that separate pending H join.

`cleanup-plan` requires successful verification. It performs read-only marker/role checks and emits `STATE_JSON.schema-cleanup-plan.json` for exactly the two originally planned names, with marker verification required before either drop. It drops nothing and preserves the state and anchor evidence. The exclusive operator owns both actual drops and any later task-owned file cleanup. Failed prepare retains its state/create plan for the operator's bounded recovery cleanup; it cannot claim acceptance. An existing unmarked schema is always refused. Neither source nor cleanup plans claim physical media, WAL, or backup erasure.

No PostgreSQL connection or acceptance run is made merely by adding this source. Report prepare and verify results separately; source checks or `--help` do not count as PostgreSQL acceptance.
