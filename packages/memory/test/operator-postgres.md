# Operator-managed PostgreSQL synthetic acceptance

`operator-postgres.mjs` operates only on the explicitly supplied disposable `aukora_prime_synthetic` database. It creates two unique, marked schemas. It never initializes, starts, stops, or restarts PostgreSQL, changes accounts or permissions, opens TCP connections, discovers credentials, or accesses a VM. The operator owns those actions.

The harness requires Node 22.19 or later and the declared `pg` **8.16.3** dependency physically inside the deployed Prime source closure. Symlinks or module resolution outside Prime are refused. The connection expects local peer authentication; any password request is refused instead of using environment credentials or pgpass. The authority is a private toy fixture, not production C; a pass proves PostgreSQL storage behavior and D's fixture protocol only.

Write the following closed JSON config to an absolute task-owned file. Extra keys, passwords, connection strings, different hosts, databases, users, or ports are refused.

```json
{"host":"/run/aukora-prime/postgres","port":55434,"database":"aukora_prime_synthetic","user":"prime_memory","max":4,"connectionTimeoutMillis":5000}
```

Run each command as the authorized memory worker account using the same two absolute task-owned paths. `STATE_JSON` must initially be absent and its parent must exist without a symlink. The first phase also creates `STATE_JSON.anchors.json` with independently retained heads observed from the live database before exporting its snapshot; preserve this operator-owned file through verification.

```text
node packages/memory/test/operator-postgres.mjs prepare CONFIG_JSON STATE_JSON
# The operator restarts the isolated disposable PostgreSQL cluster here.
node packages/memory/test/operator-postgres.mjs verify CONFIG_JSON STATE_JSON
node packages/memory/test/operator-postgres.mjs cleanup CONFIG_JSON STATE_JSON
```

Prepare checks three concurrent calls with one exact approved synthetic operation produce one record and one effect; saved and pending index states remain distinct; an injected FTS projection failure leaves the record saved; retry becomes searchable; citations preserve exact original bytes; and owner filtering rejects another synthetic owner. All SQL uses actual PostgreSQL tables and transactions.

Verify requires a later PostgreSQL postmaster start time. A new Node process checks durable bytes, FTS, citations, owner filtering, and reconciliation of the committed receipt without reserve or dispatch. It verifies a Prime export against the separately retained heads and restores into the fresh marked schema with a trusted anchor callback. This is a synthetic anchor fixture, not an owner enrollment or production authority test.

Cleanup drops only the two exact schema names in the state file after checking their unique synthetic run markers. It preserves a content-free run report and removes the synthetic anchor file. Failed prepare leaves its state file so cleanup can remove any marked schemas. An existing unmarked schema is always refused. Cleanup makes no physical media, WAL, or backup erasure claim.

No PostgreSQL connection or acceptance run is made merely by adding this source. Report prepare and verify results separately; source checks or `--help` do not count as PostgreSQL acceptance.
