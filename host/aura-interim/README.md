# INTERIM Aura collector install (Grok, 2026-10-04)

This is the exact source of the Aura collector installed on the Nebius pilot at 17:33 WITA,
2026-10-04. It runs D's collector (`scripts/aura/collect-gate.mjs` from the live release)
with an INTERIM operator context. It is a stopgap: D's lifecycle context (c3f07af, with
the import closure H pins) replaces it, and this directory is then removed.

- `install.sh`: creates the `aukora-aura` user and dirs, copies the gate public key,
  generates INTERIM keys on the pilot (`keygen.mjs`), records a root anchor
  (`anchor.mjs`) and installs the systemd service and timer.
- `snapshot.mjs`: root takes a consistent `VACUUM INTO` copy of the gate ledger
  for the unprivileged collector.
- `context.mjs`: the trusted context (`/etc/aukora-aura/context.mjs`). It imports
  `collect-gate.mjs?context` as a separate module instance, which avoids the
  top-level-await import cycle with the CLI entrypoint.
- `verify.mjs`: the cold verifier (fresh process, fresh snapshot).

INTERIM, not custody: the owner and controller keys are generated on the pilot
(root-only). The owner subject is derived from the INTERIM owner key and must be
replaced by the Touch ID owner root (G) when native custody lands. Anchors are
recorded by root and are not an independent witness. The collector observes only
and grants no authority.
