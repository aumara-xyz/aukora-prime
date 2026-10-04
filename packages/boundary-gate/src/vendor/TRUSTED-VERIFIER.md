# Trusted operator verifier — source acceptance

Both operator entrypoints use Node builtins until their bootstrap verifies the fixed `/opt/aukora-boundary-gate` entrypoint, protected ancestors, and closed `trusted-verifier-pins.json`. The five pinned buffers are canon, floor, operator-data, retained renderer, and signer-epochs. All hashes are checked before any buffer executes. Executable buffers use data URLs; no checked pathname is imported again. Candidate releases supply JSON data only and cannot supply verifiers or helpers.

The gate owner log exports `signed_entry` with the original SQLite TEXT detail. The ordered verifier checks the unchanged receipt-v2 signature, exact signed row/effect/detail binding, ledger body hash and Ed25519 row signature. The full SPKI hash resolves a unique epoch in the protected public `/etc/aukora-boundary-gate/signer-epochs.json`. Epochs are consecutive starting at 1, each key occurs once, and no timestamp orders admission. The root operator controls this public registry; source validation does not constrain a malicious root updater.

The v2 floor orders `(signer_epoch, ledger_seq)`. Ordinary install refuses equal or older proofs, including replay. Boot requires the exact committed tuple, key, ledger hash, record and release. A newer proof with a stale floor is an incomplete installation and refuses. Floor replacement rereads under an exclusive root-protected lock, syncs the file, renames atomically, then syncs the directory. A crashed lock is retained as an operator reconciliation fence; there is no automatic expiry or stealing.

Install commits the floor before publishing approval and pin files. Cache publication and reads validate protected ancestors, regular single-link files and no-follow descriptors; publication syncs the file and directory. Interruption can make the release unavailable, but cannot admit a release above an uncommitted floor. Concurrent stale cache publication likewise causes exact-proof boot refusal.

Two explicit root actions provide bounded completion:
- `approval recover-cache` obtains and verifies the actual owner-channel signed proof, requires exact equality with the committed v2 floor, and publishes cache files without rewriting or advancing the floor. It refuses another sequence, epoch, release or record.
- `approval migrate-clock-floor` migrates a v1 floor only when the actual signed approval matches its current release, record and receipt timestamp. It uses no clock ordering, preserves history, and cannot reset the floor. The separate `floor migrate-clock-floor` action requires an already complete installed proof.

The reviewed pre-Node launcher source is `host/install/gate-bootstrap.py`; operator-installed invocations use fixed Python with `-I -S` before Node. Its external full-package manifest covers entrypoints and transitive package bytes, and pins the public epoch registry. See `host/install/README.md` for exact source staging and fixed role grammar. Gate, approval and floor roles have no arbitrary entry/import/environment override. Aura launch remains unavailable until its separate fixed context and import closure are reviewed.

The installed Python, standard library/native loader, Node executable, root-owned bootstrap, service definition and root updater are external trust anchors. JavaScript refusal cannot undo a Node preload that already ran. The service removes preload variables before the pre-Node launch, and the bootstrap constructs a clean Node environment. Interactive operators must use the same reviewed bootstrap rather than an injected interpreter environment.

Focused commands:

```sh
node packages/boundary-gate/src/vendor/check-trusted-verifier.mjs --mutations
node packages/boundary-gate/src/vendor/check-ordered-approval.mjs --mutations
node packages/boundary-gate/src/vendor/check-sequence-floor.mjs --mutations
node packages/boundary-gate/src/vendor/check-preview-policy.mjs
node tests/desktop-first-run.test.mjs
/usr/bin/python3 -I -S packages/boundary-gate/host/install/check-bootstrap.py
```

These are source checks. CLI/module buffers use synthetic root metadata and Unix replies; malicious candidate/helper files genuinely write markers if executed. The gate test uses actual disposable SQLite, synthetic Ed25519/HMAC and a declarative store, not an authenticated owner socket or human enrollment. Floor metadata and race fixtures are synthetic. Preview checks exercise argument/configuration source only. No check qualifies an installed Linux host, real owner custody, loaded runtime bytes, OpenShell enforcement or a complete release. Shared capability claims remain with the integrator.

First-party license and original source hashes: `trusted-verifier-provenance.json`, AGPL-3.0-or-later.
