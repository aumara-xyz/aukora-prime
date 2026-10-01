# H-only app preview staging

`preview_stage.py` is a standalone standard-library source artifact for H's approved app-only staging. It never starts the candidate, imports candidate code, changes users/groups, writes C/D configuration or secrets, creates units, changes PostgreSQL, or stops a process. It can prepare a root-owned complete release, pinned Node binary, launcher, independently retained external manifest and a fresh private app-state child. Worker installation guards remain held in `pilot.py`.

H reported the parent setup executed successfully with app UID997/GID987 and supplementary memory IPC GID983. Apply checks those exact identities/groups, existing root:root0711 state/run parents and app:app0700 app parent. It preserves them. Root code/config parents must be canonical root:root0755 with protected ancestors; existing conflicts are refused. No existing manifest, release destination or preview state is replaced or repaired. Partial staging requires scoped reconciliation; no automatic retry/cleanup is attempted.

Before root execution, H stages the script and spec in a root-owned protected directory and uses a trusted outer tool to check their final bytes against independently retained SHA-256 values. The script's internal hashes are drift checks, not an independent code-review/approval mechanism. Use isolated Python (`-I -B`) and a clean environment to prevent user/candidate Python import shadowing.

Standalone source SHA-256:

```
5928b8c09090f1033bc8c1c3b0811fbbdf350347cad5cb12189f91e1f1d9cc07
```

The closed staging spec has exactly:

```
{
  "schema": "prime-preview-stage-v1",
  "release_source": "operator-source:redacted-private-checkout",
  "release_digest": "d0e98c5fdc5b128daad81f9bf11633573b1427b9a503930acbb40fdf40f769f0",
  "node_source": "operator-tool:node-v24.11.1-linux-x64/node",
  "node_sha256": "<H independently retained Node SHA-256>",
  "manifest_source": "/absolute/operator-controlled/preview-deployment.json",
  "manifest_sha256": "<H independently retained manifest SHA-256>",
  "app_entry_sha256": "<H independently retained harness/cli.mjs SHA-256>"
}
```

Angle-bracket values are required operator inputs; this example intentionally cannot execute. G has not materialized these Linux paths on the Mac or constructed H's final spec. H recomputes the full physical tree with a trusted independent outer evaluator and retains the given expected hash before copying. The helper hashes every regular file, executable-bit class and contained relative symlink target, checks stable descriptors, rejects hardlinks/escaping links/privileged or mutable file modes, copies without following links, and rehashes the staged physical closure. No dependency bytes are omitted. Limits: 200,000 physical entries (including directories), 2GiB cumulative physical bytes, 65,536-byte release metadata matching the reviewed H boot helper. Larger inputs refuse; a limit is never treated as a successful partial hash.

The independently pinned manifest is closed and remains outside the candidate:

```
{
  "version": 1,
  "kind": "prime-preview-deployment/v1",
  "source_commit": "0873f6a2bf36de9eb1762e626d91a014e4cca4a2",
  "release_dir": "/opt/aukora-prime/preview/d0e98c5fdc5b128daad81f9bf11633573b1427b9a503930acbb40fdf40f769f0/release",
  "release_digest": "d0e98c5fdc5b128daad81f9bf11633573b1427b9a503930acbb40fdf40f769f0",
  "ui_integrity_sha256": "8a1c3a302abf3b502b9af6dbbae9e5296f9cd341e226e43f7ae103d0fc16bf2a",
  "qualification": "PENDING"
}
```

These values are H-relayed build inputs, not a G verification of the Linux build or installation. H retains/hash-verifies actual manifest bytes independently; the artifact never calculates a candidate digest and feeds it back as authority. `prime-release.json`, `prime-ui-integrity.json` and the app entrypoint are cross-bound to that manifest before root writes. On success the manifest is root:root0644 at `/etc/aukora-prime/preview-deployment.json`; only root can change its protected parent.

After trusted outer staging, use the exact pinned source and spec for `plan`/`verify`, then the separately authorized H mutation phase:

```
/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B /absolute/root-protected/preview_stage.py apply --spec /absolute/root-protected/preview-spec.json --expected-spec-sha256 <reviewed-spec64hex> --expected-script-sha256 5928b8c09090f1033bc8c1c3b0811fbbdf350347cad5cb12189f91e1f1d9cc07
```

The apply phase atomically publishes only fresh no-replace destinations. New state inode is captured under root ownership, moved into the app-owned parent through directory descriptors, then changed to app997:9870700 through that held inode. Root performs no subsequent reads/writes through the app-writable child. Actual staging has not been run by G.

The launcher is root-owned0755 in the digest-named preview directory, checks UID997/GID987, clears the environment, and invokes only the copied absolute Node and release entry with external `--deployment-manifest`, explicit `--release-dir`, fresh `--state-dir` and localhost preview port18731. It matches the interface inspected read-only at H source `fbb943935b1e8c6ecb2f4c5f49c044930cffaea9` (CLI/manifest helper last change500191c); H must confirm the newly compiled0873 entry's independently pinned interface. H handles port availability and any separate approved app launch; the artifact never kills an existing listener or launches automatically.

Launcher file/heap limits are not cgroup, network or provider-cost enforcement. The harness currently scrubs child environment, so the parent NODE_OPTIONS value does not prove child memory limits. H retains the separate approved process/resource observations/control before launch. Runtime, namespace, networking, core availability and all G1–G6 acceptance remain PENDING; no same-UID fixture is OS isolation evidence. Core capabilities remain unavailable under the app-only scope.

Disposable checks:

```
python3 -I -B packages/ops/pilot/check_preview_stage.py
```

They cover closed external pins, metadata/source/UI binding, digest compatibility, physical dependency/link/mode coverage, finite bounds, no-replace/conflict behavior, launcher identity/arguments/environment, and no staging/boot side effects in source phases. G made no SSH/VM mutation, app start, paid call, key migration, private import or publication.
