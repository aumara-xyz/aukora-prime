# Pre-Node gate package custody — SOURCE-ONLY

`gate-bootstrap.py` is the reviewed standalone launcher source. The operator's installed copy is `/usr/local/lib/aukora-boundary/gate-bootstrap`; services and operators invoke it with `/usr/bin/python3 -I -S`. It verifies the complete fixed `/opt/aukora-boundary-gate` package and protected public signer registry before starting `/opt/aukora-node/bin/node` for the gate, approval or release-floor role. This source addition does not install, configure, start, or qualify a host.

The manifest is `/etc/aukora-boundary-gate/gate-package-manifest.json`, outside the package. Its closed `aukora-gate-package/v1` schema contains the fixed package root and `bin/gate.mjs` entry, every regular package file's SHA256, and exactly one `external_files` SHA256 entry for `/etc/aukora-boundary-gate/signer-epochs.json`. The version-2 schema below adds pinned `launcher` and `owner_key` profiles under the same external manifest. The inventory must include `bin/gate.mjs`, `bin/plugin-set-approval.mjs`, `bin/release-floor.mjs` and `package.json`. Missing, added, removed, or modified files refuse before Node starts. The inventory also includes every first-party transitive helper, all present `host/aura/**` source including `trusted-context.mjs`, and the source check files. Check files are hashed as data; none executes during boot. Manifest keys cannot name absolute or escaping package paths, aliases, candidates, or additional external files. Duplicate JSON keys refuse.

The package, bootstrap, Node binary, manifest and public signer registry must be regular single-link files under directories owned by root with no group/other write access, readable by the gate service user. Typical protected public data modes are root-owned `0755` directories and `0644` files; the Node executable also needs execute permission. Every ancestor is checked from `/`, opened without following links, and checked again through its descriptor. Package symlinks are rejected even when their target stays within the package; absolute, escaping and dangling links, hardlinks and special files also refuse. File hashing uses bounded reads from checked no-follow descriptors, with identity and size checks before and after reading. The whole installed package must be complete: generating an inventory from a sparse development checkout is insufficient.

The public signer registry has at most 64 rows and 16,384 bytes. Epochs are consecutive starting at 1; each full `gate_pubkey_sha256` occurs once. The Node verifier independently binds the signer's full public-key hash to its registered epoch. A new root-reviewed registry requires a corresponding manifest update. The manifest contains public hashes and paths, never private keys.

The gate role accepts `serve` and the reviewed gate options. `--home`, `--run`, `--target-root`, and optional `--releases-root` have fixed installed paths. `--gid` is required and positive; port and group numbers are bounded decimal integers; time zones use a bounded path-like grammar. `--owner-page` is an explicit boolean switch. The `floor` role maps only `show`, `check` and `migrate-clock-floor` to `bin/release-floor.mjs`; the `approval` role maps only `show`, `raise`, `install`, `migrate-clock-floor` and `recover-cache` to `bin/plugin-set-approval.mjs`. Each action has its own finite option set. Release paths match `/opt/aukora-genesis/release-<7 lowercase hex>`; approval state paths match `/etc/aukora-approvals/<40 or 64 lowercase hex>/state`, with install, migration and recovery output ending in `/gate-state`. Floor, socket and target roots are fixed; operation digests are 64 lowercase hex and repin is an explicit boolean. The bootstrap changes no UID or authority; the existing operator entrypoints retain their root/action and signed-proof requirements.

Approval `migrate-clock-floor` is the explicit operator route for an actual signed owner-log row matching the same legacy floor's release, record and receipt timestamp; its entrypoint migrates that floor and publishes the cache. Approval `recover-cache` requires the exact current version-2 floor proof and publishes the protected cache without advancing or rewriting the floor. Both use the install action's bounded launch flags and require the fixed-pattern output path. They do not change ordinary install's refusal of equal or older approvals. The bootstrap checks custody and the closed launch interface; proof verification and durable publication remain the operator entrypoint's responsibility.

Unknown or duplicate options, extra positionals, config paths, Node flags and unsafe-preview flags refuse before Node. Unsafe-preview configuration or environment keys refuse even when their value is false. The Node environment is newly constructed with only fixed `PATH`, `HOME`, `LANG` and `LC_ALL`, and its working directory is `/`. No `NODE_OPTIONS`, `NODE_PATH`, loader environment or inherited application configuration reaches Node. All roles use the same complete package and registry verification before their respective fixed Node entry executes.

The separate `check-package` action accepts no flags or positionals. It performs the same bootstrap, runtime, complete package, manifest and signer-registry checks, prints only `PACKAGE_VERIFIED`, and exits successfully without starting Node. A service can run this first, before a direct Node package self-check. Protected nonroot custody remains in force between these checks; the trusted root updater must remain quiescent until startup completes.

Aura launch is unavailable: the explicit `aura` action and every Aura context refuse `aura-context-unconfigured` before Node. A gate launch does not interpret an Aura context or execute Aura code. A future Aura launcher needs a separately reviewed fixed entry, closed protected context and complete pinned transitive import closure, including any module outside the gate package. Merely hashing Aura source in the gate inventory does not qualify its authority context or execution. This keeps gate custody independent of an unfinished Aura integration while preserving the same source-file custody for present Aura modules.

## Operator staging recipe

Review and materialize the complete package plus the exact public epoch registry in a staging directory. Run the generator from the reviewed source with an isolated interpreter; replace these placeholder staging paths with that materialization:

```sh
/usr/bin/python3 -I -S packages/boundary-gate/host/install/generate-manifest.py \
  --package /operator-staging/gate-package \
  --signer-epochs /operator-staging/signer-epochs.json \
  --output /operator-staging/gate-package-manifest.json
```

The generator hashes all regular staged package files, validates the public epoch registry, sorts mapping keys and writes deterministic JSON. It creates a new output file outside the package, refuses to overwrite existing files, and performs no installation or permission changes. Its staging paths are generator inputs only; the production launcher has no path, UID, fixture, context or manifest overrides. The operator must review the resulting inventory and separately materialize the reviewed bootstrap, package, external manifest and registry at their fixed protected paths. Do not copy an unchecked candidate into the trusted package to make the checks pass.

### Version-2 manifest: launcher and owner-key profiles

Supplying `--owner-key` selects the closed `aukora-gate-package/v2` schema and makes `--launcher-checkout` mandatory. The v2 manifest adds a `profiles` object beside the v1 package inventory. The `launcher` profile names the fixed root `/opt/aukora-genesis/src` and exactly the six pinned launcher inputs — `scripts/launch-dsh.py`, `scripts/genesis-check.mjs`, `scripts/lib/artifact-integrity.mjs`, `scripts/lib/release-strip.mjs`, `scripts/artifacts-coverage.json` and `upstream-dsh.json` — each hash-pinned in the reviewed bootstrap source. The `owner_key` profile names the fixed root `/opt/owner-key` and its closed eleven-file inventory (`PROVENANCE.json`, `README.md`, `TRUSTED-PATH.json`, `package.json`, the five `checks/` files, `src/authorization.mjs` and `src/index.mjs`), with the two `src/` files hash-pinned in the bootstrap source. A v2 manifest with a missing, added, renamed or modified launcher or owner-key file refuses before Node; the pinned entries refuse on any byte change, so a v2 manifest can only describe the exact reviewed launcher and owner-key sources.

Every v2 input must be a staged copy outside every installed root: naming an installed path (`/opt/aukora-boundary-gate`, `/opt/owner-key`, `/opt/aukora-genesis/src`, `/opt/aukora-aura`, the bootstrap or Node directories) refuses `staging-installed-path`, and no staged root may contain another staged root or the output (`staging-profile-overlap`, `manifest-inside-profile`). Stage the launcher as its own six-file checkout layout, not the whole source tree. The working recipe, run as root with the reviewed source (RAN on the pilot for the r3 package; printed `SOURCE-ONLY staged manifest: 78 package files; no installation performed`):

```sh
install -d -m 700 /root/stage-launcher/scripts/lib
for f in scripts/launch-dsh.py scripts/genesis-check.mjs \
  scripts/lib/artifact-integrity.mjs scripts/lib/release-strip.mjs \
  scripts/artifacts-coverage.json upstream-dsh.json; do
  install -m 644 "/reviewed/checkout/$f" "/root/stage-launcher/$f"
done
install -d -m 700 /root/stage-owner-key
cp -a /opt/owner-key/. /root/stage-owner-key/
install -m 600 /etc/aukora-boundary-gate/signer-epochs.json /root/stage-signer-epochs.json

/usr/bin/python3 -I -S packages/boundary-gate/host/install/generate-manifest.py \
  --package /operator-staging/gate-package \
  --signer-epochs /root/stage-signer-epochs.json \
  --owner-key /root/stage-owner-key \
  --launcher-checkout /root/stage-launcher \
  --output /root/gate-package-manifest.json
```

Copying `/opt/owner-key` reads public package source only; the owner key's private material is never an input. The generator then writes one deterministic v2 manifest whose package, launcher and owner-key inventories the bootstrap verifies together at every boot. Install the manifest at the same fixed external path as v1; the installed launcher checkout and owner-key package must satisfy the same root-owned, single-link, no-group/other-write custody as the gate package itself.


The installed gate service invocation is:

```text
/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap serve --home /home/aukora-gate --run /run/aukora-gate --target-root /var/lib/aukora-boundary/targets --port 17792 --gid <skgate-gid> --time-zone Asia/Makassar
```

Release-floor service checks and interactive operator actions use the fixed role interface, for example:

```text
/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check --release-dir /opt/aukora-genesis/release-<7hex> --approval-state-root /etc/aukora-approvals/<40-or-64hex>/state
/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap approval show --release-dir /opt/aukora-genesis/release-<7hex>
```

Before a package self-check that starts Node directly, the first service precheck is:

```text
/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package
```

The service manager and interpreter must start from a root-controlled environment that excludes `LD_PRELOAD`, `LD_LIBRARY_PATH` and Python startup hooks. Cleaning the child environment cannot undo injection into Python before this source begins executing. `-I -S` excludes Python environment, user-site and site startup hooks. The fixed distro Python path may be a root-managed symlink; the installed interpreter, standard library, native system loader, reviewed Node binary, root-owned bootstrap and service definition are external trust anchors. The bootstrap does not pin itself into its own manifest. A malicious root updater can replace those anchors or race the handoff to Node. Operator updates must quiesce the service, review and materialize one coherent package/registry/manifest set, and restart through this launcher. The hash check closes nonroot modification under protected ancestors; it does not constrain a trusted root updater.

## Numbered pilot migration runbook — operator actions, not an installed result

This procedure is for the existing pilot, without enrollment, key generation, a new release or an owner-approval bypass. Installation and service actions belong to the authorized operator. A deployment pause also pauses these actions. The reported starting point is `release-5f0601f`, gate fingerprint `6cdce2bbeb7b725c`, `skgate` GID `1003`, and applied plugin-set ledger sequence `115`. These are reconciliation inputs, not observations made by this source change. Verify them against the actual installed public key, signed row, target and legacy floor before proceeding. If a newer plugin-set approval has replaced sequence 115, stop and reconcile its exact proof; do not edit the floor to fit this recipe.

1. **Record and back up the coherent starting state.** Record the installed gate package, bootstrap, Node identity, public signer registry/manifest if present, both service units, `/etc/aukora-genesis/release.env`, the exact current approval-state directory and `/etc/aukora-approvals/release-floor.json`. Record hashes and file metadata. Use a fresh root-owned `0700` backup directory; keep approval-cache and floor bytes together with the release configuration. Never print desktop tokens or private configuration. This backup does not include, restore or replace the gate's private key or live database. Stop Genesis before changing its admission dependencies. Quiesce the gate while replacing its package and units; coordinate other gate clients separately. Preserve the existing key and database in place. Record whether the floor is still the original clock-based floor so rollback can distinguish steps 8A and 8B below.

2. **Stage the complete reviewed source and public epoch registry.** Materialize one approved revision's entire boundary-gate package, including files absent from a sparse development checkout. Preserve notices and the reviewed Node binary at `/opt/aukora-node/bin/node`; this procedure does not upgrade dependencies. Obtain the existing gate's *public* Ed25519 SPKI through the independently checked installed public-key channel. Hash its DER bytes, require the first 16 hex characters to equal `6cdce2bbeb7b725c`, and independently compare the complete 64-character result. Do not hash a PEM text serialization or read a private key. The epoch registry for this existing key is:

   ```json
   {"version":1,"kind":"aukora-signer-epochs/v1","epochs":[{"epoch":1,"gate_pubkey_sha256":"<verified full SHA256 of the existing public SPKI DER>"}]}
   ```

   The angle-bracket value is a placeholder, not valid installed JSON. No full key hash is invented here. A different key, an already provisioned epoch history or a missing independent pin requires reconciliation rather than replacing that history. Generate a new manifest outside the staged package with the generator command above, using this exact public registry. Review every path/hash; the only external file allowed is the signer registry. The generator does not authorize its own input.

3. **Install the coherent protected package while services are quiescent.** Install the staged package at `/opt/aukora-boundary-gate`, the reviewed `gate-bootstrap.py` at `/usr/local/lib/aukora-boundary/gate-bootstrap` as root-owned `0755`, and the registry and generated manifest at their fixed `/etc/aukora-boundary-gate` paths as root-owned `0644`. Require root-owned, non-symlink ancestors with no group/other write bits, normally `0755`, and single-link regular files. The fixed Node executable needs execute permission and the same protected ancestry. Replace the package as a complete set; do not leave an old helper or an extra candidate file behind. Keep the root updater quiescent through validation and startup. Install the two reviewed unit files under `/etc/systemd/system`; substitute only `SKGATE_GID` with the verified existing value `1003` in the gate unit. Retain its gate UID and primary `skgate` group. The Genesis unit must retain `--foreground`, the approved-record and approval-state arguments, and all three ordered prechecks. Neither unit accepts preview flags. Both must remove the listed Node, Python and dynamic-loader preload variables *before* Python runs. Then reload unit definitions, without starting Genesis yet.

4. **Check custody, then restart only the gate.** From a clean operator environment, run:

   ```sh
   /usr/bin/env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C \
     /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package
   ```

   Require exit 0 and exactly `PACKAGE_VERIFIED`. This action starts no Node process. Inspect the installed unit bytes and ownership, then restart `aukora-boundary-gate.service`. Verify the actual service UID/group, fixed bootstrap/Node command and absence of injected startup environment. Through the existing protected channels, verify the unchanged full gate public-key identity and whole-ledger result. The upgraded owner-log response must contain the original raw signed row for the latest applied plugin-set target. Starting a gate appends ordinary lifecycle evidence; it must not enroll a new key or manufacture a replacement apply row.

5. **Migrate the existing floor with its exact existing proof.** Read the root-protected release configuration as data. Require its release path to be `/opt/aukora-genesis/release-5f0601f`; retain its existing full approval-root component and record hash. Verify the legacy floor names the same release, record and receipt timestamp, and that the latest owner-log apply row is sequence `115` for this exact canonical target. Its full SPKI hash must be epoch 1 in the protected registry. Run the command below as the root operator, substituting only the verified existing approval-root component:

   ```sh
   /usr/bin/env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C \
     /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap \
     approval migrate-clock-floor \
     --release-dir /opt/aukora-genesis/release-5f0601f \
     --out /etc/aukora-approvals/<existing-40-or-64-hex>/state/gate-state
   ```

   Require exit 0, `INSTALLED` with `ledger seq 115`, and `FLOOR` with `signer epoch 1, signed seq 115`. Inspect the protected floor: kind `aukora-release-floor/v2`, the unchanged full release/record, epoch 1, sequence 115, the exact full signer hash and signed ledger hash, with legacy history retained. This command verifies the signed proof itself and writes the floor before publishing the approval cache. Do not use `install` to migrate a legacy floor, change timestamps, add `--repin`, delete a lock, or restore a saved floor to make a refusal disappear. The separate `floor migrate-clock-floor` command requires an already complete ordered approval cache; it is not a substitute for this cache-producing migration.

6. **Verify exact-floor admission and start Genesis.** Run the same clean bootstrap as `aukora-host`, with the exact existing approval root:

   ```text
   /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check --release-dir /opt/aukora-genesis/release-5f0601f --approval-state-root /etc/aukora-approvals/<existing-40-or-64-hex>/state
   ```

   Require exit 0 and `release-floor: OK` naming the current full release and `(signer epoch 1, ledger sequence 115) = floor` with the same tuple. Check the record hash in `release.env` against the verified current record. Start `aukora-genesis.service`. Observe actual success of `check-package`, the gate self-check and the exact-floor precheck, then the foreground process under the expected host UID. An active service alone is insufficient: verify the installed unit/launch bytes, actual release directory, process arguments and the actual application response. Preserve failures. Installed source custody, signing-key provenance and loaded runtime identity are separate observations; this runbook supplies none by itself.

7. **Perform the explicit Mac legacy-false edit separately.** The production desktop intentionally refuses an own `allowUnapproved` field even when false. With the desktop stopped, privately back up the explicitly named existing `~/.aukora-nebius/electron-userdata/config.json` in a current-owner `0700` directory as a `0600` single-link file. Do not include that file or backup in a public artifact. Use its canonical absolute path with the reviewed read-only helper:

   ```text
   node apps/aukora-desktop/migrate-preview-config.mjs --config <canonical-absolute-private-config-file>
   ```

   `preview-config-migration:eligible` means only that one own top-level literal `allowUnapproved:false` field can be removed. The helper writes nothing, discovers no paths and prints no configuration values. Manually remove only that field and its necessary comma; preserve every other setting and raw value byte, including any launch token. Privately check the remaining settings against the backup. Keep file `0600`, direct parent `0700`, current-owner, canonical and single-link. Run the helper again and require `preview-config-migration:unchanged`. A true/nonboolean legacy value, duplicate key or any `unsafePreviewAllowUnapproved` field refuses and needs separate operator review; never rename or convert the old field into a preview waiver. Launch the reviewed production desktop only after its configured approval path verifies. If the edit or desktop verification fails, keep it stopped and restore the private backup only alongside the corresponding old desktop code; restoring the old config to new code correctly restores the refusal. No gate-floor rollback is caused by this Mac edit.

8. **Use the rollback branch matching the observed durable state.**

   **8A — floor migration has not committed:** stop affected services. Verify the floor is byte-identical to the recorded pre-migration floor and no newer approval has been installed. Restore the coherent backed-up code, bootstrap, units, public configuration and matching approval-cache files; keep the existing gate database/key in place. Reload units, verify the restored public bytes and original proof, then restart the old gate and original Genesis release through the restored admission path. Do not restore a stale floor if it has changed, or mix a new unit with an old verifier. If the current floor cannot be established, stop and reconcile rather than taking this branch.

   **8B — version-2 floor migration has committed:** retain the current floor and its history. Do not restore a clock-based verifier/floor, reset epochs, unconsume evidence or delete the floor/lock. Stop Genesis while repairing the coherent version-2 package/registry/manifest/units. If publication was interrupted, the approved root operator may use `approval recover-cache` with the same `--release-dir` and `--out` as step 5; require `FLOOR unchanged` and rerun step 6. Recovery requires the actual current target, latest apply row and current gate key still to furnish the exact floor proof. A changed target/key, later approval, orphan temporary file, crashed lock or unavailable exact proof requires manual reconciliation and continued unavailability, not a retry loop or stale-lock stealing. Keep an independently checked working version-2 package after the first successful migration so later code repairs can restore that package while retaining the current floor. There is no safe fallback to the old clock verifier after this first transition. To return the *application release* to earlier bytes, raise a fresh canonical plugin-set request, let the owner review the `ROLLBACK` card, install its genuinely newer signed approval through this version-2 bootstrap, update the exact root-protected release configuration, and verify step 6 for that approval. A source/code backup is never permission to lower the admission floor.

9. **Record the outcome and remaining gaps.** Record actual commands, exit statuses, public hashes, floor tuple, unit/PID/UID observations and application verification separately. Keep all refusal and crash evidence. Run mutation probes only in disposable source fixtures, not against live protected state. Aura remains `aura-context-unconfigured` in this bootstrap: the separate interim collector's run does not complete the protected pin/load interface described below. This procedure does not enable owner-key custody, OpenShell containment, private memory, paid inference or any other unfinished join.

## Aura pin/load interface and precise remaining allocation

D's selected citation repair is `c3f07af37d8e5dd291a655d0ba22f67115288d36` on `b549936f5617181bad1dfb6db9cd267798a5d148`, changing only `scripts/aura/collect-gate.mjs` and its collector check. The separately delivered import inventory pins dependency revision `6f9e6f433924800e365c7e400a6c4bdb30bcdc79`: 27 runtime-static modules, with the complete 29-module Noble vendor trees plus three licenses and two upstream manifests preserved. These are source pins, not an installed manifest or authority context. Compare integrated postimages before selecting them; do not infer current-main or installed equality.

The proposed fixed package paths are `host/aura/trusted-context.mjs` and `host/aura/collector-entry.mjs`, exposing only `collect` and `verify`, with no caller module-path argument. The context must import the same collector module used to create its branded codec. A module exporting `collectorContext` is executable code, even if its export is an object; it and its complete import closure must be protected and hashed before Node. The current manifest permits only the public epoch registry outside the gate package. An outside Aura closure therefore needs a separately allocated fixed protected root and reviewed complete inventory; adding a dynamic import or extra manifest exception is not this interface's implementation.

The missing allocation is the actual fixed context/entry/provider source and its complete selected closure, independently trusted source/controller/recipient public pins and anchors, the metadata for existing scoped-author credentials, collector UID/access, a real note-to-source association, and the trusted host lifecycle plus retained read-grant seam. The separately reported interim pilot context and keys do not supply this reviewed context. No credential bytes or new keys are requested by this source handoff. Until these inputs and ownership are assigned, the fixed Aura role remains disabled.

`createCollectorCitationReader(context,{isLive,hasReadGrant})` requires synchronous trusted predicates bound to the existing lifecycle and the same retained owner/read grant; exact `true` is checked before and after awaited reading. Unload must call the reader's permanent `dispose()` latch. Publish only its `readCitation` method. Both methods of an eventual `aura.records` provider must independently check lifecycle and that same grant on every invocation, including cached Cordis handles and after awaits. A replacement grant does not revive an old handle. `referenceForRecord` must use a real trusted note/source association or return unavailable; a remembered ID, journal head or session sequence cannot fabricate that association. Installed cold-read/restart/deduplication, provider unload/revoke and actual custody remain separate unperformed gates.

## Focused source verification

```sh
/usr/bin/python3 -I -S packages/boundary-gate/host/install/check-bootstrap.py
```

The regression uses actual tiny files, opened reads, symlinks, hardlinks, a FIFO, and marker execution, with explicitly synthetic root metadata. The marker dispatcher runs a tiny Python fixture stored at the gate entry name; it proves refusal precedes dispatch without relying on an installed Node. Separate mocked `main()` checks inspect each fixed Node entry, arguments, environment and refusal ordering; `check-package` success and hash refusal both leave the exec recorder and marker untouched. It also checks complete inventory, descriptor identity, read mutation/short reads, signer format, external hashes, finite role/action arguments, preview rejection, disabled Aura launch and deterministic staging output. Three in-memory single-guard mutants disable the hash, inventory and preview-environment guards individually; their specific regressions must fail, with actual trap dispatch only in the hash/inventory mutants. No mutation selector exists in production. These checks establish source behavior only. Real installed ownership, interpreter/Node launch, service behavior, public context custody, signer enrollment and owner effects remain UNPERFORMED.

All files in this directory are first-party `AGPL-3.0-or-later` source. No dependencies, third-party implementations or generated keys are added.
