# Pre-Node gate package custody — SOURCE-ONLY

`gate-bootstrap.py` is the reviewed standalone launcher source. The operator's installed copy is `/usr/local/lib/aukora-boundary/gate-bootstrap`; services and operators invoke it with `/usr/bin/python3 -I -S`. It verifies the complete fixed `/opt/aukora-boundary-gate` package and protected public signer registry before starting `/opt/aukora-node/bin/node` for the gate, approval or release-floor role. This source addition does not install, configure, start, or qualify a host.

The manifest is `/etc/aukora-boundary-gate/gate-package-manifest.json`, outside the package. Its closed `aukora-gate-package/v1` schema contains the fixed package root and `bin/gate.mjs` entry, every regular package file's SHA256, and exactly one `external_files` SHA256 entry for `/etc/aukora-boundary-gate/signer-epochs.json`. The inventory must include `bin/gate.mjs`, `bin/plugin-set-approval.mjs`, `bin/release-floor.mjs` and `package.json`. Missing, added, removed, or modified files refuse before Node starts. The inventory also includes every first-party transitive helper, all present `host/aura/**` source including `trusted-context.mjs`, and the source check files. Check files are hashed as data; none executes during boot. Manifest keys cannot name absolute or escaping package paths, aliases, candidates, or additional external files. Duplicate JSON keys refuse.

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

## Focused source verification

```sh
/usr/bin/python3 -I -S packages/boundary-gate/host/install/check-bootstrap.py
```

The regression uses actual tiny files, opened reads, symlinks, hardlinks, a FIFO, and marker execution, with explicitly synthetic root metadata. The marker dispatcher runs a tiny Python fixture stored at the gate entry name; it proves refusal precedes dispatch without relying on an installed Node. Separate mocked `main()` checks inspect each fixed Node entry, arguments, environment and refusal ordering; `check-package` success and hash refusal both leave the exec recorder and marker untouched. It also checks complete inventory, descriptor identity, read mutation/short reads, signer format, external hashes, finite role/action arguments, preview rejection, disabled Aura launch and deterministic staging output. Three in-memory single-guard mutants disable the hash, inventory and preview-environment guards individually; their specific regressions must fail, with actual trap dispatch only in the hash/inventory mutants. No mutation selector exists in production. These checks establish source behavior only. Real installed ownership, interpreter/Node launch, service behavior, public context custody, signer enrollment and owner effects remain UNPERFORMED.

All files in this directory are first-party `AGPL-3.0-or-later` source. No dependencies, third-party implementations or generated keys are added.
