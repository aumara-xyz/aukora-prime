# Prime ops

Source and disposable tools only. No app is installed or activated by this package.
Node 22+ and Python 3.9+ standard library are sufficient; the production runtime/build
versions must be pinned by A/H. There are no npm dependencies or sibling-repo imports.

Root A/H forwards `./prime check G1` to:

```sh
node packages/ops/cli.mjs check G1 --root . --evidence-dir /tmp/prime-evidence
```

For a protected release with external private runtime state, add the explicit physical
absolute `--state-dir /named/private/state` and `--release-dir /named/frozen/release`.
Both named directories must be canonical, with no symlink aliases; state must be
private and owned by the evaluator's current UID. The runner forwards only these
named arguments through its explicit evaluator Node/status call and records the
identical argv in evidence. Returned running `release_dir` must exactly match the
explicit release input. Omitting both options preserves the default status call.
No environment/PATH override, state symlink or directory discovery is used.

Optional disposable DSH launch handshake: add `--ui-launch-access true`. The runner
opens only the status-named private `launch-url.json` under the explicit state directory
(or `.prime-state` when state is omitted), checks owner/mode,
PID and the sanitized localhost origin, requests the token URL with manual redirects,
keeps its host-only HttpOnly/SameSite=Strict cookie in memory, and then requests the
clean base URL. It never prints/persists the raw launch URL, token or cookie. An
explicit alternate private file can be selected with `--ui-access-file /named/private/launch-url.json`
and must match status; when state is explicit it must exactly equal
`<state-dir>/launch-url.json`. File reads are capped at16KiB with descriptor/file/parent
identity checks before and after; oversized or changing files refuse. The launch PID
must be a positive safe integer matching the observed status PID. No directory scan
or credential-store import occurs. This is
DSH disposable launch access, not owner-key/passkey authentication; G2 stays PENDING.

PASS exits 0, FAIL 1, PENDING 2. G1 reads status through the equivalent
`process.execPath root/harness/cli.mjs status [--state-dir NAMED] [--release-dir NAMED] --json`
call, so the scrubbed child PATH
need not contain the approved user-local Node binary. It observes the PID, recomputes
the reported release digest and fetches only the local HTML endpoint.
Evidence records the evaluator Node executable/version and exact status argv.
It reports the running observations separately from the complete acceptance gate.
Source path/disk hashes are host observations, not loaded-memory attestation.
No status flag or installation marker alone passes G1. Unsupported/unconnected gates
remain PENDING. Source-stage G1 does not boot/stop a process or alter candidate policy.
The current generic probes report individual comparisons; every complete gate remains
PENDING until the integrator connects its full gate-specific evaluator. A label saying
actual adapter and a candidate JSON observation alone cannot promote a gate to PASS.

For independently evaluated acceptance, copy this package to an evaluator directory
outside the frozen candidate. Retain `evaluator-digest` externally and supply
`--expected-evaluator-digest`, `--release-dir`, `--expected-candidate-digest`,
`--probe-plan` and `--expected-probe-digest`. The externally pinned `prime-probes-v1`
JSON lists actual adapter entrypoints, args, expected exit code and exact field
assertions for the cases in `gates.mjs`. Each probe must use
`qualification: "actual-prime-adapter"`. Toy observations do not qualify the adapters.
Candidate-provided verdict fields are rejected. Plans and evaluator code are checked
again after probes. There is no candidate callback that can redefine assertions.
Same-UID writable evaluator/policy is NOT an independent enforcement boundary;
separate ownership/read-only mounts still need approved host setup. Gate prerequisites
and real UI/source baseline, confinement, approval ceremony and memory recovery must
be supplied/observed through the actual lane adapters. G6 needs separately approved
inference inputs/spend; this package never makes a paid model call.

The external-state option does not relax private-file ownership: a root evaluator
must not read an App997-owned launch file through an owner-check exception. H's
already-authorized App997 context can read its matching private state with a separately
root-owned/read-only evaluator closure and a newly independently retained evaluator
digest. Same-UID evaluation still establishes no OS enforcement boundary. Canonical
path and pre/post identity checks narrow pathname races; they do not establish atomic
isolation against a process with the same UID. All three G1 probes and final gate
`PENDING` behavior remain in force. This source followup performs no remote observation
or VM lifecycle action.

Deterministic archive of an already materialized, pinned release:

```sh
node packages/ops/cli.mjs package --root /path/to/materialized-release --out /tmp/prime.tar --kind release --version VERSION --commit FULL_COMMIT --recipe /path/to/frozen-build-recipe.json
node packages/ops/cli.mjs verify --archive /tmp/prime.tar --expected-digest RETAINED_DIGEST --expected-archive-sha256 RETAINED_ARCHIVE_SHA256
node packages/ops/cli.mjs stage-release --archive /tmp/prime.tar --expected-digest RETAINED_DIGEST --into /path/to/existing-empty-dir
```

Recipe is mandatory; package bytes are reproducible (sorted USTAR, fixed ownership,
mtime and modes). This does not prove a reproducible upstream build. `--root` must
contain the materialized local closure, with no escaping/absolute links, hardlinks, special files,
keys, credentials paths, authority-state or `.git`. Source `.git` must not be passed.
Input selection belongs to A/H; no old checkout is traversed. Known key/path detection
is a refusal guard, not a complete secret scanner. Contained pnpm links hash path/target
text, with all physical target bytes/modes included; dangling/cyclic/outside links are
refused. Memory exports reject links entirely. No source path is a trusted key.

Release digest and archive entrypoints reject C0 characters (U+0000–U+001F) and DEL
(U+007F) in raw/resolved release paths, entry names and raw symlink targets before
computing a release digest, accepting an archive or staging. Raw path checks precede
canonicalization, so a control-containing component cannot disappear through `..`.
Ordinary v1 domain, sorting, file/executable
classes and serialized bytes stay unchanged. The retained newline collision pair is
refused before hashing; this fixes a row serialization ambiguity, not a SHA-256
collision. Archive canonical manifests and archive SHA remain separate pins.

`fullTreeDigest` confines physical link targets to the release. An exact `..` or
`../` prefix means outside; ordinary contained names such as `..module` remain valid.
Archive link validation still requires canonical relative entry names and rejects
absolute, escaping, dangling and cyclic targets. The donor `treeDigest` retains its
legacy exclusions and opaque link-text scope for byte compatibility; it does not
prove physical link containment. Its new controls guard does not upgrade that scope.
Digest JS refusals are `RELEASE_PATH_CONTROL_CHARACTER` or
`RELEASE_LINK_CONTROL_CHARACTER`. Archive refusals are `INVALID_ARTIFACT_PATH` for
entry names, `ARTIFACT_PATH_CONTROL_CHARACTER` for input/output path arguments and
`RELEASE_LINK_CONTROL_CHARACTER` for targets. Python pilot digest names use
`UNSAFE_RELEASE_NAME`; root and target controls use the JS refusal names. No exported
function signature, archive schema or digest algorithm identifier changes.

Backup scope is ONLY a D-created memory export. Use `--kind memory-export`; never pass
raw state, database directories or authority stores. `restore` accepts this kind into
an existing empty directory and returns STAGED, authority_restored:false. It does not
activate data, rewind consumed grants or claim cold memory semantics. D/A own real
`./prime export`, `./prime verify`, `./prime restore --into`; perform D cold verification,
owner/forget/tombstone and independent consumption reconciliation before use.
Keep last-known-good artifact plus a pre-migration export; uncertain effects block
blind retry. Retention/deletion has no automatic implementation here.

`plan` gives the existing pilot and exact remaining permissions. `unit-template`
prints a reviewable Ubuntu systemd unit; it never installs/enables it. Root boot is
foreground/localhost only. Cgroup limits: CPU 150%, memory 5 GiB, tasks 128, descriptors
4096, Node build/runtime heap 1536 MiB. PostgreSQL/OS/broker require the remaining
budget; these limits are not a dollar cap, token cap or guest confinement. The
existing $2/day new CPU/disk/IP cap needs invoice reconciliation and a separately
approved independent provider watchdog; paid inference/GPU stay disabled. No new
backup resources, IAM, credentials, firewall, public ports or network access.

Deployment still requires verified SSH host identity, reviewed pinned packages,
approved runtime/broker UIDs/directories/socket ACLs, systemd/security setup,
PostgreSQL configuration/retention, artifact transfer/start permission and watchdog
permission. No SSH or VM command is run by these tools. No old Mac app activation.
The direct-child probe wrapper signals only its own spawn; it never kills unrelated
PIDs. Descendant cleanup remains NOT_VERIFIED unless actual H/F/cgroup evidence exists.

One disposable ops regression: `node packages/ops/regression.mjs`.
It covers reproducible package, tampered bytes/digest, empty recovery target, sensitive
paths, changed installation marker, output redaction, owned cancellation and rejection
of candidate PASS. It is not an authority/OpenShell/inference acceptance result.

Focused external-state regression: `node packages/ops/check-external-state.mjs`.
It uses only disposable files, its own PID and an ephemeral localhost protocol fixture
to check exact status argv, state/release/file/PID binding, default behavior, private
file bounds, path refusals, token redaction and all three missing G1 probes. It performs
no actual Prime/DSH qualification or live app observation.

Focused metadata regression: `node packages/ops/check-digest-controls.mjs`.
It checks the exact newline collision pair, frozen ordinary v1 hashes, all 33 C0/DEL
code points, contained dependency links and correctly hashed malformed archives.
It reuses a few disposable entries and performs no network or service action. NUL
cannot be an OS entry name or link target; its coverage uses raw path and serialized
metadata inputs. Qualification remains PENDING; source checks establish no independent
host boundary, protected deployment or loaded-code attestation. A changed evaluator
closure requires a newly retained external `evaluator-digest` before a future run.

The new ordinary keyless runner is `node packages/ops/verify-fast.mjs --root
/physical/source --evidence-dir /physical/private/parent/new-run [--json true]`.
H owns its root `./prime verify` hook. See [the closed ordinary source profile](fast-verify/README.md)
for the required closed 66-job / 65-file profile, inventories, literal pins, exit codes
and historical-only records. The union retains all 29 required whole owner-memory
files from H's 37-job profile, including eight files absent from the earlier G53
profile. Four missing whole files and H's bounded ordinary `bash_parameters`
selection are now required. The initial adjudicated source review covered 140
references across 99 selected paths. Subsequent reviewed fixture repairs and the
exact worker socket helper binding make the current closure 142 references across
101 paths; every literal pin matched the selected source. The current manifest
SHA256 is `d7916f11cdd9b2bda39e7efe3e7e6b217140b7bbec03e4fb4e6cf9b352cfcca7`.
The initial review basis and its original manifest remain historical in PROVENANCE.json.

The corrected final profile awaits two complete runs at the same frozen revision:
integrator and independent clean-copy reader. The planned `prime-v1.2-research-review`
reference and external immutable receipt must identify that exact source and both
results. The most recent [8bd failed run](../../docs/evidence/source-profile-8bd7dbb.json)
returned 63 PASS / 2 FAIL / 1 UNPERFORMED after the decoder rejected honest live
qualification annotations; worker and authority jobs passed. The retained [54c failed run](../../docs/evidence/source-profile-54c4a306.json)
returned 63 PASS / 2 FAIL / 1 UNPERFORMED; the prior 9c8 failed run returned
58 PASS / 2 FAIL / 6 UNPERFORMED. Older H37 results and its independent
36-PASS/1-host-FAIL observation remain separately attributed. The previous denied
Unix-socket bind is preserved; it is not retried or promoted to PASS.

The evaluator supplies its existing private evidence directory only to the exact
compiled `bridge-worker` fixture. Socket path length is checked before creation;
config/state retain the case TMPDIR. No caller override, ancestor discovery or
fallback after refusal is introduced, and the production 103-byte IPC limit stays
unchanged. Other jobs and prerequisite probes receive no socket-root binding.

The 600000 ms suite and 120000 ms full-TAP limits remain. The exact pinned
`authority-core-only` job has a 180000 ms exception; other non-TAP jobs retain
60000 ms maximum and existing shorter bounds. Output is capped at 65536 bytes
and the direct Node heap at 512 MiB. The inference mock retains 20000 ms.
These are cooperative budgets, not containment. The three historical failed66
runs took 209966 ms, 242303 ms and 341689 ms; final-pair duration remains unmeasured.
The E total-budget gate is absent from this source profile: UNPERFORMED, deferral
intent UNKNOWN pending its owner. Archive verification is unchanged; qualification
stays UNPERFORMED and G1 stays PENDING.

The decoder distinguishes required-test incompletion from the two existing root
qualification annotations in exact pinned jobs: `live_auth: UNPERFORMED` and
`public_qualification: UNPERFORMED`. Required counters stay exact and numeric;
changed jobs, nested fields, unknown annotations, required skips/TODOs and failed
results still refuse. No source test output or assertion was changed.

The historical `source_review_commit` is explicitly a literal pin-review basis.
Separate before/after invocation HEAD observations identify mutable Git metadata;
they are not checkout, worktree, loaded-code or runtime attestation. The outer
review receipt must bind the frozen source and both complete results. The final
46-check engine observation covers all12 selected JSON schemas and this distinction.
