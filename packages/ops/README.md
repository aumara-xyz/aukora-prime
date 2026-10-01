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
