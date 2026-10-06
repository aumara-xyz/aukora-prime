# systemd unit source and historical pilot layout

The current units and recovery helper are a source proposal. The historical layout
below describes the reported 2026-10-04 pilot; these edited bytes are not evidence
of installed unit identity, a deployment, or successful systemd execution.

Replaces the lab's pm2 supervision (L4). Install as root into `/etc/systemd/system/`, then
`systemctl daemon-reload && systemctl enable --now aukora-auma-podman aukora-openshell-gateway aukora-auma-sandbox aukora-boundary-gate`.

`aukora-genesis.service` runs the Genesis runtime (`scripts/launch-dsh.py`) as `aukora-host` on loopback port 18735,
after the gate and sandbox. Its state root (`/home/aukora-host/genesis/state`, 0700) holds the provider credential;
the owner reaches it only through an SSH tunnel. The unit file is release-agnostic; the
only per-release file is the root-owned `/etc/aukora-genesis/release.env` (`aukora-genesis.release.env.example`).

## Release switch (signed enforcement, no waiver)

1. Materialize the release under `/opt/aukora-genesis/release-<7>`.
2. `plugin-set-approval.mjs raise --release-dir <dir>` puts a plugin-set card in front of the owner (one click; the card
   states as gate facts whether the plugin set is unchanged since the previous approval, and ROLLBACK when the release is
   below the floor). Root never imports anything from the candidate release: `src/plugin-set-canon.mjs` reads it as data.
3. After the owner approves: `plugin-set-approval.mjs install --release-dir <dir> --out /etc/aukora-approvals/<sha>/state/gate-state`
   writes the approval + pin and moves the monotonic release floor (`/etc/aukora-approvals/release-floor.json`) forward.
4. Write `release.env`, `systemctl restart aukora-genesis`. `ExecStartPre` runs the self-check, then
   `release-floor.mjs check`, which refuses an approval older than the floor (an old release with its own old approval).
   Rolling back means raising the old release again for a fresh owner approval.

Assumed layout (see `../SETUP.md`): host scripts in `/usr/local/lib/aukora-boundary/` (root 0755), OpenShell 0.1.2
`openshell`/`openshell-gateway` in `/usr/bin`, Node 24.11.1 in `/opt/aukora-node`, this package (root-owned) in
`/opt/aukora-boundary-gate`, gate targets in `/var/lib/aukora-boundary/targets`, linger enabled for `auma`.
Differences from SETUP.md observed on Ubuntu 24.04: Podman is 4.9.3 (distribution package), not 5.4.2.

## Boundary self-check (fail closed)

`aukora-genesis.service` runs `bin/selfcheck.mjs` as `ExecStartPre` (as aukora-host): every forbidden action must be
refused and the in-sandbox egress probe must pass, and the result must be recorded as a signed `selfcheck` ledger entry,
or the runtime does not start (three tries in five minutes, then it stays down). `aukora-selfcheck.timer` re-runs the
same check every 15 minutes through `aukora-selfcheck-periodic.service`; a failure starts
`aukora-genesis-failclosed@%n.service`, which stops the runtime.
Install `bin/selfcheck.mjs` with the gate runtime (`/opt/aukora-boundary-gate/bin/`), then
`systemctl enable --now aukora-selfcheck.timer`.

## Current source failure-stop and recovery protocol

Genesis and both selfchecks verify `check-boot`, then the separate `check-ready`
protocol before executing application checks. The gate verifies pure `check-boot`
before serving. Genesis uses `Requisite` for the gate and sandbox: those providers
must already be running. Starting Genesis does not request a gate start.

The startup selfcheck stays active after success with one `RemainAfterExit=yes`.
The periodic check returns to inactive after success, so its timer keeps running.
An active startup latch with no executing process does not block recovery.

The template failure handler requires systemd 251 or later. Separate template
instances preserve `MONITOR_UNIT`, `MONITOR_INVOCATION_ID` and
`MONITOR_SERVICE_RESULT`; a shared handler would lose those variables. The owned
`genesis-recover-probe failclosed <selfcheck-unit>` helper stops Genesis even when
failure provenance is missing, but records eligibility only for a verified failed
selfcheck invocation, an active exact Genesis invocation, and a matching successful
stop-post witness inside the helper's stop transaction. It stores
the boot ID, the stopped unit snapshot and the release configuration digest in a
root-owned private directory under `/run/aukora-genesis-recovery`. Its own stop
transaction is recognized by Genesis `ExecStopPost`; ordinary stops invalidate
eligibility. Bookkeeping refusal still attempts the fixed mandatory runtime stop
and grants no recovery eligibility. The legacy non-template failclosed unit only stops and never arms
recovery. [systemd monitor environment documentation](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)

Recovery reads `release.env` as a closed three-field data format. It requires the
same stopped invocation and release, idle selfchecks, already active providers,
fresh boot and readiness verification, the exact floor check, and a passing real
selfcheck through the harness user. It rechecks provider invocations and custody
before consuming eligibility and requesting `systemctl start` of Genesis. It does
not switch releases or clear systemd failure/start-limit counters. A refused start
consumes eligibility and requires explicit operator reconciliation.

Both selfcheck units and the retry wrapper share the root-owned regular read-only
execution lock `/run/aukora-boundary-selfcheck.lock`. A fixed root preparation action
creates and checks it without taking the separate recovery protocol lock. The
wrapper holds the execution lock across both attempts and the retry delay; the
systemd unit uses `flock --exclusive --no-fork` around its Node selfcheck. Recovery
releases this execution lock before requesting Genesis start, so the Genesis
precheck can acquire it without waiting on a lock held by its own start caller.

For an intentional stop, the protected operator route is:

```sh
/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/genesis-recover-probe inhibit
```

This writes the root-protected persistent inhibitor and consumes eligibility before
stopping Genesis, including when Genesis is already inactive. A later intentional
start uses `genesis-recover-probe operator-start`; it verifies admission, consumes
any old eligibility and clears inhibition before requesting the ordinary guarded
start. There is no generic reset or allow operation.

A raw `systemctl stop` on an already inactive unit has no observable stop event.
It therefore cannot revoke an existing token without the coordinated inhibitor
route. A raw stop concurrent with the failure-stop transaction is also
indistinguishable from the helper's stop using the available witness. Intentional
stops must use the serialized inhibitor route. This is an explicit operator
coordination requirement, not a universal proof that all root/operator actions are
distinguishable. Root updates must quiesce the
protocol and preserve coherent verified units and helpers.

`node --test tests/aukora-genesis-recovery.test.mjs` executes the actual recovery
helper, retry logic and `bin/selfcheck.mjs` main against a declared fake-systemctl
source fixture. Fixed paths and UID metadata are adapted only in the fixture;
sandbox/readiness replies and selfcheck recording are synthetic and unsigned. The
wrapper's fixed Node/lock paths, a real-fcntl adapter for util-linux flock, and its
45 second delay are adapted for the fixture. The concurrent test removes the
wrapper fence and witnesses overlapping real Node selfcheck calls.
`node --test tests/aukora-selfcheck-wiring.test.mjs` separately checks source unit
graphs and guard mutations. These checks establish no installed systemd result,
owner enrollment, real containment or runtime qualification. Actual Linux systemd
failure-stop-recovery, installed custody and application response remain
**UNPERFORMED** until an authorized configured-host route supplies evidence.
