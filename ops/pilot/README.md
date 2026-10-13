# Pilot: moving the live harness to a commit of `main`

`mat-live-main.sh <full commit>` builds `/opt/aukora-genesis/release-<sha7>` beside the live release. It approves, installs and switches nothing. It ran on the pilot on 2026-10-13 for `b65f39c`, `5ad3467` and `c8cf03c` while the harness stayed on `3673b98`.

The earlier `live-switch-main.sh` ran on the pilot on 2026-10-13, with the owner's click, from `3673b98` to `c8cf03c`. Three runs were needed. It first stopped the harness before asking for approval, making the desktop popup unreachable. The owner approved the pending card with the old release running, and a later run found that approval. Lingering connections then prevented both the new and restored harness from starting. The third run reported `SWITCH_DONE`, selfcheck and plugin enforcement passed, the memory probe passed 6 of 6, and a real model turn answered. These are historical observations of the earlier script.

The version now in source has **not run on a real machine**. Its tests run the actual Bash script against private temporary roots with synthetic services, gate responses and approvals. They do not establish owner enrollment, Linux service behavior, installed package compatibility, real UI availability, or recovery after a machine power loss.

As root, run `bash live-switch-main.sh <full commit>` with `ui-probe.mjs` beside it. The script:

1. Checks the built release, clean launcher checkout, active harness and gate, absent floor lock, and presence of the UI probe. It refuses an unfinished previous switch and names its recovery command.
2. Saves private backups, the launcher commit, every originally active systemd unit and the selfcheck timer's state. A failed unit snapshot refuses before stopping. It stages the new package and manifest without stopping services.
3. Uses the **installed gate** to describe and raise the new release's approval card. It can reuse a matching pending card or an already applied approval. It waits up to 15 minutes (`WAIT_TICKS`, five seconds each) with the old harness and gate running. An incompatible old gate or missing approval stops the switch before any service stop. The full applied content digest must match; installation of the signed proof remains a separate check.
4. Prepares protected package copies on the destination filesystem, then stops services. Each package swap uses two renames, with the state file naming the rename in flight. It moves the launcher, checks the package, starts the gate and waits for **both** gate and owner sockets (up to 30 seconds; `GATE_SOCKETS_MISSING` otherwise) before installing approval. Approval directories are `0755`, approval files and the release-floor file are `0644`, including under an inherited `umask 002`. The harness user's floor check must pass.
5. Requires the port to drain, publishes `release.env` immediately before starting, and waits for an active harness with an HTTP response. The candidate package, approval and floor have passed before publication; runtime UI and plugin-load checks follow startup. The signed-in `ui-probe.mjs` runs against `/home/aukora-host/genesis/state/launch-url.json`. The new systemd invocation's journal must contain no plugin-load line matching `^aukora-[a-z-]+ \(file://.*\): Error`. Only then are the original unit states restored and `SWITCH_DONE` reported, followed by `OLD_RELEASE`, `NEW_RELEASE` and `BACKUP_DIRECTORY` for the operator's record. Already active unrelated units are checked without restarting them.

Any failure after stopping invokes recovery. The backup keeps immutable package copies, the original environment, manifest, bootstrap, floor, candidate approval cache and launcher commit, plus `units.old`, `state` and `RECOVERY.txt`. State updates are atomically renamed and fsynced before the next operation. Recovery starts the previously active selfcheck timer too. It tries the old harness at most three times, draining before each start. A port that never drains or a harness that cannot start ends with **HARNESS DOWN**, nonzero status and an unfinished state; it is not a successful restoration.

After an interrupt or hard kill, use the exact backup printed by the script:

```sh
bash live-switch-main.sh --recover /root/aukora-backup-pre-<sha7>-<suffix>
```

`--recover` also works after a completed switch and can be repeated. It supersedes the removed `live-rollback.sh`. Do not start another switch until recovery succeeds. A failed recovery keeps its state unfinished for another attempt. Original package siblings are named `.switch-old-<backup-name>`; the immutable copies in the backup remain available even after these siblings are removed during recovery. A floor lock present before the switch requires operator reconciliation; recovery only removes a lock created after this run's recorded absent lock.

A terminal/SSH invocation re-executes under `nohup` with closed terminal input and a private `/root/aukora-switch-log-*` log; the parent prints its PID and `tail -f` command. Existing `nohup`, session-leader `setsid`, and systemd launches with a matching journal stream retain their launch route. Detachment's initial exit does not mean the switch succeeded: read the log. `ROOT` changes installed absolute paths only for tests and is refused unless `PILOT_SWITCH_TEST=1`; production defaults to the original paths. No harness source archive or build is needed by these switch tests.

After a qualified switch, as the harness user, the additional door acceptance and memory probe remain: `plugins/aukora-buzz-door/checks/installed-accept.mjs <release> --scratch-home <dir in the harness user's home>` and `scripts/kira/release-recall-probe.mjs <release> --scratch-state <empty 0700 dir>` (environment in `plugins/aukora-kira/README.md`).

## Rehearsals of the rewritten script (2026-10-13, staging container, stand-in key)

1. Waited for approval with the old release up, then stopped at the floor check and restored: the approval folders had been created unreadable to the harness user (the script runs under a private file mask).
2. Same class, one file further: the release-floor file was written unreadable. Restored.
3. `SWITCH_DONE`: approval installed, harness on the new release, self-check timer active, the script's own screen probe and plugin-load check passed.

Both faults are fixed in the script and covered by fake-tree mode assertions and mutations. The tests also delay the two sockets separately and refuse either missing socket before approval installation. Restricted sandboxes that refuse AF_UNIX binding explicitly report that the fixture simulates socket status. These tests do not prove real socket readiness, cross-user file access, machine power-loss recovery or installed behavior. A hard kill after publication requires `--recover`; the candidate has passed package, approval and floor verification, but its runtime UI checks may still be pending. A staging rehearsal remains required before any live run. The rewritten script has NOT run on the live pilot.

