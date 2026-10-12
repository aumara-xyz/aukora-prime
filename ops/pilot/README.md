# Pilot: moving the live harness to a commit of `main`

Two scripts, copies of the ones in `~/aukora-zip` on the pilot. They contain no address, key or token.

1. `mat-live-main.sh <full commit>` (as the admin user): builds `/opt/aukora-genesis/release-<sha7>` beside the live release, with Kira's OpenViking setting on. Nothing is approved, installed or switched. **RAN on the pilot** 2026-10-13 for `b65f39c`, `5ad3467` and `c8cf03c`; the live harness stayed on `3673b98`.
2. `sudo bash live-switch-main.sh <full commit>`: backup; gate package upgraded from staged copies; launcher source moved; package check; **one approval card raised; waits up to 15 minutes for the owner's click in his own popup**; approval installed; harness started on the new release. Any stop restores the old gate package, manifest, bootstrap, launcher source and release.

**`live-switch-main.sh` has NOT RUN on the live pilot.** Rehearsed in the staging container on 2026-10-13 with the staging stand-in key:

- to `SWITCH_DONE`, the stand-in approving the card it raised;
- no approval at all: restored (manifest and release file byte-identical before and after, both services active, door acceptance passing afterwards);
- **interrupted (SIGTERM) while waiting for the click**: restored the same way. A review had shown that an interrupt after the services were stopped skipped the restore; the script now traps interrupts from that point, keeps each backup in its own directory (a rerun in the same minute used to nest them), checks every backup and swap step, and writes `RECOVERY.txt` beside the backup with the commands to run by hand after a hard kill;
- run again after the owner had approved in the meantime: it found the approval and went straight through. Found in rehearsal: before this, a card left pending by an interrupted run made the next run fail at "raise".

Not rehearsed: a rerun while the earlier card is still pending and unapproved (the script waits on that card; written, not exercised); a hard kill (`kill -9`, power loss), for which `RECOVERY.txt` is the only remedy. Staging has no sandbox, no OpenShell gateway and not the owner's real key, so a first live run can still stop; it restores when it does.

While it waits for the click, the harness is down. If the wait times out the card stays pending in the gate until it expires; approving it later installs nothing.

After a switch, as the harness user: `plugins/aukora-buzz-door/checks/installed-accept.mjs <release> --scratch-home <dir in the harness user's home>` and `scripts/kira/release-recall-probe.mjs <release> --scratch-state <empty 0700 dir>` (environment in `plugins/aukora-kira/README.md`).
