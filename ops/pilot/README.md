# Pilot: moving the live harness to a commit of `main`

Two scripts, copies of the ones in `~/aukora-zip` on the pilot. They contain no address, key or token.

1. `mat-live-main.sh <full commit>` (as the admin user): builds `/opt/aukora-genesis/release-<sha7>` beside the live release, with Kira's OpenViking setting on. Nothing is approved, installed or switched. **RAN on the pilot** 2026-10-13 for `b65f39c`, `5ad3467` and `c8cf03c`; the live harness stayed on `3673b98`.
2. `sudo bash live-switch-main.sh <full commit>`: backup; gate package upgraded from staged copies; launcher source moved; package check; **one approval card raised; waits up to 15 minutes for the owner's click in his own popup**; approval installed; harness started on the new release. Any stop restores the old gate package, manifest, bootstrap, launcher source and release.

**`live-switch-main.sh` RAN on the live pilot on 2026-10-13, with the owner's own click: `3673b98` -> `c8cf03c`.** It took three runs, and the two failures were this script's, found only on the live machine:

1. It stopped the harness and then waited for the click. The owner's approval popup lives in the desktop app, and the app cannot attach while the harness is down, so no card could be shown. Interrupted; it restored. What worked: with the OLD release running and the app attached, the owner approved the card already pending; the next run found the approval and did not wait. **The script's order is still wrong for a first-time approval** and must be changed to raise the card and collect the click BEFORE stopping anything.
2. The new harness, and then the restored old one, failed with `port-unavailable: 18735`: the launcher refuses to start while connections on its port linger, and an attached app leaves some for seconds after a stop. The harness was down for about two minutes until it was started by hand. The script now waits for the port to drain before every start, including in the restore.

Third run: `SWITCH_DONE`, selfcheck passed, plugin set enforced, the memory probe 6 of 6 against the live release, and one real model turn answered.

Before that, rehearsed in the staging container with the staging stand-in key (which needs no window, and has no attached app holding the port, which is why neither failure showed there):

- to `SWITCH_DONE`, the stand-in approving the card it raised;
- no approval at all: restored (manifest and release file byte-identical before and after, both services active, door acceptance passing afterwards);
- **interrupted (SIGTERM) while waiting for the click**: restored the same way. A review had shown that an interrupt after the services were stopped skipped the restore; the script now traps interrupts from that point, keeps each backup in its own directory (a rerun in the same minute used to nest them), checks every backup and swap step, and writes `RECOVERY.txt` beside the backup with the commands to run by hand after a hard kill;
- run again after the owner had approved in the meantime: it found the approval and went straight through. Found in rehearsal: before this, a card left pending by an interrupted run made the next run fail at "raise".

Not rehearsed: a rerun while the earlier card is still pending and unapproved (the script waits on that card; written, not exercised); a hard kill (`kill -9`, power loss), for which `RECOVERY.txt` is the only remedy. Staging has no sandbox, no OpenShell gateway and not the owner's real key, so a first live run can still stop; it restores when it does.

While it waits for the click, the harness is down. If the wait times out the card stays pending in the gate until it expires; approving it later installs nothing.

After a switch, as the harness user: `plugins/aukora-buzz-door/checks/installed-accept.mjs <release> --scratch-home <dir in the harness user's home>` and `scripts/kira/release-recall-probe.mjs <release> --scratch-state <empty 0700 dir>` (environment in `plugins/aukora-kira/README.md`).
