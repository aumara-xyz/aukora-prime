# Pilot: moving the live harness to a commit of `main`

Two scripts, copies of the ones in `~/aukora-zip` on the pilot. They contain no address, key or token.

1. `mat-live-main.sh <full commit>` (as the admin user): builds `/opt/aukora-genesis/release-<sha7>` beside the live release, with Kira's OpenViking setting on. Nothing is approved, installed or switched. **RAN on the pilot** 2026-10-13 for `b65f39c` and again for `5ad3467`; the live harness stayed on `3673b98`.
2. `sudo bash live-switch-main.sh <full commit>`: backup; gate package upgraded from staged copies; launcher source moved; package check; **one approval card raised; waits up to 15 minutes for the owner's click in his own popup**; approval installed; harness started on the new release. Any stop restores the old gate package, manifest, bootstrap, launcher source and release.

**`live-switch-main.sh` has NOT RUN on the live pilot.** It was rehearsed twice in the staging container on 2026-10-13: once through to `SWITCH_DONE` with the staging stand-in key approving the card it raised, and once with no approval, where it restored everything (manifest and release file byte-identical before and after, both services active, door acceptance passing afterwards). Staging has no sandbox, no OpenShell gateway and not the owner's real key, so a first live run can still stop; it restores when it does.

While it waits for the click, the harness is down. If the wait times out the card stays pending in the gate until it expires; approving it later installs nothing.

After a switch, as the harness user: `plugins/aukora-buzz-door/checks/installed-accept.mjs <release> --scratch-home <dir in the harness user's home>` and `scripts/kira/release-recall-probe.mjs <release> --scratch-state <empty 0700 dir>` (environment in `plugins/aukora-kira/README.md`).
