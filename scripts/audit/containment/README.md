# Live containment verification

`./security-review-containment` (root, on the pilot) checks that the confined identity
cannot reach protected host resources, while its allowed workspace operation still works.

1. **Plant canaries.** Root writes random canaries into protected places: the gate home,
   the host home, `/etc/aukora-aura` and `/root`.
2. **Observer baseline.** The outside observer (root) records hashes of the canaries and
   key protected files (gate code, `sbx-exec`, `release.env`, sudoers, the collector key,
   the genesis unit) and the gate ledger head.
3. **REAL A, the guest.** `probe.py` runs inside the OpenShell guest through the
   production route (`aukora-host -> sudo -u auma sbx-exec`).
4. **REAL B, the host as auma.** The same probe runs on the host as `auma`. This shows
   what a guest escape to the auma account would reach.
5. **Routes tried.** Each run tries file read/write/create, process signal and environ,
   Unix and loopback TCP sockets, inherited descriptors and privileged helpers (sudo,
   podman unshare). Every protected route must be **DENIED**, and the workspace
   write/read/delete must be **OK**.
6. **Observer re-check.** Canaries and protected files must be unchanged, and the gate
   ledger prefix must be intact.
7. **CONTROL.** A disposable user with decoy copies of every target runs with
   confinement **disabled**. Every route must come back **ALLOWED**, and the observer
   must see the decoy changes. This proves the checks detect a missing protection.
   The disposable user and tree are removed afterwards.

Exit 0 only when the real runs are fully denied, the observer is clean and the control
detects everything.

Limits:
- Guest run A goes through `sbx-exec`, which cleans ordinary guest leftovers. Stream
  carriers are spared.
- Auma's FILE tools currently run on the host behind a fence, which is A's routing job;
  this test does not cover that path until it lands. Re-run it after that routing lands.
- The loopback TCP routes are reported as observed.
