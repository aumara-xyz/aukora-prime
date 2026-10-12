# Node spawn — source-only provisioning steps

```sh
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
export AUKORA_NETWORK_ROOT_PUBKEY='<configured network creator public key: 64 lowercase hex>'
bash ops/node-spawn/spawn.sh --plan member-node /path/to/admission-record.json
```

The admission file is `verifyAdmission(...).record` from `packages/invites`,
exactly `{ "chain": [...] }`, not its whole response. Both plan and execution
read the bounded regular file and call the repository's `verifyRecord` against
that independently configured root. Invalid signatures, ancestry, roots and
inputs refuse before LXD. No admission contents or private keys are printed.
Plan mode runs this read-only Node verifier, then prints exact conditional
commands; it never calls LXD or installs anything. `<...>` operands remain
unresolved, so the plan is not a script to paste and run.

Real source steps:

- Verify the signed root-to-member path before any container operation.
- After the protected source checkout passes the revision check, install
  `/etc/aukora-node/member.json` with the node name, configured network root,
  verified member public key and final redemption ID. `install-member.py`
  requires root, creates a root-owned 0644 file under protected 0755 directories,
  refuses symlinks/unsafe custody or conflicting state, and preserves an identical
  existing binding. This public config is provisioning metadata, not a gate grant.
- Call existing local-deny installation, Podman and gateway systemd units, then
  the guest builder as `auma` with its actual three arguments (Node binary,
  release `guest/exec.py`, release PTC `process.js`), then sandbox admission.
  The units invoke `podman-service.sh`, `gateway.sh` and `ensure-sandbox.sh`
  without arguments; mTLS generation stays in the gateway script.

Refusals still enforced:

- A valid record reaches `LXD_PROFILE_MISSING`. Image/profile, shared admission
  accounting and resumable node allocation, pinned runtimes, principals,
  protected source/gate installation, gate-local first-key bootstrap, node state,
  approval/resume, release selection and auxiliary service setup remain gaps.
  Offline verification cannot prove authoritative consumption, quotas, historical
  clock accuracy or that one admission was allocated to only one node.
- `OWNER_ENROLLMENT_DERIVATION_MISSING`: `ownerRootPin()` derives the P-256 SPKI
  `owner_root_id`; it cannot derive the trusted `owner_subject` binding, active
  `owner_epoch`, `registry_sha256` or `activation_sha256`. The eight-field
  `/etc/aukora-boundary-gate/owner-state.json` also needs `version`, `kind` and
  `owner_root_spki_base64`. No registry/activation producer is defined. No owner
  state is fabricated, and no member private key is accepted. Future enrollment
  must write root-owned state that the gate account cannot change.
- `OPENSHELL_BINARY_PROVENANCE_MISSING`: the host needs reviewed OpenShell
  CLI/gateway 0.1.2 binaries and the custody patches. [SETUP](../../packages/boundary-gate/host/SETUP.md)
  traces the recipe to Genesis lab `6fa70cd` and names GHCR sandbox/supervisor
  images; [systemd notes](../../packages/boundary-gate/host/systemd/README.md)
  record Ubuntu 24.04/Podman 4.9.3 on the pilot. Neither gives its exact binary
  download/build provenance. The custody notes still leave the pinned rebuild
  or installed provenance pending; a version string is insufficient.
- `GUEST_IMAGE_INPUTS_MISSING`: a guest image builder exists, but its required
  `plugins/aukora-openshell-confinement/guest/exec.py` and producer are absent.
  Its NVIDIA Ubuntu base tag and apt inputs also need provenance review; exact
  pilot guest-carrier provenance is not documented. The PTC bootstrap comes
  from the pinned harness build. Do not invent or download a replacement.
- `SANDBOX_PRODUCER_MISSING`: a qualified workspace mount producer and protected
  `openshell-workspace.json`/`openshell-inventory.json` are still required.
  `ensure-sandbox.sh` only checks admission; `--bootstrap-profile` always refuses.
  Older SETUP/builder comments claiming sandbox creation/recreation are stale.
- Owner approval remains the owner's existing review/decide_review action.

Run `node --test ops/node-spawn/test.mjs` with Node **24.11.1**. Tests use synthetic
signed admissions, stub LXD and temporary filesystem fixtures, including guard
removal mutations. They do **not** prove real owner enrollment, a working fresh
installer, global single use, installed enforcement or containment. No LXD,
staging or live-node execution has been performed here. No dependencies or
exports outside this directory were added.

The incubator operator controls the containers and can read their keys/state.
The member's private owner key must stay on their own device. Export to a server
outside the incubator's reach remains future work.
