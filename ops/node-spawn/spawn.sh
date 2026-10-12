#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Verify admission before LXD and refuse unsupported provisioning steps.
# Gaps in this revision (never supplied by the admission file or environment):
# LXD_PROFILE_MISSING: no pinned Ubuntu 24.04 image or qualified unprivileged,
#   isolated profile for nested rootless Podman; no network publishing allowed.
# RESUME_CONTRACT_MISSING: no admission/container/revision binding or crash recovery.
# RUNTIME_INSTALL_MISSING: no pinned Linux Node 24.11.1/OpenShell 0.1.2 installer.
# PRINCIPAL_INSTALL_MISSING: no reconciler for users, ranges, directories or sudoers.
# SOURCE_INSTALL_MISSING: no protected checkout transport/install at a reviewed SHA.
# FRESH_KEYS_MISSING: gate creates local keys, but bootstrap needs its public epoch first.
# OWNER_ENROLLMENT_DERIVATION_MISSING: no subject/epoch registry or activation producer.
# GATE_INSTALL_MISSING: manifest generator is not a fresh protected-package installer.
# OPENSHELL_BINARY_PROVENANCE_MISSING: no pinned host binary install/rebuild route.
# GUEST_IMAGE_INPUTS_MISSING: builder exists, but its guest/exec.py input does not.
# SANDBOX_PRODUCER_MISSING: ensure-sandbox.sh only checks an existing bound sandbox.
# NODE_STATE_MISSING: no fresh provider/state/targets/linux-openshell overlay recipe.
# OWNER_APPROVAL_REQUIRED: only the owner's existing review/decide_review may approve.
# APPROVAL_RESUME_MISSING: equal-floor reinstall refuses; preserve verified approvals.
# RELEASE_ENV_MISSING: no reviewed writer for release.env from the approved record.
# AUXILIARY_SETUP_MISSING: memory/relay/Aura and shared community relay need separate
#   configuration; existing host units do not constitute a fresh-node installer.
set -euo pipefail

case ${1-} in
  --linux|--dry-run) exec bash "${BASH_SOURCE[0]%/*}/linux.sh" "$@" ;;
esac

refuse() { printf 'REFUSED %s\n' "$1" >&2; exit 1; }
plan=0
if [[ ${1-} == --plan ]]; then plan=1; shift; fi
[[ $# -ge 1 ]] || refuse 'USAGE: spawn.sh [--plan] NODE ADMISSION_RECORD'
node=$1
[[ $# -le 2 ]] || refuse 'USAGE: spawn.sh [--plan] NODE ADMISSION_RECORD'
admission=${2-}

step() { printf '\n# %s\n' "$1"; }
command_step() {
  if [[ $plan == 1 ]]; then printf '%q ' "$@"; printf '\n'; else "$@"; fi
}
inside() { command_step lxc --force-local exec "$node" -- "$@"; }
gap() {
  if [[ $plan == 1 ]]; then printf '# GAP %s: %s\n' "$1" "$2"; else refuse "$1"; fi
}

# Check actual TCP/UDP endpoints, not client URLs or service comments.
listener_check='set -euo pipefail
ss -H -lntu | awk '\''function loopback(address, octets, count, i) {
  if (address == "[::1]" || address == "::1") return 1
  count=split(address, octets, ".")
  if (count != 4 || octets[1] != "127") return 0
  for (i=2; i<=4; i++) if (octets[i] !~ /^[0-9]+$/ || octets[i] > 255) return 0
  return 1
} {
  address=$5; sub(/:[^:]*$/, "", address)
  if (!loopback(address)) bad=1
} END { if (bad) { print "REFUSED OFF_LOOPBACK_LISTENER" > "/dev/stderr"; exit 1 } }'\'''

step '01 Admission — verify the compact packages/invites record against the configured root'
[[ ${NODE_OPTIONS+x} != x ]] || refuse NODE_OPTIONS_FORBIDDEN
member_config=$(node "${BASH_SOURCE[0]%/*}/admission.mjs" "$node" "$admission") || exit 1
printf '# SOURCE-ONLY conditional plan; GAP lines block execution. Angle brackets are unresolved operands.\n'
printf '# Verified signed path; authoritative consumption and node allocation still require shared accounting.\n'

step '02 Container — LXD CLI; no repository image/profile provisioning script'
gap LXD_PROFILE_MISSING 'review image fingerprint, Ubuntu 24.04, nested rootless Podman, storage and resources; isolate networking until listener checks pass'
gap RESUME_CONTRACT_MISSING 'inspect and refuse an unrelated existing name; resume only the same verified admission/revision; never delete or clone staging'
command_step lxc --force-local info "$node"
printf '# Only if absent, after the preceding contracts are implemented:\n'
command_step lxc --force-local launch '<reviewed-ubuntu-24.04-image-fingerprint>' "$node" --profile '<reviewed-isolated-unprivileged-profile>'

step '03 Runtimes — packages/boundary-gate/host/systemd/README.md prerequisites'
gap RUNTIME_INSTALL_MISSING 'root-protected /opt/aukora-node Node 24.11.1, /usr/bin OpenShell 0.1.2, Podman, Python, pnpm, git, sudo, nftables and iproute2; no guessed downloads'
inside bash -c 'test "$(/opt/aukora-node/bin/node --version)" = v24.11.1 || { echo "REFUSED NODE_VERSION_MISMATCH" >&2; exit 1; }'
inside bash -c "$listener_check"

step '04 Principals — packages/boundary-gate/host/SETUP.md and host/auma-local-deny/install.sh'
gap PRINCIPAL_INSTALL_MISSING 'reconcile auma UID 1001, subuid/subgid 165536:65536, aukora-host, aukora-gate, skgate memberships; protected homes/runtime/targets/state; linger for auma'
printf '# Install root-owned sbx-exec and visudo-checked sudoers.template; no broader sudo grant.\n'

step '05 Source — plan/NORTH-STAR.md launcher/release equality rule'
gap SOURCE_INSTALL_MISSING 'install a clean root-protected checkout at /opt/aukora-genesis/src and a separate manifest staging checkout, both at the reviewed full release SHA'
inside git -C /opt/aukora-genesis/src rev-parse HEAD
inside bash -c 'test "$(git -C /opt/aukora-genesis/src rev-parse HEAD)" = "$1" || { echo "REFUSED SOURCE_RELEASE_MISMATCH" >&2; exit 1; }' spawn '<reviewed-full-release-sha>'
inside /usr/bin/python3 -I -S /opt/aukora-genesis/src/ops/node-spawn/install-member.py "$member_config"

step '06 Build — scripts/build-dsh.py; scripts/materialize-aukora-release.py'
inside /usr/bin/env PATH=/opt/aukora-node/bin:/usr/local/bin:/usr/bin:/bin bash -c 'cd /opt/aukora-genesis/src && /usr/bin/python3 scripts/build-dsh.py'
inside /usr/bin/env PATH=/opt/aukora-node/bin:/usr/local/bin:/usr/bin:/bin /usr/bin/python3 /opt/aukora-genesis/src/scripts/materialize-aukora-release.py --from /opt/aukora-genesis/src/vendor/dsh --to '/opt/aukora-genesis/release-<sha7>'
printf '# Keep that checkout at the same SHA through installation and every launch. Never use force/development/prune or preview waivers.\n'

step '07 Owner enrollment and local gate keys — separate authorities'
gap OWNER_ENROLLMENT_DERIVATION_MISSING 'cannot write /etc/aukora-boundary-gate/owner-state.json: ownerRootPin derives only P-256 SPKI identity; missing trusted owner_subject/root binding, active owner_epoch registry and exact registry_sha256/activation_sha256 producers; private keys stay on the member device'
gap FRESH_KEYS_MISSING 'generate gate-local owner-secret.json and receipt key inside its gate home, never copy them; protected startup already requires the new public signer epoch; no reviewed first-key route'
printf '# gate.mjs creates owner-secret.json and receipt-ed25519.pem locally; neither is member owner-key enrollment. Do not bypass bootstrap to create them.\n'

step '08 Custody — packages/boundary-gate/host/install/generate-manifest.py and gate-bootstrap.py'
gap GATE_INSTALL_MISSING 'stage/install complete gate and owner-key packages, bootstrap, public epochs, v2 manifest, host scripts and reviewed systemd units; no fresh installer exists'
inside /usr/bin/python3 -I -S /opt/aukora-genesis/src/packages/boundary-gate/host/install/generate-manifest.py --package '<staged-complete-gate-package>' --signer-epochs '<staged-public-signer-epochs.json>' --owner-key '<staged-complete-owner-key-package>' --launcher-checkout '<staged-same-commit-checkout>' --output '<new-staged-manifest.json>'
printf '# Fixed installs: /opt/aukora-boundary-gate, /opt/owner-key, /usr/local/lib/aukora-boundary, /etc/aukora-boundary-gate. Preserve protected root custody.\n'
printf '# Use host/systemd units; substitute SKGATE_GID with this container verified group, never a pilot ID. Gate owner HTTP stays disabled.\n'
inside /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package
inside /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-runtime
inside systemctl daemon-reload
inside /opt/aukora-genesis/src/host/auma-local-deny/install.sh

step '09 Podman — host/systemd/aukora-auma-podman.service calls openshell/podman-service.sh with no arguments'
inside systemctl enable --now aukora-auma-podman.service
step '10 Gateway — host/systemd/aukora-openshell-gateway.service calls openshell/gateway.sh'
gap OPENSHELL_BINARY_PROVENANCE_MISSING 'require reviewed /usr/bin/openshell and openshell-gateway 0.1.2 with custody patches; SETUP names Genesis lab 6fa70cd, but gives no pinned pilot binary installer or rebuild'
printf '# gateway.sh generates this node mTLS locally; its port setting does not prove the bind address. Keep networking isolated.\n'
inside systemctl enable --now aukora-openshell-gateway.service
inside bash -c "$listener_check"
step '11 Guest and sandbox — existing image builder, then admission-only ensure-sandbox.sh'
gap GUEST_IMAGE_INPUTS_MISSING 'guest-image/build.sh exists but release/plugins/aukora-openshell-confinement/guest/exec.py and its producer are absent; review NVIDIA Ubuntu base/apt provenance too'
inside sudo -n -u auma -H /usr/local/lib/aukora-boundary/openshell/guest-image/build.sh /opt/aukora-node/bin/node '/opt/aukora-genesis/release-<sha7>/plugins/aukora-openshell-confinement/guest/exec.py' '/opt/aukora-genesis/release-<sha7>/packages/ptc-runtime/ptc-runtime-node/lib/process.js'
gap SANDBOX_PRODUCER_MISSING 'qualified workspace mount producer and root-protected openshell-workspace.json/openshell-inventory.json required; --bootstrap-profile always refuses; SETUP and builder recreation comments are stale'
inside systemctl enable --now aukora-auma-sandbox.service

step '12 Gate and host state — host/systemd/aukora-boundary-gate.service calls gate-bootstrap serve'
gap NODE_STATE_MISSING 'provision private provider/state/support, allowlisted targets and reviewed linux-openshell.patch.yml without copying staging secrets'
inside systemctl enable --now aukora-boundary-gate.service

step '13 Release approval — gate-bootstrap approval delegates to bin/plugin-set-approval.mjs'
gap APPROVAL_RESUME_MISSING 'first inspect exact existing proof/floor; already approved release skips raise/install; ambiguous state refuses, never repin or reset floor'
inside /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap approval show --release-dir '/opt/aukora-genesis/release-<sha7>'
printf '# For a new release only:\n'
inside /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap approval raise --release-dir '/opt/aukora-genesis/release-<sha7>'
gap OWNER_APPROVAL_REQUIRED 'owner reviews the exact release card and approves through OWNER review/decide_review; this script never signs or clicks'
inside /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap approval install --release-dir '/opt/aukora-genesis/release-<sha7>' --out '/etc/aukora-approvals/<full-release-sha>/state/gate-state'

step '14 Release selection — host/systemd/aukora-genesis.release.env.example'
gap RELEASE_ENV_MISSING 'write root:root 0644 release.env with exact release directory, approval state root and approved genesis-artifacts.json SHA256; no placeholder hashes'
inside /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check --release-dir '/opt/aukora-genesis/release-<sha7>' --approval-state-root '/etc/aukora-approvals/<full-release-sha>/state'
inside bash -c 'test "$(git -C /opt/aukora-genesis/src rev-parse HEAD)" = "$1" || { echo "REFUSED SOURCE_RELEASE_MISMATCH" >&2; exit 1; }' spawn '<reviewed-full-release-sha>'

step '15 Harness — host/systemd/aukora-genesis.service calls scripts/launch-dsh.py'
printf '# Unit prechecks: gate-bootstrap check-package, check-runtime, selfcheck-with-retry, floor check.\n'
printf '# Unit launch: scripts/launch-dsh.py --release RELEASE --state-root /home/aukora-host/genesis/state --port 18735 --foreground --node /opt/aukora-node/bin/node --approval-state-root APPROVAL --approved-record-sha RECORD --patch RELEASE/aukora-composition.patch.yml --patch RELEASE/linux-openshell.patch.yml\n'
inside systemctl enable --now aukora-genesis.service aukora-selfcheck.timer

step '16 Auxiliary services — host/units, host/relay, host/aura-interim and ops/buzz-relay'
gap AUXILIARY_SETUP_MISSING 'OpenViking needs its own private root key and pinned model/runtime; relay unit pins an old release; Aura interim is not owner custody; one shared closed community relay, no per-member public relay'
printf '# Relevant entrypoints: scripts/openviking-setup.sh, host/relay/server.mjs, host/aura-interim/install.sh, ops/buzz-relay/install.sh; no automatic install without their node-specific prerequisites.\n'

step '17 Readback — systemd plus listener and HTTP observations, not an installation claim'
inside systemctl is-active aukora-genesis.service aukora-boundary-gate.service aukora-auma-podman.service aukora-openshell-gateway.service aukora-auma-sandbox.service aukora-auma-local-deny.service aukora-selfcheck.timer
inside systemctl show aukora-genesis.service --property=User,MainPID,ExecStart,WorkingDirectory
inside bash -c "$listener_check"
inside curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}\n' http://127.0.0.1:18735/
printf '# Expect unauthenticated 401; inspect actual loaded release and run the existing boundary selfcheck. Active services alone do not prove containment.\n'
