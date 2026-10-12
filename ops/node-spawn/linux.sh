#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install a pinned Linux node only after both identities pass invite admission.
set -euo pipefail
umask 022
HERE=$(cd "${BASH_SOURCE[0]%/*}" && pwd)
refuse() { printf 'REFUSED %s\n' "$1" >&2; exit 1; }
dry=0; config=; root=/
while [[ $# -gt 0 ]]; do
  case $1 in
    --linux) shift ;;
    --dry-run) dry=1; shift ;;
    --config) [[ $# -ge 2 ]] || refuse SPAWN_USAGE; config=$2; shift 2 ;;
    --root) [[ $# -ge 2 ]] || refuse SPAWN_USAGE; root=$2; shift 2 ;;
    *) refuse SPAWN_USAGE ;;
  esac
done
[[ -n $config ]] || refuse SPAWN_USAGE
[[ ${NODE_OPTIONS+x} != x && ${NODE_PATH+x} != x && ${LD_PRELOAD+x} != x && ${LD_LIBRARY_PATH+x} != x && ${LD_AUDIT+x} != x ]] || refuse SPAWN_PRELOAD_FORBIDDEN
[[ $(node --version) == v24.11.1 ]] || refuse NODE_VERSION_MISMATCH
[[ $root == /* && $root != */../* && $root != */./* ]] || refuse SPAWN_ROOT_INVALID
[[ $dry == 1 || $root != / || $(id -u) == 0 ]] || refuse SPAWN_ROOT_REQUIRED
[[ $dry == 1 || $root != / || $(uname -s) == Linux ]] || refuse SPAWN_LINUX_REQUIRED
root=${root%/}
path() { printf '%s%s' "$root" "$1"; }
field() { python3 -I -S "$HERE/stage.py" field "$config" "$1"; }
run() { if [[ $dry == 1 ]]; then printf '%q ' "$@"; printf '\n'; else "$@"; fi; }
as_user() { local user=$1; shift; run runuser -u "$user" -- env HOME="$(path /home/"$user")" "$@"; }
service() { if [[ -n $root ]]; then run systemctl --root "$root" "$@"; else run systemctl "$@"; fi; }
account() {
  if [[ -z $root ]]; then getent "$1" "$2"; else
    [[ -f $root/etc/$1 ]] || return 1
    awk -F: -v name="$2" '$1 == name { print; found=1 } END { if (!found) exit 1 }' "$root/etc/$1"
  fi
}
step() { printf '# %s\n' "$1"; }
offer=$(field offer); auma_offer=$(field auma_offer); commit=$(field release_commit)
source=$(field source_checkout); built=$(field built_harness); door=$(field door_config)
stage_dir=$(path /var/lib/aukora-spawn/stage)
release=$(path /opt/aukora-genesis/release-"${commit:0:7}")
approval=$(path /etc/aukora-approvals/"$commit"/state)
bootstrap=$(path /usr/local/lib/aukora-boundary/gate-bootstrap)
node_key=$(path /home/aukora-member/.config/aukora-node/node-key)
auma_key=$(path /home/aukora-host/.config/aukora-buzz/auma.key)
node_record=$(path /home/aukora-member/.config/aukora-node/admission.json)
auma_record=$(path /home/aukora-host/.config/aukora-buzz/admission.json)
runtime=$(path /opt/aukora-node/bin/node)
installed_helpers=$(path /opt/aukora-genesis/src/ops/node-spawn)

verify_invites() {
  step '01 Verify signed offers and authoritative availability before installation'
  run node "$HERE/invite.mjs" preflight --config "$config" --offer "$offer"
  run node "$HERE/invite.mjs" preflight --config "$config" --offer "$auma_offer"
  run python3 -I -S "$HERE/stage.py" precheck "$config" "${root:-/}"
  if [[ $phase == 0 ]]; then
    [[ ! -e $node_key && ! -L $node_key && ! -e $auma_key && ! -L $auma_key ]] || refuse SPAWN_KEY_EXISTS
  fi
}
create_users() {
  step '02 Reconcile service users and private homes'
  if [[ $dry == 1 ]] || ! account group skgate >/dev/null; then run groupadd --root "${root:-/}" --system skgate; fi
  local user home entry uid group
  for user in aukora-member aukora-host aukora-gate auma; do
    home=$(path /home/"$user"); group=$user
    [[ $user != aukora-gate ]] || group=skgate
    if [[ $dry == 0 ]] && entry=$(account passwd "$user"); then
      [[ $(printf '%s' "$entry" | cut -d: -f6) == /home/"$user" ]] || refuse SPAWN_USER_CONFLICT
      [[ $user != auma || $(printf '%s' "$entry" | cut -d: -f3) == 1001 ]] || refuse SPAWN_USER_CONFLICT
      if [[ $user == aukora-host ]]; then
        entry=$(account group skgate)
        [[ ,${entry##*:}, == *,aukora-host,* ]] || refuse SPAWN_USER_CONFLICT
      fi
    else
      if [[ $user == auma ]]; then
        run useradd --root "${root:-/}" --system --uid 1001 --user-group --home-dir /home/auma --shell /usr/sbin/nologin auma
      elif [[ $user == aukora-gate ]]; then
        run useradd --root "${root:-/}" --system --gid skgate --home-dir /home/aukora-gate --shell /usr/sbin/nologin aukora-gate
      elif [[ $user == aukora-host ]]; then
        run useradd --root "${root:-/}" --system --user-group --groups skgate --home-dir /home/aukora-host --shell /usr/sbin/nologin aukora-host
      else
        run useradd --root "${root:-/}" --system --user-group --home-dir /home/"$user" --shell /usr/sbin/nologin "$user"
      fi
    fi
    run install -d -m 0700 -o "$user" -g "$group" "$home"
  done
  run install -d -m 0700 -o aukora-member -g aukora-member "${node_key%/*}"
  run install -d -m 0700 -o aukora-host -g aukora-host "${auma_key%/*}"
  run install -m 0600 -o aukora-member -g aukora-member "$config" "${node_key%/*}/spawn-config.json"
  run install -m 0600 -o aukora-member -g aukora-member "$offer" "${node_key%/*}/offer.json"
  run install -m 0600 -o aukora-host -g aukora-host "$config" "${auma_key%/*}/spawn-config.json"
  run install -m 0600 -o aukora-host -g aukora-host "$auma_offer" "${auma_key%/*}/offer.json"
  run install -m 0600 -o aukora-host -g aukora-host "$door" "${auma_key%/*}/door-template.json"
}
install_release() {
  step '03 Stage pinned runtime, materialize named commit, then publish launcher before package check'
  run python3 -I -S "$HERE/stage.py" stage "$config" "${root:-/}"
  run "$stage_dir/node/bin/node" --version
  if [[ $dry == 0 ]]; then [[ $("$stage_dir/node/bin/node" --version) == v24.11.1 ]] || refuse NODE_VERSION_MISMATCH; fi
  run env PATH="$stage_dir/node/bin:/usr/local/bin:/usr/bin:/bin" python3 -I -S "$stage_dir/checkout/scripts/build-dsh.py" --verify-built --source "$built"
  run env PATH="$stage_dir/node/bin:/usr/local/bin:/usr/bin:/bin" AUKORA_STATE="$(path /home/aukora-host/genesis/state)" python3 -I -S "$stage_dir/checkout/scripts/materialize-aukora-release.py" --from "$built" --to "$release"
  run python3 -I -S "$stage_dir/checkout/packages/boundary-gate/host/install/generate-manifest.py" --package "$stage_dir/gate-package" --signer-epochs "$stage_dir/signer-epochs.json" --owner-key "$stage_dir/owner-key" --launcher-checkout "$stage_dir/checkout" --output "$stage_dir/gate-package-manifest.json"
  run python3 -I -S "$HERE/stage.py" publish "$config" "${root:-/}"
  run python3 -I -S "$bootstrap" check-package
}
generate_keys() {
  step '04 Generate separate private keys as their actual readers'
  as_user aukora-member "$runtime" "$installed_helpers/invite.mjs" key --key-file "$node_key"
  as_user aukora-host "$runtime" "$installed_helpers/invite.mjs" key --key-file "$auma_key"
}
redeem_invites() {
  step '05 Redeem each offer for exactly its generated key at the one authority'
  as_user aukora-member "$runtime" "$installed_helpers/invite.mjs" redeem --config "${node_key%/*}/spawn-config.json" --offer "${node_key%/*}/offer.json" --key-file "$node_key" --out "$node_record"
  as_user aukora-host "$runtime" "$installed_helpers/invite.mjs" redeem --config "${auma_key%/*}/spawn-config.json" --offer "${auma_key%/*}/offer.json" --key-file "$auma_key" --out "$auma_record"
}
configure_door() {
  step '06 Write private door configuration without granting owner authority'
  run install -m 0600 -o aukora-host -g aukora-host "$node_record" "${auma_key%/*}/node-admission.json"
  as_user aukora-host "$runtime" "$installed_helpers/configure.mjs" door "${auma_key%/*}/door-template.json" "${auma_key%/*}/door.json" "${auma_key%/*}/spawn-config.json" "${auma_key%/*}/node-admission.json"
}
start_and_accept() {
  step '07 Preserve owner approval and release floor before starting the harness'
  run python3 -I -S "$HERE/configure-host.py" units "$config" "${root:-/}"
  service daemon-reload
  run python3 -I -S "$bootstrap" check-runtime
  service enable --now aukora-boundary-gate.service
  if [[ $dry == 1 || ! -f $(path /etc/aukora-approvals/release-floor.json) ]]; then
    run python3 -I -S "$bootstrap" approval show --release-dir "$release"
    if [[ $phase -lt 6 ]]; then
      run python3 -I -S "$bootstrap" approval raise --release-dir "$release"
      run python3 -I -S "$HERE/configure-host.py" mark-6 "$config" "${root:-/}"
    fi
    if ! run python3 -I -S "$bootstrap" approval install --release-dir "$release" --out "$approval/gate-state"; then owner_next; refuse OWNER_APPROVAL_REQUIRED; fi
  fi
  run python3 -I -S "$bootstrap" floor check --release-dir "$release" --approval-state-root "$approval"
  run python3 -I -S "$HERE/configure-host.py" release-env "$config" "${root:-/}"
  service enable --now aukora-genesis.service aukora-selfcheck.timer
  installed_acceptance
}
installed_acceptance() {
  run python3 -I -S "$bootstrap" check-package
  run python3 -I -S "$bootstrap" check-runtime
  run python3 -I -S "$bootstrap" floor check --release-dir "$release" --approval-state-root "$approval"
  service is-active aukora-boundary-gate.service aukora-genesis.service aukora-selfcheck.timer
  as_user aukora-host "$runtime" "$installed_helpers/configure.mjs" acceptance "$release" "$auma_key" "${auma_key%/*}/door.json"
}
owner_next() {
  step '08 Member action: enroll your own owner key through the owner enrollment route; review the exact release card yourself'
  printf '# No owner key, approval, model credential, OpenShell sandbox or relay was provisioned on your behalf.\n'
}

phase=0
if [[ $dry == 0 ]]; then phase=$(python3 -I -S "$HERE/configure-host.py" phase "$config" "${root:-/}"); fi
if [[ $dry == 0 && $phase == 8 ]]; then
  as_user aukora-member "$runtime" "$installed_helpers/invite.mjs" verify --config "${node_key%/*}/spawn-config.json" --record "$node_record" --key-file "$node_key"
  as_user aukora-host "$runtime" "$installed_helpers/invite.mjs" verify --config "${auma_key%/*}/spawn-config.json" --record "$auma_record" --key-file "$auma_key"
  installed_acceptance
  owner_next
  exit 0
fi
if [[ $phase -lt 3 ]]; then verify_invites; fi
if [[ $phase -lt 1 ]]; then
  create_users
  install_release
  run python3 -I -S "$HERE/configure-host.py" mark-1 "$config" "${root:-/}"
fi
if [[ $dry == 0 && ! -f $(path /etc/aukora-boundary-gate/owner-state.json) ]]; then owner_next; refuse OWNER_ENROLLMENT_REQUIRED; fi
run python3 -I -S "$HERE/configure-host.py" prerequisites "$config" "${root:-/}"
as_user aukora-gate "$runtime" "$installed_helpers/configure.mjs" signer "$(path /home/aukora-gate/receipt-ed25519.pem)" "$(path /etc/aukora-boundary-gate/signer-epochs.json)"
if [[ $phase -lt 2 ]]; then generate_keys; run python3 -I -S "$HERE/configure-host.py" mark-2 "$config" "${root:-/}"; fi
if [[ $phase -lt 3 ]]; then redeem_invites; run python3 -I -S "$HERE/configure-host.py" mark-3 "$config" "${root:-/}"; fi
if [[ $phase -lt 4 ]]; then configure_door; run python3 -I -S "$HERE/configure-host.py" mark-4 "$config" "${root:-/}"; fi
run python3 -I -S "$HERE/configure-host.py" mark-5 "$config" "${root:-/}"
start_and_accept
run python3 -I -S "$HERE/configure-host.py" mark-7 "$config" "${root:-/}"
run python3 -I -S "$HERE/configure-host.py" mark-8 "$config" "${root:-/}"
owner_next
