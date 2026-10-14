#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Create a fresh unprivileged offline container with host-loopback proxies.
set -euo pipefail
umask 077
refuse() { printf 'REFUSED %s\n' "$1" >&2; exit 1; }
name= image= inputs= checkout_sha= revision= node_sha= dependencies_sha= app_port= owner_port= claim_port= app_host= owner_host= seen=
openviking_bundle= openviking_sha=
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || refuse BROWSER_CREATE_USAGE
  [[ "|$seen|" != *"|$1|"* ]] || refuse BROWSER_CREATE_DUPLICATE_ARGUMENT
  seen="$seen|$1"
  case $1 in
    --name) name=$2 ;;
    --image) image=$2 ;;
    --inputs) inputs=$2 ;;
    --checkout-sha256) checkout_sha=$2 ;;
    --revision) revision=$2 ;;
    --node-sha256) node_sha=$2 ;;
    --dependencies-sha256) dependencies_sha=$2 ;;
    --app-port) app_port=$2 ;;
    --owner-port) owner_port=$2 ;;
    --claim-port) claim_port=$2 ;;
    --app-host) app_host=$2 ;;
    --owner-host) owner_host=$2 ;;
    --openviking-bundle) openviking_bundle=$2 ;;
    --openviking-sha256) openviking_sha=$2 ;;
    *) refuse BROWSER_CREATE_USAGE ;;
  esac
  shift 2
done
[[ -z $openviking_bundle && -z $openviking_sha || -n $openviking_bundle && -n $openviking_sha ]] || refuse BROWSER_CREATE_OPENVIKING_PAIR_REQUIRED
if [[ -n $openviking_bundle ]]; then
  [[ $openviking_sha =~ ^[0-9a-f]{64}$ ]] || refuse BROWSER_CREATE_OPENVIKING_DIGEST_INVALID
  [[ $openviking_bundle == /* && $openviking_bundle != / && $openviking_bundle != *$'\n'* && $openviking_bundle != *$'\r'* ]] || refuse BROWSER_CREATE_OPENVIKING_PATH_INVALID
fi
[[ -n $name && -n $image && -n $inputs && -n $checkout_sha && -n $revision && -n $node_sha && -n $dependencies_sha && -n $app_port && -n $owner_port && -n $claim_port && -n $app_host && -n $owner_host ]] || refuse BROWSER_CREATE_USAGE
[[ ${#name} -le 63 && $name =~ ^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*$ ]] || refuse BROWSER_CREATE_NAME_INVALID
[[ $image =~ ^[0-9a-f]{64}$ ]] || refuse BROWSER_CREATE_IMAGE_INVALID
[[ $revision =~ ^[0-9a-f]{40}$ ]] || refuse BROWSER_CREATE_REVISION_INVALID
for pin in "$checkout_sha" "$node_sha" "$dependencies_sha"; do
  [[ $pin =~ ^[0-9a-f]{64}$ ]] || refuse BROWSER_CREATE_DIGEST_INVALID
done
for port in "$app_port" "$owner_port" "$claim_port"; do
  [[ $port =~ ^[1-9][0-9]{3,4}$ && $port -ge 1024 && $port -le 65535 ]] || refuse BROWSER_CREATE_PORT_INVALID
done
[[ $app_port != "$owner_port" && $claim_port != "$app_port" && $claim_port != "$owner_port" ]] || refuse BROWSER_CREATE_PORT_CONFLICT
[[ $app_host != "$owner_host" ]] || refuse BROWSER_CREATE_HOST_CONFLICT
[[ $inputs == /* && $inputs != / && $inputs != *$'\n'* && $inputs != *$'\r'* ]] || refuse BROWSER_CREATE_INPUTS_INVALID
[[ ${LD_PRELOAD+x} != x && ${LD_LIBRARY_PATH+x} != x && ${LD_AUDIT+x} != x ]] || refuse BROWSER_CREATE_PRELOAD_FORBIDDEN
[[ $(uname -s) == Linux ]] || refuse BROWSER_CREATE_LINUX_REQUIRED
for tool in python3 git lxc; do command -v "$tool" >/dev/null 2>&1 || refuse BROWSER_CREATE_TOOL_REQUIRED; done
python3 -I -S - "$app_host" "$owner_host" <<'PY'
import re, sys
for value in sys.argv[1:]:
    labels = value.split('.')
    if (value != value.lower() or value == 'localhost' or len(value) > 253 or len(labels) < 2
            or re.search(r'[a-z]', labels[-1]) is None
            or any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) is None for label in labels)):
        print('REFUSED BROWSER_CREATE_HOST_INVALID', file=sys.stderr)
        sys.exit(1)
PY
lxc() { command lxc --force-local "$@"; }
inputs=${inputs%/}
work=
profile="browser-$name"
created_profile=0
created_container=0
complete=0
cleanup() {
  local result=$?
  trap - EXIT
  # AUKORA_BROWSER_KEEP_FAILED=1 leaves a failed node in place for the operator to inspect and remove.
  if [[ $complete == 0 && ${AUKORA_BROWSER_KEEP_FAILED:-0} != 1 ]]; then
    if [[ $created_container == 1 ]]; then lxc delete --force "$name" >/dev/null 2>&1 || printf "REFUSED BROWSER_CREATE_ROLLBACK_CONTAINER_FAILED\n" >&2; fi
    if [[ $created_profile == 1 ]]; then lxc profile delete "$profile" >/dev/null 2>&1 || printf "REFUSED BROWSER_CREATE_ROLLBACK_PROFILE_FAILED\n" >&2; fi
  fi
  if [[ -n $work ]]; then rm -rf -- "$work"; fi
  exit "$result"
}
trap cleanup EXIT
work=$(python3 -I -S - "$inputs" "$checkout_sha" "$node_sha" "$dependencies_sha" "$openviking_bundle" "$openviking_sha" <<'PY'
import hashlib, os, pathlib, shutil, stat, sys, tempfile
work = None
try:
    base = pathlib.Path(sys.argv[1])
    info = base.lstat()
    if not base.is_absolute() or base.resolve() != base or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('BROWSER_CREATE_INPUTS_CUSTODY')
    work = pathlib.Path(tempfile.mkdtemp(prefix='.browser-create-', dir=base))
    artifacts = [(name, base / name, expected) for name, expected in [('checkout.bundle', sys.argv[2]), ('node.tar.xz', sys.argv[3]), ('dependencies.tar.gz', sys.argv[4]), ('dsh-source.tar.gz', None)]]
    if sys.argv[5]:
        bundle = pathlib.Path(sys.argv[5])
        if bundle.resolve() != bundle:
            raise ValueError('BROWSER_CREATE_INPUTS_CUSTODY')
        artifacts.append(('openviking.tar.gz', bundle, sys.argv[6]))
    for name, file, expected in artifacts:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            os.close(fd)
            raise ValueError('BROWSER_CREATE_INPUT_FILE_CUSTODY')
        with os.fdopen(fd, 'rb') as source:
            digest = hashlib.sha256()
            with (work / name).open('xb') as output:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
                    output.write(block)
            if expected is not None and digest.hexdigest() != expected:
                raise ValueError('BROWSER_CREATE_INPUT_DIGEST_MISMATCH')
    print(work)
except (OSError, ValueError):
    if work is not None:
        shutil.rmtree(work)
    code = str(sys.exc_info()[1])
    print('REFUSED ' + (code if code.startswith('BROWSER_CREATE_') else 'BROWSER_CREATE_INPUTS_UNAVAILABLE'), file=sys.stderr)
    sys.exit(1)
PY
)
# A failed step repeats only the named refusal lines of its output; nothing else leaves the action log.
run() { local code=$1; shift; "$@" >"$work/action.log" 2>&1 || { grep -E '^REFUSED [A-Z0-9_]+$' "$work/action.log" >&2 || true; refuse "$code"; }; }
source_git() { env -i PATH="$PATH" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"; }
run BROWSER_CREATE_BUNDLE_INVALID source_git clone --quiet --no-checkout --no-local -- "$work/checkout.bundle" "$work/checkout"
run BROWSER_CREATE_REVISION_UNAVAILABLE source_git -C "$work/checkout" checkout --quiet --detach "$revision"
source_git -C "$work/checkout" rev-parse HEAD >"$work/revision" 2>"$work/action.log" || refuse BROWSER_CREATE_REVISION_UNAVAILABLE
[[ $(cat "$work/revision") == "$revision" ]] || refuse BROWSER_CREATE_REVISION_MISMATCH
python3 -I -S - "$work" <<'PY'
import hashlib, json, pathlib, re, sys
try:
    work = pathlib.Path(sys.argv[1])
    pin = json.loads((work / 'checkout/upstream-dsh.json').read_bytes())['archiveSha256']
    if not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin):
        raise ValueError('BROWSER_CREATE_HARNESS_PIN_INVALID')
    with (work / 'dsh-source.tar.gz').open('rb') as source:
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
        digest = digest.hexdigest()
    if digest != pin:
        raise ValueError('BROWSER_CREATE_HARNESS_DIGEST_MISMATCH')
    installer = work / 'checkout/ops/node-spawn/browser/install.sh'
    if not installer.is_file() or installer.is_symlink():
        raise ValueError('BROWSER_CREATE_INSTALLER_REQUIRED')
    helper = work / 'checkout/ops/node-spawn/stage.py'
    if not helper.is_file() or helper.is_symlink():
        raise ValueError('BROWSER_CREATE_HELPER_REQUIRED')
except (OSError, ValueError, TypeError, KeyError):
    code = str(sys.exc_info()[1])
    print('REFUSED ' + (code if code.startswith('BROWSER_CREATE_') else 'BROWSER_CREATE_CHECKOUT_INVALID'), file=sys.stderr)
    sys.exit(1)
PY
run BROWSER_CREATE_LXD_UNAVAILABLE lxc query /1.0/instances
mv "$work/action.log" "$work/instances.json"
run BROWSER_CREATE_LXD_UNAVAILABLE lxc query /1.0/profiles
mv "$work/action.log" "$work/profiles.json"
run BROWSER_CREATE_IMAGE_UNAVAILABLE lxc query "/1.0/images/$image"
mv "$work/action.log" "$work/image.json"
python3 -I -S - "$work" "$name" "$profile" "$image" <<'PY'
import json, pathlib, sys
try:
    work, name, profile, fingerprint = pathlib.Path(sys.argv[1]), *sys.argv[2:]
    for file, kind, target in [('instances.json', 'instances', name), ('profiles.json', 'profiles', profile)]:
        rows = json.loads((work / file).read_bytes())
        if not isinstance(rows, list) or any(not isinstance(row, str) or not row.startswith('/1.0/' + kind + '/') for row in rows):
            raise ValueError('BROWSER_CREATE_LXD_RESPONSE_INVALID')
        if '/1.0/' + kind + '/' + target in rows:
            raise ValueError('BROWSER_CREATE_' + ('NODE_EXISTS' if kind == 'instances' else 'PROFILE_EXISTS'))
    image = json.loads((work / 'image.json').read_bytes())
    properties = image.get('properties', {}) if isinstance(image, dict) else {}
    if not isinstance(properties, dict) or image.get('fingerprint') != fingerprint or image.get('type') != 'container' or str(properties.get('os')).lower() != 'ubuntu' or not (properties.get('release') in ('noble', '24.04') or properties.get('version') == '24.04'):
        raise ValueError('BROWSER_CREATE_IMAGE_NOT_UBUNTU_24_04')
except (OSError, ValueError, TypeError, AttributeError):
    code = str(sys.exc_info()[1])
    print('REFUSED ' + (code if code.startswith('BROWSER_CREATE_') else 'BROWSER_CREATE_LXD_RESPONSE_INVALID'), file=sys.stderr)
    sys.exit(1)
PY
run BROWSER_CREATE_STORAGE_REQUIRED lxc profile device get default root pool
pool=$(cat "$work/action.log")
[[ $pool =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || refuse BROWSER_CREATE_STORAGE_INVALID
run BROWSER_CREATE_PROFILE_FAILED lxc profile create "$profile"
created_profile=1
for setting in security.privileged=false security.nesting=false security.idmap.isolated=true security.devlxd=false limits.cpu=2 limits.memory=4GiB limits.memory.swap=false limits.processes=512 boot.autostart=false; do
  run BROWSER_CREATE_PROFILE_FAILED lxc profile set "$profile" "${setting%=*}" "${setting#*=}"
done
run BROWSER_CREATE_PROFILE_FAILED lxc profile device add "$profile" root disk path=/ "pool=$pool" size=20GiB
run BROWSER_CREATE_LAUNCH_FAILED lxc launch "$image" "$name" --profile "$profile"
created_container=1
run BROWSER_CREATE_COPY_FAILED lxc exec "$name" -- mkdir -m 0700 /root/aukora-browser-inputs /root/aukora-browser-installer
for file in checkout.bundle dsh-source.tar.gz node.tar.xz dependencies.tar.gz; do
  run BROWSER_CREATE_COPY_FAILED lxc file push "$work/$file" "$name/root/aukora-browser-inputs/$file" --mode 0600 --uid 0 --gid 0
done
openviking_args=()
if [[ -n $openviking_bundle ]]; then
  run BROWSER_CREATE_COPY_FAILED lxc file push "$work/openviking.tar.gz" "$name/root/aukora-browser-inputs/openviking.tar.gz" --mode 0600 --uid 0 --gid 0
  openviking_args=(--openviking-bundle /root/aukora-browser-inputs/openviking.tar.gz --openviking-sha256 "$openviking_sha")
fi
for script in "$work/checkout/ops/node-spawn/browser/"*; do
  [[ -f $script && ! -L $script ]] || refuse BROWSER_CREATE_INSTALLER_INVALID
  run BROWSER_CREATE_COPY_FAILED lxc file push "$script" "$name/root/aukora-browser-installer/${script##*/}" --mode 0700 --uid 0 --gid 0
done
run BROWSER_CREATE_COPY_FAILED lxc file push "$work/checkout/ops/node-spawn/stage.py" "$name/root/aukora-browser-installer/stage.py" --mode 0700 --uid 0 --gid 0
run BROWSER_CREATE_INSTALL_FAILED lxc exec "$name" -- /bin/bash /root/aukora-browser-installer/install.sh --inputs /root/aukora-browser-inputs --checkout-sha256 "$checkout_sha" --revision "$revision" --node-sha256 "$node_sha" --dependencies-sha256 "$dependencies_sha" --app-host "$app_host" --owner-host "$owner_host" ${openviking_args[@]+"${openviking_args[@]}"}
run BROWSER_CREATE_PROXY_FAILED lxc config device add "$name" browser-app proxy "listen=tcp:127.0.0.1:$app_port" connect=tcp:127.0.0.1:18735 bind=host nat=false security.uid=65534 security.gid=65534
run BROWSER_CREATE_PROXY_FAILED lxc config device add "$name" browser-owner proxy "listen=tcp:127.0.0.1:$owner_port" connect=tcp:127.0.0.1:17792 bind=host nat=false security.uid=65534 security.gid=65534
run BROWSER_CREATE_PROXY_FAILED lxc config device add "$name" browser-claim proxy "listen=tcp:127.0.0.1:$claim_port" connect=tcp:127.0.0.1:18736 bind=host nat=false security.uid=65534 security.gid=65534
complete=1
printf 'CREATED %s; harness stopped pending owner approval\n' "$name"
