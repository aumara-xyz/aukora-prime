#!/usr/bin/env python3
# Install pinned fresh inputs and require protected approval before launch.
import argparse
import ast
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time

STATE = Path('/var/lib/aukora-browser')
CHECKOUT = Path('/opt/aukora-genesis/src')
NODE = '/opt/aukora-node/bin/node'
BOOT = '/usr/local/lib/aukora-boundary/gate-bootstrap'
ENV = {'PATH': '/opt/aukora-node/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
PRELOAD = ('NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME',
           'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT')


def refuse(code):
    raise ValueError('BROWSER_' + code)


def need(condition, code):
    if not condition:
        refuse(code)


def absolute(value):
    path = Path(value)
    need(path.is_absolute() and str(path) == value and str(path.resolve()) == value
         and not re.search(r'[\s\x00-\x1f\x7f]', value), 'PATH_INVALID')
    return path


def digest(value, revision=False):
    need(bool(re.fullmatch(r'[a-f0-9]{40}' if revision else r'[a-f0-9]{64}', value)), 'DIGEST_INVALID')
    return value


def protected(path, directory=False, uid=0, private=False):
    info = path.lstat()
    need(info.st_uid == uid and not info.st_mode & (0o077 if private else 0o022)
         and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
         'CUSTODY_INVALID')


def module(file):
    spec = importlib.util.spec_from_file_location('browser_' + file.stem.replace('-', '_'), file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(command, code, env=None, cwd=None, expected=0):
    result = subprocess.run(command, env=env or ENV, cwd=cwd, capture_output=True)
    need(result.returncode == expected, code)
    return result.stdout.decode()


def root_check():
    need(not any(key in os.environ for key in PRELOAD), 'PRELOAD_FORBIDDEN')
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    need(sys.platform == 'linux', 'LINUX_REQUIRED')
    release = Path('/etc/os-release').read_text()
    need(re.search(r'^ID=ubuntu$', release, re.M) is not None
         and re.search(r'^VERSION_ID="24\.04"$', release, re.M) is not None, 'UBUNTU_24_04_REQUIRED')


def extract(archive, target):
    # Reject special files, duplicate paths and links outside the new archive root.
    need(not target.exists() and not target.is_symlink(), 'EXTRACT_EXISTS')
    with tarfile.open(archive) as source:
        members = source.getmembers()
        need(0 < len(members) <= 500000 and sum(m.size for m in members) <= 8 * 1024**3, 'ARCHIVE_LIMIT')
        names = set()
        for member in members:
            name = member.name.rstrip('/')
            need(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/'))
                 and name not in names, 'ARCHIVE_PATH')
            names.add(name)
            need(member.isdir() or member.isfile() or member.issym(), 'ARCHIVE_TYPE')
            if member.issym():
                link = target / Path(name).parent / member.linkname
                need(not os.path.isabs(member.linkname) and link.resolve().is_relative_to(target.resolve()), 'ARCHIVE_LINK')
        links = {m.name.rstrip('/') for m in members if m.issym()}
        for name in names:
            need(not any(parent.as_posix() in links
                         for parent in Path(name).parents if parent != Path('.')), 'ARCHIVE_LINK_PARENT')
        target.mkdir(mode=0o700)
        for member in members:
            path = target / member.name.rstrip('/')
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with source.extractfile(member) as content, path.open('xb') as output:
                    shutil.copyfileobj(content, output)
                path.chmod(member.mode & 0o755)
        for member in members:
            if member.issym():
                path = target / member.name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                path.symlink_to(member.linkname)
    for folder, dirs, files in os.walk(target, followlinks=False):
        for entry in [Path(folder)] + [Path(folder) / name for name in files]:
            if not entry.is_symlink():
                entry.chmod((entry.stat().st_mode & 0o755) & ~0o022)


def checked_inputs(options, stage):
    inputs = absolute(options.inputs)
    protected(inputs, True)
    for name, expected in [('checkout.bundle', options.checkout_sha256), ('node.tar.xz', options.node_sha256),
                           ('dependencies.tar.gz', options.dependencies_sha256)]:
        file = inputs / name
        protected(file)
        need(stage.digest_file(file) == digest(expected), 'INPUT_DIGEST_MISMATCH')
    protected(inputs / 'dsh-source.tar.gz')
    digest(options.revision, True)
    return inputs


def installed():
    protected(STATE, True)
    file = STATE / 'installed.json'
    protected(file)
    value = json.loads(file.read_text())
    need(isinstance(value, dict) and set(value) == {'revision', 'inputs'} and isinstance(value['inputs'], dict), 'INSTALL_RECORD_INVALID')
    digest(value['revision'], True)
    return value


def release_paths(value):
    revision = value['revision']
    return Path('/opt/aukora-genesis/release-' + revision[:7]), Path('/etc/aukora-approvals') / revision / 'state'


def bootstrap(*arguments):
    return run(['/usr/bin/python3', '-I', '-S', BOOT, *map(str, arguments)], 'BOOTSTRAP_REFUSED')


def sockets():
    for attempt in range(60):
        if all(Path('/run/aukora-gate/' + name).is_socket() for name in ('gate.sock', 'owner.sock')):
            return
        time.sleep(0.5)
    refuse('GATE_SOCKETS_MISSING')


def profile_rules():
    file = CHECKOUT / 'scripts/materialize-aukora-release.py'
    protected(file)
    names = {'BROWSER_DISABLED_ROWS', 'BROWSER_REFUSAL_ENTRY', 'BROWSER_REFUSAL_SOURCE'}
    rules = {}
    for node in ast.parse(file.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names:
            rules[node.targets[0].id] = ast.literal_eval(node.value)
    need(set(rules) == names, 'PROFILE_RULES_MISSING')
    return rules


def profile(release):
    rules = profile_rules()
    file = release / 'browser-node-profile.patch.yml'
    prefix = '# aukora-browser-node-profile '
    text = file.read_text()
    need(text.startswith(prefix) and text.count('\n') == 1, 'PROFILE_INVALID')
    value = json.loads(text[len(prefix):])
    need(set(value) == {'formatVersion', 'kind', 'relay', 'buzz', 'disabledRows', 'presets', 'refusalEntry', 'refusalSha256'}
         and value.get('formatVersion') == 1 and value.get('kind') == 'aukora-browser-node-profile'
         and value.get('relay') is False and value.get('buzz') is False
         and isinstance(value.get('presets'), dict) and bool(value['presets'])
         and value.get('disabledRows') == list(rules['BROWSER_DISABLED_ROWS']), 'PROFILE_INVALID')
    need(not any((release / 'plugins' / name).exists() for name in ('aukora-relay-auma', 'aukora-buzz-door')), 'NETWORK_PLUGIN_PRESENT')
    need(value.get('refusalEntry') == rules['BROWSER_REFUSAL_ENTRY']
         and value.get('refusalSha256') == hashlib.sha256(rules['BROWSER_REFUSAL_SOURCE'].encode()).hexdigest()
         and hashlib.sha256((release / value['refusalEntry']).read_bytes()).hexdigest()
         == digest(value.get('refusalSha256', '')), 'REFUSAL_MODULE_CHANGED')
    composition = (release / 'aukora-composition.patch.yml').read_text()
    policy = json.loads((release / 'plugins/aukora-composition-gate/policy.json').read_text())
    need('name: ./' + rules['BROWSER_REFUSAL_ENTRY'] in composition
         and 'aukora-browser-refusal' in policy.get('pluginSet', []), 'REFUSAL_NOT_MOUNTED')
    for relative, expected in value['presets'].items():
        need(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'PROFILE_INVALID')
        need(hashlib.sha256((release / relative).read_bytes()).hexdigest() == digest(expected), 'PRESET_CHANGED')
    return value


def install(options):
    root_check()
    here = Path(__file__).resolve().parent
    stage = module(here.parent / 'stage.py' if (here.parent / 'stage.py').is_file() else here / 'stage.py')
    inputs = checked_inputs(options, stage)
    binding = {'checkout': options.checkout_sha256, 'node': options.node_sha256,
               'dependencies': options.dependencies_sha256, 'harness': stage.digest_file(inputs / 'dsh-source.tar.gz')}
    if (STATE / 'installed.json').exists():
        need(installed() == {'revision': options.revision, 'inputs': binding}, 'RERUN_CONFLICT')
        bootstrap('check-package')
        bootstrap('check-runtime')
        profile(release_paths(installed())[0])
        sockets()
        print('BROWSER_ALREADY_INSTALLED')
        return
    need(not STATE.exists() and not STATE.is_symlink(), 'PARTIAL_INSTALL_REQUIRES_REVIEW')
    for name in ('aukora-host', 'aukora-gate'):
        result = subprocess.run(['getent', 'passwd', name], env=ENV, capture_output=True)
        need(result.returncode == 2, 'USER_EXISTS')
    for name in ('/opt/aukora-genesis', '/opt/aukora-node', '/opt/aukora-boundary-gate', '/opt/owner-key',
                 '/etc/aukora-boundary-gate', '/etc/aukora-approvals', '/etc/aukora-genesis',
                 '/home/aukora-gate', '/home/aukora-host', '/etc/systemd/system/aukora-browser.service',
                 '/etc/systemd/system/aukora-boundary-gate.service'):
        need(not Path(name).exists() and not Path(name).is_symlink(), 'INSTALL_EXISTS')
    for name in ('/var', '/var/lib', '/opt', '/home', '/etc', '/etc/systemd', '/etc/systemd/system',
                 '/usr', '/usr/local', '/usr/local/lib', '/var/lib/aukora-boundary', '/usr/local/lib/aukora-boundary'):
        if Path(name).exists() or Path(name).is_symlink():
            protected(Path(name), True)
    STATE.mkdir(mode=0o700)
    deps = STATE / 'dependencies'
    extract(inputs / 'dependencies.tar.gz', deps)
    debs = sorted((deps / 'debs').glob('*.deb'))
    need(bool(debs) and (deps / 'pnpm/bin/pnpm.cjs').is_file() and (deps / 'store').is_dir(), 'DEPENDENCIES_MISSING')
    run(['dpkg', '--install', *map(str, debs)], 'OS_DEPENDENCIES_REFUSED')
    checkout = STATE / 'checkout'
    run(['git', 'clone', '--quiet', '--no-local', '--', str(inputs / 'checkout.bundle'), str(checkout)], 'CLONE_REFUSED')
    run(['git', 'bundle', 'verify', str(inputs / 'checkout.bundle')], 'BUNDLE_INVALID', cwd=checkout)
    run(['git', '-C', str(checkout), 'checkout', '--quiet', '--detach', options.revision], 'REVISION_MISSING')
    stage.source_check({'source_checkout': str(checkout), 'release_commit': options.revision})
    pin = json.loads((checkout / 'upstream-dsh.json').read_text())
    fresh = module(checkout / 'scripts/fresh_clone.py')
    fresh.verify_archive(inputs / 'dsh-source.tar.gz', pin)
    shutil.copyfile(inputs / 'dsh-source.tar.gz', checkout / 'vendor/dsh-source.tar.gz')
    node_tree = STATE / 'node-tree'
    extract(inputs / 'node.tar.xz', node_tree)
    names = list(node_tree.iterdir())
    need(len(names) == 1 and re.fullmatch(r'node-v24\.11\.1-linux-(x64|arm64)', names[0].name), 'NODE_ARCHIVE_INVALID')
    node = names[0]
    need((node / 'include/node/node_api.h').is_file(), 'NODE_HEADERS_MISSING')
    need(run([str(node / 'bin/node'), '--version'], 'NODE_INVALID').strip() == 'v24.11.1', 'NODE_VERSION_MISMATCH')
    stage.public_modes(node)
    node.rename('/opt/aukora-node')
    tools = STATE / 'tools'
    tools.mkdir(mode=0o755)
    (tools / 'pnpm').write_text('#!/bin/sh\nexec /opt/aukora-node/bin/node ' + str(deps / 'pnpm/bin/pnpm.cjs') + ' "$@"\n')
    (tools / 'pnpm').chmod(0o755)
    env = dict(ENV)
    build_home = STATE / 'build-home'
    build_home.mkdir(mode=0o700)
    env.update(HOME=str(build_home), PATH=str(tools) + ':' + ENV['PATH'], npm_config_offline='true',
               npm_config_store_dir=str(deps / 'store'), CI='true', PYTHONDONTWRITEBYTECODE='1')
    fresh.work = STATE
    os.environ['PATH'] = env['PATH']
    fresh.preflight()
    need(run([str(tools / 'pnpm'), '--version'], 'PNPM_INVALID', env).strip() == pin['packageManager'].removeprefix('pnpm@'), 'PNPM_VERSION_MISMATCH')
    fresh.run(['python3', str(checkout / 'scripts/build-dsh.py')], 'build', checkout, env)
    fresh.verify_built(checkout / 'vendor/dsh', checkout, env)
    release = Path('/opt/aukora-genesis/release-' + options.revision[:7])
    release.parent.mkdir(mode=0o755)
    env['AUKORA_STATE'] = '/home/aukora-host/genesis/state'
    fresh.run(['python3', str(checkout / 'scripts/materialize-aukora-release.py'), '--browser-node',
               '--from', str(checkout / 'vendor/dsh'), '--to', str(release)], 'materialize', checkout, env)
    stage.public_modes(release)
    profile(release)
    gate = STATE / 'gate-package'
    owner = STATE / 'owner-key'
    shutil.copytree(checkout / 'packages/boundary-gate', gate)
    shutil.copytree(checkout / 'packages/owner-key', owner)
    run(['groupadd', '--system', 'skgate'], 'GROUP_CREATE_REFUSED')
    for name, group in [('aukora-gate', 'skgate'), ('aukora-host', 'aukora-host')]:
        arguments = ['useradd', '--system', '--home-dir', '/home/' + name, '--shell', '/usr/sbin/nologin']
        arguments += ['--gid', group] if name == 'aukora-gate' else ['--user-group', '--groups', 'skgate']
        run(arguments + [name], 'USER_CREATE_REFUSED')
        run(['install', '-d', '-m', '0700', '-o', name, '-g', group, '/home/' + name], 'HOME_CREATE_REFUSED')
    for tree, output in [(gate, '/opt/aukora-boundary-gate'), (owner, '/opt/owner-key')]:
        stage.public_modes(tree)
        tree.rename(output)
    run(['runuser', '-u', 'aukora-gate', '--', NODE, '--input-type=module', '-e',
         (checkout / 'ops/node-spawn/browser/keys.mjs').read_text()], 'KEY_GENERATION_REFUSED')
    epochs = STATE / 'signer-epochs.json'
    shutil.copyfile('/home/aukora-gate/signer-epochs.json', epochs)
    # Manifest generator requires staged inputs outside all installed paths.
    shutil.copytree('/opt/aukora-boundary-gate', gate)
    shutil.copytree('/opt/owner-key', owner)
    run(['python3', '-I', '-S', str(gate / 'host/install/generate-manifest.py'), '--package', str(gate),
         '--owner-key', str(owner), '--launcher-checkout', str(checkout), '--signer-epochs', str(epochs),
         '--output', str(STATE / 'manifest.json')], 'MANIFEST_REFUSED')
    stage.public_modes(checkout)
    checkout.rename(CHECKOUT)
    config = module(CHECKOUT / 'ops/node-spawn/configure-host.py')
    for source, destination, mode in [(epochs, Path('/etc/aukora-boundary-gate/signer-epochs.json'), 0o644),
        (STATE / 'manifest.json', Path('/etc/aukora-boundary-gate/gate-package-manifest.json'), 0o644),
        (Path('/opt/aukora-boundary-gate/host/install/gate-bootstrap.py'), Path(BOOT), 0o755)]:
        config.write(destination, source.read_bytes(), Path('/'), mode)
    target = Path('/var/lib/aukora-boundary/targets')
    run(['install', '-d', '-m', '0750', '-o', 'aukora-gate', '-g', 'skgate', str(target)], 'TARGET_CREATE_REFUSED')
    for name in ('', 'state', 'support', 'state/home', 'state/agents', 'state/workspace', 'state/logs'):
        run(['install', '-d', '-m', '0700', '-o', 'aukora-host', '-g', 'aukora-host', '/home/aukora-host/genesis/' + name], 'STATE_CREATE_REFUSED')
    config_path = STATE / 'spawn.json'
    config_path.write_text(json.dumps({'release_commit': options.revision}))
    config_path.chmod(0o600)
    run(['python3', '-I', '-S', str(CHECKOUT / 'ops/node-spawn/configure-host.py'), 'release-env', str(config_path), '/'], 'RELEASE_ENV_REFUSED')
    units(config)
    bootstrap('check-package')
    bootstrap('check-runtime')
    run(['systemctl', 'daemon-reload'], 'SYSTEMD_REFUSED')
    run(['systemctl', 'enable', '--now', 'aukora-boundary-gate.service'], 'GATE_START_REFUSED')
    sockets()
    bootstrap('approval', 'raise', '--release-dir', release)
    value = {'revision': options.revision, 'inputs': binding}
    config.write(STATE / 'installed.json', (json.dumps(value, sort_keys=True) + '\n').encode(), Path('/'))
    print('BROWSER_INSTALLED_PENDING_OWNER_APPROVAL; harness stopped; bearer never printed')


def units(config):
    group = run(['getent', 'group', 'skgate'], 'GROUP_MISSING').strip().split(':')[2]
    need(group.isdigit(), 'GROUP_INVALID')
    gate = (CHECKOUT / 'packages/boundary-gate/host/systemd/aukora-boundary-gate.service').read_text()
    gate = gate.replace('SKGATE_GID', group).replace(' --port 17792', ' --owner-page --port 17792')
    config.write(Path('/etc/systemd/system/aukora-boundary-gate.service'), gate.encode(), Path('/'))
    data = '''[Unit]
Description=AUKORA restricted browser node (effect providers disabled)
After=aukora-boundary-gate.service
Requires=aukora-boundary-gate.service
[Service]
User=aukora-host
Group=aukora-host
Type=exec
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/aukora-host/genesis
PrivateTmp=yes
WorkingDirectory=/opt/aukora-genesis/src
EnvironmentFile=/etc/aukora-genesis/release.env
Environment=PATH=/opt/aukora-node/bin:/usr/bin:/bin
Environment=AUKORA_SUPPORT_ROOT=/home/aukora-host/genesis/support
UnsetEnvironment=NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
ExecStartPre=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package
ExecStartPre=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-runtime
ExecStartPre=/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py verify-profile --release ${AUKORA_RELEASE_DIR}
ExecStartPre=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check --release-dir ${AUKORA_RELEASE_DIR} --approval-state-root ${AUKORA_APPROVAL_ROOT}
ExecStart=/usr/bin/python3 scripts/launch-dsh.py --release ${AUKORA_RELEASE_DIR} --state-root /home/aukora-host/genesis/state --port 18735 --foreground --node /opt/aukora-node/bin/node --approval-state-root ${AUKORA_APPROVAL_ROOT} --approved-record-sha ${AUKORA_RECORD_SHA} --patch ${AUKORA_RELEASE_DIR}/aukora-composition.patch.yml
KillMode=control-group
Restart=no
[Install]
WantedBy=multi-user.target
'''
    config.write(Path('/etc/systemd/system/aukora-browser.service'), data.encode(), Path('/'))


def start():
    root_check()
    value = installed()
    release, approval = release_paths(value)
    profile(release)
    bootstrap('check-package')
    bootstrap('check-runtime')
    sockets()
    config = module(CHECKOUT / 'ops/node-spawn/configure-host.py')
    config.parents(approval / 'gate-state', Path('/'))
    command = ['/usr/bin/python3', '-I', '-S', BOOT, 'approval', 'recover-cache',
               '--release-dir', str(release), '--out', str(approval / 'gate-state')]
    recovered = subprocess.run(command, env=ENV, capture_output=True)
    if recovered.returncode != 0:
        bootstrap('approval', 'install', '--release-dir', release, '--out', approval / 'gate-state')
    for folder, dirs, files in os.walk(approval):
        for path in [Path(folder)] + [Path(folder) / name for name in files]:
            protected(path, path.is_dir())
            path.chmod(0o755 if path.is_dir() else 0o644)
    Path('/etc/aukora-approvals/release-floor.json').chmod(0o644)
    run(['runuser', '-u', 'aukora-host', '--', '/usr/bin/python3', '-I', '-S', BOOT,
         'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)], 'FLOOR_REFUSED')
    run(['systemctl', 'enable', '--now', 'aukora-browser.service'], 'HARNESS_START_REFUSED')
    print('BROWSER_STARTED; verify acceptance and the actual browser separately')


def listeners(text):
    rows = text.splitlines()[1:]
    need(bool(rows), 'LISTENERS_MISSING')
    endpoints = [row.split()[3] for row in rows if len(row.split()) >= 4]
    try:
        local = all(ipaddress.ip_address(item.rsplit(':', 1)[0].strip('[]')).is_loopback for item in endpoints)
    except ValueError:
        local = False
    need(len(endpoints) == len(rows) and local, 'NON_LOOPBACK_LISTENER')
    need('127.0.0.1:17792' in endpoints, 'OWNER_LISTENER_MISSING')
    return endpoints


def accept(phase):
    root_check()
    value = installed()
    release, approval = release_paths(value)
    profile(release)
    for name, group in [('aukora-host', 'aukora-host'), ('aukora-gate', 'skgate')]:
        row = run(['getent', 'passwd', name], 'USER_MISSING').strip().split(':')
        need(len(row) == 7 and row[5] == '/home/' + name and row[6] == '/usr/sbin/nologin'
             and row[2] != '0', 'USER_INVALID')
        protected(Path(row[5]), True, int(row[2]), True)
        groups = run(['id', '-nG', name], 'GROUP_MISSING').split()
        need(set(groups) == ({'aukora-host', 'skgate'} if name == 'aukora-host' else {'skgate'}), 'USER_GROUP_INVALID')
        if name == 'aukora-gate':
            for file in ('owner-secret.json', 'receipt-ed25519.pem'):
                protected(Path(row[5]) / file, uid=int(row[2]), private=True)
    for path in (Path('/opt/aukora-boundary-gate'), Path('/opt/owner-key'), Path('/opt/aukora-node'), CHECKOUT, release):
        for folder, dirs, files in os.walk(path, followlinks=False):
            for entry in [Path(folder)] + [Path(folder) / name for name in dirs + files]:
                if entry.is_symlink():
                    need(entry.resolve().is_relative_to(path), 'PACKAGE_LINK')
                else:
                    protected(entry, entry.is_dir())
    need(run([NODE, '--version'], 'NODE_INVALID').strip() == 'v24.11.1', 'NODE_VERSION_MISMATCH')
    bootstrap('check-package')
    bootstrap('check-runtime')
    sockets()
    run(['runuser', '-u', 'aukora-gate', '--', NODE, str(CHECKOUT / 'ops/node-spawn/configure.mjs'),
         'signer', '/home/aukora-gate/receipt-ed25519.pem', '/etc/aukora-boundary-gate/signer-epochs.json'], 'SIGNER_REFUSED')
    epochs = json.loads(Path('/etc/aukora-boundary-gate/signer-epochs.json').read_text())
    print('GATE_SIGNER_SHA256 ' + epochs['epochs'][-1]['gate_pubkey_sha256'])
    endpoints = listeners(run(['ss', '-ltn'], 'LISTENERS_UNAVAILABLE'))
    if phase == 'before':
        need(not Path('/etc/aukora-approvals/release-floor.json').exists(), 'ALREADY_APPROVED')
        command = ['/usr/bin/python3', '-I', '-S', BOOT, 'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)]
        result = subprocess.run(command, env=ENV, capture_output=True)
        need(result.returncode != 0, 'UNAPPROVED_FLOOR_ACCEPTED')
        result = subprocess.run(['systemctl', 'start', 'aukora-browser.service'], env=ENV, capture_output=True)
        need(result.returncode != 0, 'UNAPPROVED_HARNESS_STARTED')
        active = subprocess.run(['systemctl', 'is-active', '--quiet', 'aukora-browser.service'], env=ENV, capture_output=True)
        need(active.returncode != 0, 'UNAPPROVED_HARNESS_ACTIVE')
        endpoints = listeners(run(['ss', '-ltn'], 'LISTENERS_UNAVAILABLE'))
        need('127.0.0.1:18735' not in endpoints, 'UNAPPROVED_LISTENER')
        need(not Path('/home/aukora-host/genesis/state/launch-url.json').exists(), 'UNAPPROVED_DESCRIPTOR')
        print('PASS | harness refuses before approval')
    else:
        bootstrap('floor', 'check', '--release-dir', release, '--approval-state-root', approval)
        run(['systemctl', 'is-active', '--quiet', 'aukora-browser.service'], 'HARNESS_INACTIVE')
        need('127.0.0.1:18735' in endpoints, 'HARNESS_LISTENER_MISSING')
        print(run(['runuser', '-u', 'aukora-host', '--', NODE, str(CHECKOUT / 'ops/pilot/ui-probe.mjs')], 'UI_PROBE_REFUSED').strip())
        invocation = run(['systemctl', 'show', '-p', 'InvocationID', '--value', 'aukora-browser.service'], 'JOURNAL_UNAVAILABLE').strip()
        need(bool(re.fullmatch(r'[0-9a-f]{32}', invocation)), 'JOURNAL_UNAVAILABLE')
        journal = run(['journalctl', '--no-pager', '-o', 'cat', '_SYSTEMD_INVOCATION_ID=' + invocation], 'JOURNAL_UNAVAILABLE')
        need(not re.search(r'^aukora-[a-z-]+ \(file://.*\): Error', journal, re.M), 'PLUGIN_LOAD_FAILED')
        print('PASS | approved signed-in UI and plugin load')
    print('PASS | users modes package pins and loopback listeners')


class Parser(argparse.ArgumentParser):
    def error(self, message):
        refuse('USAGE')


def main(args):
    parser = Parser(add_help=False)
    parser.add_argument('action', choices=['install', 'start', 'status', 'remove', 'accept', 'verify-profile'])
    parser.add_argument('--inputs')
    for key in ('checkout-sha256', 'revision', 'node-sha256', 'dependencies-sha256'):
        parser.add_argument('--' + key)
    parser.add_argument('--phase', choices=['before', 'after'])
    parser.add_argument('--release')
    need(len([a for a in args if a.startswith('--')]) == len(set(a for a in args if a.startswith('--'))), 'USAGE')
    options = parser.parse_args(args)
    fields = ('inputs', 'checkout_sha256', 'revision', 'node_sha256', 'dependencies_sha256')
    need(all(getattr(options, key) is not None for key in fields) if options.action == 'install'
         else all(getattr(options, key) is None for key in fields), 'USAGE')
    need((options.phase is not None) == (options.action == 'accept'), 'USAGE')
    need((options.release is not None) == (options.action == 'verify-profile'), 'USAGE')
    if options.action == 'install':
        absolute(options.inputs)
        for key in fields[1:]:
            digest(getattr(options, key), key == 'revision')
        install(options)
    elif options.action == 'start':
        start()
    elif options.action == 'accept':
        accept(options.phase)
    elif options.action == 'verify-profile':
        release = absolute(options.release)
        need(bool(re.fullmatch(r'/opt/aukora-genesis/release-[0-9a-f]{7}', str(release))), 'PROFILE_RELEASE_INVALID')
        for parent in [release, *release.parents]:
            protected(parent, True)
        profile(release)
        print('BROWSER_PROFILE_VERIFIED')
    elif options.action == 'remove':
        root_check()
        installed()
        run(['systemctl', 'disable', '--now', 'aukora-browser.service', 'aukora-boundary-gate.service'], 'REMOVE_REFUSED')
        print('BROWSER_DEACTIVATED; protected state and floor retained')
    else:
        root_check()
        value = installed()
        release, approval = release_paths(value)
        bootstrap('check-package')
        print('BROWSER_INSTALLED revision=' + value['revision'])
        for name in ('aukora-boundary-gate.service', 'aukora-browser.service'):
            result = subprocess.run(['systemctl', 'is-active', name], env=ENV, capture_output=True)
            print(name + ' ' + ('active' if result.returncode == 0 else 'inactive'))
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', BOOT, 'floor', 'check', '--release-dir', str(release), '--approval-state-root', str(approval)], env=ENV, capture_output=True)
        print('FLOOR ' + ('verified' if result.returncode == 0 else 'not verified'))


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as error:
        code = str(error)
        print('REFUSED ' + (code if re.fullmatch(r'BROWSER_[A-Z_]+', code) else 'BROWSER_OPERATION_REFUSED'), file=sys.stderr)
        sys.exit(1)
