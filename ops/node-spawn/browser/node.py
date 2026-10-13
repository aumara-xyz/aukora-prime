#!/usr/bin/env python3
# Install pinned fresh inputs and require protected approval before launch.
import argparse
import ast
import errno
import getpass
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import warnings

STATE = Path('/var/lib/aukora-browser')
CHECKOUT = Path('/opt/aukora-genesis/src')
NODE = '/opt/aukora-node/bin/node'
BOOT = '/usr/local/lib/aukora-boundary/gate-bootstrap'
ENV = {'PATH': '/opt/aukora-node/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
PRELOAD = ('NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME',
           'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT')
MODEL_PROVIDER = 'deepseek'
MODEL_REF = 'DEEPSEEK_API_KEY'
MODEL_HOME = Path('/home/aukora-host/genesis/state/home')
MODEL_STORE = '.credentials.yaml'
MODEL_KEY_MAX_BYTES = 4096
MODEL_STORE_MAX_BYTES = 32 * 1024
EVIDENCE_JSON_LIMITS = {
    'INSTALL_RECORD': 16 * 1024,
    'APPROVER_PIN': 64 * 1024,
    'APPROVAL_CACHE': 128 * 1024,
    'RELEASE_FLOOR': 16 * 1024,
    'PLUGIN_SET': 2 * 1024 * 1024,
}
# A real 15,700-entry artifact record is about 2 MiB; 8 MiB permits growth while keeping the streamed read finite.
EVIDENCE_ARTIFACT_RECORD_MAX_BYTES = 8 * 1024 * 1024
EVIDENCE_DIGEST_CHUNK_BYTES = 64 * 1024


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


def hostname(value):
    labels = value.split('.')
    need(value == value.lower() and value != 'localhost' and len(value) <= 253 and len(labels) >= 2
         and re.search(r'[a-z]', labels[-1]) is not None
         and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) is not None for label in labels),
         'HOST_INVALID')
    return value


def protected(path, directory=False, uid=0, private=False, linked=False):
    info = path.lstat()
    need(info.st_uid == uid and not info.st_mode & (0o077 if private else 0o022)
         and (stat.S_ISDIR(info.st_mode) if directory
              else stat.S_ISREG(info.st_mode) and (linked or info.st_nlink == 1)),
         'CUSTODY_INVALID')


def module(file):
    spec = importlib.util.spec_from_file_location('browser_' + file.stem.replace('-', '_'), file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(command, code, env=None, cwd=None, expected=0):
    result = subprocess.run(command, env=env or ENV, cwd=cwd, capture_output=True)
    if result.returncode != expected and STATE.is_dir():
        # Root-private; the refusal code alone is printed.
        (STATE / 'last-failure.log').write_bytes(result.stdout[-20000:] + b'\n--- stderr\n' + result.stderr[-20000:])
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
    file = STATE / 'installed.json'
    value, _ = evidence_json(file, 'INSTALL_RECORD')
    need(isinstance(value, dict) and set(value) == {'revision', 'inputs'} and isinstance(value['inputs'], dict), 'INSTALL_RECORD_INVALID')
    digest(value['revision'], True)
    return value


def harness_identity():
    try:
        user = pwd.getpwnam('aukora-host')
    except KeyError:
        refuse('MODEL_USER_INVALID')
    need(user.pw_uid != 0 and user.pw_gid != 0 and user.pw_dir == '/home/aukora-host',
         'MODEL_USER_INVALID')
    return user.pw_uid, user.pw_gid


def open_model_home(uid, gid):
    # Credential writes stay under the private harness-owned DSH home.
    paths = [MODEL_HOME, *list(MODEL_HOME.parents)[:3]]
    need(MODEL_HOME.is_absolute(), 'MODEL_STORE_PATH_INVALID')
    for path in paths:
        try:
            info = path.lstat()
        except OSError:
            refuse('MODEL_STORE_CUSTODY_INVALID')
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
             and not info.st_mode & 0o077, 'MODEL_STORE_CUSTODY_INVALID')
    try:
        descriptor = os.open(MODEL_HOME, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        refuse('MODEL_STORE_CUSTODY_INVALID')
    info = os.fstat(descriptor)
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
            and not info.st_mode & 0o077):
        os.close(descriptor)
        refuse('MODEL_STORE_CUSTODY_INVALID')
    return descriptor


def validate_model_key(value):
    need(0 < len(value) <= MODEL_KEY_MAX_BYTES, 'MODEL_KEY_LENGTH_INVALID')
    try:
        text = value.decode('utf-8')
    except UnicodeError:
        refuse('MODEL_KEY_SHAPE_INVALID')
    need(bool(text) and all(character.isprintable() for character in text),
         'MODEL_KEY_SHAPE_INVALID')
    return text


def read_model_key(prompt=False):
    # Non-prompt input must not be a terminal that can echo the credential.
    if prompt:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                value = getpass.getpass('Model key: ').encode('utf-8')
        except (EOFError, KeyboardInterrupt, UnicodeError, getpass.GetPassWarning):
            refuse('MODEL_KEY_INPUT_REFUSED')
    else:
        need(not sys.stdin.isatty(), 'MODEL_KEY_TTY_REFUSED')
        value = sys.stdin.buffer.read(MODEL_KEY_MAX_BYTES + 3)
        if value.endswith(b'\r\n'):
            value = value[:-2]
        elif value.endswith(b'\n'):
            value = value[:-1]
        need(b'\r' not in value and b'\n' not in value, 'MODEL_KEY_MULTILINE_REFUSED')
    validate_model_key(value)
    return value


def render_model_store(value):
    text = validate_model_key(value)
    return ('version: 1\nrefs:\n  ' + MODEL_REF + ': '
            + json.dumps(text, ensure_ascii=True) + '\n').encode('ascii')


def model_store_key(directory, uid, gid):
    try:
        info = os.stat(MODEL_STORE, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        refuse('MODEL_STORE_INVALID')
    need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid
         and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
         and info.st_size <= MODEL_STORE_MAX_BYTES, 'MODEL_STORE_INVALID')
    try:
        descriptor = os.open(MODEL_STORE, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory)
    except OSError:
        refuse('MODEL_STORE_INVALID')
    try:
        current = os.fstat(descriptor)
        need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'MODEL_STORE_INVALID')
        payload = os.read(descriptor, MODEL_STORE_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    prefix = ('version: 1\nrefs:\n  ' + MODEL_REF + ': ').encode('ascii')
    try:
        text = json.loads(payload[len(prefix):-1].decode('ascii'))
        value = text.encode('utf-8')
    except (AttributeError, UnicodeError, ValueError):
        refuse('MODEL_STORE_INVALID')
    need(render_model_store(value) == payload, 'MODEL_STORE_INVALID')
    return value


def write_model_store(directory, uid, gid, payload):
    # Replace one validated store from a private same-directory temporary file.
    temporary = '.' + MODEL_STORE + '.tmp-' + secrets.token_hex(12)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            descriptor = None
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, MODEL_STORE, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError:
        refuse('MODEL_STORE_WRITE_REFUSED')
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError as error:
            if error.errno != errno.ENOENT:
                refuse('MODEL_STORE_WRITE_REFUSED')


def model_key(remove=False, prompt=False):
    root_check()
    installed()
    uid, gid = harness_identity()
    directory = open_model_home(uid, gid)
    try:
        existing = model_store_key(directory, uid, gid)
        if remove:
            if existing is not None:
                try:
                    os.unlink(MODEL_STORE, dir_fd=directory)
                    os.fsync(directory)
                except OSError:
                    refuse('MODEL_STORE_REMOVE_REFUSED')
            print('MODEL_KEY_REMOVED provider=' + MODEL_PROVIDER)
            return
        value = read_model_key(prompt)
        write_model_store(directory, uid, gid, render_model_store(value))
    finally:
        os.close(directory)
    prefix = hashlib.sha256(value).hexdigest()[:12]
    print('MODEL_KEY_SET provider=' + MODEL_PROVIDER + ' sha256=' + prefix)


def model_status():
    root_check()
    installed()
    uid, gid = harness_identity()
    directory = open_model_home(uid, gid)
    try:
        present = model_store_key(directory, uid, gid) is not None
    finally:
        os.close(directory)
    print('MODEL_KEY provider=' + MODEL_PROVIDER + ' present=' + ('yes' if present else 'no'))


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


def profile_rules(checkout=None):
    # During install the reviewed checkout has not yet moved to its installed path.
    file = (checkout or CHECKOUT) / 'scripts/materialize-aukora-release.py'
    protected(file)
    names = {'BROWSER_DISABLED_ROWS', 'BROWSER_REFUSAL_ENTRY', 'BROWSER_REFUSAL_SOURCE'}
    rules = {}
    for node in ast.parse(file.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names:
            rules[node.targets[0].id] = ast.literal_eval(node.value)
    need(set(rules) == names, 'PROFILE_RULES_MISSING')
    return rules


def profile(release, checkout=None):
    rules = profile_rules(checkout)
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
    app_host, owner_host = hostname(options.app_host), hostname(options.owner_host)
    need(app_host != owner_host, 'HOST_CONFLICT')
    here = Path(__file__).resolve().parent
    stage = module(here.parent / 'stage.py' if (here.parent / 'stage.py').is_file() else here / 'stage.py')
    inputs = checked_inputs(options, stage)
    binding = {'checkout': options.checkout_sha256, 'node': options.node_sha256,
               'dependencies': options.dependencies_sha256, 'harness': stage.digest_file(inputs / 'dsh-source.tar.gz'),
               'app_host': app_host, 'owner_host': owner_host}
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
                 '/opt/authority', '/opt/contracts', '/opt/aukora-aumlok',
                 '/etc/aukora-boundary-gate', '/etc/aukora-approvals', '/etc/aukora-genesis',
                 '/etc/aukora', '/etc/systemd/system/aukora-browser-claim.service',
                 '/etc/systemd/system/aukora-boundary-gate.service.d',
                 '/home/aukora-gate', '/home/aukora-host', '/etc/systemd/system/aukora-browser.service',
                 '/etc/systemd/system/aukora-boundary-gate.service'):
        need(not Path(name).exists() and not Path(name).is_symlink(), 'INSTALL_EXISTS')
    for name in ('/var', '/var/lib', '/opt', '/home', '/etc', '/etc/systemd', '/etc/systemd/system',
                 '/usr', '/usr/local', '/usr/local/lib', '/var/lib/aukora-boundary', '/usr/local/lib/aukora-boundary'):
        if Path(name).exists() or Path(name).is_symlink():
            protected(Path(name), True)
    # The stock image listens for SSH on every address; this node uses loopback proxies.
    run(['systemctl', 'mask', '--now', 'ssh.socket', 'ssh.service'], 'SSH_DISABLE_REFUSED')
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
    env.update(HOME=str(build_home), PATH=str(tools) + ':' + ENV['PATH'], npm_config_offline='true', pnpm_config_offline='true', pnpm_config_store_dir=str(deps / 'store'),
               pnpm_config_cache_dir=str(deps / 'cache'),
               npm_config_store_dir=str(deps / 'store'), CI='true', PYTHONDONTWRITEBYTECODE='1')
    fresh.work = STATE
    os.environ['PATH'] = env['PATH']
    fresh.preflight()
    need(run([str(tools / 'pnpm'), '--version'], 'PNPM_INVALID', env).strip() == pin['packageManager'].removeprefix('pnpm@'), 'PNPM_VERSION_MISMATCH')
    # Two capped CPUs build the harness slowly; the limit is an hour, not the fresh-clone default.
    fresh.run(['python3', str(checkout / 'scripts/build-dsh.py')], 'build', checkout, env, timeout=3600)
    fresh.verify_built(checkout / 'vendor/dsh', checkout, env)
    release = Path('/opt/aukora-genesis/release-' + options.revision[:7])
    release.parent.mkdir(mode=0o755)
    env['AUKORA_STATE'] = '/home/aukora-host/genesis/state'
    fresh.run(['python3', str(checkout / 'scripts/materialize-aukora-release.py'), '--browser-node',
               '--public-origin', 'https://' + app_host,
               '--from', str(checkout / 'vendor/dsh'), '--to', str(release)], 'materialize', checkout, env)
    stage.public_modes(release)
    profile(release, checkout)
    gate = STATE / 'gate-package'
    owner = STATE / 'owner-key'
    shutil.copytree(checkout / 'packages/boundary-gate', gate)
    shutil.copytree(checkout / 'packages/owner-key', owner)
    profiles = [('authority', checkout / 'packages/authority', '/opt/authority', '--passkey-authority'),
                ('contracts', checkout / 'packages/contracts', '/opt/contracts', '--passkey-contracts'),
                ('browser-aumlok', checkout / 'plugins/aukora-aumlok', '/opt/aukora-aumlok', '--browser-aumlok')]
    for name, source, destination, flag in profiles:
        shutil.copytree(source, STATE / name)
    run(['groupadd', '--system', 'skgate'], 'GROUP_CREATE_REFUSED')
    for name, group in [('aukora-gate', 'skgate'), ('aukora-host', 'aukora-host')]:
        arguments = ['useradd', '--system', '--home-dir', '/home/' + name, '--shell', '/usr/sbin/nologin']
        arguments += ['--gid', group] if name == 'aukora-gate' else ['--user-group', '--groups', 'skgate']
        run(arguments + [name], 'USER_CREATE_REFUSED')
        run(['install', '-d', '-m', '0700', '-o', name, '-g', group, '/home/' + name], 'HOME_CREATE_REFUSED')
    for tree, output in [(gate, '/opt/aukora-boundary-gate'), (owner, '/opt/owner-key')]:
        stage.public_modes(tree)
        tree.rename(output)
    for name, source, destination, flag in profiles:
        stage.public_modes(STATE / name)
        (STATE / name).rename(destination)
    run(['runuser', '-u', 'aukora-gate', '--', NODE, '--input-type=module', '-e',
         (checkout / 'ops/node-spawn/browser/keys.mjs').read_text()], 'KEY_GENERATION_REFUSED')
    epochs = STATE / 'signer-epochs.json'
    shutil.copyfile('/home/aukora-gate/signer-epochs.json', epochs)
    # Manifest generator requires staged inputs outside all installed paths.
    shutil.copytree('/opt/aukora-boundary-gate', gate)
    shutil.copytree('/opt/owner-key', owner)
    profile_args = []
    for name, source, destination, flag in profiles:
        shutil.copytree(destination, STATE / name)
        profile_args += [flag, str(STATE / name)]
    run(['python3', '-I', '-S', str(gate / 'host/install/generate-manifest.py'), '--package', str(gate),
         '--owner-key', str(owner), '--launcher-checkout', str(checkout), '--signer-epochs', str(epochs),
         *profile_args, '--output', str(STATE / 'manifest.json')], 'MANIFEST_REFUSED')
    stage.public_modes(checkout)
    checkout.rename(CHECKOUT)
    # The harness user reads the root-owned checkout's recorded pin through git; git refuses a
    # repository owned by another user unless the system names it.
    run(['git', 'config', '--system', '--add', 'safe.directory', str(CHECKOUT)], 'GIT_SAFE_DIRECTORY_REFUSED')
    if Path('/etc/gitconfig').is_file():
        Path('/etc/gitconfig').chmod(0o644)
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
    config.write(Path('/etc/aukora/public-origin'), ('https://' + app_host + '\n').encode(), Path('/'))
    config.write(Path('/etc/aukora/owner-public-origin'), ('https://' + owner_host + '\n').encode(), Path('/'))
    units(config)
    bootstrap('check-package')
    bootstrap('check-runtime')
    run(['systemctl', 'daemon-reload'], 'SYSTEMD_REFUSED')
    run(['systemctl', 'enable', '--now', 'aukora-boundary-gate.service'], 'GATE_START_REFUSED')
    run(['systemctl', 'enable', '--now', 'aukora-browser-claim.service'], 'CLAIM_START_REFUSED')
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
ExecStart=/usr/bin/python3 scripts/launch-dsh.py --release ${AUKORA_RELEASE_DIR} --state-root /home/aukora-host/genesis/state --port 18735 --foreground --public-origin-file /etc/aukora/public-origin --node /opt/aukora-node/bin/node --approval-state-root ${AUKORA_APPROVAL_ROOT} --approved-record-sha ${AUKORA_RECORD_SHA} --patch ${AUKORA_RELEASE_DIR}/aukora-composition.patch.yml
KillMode=control-group
Restart=no
[Install]
WantedBy=multi-user.target
'''
    config.write(Path('/etc/systemd/system/aukora-browser.service'), data.encode(), Path('/'))
    claim_unit = '''[Unit]
Description=AUKORA one-use browser claim broker
After=aukora-boundary-gate.service
[Service]
User=root
Group=root
Type=exec
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/aukora-browser
PrivateTmp=yes
WorkingDirectory=/opt/aukora-genesis/src
UnsetEnvironment=NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
ExecStart=/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/ingress/claim.py serve --public-origin-file /etc/aukora/public-origin --owner-origin-file /etc/aukora/owner-public-origin --state-file /var/lib/aukora-browser/claims.json --launch-url-file /home/aukora-host/genesis/state/launch-url.json --harness-port 18735 --owner-page-port 17792 --listen-port 18736
Restart=on-failure
[Install]
WantedBy=multi-user.target
'''
    config.write(Path('/etc/systemd/system/aukora-browser-claim.service'), claim_unit.encode(), Path('/'))


def claim():
    root_check()
    installed()
    for name in ('aukora-browser.service', 'aukora-browser-claim.service'):
        run(['systemctl', 'is-active', '--quiet', name], 'CLAIM_SERVICE_INACTIVE')
    link = run(['/usr/bin/python3', '-I', '-S', '-B', str(CHECKOUT / 'ops/node-spawn/ingress/claim.py'),
                'mint', '--public-origin-file', '/etc/aukora/public-origin',
                '--state-file', str(STATE / 'claims.json')], 'CLAIM_MINT_REFUSED')
    print(link, end='')


def rotate_owner_link():
    root_check()
    installed()
    bootstrap('check-package')
    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_ROTATE_REFUSED')
    sockets()
    print('BROWSER_OWNER_LINK_ROTATED; retrieve bearer through the private operator route')


def passkey_claim():
    root_check()
    value = installed()
    release, approval = release_paths(value)
    bootstrap('check-package')
    bootstrap('floor', 'check', '--release-dir', release, '--approval-state-root', approval)
    ingress = module(CHECKOUT / 'ops/node-spawn/ingress/claim.py')
    app_public = ingress.read_origin_file(Path('/etc/aukora/public-origin'))[0]
    owner_public = ingress.read_origin_file(Path('/etc/aukora/owner-public-origin'))[0]
    link = run([NODE, '/opt/aukora-boundary-gate/bin/browser-passkey-claim.mjs',
                '--owner-origin', owner_public, '--app-origin', app_public,
                '--release', str(release)], 'PASSKEY_CLAIM_REFUSED')
    if re.fullmatch(re.escape(owner_public + '/owner/enroll#claim=') + r'[A-Za-z0-9_-]{43}\n', link) is None:
        refuse('PASSKEY_LINK_INVALID')
    group = run(['getent', 'group', 'skgate'], 'GROUP_MISSING').strip().split(':')[2]
    if not group.isdigit():
        refuse('GROUP_INVALID')
    setup = Path('/etc/aukora-boundary-gate/passkey-setup.json')
    protected(setup)
    os.chown(setup, 0, int(group), follow_symlinks=False)
    setup.chmod(0o640)
    script = "import { passkeySetupReader } from '/opt/aukora-boundary-gate/src/owner-state.mjs'; const read = passkeySetupReader('/etc/aukora-boundary-gate/passkey-setup.json'); read();"
    run(['runuser', '-u', 'aukora-gate', '--', NODE, '--input-type=module', '-e', script],
        'PASSKEY_CONFIG_REFUSED')
    config = module(CHECKOUT / 'ops/node-spawn/configure-host.py')
    passkey_service = '''[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap serve --home /home/aukora-gate --run /run/aukora-gate --target-root /var/lib/aukora-boundary/targets --port 17792 --gid GROUP --time-zone Asia/Makassar --journal-id aukora-gate-pilot --passkey-setup /etc/aukora-boundary-gate/passkey-setup.json
'''.replace('GROUP', group)
    config.write(Path('/etc/systemd/system/aukora-boundary-gate.service.d') / 'browser-owner.conf', passkey_service.encode(), Path('/'))
    run(['systemctl', 'daemon-reload'], 'SYSTEMD_REFUSED')
    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'PASSKEY_START_REFUSED')
    sockets()
    run(['systemctl', 'is-active', '--quiet', 'aukora-boundary-gate.service'], 'PASSKEY_GATE_INACTIVE')
    sys.stdout.write(link)


def enable_owner_signin():
    root_check()
    installed()
    bootstrap('check-package')
    ingress = module(CHECKOUT / 'ops/node-spawn/ingress/claim.py')
    app_origin, _ = ingress.read_origin_file(Path('/etc/aukora/public-origin'))
    owner_origin, _ = ingress.read_origin_file(Path('/etc/aukora/owner-public-origin'))
    script = '''import { passkeySetupReader } from '/opt/aukora-boundary-gate/src/owner-state.mjs';
import { browserJoinReader } from '/opt/aukora-boundary-gate/src/browser-join.mjs';
import { createHash, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
const setup = passkeySetupReader('/etc/aukora-boundary-gate/passkey-setup.json')();
const join = browserJoinReader('/etc/aukora-boundary-gate/browser-join.json')();
if (setup.origin !== process.argv[1] || join.app_origin !== process.argv[2]) throw new Error('BROWSER_OWNER_SIGNIN_ORIGIN_MISMATCH');
const signer = createPublicKey(fs.readFileSync('/home/aukora-gate/receipt-ed25519.pem'));
if (setup.gate !== createHash('sha256').update(signer.export({ type: 'spki', format: 'der' })).digest('hex')) throw new Error('BROWSER_OWNER_SIGNIN_GATE_MISMATCH');
'''
    run(['runuser', '-u', 'aukora-gate', '--', NODE, '--input-type=module', '-e', script,
         owner_origin, app_origin], 'OWNER_SIGNIN_CONFIG_REFUSED')
    group = run(['getent', 'group', 'skgate'], 'GROUP_MISSING').strip().split(':')[2]
    need(group.isdigit(), 'GROUP_INVALID')
    config = module(CHECKOUT / 'ops/node-spawn/configure-host.py')
    dropin = '''[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap serve --home /home/aukora-gate --run /run/aukora-gate --target-root /var/lib/aukora-boundary/targets --port 17792 --gid GROUP --time-zone Asia/Makassar --journal-id aukora-gate-pilot --passkey-setup /etc/aukora-boundary-gate/passkey-setup.json --browser-join /etc/aukora-boundary-gate/browser-join.json
'''.replace('GROUP', group)
    config.write(Path('/etc/systemd/system/aukora-boundary-gate.service.d/browser-owner.conf'), dropin.encode(), Path('/'))
    run(['systemctl', 'daemon-reload'], 'SYSTEMD_REFUSED')
    run(['systemctl', 'restart', 'aukora-boundary-gate.service'], 'OWNER_SIGNIN_START_REFUSED')
    sockets()
    print('BROWSER_OWNER_SIGNIN_ENABLED; owner enrollment and final binding required')


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
        local = all(ipaddress.ip_address(item.rsplit(':', 1)[0].strip('[]').split('%', 1)[0]).is_loopback for item in endpoints)
    except ValueError:
        local = False
    need(len(endpoints) == len(rows) and local, 'NON_LOOPBACK_LISTENER')
    need('127.0.0.1:17792' in endpoints, 'OWNER_LISTENER_MISSING')
    return endpoints


def accept(phase, checks=None):
    def checkpoint(name):
        if checks is not None:
            if checks:
                checks[-1]['status'] = 'PASS'
            checks.append({'name': name, 'status': 'FAIL'})

    checkpoint('root_platform')
    root_check()
    checkpoint('installation_record')
    value = installed()
    release, approval = release_paths(value)
    checkpoint('browser_profile')
    profile(release)
    checkpoint('users_modes')
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
    checkpoint('package_custody')
    for path in (Path('/opt/aukora-boundary-gate'), Path('/opt/owner-key'), Path('/opt/authority'),
                 Path('/opt/contracts'), Path('/opt/aukora-aumlok'), Path('/opt/aukora-node'), CHECKOUT, release):
        for folder, dirs, files in os.walk(path, followlinks=False):
            for entry in [Path(folder)] + [Path(folder) / name for name in dirs + files]:
                if entry.is_symlink():
                    need(entry.resolve().is_relative_to(path), 'PACKAGE_LINK')
                else:
                    # pnpm hard-links the built harness's dependencies from its root-private store;
                    # owner and mode are still required there, a single link is not.
                    protected(entry, entry.is_dir(), linked=entry.is_relative_to(CHECKOUT / 'vendor/dsh'))
    checkpoint('node_version')
    need(run([NODE, '--version'], 'NODE_INVALID').strip() == 'v24.11.1', 'NODE_VERSION_MISMATCH')
    checkpoint('package_pins')
    bootstrap('check-package')
    bootstrap('check-runtime')
    checkpoint('gate_sockets')
    sockets()
    checkpoint('signer_pin')
    run(['runuser', '-u', 'aukora-gate', '--', NODE, str(CHECKOUT / 'ops/node-spawn/configure.mjs'),
         'signer', '/home/aukora-gate/receipt-ed25519.pem', '/etc/aukora-boundary-gate/signer-epochs.json'], 'SIGNER_REFUSED')
    epochs = json.loads(Path('/etc/aukora-boundary-gate/signer-epochs.json').read_text())
    print('GATE_SIGNER_SHA256 ' + epochs['epochs'][-1]['gate_pubkey_sha256'])
    checkpoint('loopback_listeners')
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
        checkpoint('approved_floor')
        bootstrap('floor', 'check', '--release-dir', release, '--approval-state-root', approval)
        checkpoint('harness_service')
        run(['systemctl', 'is-active', '--quiet', 'aukora-browser.service'], 'HARNESS_INACTIVE')
        need('127.0.0.1:18735' in endpoints, 'HARNESS_LISTENER_MISSING')
        checkpoint('signed_in_ui')
        print(run(['runuser', '-u', 'aukora-host', '--', NODE, str(CHECKOUT / 'ops/pilot/ui-probe.mjs')], 'UI_PROBE_REFUSED').strip())
        checkpoint('plugin_load')
        invocation = run(['systemctl', 'show', '-p', 'InvocationID', '--value', 'aukora-browser.service'], 'JOURNAL_UNAVAILABLE').strip()
        need(bool(re.fullmatch(r'[0-9a-f]{32}', invocation)), 'JOURNAL_UNAVAILABLE')
        journal = run(['journalctl', '--no-pager', '-o', 'cat', '_SYSTEMD_INVOCATION_ID=' + invocation], 'JOURNAL_UNAVAILABLE')
        need(not re.search(r'^aukora-[a-z-]+ \(file://.*\): Error', journal, re.M), 'PLUGIN_LOAD_FAILED')
        checkpoint('claim_service')
        run(['systemctl', 'is-active', '--quiet', 'aukora-browser-claim.service'], 'CLAIM_INACTIVE')
        need('127.0.0.1:18736' in endpoints, 'CLAIM_LISTENER_MISSING')
        checkpoint('public_origins')
        claim = module(CHECKOUT / 'ops/node-spawn/ingress/claim.py')
        try:
            public_origin, authority = claim.read_origin_file(Path('/etc/aukora/public-origin'))
            _, owner_authority = claim.read_origin_file(Path('/etc/aukora/owner-public-origin'))
        except (OSError, claim.ClaimRefusal):
            refuse('PUBLIC_ORIGIN_INVALID')
        need(authority != owner_authority, 'PUBLIC_HOSTS_MUST_DIFFER')
        import http.client

        def request(port, method, target, body=None, cookie=None):
            headers = {'Host': authority, 'Origin': public_origin, 'Sec-Fetch-Site': 'same-origin'}
            if body is not None:
                headers['Content-Type'] = 'text/plain'
            if cookie is not None:
                headers['Cookie'] = cookie
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                connection.request(method, target, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read(1024 * 1024 + 1)
                response_headers = response.getheaders()
                need(len(payload) <= 1024 * 1024, 'ACCEPTANCE_RESPONSE_LIMIT')
                return response.status, response_headers, payload
            except OSError:
                refuse('ACCEPTANCE_HTTP_UNAVAILABLE')
            finally:
                connection.close()

        checkpoint('anonymous_session')
        status, _, _ = request(18735, 'GET', '/')
        need(status == 401, 'ANONYMOUS_HARNESS_ACCEPTED')
        checkpoint('claim_exchange')
        link = run(['/usr/bin/python3', '-I', '-S', str(CHECKOUT / 'ops/node-spawn/ingress/claim.py'),
                    'mint', '--public-origin-file', '/etc/aukora/public-origin',
                    '--state-file', '/var/lib/aukora-browser/claims.json'], 'CLAIM_MINT_REFUSED')
        match = re.fullmatch(re.escape(public_origin + claim.CLAIM_PATH) + r'#([A-Za-z0-9_-]{43})\n', link)
        need(match is not None, 'CLAIM_LINK_INVALID')
        code = match[1].encode('ascii')
        status, headers, payload = request(18736, 'POST', claim.CLAIM_PATH, code)
        need(status == 204 and not payload, 'CLAIM_EXCHANGE_REFUSED')
        checkpoint('claim_cookie')
        cookies = [value for name, value in headers if name.lower() == 'set-cookie']
        need(len(cookies) == 1, 'CLAIM_COOKIE_INVALID')
        try:
            cookie = claim.bounded_cookie(cookies[0], authority, time.time()).split(';', 1)[0]
        except claim.ClaimRefusal:
            refuse('CLAIM_COOKIE_INVALID')
        checkpoint('public_session')
        status, _, payload = request(18735, 'GET', '/', cookie=cookie)
        need(status == 200 and bool(payload), 'PUBLIC_SESSION_REFUSED')
        checkpoint('claim_replay')
        status, headers, payload = request(18736, 'POST', claim.CLAIM_PATH, code)
        need(status == 403 and payload == b'CLAIM_SPENT\n'
             and not any(name.lower() == 'set-cookie' for name, _ in headers), 'CLAIM_REPLAY_ACCEPTED')
        print('PASS | protected public origins, anonymous 401 and one-use public-authority claim cookie')
        print('PASS | approved signed-in UI and plugin load')
        if phase == 'passkey':
            print(run([NODE, str(CHECKOUT / 'ops/node-spawn/browser/passkey-acceptance.mjs')],
                      'PASSKEY_ACCEPTANCE_REFUSED').strip())
    print('PASS | users modes package pins and loopback listeners')
    if checks:
        checks[-1]['status'] = 'PASS'


def evidence_custody(file):
    for parent in file.parents:
        protected(parent, True)
    protected(file)


def evidence_json(file, label):
    evidence_custody(file)
    limit = EVIDENCE_JSON_LIMITS[label]
    with file.open('rb') as source:
        raw = source.read(limit + 1)
    need(len(raw) <= limit, 'EVIDENCE_' + label + '_LIMIT')
    return json.loads(raw), raw


def evidence_digest(file):
    evidence_custody(file)
    total = 0
    digest = hashlib.sha256()
    with file.open('rb') as source:
        while True:
            block = source.read(EVIDENCE_DIGEST_CHUNK_BYTES)
            if not block:
                break
            total += len(block)
            need(total <= EVIDENCE_ARTIFACT_RECORD_MAX_BYTES, 'EVIDENCE_ARTIFACT_RECORD_LIMIT')
            digest.update(block)
    return digest.hexdigest()


def evidence_record(checks):
    # Export only public approval proofs, digests and named check outcomes.
    value = installed()
    release, approval = release_paths(value)
    pin, _ = evidence_json(approval / 'gate-state/plugin-set-approver.json', 'APPROVER_PIN')
    # This cache holds one signed apply row; the growing gate ledger is not read or exported.
    receipt, _ = evidence_json(approval / 'gate-state/plugin-set-approval.json', 'APPROVAL_CACHE')
    floor, _ = evidence_json(Path('/etc/aukora-approvals/release-floor.json'), 'RELEASE_FLOOR')
    plugins, _ = evidence_json(release / '.dsh-build/plugin-set.json', 'PLUGIN_SET')
    # A real plugin-set record names no revision (kind, counts, set digest and artifacts only); the signed
    # floor does, in full, and is what a start checks, so the installed revision is bound to that.
    need(floor.get('release') == value['revision'], 'EVIDENCE_REVISION_MISMATCH')
    artifact_sha256 = evidence_digest(release / '.dsh-build/genesis-artifacts.json')
    public_key = pin['gatePubkeyPem']
    need(gate_signer() == public_key, 'EVIDENCE_SIGNER_MISMATCH')
    # The verifier derives the full fingerprint from this public key and binds it to the floor.
    record = {'kind': 'aukora-browser-node-evidence/v1', 'phase': 'after',
              'observed_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
              'release': {'revision': value['revision'], 'record_sha256': artifact_sha256,
                          'plugin_set_sha256': plugins['setDigest']},
              'signer': {'public_key_pem': public_key, 'sha256': floor['signer_key_sha256']},
              'approval': receipt, 'floor': floor,
              'installer_inputs': {name: value['inputs'][name] for name in ('checkout', 'node', 'dependencies', 'harness')},
              'checks': checks, 'record_signature': None}
    raw = json.dumps(record, separators=(',', ':'), ensure_ascii=False).encode()
    verifier = CHECKOUT / 'scripts/audit/browser-node-evidence.mjs'
    for file in (Path(NODE), verifier):
        for parent in file.parents:
            protected(parent, True)
        protected(file)
    result = subprocess.run([NODE, str(verifier), '--stdin-container'],
                            env=ENV, input=raw, capture_output=True)
    need(result.returncode in (0, 2), 'EVIDENCE_PUBLIC_SCHEMA_REFUSED')
    return raw.decode()


def gate_signer():
    # Read only the gate's public signer through its existing ping operation.
    raw = b''
    deadline = time.monotonic() + 5
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect('/run/aukora-gate/gate.sock')
        connection.sendall(b'{"op":"ping","args":{}}\n')
        while b'\n' not in raw:
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'EVIDENCE_GATE_PING_DEADLINE')
            connection.settimeout(remaining)
            block = connection.recv(4097 - len(raw))
            need(bool(block) and len(raw) + len(block) <= 4096, 'EVIDENCE_GATE_PING_LIMIT')
            raw += block
    value = json.loads(raw)
    need(isinstance(value, dict) and set(value) == {'ok', 'result'} and value['ok'] is True
         and isinstance(value['result'], dict) and set(value['result']) == {'ok', 'pubkey_fp', 'pubkey_pem'}
         and value['result']['ok'] is True and isinstance(value['result']['pubkey_pem'], str), 'EVIDENCE_GATE_PING_INVALID')
    return value['result']['pubkey_pem']


def accept_evidence(phase):
    need(phase == 'after', 'EVIDENCE_PHASE_INVALID')
    root_check()
    checks = []
    failed = False
    # Command output, journals, links, cookies and failure messages never enter public evidence.
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            accept(phase, checks)
        except Exception:
            failed = True
    print(evidence_record(checks))
    if failed:
        refuse('ACCEPTANCE_FAILED')


class Parser(argparse.ArgumentParser):
    def error(self, message):
        refuse('USAGE')


def main(args):
    parser = Parser(add_help=False)
    parser.add_argument('action', choices=['install', 'start', 'status', 'remove', 'accept', 'verify-profile', 'claim', 'rotate-owner-link', 'passkey-claim', 'enable-owner-signin', 'model-key'])
    parser.add_argument('--inputs')
    parser.add_argument('--app-host')
    parser.add_argument('--owner-host')
    for key in ('checkout-sha256', 'revision', 'node-sha256', 'dependencies-sha256'):
        parser.add_argument('--' + key)
    parser.add_argument('--phase', choices=['before', 'after', 'passkey'])
    parser.add_argument('--evidence', action='store_true')
    parser.add_argument('--release')
    parser.add_argument('--prompt', action='store_true')
    parser.add_argument('--remove', dest='remove_model_key', action='store_true')
    need(len([a for a in args if a.startswith('--')]) == len(set(a for a in args if a.startswith('--'))), 'USAGE')
    options = parser.parse_args(args)
    fields = ('inputs', 'checkout_sha256', 'revision', 'node_sha256', 'dependencies_sha256', 'app_host', 'owner_host')
    need(all(getattr(options, key) is not None for key in fields) if options.action == 'install'
         else all(getattr(options, key) is None for key in fields), 'USAGE')
    need((options.phase is not None) == (options.action == 'accept'), 'USAGE')
    need((options.release is not None) == (options.action == 'verify-profile'), 'USAGE')
    need(not options.prompt or options.action == 'model-key', 'USAGE')
    need(not options.remove_model_key or options.action == 'model-key', 'USAGE')
    need(not (options.prompt and options.remove_model_key), 'USAGE')
    need(not options.evidence or options.action == 'accept' and options.phase == 'after', 'USAGE')
    if options.action == 'install':
        absolute(options.inputs)
        for key in fields[1:5]:
            digest(getattr(options, key), key == 'revision')
        install(options)
    elif options.action == 'start':
        start()
    elif options.action == 'claim':
        claim()
    elif options.action == 'rotate-owner-link':
        rotate_owner_link()
    elif options.action == 'passkey-claim':
        passkey_claim()
    elif options.action == 'enable-owner-signin':
        enable_owner_signin()
    elif options.action == 'model-key':
        model_key(options.remove_model_key, options.prompt)
    elif options.action == 'accept':
        if options.evidence:
            accept_evidence(options.phase)
        else:
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
        run(['systemctl', 'disable', '--now', 'aukora-browser.service', 'aukora-browser-claim.service', 'aukora-boundary-gate.service'], 'REMOVE_REFUSED')
        print('BROWSER_DEACTIVATED; protected state and floor retained')
    else:
        model_status()


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r'BROWSER_[A-Z_]+', code) and STATE.is_dir():
            # An unnamed failure keeps its trace root-private; only the refusal line is printed.
            import traceback
            (STATE / 'last-failure.log').write_text(traceback.format_exc())
        print('REFUSED ' + (code if re.fullmatch(r'BROWSER_[A-Z_]+', code) else 'BROWSER_OPERATION_REFUSED'), file=sys.stderr)
        sys.exit(1)
