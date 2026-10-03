#!/usr/bin/env python3
"""Start the approved aukora-host backend under systemd; never provision the host."""
import argparse
import hashlib
import json
import os
import pwd
import stat
import subprocess
import re
import sys
from pathlib import Path


def private_json(path, owner):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_mode & 0o027 or info.st_nlink != 1 or info.st_size > 65536):
            raise ValueError('PRIVATE_FILE_INVALID')
        with os.fdopen(fd, 'r', closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or any(c in value for c in '\n\r\x00'):
        raise ValueError('ABSOLUTE_PATH_REQUIRED')
    path = Path(value)
    if '..' in path.parts or str(path) != value or path.resolve() != path:
        raise ValueError('CANONICAL_PATH_REQUIRED')
    return path


def protected(path):
    for part in (path, *path.parents):
        info = part.lstat()
        if part.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('ROOT_PROTECTED_PATH_REQUIRED')


def protected_tree(root):
    pending, seen = [root], set()
    while pending:
        path = pending.pop()
        info = path.lstat()
        if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022):
            raise ValueError('ROOT_PROTECTED_TREE_REQUIRED')
        if path.is_symlink():
            target = path.resolve(strict=True)
            if target != root and root not in target.parents:
                raise ValueError('TREE_LINK_ESCAPES')
            if target not in seen:
                seen.add(target)
                pending.append(target)
        elif path.is_dir():
            pending.extend(path.iterdir())
        elif not path.is_file():
            raise ValueError('SPECIAL_FILE_REFUSED')


def configuration(path):
    protected(path)
    value = private_json(path, 0)
    fields = {'version', 'service', 'source_root', 'source_commit', 'runtime_root', 'node_path', 'node_sha256',
              'support_root', 'state_root', 'releases_root', 'control_root', 'active_file', 'port', 'startup_timeout_seconds'}
    if not isinstance(value, dict) or set(value) != fields or value['version'] != 1:
        raise ValueError('HOST_CONFIG_INVALID')
    if value['service'] != 'aukora-host.service':
        raise ValueError('SERVICE_INVALID')
    if not re.fullmatch('[a-f0-9]{40}', value['source_commit']) or not re.fullmatch('[a-f0-9]{64}', value['node_sha256']):
        raise ValueError('HOST_CONFIG_PIN_INVALID')
    for key in fields - {'version', 'service', 'port', 'startup_timeout_seconds', 'source_commit', 'node_sha256'}:
        value[key] = absolute(value[key])
    if value['state_root'] != value['support_root'] / 'state':
        raise ValueError('STATE_ROOT_INVALID')
    if value['active_file'] != value['control_root'] / 'deployment.json':
        raise ValueError('ACTIVE_FILE_INVALID')
    for key in ('source_root', 'runtime_root', 'node_path', 'releases_root', 'control_root'):
        protected(value[key])
    if value['runtime_root'] not in value['node_path'].parents or not value['node_path'].is_file() or not os.access(value['node_path'], os.X_OK):
        raise ValueError('NODE_OUTSIDE_RUNTIME')
    if hashlib.sha256(value['node_path'].read_bytes()).hexdigest() != value['node_sha256']:
        raise ValueError('NODE_PIN_CHANGED')
    if value['control_root'] == value['support_root'] or value['support_root'] in value['control_root'].parents:
        raise ValueError('CONTROL_ROOT_INSIDE_HOST_STATE')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535:
        raise ValueError('PORT_INVALID')
    if type(value['startup_timeout_seconds']) is not int or not 1 <= value['startup_timeout_seconds'] <= 180:
        raise ValueError('STARTUP_WINDOW_INVALID')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise ValueError('LINUX_REQUIRED')
    user = pwd.getpwnam('aukora-host')
    if os.getuid() != user.pw_uid or os.geteuid() != user.pw_uid:
        raise ValueError('AUKORA_HOST_UID_REQUIRED')
    config = configuration(absolute(args.config))
    protected(config['active_file'])
    active = private_json(config['active_file'], 0)
    if (not isinstance(active, dict) or set(active) != {'version', 'commit', 'release', 'approval_state', 'approved_record_sha',
                                        'plugin_set_sha256', 'approval_sha256', 'pin_sha256'}
            or active['version'] != 2):
        raise ValueError('ACTIVE_DEPLOYMENT_INVALID')
    if not re.fullmatch('[a-f0-9]{40}', active['commit']) or not re.fullmatch('[a-f0-9]{64}', active['approved_record_sha']):
        raise ValueError('ACTIVE_DEPLOYMENT_PIN_INVALID')
    release = absolute(active['release'])
    if config['releases_root'] not in release.parents:
        raise ValueError('RELEASE_OUTSIDE_ROOT')
    state = config['state_root']
    if state == release or release in state.parents:
        raise ValueError('STATE_INSIDE_RELEASE')
    record = release / '.dsh-build/genesis-artifacts.json'
    if hashlib.sha256(record.read_bytes()).hexdigest() != active['approved_record_sha']:
        raise ValueError('APPROVED_RECORD_CHANGED')
    approval_state = absolute(active['approval_state'])
    if approval_state != config['control_root'] / 'approvals' / active['commit'] / 'state':
        raise ValueError('APPROVAL_CACHE_FENCE_INVALID')
    protected(approval_state)
    protected_tree(config['source_root'])
    env = {'HOME': user.pw_dir, 'USER': user.pw_name, 'LOGNAME': user.pw_name, 'LANG': 'C',
           'PATH': str(config['node_path'].parent) + ':/usr/bin:/bin'}
    verified = subprocess.run([str(config['node_path']), str(config['source_root'] / 'scripts/aukora/become-linux.mjs'),
                               '--config', args.config, '--verify-start'], env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    if verified.returncode != 0:
        raise ValueError('START_APPROVAL_REFUSED')
    if private_json(config['active_file'], 0) != active:
        raise ValueError('ACTIVE_DEPLOYMENT_CHANGED')
    if args.check:
        print(json.dumps({'status': 'START_PROOF_VERIFIED', 'commit': active['commit'], 'port': config['port']}))
        return
    # The launcher keeps its exact environment whitelist; no secret or unrestricted environment forwarding.
    env['PATH'] = str(config['node_path'].parent) + ':/usr/bin:/bin'
    env['AUKORA_SUPPORT_ROOT'] = str(config['support_root'])
    env['AUKORA_LAUNCH_STARTUP_TIMEOUT'] = str(config['startup_timeout_seconds'])
    script = config['source_root'] / 'scripts/launch-dsh.py'
    os.execve(sys.executable, [sys.executable, str(script), '--foreground', '--release', str(release),
              '--state-root', str(state), '--port', str(config['port']),
              '--approved-record-sha', active['approved_record_sha'], '--node', str(config['node_path']),
              '--approval-state-root', str(approval_state)], env)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Never echo descriptor, credentials, environment, arbitrary JSON or filesystem contents.
        code = str(error) if re.fullmatch('[A-Z_]+', str(error)) else 'REQUIRED_HOST_SETUP_REFUSED'
        print('aukora-host: ' + code + '; no backend started', file=sys.stderr)
        raise SystemExit(2)
