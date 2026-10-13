#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Preserve protected configuration and bind successful reruns to identical inputs.
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def refuse(code):
    raise ValueError(code)


def checked(path, directory=False):
    info = path.lstat()
    if (info.st_uid != os.geteuid() or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        refuse('SPAWN_CONFIG_CUSTODY')


def parents(path, root):
    if not path.is_relative_to(root):
        refuse('SPAWN_ROOT_INVALID')
    checked(root, True)
    current = root
    for component in path.relative_to(root).parts[:-1]:
        current = current / component
        if not current.exists():
            current.mkdir(mode=0o755)
        checked(current, True)


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16777216 or info.st_nlink != 1:
            refuse('SPAWN_CONFIG_INPUT')
        data = os.read(fd, 16777217)
        if len(data) != info.st_size:
            refuse('SPAWN_CONFIG_INPUT')
        return data
    finally:
        os.close(fd)


def write(path, data, root, mode=0o644):
    parents(path, root)
    if path.exists() or path.is_symlink():
        checked(path)
        if read(path) != data:
            refuse('SPAWN_CONFIG_CONFLICT')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def binding(config_path, config, root, phase):
    digest = hashlib.sha256(read(config_path))
    for name in ('offer', 'auma_offer', 'door_config', 'public_signer_epochs'):
        digest.update(read(Path(config[name])))
    files = []
    for home, key in [('aukora-member/.config/aukora-node', 'node-key'), ('aukora-host/.config/aukora-buzz', 'auma.key')]:
        if phase >= 2:
            files.extend([root / 'home' / home / key, root / 'home' / home / 'spawn-config.json', root / 'home' / home / 'offer.json'])
        if phase >= 3:
            files.append(root / 'home' / home / 'admission.json')
    if phase >= 4:
        files.append(root / 'home/aukora-host/.config/aukora-buzz/door.json')
    if phase >= 7:
        files.append(root / 'etc/aukora-genesis/release.env')
    for path in files:
        digest.update(hashlib.sha256(read(path)).digest())
    return (digest.hexdigest() + '\n').encode()


def main():
    action, config_path, prefix = sys.argv[1:]
    config_path, root = Path(config_path), Path(prefix)
    if not root.is_absolute() or str(root) != os.path.realpath(root):
        refuse('SPAWN_ROOT_INVALID')
    checked(config_path)
    config = json.loads(read(config_path))
    destination = lambda path: root / path.lstrip('/')
    state = destination('/var/lib/aukora-spawn')
    if action == 'phase':
        phase = 0
        for number in range(1, 9):
            marker = state / ('phase-' + str(number))
            if not marker.exists() and not marker.is_symlink():
                break
            parents(marker, root)
            checked(marker)
            if read(marker) != binding(config_path, config, root, number):
                refuse('SPAWN_RESUME_CONFLICT')
            phase = number
        print(phase)
        return 0
    if action.startswith('mark-') and action[5:] in [str(n) for n in range(1, 9)]:
        phase = int(action[5:])
        write(state / ('phase-' + str(phase)), binding(config_path, config, root, phase), root, 0o600)
    elif action == 'units':
        source = destination('/opt/aukora-genesis/src/packages/boundary-gate/host/systemd')
        group_rows = read(destination('/etc/group')).decode().splitlines()
        groups = [row.split(':')[2] for row in group_rows if row.startswith('skgate:')]
        if len(groups) != 1 or not groups[0].isdigit():
            refuse('SPAWN_GATE_GROUP_REQUIRED')
        for unit in ('aukora-boundary-gate.service', 'aukora-genesis.service', 'aukora-selfcheck.service',
                     'aukora-selfcheck-periodic.service', 'aukora-selfcheck.timer'):
            data = read(source / unit).replace(b'SKGATE_GID', groups[0].encode())
            write(destination('/etc/systemd/system/' + unit), data, root)
    elif action == 'prerequisites':
        required = ['/usr/bin/openshell', '/usr/bin/openshell-gateway',
                    '/etc/aukora-boundary-gate/owner-state.json',
                    '/etc/aukora-boundary-gate/openshell-workspace.json',
                    '/etc/aukora-boundary-gate/openshell-inventory.json',
                    '/etc/sudoers.d/aukora-boundary',
                    '/etc/systemd/system/aukora-auma-local-deny.service',
                    '/etc/systemd/system/aukora-auma-podman.service',
                    '/etc/systemd/system/aukora-openshell-gateway.service',
                    '/etc/systemd/system/aukora-auma-sandbox.service']
        if any(not destination(name).exists() for name in required):
            refuse('SPAWN_HOST_PREREQUISITES_REQUIRED')
        for name in required:
            parents(destination(name), root)
            checked(destination(name))
        for name in ('receipt-ed25519.pem', 'owner-secret.json'):
            try:
                read(destination('/home/aukora-gate/' + name))
            except OSError:
                refuse('SPAWN_GATE_SIGNER_REQUIRED')
        for name in ('subuid', 'subgid'):
            if read(destination('/etc/' + name)).decode().splitlines().count('auma:165536:65536') != 1:
                refuse('SPAWN_AUMA_RANGE_REQUIRED')
        for name in ('/home/aukora-host/genesis/state', '/home/aukora-host/genesis/support', '/var/lib/aukora-boundary/targets'):
            try:
                info = destination(name).lstat()
            except OSError:
                refuse('SPAWN_HOST_PREREQUISITES_REQUIRED')
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                refuse('SPAWN_HOST_PREREQUISITES_REQUIRED')
    elif action == 'release-env':
        commit = config['release_commit']
        release_path = '/opt/aukora-genesis/release-' + commit[:7]
        record = read(destination(release_path + '/.dsh-build/genesis-artifacts.json'))
        metadata = json.loads(record)
        if metadata.get('producer', {}).get('genesisCommit') != commit:
            refuse('SOURCE_RELEASE_MISMATCH')
        data = ('AUKORA_RELEASE_DIR=' + release_path + '\nAUKORA_APPROVAL_ROOT=/etc/aukora-approvals/'
                + commit + '/state\nAUKORA_RECORD_SHA=' + hashlib.sha256(record).hexdigest() + '\n').encode()
        write(destination('/etc/aukora-genesis/release.env'), data, root)
    else:
        refuse('SPAWN_USAGE')
    print('CONFIGURED')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        error = sys.exc_info()[1]
        code = str(error) if str(error).startswith(('SPAWN_', 'SOURCE_RELEASE_')) else 'SPAWN_CONFIG_INPUT'
        print('REFUSED ' + code, file=sys.stderr)
        sys.exit(1)
