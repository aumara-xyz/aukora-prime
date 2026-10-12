#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Stage pinned inputs and publish protected packages before launcher admission.
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

REQUIRED = {'version', 'node', 'source_checkout', 'release_commit', 'node_archive',
            'node_archive_sha256', 'public_signer_epochs', 'offer', 'auma_offer',
            'root', 'admission', 'door_config', 'built_harness'}
PATHS = {'source_checkout', 'node_archive', 'public_signer_epochs', 'offer',
         'auma_offer', 'door_config', 'built_harness'}
PRINTABLE = PATHS | {'node', 'release_commit', 'node_archive_sha256'}


def refuse(code):
    raise ValueError('SPAWN_' + code)


def regular(path, maximum=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            refuse('INPUT_FILE_INVALID')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(maximum + 1)
        if len(data) != info.st_size or len(data) > maximum:
            refuse('INPUT_FILE_INVALID')
        return data
    finally:
        os.close(fd)


def config(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refuse('CONFIG_INVALID')
            result[key] = value
        return result
    value = json.loads(regular(path, 16384), object_pairs_hook=pairs)
    if (type(value) is not dict or not REQUIRED <= set(value)
            or set(value) - REQUIRED
            or type(value['version']) is not int or value['version'] != 1
            or type(value['node']) is not str or len(value['node']) > 63
            or not re.fullmatch(r'[a-z][a-z0-9]*(-[a-z0-9]+)*', value['node'])
            or any(type(value[key]) is not str or not re.fullmatch(pattern, value[key])
                   for key, pattern in [('release_commit', r'[0-9a-f]{40}'),
                                        ('node_archive_sha256', r'[0-9a-f]{64}'),
                                        ('root', r'[0-9a-f]{64}')])
            or type(value['admission']) is not str or not value['admission']
            or any(type(value[key]) is not str or not os.path.isabs(value[key])
                   or any(char in value[key] for char in ('\0', '\n', '\r'))
                   for key in PATHS & set(value))):
        refuse('CONFIG_INVALID')
    return value


def git(source, *args):
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                             '-C', str(source), *args], env=env, capture_output=True)
    if result.returncode:
        refuse('SOURCE_UNAVAILABLE')
    return result.stdout.decode().strip()


def source_check(value):
    source = value['source_checkout']
    if git(source, 'rev-parse', 'HEAD') != value['release_commit']:
        refuse('SOURCE_RELEASE_MISMATCH')
    if git(source, 'status', '--porcelain', '--untracked-files=no'):
        refuse('SOURCE_DIRTY')


def digest_file(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            refuse('INPUT_FILE_INVALID')
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        if os.fstat(stream.fileno()).st_size != info.st_size:
            refuse('INPUT_FILE_INVALID')
        return digest.hexdigest()


def mapped(root, name):
    if not name.startswith('/') or '..' in Path(name).parts:
        refuse('INSTALL_PATH_INVALID')
    return root / name.lstrip('/')


def custody(path, uid, directory=None):
    info = os.lstat(path)
    if (info.st_uid != uid or info.st_mode & 0o022
            or (directory is True and not stat.S_ISDIR(info.st_mode))
            or (directory is False and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        refuse('INSTALL_UNPROTECTED')


def protected_root(operand):
    root = Path(operand)
    if not root.is_absolute() or str(root.resolve()) != str(root):
        refuse('INSTALL_ROOT_INVALID')
    if root == Path('/') and os.geteuid() != 0:
        refuse('ROOT_REQUIRED')
    custody(root, os.geteuid(), True)
    return root


def directories(root, target, mode=0o755):
    current = root
    for part in target.relative_to(root).parts:
        current /= part
        try:
            current.mkdir(mode=mode if current == target else 0o755)
        except FileExistsError:
            pass
        custody(current, os.geteuid(), True)


def tree(path, allow_links=False):
    custody(path, os.geteuid(), True)
    for current, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            child = Path(current) / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                if not allow_links or not child.resolve().is_relative_to(path.resolve()):
                    refuse('PACKAGE_LINK_INVALID')
            elif stat.S_ISDIR(info.st_mode):
                custody(child, os.geteuid(), True)
            else:
                custody(child, os.geteuid(), False)


def public_modes(path):
    path.chmod(0o755)
    for current, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            child = Path(current) / name
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode):
                child.chmod(0o755)
            elif stat.S_ISREG(info.st_mode):
                child.chmod(0o755 if info.st_mode & 0o111 else 0o644)


def node_extract(archive, destination, expected):
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as archive_stream, \
            tempfile.TemporaryFile(dir=destination.parent) as snapshot:
        info = os.fstat(archive_stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            refuse('INPUT_FILE_INVALID')
        digest = hashlib.sha256()
        for block in iter(lambda: archive_stream.read(1024 * 1024), b''):
            snapshot.write(block)
            digest.update(block)
        if digest.hexdigest() != expected:
            refuse('NODE_ARCHIVE_PIN_MISMATCH')
        snapshot.seek(0)
        with tarfile.open(fileobj=snapshot, mode='r:*') as source:
            extract_node(source, destination)


def extract_node(source, destination):
    found, names, prefix = False, set(), None
    for member in source:
        name = member.name.rstrip('/')
        parts = name.split('/')
        if (not name or name.startswith('/') or any(part in ('', '.', '..') for part in parts)
                or name in names or not re.fullmatch(r'node-v24\.11\.1-linux-(x64|arm64)', parts[0])):
            refuse('NODE_ARCHIVE_PATH_INVALID')
        names.add(name)
        if prefix is not None and parts[0] != prefix:
            refuse('NODE_ARCHIVE_PATH_INVALID')
        prefix = parts[0]
        if member.issym():
            link = Path(*parts[:-1]) / member.linkname
            if (os.path.isabs(member.linkname)
                    or not (destination / link).resolve().is_relative_to((destination / prefix).resolve())):
                refuse('NODE_ARCHIVE_LINK_INVALID')
            continue
        if not member.isdir() and not member.isfile():
            refuse('NODE_ARCHIVE_TYPE_INVALID')
        if name == prefix + '/bin/node':
            if not member.isfile() or member.size < 1 or member.size > 256 * 1024 * 1024:
                refuse('NODE_BINARY_INVALID')
            destination.mkdir(mode=0o755)
            (destination / 'bin').mkdir(mode=0o755)
            with source.extractfile(member) as content, (destination / 'bin/node').open('xb') as output:
                shutil.copyfileobj(content, output)
            (destination / 'bin/node').chmod(0o755)
            found = True
    if not found:
        refuse('NODE_BINARY_INVALID')


def precheck(value, root):
    source_check(value)
    if digest_file(value['node_archive']) != value['node_archive_sha256']:
        refuse('NODE_ARCHIVE_PIN_MISMATCH')
    for name in ('offer', 'auma_offer', 'door_config', 'public_signer_epochs'):
        regular(value[name])
    if not Path(value['built_harness']).is_dir():
        refuse('HARNESS_REQUIRED')


def stage(value, root):
    precheck(value, root)
    target = mapped(root, '/var/lib/aukora-spawn/stage')
    parent = target.parent
    directories(root, parent, 0o700)
    if target.exists() or target.is_symlink():
        refuse('STAGE_EXISTS')
    target.mkdir(mode=0o700)
    checkout = target / 'checkout'
    git(root, 'clone', '--quiet', '--no-hardlinks', '--no-checkout', value['source_checkout'], str(checkout))
    git(checkout, 'checkout', '--quiet', '--detach', value['release_commit'])
    source_check(dict(value, source_checkout=str(checkout)))
    archive = Path(value['source_checkout']) / 'vendor/dsh-source.tar.gz'
    pin = json.loads(regular(checkout / 'upstream-dsh.json'))
    if digest_file(archive) != pin.get('archiveSha256'):
        refuse('HARNESS_ARCHIVE_PIN_MISMATCH')
    (checkout / 'vendor').mkdir(exist_ok=True)
    shutil.copyfile(archive, checkout / 'vendor/dsh-source.tar.gz')
    for source, name in [('packages/boundary-gate', 'gate-package'), ('packages/owner-key', 'owner-key')]:
        tree(checkout / source)
        shutil.copytree(checkout / source, target / name)
    node_extract(value['node_archive'], target / 'node', value['node_archive_sha256'])
    (target / 'signer-epochs.json').write_bytes(regular(value['public_signer_epochs']))
    (target / 'signer-epochs.json').chmod(0o600)
    print('STAGED')


def file_install(root, source, destination, mode):
    directories(root, destination.parent)
    data = regular(source, 16 * 1024 * 1024)
    if destination.exists() or destination.is_symlink():
        custody(destination, os.geteuid(), False)
        if regular(destination, 16 * 1024 * 1024) != data or destination.stat().st_mode & 0o777 != mode:
            refuse('INSTALL_CONFLICT')
        return
    with destination.open('xb') as output:
        output.write(data)
    destination.chmod(mode)


def publish(value, root):
    target = mapped(root, '/var/lib/aukora-spawn/stage')
    custody(target, os.geteuid(), True)
    checkout = target / 'checkout'
    source_check(dict(value, source_checkout=str(checkout)))
    outputs = [('checkout', '/opt/aukora-genesis/src'), ('gate-package', '/opt/aukora-boundary-gate'),
               ('owner-key', '/opt/owner-key'), ('node', '/opt/aukora-node')]
    for name, destination in outputs:
        source, output = target / name, mapped(root, destination)
        tree(source, allow_links=name == 'checkout')
        if output.exists() or output.is_symlink():
            refuse('INSTALL_CONFLICT')
    for name in ('gate-package-manifest.json', 'signer-epochs.json'):
        regular(target / name)
    for name, destination in outputs:
        source, output = target / name, mapped(root, destination)
        directories(root, output.parent)
        public_modes(source)
        source.rename(output)
    package = mapped(root, '/opt/aukora-boundary-gate')
    for name, destination, mode in [
            ('gate-package-manifest.json', '/etc/aukora-boundary-gate/gate-package-manifest.json', 0o644),
            ('signer-epochs.json', '/etc/aukora-boundary-gate/signer-epochs.json', 0o644)]:
        file_install(root, target / name, mapped(root, destination), mode)
    file_install(root, package / 'host/install/gate-bootstrap.py',
                 mapped(root, '/usr/local/lib/aukora-boundary/gate-bootstrap'), 0o755)
    file_install(root, package / 'host/sbx-exec', mapped(root, '/usr/local/lib/aukora-boundary/sbx-exec'), 0o755)
    file_install(root, package / 'host/systemd/selfcheck-with-retry',
                 mapped(root, '/usr/local/lib/aukora-boundary/selfcheck-with-retry'), 0o755)
    openshell = mapped(root, '/usr/local/lib/aukora-boundary/openshell')
    if openshell.exists() or openshell.is_symlink():
        refuse('INSTALL_CONFLICT')
    tree(package / 'host/openshell')
    shutil.copytree(package / 'host/openshell', openshell)
    print('PUBLISHED')


def main(args):
    try:
        if len(args) != 3 or args[0] not in ('field', 'precheck', 'stage', 'publish'):
            refuse('USAGE_INVALID')
        action, path, operand = args
        value = config(path)
        if action == 'field':
            if operand not in PRINTABLE or operand not in value:
                refuse('FIELD_FORBIDDEN')
            print(value[operand])
        else:
            root = protected_root(operand)
            {'precheck': precheck, 'stage': stage, 'publish': publish}[action](value, root)
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        error = sys.exc_info()[1]
        code = str(error) if str(error).startswith('SPAWN_') else 'SPAWN_INPUT_INVALID'
        print('REFUSED ' + code, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
