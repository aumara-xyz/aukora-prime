#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""H-only, source-reviewed staging for a disposable app preview; never launches it.

Before executing as root, H must verify this script and the spec against independently
retained hashes using a trusted tool. The CLI hashes are drift checks, not self-approval.
No candidate module is imported. No account, unit, worker config or PG object is changed.
Conflicts/partial stages require operator reconciliation; this tool never repairs them.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import uuid

CODE = Path('/opt/aukora-prime')
CONF = Path('/etc/aukora-prime')
STATE = Path('/var/lib/aukora-prime')
RUN = Path('/run/aukora-prime')
MANIFEST = CONF / 'preview-deployment.json'
APP_UID, APP_GID, APP_IPC_GID = 997, 987, 983
HEX = re.compile(r'[0-9a-f]{64}')
MAX_FILES, MAX_BYTES = 200000, 2 * 1024 ** 3
MAX_METADATA = 65536
NOFOLLOW = os.O_NOFOLLOW | os.O_NONBLOCK


class Refusal(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refusal(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'DUPLICATE_JSON_FIELD')
        result[key] = value
    return result


def strict(data):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('NONFINITE_JSON')))
    except (UnicodeError, json.JSONDecodeError):
        raise Refusal('STRICT_JSON_REQUIRED') from None


def digest(value):
    need(isinstance(value, str) and HEX.fullmatch(value), 'EXACT_SHA256_REQUIRED')
    return value


def absolute(value):
    need(isinstance(value, str) and len(value) <= 4096 and value.startswith('/')
         and not re.search(r'[\x00-\x1f\x7f]', value)
         and str(Path(value)) == value and os.path.normpath(value) == value,
         'ABSOLUTE_CANONICAL_PATH_REQUIRED')
    return Path(value)


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def open_directory(path):
    path = absolute(str(path)); fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        return fd
    except Exception:
        os.close(fd); raise


def stable_bytes(path, expected=None, maximum=16 * 1024 * 1024):
    path = absolute(str(path))
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = next_fd
        fd = os.open(path.name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    except Exception:
        os.close(parent); raise
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             'BOUNDED_SINGLE_LINK_REGULAR_FILE_REQUIRED')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - size))
            if not block:
                break
            chunks.append(block); size += len(block)
            need(size <= maximum, 'FILE_SIZE_LIMIT')
        data = b''.join(chunks)
        need(identity(before) == identity(os.fstat(fd)) == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
             and size == before.st_size, 'FILE_CHANGED_DURING_READ')
    finally:
        os.close(fd)
        os.close(parent)
    if expected is not None:
        need(sha(data) == digest(expected), 'FILE_PIN_MISMATCH')
    return data


def spec_value(value):
    need(isinstance(value, dict) and set(value) == {
        'schema', 'release_source', 'release_digest', 'node_source', 'node_sha256',
        'manifest_source', 'manifest_sha256', 'app_entry_sha256'}, 'CLOSED_PREVIEW_SPEC_REQUIRED')
    need(value['schema'] == 'prime-preview-stage-v1', 'PREVIEW_SPEC_SCHEMA')
    for key in ['release_source', 'node_source', 'manifest_source']:
        absolute(value[key])
    for key in ['release_digest', 'node_sha256', 'manifest_sha256', 'app_entry_sha256']:
        digest(value[key])
    return value


def paths(spec):
    base = CODE / 'preview' / spec['release_digest']
    return {'base': base, 'release': base / 'release', 'node': base / 'node',
            'launcher': base / 'launch', 'manifest': MANIFEST,
            'state': STATE / 'app' / ('preview-' + spec['release_digest'])}


def manifest_value(data, spec):
    value = strict(data)
    need(isinstance(value, dict) and set(value) == {'version', 'kind', 'source_commit',
         'release_dir', 'release_digest', 'ui_integrity_sha256', 'qualification'},
         'CLOSED_PREVIEW_MANIFEST_REQUIRED')
    need(type(value['version']) is int and value['version'] == 1
         and value['kind'] == 'prime-preview-deployment/v1'
         and value['qualification'] == 'PENDING', 'EXACT_PENDING_PREVIEW_REQUIRED')
    need(isinstance(value['source_commit'], str)
         and re.fullmatch(r'[0-9a-f]{40}', value['source_commit']), 'EXACT_SOURCE_COMMIT_REQUIRED')
    digest(value['release_digest']); digest(value['ui_integrity_sha256'])
    need(value['release_digest'] == spec['release_digest']
         and value['release_dir'] == str(paths(spec)['release']), 'MANIFEST_RELEASE_BINDING_MISMATCH')
    return value


def links_contained(entries):
    """Resolve only the captured tree, never an unchecked filesystem link."""
    for name, entry in entries.items():
        if entry['kind'] != 'l':
            continue
        target = entry['target']
        need(target and not target.startswith('/') and not re.search(r'[\x00-\x1f\x7f]', target),
             'ABSOLUTE_OR_UNSAFE_RELEASE_LINK')
        parts = name.split('/')[:-1] + target.split('/')
        resolved, hops = [], 0
        while parts:
            part = parts.pop(0)
            if part in ['', '.']:
                continue
            if part == '..':
                need(resolved, 'RELEASE_LINK_ESCAPES_ROOT'); resolved.pop(); continue
            resolved.append(part)
            path = '/'.join(resolved)
            need(path in entries, 'RELEASE_LINK_TARGET_MISSING')
            found = entries[path]
            if found['kind'] == 'l':
                hops += 1
                need(hops <= 64, 'RELEASE_LINK_CYCLE')
                next_target = found['target']
                need(next_target and not next_target.startswith('/')
                     and not re.search(r'[\x00-\x1f\x7f]', next_target), 'ABSOLUTE_OR_UNSAFE_RELEASE_LINK')
                resolved.pop(); parts = next_target.split('/') + parts
            elif parts:
                need(found['kind'] == 'd', 'RELEASE_LINK_TRAVERSES_FILE')


def tree(root, copy_to=None):
    """Hash/copy physical closure with descriptor-anchored reads and no link traversal."""
    root = absolute(str(root))
    need(root.resolve(strict=True) == root, 'REAL_CANONICAL_RELEASE_ROOT_REQUIRED')
    root_fd = open_directory(root)
    entries, rows, count, total = {'': {'kind': 'd'}}, [], 0, 0
    if copy_to is not None:
        Path(copy_to).mkdir(mode=0o755)
        Path(copy_to).chmod(0o755)

    def visit(fd, rel):
        nonlocal count, total
        before = os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o022,
             'UNSAFE_RELEASE_DIRECTORY')
        for name in sorted(os.listdir(fd)):
            need(name not in ['.', '..'] and '/' not in name
                 and not re.search(r'[\x00-\x1f\x7f]', name), 'UNSAFE_RELEASE_NAME')
            path = name if not rel else rel + '/' + name
            count += 1; need(count <= MAX_FILES, 'RELEASE_FILE_LIMIT')
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            dest = Path(copy_to) / path if copy_to is not None else None
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(name, dir_fd=fd)
                need(identity(st) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
                     'RELEASE_ENTRY_CHANGED')
                entries[path] = {'kind': 'l', 'target': target}
                rows.append('l ' + path + '\0' + target)
                if dest is not None:
                    os.symlink(target, dest)
            elif stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
                try:
                    need(identity(st) == identity(os.fstat(child)), 'RELEASE_ENTRY_CHANGED')
                    entries[path] = {'kind': 'd'}
                    if dest is not None:
                        dest.mkdir(mode=0o755)
                        dest.chmod(0o755)
                    visit(child, path)
                finally:
                    os.close(child)
            else:
                need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                     and not st.st_mode & 0o7022, 'NONREGULAR_OR_MUTABLE_RELEASE_FILE')
                held = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=fd)
                output = None
                try:
                    need(identity(st) == identity(os.fstat(held)), 'RELEASE_ENTRY_CHANGED')
                    mode = 0o755 if st.st_mode & 0o111 else 0o644
                    if dest is not None:
                        output = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode)
                    hasher, size = hashlib.sha256(), 0
                    while True:
                        block = os.read(held, 1024 * 1024)
                        if not block:
                            break
                        size += len(block); total += len(block)
                        need(total <= MAX_BYTES, 'RELEASE_BYTES_LIMIT')
                        hasher.update(block)
                        if output is not None:
                            write_all(output, block)
                    need(identity(st) == identity(os.fstat(held))
                         == identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
                         and size == st.st_size, 'RELEASE_ENTRY_CHANGED')
                    entries[path] = {'kind': 'f', 'sha256': hasher.hexdigest()}
                    rows.append(('x' if st.st_mode & 0o111 else 'f') + ' ' + path + '\0' + hasher.hexdigest())
                    if output is not None:
                        os.fchmod(output, mode); os.fsync(output)
                finally:
                    os.close(held)
                    if output is not None:
                        os.close(output)
        # Reading changes atime only. Directory ctime/mtime changes reveal add/remove/rename.
        need(identity(before) == identity(os.fstat(fd)), 'RELEASE_DIRECTORY_CHANGED')

    try:
        root_before = os.fstat(root_fd)
        visit(root_fd, '')
        need(identity(root_before) == identity(root.lstat()), 'RELEASE_ROOT_CHANGED')
    finally:
        os.close(root_fd)
    links_contained(entries)
    rows.sort(key=lambda s: s.encode('utf-16-be', errors='surrogatepass'))
    return {'digest': sha(('aukora-prime:full-release:v1\0' + '\n'.join(rows)).encode()),
            'files': len(rows), 'bytes': total, 'entries': entries}


def verify(spec):
    spec_value(spec)
    manifest_bytes = stable_bytes(spec['manifest_source'], spec['manifest_sha256'], 16384)
    manifest = manifest_value(manifest_bytes, spec)
    node = stable_bytes(spec['node_source'], spec['node_sha256'], 256 * 1024 * 1024)
    observed = tree(spec['release_source'])
    need(observed['digest'] == spec['release_digest'], 'RELEASE_PIN_MISMATCH')
    need(observed['entries'].get('harness/cli.mjs', {}).get('sha256') == spec['app_entry_sha256'],
         'APP_ENTRY_PIN_MISMATCH')
    need(observed['entries'].get('prime-ui-integrity.json', {}).get('sha256')
         == manifest['ui_integrity_sha256'], 'UI_INTEGRITY_PIN_MISMATCH')
    metadata_pin = observed['entries'].get('prime-release.json', {}).get('sha256')
    need(metadata_pin is not None, 'REGULAR_RELEASE_METADATA_REQUIRED')
    metadata = strict(stable_bytes(Path(spec['release_source']) / 'prime-release.json', metadata_pin, maximum=MAX_METADATA))
    need(isinstance(metadata, dict) and metadata.get('source_commit') == manifest['source_commit'],
         'SOURCE_COMMIT_BINDING_MISMATCH')
    return manifest_bytes, node, observed


def launcher(spec):
    p = paths(spec)
    return ('#!/bin/sh\nset -eu\n'
            '[ "$(/usr/bin/id -u)" = "997" ] && [ "$(/usr/bin/id -g)" = "987" ] || exit 77\n'
            'ulimit -c 0\nulimit -n 1024\n'
            'exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C '
            'HOME=' + str(p['state'] / 'home') + ' NODE_OPTIONS=--max-old-space-size=1536 '
            + str(p['node']) + ' ' + str(p['release'] / 'harness/cli.mjs')
            + ' boot --deployment-manifest ' + str(MANIFEST)
            + ' --release-dir ' + str(p['release'])
            + ' --state-dir ' + str(p['state']) + ' --port 18731\n').encode()


def plan(spec):
    spec_value(spec)
    return {'schema': 'prime-preview-stage-plan-v1', 'qualification': 'PENDING',
            'destinations': {key: str(value) for key, value in paths(spec).items()},
            'app_identity': {'uid': APP_UID, 'gid': APP_GID}, 'port': 18731,
            'effects': ['fresh app-only release/node/launcher/manifest/private preview state'],
            'unperformed': ['H trusted outer script/spec verification', 'H staging',
                            'separate approved app launch and port availability',
                            'OS/process/resource qualification', 'all worker/PG/API qualification'],
            'launcher_sha256': sha(launcher(spec))}


def write_all(fd, data):
    while data:
        size = os.write(fd, data); need(size > 0, 'SHORT_WRITE'); data = data[size:]


def fresh_file(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode)
    try:
        write_all(fd, data); os.fchmod(fd, mode); os.fsync(fd)
    finally:
        os.close(fd)


def root_directory(path, exact_mode=None, create=False):
    """Open every ancestor without following links; existing directories are never fixed."""
    path = absolute(str(path)); fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        root_stat = os.fstat(fd)
        need(root_stat.st_uid == 0 and root_stat.st_gid == 0 and not root_stat.st_mode & 0o022,
             'ROOT_PROTECTED_PARENT_REQUIRED')
        for index, component in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                need(create and last, 'REQUIRED_ROOT_PARENT_MISSING')
                os.mkdir(component, mode=exact_mode or 0o755, dir_fd=fd)
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
                os.fchmod(next_fd, exact_mode or 0o755)
            os.close(fd); fd = next_fd
            st = os.fstat(fd)
            need(st.st_uid == 0 and st.st_gid == 0 and not st.st_mode & 0o022,
                 'ROOT_PROTECTED_PARENT_REQUIRED')
        if exact_mode is not None:
            need(stat.S_IMODE(os.fstat(fd).st_mode) == exact_mode, 'ROOT_PARENT_MODE_MISMATCH')
        return fd
    except Exception:
        os.close(fd); raise


def root_existing_or_absent(path, mode):
    try:
        fd = root_directory(path, mode)
    except FileNotFoundError:
        return
    except Refusal as error:
        if str(error) == 'REQUIRED_ROOT_PARENT_MISSING' and not path.exists() and not path.is_symlink():
            return
        raise
    else:
        os.close(fd)


def app_parent():
    root = root_directory(STATE, 0o711)
    try:
        fd = os.open('app', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=root)
    finally:
        os.close(root)
    st = os.fstat(fd)
    if not (st.st_uid == APP_UID and st.st_gid == APP_GID and stat.S_IMODE(st.st_mode) == 0o700):
        os.close(fd); raise Refusal('EXACT_PRIVATE_APP_PARENT_REQUIRED')
    return fd


def absent(path):
    need(not path.exists() and not path.is_symlink(), 'DESTINATION_ALREADY_EXISTS')


def apply(spec):
    need(sys.platform == 'linux' and os.geteuid() == 0 and os.getegid() == 0, 'H_LINUX_ROOT_ONLY')
    need(sys.flags.isolated == 1, 'ISOLATED_TRUSTED_PYTHON_REQUIRED')
    os_release = stable_bytes('/usr/lib/os-release', maximum=16384).decode()
    need(re.search(r'^ID=ubuntu$', os_release, re.M)
         and re.search(r'^VERSION_ID="?24\.04"?$', os_release, re.M), 'EXACT_UBUNTU_24_04_REQUIRED')
    account = pwd.getpwnam('prime-app')
    need((account.pw_uid, account.pw_gid) == (APP_UID, APP_GID)
         and set(os.getgrouplist('prime-app', APP_GID)) == {APP_GID, APP_IPC_GID},
         'EXACT_APP_IDENTITY_GROUPS_REQUIRED')
    manifest, node, _ = verify(spec)
    p = paths(spec)
    for required in [STATE, RUN]:
        fd = root_directory(required, 0o711); os.close(fd)
    for existing in [CODE, CODE / 'preview', CONF]:
        root_existing_or_absent(existing, 0o755)
    for destination in [p['base'], MANIFEST]:
        absent(destination)
    state_parent = app_parent()
    try:
        name = p['state'].name
        try:
            os.stat(name, dir_fd=state_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refusal('DESTINATION_ALREADY_EXISTS')
        for directory in [CODE, CODE / 'preview', CONF]:
            fd = root_directory(directory, 0o755, create=True); os.close(fd)
        # Everything remains root-owned. No code is executed while staging/verifying.
        temporary = CODE / 'preview' / ('.stage-' + uuid.uuid4().hex)
        temporary.mkdir(mode=0o755); os.chmod(temporary, 0o755)
        observed = tree(spec['release_source'], temporary / 'release')
        need(observed['digest'] == spec['release_digest'], 'RELEASE_CHANGED_DURING_STAGE')
        fresh_file(temporary / 'node', node, 0o755)
        fresh_file(temporary / 'launch', launcher(spec), 0o755)
        need(tree(temporary / 'release')['digest'] == spec['release_digest'], 'STAGED_RELEASE_PIN_MISMATCH')
        # Capture the new state inode under a protected root parent, before moving it
        # into the app-owned namespace. An app rename cannot redirect root fchown.
        os.mkdir(temporary / '.new-private-state', mode=0o700)
        private = os.open(temporary / '.new-private-state', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
        try:
            st = os.fstat(private)
            need(st.st_uid == 0 and st.st_gid == 0, 'FRESH_STATE_IDENTITY_CHANGED')
            rename_noreplace(temporary, p['base'])
            base_fd = root_directory(p['base'], 0o755)
            try:
                rename_noreplace('.new-private-state', name, base_fd, state_parent)
            finally:
                os.close(base_fd)
            os.fchmod(private, 0o700); os.fchown(private, APP_UID, APP_GID); os.fsync(private)
        finally:
            os.close(private)
        # No root access to the app-writable child after handing over ownership.
        fresh_file(MANIFEST, manifest, 0o644)
    finally:
        os.close(state_parent)
    return {**plan(spec), 'staging': 'COMPLETE', 'running': 'UNPERFORMED'}


def rename_noreplace(source, destination, source_fd=-100, destination_fd=-100):
    """Linux atomic no-replacement publish; no unsafe rename fallback."""
    libc = ctypes.CDLL(None, use_errno=True)
    need(hasattr(libc, 'renameat2'), 'ATOMIC_NOREPLACE_UNAVAILABLE')
    function = libc.renameat2
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    result = function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1)
    if result != 0:
        raise Refusal('ATOMIC_PUBLISH_REFUSED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['plan', 'verify', 'render', 'apply'])
    parser.add_argument('--spec', required=True)
    parser.add_argument('--expected-spec-sha256', required=True)
    parser.add_argument('--expected-script-sha256')
    parser.add_argument('--output-dir')
    args = parser.parse_args()
    try:
        data = stable_bytes(args.spec, args.expected_spec_sha256, 16384)
        spec = spec_value(strict(data))
        if args.phase == 'apply':
            need(args.expected_script_sha256 is not None, 'TRUSTED_OUTER_SCRIPT_PIN_REQUIRED')
            stable_bytes(str(Path(__file__).resolve()), args.expected_script_sha256)
            result = apply(spec)
        elif args.phase == 'plan':
            result = plan(spec)
        else:
            manifest, _, observed = verify(spec)
            result = {**plan(spec), 'input_verification': 'MATCH',
                      'release_files': observed['files'], 'release_bytes': observed['bytes']}
            if args.phase == 'render':
                need(args.output_dir is not None, 'FRESH_OUTPUT_DIRECTORY_REQUIRED')
                output = absolute(args.output_dir); output.mkdir(mode=0o700)
                fresh_file(output / 'launch', launcher(spec), 0o755)
                fresh_file(output / 'preview-deployment.json', manifest, 0o644)
                fresh_file(output / 'plan.json', (json.dumps(result, indent=2) + '\n').encode(), 0o644)
        print(json.dumps(result, sort_keys=True))
    except (Refusal, OSError, KeyError) as error:
        # Never echo supplied JSON, raw paths, environment, launch token or file bytes.
        reason = str(error) if isinstance(error, Refusal) else type(error).__name__
        print(json.dumps({'status': 'REFUSED', 'reason': reason, 'qualification': 'PENDING'}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
