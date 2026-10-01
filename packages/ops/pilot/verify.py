#!/usr/bin/env python3
"""Pinned, scoped, read-only Prime pilot privilege observations. No service changes."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

CODE = '/opt/aukora-prime'
CONFIG = '/etc/aukora-prime'
STATE = '/var/lib/aukora-prime'
WITNESS = '/var/lib/aukora-prime-witness/pilot'
RUN = '/run/aukora-prime'
ROOTS = (CODE, CONFIG, STATE, WITNESS, RUN)
UNITS = {'prime-app.service': 'prime-app', 'prime-authority.service': 'prime-authority',
         'prime-memory.service': 'prime-memory', 'prime-postgresql.service': 'postgres'}
GROUPS = {'prime-app': ['prime-memory-ipc'],
          'prime-authority': ['prime-authority-ipc'],
          'prime-memory': ['prime-memory-ipc', 'prime-authority-ipc', 'prime-pg-socket'],
          'postgres': ['prime-pg-socket']}
PRIMARY_GROUPS = {'prime-app': 'prime-app', 'prime-authority': 'prime-authority',
                  'prime-memory': 'prime-memory', 'postgres': 'postgres'}
UNIT_FILES = {'/etc/systemd/system/' + unit for unit in UNITS}
SOCKETS = {RUN + '/authority/authority.sock': ('prime-authority', 'prime-authority-ipc', '0660', ['prime-memory'], ['prime-app']),
           RUN + '/memory/memory.sock': ('prime-memory', 'prime-memory-ipc', '0660', ['prime-app'], ['prime-authority']),
           RUN + '/postgres/.s.PGSQL.55434': ('postgres', 'prime-pg-socket', '0770', ['prime-memory'], ['prime-app'])}
SHA = re.compile(r'^[0-9a-f]{64}$')
MODE = re.compile(r'^0[0-7]{3}$')
MAX_SPEC = 1024 * 1024
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


class Refusal(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def closed(value, keys, reason):
    require(isinstance(value, dict) and set(value) == set(keys), reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_FIELD')
        result[key] = value
    return result


def under(path, root):
    return path == root or path.startswith(root + '/')


def scoped_path(value, *, unit=False, witness_parent=False):
    require(isinstance(value, str) and 0 < len(value) <= 1024
            and re.fullmatch(r'/[A-Za-z0-9_./@+:\-]+', value) is not None
            and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts, 'UNSAFE_PATH')
    require(any(under(value, root) for root in ROOTS)
            or (unit and value in UNIT_FILES)
            or (witness_parent and value == str(PurePosixPath(WITNESS).parent)), 'OUT_OF_SCOPE_PATH')
    return value


def strings(value, allowed=None):
    require(isinstance(value, list) and len(value) <= 4096
            and all(isinstance(x, str) for x in value) and len(set(value)) == len(value), 'INVALID_STRING_LIST')
    if allowed is not None:
        require(set(value) <= set(allowed), 'UNKNOWN_IDENTITY')
    return value


def validate_boundary(entry, kind):
    path, owner, group, mode = entry['path'], entry['owner'], entry['group'], int(entry['mode'], 8)
    if under(path, CODE):
        require(owner == 'root' and not mode & 0o022, 'WRITABLE_CODE_OR_CONFIG')
        require(group == 'root', 'UNTRUSTED_CODE_GROUP')
    if under(path, CONFIG):
        if kind == 'directories':
            require(owner == 'root' and not mode & 0o022, 'WRITABLE_CODE_OR_CONFIG')
            require(group in {'root', *GROUPS}, 'IPC_GROUP_CONFIG_ACCESS')
        elif path == CONFIG + '/preview-deployment.json':
            require((owner, group, mode) == ('root', 'root', 0o644), 'UNSAFE_PUBLIC_DEPLOYMENT_MANIFEST')
        elif under(path, CONFIG + '/postgres'):
            require(owner == 'root' and group == 'postgres' and mode == 0o640, 'UNSAFE_POSTGRES_CONFIG')
        else:
            kind_name = next((name for name in ('app', 'authority', 'memory') if under(path, CONFIG + '/' + name)), None)
            require(kind_name is not None and (owner, group, mode) == ('root', 'prime-' + kind_name, 0o440),
                    'UNSAFE_PRIVATE_CONFIG')
    if kind == 'directories' and path in (CODE, CONFIG, STATE, RUN, str(PurePosixPath(WITNESS).parent)):
        expected_mode = 0o711 if path in (STATE, RUN) else 0o755
        require((owner, group, mode) == ('root', 'root', expected_mode), 'UNPROTECTED_ROOT_DIRECTORY')
    if path in UNIT_FILES:
        require(kind == 'files' and (owner, group, mode) == ('root', 'root', 0o644), 'UNPROTECTED_UNIT_FILE')
    if under(path, WITNESS):
        require(owner == 'prime-authority' and group == 'prime-authority' and not mode & 0o077, 'UNPROTECTED_WITNESS')
    if kind == 'directories' and path in (RUN + '/authority', RUN + '/memory'):
        expected = ('prime-authority', 'prime-authority-ipc') if path.endswith('/authority') else ('prime-memory', 'prime-memory-ipc')
        require((owner, group) == expected and mode == 0o710, 'UNSAFE_IPC_DIRECTORY')
    if kind == 'directories' and path == RUN + '/postgres':
        require((owner, group, mode) == ('postgres', 'prime-pg-socket', 0o750), 'UNSAFE_POSTGRES_SOCKET_DIRECTORY')


def validate_spec(spec):
    closed(spec, ['schema', 'source_only', 'directories', 'files', 'subjects', 'sockets', 'units', 'release_root'], 'INVALID_SPEC_FIELDS')
    require(spec['schema'] == 'prime-pilot-privileges-v1' and spec['source_only'] is True, 'INVALID_SPEC_IDENTITY')
    release = scoped_path(spec['release_root'])
    require(str(PurePosixPath(release).parent) == CODE + '/releases'
            and SHA.fullmatch(PurePosixPath(release).name) is not None, 'INVALID_RELEASE_ROOT')
    for key in ('directories', 'files', 'subjects', 'sockets', 'units'):
        require(isinstance(spec[key], list) and len(spec[key]) <= 4096, 'INVALID_SPEC_LIST')
    paths = set()
    for kind in ('directories', 'files'):
        for entry in spec[kind]:
            closed(entry, ['path', 'owner', 'group', 'mode'] + (['sha256'] if kind == 'files' else []), 'INVALID_PATH_ENTRY')
            scoped_path(entry['path'], unit=kind == 'files', witness_parent=kind == 'directories')
            require(entry['path'] not in paths, 'DUPLICATE_PATH')
            paths.add(entry['path'])
            require(isinstance(entry['owner'], str) and entry['owner'] in {'root', *GROUPS}
                    and isinstance(entry['group'], str) and entry['group'] in {'root', *GROUPS, 'prime-authority-ipc', 'prime-memory-ipc', 'prime-pg-socket'}, 'UNKNOWN_IDENTITY')
            require(isinstance(entry['mode'], str) and MODE.fullmatch(entry['mode']) is not None, 'INVALID_MODE')
            validate_boundary(entry, kind)
            if kind == 'files':
                require(isinstance(entry['sha256'], str) and SHA.fullmatch(entry['sha256']) is not None, 'INVALID_FILE_DIGEST')
    require(set(ROOTS) | {RUN + '/authority', RUN + '/memory', RUN + '/postgres'}
            <= {e['path'] for e in spec['directories']}, 'MISSING_ROOT_DIRECTORY')
    directories = {entry['path']: entry for entry in spec['directories']}
    private_files = [entry for entry in spec['files']
                     if any(under(entry['path'], CONFIG + '/' + kind) for kind in ('app', 'authority', 'memory'))]
    for entry in private_files:
        parent = directories.get(str(PurePosixPath(entry['path']).parent))
        require(parent is not None and (parent['owner'], parent['group'], parent['mode']) == ('root', entry['group'], '0750'),
                'UNSAFE_PRIVATE_CONFIG_PARENT')
    memory_configs = {entry['path'] for entry in private_files if under(entry['path'], CONFIG + '/memory')}
    require(memory_configs, 'MISSING_MEMORY_PRIVATE_CONFIG')
    subjects = set()
    for subject in spec['subjects']:
        closed(subject, ['user', 'group', 'supplementary_groups', 'denied_write', 'denied_read', 'denied_traverse', 'allowed_traverse'], 'INVALID_SUBJECT')
        user = subject['user']
        require(isinstance(user, str) and user in GROUPS and subject['group'] == PRIMARY_GROUPS[user] and user not in subjects, 'INVALID_SUBJECT_IDENTITY')
        subjects.add(user)
        supplemental = strings(subject['supplementary_groups'])
        if user == 'postgres':
            require('prime-memory' not in supplemental, 'PG_MEMORY_CONFIG_READ_GROUP_CONFLICT')
        require(sorted(supplemental) == sorted(GROUPS[user]), 'INVALID_SUBJECT_GROUPS')
        for key in ('denied_write', 'denied_read', 'denied_traverse', 'allowed_traverse'):
            for path in strings(subject[key]):
                scoped_path(path, unit=True, witness_parent=True)
                require(path in paths or path in UNIT_FILES, 'UNPINNED_PROBE_PATH')
        require(not (set(subject['denied_traverse']) & set(subject['allowed_traverse'])), 'CONFLICTING_PROBE')
        if user in ('prime-app', 'prime-memory'):
            require(subject['denied_write'] and subject['denied_read'], 'MISSING_UNTRUSTED_NEGATIVE_PROBE')
        if user == 'postgres':
            require(memory_configs <= set(subject['denied_read']), 'MISSING_POSTGRES_MEMORY_SECRET_NEGATIVE_PROBE')
    require(subjects == set(GROUPS), 'MISSING_SUBJECT')
    found = set()
    for entry in spec['units']:
        closed(entry, ['name', 'sha256', 'user', 'group', 'supplementary_groups'], 'INVALID_UNIT')
        require(isinstance(entry['name'], str) and entry['name'] in UNITS and entry['name'] not in found, 'INVALID_UNIT_NAME')
        found.add(entry['name'])
        require(entry['user'] == UNITS[entry['name']] and entry['group'] == PRIMARY_GROUPS[entry['user']], 'INVALID_UNIT_IDENTITY')
        supplemental = strings(entry['supplementary_groups'])
        if entry['user'] == 'postgres':
            require('prime-memory' not in supplemental, 'PG_MEMORY_CONFIG_READ_GROUP_CONFLICT')
        require(sorted(supplemental) == sorted(GROUPS[entry['user']]), 'INVALID_UNIT_GROUPS')
        require(isinstance(entry['sha256'], str) and SHA.fullmatch(entry['sha256']) is not None, 'INVALID_UNIT_DIGEST')
        pins = [e for e in spec['files'] if e['path'] == '/etc/systemd/system/' + entry['name']]
        if pins:
            require(len(pins) == 1 and pins[0]['sha256'] == entry['sha256'], 'CONFLICTING_UNIT_PIN')
    require(found == set(UNITS), 'MISSING_UNIT')
    sockets = set()
    for entry in spec['sockets']:
        closed(entry, ['path', 'owner', 'group', 'mode', 'allowed_users', 'denied_users'], 'INVALID_SOCKET')
        require(isinstance(entry['path'], str) and entry['path'] in SOCKETS and entry['path'] not in sockets, 'INVALID_SOCKET_PATH')
        sockets.add(entry['path'])
        owner, group, mode, allowed, denied = SOCKETS[entry['path']]
        require((entry['owner'], entry['group'], entry['mode']) == (owner, group, mode), 'INVALID_SOCKET_PERMISSIONS')
        require(sorted(strings(entry['allowed_users'], GROUPS)) == sorted(allowed)
                and sorted(strings(entry['denied_users'], GROUPS)) == sorted(denied), 'INVALID_SOCKET_SUBJECTS')
        require(set(allowed + denied) <= subjects, 'SOCKET_SUBJECT_NOT_DEFINED')
    require(sockets == set(SOCKETS), 'MISSING_SOCKET')
    return spec


def read_spec(path, expected_sha256):
    require(isinstance(expected_sha256, str) and SHA.fullmatch(expected_sha256) is not None, 'EXPECTED_DIGEST_REQUIRED')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_SPEC, 'INVALID_EXPECTATIONS_FILE')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_SPEC + 1)
        after = os.fstat(fd)
        require(len(data) <= MAX_SPEC and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'EXPECTATIONS_CHANGED')
    finally:
        os.close(fd)
    require(hashlib.sha256(data).hexdigest() == expected_sha256, 'EXPECTATIONS_DIGEST_MISMATCH')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refusal('INVALID_JSON_CONSTANT')))
    except (UnicodeError, json.JSONDecodeError):
        raise Refusal('INVALID_EXPECTATIONS_JSON') from None
    return validate_spec(value)


def protected_ancestor(metadata, trusted_uid=0):
    require(metadata.st_uid == trusted_uid and not metadata.st_mode & 0o022, 'WRITABLE_RELEASE_ANCESTOR')


def relative_release_target(link, target, release_root):
    require(isinstance(target, str) and not os.path.isabs(target), 'ABSOLUTE_RELEASE_LINK')
    resolved = os.path.normpath(str(Path(link).parent / target))
    require(under(resolved, release_root), 'ESCAPING_RELEASE_LINK')
    return resolved


def safe_chain(path, release_root, link_depth=0):
    """Check only named path ancestors. Release links must remain relative and contained."""
    current = Path('/')
    require(link_depth <= 40, 'RELEASE_LINK_LOOP')
    for part in Path(path).parts[1:]:
        current /= part
        item = current.lstat()
        if stat.S_ISLNK(item.st_mode):
            require(under(str(current), release_root), 'SYMLINK_OUTSIDE_RELEASE')
            require(item.st_uid == 0 and item.st_gid == 0, 'UNTRUSTED_RELEASE_LINK_OWNER')
            target = relative_release_target(str(current), os.readlink(current), release_root)
            safe_chain(target, release_root, link_depth + 1)
            resolved = current.resolve(strict=True)
            require(under(str(resolved), release_root), 'ESCAPING_RELEASE_LINK')
            # Resolved physical ancestors must not be writable by an untrusted UID/group.
            for physical in [resolved, *resolved.parents]:
                if str(physical) == '/':
                    break
                metadata = physical.stat()
                if physical != resolved or stat.S_ISDIR(metadata.st_mode):
                    protected_ancestor(metadata)
        elif current != Path(path):
            require(stat.S_ISDIR(item.st_mode), 'NON_DIRECTORY_ANCESTOR')
        if not stat.S_ISLNK(item.st_mode) and stat.S_ISDIR(item.st_mode):
            if (not any(under(str(current), root) for root in ROOTS)
                    or under(str(current), CODE) or under(str(current), CONFIG)):
                protected_ancestor(item)
    return Path(path).stat()


def digest_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'NON_REGULAR_PINNED_FILE')
        result = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            result.update(block)
        after = os.fstat(fd)
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'PINNED_FILE_CHANGED')
        return result.hexdigest()
    finally:
        os.close(fd)


# Run as the exact service UID/groups. Never read data or write, truncate or create anything.
PROBE = r'''
import errno,json,os,socket,stat,sys
request=json.loads(sys.argv[1]); output=[]
for kind,paths in request['checks'].items():
 for path in paths:
  row={'check':kind,'path':path,'status':'PENDING'}
  try:
   metadata=os.lstat(path)
   if kind in ('denied_traverse','allowed_traverse','ancestor_write'):
    if not stat.S_ISDIR(metadata.st_mode): row.update(status='FAIL',reason='NOT_DIRECTORY')
    else:
     allowed=os.access(path,os.W_OK if kind=='ancestor_write' else os.X_OK,effective_ids=True)
     desired=kind=='allowed_traverse'
     row.update(status='OBSERVED' if allowed==desired else 'FAIL',reason='ACCESS_ALLOWED' if allowed else 'ACCESS_DENIED')
   elif kind in ('denied_read','denied_write'):
    if stat.S_ISDIR(metadata.st_mode):
     if kind=='denied_write':
      allowed=os.access(path,os.W_OK,effective_ids=True)
      row.update(status='FAIL' if allowed else 'OBSERVED',reason='DIRECTORY_ACCESS_ALLOWED' if allowed else 'DIRECTORY_ACCESS_DENIED')
     else: row.update(status='FAIL',reason='READ_PROBE_REQUIRES_REGULAR_FILE')
    elif not stat.S_ISREG(metadata.st_mode): row.update(status='FAIL',reason='NOT_REGULAR_FILE')
    else:
     flags=(os.O_RDONLY if kind=='denied_read' else os.O_WRONLY)|os.O_NOFOLLOW|os.O_NONBLOCK
     fd=os.open(path,flags);os.close(fd)
     row.update(status='FAIL',reason='OPEN_ALLOWED_NO_DATA_READ_OR_WRITTEN')
   elif kind in ('socket_allowed','socket_denied'):
    if not stat.S_ISSOCK(metadata.st_mode): row.update(status='FAIL',reason='NOT_SOCKET')
    else:
     with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
      connection.settimeout(1);connection.connect(path)
     row.update(status='OBSERVED' if kind=='socket_allowed' else 'FAIL',reason='CONNECTED_NO_PAYLOAD')
  except OSError as error:
   denied=error.errno in (errno.EACCES,errno.EPERM)
   row.update(status=('OBSERVED' if denied and kind!='allowed_traverse' and kind!='socket_allowed' else ('PENDING' if error.errno in (errno.ENOENT,errno.ECONNREFUSED) else 'FAIL')),reason='PERMISSION_DENIED' if denied else 'OS_ERROR',errno=error.errno)
  output.append(row)
print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'groups':sorted(os.getgroups()),'observations':output},separators=(',',':')))
'''


def summarize(rows):
    return 'FAIL' if any(r['status'] == 'FAIL' for r in rows) else ('PENDING' if not rows or any(r['status'] == 'PENDING' for r in rows) else 'OBSERVED')


def run_command(argv):
    completed = subprocess.run(argv, env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=8, check=False)
    require(len(completed.stdout) <= 256 * 1024 and len(completed.stderr) <= 16 * 1024, 'COMMAND_OUTPUT_LIMIT')
    return completed


def release_observation(spec):
    root = spec['release_root']
    row = {'check': 'release_tree', 'path': root, 'status': 'PENDING',
           'algorithm': 'aukora-prime:full-release:v1', 'expected_digest': Path(root).name}
    try:
        metadata = safe_chain(root, root)
        require(stat.S_ISDIR(metadata.st_mode), 'RELEASE_ROOT_NOT_DIRECTORY')
        protected_ancestor(metadata)
        entries, byte_count, started = 0, 0, time.monotonic()
        def walk_error(error):
            raise error
        for parent, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
            for name in directories + files:
                entries += 1
                require(entries <= 50000 and time.monotonic() - started < 30, 'RELEASE_METADATA_OBSERVATION_LIMIT')
                path = Path(parent, name)
                item = path.lstat()
                require(item.st_uid == 0 and item.st_gid == 0, 'UNTRUSTED_RELEASE_ENTRY_OWNER')
                if stat.S_ISLNK(item.st_mode):
                    safe_chain(str(path), root)
                elif stat.S_ISDIR(item.st_mode):
                    protected_ancestor(item)
                elif stat.S_ISREG(item.st_mode):
                    require(item.st_nlink == 1 and not item.st_mode & 0o022, 'MUTABLE_OR_HARDLINKED_RELEASE_FILE')
                    byte_count += item.st_size
                    require(byte_count <= 1024 * 1024 * 1024, 'RELEASE_BYTE_OBSERVATION_LIMIT')
                else:
                    raise Refusal('NONREGULAR_RELEASE_ENTRY')
        # Independently hash every physical dependency file with the shared pinned build algorithm.
        # Source mode never imports or executes this installer module.
        from pilot import full_digest
        digest = full_digest(root)
        require(digest == Path(root).name, 'FULL_RELEASE_DIGEST_MISMATCH')
        row.update(status='OBSERVED', digest=digest, entries=entries, physical_bytes=byte_count)
    except FileNotFoundError:
        row['reason'] = 'RELEASE_UNAVAILABLE'
    except (OSError, Refusal) as error:
        reason = str(error) if isinstance(error, Refusal) else 'RELEASE_OS_ERROR'
        row.update(status='PENDING' if reason.endswith('_LIMIT') else 'FAIL', reason=reason)
    except Exception:
        # The sibling evaluator refuses malformed/escaping trees without returning file contents.
        row.update(status='FAIL', reason='RELEASE_DIGEST_EVALUATOR_REFUSED_OR_UNAVAILABLE')
    return row


def validate_host_account(user, account, account_primary):
    require(account.pw_uid != 0 and account.pw_gid == account_primary.gr_gid, 'INVALID_HOST_IDENTITY')
    if user == 'postgres':
        require((account.pw_uid, account.pw_gid, account_primary.gr_gid) == (113, 114, 114), 'POSTGRES_REPORTED_IDENTITY_CHANGED')
        # Existing distro account/shell/NSS are observed, never repaired or treated as a new no-login account.
    else:
        require(account.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false'), 'LOGIN_NOT_DISABLED')


def reject_postgres_private_group(user, effective_groups, memory_gid):
    if user == 'postgres':
        require(memory_gid not in effective_groups, 'PG_MEMORY_CONFIG_READ_GROUP_CONFLICT')


def host_observations(spec):
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'HOST_MODE_REQUIRES_LINUX_ROOT')
    import grp
    import pwd
    observations = []
    identities = {}
    for user in GROUPS:
        try:
            account, account_primary = pwd.getpwnam(user), grp.getgrnam(user)
            effective_primary = grp.getgrnam(PRIMARY_GROUPS[user])
            validate_host_account(user, account, account_primary)
            supplemental = [grp.getgrnam(name).gr_gid for name in GROUPS[user]]
            identities[user] = (account.pw_uid, effective_primary.gr_gid, supplemental)
            actual = set(os.getgrouplist(user, account_primary.gr_gid))
            reject_postgres_private_group(user, actual, grp.getgrnam('prime-memory').gr_gid)
            extra = actual - {account_primary.gr_gid, *supplemental}
            observations.append({'check': 'identity', 'user': user,
                                 'status': 'PENDING' if user == 'postgres' else ('FAIL' if extra else 'OBSERVED'),
                                 'reason': 'POSTGRES_EXISTING_NSS_SCOPE_SEPARATE_FROM_UNIT_GROUP' if user == 'postgres' else 'NAMED_ACCOUNT_OBSERVED',
                                 'uid': account.pw_uid, 'nss_primary_gid': account_primary.gr_gid,
                                 'effective_unit_gid': effective_primary.gr_gid, 'nss_groups': sorted(actual),
                                 'unexpected_nss_groups': sorted(extra)})
        except (KeyError, Refusal) as error:
            observations.append({'check': 'identity', 'user': user, 'status': 'FAIL',
                                 'reason': str(error) if isinstance(error, Refusal) else 'IDENTITY_UNAVAILABLE_OR_UNSAFE'})
    if len(identities) != len(GROUPS) or len({i[0] for i in identities.values()}) != len(GROUPS):
        observations.append({'check': 'identity_separation', 'status': 'FAIL', 'reason': 'IDENTITY_NOT_DISTINCT_OR_MISSING'})
        return observations
    observations.append(release_observation(spec))
    for kind in ('directories', 'files'):
        for entry in spec[kind]:
            row = {'check': kind, 'path': entry['path'], 'status': 'PENDING'}
            try:
                info = safe_chain(entry['path'], spec['release_root'])
                require(stat.S_ISDIR(info.st_mode) if kind == 'directories' else stat.S_ISREG(info.st_mode), 'WRONG_PATH_TYPE')
                require(info.st_uid == pwd.getpwnam(entry['owner']).pw_uid and info.st_gid == grp.getgrnam(entry['group']).gr_gid,
                        'OWNERSHIP_MISMATCH')
                require(stat.S_IMODE(info.st_mode) == int(entry['mode'], 8), 'MODE_MISMATCH')
                if kind == 'files':
                    require(digest_file(entry['path']) == entry['sha256'], 'FILE_DIGEST_MISMATCH')
                row['status'] = 'OBSERVED'
            except FileNotFoundError:
                row['reason'] = 'PATH_UNAVAILABLE'
            except (OSError, Refusal) as error:
                row.update(status='FAIL', reason=str(error) if isinstance(error, Refusal) else 'PATH_OS_ERROR')
            observations.append(row)
    for socket in spec['sockets']:
        row = {'check': 'socket_metadata', 'path': socket['path'], 'status': 'PENDING'}
        try:
            info = safe_chain(socket['path'], spec['release_root'])
            require(stat.S_ISSOCK(info.st_mode), 'NOT_SOCKET')
            require(info.st_uid == pwd.getpwnam(socket['owner']).pw_uid and info.st_gid == grp.getgrnam(socket['group']).gr_gid
                    and stat.S_IMODE(info.st_mode) == int(socket['mode'], 8), 'SOCKET_PERMISSIONS_MISMATCH')
            row['status'] = 'OBSERVED'
        except FileNotFoundError:
            row['reason'] = 'SOCKET_UNAVAILABLE'
        except (OSError, Refusal) as error:
            row.update(status='FAIL', reason=str(error) if isinstance(error, Refusal) else 'SOCKET_OS_ERROR')
        observations.append(row)
    # Do not probe through a metadata/hash failure or an untrusted parent chain.
    if any(row['status'] == 'FAIL' for row in observations):
        return observations
    subjects = {entry['user']: entry for entry in spec['subjects']}
    for user, subject in subjects.items():
        checks = {key: subject[key] for key in ('denied_write', 'denied_read', 'denied_traverse', 'allowed_traverse')}
        ancestors = set()
        for path in subject['denied_write']:
            ancestors.update(str(parent) for parent in Path(path).parents)
        # Only actual named protected-file ancestors, never a host-wide directory scan.
        checks['ancestor_write'] = sorted(ancestors)
        checks['socket_allowed'] = [s['path'] for s in spec['sockets'] if user in s['allowed_users']]
        checks['socket_denied'] = [s['path'] for s in spec['sockets'] if user in s['denied_users']]
        argv = ['/usr/sbin/runuser', '-u', user, '-g', subject['group']]
        for group in subject['supplementary_groups']:
            argv += ['-G', group]
        if not subject['supplementary_groups']:
            # A repeated primary group adds no privilege, but explicitly overrides inherited NSS extras.
            argv += ['-G', subject['group']]
        argv += ['--', '/usr/bin/python3', '-I', '-c', PROBE, json.dumps({'checks': checks}, separators=(',', ':'))]
        try:
            result = run_command(argv)
            require(result.returncode == 0, 'RUNUSER_PROBE_UNAVAILABLE')
            child = json.loads(result.stdout, object_pairs_hook=unique_object)
            uid, gid, groups = identities[user]
            require(child['uid'] == uid and child['gid'] == gid and set(child['groups']) <= {gid, *groups}
                    and set(groups) <= set(child['groups']), 'PROBE_IDENTITY_MISMATCH')
            for row in child['observations']:
                observations.append({**row, 'user': user})
        except (OSError, subprocess.TimeoutExpired, Refusal, ValueError, KeyError):
            observations.append({'check': 'runuser', 'user': user, 'status': 'FAIL', 'reason': 'PROBE_UNAVAILABLE_OR_INVALID'})
    return observations


def check_unit_file(unit, release_root):
    path = '/etc/systemd/system/' + unit['name']
    metadata = safe_chain(path, release_root)
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o644, 'UNSAFE_UNIT_FILE_METADATA')
    require(digest_file(path) == unit['sha256'], 'UNIT_FILE_DIGEST_MISMATCH')


def unit_observations(spec):
    rows = []
    properties = ['LoadState', 'ActiveState', 'User', 'Group', 'SupplementaryGroups', 'FragmentPath',
                  'DropInPaths', 'MainPID', 'NoNewPrivileges', 'ProtectSystem', 'ProtectHome',
                  'ReadWritePaths', 'RestrictAddressFamilies', 'IPAddressDeny', 'IPAddressAllow']
    for unit in spec['units']:
        row = {'check': 'unit', 'unit': unit['name'], 'status': 'PENDING'}
        try:
            check_unit_file(unit, spec['release_root'])
            result = run_command(['/usr/bin/systemctl', '--no-pager', 'show', unit['name'], '--property=' + ','.join(properties)])
            require(result.returncode == 0, 'SYSTEMCTL_SHOW_UNAVAILABLE')
            observed = dict(line.split('=', 1) for line in result.stdout.decode('utf-8').splitlines() if '=' in line)
            require(observed.get('LoadState') == 'loaded', 'UNIT_NOT_LOADED')
            require(not observed.get('DropInPaths'), 'UNIT_DROP_INS_PRESENT')
            require(observed.get('FragmentPath') == '/etc/systemd/system/' + unit['name'], 'UNEXPECTED_UNIT_FRAGMENT')
            require(observed.get('User') == unit['user'] and observed.get('Group') == unit['group']
                    and sorted(observed.get('SupplementaryGroups', '').split()) == sorted(unit['supplementary_groups']), 'UNIT_IDENTITY_MISMATCH')
            enabled = run_command(['/usr/bin/systemctl', '--no-pager', 'is-enabled', unit['name']])
            state = enabled.stdout.decode('utf-8').strip()
            require(state in ('disabled', 'static'), 'UNIT_AUTOSTART_OR_UNSAFE_STATE')
            require(observed.get('NoNewPrivileges') == 'yes' and observed.get('ProtectSystem') == 'strict'
                    and observed.get('ProtectHome') == 'yes', 'UNIT_BASIC_HARDENING_MISMATCH')
            row.update(status='OBSERVED', unit_file_state=state, properties=observed)
            pid = int(observed.get('MainPID', '0'))
            if pid > 0:
                require(pid <= 4194304, 'INVALID_UNIT_PID')
                proc = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines() if ':' in line)
                import pwd, grp
                expected_uid, expected_gid = pwd.getpwnam(unit['user']).pw_uid, grp.getgrnam(unit['group']).gr_gid
                require(all(int(x) == expected_uid for x in proc['Uid'].split())
                        and all(int(x) == expected_gid for x in proc['Gid'].split()), 'RUNNING_UNIT_IDENTITY_MISMATCH')
                allowed = {expected_gid, *(grp.getgrnam(g).gr_gid for g in unit['supplementary_groups'])}
                actual = {int(x) for x in proc['Groups'].split()}
                reject_postgres_private_group(unit['user'], actual, grp.getgrnam('prime-memory').gr_gid)
                if unit['user'] == 'postgres' and not actual <= allowed:
                    row.update(status='PENDING', running_supplementary_groups=sorted(actual),
                               reason='POSTGRES_NSS_GROUPS_REQUIRE_SEPARATE_QUALIFICATION')
                else:
                    require(actual <= allowed and allowed - {expected_gid} <= actual, 'RUNNING_UNIT_GROUPS_MISMATCH')
                row['running_process_identity'] = 'OBSERVED'
            else:
                row['running_process_identity'] = 'PENDING'
        except (OSError, ValueError, subprocess.TimeoutExpired, Refusal, KeyError) as error:
            row.update(status='FAIL', reason=str(error) if isinstance(error, Refusal) else 'UNIT_OBSERVATION_UNAVAILABLE')
        rows.append(row)
    return rows


def verify(spec, mode, expected_sha256):
    validate_spec(spec)
    require(mode in ('source', 'host'), 'INVALID_MODE')
    result = {'schema': 'prime-pilot-privilege-observations-v1', 'mode': mode, 'source_only': mode == 'source',
              'expectations_sha256': expected_sha256, 'spec_status': 'VALIDATED', 'verdict': 'PENDING',
              'host_dac_status': 'NOT_RUN', 'unit_status': 'NOT_RUN', 'observations': [],
              'qualification': {'runtime_namespace_enforcement': 'PENDING', 'loopback_bpf_enforcement': 'PENDING',
                                'semantic_owner_ipc_auth': 'PENDING', 'postgres_auth_and_role_privileges': 'PENDING',
                                'private_config_mount_readonly': 'PENDING', 'postgres_peer_role_mapping': 'PENDING',
                                'postgres_worker_secret_separation': 'PENDING',
                                'retained_witness_restore_fence': 'PENDING', 'release_full_tree_digest': 'PENDING'},
              'known_source_conflicts': []}
    # The separate socket group resolves the source conflict only. The old D-private
    # group grant is explicitly refused by validate_spec, and real process access is pending.
    if mode == 'host':
        dac = host_observations(spec)
        units = unit_observations(spec)
        result.update(host_dac_status=summarize(dac), unit_status=summarize(units), observations=dac + units)
        if result['host_dac_status'] == 'FAIL' or result['unit_status'] == 'FAIL':
            result['verdict'] = 'FAIL'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expectations', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--mode', choices=('source', 'host'), default='source')
    args = parser.parse_args(argv)
    try:
        spec = read_spec(args.expectations, args.expected_sha256)
        result = verify(spec, args.mode, args.expected_sha256)
        print(json.dumps(result, separators=(',', ':'), sort_keys=True))
        return 1 if result['verdict'] == 'FAIL' else 0
    except (Refusal, OSError) as error:
        print(json.dumps({'schema': 'prime-pilot-privilege-observations-v1', 'mode': args.mode,
                          'source_only': args.mode == 'source', 'verdict': 'REFUSED', 'host_dac_status': 'NOT_RUN',
                          'reason': str(error) if isinstance(error, Refusal) else 'EXPECTATIONS_OS_ERROR'}, separators=(',', ':')))
        return 2


if __name__ == '__main__':
    sys.exit(main())
