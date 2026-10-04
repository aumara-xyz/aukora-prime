#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded observations; production data is never read, written or signalled.

Only the explicit control phase mutates probe-owned decoys. Importing this module
does nothing. Namespace-limited observations require an independent observer;
missing targets, timeouts, unsupported syscalls and truncation are inconclusive.
"""
import argparse
import base64
import ctypes
import errno
import ipaddress
import json
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 256 * 1024
MAX_ROWS = 256
MAX_ENTRIES = 2048
MAX_SECONDS = 12
SOCKET_TIMEOUT = 0.15
INVENTORIES = {'inventory-unix', 'inventory-tcp', 'inventory-processes',
               'inventory-shm', 'final-environment', 'final-mountinfo'}
CONTROL_ROUTES = {'decoy-read', 'decoy-write', 'decoy-create', 'decoy-signal',
                  'decoy-fd', 'decoy-mem', 'decoy-shm', 'decoy-unix',
                  'decoy-abstract', 'decoy-tcp'}
PROTECTED_ROUTES = {'socket-unix', 'socket-tcp', 'process-signal', 'process-fd',
                    'process-mem', 'path-access', 'file-read-access', 'file-write-access',
                    'directory-write-access', 'user-service-path', 'shm-access', 'inherited-handle'}


class ProbeDeadline(BaseException):
    """Global deadline must escape per-action inconclusive-result catches."""


def directory_handle(path):
    if (not hasattr(os, 'O_PATH') or not isinstance(path, str) or not path.startswith('/') or
            '\0' in path or any(part in ('.', '..') for part in path.split('/')) or
            (path != '/' and (path.endswith('/') or '//' in path))):
        raise ValueError('anchored Linux directory unavailable')
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    handle = os.open('/', flags)
    try:
        for part in path.split('/')[1:]:
            if not part:
                continue
            child = os.open(part, flags, dir_fd=handle)
            os.close(handle)
            handle = child
        return handle
    except BaseException:
        os.close(handle)
        raise


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate JSON key')
            out[key] = value
        return out
    if len(raw.encode('utf8') if isinstance(raw, str) else raw) > MAX_BYTES:
        raise ValueError('JSON size limit')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read_bounded(path, limit=MAX_BYTES):
    with open(path, 'rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('inventory truncated')
    return raw.decode('utf8', 'strict')


def mountinfo_rows(raw):
    """Preserve IDs, parent topology, order and every effective mount field."""
    result = []
    def unescape(value):
        import re
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
    for line in raw.splitlines():
        left, right = line.split(' - ', 1)
        fields, tail = left.split(), right.split()
        if len(fields) < 6 or len(tail) != 3 or len(result) >= MAX_ENTRIES:
            raise ValueError('mountinfo malformed or truncated')
        if not fields[0].isdigit() or not fields[1].isdigit():
            raise ValueError('invalid mount topology')
        result.append({'mount_id': fields[0], 'parent_id': fields[1],
                       'device': fields[2], 'root': unescape(fields[3]),
                       'mountpoint': unescape(fields[4]), 'options': sorted(fields[5].split(',')),
                       'optional': sorted(fields[6:]), 'filesystem': tail[0],
                       'source': unescape(tail[1]), 'super_options': sorted(tail[2].split(','))})
    if not result:
        raise ValueError('mountinfo empty')
    return result


def unix_rows(raw):
    lines = raw.splitlines()
    if not lines or lines[0].split() != ['Num', 'RefCount', 'Protocol', 'Flags', 'Type', 'St', 'Inode', 'Path']:
        raise ValueError('unix inventory header missing')
    rows = []
    for line in lines[1:]:
        fields = line.split(None, 7)
        if len(fields) < 7 or len(rows) >= MAX_ENTRIES:
            raise ValueError('unix inventory malformed or truncated')
        # Include named abstract sockets, datagrams and non-listening endpoints.
        rows.append({'type': fields[4], 'state': fields[5], 'inode': fields[6],
                     'address': fields[7] if len(fields) == 8 else ''})
    return rows


def tcp_rows(raw, family):
    lines = raw.splitlines()
    header = lines[0].split() if lines else []
    if (len(header) < 4 or header[0:2] != ['sl', 'local_address'] or
            header[2] not in ('rem_address', 'remote_address') or header[3] != 'st' or 'inode' not in header):
        raise ValueError('tcp inventory header missing')
    rows = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            raise ValueError('tcp inventory malformed')
        if fields[3] != '0A':
            continue
        address, port = fields[1].split(':')
        bits = bytes.fromhex(address)
        if family == socket.AF_INET:
            bits = bits[::-1]
        else:
            bits = b''.join(bits[i:i + 4][::-1] for i in range(0, 16, 4))
        host = socket.inet_ntop(family, bits)
        # Wildcard listeners are loopback-reachable in this same namespace.
        if ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_unspecified:
            rows.append({'host': host, 'port': int(port, 16), 'uid': int(fields[7]),
                         'inode': fields[9], 'family': 'ipv4' if family == socket.AF_INET else 'ipv6'})
        if len(rows) > MAX_ENTRIES:
            raise ValueError('tcp inventory truncated')
    return rows


def id_map_rows(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not value.isdigit() for value in fields):
            raise ValueError('invalid namespace identity map')
        container, host, size = map(int, fields)
        if not size or container + size > 1 << 32 or host + size > 1 << 32 or len(rows) >= 16:
            raise ValueError('identity map bounds')
        for previous in rows:
            if (max(container, previous['container_id']) < min(container + size, previous['container_id'] + previous['size']) or
                    max(host, previous['host_id']) < min(host + size, previous['host_id'] + previous['size'])):
                raise ValueError('overlapping identity map')
        rows.append({'container_id': container, 'host_id': host, 'size': size})
    if not rows:
        raise ValueError('empty identity map')
    return rows


def process_identity(pid, proc='/proc'):
    if type(pid) is not int or pid <= 0:
        raise ValueError('invalid process identity')
    raw = read_bounded(f'{proc}/{pid}/stat', 8192)
    tail = raw[raw.rindex(')') + 2:].split()
    status = read_bounded(f'{proc}/{pid}/status', 16384)
    uid_line = next(line for line in status.splitlines() if line.startswith('Uid:'))
    return {'pid': pid, 'start_time': tail[19], 'uid': int(uid_line.split()[1])}


def exact_identity(expected):
    try:
        return (set(expected) == {'pid', 'start_time', 'uid'} and
                process_identity(expected['pid']) == expected)
    except Exception as error:
        raise ValueError('process identity unavailable') from error


def scan_sockets(roots, deadline):
    found, examined = [], 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    for root in roots:
        anchor = directory_handle(root)
        try:
            pending = [(os.open('.', flags, dir_fd=anchor), root)]
        finally:
            os.close(anchor)
        try:
            while pending:
                current, current_path = pending.pop()
                try:
                    with os.scandir(current) as entries:
                        for entry in entries:
                            examined += 1
                            if examined > MAX_ENTRIES or time.monotonic() > deadline:
                                raise ValueError('socket scan truncated')
                            path = os.path.join(current_path, entry.name)
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISSOCK(info.st_mode):
                                found.append(path)
                            elif stat.S_ISDIR(info.st_mode):
                                child = os.open(entry.name, flags, dir_fd=current)
                                try:
                                    actual = os.fstat(child)
                                    if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                                        raise ValueError('socket directory identity changed')
                                    pending.append((child, path))
                                except BaseException:
                                    os.close(child)
                                    raise
                finally:
                    os.close(current)
        finally:
            for handle, _ in pending:
                os.close(handle)
    return sorted(found)


def inventory(route, manifest, deadline):
    if route == 'inventory-unix':
        return {'proc': unix_rows(read_bounded('/proc/net/unix')),
                'filesystem': scan_sockets(manifest['socket_roots'], deadline),
                'namespace': os.readlink('/proc/self/ns/net')}
    if route == 'inventory-tcp':
        return {'listeners': tcp_rows(read_bounded('/proc/net/tcp'), socket.AF_INET) +
                tcp_rows(read_bounded('/proc/net/tcp6'), socket.AF_INET6),
                'namespace': os.readlink('/proc/self/ns/net')}
    if route == 'inventory-processes':
        wanted = manifest['process_uid']
        if type(wanted) is not int or wanted < 0:
            raise ValueError('process uid required')
        rows = []
        names = os.listdir('/proc')
        if len(names) > MAX_ENTRIES:
            raise ValueError('process scan truncated')
        for name in names:
            if not name.isdigit() or int(name) <= 0:
                continue
            if time.monotonic() > deadline:
                raise ValueError('process scan timed out')
            identity = process_identity(int(name))
            if identity['uid'] == wanted:
                rows.append(identity)
        return {'processes': rows, 'probe_identity': process_identity(os.getpid()),
                'namespace': os.readlink('/proc/self/ns/pid'),
                'uid_map': id_map_rows(read_bounded('/proc/self/uid_map', 8192)),
                'gid_map': id_map_rows(read_bounded('/proc/self/gid_map', 8192))}
    if route == 'inventory-shm':
        names = os.listdir('/dev/shm')
        if len(names) > MAX_ENTRIES:
            raise ValueError('shared memory inventory truncated')
        rows = []
        for name in names:
            if time.monotonic() > deadline:
                raise ValueError('shared memory inventory timed out')
            path = '/dev/shm/' + name
            info = os.lstat(path)
            rows.append({'path': path, 'uid': info.st_uid, 'gid': info.st_gid,
                         'mode': stat.S_IMODE(info.st_mode), 'type': stat.S_IFMT(info.st_mode)})
        return {'entries': sorted(rows, key=lambda row: row['path'])}
    if route == 'final-environment':
        expected = manifest['environment']
        if set(expected) != {'keys', 'values'} or len(os.environ) > MAX_ENTRIES:
            raise ValueError('environment blueprint missing')
        if sorted(os.environ) != sorted(expected['keys']):
            raise ValueError('environment keys differ')
        # No arbitrary credential values or hashes are printed. Only these public
        # execution settings may be named for exact value comparison.
        if any(key not in {'PATH', 'LANG', 'LC_ALL', 'TERM'} for key in expected['values']):
            raise ValueError('nonpublic environment value requested')
        if any(os.environ.get(key) != value for key, value in expected['values'].items()):
            raise ValueError('environment public values differ')
        return {'keys': sorted(os.environ), 'values': expected['values']}
    if route == 'final-mountinfo':
        rows = mountinfo_rows(read_bounded('/proc/self/mountinfo'))
        if rows != manifest['mountinfo']:
            raise ValueError('effective mount inventory differs')
        return {'mounts': rows, 'namespace': os.readlink('/proc/self/ns/mnt')}
    raise ValueError('unknown inventory')


def access_result(error):
    # A missing target, resource error, timeout or unsupported operation proves
    # no denial. The independent observer must also establish target liveness.
    return 'DENIED' if isinstance(error, OSError) and error.errno in (errno.EACCES, errno.EPERM) else 'INCONCLUSIVE'


def target_attested(manifest, target):
    observer = manifest.get('observer_inventory', {})
    evidence = observer.get('targets', {}).get(target)
    if (observer.get('run_id') != manifest['run_id'] or observer.get('complete') is not True or
            not isinstance(evidence, dict) or evidence.get('present') is not True):
        raise ValueError('outside target presence unavailable')


def socket_connect(route, target, manifest):
    if route == 'socket-unix':
        if not isinstance(target, str) or len(target) > 108:
            raise ValueError('invalid unix address')
        address, family = ('\0' + target[1:] if target.startswith('@') else target), socket.AF_UNIX
    else:
        host, port = target.rsplit(':', 1)
        host = host.strip('[]')
        if not ipaddress.ip_address(host).is_loopback or not 1 <= int(port) <= 65535:
            raise ValueError('only loopback TCP permitted')
        address = (host, int(port))
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
    kind = socket.SOCK_STREAM
    if route == 'socket-unix':
        declared = manifest['observer_inventory'].get('unix_types', {}).get(target)
        if declared not in ('stream', 'datagram', 'seqpacket'):
            raise ValueError('socket type not observed')
        kind = {'stream': socket.SOCK_STREAM, 'datagram': socket.SOCK_DGRAM,
                'seqpacket': socket.SOCK_SEQPACKET}[declared]
    with socket.socket(family, kind) as connection:
        connection.settimeout(SOCKET_TIMEOUT)
        connection.connect(address)  # No production protocol bytes, retries or API calls.
        return True


def protected_access(route, target, manifest):
    target_attested(manifest, target)
    if route in ('socket-unix', 'socket-tcp'):
        try:
            if socket_connect(route, target, manifest) is not True:
                raise ValueError('socket attempt incomplete')
        except OSError as error:
            return access_result(error), type(error).__name__
    elif route in ('process-signal', 'process-fd', 'process-mem'):
        identity = next(row for row in manifest['processes'] if str(row['pid']) == target)
        if not exact_identity(identity):
            raise ValueError('process identity changed')
        pid = identity['pid']
        try:
            if route == 'process-signal':
                os.kill(pid, 0)  # Permission observation only; no production signal delivery.
            elif route == 'process-fd':
                names = os.listdir(f'/proc/{pid}/fd')
                if len(names) > MAX_ENTRIES:
                    raise ValueError('fd inventory truncated')
                for name in names:
                    os.readlink(f'/proc/{pid}/fd/{name}')  # No FD content reads.
            else:
                fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY | os.O_CLOEXEC)
                os.close(fd)  # No protected process memory read.
        except OSError as error:
            if not exact_identity(identity):
                raise ValueError('process identity changed')
            return access_result(error), type(error).__name__
        if not exact_identity(identity):
            raise ValueError('process identity changed')
    elif route == 'directory-write-access':
        anchor = directory_handle(target)
        try:
            if not os.access('.', os.W_OK, dir_fd=anchor, effective_ids=True, follow_symlinks=False):
                return 'DENIED', 'directory write access refused; no file created'
        finally:
            os.close(anchor)
    elif route in ('path-access', 'file-read-access', 'file-write-access', 'user-service-path', 'shm-access'):
        parent = directory_handle(os.path.dirname(target))
        anchor = None
        try:
            anchor = os.open(os.path.basename(target), os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(anchor)
        except BaseException:
            if anchor is not None:
                os.close(anchor)
            raise
        finally:
            os.close(parent)
        if not (stat.S_ISREG(info.st_mode) or (route == 'user-service-path' and stat.S_ISDIR(info.st_mode))):
            os.close(anchor)
            raise ValueError('special file or alias refused')
        flags = os.O_WRONLY if route == 'file-write-access' else os.O_RDONLY
        try:
            # Reopen only the already pinned regular inode, never a raced device.
            fd = os.open('/proc/self/fd/' + str(anchor), flags | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                actual = os.fstat(fd)
                if (actual.st_dev, actual.st_ino, actual.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
                    raise ValueError('file identity changed')
            finally:
                os.close(fd)
        except OSError as error:
            return access_result(error), type(error).__name__
        finally:
            os.close(anchor)
    else:
        raise ValueError('unknown protected route')
    return 'ALLOWED', 'access granted; no data read/write, signal delivery or protocol payload'


def inherited_handles(manifest):
    leaks, unknown = [], []
    names = os.listdir('/proc/self/fd')
    if len(names) > MAX_ENTRIES:
        raise ValueError('fd scan truncated')
    for name in names:
        if not name.isdigit():
            continue
        try:
            value = os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:
            continue  # listdir's own temporary descriptor.
        if value.startswith('socket:') or value in ('/dev/ptmx', '/dev/pts/ptmx') or any(value == root or value.startswith(root + '/')
                                             for root in manifest['protected_prefixes']):
            kind = 'socket' if value.startswith('socket:') else 'terminal-master' if value in ('/dev/ptmx', '/dev/pts/ptmx') else 'protected-path'
            leaks.append({'fd': int(name), 'kind': kind})
        elif int(name) > 2:
            unknown.append(int(name))
        else:
            role = manifest.get('stdio_roles', {}).get(name)
            info = os.fstat(int(name))
            expected = {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode}
            if role != expected:
                unknown.append(int(name))
    return ('ALLOWED' if leaks else 'INCONCLUSIVE' if unknown else 'DENIED'), {'leaks': leaks, 'unclassified': unknown}


def workspace_write(path):
    if not hasattr(os, 'O_TMPFILE'):
        raise ValueError('unnamed workspace control unavailable')
    anchor = directory_handle(path)
    fd = None
    try:
        # The inode is never named. Closing it deletes only our own temporary file.
        fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=anchor)
        os.write(fd, b'allowed\n')
        os.lseek(fd, 0, os.SEEK_SET)
        if os.read(fd, 8) != b'allowed\n':
            raise ValueError('workspace round trip failed')
    finally:
        if fd is not None:
            os.close(fd)
        os.close(anchor)


def decoy_controls(requested):
    """Owned resources only; never create users, change services or sweep PIDs."""
    results = {}
    marker = os.urandom(24).hex().encode()
    def check(name, action):
        key = name if isinstance(name, tuple) else (name, 'owned')
        try:
            action()
            results[key] = ('ALLOWED', 'owned decoy detected')
        except Exception as error:
            results[key] = ('INCONCLUSIVE', type(error).__name__)
    def own_manifest(target, identity=None, socket_type=None):
        return {'run_id': 'owned-decoy', 'processes': [] if identity is None else [identity],
                'observer_inventory': {'run_id': 'owned-decoy', 'complete': True,
                    'targets': {target: {'present': True}},
                    'unix_types': {} if socket_type is None else {target: socket_type}}}
    def require_access(route, target, identity=None, socket_type=None):
        if protected_access(route, target, own_manifest(target, identity, socket_type))[0] != 'ALLOWED':
            raise ValueError('owned access positive control not detected')
    with tempfile.TemporaryDirectory(prefix='containment-decoy-') as root:
        path = root + '/data'
        with open(path, 'xb') as stream:
            stream.write(marker)
        def decoy_read():
            require_access('file-read-access', path)
            with open(path, 'rb') as stream:
                if stream.read(128) != marker:
                    raise ValueError('decoy read mismatch')
        check('decoy-read', decoy_read)
        def decoy_write():
            require_access('file-write-access', path)
            with open(path, 'ab') as stream:
                stream.write(b'+')
            with open(path, 'rb') as stream:
                if stream.read(128) != marker + b'+':
                    raise ValueError('decoy write mismatch')
        check('decoy-write', decoy_write)
        def decoy_create():
            require_access('directory-write-access', root)
            with open(root + '/new', 'xb') as stream:
                stream.write(marker)
            if os.stat(root + '/new').st_size != len(marker):
                raise ValueError('decoy create mismatch')
        check('decoy-create', decoy_create)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            def decoy_fd():
                identity = process_identity(os.getpid())
                require_access('process-fd', str(identity['pid']), identity)
                if os.pread(fd, len(marker), 0) != marker:
                    raise ValueError('decoy FD mismatch')
                if inherited_handles({'protected_prefixes': [root]})[0] != 'ALLOWED':
                    raise ValueError('owned inherited FD not detected')
            check('decoy-fd', decoy_fd)
        finally:
            os.close(fd)
        # Synthetic memory, never a protected process address or real key.
        memory = ctypes.create_string_buffer(marker)
        def decoy_mem():
            identity = process_identity(os.getpid())
            require_access('process-mem', str(identity['pid']), identity)
            fd = os.open('/proc/self/mem', os.O_RDONLY | os.O_CLOEXEC)
            try:
                if os.pread(fd, len(marker), ctypes.addressof(memory)) != marker:
                    raise ValueError('decoy memory mismatch')
            finally:
                os.close(fd)
        check('decoy-mem', decoy_mem)
        def decoy_shm():
            fd, name = tempfile.mkstemp(prefix='containment-decoy-', dir='/dev/shm')
            try:
                os.write(fd, marker)
                require_access('shm-access', name)
                if os.pread(fd, len(marker), 0) != marker:
                    raise ValueError('decoy shared memory mismatch')
            finally:
                os.close(fd)
                os.unlink(name)
        check('decoy-shm', decoy_shm)
        def connection(family, address, kind, declared):
            with socket.socket(family, kind) as listener:
                listener.settimeout(SOCKET_TIMEOUT)
                listener.bind(address)
                if kind != socket.SOCK_DGRAM:
                    listener.listen(2)
                actual = listener.getsockname()
                if family == socket.AF_UNIX:
                    target = '@' + actual[1:].decode() if isinstance(actual, bytes) else actual
                    require_access('socket-unix', target, socket_type=declared)
                else:
                    host = '[' + actual[0] + ']' if family == socket.AF_INET6 else actual[0]
                    require_access('socket-tcp', host + ':' + str(actual[1]))
                if kind != socket.SOCK_DGRAM:
                    first, _ = listener.accept()
                    first.close()
                with socket.socket(family, kind) as client:
                    client.settimeout(SOCKET_TIMEOUT)
                    client.connect(actual)
                    client.sendall(marker)
                    if kind == socket.SOCK_DGRAM:
                        received = listener.recv(128)
                    else:
                        accepted, _ = listener.accept()
                        with accepted:
                            accepted.settimeout(SOCKET_TIMEOUT)
                            received = accepted.recv(128)
                    if received != marker:
                        raise ValueError('decoy socket mismatch')
        for expected in requested:
            name, subtype = expected['route'], expected['target']
            if name in ('decoy-unix', 'decoy-abstract'):
                kind = {'stream': socket.SOCK_STREAM, 'datagram': socket.SOCK_DGRAM,
                        'seqpacket': socket.SOCK_SEQPACKET}[subtype]
                address = (root + '/socket-' + subtype if name == 'decoy-unix' else
                           '\0containment-decoy-' + marker.decode() + '-' + subtype)
                check((name, subtype), lambda a=address, k=kind, d=subtype:
                      connection(socket.AF_UNIX, a, k, d))
            elif name == 'decoy-tcp':
                family = socket.AF_INET if subtype == 'ipv4' else socket.AF_INET6
                address = ('127.0.0.1', 0) if subtype == 'ipv4' else ('::1', 0)
                check((name, subtype), lambda f=family, a=address:
                      connection(f, a, socket.SOCK_STREAM, 'stream'))
        def decoy_signal():
            # pidfd binds the owned child even if it exits; no PID-reuse signal risk.
            if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
                raise ValueError('pidfd signal control unavailable')
            code = ('import os,signal,time\n'
                    'signal.signal(signal.SIGUSR1,lambda *_:os.write(1,b"ack\\n"))\n'
                    'os.write(1,b"ready\\n")\ntime.sleep(2)\n')
            child = subprocess.Popen([sys.executable, '-I', '-S', '-c', code],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, close_fds=True)
            handle = os.pidfd_open(child.pid)
            try:
                if not select.select([child.stdout], [], [], 0.5)[0] or os.read(child.stdout.fileno(), 6) != b'ready\n':
                    raise ValueError('decoy child not ready')
                identity = process_identity(child.pid)
                require_access('process-signal', str(child.pid), identity)
                signal.pidfd_send_signal(handle, signal.SIGUSR1)
                if not select.select([child.stdout], [], [], 0.5)[0] or os.read(child.stdout.fileno(), 4) != b'ack\n':
                    raise ValueError('decoy signal not observed')
            finally:
                try:
                    signal.pidfd_send_signal(handle, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(handle)
                child.stdout.close()
                child.wait(timeout=3)
        check('decoy-signal', decoy_signal)
    return results


def validate_manifest(manifest):
    if (not isinstance(manifest, dict) or manifest.get('schema_version') != 1 or
            manifest.get('phase') not in ('real', 'control') or
            not isinstance(manifest.get('run_id'), str) or not 1 <= len(manifest['run_id']) <= 128 or
            not isinstance(manifest.get('expected_routes'), list) or
            not 1 <= len(manifest['expected_routes']) <= MAX_ROWS):
        raise ValueError('reviewed manifest required')
    seen, pairs = set(), set()
    for row in manifest['expected_routes']:
        if (not isinstance(row, dict) or set(row) != {'route_id', 'route', 'target', 'expect'} or
                any(not isinstance(row[key], str) or not row[key] or len(row[key]) > 4096 for key in row) or
                row['route_id'] in seen):
            raise ValueError('invalid or duplicate expected route')
        seen.add(row['route_id'])
        pair = (row['route'], row['target'])
        if pair in pairs:
            raise ValueError('duplicate route target')
        pairs.add(pair)
        if manifest['phase'] == 'real' and row['expect'] not in ('DENIED', 'OK', 'OBSERVED'):
            raise ValueError('real ALLOWED exemption refused')
        if manifest['phase'] == 'real':
            expected_result = ('OBSERVED' if row['route'] in INVENTORIES else 'OK'
                               if row['route'] == 'workspace-write' else 'DENIED'
                               if row['route'] in PROTECTED_ROUTES else None)
            if row['expect'] != expected_result:
                raise ValueError('route-specific expectation refused')
        if manifest['phase'] == 'control' and (row['route'] not in CONTROL_ROUTES or row['expect'] != 'ALLOWED'):
            raise ValueError('control must use owned decoy routes')
        if manifest['phase'] == 'control':
            allowed = ('stream', 'datagram', 'seqpacket') if row['route'] in ('decoy-unix', 'decoy-abstract') else ('ipv4', 'ipv6') if row['route'] == 'decoy-tcp' else ('owned',)
            if row['target'] not in allowed:
                raise ValueError('unsupported decoy type')
    if manifest['phase'] == 'control' and (
            {row['route'] for row in manifest['expected_routes']} != CONTROL_ROUTES):
        raise ValueError('all exact decoy controls must be explicitly reviewed')
    return manifest


def run_probe(manifest):
    validate_manifest(manifest)
    deadline = time.monotonic() + MAX_SECONDS
    controls = decoy_controls(manifest['expected_routes']) if manifest['phase'] == 'control' else {}
    for expected in manifest['expected_routes']:
        route, target = expected['route'], expected['target']
        row = {'run_id': manifest['run_id'], 'route_id': expected['route_id'],
               'route': route, 'target': target, 'result': 'INCONCLUSIVE', 'detail': ''}
        try:
            if time.monotonic() > deadline:
                raise ValueError('overall probe deadline')
            if manifest['phase'] == 'control':
                row['result'], row['detail'] = controls[(route, target)]
                if route in ('decoy-unix', 'decoy-abstract'):
                    row['metadata'] = {'socket_type': target}
                elif route == 'decoy-tcp':
                    row['metadata'] = {'family': target}
            elif route in INVENTORIES:
                row.update(result='OBSERVED', complete=True, metadata=inventory(route, manifest, deadline))
            elif route == 'inherited-handle':
                row['result'], row['metadata'] = inherited_handles(manifest)
                row['complete'] = row['result'] != 'INCONCLUSIVE'
            elif route == 'workspace-write':
                if target != manifest['workspace']:
                    raise ValueError('workspace target binding differs')
                workspace_write(manifest['workspace'])
                row.update(result='OK', detail='anonymous owned workspace round trip')
            else:
                row['result'], row['detail'] = protected_access(route, target, manifest)
        except Exception as error:
            row.update(result='INCONCLUSIVE', detail=type(error).__name__)
            if route in INVENTORIES:
                row.update(result='INCONCLUSIVE', complete=False)
        yield row


def bounded_output(rows):
    """Retain adverse evidence even when metadata/output limits are reached."""
    written = 0
    for original in rows:
        row = dict(original)
        adverse = row.get('result') in ('ALLOWED', 'FAIL')
        encoded = json.dumps(row, separators=(',', ':'))
        if len(encoded.encode()) > 65536:
            row.pop('metadata', None)
            row.update(complete=False, detail='row byte cap exceeded')
            if not adverse:
                row['result'] = 'INCONCLUSIVE'
            encoded = json.dumps(row, separators=(',', ':'))
        size = len(encoded.encode()) + 1
        # Reserve a full compact row for the next already-observed adverse result.
        if written + size > MAX_BYTES - 65536 and not adverse:
            raise ValueError('output byte cap exceeded')
        if written + size > MAX_BYTES:
            row.pop('metadata', None)
            row.update(complete=False, detail='output byte cap exceeded')
            encoded = json.dumps(row, separators=(',', ':'))
            size = len(encoded.encode()) + 1
            if not adverse or written + size > MAX_BYTES:
                raise ValueError('output byte cap exceeded')
        written += size
        yield encoded
        if written > MAX_BYTES - 65536:
            raise ValueError('output byte cap exceeded')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', help='reviewed JSON manifest or base64 JSON; no default targets')
    args = parser.parse_args(argv)
    raw = args.manifest if args.manifest.startswith('{') else base64.b64decode(args.manifest, validate=True)
    manifest = validate_manifest(strict_json(raw))
    def expired(*_):
        raise ProbeDeadline('probe deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, MAX_SECONDS)
    try:
        for encoded in bounded_output(run_probe(manifest)):
            print(encoded, flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, ProbeDeadline) as error:
        print('containment-probe: invalid or incomplete input (' + type(error).__name__ + ')', file=sys.stderr)
        sys.exit(2)
