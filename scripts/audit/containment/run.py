#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded containment evidence runner; importing this file performs no effects.

The operator supplies the reviewed inventory, exact launch argv and independently
collected observer evidence. There are no production targets, privileged launches,
user provisioning, credential reads or mutable protected fixtures built into this
runner. Probe writes and state-changing signals belong only to its owned decoys.
Source fixtures do not qualify an installed confinement or an observer.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time

MAX_BYTES = 1 << 20
MAX_LINE_BYTES = 65536
MAX_ROWS = 8192
MAX_FILE_BYTES = 4 << 20
ROW_KEYS = frozenset(('run_id', 'route_id', 'route', 'target', 'result',
                      'detail', 'complete', 'metadata'))
RESULTS = frozenset(('DENIED', 'ALLOWED', 'OK', 'FAIL', 'OBSERVED', 'INCONCLUSIVE'))
INVENTORIES = frozenset(('inventory-unix', 'inventory-tcp', 'inventory-processes', 'inventory-shm',
                         'final-environment', 'final-mountinfo'))
CONTROL_KINDS = frozenset(('decoy-read', 'decoy-write', 'decoy-create', 'decoy-signal',
                          'decoy-fd', 'decoy-mem', 'decoy-shm', 'decoy-unix',
                          'decoy-abstract', 'decoy-tcp'))
COVERAGE_KINDS = {
    'socket-unix': frozenset(('decoy-unix', 'decoy-abstract')),
    'socket-tcp': frozenset(('decoy-tcp',)),
    'process-signal': frozenset(('decoy-signal',)),
    'process-fd': frozenset(('decoy-fd',)),
    'process-mem': frozenset(('decoy-mem',)),
    'path-access': frozenset(('decoy-read',)),
    'file-read-access': frozenset(('decoy-read',)),
    'file-write-access': frozenset(('decoy-write',)),
    'directory-write-access': frozenset(('decoy-create',)),
    'user-service-path': frozenset(('decoy-read',)),
    'shm-access': frozenset(('decoy-shm',)),
    'inherited-handle': frozenset(('decoy-fd',)),
}


def _json(raw, allowed=None):
    def pairs(items):
        out = {}
        duplicate = False
        for key, value in items:
            if key == 'result' and value == 'ALLOWED' and allowed is not None:
                allowed[0] = True
            if key in out:
                duplicate = True
            out[key] = value
        if duplicate:
            raise ValueError('duplicate JSON key')
        return out

    def constant(_):
        raise ValueError('non-finite JSON value')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _allowed_token(raw):
    # Preserve an escaped adverse result even when another JSON value/key is
    # malformed. This is a conservative failure signal, never positive proof.
    token = br'"(?:[^"\\]|\\.)*"'
    for match in re.finditer(b'(' + token + br')\s*:\s*(' + token + b')', raw):
        try:
            if _json(match[1].decode('utf-8')) == 'result' and _json(match[2].decode('utf-8')) == 'ALLOWED':
                return True
        except (ValueError, UnicodeError, RecursionError):
            pass
    return False


def parse_jsonl(raw, max_bytes=MAX_BYTES, max_rows=MAX_ROWS,
                max_line_bytes=MAX_LINE_BYTES):
    """Keep valid evidence and adverse evidence while refusing incomplete JSONL."""
    rows, errors, allowed = [], [], [False]
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    if not isinstance(raw, bytes):
        return {'rows': [], 'errors': ['output is not bytes or text'], 'allowed_seen': False}
    if len(raw) > max_bytes:
        errors.append('output byte cap exceeded')
        raw = raw[:max_bytes]
    if _allowed_token(raw):
        allowed[0] = True
    lines = raw.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    for index, line in enumerate(lines):
        # Adverse evidence cannot vanish because its row has another defect.
        # Decoded pairs also preserve escaped and duplicate-key forms.
        if index >= max_rows:
            errors.append('row cap exceeded')
            break
        if len(line) > max_line_bytes:
            errors.append('line byte cap exceeded')
            continue
        try:
            row = _json(line.decode('utf-8'), allowed)
            if not isinstance(row, dict):
                raise ValueError('row is not an object')
            rows.append(row)
        except (ValueError, UnicodeError, RecursionError):
            errors.append('malformed JSONL row')
    if not lines:
        errors.append('empty output')
    return {'rows': rows, 'errors': errors, 'allowed_seen': allowed[0]}


def _safe_metadata(value, depth=0):
    if depth > 12:
        return False
    if value is None or type(value) in (bool, int):
        return True
    if isinstance(value, str):
        return len(value.encode('utf-8')) <= MAX_LINE_BYTES and '\0' not in value
    if isinstance(value, list):
        return len(value) <= MAX_ROWS and all(_safe_metadata(x, depth + 1) for x in value)
    if isinstance(value, dict):
        return (len(value) <= MAX_ROWS and all(isinstance(k, str) and
                _safe_metadata(k, depth + 1) and _safe_metadata(v, depth + 1)
                for k, v in value.items()))
    return False


def _expected(expected_routes):
    if not isinstance(expected_routes, list) or not expected_routes or len(expected_routes) > MAX_ROWS:
        raise ValueError('expected routes must be a nonempty bounded list')
    expected, targets = {}, set()
    for item in expected_routes:
        if (not isinstance(item, dict) or set(item) != {'route_id', 'route', 'target', 'expect'}
                or any(not isinstance(item.get(k), str) or not item[k] or '\0' in item[k]
                       or len(item[k]) > 4096
                       for k in ('route_id', 'route', 'target'))
                or item['expect'] not in ('DENIED', 'OK', 'ALLOWED', 'OBSERVED')
                or item['route_id'] in expected):
            raise ValueError('invalid or duplicate expected route')
        expected[item['route_id']] = item
        required_result = ('OBSERVED' if item['route'] in INVENTORIES else 'OK'
                           if item['route'] == 'workspace-write' else 'DENIED'
                           if item['route'] in COVERAGE_KINDS else 'ALLOWED'
                           if item['route'] in CONTROL_KINDS else None)
        if item['expect'] != required_result:
            raise ValueError('route-specific expectation refused')
        pair = (item['route'], item['target'])
        if pair in targets:
            raise ValueError('duplicate expected route target')
        targets.add(pair)
    return expected


def summarize(parsed, expected_routes, run_id, phase, returncode=0,
              truncated=False, timed_out=False):
    """Pure exact-row verdict. No network target gets a success exception."""
    if not isinstance(parsed, dict):
        parsed = {'errors': ['invalid parsed evidence'], 'rows': []}
    errors = parsed.get('errors', [])
    errors = list(errors) if isinstance(errors, list) and all(isinstance(x, str) for x in errors) else ['invalid parser errors']
    rows = parsed.get('rows', [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        errors.append('invalid parsed rows')
        rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    failed = phase == 'real' and (parsed.get('allowed_seen') is True or
                                  any(r.get('result') in ('ALLOWED', 'FAIL') for r in rows))
    if phase not in ('real', 'control') or not isinstance(run_id, str) or not run_id:
        errors.append('invalid run binding')
    try:
        expected = _expected(expected_routes)
    except ValueError as e:
        expected = {}
        errors.append(str(e))
    if truncated or timed_out or returncode != 0:
        errors.append('launch did not complete within its bounds')
    seen, matched = set(), {}
    for row in rows:
        route_id = row.get('route_id')
        if not isinstance(route_id, str) or route_id in seen or route_id not in expected:
            errors.append('unknown, missing or duplicate route ID')
            continue
        seen.add(route_id)
        item = expected[route_id]
        required = {'run_id', 'route_id', 'route', 'target', 'result', 'detail'}
        if (not required.issubset(row) or set(row) - ROW_KEYS or row.get('run_id') != run_id
                or row.get('route') != item['route'] or row.get('target') != item['target']
                or not isinstance(row.get('result'), str) or row['result'] not in RESULTS
                or not isinstance(row.get('detail'), str)
                or len(row['detail'].encode('utf-8')) > 1024
                or ('complete' in row and type(row['complete']) is not bool)
                or ('metadata' in row and (not isinstance(row['metadata'], dict) or not _safe_metadata(row['metadata'])))):
            errors.append('row schema or binding mismatch')
            continue
        if row.get('complete') is False:
            errors.append('route reports incomplete evidence')
        if row['result'] != item['expect']:
            errors.append('route did not provide its exact expected result')
        if row['result'] == 'OBSERVED' and row.get('complete') is not True:
            errors.append('inventory observation is incomplete')
        matched[route_id] = row
    if set(matched) != set(expected):
        errors.append('missing expected route evidence')
    if phase == 'real' and not any(i['route'] == 'workspace-write' and i['expect'] == 'OK'
                                   for i in expected.values()):
        errors.append('missing workspace success control')
    status = 'FAIL' if failed else 'INCONCLUSIVE' if errors else 'PASS'
    return {'status': status, 'errors': sorted(set(errors)), 'rows': matched,
            'counts': {r: sum(x.get('result') == r for x in rows) for r in sorted(RESULTS)}}


def _closed(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def _identity(value):
    return (_closed(value, ('pid', 'start_time', 'uid')) and type(value['pid']) is int
            and value['pid'] > 0 and type(value['uid']) is int and value['uid'] >= 0
            and isinstance(value['start_time'], str) and value['start_time'].isdigit())


def _maps(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        return False
    spans = []
    for row in value:
        if (not _closed(row, ('container_id', 'host_id', 'size')) or
                any(type(row[k]) is not int or row[k] < 0 for k in row) or not row['size'] or
                row['container_id'] + row['size'] > 1 << 32 or row['host_id'] + row['size'] > 1 << 32):
            return False
        for before in spans:
            if any(max(row[k], before[k]) < min(row[k] + row['size'], before[k] + before['size'])
                   for k in ('container_id', 'host_id')):
                return False
        spans.append(row)
    return True


def _exact_inventory_metadata(manifest, observer, metadata):
    """A complete flag cannot replace a closed, bound observation payload."""
    try:
        namespaces = observer['namespaces']
        if (not _closed(namespaces, ('net', 'pid', 'mnt')) or
                any(not isinstance(value, str) or not re.fullmatch(kind + r':\[\d+\]', value)
                    for kind, value in namespaces.items())):
            return False
        unix = metadata['inventory-unix']
        tcp = metadata['inventory-tcp']
        procs = metadata['inventory-processes']
        shm = metadata['inventory-shm']
        env = metadata['final-environment']
        mounts = metadata['final-mountinfo']
        if (not _closed(unix, ('proc', 'filesystem', 'namespace')) or unix['namespace'] != namespaces['net'] or
                not isinstance(unix['proc'], list) or not isinstance(unix['filesystem'], list) or
                any(not isinstance(path, str) or not path.startswith('/') for path in unix['filesystem']) or
                any(not _closed(row, ('type', 'state', 'inode', 'address')) or
                    any(not isinstance(row[key], str) for key in row) or not row['inode'].isdigit()
                    for row in unix['proc'])):
            return False
        if (not _closed(tcp, ('listeners', 'namespace')) or tcp['namespace'] != namespaces['net'] or
                not isinstance(tcp['listeners'], list)):
            return False
        for row in tcp['listeners']:
            if (not _closed(row, ('host', 'port', 'uid', 'inode', 'family')) or
                    type(row['port']) is not int or not 1 <= row['port'] <= 65535 or
                    type(row['uid']) is not int or row['uid'] < 0 or
                    not isinstance(row['inode'], str) or not row['inode'].isdigit()):
                return False
            address = ipaddress.ip_address(row['host'])
            if (not (address.is_loopback or address.is_unspecified) or
                    row['family'] != ('ipv4' if address.version == 4 else 'ipv6')):
                return False
        if (not _closed(procs, ('processes', 'probe_identity', 'namespace', 'uid_map', 'gid_map')) or
                procs['namespace'] != namespaces['pid'] or not isinstance(procs['processes'], list) or
                not _identity(procs['probe_identity']) or any(not _identity(row) for row in procs['processes']) or
                procs['probe_identity'] not in procs['processes'] or
                not _maps(procs['uid_map']) or not _maps(procs['gid_map']) or
                procs['uid_map'] != observer['uid_map'] or procs['gid_map'] != observer['gid_map'] or
                procs['probe_identity']['uid'] != manifest['process_uid']):
            return False
        if (not _closed(shm, ('entries',)) or not isinstance(shm['entries'], list) or
                any(not _closed(row, ('path', 'uid', 'gid', 'mode', 'type')) or
                    not isinstance(row['path'], str) or not row['path'].startswith('/dev/shm/') or
                    any(type(row[k]) is not int or row[k] < 0 for k in ('uid', 'gid', 'mode', 'type'))
                    for row in shm['entries'])):
            return False
        expected_env = manifest['environment']
        if (not _closed(env, ('keys', 'values')) or not _closed(expected_env, ('keys', 'values')) or
                not isinstance(env['keys'], list) or len(set(env['keys'])) != len(env['keys']) or
                not isinstance(env['values'], dict) or
                any(key not in ('PATH', 'LANG', 'LC_ALL', 'TERM') for key in env['values']) or
                sorted(env['keys']) != sorted(expected_env['keys']) or env['values'] != expected_env['values']):
            return False
        if (not _closed(mounts, ('mounts', 'namespace')) or mounts['namespace'] != namespaces['mnt'] or
                not isinstance(mounts['mounts'], list) or not mounts['mounts'] or mounts['mounts'] != manifest['mountinfo']):
            return False
        for row in mounts['mounts']:
            if (not _closed(row, ('mount_id', 'parent_id', 'device', 'root', 'mountpoint', 'options',
                                 'optional', 'filesystem', 'source', 'super_options')) or
                    any(not isinstance(row[k], str) for k in ('mount_id', 'parent_id', 'device', 'root', 'mountpoint', 'filesystem', 'source')) or
                    not row['mount_id'].isdigit() or not row['parent_id'].isdigit() or
                    not re.fullmatch(r'\d+:\d+', row['device']) or
                    any(not row[k].startswith('/') for k in ('root', 'mountpoint')) or
                    any(not isinstance(row[k], list) or any(not isinstance(x, str) for x in row[k])
                        for k in ('options', 'optional', 'super_options'))):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def _inventory_coverage(spec, summary):
    """Discoveries and outside inventory must each have exact attempted routes."""
    errors = []
    manifest = spec.get('manifest', {})
    observer = manifest.get('observer_inventory', {})
    needed = {'unix', 'tcp', 'processes', 'shm', 'user_service_paths'}
    if (not isinstance(observer, dict) or observer.get('run_id') != spec.get('run_id')
            or observer.get('complete') is not True or not needed.issubset(observer)
            or any(not isinstance(observer[k], list) for k in needed)):
        return ['missing complete outside route inventory']
    rows = list(summary['rows'].values())
    attempted = {(x['route'], x['target']) for x in rows}
    metadata = {}
    for row in rows:
        if row['route'] in INVENTORIES:
            if row['route'] in metadata:
                errors.append('duplicate inventory category')
            metadata[row['route']] = row.get('metadata', {})
    if not _exact_inventory_metadata(manifest, observer, metadata):
        errors.append('incomplete, extra or unbound inventory metadata')
    try:
        unix = set(observer['unix'])
        unix_meta = metadata['inventory-unix']
        unix.update(unix_meta['filesystem'])
        types = {'0001': 'stream', '0002': 'datagram', '0005': 'seqpacket'}
        for row in unix_meta['proc']:
            address = row['address']
            if not address:
                # Unnamed endpoints are recorded but have no connectable address.
                inherited = [x for x in rows if x['route'] == 'inherited-handle']
                if not inherited or any(x.get('complete') is not True for x in inherited):
                    errors.append('unnamed Unix endpoint lacks complete inherited FD observation')
                if row['inode'] in observer.get('reachable_unnamed_unix', []):
                    errors.append('reachable unnamed Unix endpoint is unsupported')
                continue
            unix.add(address)
            kind = types.get(row['type'])
            if kind is None or observer.get('unix_types', {}).get(address) != kind:
                errors.append('unobserved or unsupported Unix socket type')
        if any(('socket-unix', target) not in attempted for target in unix):
            errors.append('unattempted discovered Unix endpoint')
        tcp = set(observer['tcp'])
        for row in metadata['inventory-tcp']['listeners']:
            host = row['host']
            host = '127.0.0.1' if host == '0.0.0.0' else '::1' if host == '::' else host
            host = '[' + host + ']' if ':' in host else host
            tcp.add(host + ':' + str(row['port']))
        if any(('socket-tcp', target) not in attempted for target in tcp):
            errors.append('unattempted discovered TCP listener')
        identities = observer['processes'] + metadata['inventory-processes']['processes']
        exact = {}
        for identity in identities:
            if (not isinstance(identity, dict) or set(identity) != {'pid', 'start_time', 'uid'}
                    or type(identity['pid']) is not int or identity['pid'] <= 0
                    or type(identity['uid']) is not int or identity['uid'] < 0
                    or not isinstance(identity['start_time'], str) or not identity['start_time'].isdigit()):
                raise ValueError('invalid observer process identity')
            pid = str(identity['pid'])
            if pid in exact and exact[pid] != identity:
                errors.append('process identity raced')
            exact[pid] = identity
            if (identity == metadata['inventory-processes'].get('probe_identity')
                    and identity == observer.get('owned_probe')):
                # The independent observer must bind this exact launched probe;
                # a PID/name/ancestor exclusion asserted by the guest is insufficient.
                continue
            if identity not in manifest.get('processes', []):
                errors.append('observed process lacks exact manifest identity')
            if any((route, pid) not in attempted for route in ('process-signal', 'process-fd', 'process-mem')):
                errors.append('unattempted discovered process route')
        shm = set(observer['shm'])
        shm.update(x['path'] for x in metadata['inventory-shm']['entries'])
        if any(('shm-access', target) not in attempted for target in shm):
            errors.append('unattempted discovered shared memory entry')
        if any(('user-service-path', target) not in attempted for target in observer['user_service_paths']):
            errors.append('unattempted outside user service route')
    except (KeyError, TypeError, ValueError):
        errors.append('invalid or missing inventory coverage metadata')
    return errors


def evaluate_runs(run_specs, run_results, observer, control_coverage):
    """Pure R2 verdict, exact observer snapshots, and named decoy coverage."""
    errors, failed, summaries, specs = [], False, {}, {}
    if not isinstance(run_specs, list) or not run_specs:
        errors.append('no expected runs')
        run_specs = []
    for spec in run_specs:
        if not isinstance(spec, dict) or not isinstance(spec.get('name'), str) or spec['name'] in specs:
            errors.append('invalid or duplicate run name')
            continue
        specs[spec['name']] = spec
        record = run_results.get(spec['name'], {})
        parsed = record.get('parsed', {'rows': [], 'errors': ['missing run'], 'allowed_seen': False})
        summary = summarize(parsed, spec.get('expected_routes'), spec.get('run_id'),
                            spec.get('phase'), record.get('returncode', -1),
                            record.get('truncated', False), record.get('timed_out', False))
        summaries[spec['name']] = summary
        failed |= summary['status'] == 'FAIL'
        if summary['status'] != 'PASS':
            errors.append('run ' + spec['name'] + ' is not complete')
    for name, record in run_results.items():
        if name not in specs:
            errors.append('unexpected run')
            if record.get('parsed', {}).get('allowed_seen') is True:
                failed = True
    real = {n: s for n, s in specs.items() if s.get('phase') == 'real'}
    control = {n: s for n, s in specs.items() if s.get('phase') == 'control'}
    if not real or not control:
        errors.append('real and control runs are both required')
    control_kinds, needs_coverage = set(), set()
    for name, spec in specs.items():
        try:
            expected = _expected(spec.get('expected_routes'))
        except ValueError:
            continue
        if name in real:
            if not INVENTORIES.issubset({x['route'] for x in expected.values() if x['expect'] == 'OBSERVED'}):
                errors.append('missing required inventory categories')
            errors.extend(_inventory_coverage(spec, summaries[name]))
            for route_id, item in expected.items():
                if item['expect'] == 'DENIED':
                    needs_coverage.add((name, route_id))
                elif item['expect'] not in ('OBSERVED', 'OK'):
                    errors.append('invalid real route expectation')
        else:
            for item in expected.values():
                targets = (('stream', 'datagram', 'seqpacket') if item['route'] in ('decoy-unix', 'decoy-abstract')
                           else ('ipv4', 'ipv6') if item['route'] == 'decoy-tcp' else ('owned',))
                if item['route'] not in CONTROL_KINDS or item['expect'] != 'ALLOWED' or item['target'] not in targets:
                    errors.append('control expectation is not an exact owned decoy')
            control_kinds.update(x['route'] for x in expected.values() if x['expect'] == 'ALLOWED')
    if not CONTROL_KINDS.issubset(control_kinds):
        errors.append('missing required decoy control kinds')
    covered = set()
    if not isinstance(control_coverage, list) or not control_coverage:
        errors.append('no exact decoy coverage')
        control_coverage = []
    for binding in control_coverage:
        if (not isinstance(binding, dict) or set(binding) != {'real_run', 'real_route_id', 'control_run', 'control_route_id'}
                or any(not isinstance(value, str) or not value for value in binding.values())):
            errors.append('invalid decoy coverage binding')
            continue
        key = (binding['real_run'], binding['real_route_id'])
        if key in covered or key not in needs_coverage or binding['control_run'] not in control:
            errors.append('unknown or duplicate decoy coverage')
            continue
        rr = summaries.get(binding['real_run'], {}).get('rows', {}).get(binding['real_route_id'])
        cr = summaries.get(binding['control_run'], {}).get('rows', {}).get(binding['control_route_id'])
        if (not rr or not cr or cr.get('result') != 'ALLOWED'
                or cr.get('route') not in COVERAGE_KINDS.get(rr.get('route'), ())):
            errors.append('decoy kind does not cover the real route')
            continue
        if rr['route'] == 'socket-unix':
            kind = 'decoy-abstract' if rr['target'].startswith('@') else 'decoy-unix'
            observer_inventory = real[binding['real_run']].get('manifest', {}).get('observer_inventory', {})
            socket_type = observer_inventory.get('unix_types', {}).get(rr['target'])
            if (cr['route'] != kind or socket_type not in ('stream', 'datagram', 'seqpacket')
                    or cr.get('metadata', {}).get('socket_type') != socket_type
                    or cr['target'] != socket_type):
                errors.append('Unix address kind is not covered')
                continue
        if rr['route'] == 'socket-tcp':
            try:
                host, port = rr['target'].rsplit(':', 1)
                address = ipaddress.ip_address(host.strip('[]'))
                if not address.is_loopback or not 1 <= int(port) <= 65535:
                    raise ValueError('invalid loopback endpoint')
                family = 'ipv4' if address.version == 4 else 'ipv6'
                if cr.get('metadata', {}).get('family') != family or cr['target'] != family:
                    raise ValueError('TCP family control differs')
            except (ValueError, TypeError):
                errors.append('TCP address family is not covered')
                continue
        covered.add(key)
    if covered != needs_coverage:
        errors.append('missing exact real route control coverage')
    if not isinstance(observer, dict):
        observer = {}
    before, after = observer.get('before'), observer.get('after')
    if (not isinstance(before, dict) or not isinstance(after, dict)
            or set(before) != {'run_id', 'complete', 'collected_at_ns', 'snapshots'}
            or set(after) != set(before) or before.get('complete') is not True
            or after.get('complete') is not True or not before.get('run_id')
            or after.get('run_id') != before['run_id']
            or any(s.get('run_id') != before['run_id'] for s in specs.values())
            or type(before.get('collected_at_ns')) is not int
            or type(after.get('collected_at_ns')) is not int
            or after['collected_at_ns'] <= before['collected_at_ns']
            or not isinstance(before.get('snapshots'), dict) or not before['snapshots']
            or not isinstance(after.get('snapshots'), dict)
            or not _safe_metadata(before['snapshots']) or not _safe_metadata(after['snapshots'])):
        errors.append('missing or invalid exact outside observer evidence')
    else:
        if set(before['snapshots']) != set(after['snapshots']):
            failed = True
        elif before['snapshots'] != after['snapshots']:
            failed = True
        starts = [r.get('started_at_ns') for r in run_results.values()]
        finishes = [r.get('finished_at_ns') for r in run_results.values()]
        if (any(type(x) is not int for x in starts + finishes) or not starts or
                before['collected_at_ns'] > min(starts) or
                after['collected_at_ns'] < max(finishes) or
                any(a > b for a, b in zip(starts, finishes))):
            errors.append('outside observer does not bracket completed runs')
    return {'status': 'FAIL' if failed else 'INCONCLUSIVE' if errors else 'PASS',
            'errors': sorted(set(errors)), 'runs': summaries}


def _read_json_file(path, expected_uid=None):
    if not isinstance(path, str) or not os.path.isabs(path) or '..' in path.split('/'):
        raise ValueError('evidence requires an absolute non-traversing path')
    parent = os.path.dirname(path)
    ancestors = []
    while True:
        ancestors.append(parent)
        if parent == '/':
            break
        parent = os.path.dirname(parent)
    for ancestor in reversed(ancestors):
        info = os.lstat(ancestor)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('symlink or nondirectory evidence ancestor')
        if expected_uid is not None and (info.st_uid not in (0, expected_uid) or info.st_mode & 0o022):
            raise ValueError('untrusted writable observer ancestor')
    if expected_uid is not None and os.lstat(os.path.dirname(path)).st_uid != expected_uid:
        raise ValueError('observer parent is not owned by the declared observer')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES
                or (expected_uid is not None and (info.st_uid != expected_uid or info.st_mode & 0o022))):
            raise ValueError('untrusted or oversized evidence file')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('evidence file byte cap exceeded')
        return raw, _json(raw.decode('utf-8'))
    finally:
        os.close(fd)


def _launch(argv, timeout_seconds, max_bytes=MAX_BYTES):
    """Bound both streams. Kill only our own immediate child on timeout/cap."""
    started = time.time_ns()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=False, close_fds=True, env={})
    outputs = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout_seconds
    truncated = timed_out = False
    launch_errors = []
    selector = selectors.DefaultSelector()
    try:
        for label, stream in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map() or proc.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                budget = max_bytes - sum(len(x) for x in outputs.values())
                outputs[key.data].extend(chunk[:max(0, budget)])
                if len(chunk) > budget:
                    truncated = True
                    break
            if truncated:
                break
    except OSError:
        launch_errors.append('bounded launch transport error')
    finally:
        selector.close()
        if proc.poll() is None and (timed_out or truncated or launch_errors):
            try:
                proc.kill()
            except OSError:
                launch_errors.append('owned child cleanup uncertain')
        try:
            returncode = proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            returncode = None
            timed_out = True
        proc.stdout.close()
        proc.stderr.close()
    parsed = parse_jsonl(bytes(outputs['stdout']))
    parsed['errors'].extend(launch_errors)
    return {'parsed': parsed, 'returncode': returncode,
            'truncated': truncated, 'timed_out': timed_out,
            'stderr_bytes': len(outputs['stderr']), 'started_at_ns': started,
            'finished_at_ns': time.time_ns()}


def validate_plan(plan):
    keys = {'schema_version', 'run_id', 'runs', 'observer', 'control_coverage'}
    if (not isinstance(plan, dict) or set(plan) != keys
            or type(plan.get('schema_version')) is not int or plan['schema_version'] != 1):
        raise ValueError('invalid reviewed plan envelope')
    if (not isinstance(plan['run_id'], str) or not 1 <= len(plan['run_id']) <= 128
            or '\0' in plan['run_id'] or not isinstance(plan['runs'], list)
            or not 1 <= len(plan['runs']) <= 16):
        raise ValueError('reviewed plan requires exact runs')
    names = set()
    for run in plan['runs']:
        if (not isinstance(run, dict) or set(run) != {'name', 'phase', 'argv', 'manifest', 'timeout_seconds'}
                or not isinstance(run['name'], str) or not run['name'] or run['name'] in names
                or run['phase'] not in ('real', 'control') or type(run['timeout_seconds']) is not int
                or not 1 <= run['timeout_seconds'] <= 180 or not isinstance(run['argv'], list)
                or not run['argv'] or len(run['argv']) > 128
                or any(not isinstance(a, str) or not a or '\0' in a or len(a) > MAX_LINE_BYTES for a in run['argv'])
                or not os.path.isabs(run['argv'][0]) or run['argv'].count('{manifest_base64}') != 1):
            raise ValueError('invalid exact launch or bounds')
        manifest = run['manifest']
        if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
                or manifest['schema_version'] != 1
                or manifest.get('run_id') != plan['run_id'] or manifest.get('phase') != run['phase']):
            raise ValueError('manifest does not bind the reviewed run')
        if (not _safe_metadata(manifest) or len(json.dumps(manifest, allow_nan=False).encode()) > MAX_LINE_BYTES
                or sum(len(a.encode()) for a in run['argv']) > MAX_BYTES):
            raise ValueError('reviewed manifest or argv exceeds bounds')
        expected = _expected(manifest.get('expected_routes'))
        if run['phase'] == 'real':
            if (not INVENTORIES.issubset({x['route'] for x in expected.values() if x['expect'] == 'OBSERVED'})
                    or not any(x['route'] == 'workspace-write' and x['expect'] == 'OK' for x in expected.values())
                    or not any(x['expect'] == 'DENIED' for x in expected.values())
                    or any(x['expect'] not in ('DENIED', 'OK', 'OBSERVED') for x in expected.values())
                    or any(x['route'] not in INVENTORIES | set(COVERAGE_KINDS) | {'workspace-write'} for x in expected.values())):
                raise ValueError('reviewed real route coverage is incomplete')
            observer_inventory = manifest.get('observer_inventory', {})
            if (not isinstance(observer_inventory, dict) or observer_inventory.get('run_id') != plan['run_id']
                    or observer_inventory.get('complete') is not True
                    or any(not isinstance(observer_inventory.get(k), list)
                           for k in ('unix', 'tcp', 'processes', 'shm', 'user_service_paths'))):
                raise ValueError('reviewed outside route inventory is incomplete')
        else:
            for item in expected.values():
                targets = (('stream', 'datagram', 'seqpacket') if item['route'] in ('decoy-unix', 'decoy-abstract')
                           else ('ipv4', 'ipv6') if item['route'] == 'decoy-tcp' else ('owned',))
                if item['route'] not in CONTROL_KINDS or item['expect'] != 'ALLOWED' or item['target'] not in targets:
                    raise ValueError('controls must use only exact owned decoys')
        names.add(run['name'])
    if sum(r['timeout_seconds'] for r in plan['runs']) > 600:
        raise ValueError('total launch deadline exceeds cap')
    observer = plan['observer']
    if (not isinstance(observer, dict) or set(observer) != {'before_path', 'after_path', 'uid'}
            or type(observer['uid']) is not int or observer['uid'] < 0
            or any(not isinstance(observer[p], str) or not os.path.isabs(observer[p]) or '\0' in observer[p]
                   for p in ('before_path', 'after_path'))
            or observer['before_path'] == observer['after_path']):
        raise ValueError('explicit trusted observer evidence paths are required')
    if not isinstance(plan['control_coverage'], list) or not plan['control_coverage']:
        raise ValueError('exact control coverage is required')
    real_routes, control_routes = {}, {}
    for run in plan['runs']:
        for route_id, expected in _expected(run['manifest']['expected_routes']).items():
            (real_routes if run['phase'] == 'real' else control_routes)[(run['name'], route_id)] = expected
    if not real_routes or not CONTROL_KINDS.issubset({x['route'] for x in control_routes.values()}):
        raise ValueError('reviewed real and all decoy kinds are required')
    needed = {key for key, item in real_routes.items() if item['expect'] == 'DENIED'}
    covered = set()
    for item in plan['control_coverage']:
        if (not isinstance(item, dict) or set(item) != {'real_run', 'real_route_id', 'control_run', 'control_route_id'}
                or any(not isinstance(x, str) or not x for x in item.values())):
            raise ValueError('invalid reviewed control binding')
        real_key, control_key = (item['real_run'], item['real_route_id']), (item['control_run'], item['control_route_id'])
        rr, cr = real_routes.get(real_key), control_routes.get(control_key)
        if (real_key not in needed or real_key in covered or not rr or not cr
                or cr['route'] not in COVERAGE_KINDS.get(rr['route'], ())
                or (rr['route'] == 'socket-unix' and cr['route'] !=
                    ('decoy-abstract' if rr['target'].startswith('@') else 'decoy-unix'))):
            raise ValueError('reviewed control binding does not cover its route')
        real_run = next(run for run in plan['runs'] if run['name'] == item['real_run'])
        if rr['route'] == 'socket-unix':
            kind = real_run['manifest']['observer_inventory'].get('unix_types', {}).get(rr['target'])
            if kind not in ('stream', 'datagram', 'seqpacket') or cr['target'] != kind:
                raise ValueError('reviewed Unix type has no exact control')
        if rr['route'] == 'socket-tcp':
            host, port = rr['target'].rsplit(':', 1)
            address = ipaddress.ip_address(host.strip('[]'))
            if not address.is_loopback or not 1 <= int(port) <= 65535 or cr['target'] != ('ipv4' if address.version == 4 else 'ipv6'):
                raise ValueError('reviewed TCP family has no exact control')
        covered.add(real_key)
    if covered != needed:
        raise ValueError('reviewed control coverage is incomplete')
    return plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--execute-reviewed-plan', action='store_true')
    args = parser.parse_args(argv)
    results, specs = {}, []
    try:
        raw, plan = _read_json_file(args.plan)
        if not re.fullmatch(r'[0-9a-f]{64}', args.plan_sha256) or hashlib.sha256(raw).hexdigest() != args.plan_sha256:
            raise ValueError('reviewed plan digest mismatch')
        validate_plan(plan)
        if not args.execute_reviewed_plan:
            print(json.dumps({'status': 'UNPERFORMED', 'detail': 'reviewed plan valid; no processes launched'}))
            return 2
        observer_spec = plan['observer']
        _, before = _read_json_file(observer_spec['before_path'], observer_spec['uid'])
        specs = [{'name': run['name'], 'phase': run['phase'], 'run_id': plan['run_id'],
                  'expected_routes': run['manifest']['expected_routes'], 'manifest': run['manifest']}
                 for run in plan['runs']]
        for run in plan['runs']:
            payload = base64.b64encode(json.dumps(run['manifest'], allow_nan=False,
                                                  separators=(',', ':')).encode()).decode()
            launch = [payload if a == '{manifest_base64}' else a for a in run['argv']]
            results[run['name']] = _launch(launch, run['timeout_seconds'])
        _, after = _read_json_file(observer_spec['after_path'], observer_spec['uid'])
        verdict = evaluate_runs(specs, results, {'before': before, 'after': after}, plan['control_coverage'])
        # Raw output and environment/credential bytes are never printed here.
        print(json.dumps({'status': verdict['status'], 'errors': verdict['errors'],
                          'runs': {n: {'status': s['status'], 'errors': s['errors'], 'counts': s['counts']}
                                   for n, s in verdict['runs'].items()}}))
        return 0 if verdict['status'] == 'PASS' else 1 if verdict['status'] == 'FAIL' else 2
    except (OSError, ValueError, RecursionError) as e:
        real_names = {spec['name'] for spec in specs if spec['phase'] == 'real'}
        failed = any(name in real_names and (record.get('parsed', {}).get('allowed_seen') is True or
                     any(row.get('result') in ('ALLOWED', 'FAIL') for row in record.get('parsed', {}).get('rows', [])))
                     for name, record in results.items())
        print(json.dumps({'status': 'FAIL' if failed else 'INCONCLUSIVE', 'detail': type(e).__name__}))
        return 1 if failed else 2


if __name__ == '__main__':
    sys.exit(main())
