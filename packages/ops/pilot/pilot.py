#!/usr/bin/env python3
"""Source-only preparation for the approved existing Ubuntu pilot. Never starts services.

Only H and the designated PG operator may execute their assigned mutation phases. Render/plan
and disposable checks work locally. Supplied pins are prerequisites, not evidence of
independent review, correct IPC semantics or running qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

CODE = Path('/opt/aukora-prime')
CONF = Path('/etc/aukora-prime')
STATE = Path('/var/lib/aukora-prime')
WITNESS = Path('/var/lib/aukora-prime-witness/pilot')
RUN = Path('/run/aukora-prime')
UNITS = {'app': 'prime-app.service', 'authority': 'prime-authority.service',
         'memory': 'prime-memory.service', 'postgres': 'prime-postgresql.service'}
PACKAGES = {
    'libjson-perl': '4.10000-1', 'postgresql-client-common': '257build1.1',
    'postgresql-common': '257build1.1', 'ssl-cert': '1.1.2ubuntu1',
    'libllvm17t64': '1:17.0.6-9ubuntu1', 'libpq5': '16.15-0ubuntu0.24.04.1',
    'postgresql-client-16': '16.15-0ubuntu0.24.04.1',
    'postgresql-16': '16.15-0ubuntu0.24.04.1',
}
GROUPS = ['prime-app', 'prime-authority', 'prime-memory', 'prime-authority-ipc',
          'prime-memory-ipc']
SUPPLEMENTARY = {'app': ['prime-memory-ipc'], 'authority': ['prime-authority-ipc'],
                 'memory': ['prime-authority-ipc', 'prime-memory-ipc'],
                 'postgres': ['prime-memory']}
POLICY = b'#!/bin/sh\n[ "${1-}" = --quiet ] && shift\ncase "${1-}" in\n  postgresql|postgresql.service|postgresql@*.service) exit 101 ;;\n  *) exit 0 ;;\nesac\n'
CREATE_POLICY = b'create_main_cluster = false\n'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'DEBIAN_FRONTEND': 'noninteractive', 'UCF_FORCE_CONFFOLD': '1',
       'NEEDRESTART_MODE': 'l', 'NEEDRESTART_SUSPEND': '1'}
HASH = re.compile(r'[0-9a-f]{64}')
WORKER_CONFIG_HOLD = 'PG_MEMORY_CONFIG_READ_GROUP_CONFLICT'

class Refusal(ValueError):
    pass

def need(condition, reason):
    if not condition:
        raise Refusal(reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'DUPLICATE_JSON_FIELD')
        result[key] = value
    return result

def read_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs)

def digest_value(value):
    need(isinstance(value, str) and HASH.fullmatch(value), 'EXACT_SHA256_REQUIRED')
    return value

def safe_relative(value):
    need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.\-/]+', value), 'SAFE_RELATIVE_PATH_REQUIRED')
    p = Path(value)
    need(not p.is_absolute() and '..' not in p.parts and value == p.as_posix(), 'PATH_ESCAPE')
    return value

def regular(path, expected=None):
    p = Path(path)
    st = p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'REGULAR_UNLINKED_FILE_REQUIRED')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        held = os.fstat(fd)
        need((held.st_dev, held.st_ino, held.st_mode, held.st_nlink) ==
             (st.st_dev, st.st_ino, st.st_mode, 1), 'FILE_CHANGED_DURING_OPEN')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read()
    finally:
        os.close(fd)
    if expected is not None:
        need(sha(data) == digest_value(expected), 'FILE_PIN_MISMATCH')
    return data

def fixed_spec(spec):
    need(isinstance(spec, dict) and set(spec) == {'schema', 'release_source', 'release_digest',
         'node_source', 'node_sha256', 'deployment_manifest_source', 'deployment_manifest_sha256',
         'services'}, 'CLOSED_DEPLOYMENT_SPEC_REQUIRED')
    need(spec['schema'] == 'prime-pilot-deployment-v1', 'DEPLOYMENT_SCHEMA')
    for field in ['release_source', 'node_source', 'deployment_manifest_source']:
        need(isinstance(spec[field], str) and Path(spec[field]).is_absolute(), 'ABSOLUTE_SOURCE_REQUIRED')
    digest_value(spec['release_digest']); digest_value(spec['node_sha256']); digest_value(spec['deployment_manifest_sha256'])
    need(set(spec['services']) == {'app', 'authority', 'memory'}, 'EXACT_THREE_NODE_SERVICES_REQUIRED')
    for kind, row in spec['services'].items():
        keys = {'entrypoint', 'sha256'} if kind == 'app' else {'entrypoint', 'sha256', 'config_source', 'config_sha256'}
        need(isinstance(row, dict) and set(row) == keys, 'CLOSED_SERVICE_BINDING_REQUIRED')
        safe_relative(row['entrypoint']); digest_value(row['sha256'])
        if kind in ['authority', 'memory']:
            digest_value(row['config_sha256'])
            need(isinstance(row['config_source'], str) and Path(row['config_source']).is_absolute()
                 and Path(row['config_source']).suffix == '.mjs', 'IMMUTABLE_MJS_CONFIG_REQUIRED')
            need(row['entrypoint'] == 'packages/runtime-bridge/src/worker.mjs', 'EXACT_WORKER_ENTRYPOINT_REQUIRED')
        else:
            need(row['entrypoint'] == 'harness/cli.mjs', 'EXACT_APP_BOOT_ENTRYPOINT_REQUIRED')
    return spec

def release_path(spec):
    return CODE / 'releases' / digest_value(spec['release_digest'])

def full_digest(root):
    """Same byte/mode/contained-link domain as ops fullTreeDigest, no omission."""
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), 'REAL_RELEASE_ROOT_REQUIRED')
    root = root.resolve(strict=True)
    rows = []
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(parent) / name
            rel = p.relative_to(root).as_posix()
            need('\n' not in rel and '\x00' not in rel, 'UNSAFE_RELEASE_NAME')
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(p)
                actual = p.resolve(strict=True)
                need(not os.path.isabs(target) and (actual == root or root in actual.parents), 'RELEASE_LINK_ESCAPES_ROOT')
                rows.append('l ' + rel + '\0' + target)
            elif stat.S_ISREG(st.st_mode):
                need(st.st_nlink == 1 and not st.st_mode & 0o022, 'MUTABLE_OR_HARDLINKED_RELEASE_FILE')
                rows.append(('x' if st.st_mode & 0o111 else 'f') + ' ' + rel + '\0' + sha(p.read_bytes()))
            else:
                need(stat.S_ISDIR(st.st_mode), 'NONREGULAR_RELEASE_ENTRY')
    # JavaScript lexical sorting uses UTF-16 code units.
    rows.sort(key=lambda s: s.encode('utf-16-be', errors='surrogatepass'))
    return sha(('aukora-prime:full-release:v1\0' + '\n'.join(rows)).encode())

def verify_inputs(spec):
    fixed_spec(spec)
    source = Path(spec['release_source']).resolve(strict=True)
    need(full_digest(source) == spec['release_digest'], 'RELEASE_PIN_MISMATCH')
    regular(spec['node_source'], spec['node_sha256'])
    for row in spec['services'].values():
        p = source / row['entrypoint']
        need(source in p.resolve(strict=True).parents, 'SERVICE_ENTRYPOINT_ESCAPES_RELEASE')
        regular(p, row['sha256'])
        if 'config_source' in row:
            regular(row['config_source'], row['config_sha256'])
    manifest = json.loads(regular(spec['deployment_manifest_source'], spec['deployment_manifest_sha256']), object_pairs_hook=pairs)
    need(isinstance(manifest, dict) and set(manifest) == {'version', 'kind', 'source_commit', 'release_digest',
         'ui_integrity_sha256', 'release_dir', 'qualification'}, 'CLOSED_DEPLOYMENT_MANIFEST_REQUIRED')
    need(type(manifest['version']) is int and manifest['version'] == 1
         and manifest['kind'] == 'prime-preview-deployment/v1' and manifest['qualification'] == 'PENDING',
         'EXACT_PENDING_PREVIEW_MANIFEST_REQUIRED')
    need(isinstance(manifest['source_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', manifest['source_commit']), 'EXACT_SOURCE_COMMIT_REQUIRED')
    digest_value(manifest['ui_integrity_sha256'])
    need(manifest['release_digest'] == spec['release_digest'] and manifest['release_dir'] == str(release_path(spec)), 'DEPLOYMENT_MANIFEST_BINDING_MISMATCH')

def common_unit(kind, extra, write_paths, memory, cpu, tasks):
    user = 'postgres' if kind == 'postgres' else 'prime-' + kind
    return '\n'.join([
        '[Unit]', 'Description=AUKORA Prime approved synthetic pilot ' + kind,
        '# Static unit: no Install section, no Wants/Requires, no automatic startup.', '',
        '[Service]', 'Type=simple', 'User=' + user, 'Group=' + user,
        'SupplementaryGroups=' + ' '.join(SUPPLEMENTARY[kind]),
        'WorkingDirectory=' + str(STATE / kind),
        'UMask=0077', 'Restart=no', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
        'AmbientCapabilities=', 'PrivateTmp=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
        'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectKernelLogs=yes',
        'ProtectControlGroups=yes', 'RestrictSUIDSGID=yes', 'RestrictRealtime=yes',
        'LockPersonality=yes', 'RestrictNamespaces=yes', 'RemoveIPC=' + ('no' if kind == 'postgres' else 'yes'),
        'ReadWritePaths=' + ' '.join(map(str, write_paths)),
        'CPUQuota=' + str(cpu) + '%', 'MemoryMax=' + memory, 'MemorySwapMax=0',
        'TasksMax=' + str(tasks), 'LimitNOFILE=1024', 'LimitCORE=0',
        'StandardOutput=journal', 'StandardError=journal',
        *extra, '',
    ])

def unit(kind, spec):
    if kind == 'postgres':
        return common_unit(kind, [
            'ExecStart=/usr/lib/postgresql/16/bin/postgres -D ' + str(STATE / 'postgres')
            + ' -c config_file=' + str(CONF / 'postgres/postgresql.conf'),
            'RestrictAddressFamilies=AF_UNIX', 'PrivateNetwork=yes',
            'KillSignal=SIGINT', 'KillMode=mixed', 'TimeoutStopSec=60',
            'InaccessiblePaths=' + str(STATE / 'authority') + ' ' + str(WITNESS),
        ], [STATE / 'postgres', RUN / 'postgres'], '1536M', 50, 32)
    row = spec['services'][kind]
    command = str(CODE / 'tools/node') + ' ' + str(release_path(spec) / row['entrypoint'])
    if kind == 'app':
        # Trusted external manifest; H's upcoming pinned helper verifies it.
        command += ' boot --deployment-manifest ' + str(CONF / 'preview-deployment.json')
        command += ' --state-dir ' + str(STATE / 'app') + ' --port 18731'
    else:
        command += ' --config ' + str(CONF / kind / 'config.mjs')
    extra = ['ExecStart=' + command, 'Environment=NODE_OPTIONS=--max-old-space-size=512',
             'Environment=AUKORA_PRIME_PAID_INFERENCE=disabled', 'Environment=AUKORA_PRIME_GPU=disabled',
             'Environment=PRIME_SYNTHETIC_ONLY=1', 'KillMode=control-group', 'TimeoutStopSec=15']
    if kind == 'app':
        extra += ['RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
                  'IPAddressDeny=any', 'IPAddressAllow=localhost',
                  'InaccessiblePaths=' + str(STATE / 'authority') + ' ' + str(STATE / 'memory')
                  + ' ' + str(STATE / 'postgres') + ' ' + str(WITNESS) + ' '
                  + str(CONF / 'authority') + ' ' + str(CONF / 'memory') + ' '
                  + str(CONF / 'postgres') + ' ' + str(RUN / 'authority') + ' ' + str(RUN / 'postgres')]
        writes = [STATE / 'app']
        budget = ('2G', 75, 64)
    elif kind == 'authority':
        extra += ['RestrictAddressFamilies=AF_UNIX', 'PrivateNetwork=yes',
                  'InaccessiblePaths=' + str(STATE / 'postgres') + ' ' + str(CONF / 'memory')]
        writes = [STATE / 'authority', WITNESS, RUN / 'authority']
        budget = ('768M', 25, 32)
    else:
        extra += ['RestrictAddressFamilies=AF_UNIX', 'PrivateNetwork=yes',
                  'InaccessiblePaths=' + str(STATE / 'authority') + ' ' + str(WITNESS)
                  + ' ' + str(STATE / 'postgres') + ' ' + str(CONF / 'authority')]
        writes = [STATE / 'memory', RUN / 'memory']
        budget = ('1G', 25, 32)
    return common_unit(kind, extra, writes, *budget)

def postgres_files():
    return {
        'postgresql.conf': ("listen_addresses = ''\nport = 55432\n"
            f"unix_socket_directories = '{RUN / 'postgres'}'\n"
            "unix_socket_group = 'prime-memory'\nunix_socket_permissions = 0770\n"
            f"hba_file = '{CONF / 'postgres/pg_hba.conf'}'\n"
            f"ident_file = '{CONF / 'postgres/pg_ident.conf'}'\n"
            "ssl = off\nmax_connections = 12\n"
            "shared_buffers = '256MB'\nwork_mem = '4MB'\nmaintenance_work_mem = '64MB'\n"
            "fsync = on\nfull_page_writes = on\nsynchronous_commit = on\n"
            "logging_collector = off\nlog_statement = 'none'\nlog_min_error_statement = 'panic'\n"),
        'pg_hba.conf': ('local all postgres peer\nlocal aukora_prime_synthetic prime_memory peer map=prime_memory_role\n'
                        'local all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n'),
        'pg_ident.conf': 'prime_memory_role prime-memory prime_memory\n',
    }

def shared_layout():
    """H's disjoint parent/account scope; no PostgreSQL child or configuration."""
    dirs = [(STATE, 'root', 'root', '0711'), (RUN, 'root', 'root', '0711'),
            (WITNESS.parent, 'root', 'root', '0755'),
            (WITNESS, 'prime-authority', 'prime-authority', '0700')]
    dirs += [(STATE / k, 'prime-' + k, 'prime-' + k, '0700') for k in ['app', 'authority', 'memory']]
    dirs += [(RUN / 'authority', 'prime-authority', 'prime-authority-ipc', '0710'),
             (RUN / 'memory', 'prime-memory', 'prime-memory-ipc', '0710')]
    return [dict(path=str(p), owner=u, group=g, mode=m) for p, u, g, m in dirs]

def code_layout():
    dirs = [(CODE, 'root', 'root', '0755'), (CODE / 'tools', 'root', 'root', '0755'),
            (CODE / 'releases', 'root', 'root', '0755'), (CONF, 'root', 'root', '0755')]
    dirs += [(CONF / k, 'root', 'prime-' + k, '0750') for k in ['authority', 'memory']]
    # PG operator exclusively materializes its config, data and socket children.
    return [dict(path=str(p), owner=u, group=g, mode=m) for p, u, g, m in dirs]

def layout():
    return shared_layout() + code_layout() + [
        dict(path=str(STATE / 'postgres'), owner='postgres', group='postgres', mode='0700'),
        dict(path=str(RUN / 'postgres'), owner='postgres', group='prime-memory', mode='0750'),
        dict(path=str(CONF / 'postgres'), owner='root', group='postgres', mode='0750')]

def expectations(spec, texts):
    node = str(CODE / 'tools/node')
    files = [dict(path=node, owner='root', group='root', mode='0755', sha256=spec['node_sha256'])]
    files.append(dict(path=str(CONF / 'preview-deployment.json'), owner='root', group='root', mode='0644', sha256=spec['deployment_manifest_sha256']))
    for kind, row in spec['services'].items():
        entry_mode = '0755' if (Path(spec['release_source']) / row['entrypoint']).stat().st_mode & 0o111 else '0644'
        entry = dict(path=str(release_path(spec) / row['entrypoint']), owner='root', group='root', mode=entry_mode, sha256=row['sha256'])
        prior = [r for r in files if r['path'] == entry['path']]
        need(not prior or prior == [entry], 'CONFLICTING_ENTRYPOINT_PIN')
        if not prior: files.append(entry)
        if 'config_source' in row:
            files.append(dict(path=str(CONF / kind / 'config.mjs'), owner='root',
                              group='prime-' + kind, mode='0440', sha256=row['config_sha256']))
    for name, text in postgres_files().items():
        files.append(dict(path=str(CONF / 'postgres' / name), owner='root', group='postgres', mode='0640', sha256=sha(text.encode())))
    subjects = []
    for kind in ['app', 'memory']:
        deny = [node, str(release_path(spec)), str(CONF), str(STATE), str(WITNESS.parent),
                str(STATE / 'authority'), str(WITNESS), str(CONF / 'authority'), str(RUN / 'authority')]
        # Memory is the authorized authority-channel client; it can traverse but never write the parent.
        traverse = [str(RUN / 'memory')]
        denied_traverse = [str(STATE / 'authority'), str(WITNESS), str(CONF / 'authority')]
        if kind == 'app':
            denied_traverse += [str(RUN / 'authority'), str(RUN / 'postgres'), str(STATE / 'postgres')]
        else:
            traverse += [str(RUN / 'authority'), str(RUN / 'postgres')]
        subjects.append(dict(user='prime-' + kind, group='prime-' + kind,
            supplementary_groups=SUPPLEMENTARY[kind], denied_write=deny + [str(RUN / 'memory'), str(RUN / 'postgres')],
            denied_read=[str(CONF / 'authority/config.mjs')], denied_traverse=denied_traverse, allowed_traverse=traverse))
    # Memory owns its server directory and must be able to create its own socket there.
    subjects[1]['denied_write'].remove(str(RUN / 'memory'))
    for kind in ['authority', 'postgres']:
        user = 'postgres' if kind == 'postgres' else 'prime-' + kind
        subjects.append(dict(user=user, group=user, supplementary_groups=SUPPLEMENTARY[kind],
            denied_write=[node, str(release_path(spec)), str(CONF), str(STATE)],
            denied_read=[str(CONF / 'memory/config.mjs')] if kind == 'postgres' else [],
            denied_traverse=[], allowed_traverse=[str(RUN / kind)]))
    sockets = [dict(path=str(RUN / 'authority/authority.sock'), owner='prime-authority', group='prime-authority-ipc', mode='0660', allowed_users=['prime-memory'], denied_users=['prime-app']),
               dict(path=str(RUN / 'memory/memory.sock'), owner='prime-memory', group='prime-memory-ipc', mode='0660', allowed_users=['prime-app'], denied_users=['prime-authority']),
               dict(path=str(RUN / 'postgres/.s.PGSQL.55432'), owner='postgres', group='prime-memory', mode='0770', allowed_users=['prime-memory'], denied_users=['prime-app'])]
    units = [dict(name=UNITS[k], sha256=sha(text.encode()), user='postgres' if k == 'postgres' else 'prime-' + k,
                  group='postgres' if k == 'postgres' else 'prime-' + k, supplementary_groups=SUPPLEMENTARY[k]) for k, text in texts.items()]
    return dict(schema='prime-pilot-privileges-v1', source_only=True, release_root=str(release_path(spec)),
                directories=layout() + [dict(path=str(release_path(spec)), owner='root', group='root', mode='0755')],
                files=files, subjects=subjects, sockets=sockets, units=units)

def render(spec, out):
    # task40 ca382593 adds the root0440 guard, but the PG process's proposed
    # prime-memory group would read D private material. No emission until resolved.
    raise Refusal(WORKER_CONFIG_HOLD)

def render_after_contract_release(spec, out):
    """Held implementation draft. Group confidentiality agreement still required."""
    raise Refusal(WORKER_CONFIG_HOLD)
    verify_inputs(spec)
    out = Path(out)
    need(not out.exists(), 'RENDER_OUTPUT_MUST_BE_NEW')
    out.mkdir(parents=True, mode=0o700)
    texts = {k: unit(k, spec) for k in UNITS}
    for kind, text in texts.items():
        (out / UNITS[kind]).write_text(text)
    for name, text in postgres_files().items():
        (out / name).write_text(text)
    (out / 'peer-role.sql').write_text(peer_role_sql())
    data = json_bytes(expectations(spec, texts))
    (out / 'expected-privileges.json').write_bytes(data)
    (out / 'deployment.json').write_bytes(json_bytes(spec))
    return dict(status='RENDERED_SOURCE', out=str(out), expected_privileges_sha256=sha(data),
                runtime_qualification='PENDING', services_started=False, autostart=False)

def command(argv, *, data=None, timeout=120):
    result = subprocess.run(argv, input=data, capture_output=True, env=ENV, timeout=timeout)
    need(result.returncode == 0, 'COMMAND_REFUSED:' + Path(argv[0]).name)
    return result.stdout

def linux_root():
    need(sys.platform == 'linux' and os.geteuid() == 0, 'DESIGNATED_OPERATOR_LINUX_ROOT_ONLY')
    text = Path('/etc/os-release').read_text()
    need('ID=ubuntu\n' in text and 'VERSION_ID="24.04"' in text, 'EXACT_UBUNTU_24_04_REQUIRED')

def root_parents(path):
    for p in [Path(path).parent, *Path(path).parent.parents]:
        st = p.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'UNSAFE_ROOT_PARENT')

def exclusive(path, data, mode, uid=0, gid=0):
    path = Path(path); root_parents(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid); os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(data); handle.flush(); os.fsync(fd)
    finally:
        os.close(fd)

def compatible_create_policy(data):
    try:
        lines = data.decode('ascii').splitlines()
    except UnicodeError:
        return False
    live = [s for s in lines if s.strip() and not s.lstrip().startswith('#')]
    return len(live) == 1 and re.fullmatch(r'[ \t]*create_main_cluster[ \t]*=[ \t]*false[ \t]*(?:#.*)?', live[0]) is not None

def package_plan(spec):
    need(set(spec) == {'schema', 'packages', 'reviewed_apt_config_sha256'}, 'CLOSED_PACKAGE_PLAN_REQUIRED')
    need(spec['schema'] == 'prime-pilot-packages-v1' and len(spec['packages']) == 8, 'EIGHT_APPROVED_DEBS_REQUIRED')
    digest_value(spec['reviewed_apt_config_sha256'])
    seen = set()
    for row in spec['packages']:
        need(set(row) == {'name', 'version', 'path', 'sha256', 'reviewed_control_sha256'}, 'CLOSED_DEB_PIN_REQUIRED')
        need(row['name'] in PACKAGES and row['version'] == PACKAGES[row['name']] and row['name'] not in seen, 'UNAPPROVED_PACKAGE')
        seen.add(row['name']); digest_value(row['sha256']); digest_value(row['reviewed_control_sha256'])
        need(Path(row['path']).is_absolute() and Path(row['path']).suffix == '.deb', 'ABSOLUTE_REVIEWED_DEB_REQUIRED')
    need(seen == set(PACKAGES), 'EXACT_PACKAGE_CLOSURE_REQUIRED')
    return spec

def package_preflight(spec):
    linux_root(); package_plan(spec)
    need(sha(command(['/usr/bin/apt-config', 'dump'])) == spec['reviewed_apt_config_sha256'], 'APT_HOOK_REVIEW_PIN_REQUIRED')
    for row in spec['packages']:
        regular(row['path'], row['sha256'])
        fields = command(['/usr/bin/dpkg-deb', '-f', row['path'], 'Package', 'Version']).decode().splitlines()
        need(fields == ['Package: ' + row['name'], 'Version: ' + row['version']], 'DEB_METADATA_MISMATCH')
        need(sha(command(['/usr/bin/dpkg-deb', '--ctrl-tarfile', row['path']])) == row['reviewed_control_sha256'], 'DEB_CONTROL_REVIEW_PIN_REQUIRED')
        q = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}', row['name']], capture_output=True, env=ENV)
        need(q.returncode != 0 or q.stdout.strip() != b'installed', 'EIGHT_NEW_ONLY_NO_EXISTING_PACKAGE_CHANGE')
    simulation = command(['/usr/bin/apt-get', '--simulate', '--no-install-recommends', '--no-upgrade', '--no-remove',
                          'install', *[row['path'] for row in spec['packages']]]).decode()
    need('0 upgraded, 8 newly installed, 0 to remove' in simulation, 'APT_SIMULATION_SCOPE_CHANGED')
    installed = re.findall(r'^Inst ([a-z0-9+.-]+)(?:\:[a-z0-9]+)? \(([^ ]+)', simulation, re.M)
    need(dict(installed) == PACKAGES and len(installed) == 8, 'APT_SIMULATION_PACKAGE_OR_VERSION_CHANGED')
    need(not Path('/usr/sbin/policy-rc.d').exists() and not Path('/usr/sbin/policy-rc.d').is_symlink(), 'EXISTING_STARTUP_POLICY_UNREVIEWED_DO_NOT_OVERWRITE')
    need(not Path('/etc/postgresql/16/main').exists(), 'EXISTING_MAIN_CLUSTER_OUTSIDE_NEW_SCOPE')
    policy = Path('/etc/postgresql-common/createcluster.conf')
    if policy.exists() or policy.is_symlink():
        root_parents(policy)
        st = policy.lstat()
        need(st.st_uid == 0 and not st.st_mode & 0o022 and compatible_create_policy(regular(policy)), 'EXISTING_CLUSTER_POLICY_UNSAFE_DO_NOT_OVERWRITE')
    return dict(status='PREFLIGHT_SOURCE_GUARDS_READY', packages=8, runtime_qualification='PENDING')

def install_packages(spec):
    package_preflight(spec)
    # apt/dpkg must never reopen a caller-writable reviewed file. Stage verified
    # bytes in a fresh root-owned directory, then validate/use only those paths.
    stage_parent = Path('/var/lib')
    root_parents(stage_parent / 'unused')
    stage = Path(tempfile.mkdtemp(prefix='.aukora-prime-approved-debs-', dir=stage_parent))
    os.chmod(stage, 0o755)
    staged = json.loads(json.dumps(spec))
    for row in staged['packages']:
        data = regular(row['path'], row['sha256'])
        target = stage / (row['name'] + '.deb')
        exclusive(target, data, 0o644)
        row['path'] = str(target)
    package_preflight(staged)
    policy = Path('/etc/postgresql-common/createcluster.conf')
    parent = policy.parent
    if not parent.exists():
        root_parents(parent); parent.mkdir(mode=0o755)
    if not policy.exists():
        exclusive(policy, CREATE_POLICY, 0o644)
    preserved = regular(policy); preserved_sha = sha(preserved)
    guard = Path('/usr/sbin/policy-rc.d')
    exclusive(guard, POLICY, 0o755)
    identity = guard.lstat()
    success = False
    try:
        # Exact reviewed local files only: no apt update/download, extra dependency or upgrade.
        command(['/usr/bin/apt-get', '--yes', '--no-download', '--no-install-recommends', '--no-upgrade', '--no-remove',
                 '-o', 'Dpkg::Options::=--force-confold', 'install', *[r['path'] for r in staged['packages']]], timeout=600)
        need(sha(regular(policy)) == preserved_sha, 'CLUSTER_POLICY_CHANGED_RECONCILIATION_REQUIRED')
        need(not Path('/etc/postgresql/16/main').exists(), 'UNEXPECTED_MAIN_CLUSTER_DO_NOT_STOP_OR_REMOVE')
        for name, version in PACKAGES.items():
            need(command(['/usr/bin/dpkg-query', '-W', '-f=${Version}', name]).decode() == version, 'INSTALLED_VERSION_MISMATCH')
        success = True
    finally:
        st = guard.lstat()
        need((st.st_dev, st.st_ino, st.st_uid, st.st_mode & 0o777) ==
             (identity.st_dev, identity.st_ino, 0, 0o755) and regular(guard) == POLICY,
             'GUARD_IDENTITY_CHANGED_LEAVE_FOR_OPERATOR')
        # On any partial/uncertain install, retain the owned guard for operator
        # reconciliation. Never enable an automatic retry or start a service.
        if success:
            guard.unlink()
    return dict(status='PACKAGES_INSTALLED_GUARDED', services_started=False,
                retained_reviewed_package_stage=str(stage),
                existing_service_transitions='REQUIRE_OPERATOR_BEFORE_AFTER_EVIDENCE', qualification='PENDING')

def postgres_identity():
    import pwd, grp
    account = pwd.getpwnam('postgres')
    need(account.pw_uid == 113 and account.pw_gid == 114 and grp.getgrnam('postgres').gr_gid == 114,
         'REPORTED_POSTGRES_IDENTITY_CHANGED_DO_NOT_MUTATE')
    return account

def check_directory(row):
    import pwd, grp
    p = Path(row['path']); st = p.lstat()
    need(stat.S_ISDIR(st.st_mode) and not p.is_symlink() and p.resolve(strict=True) == p
         and (st.st_uid, st.st_gid, st.st_mode & 0o7777) ==
         (pwd.getpwnam(row['owner']).pw_uid, grp.getgrnam(row['group']).gr_gid, int(row['mode'], 8)),
         'DIRECTORY_OWNERSHIP_CONFLICT_DO_NOT_REPAIR')

def create_directory(row):
    import pwd, grp
    p = Path(row['path']); root_parents(p)
    p.mkdir(mode=0o700)  # Exclusive; no intermediate permissive directory.
    os.chown(p, pwd.getpwnam(row['owner']).pw_uid, grp.getgrnam(row['group']).gr_gid)
    os.chmod(p, int(row['mode'], 8)); check_directory(row)

def provision_layout():
    import pwd, grp
    linux_root(); postgres_identity()
    # NSS assigns unused system IDs; output records actual numbers, never presumed worker IDs.
    for name in ['prime-app', 'prime-authority', 'prime-memory']:
        try: pwd.getpwnam(name)
        except KeyError: pass
        else: raise Refusal('IDENTITY_EXISTS_NO_ACCOUNT_MUTATION')
    for name in GROUPS:
        try: grp.getgrnam(name)
        except KeyError: pass
        else: raise Refusal('GROUP_EXISTS_NO_GROUP_MUTATION')
    for p in [STATE, WITNESS.parent, RUN]:
        need(not p.exists() and not p.is_symlink(), 'OWNED_ROOT_MUST_BE_NEW')
        root_parents(p)
    for name in GROUPS:
        command(['/usr/sbin/groupadd', '--system', name])
    for kind in ['app', 'authority', 'memory']:
        name = 'prime-' + kind
        command(['/usr/sbin/useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin',
                 '--home-dir', str(STATE / kind), '--gid', name, '--groups', ','.join(SUPPLEMENTARY[kind]), '--password', '!', name])
    for row in shared_layout(): create_directory(row)
    uid_map = {name: pwd.getpwnam(name).pw_uid for name in ['prime-app', 'prime-authority', 'prime-memory', 'postgres']}
    gid_map = {name: grp.getgrnam(name).gr_gid for name in GROUPS + ['postgres']}
    identities = dict(schema='prime-pilot-assigned-identities-v1', uid=uid_map, gid=gid_map,
        nss_supplementary={name: [grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name, pwd.getpwnam(name).pw_gid)
                                  if gid != pwd.getpwnam(name).pw_gid] for name in uid_map})
    exclusive(STATE / 'assigned-identities.json', json_bytes(identities), 0o644)
    need(not (STATE / 'postgres').exists() and not (RUN / 'postgres').exists(), 'PG_OPERATOR_CHILD_SCOPE_CONFLICT')
    return dict(status='PRIME_PARENT_UID_LAYOUT_CREATED_NOT_STARTED', **identities,
                pg_operator_children=[str(STATE / 'postgres'), str(RUN / 'postgres')],
                postgres_account_changed=False, units_installed=False, services_started=False, autostart=False,
                partial_failure='RECONCILE_ONLY_NO_AUTOMATIC_RETRY', qualification='PENDING')

def install_code(spec):
    """H only; separate from the completed shared layout and PG operator scope."""
    raise Refusal(WORKER_CONFIG_HOLD)
    import pwd, grp
    linux_root(); verify_inputs(spec); postgres_identity()
    for row in shared_layout(): check_directory(row)
    for p in [CODE, CONF]:
        need(not p.exists() and not p.is_symlink(), 'CODE_CONFIG_ROOT_MUST_BE_NEW')
        root_parents(p)
    for row in code_layout(): create_directory(row)
    exclusive(CODE / 'tools/node', regular(spec['node_source'], spec['node_sha256']), 0o755)
    release = release_path(spec)
    shutil.copytree(spec['release_source'], release, symlinks=True)
    for parent, dirs, names in os.walk(release, followlinks=False):
        os.chown(parent, 0, 0); os.chmod(parent, 0o755)
        for name in dirs + names:
            p = Path(parent) / name
            if p.is_symlink(): os.lchown(p, 0, 0)
            elif p.is_file():
                mode = 0o755 if p.stat().st_mode & 0o111 else 0o644
                os.chown(p, 0, 0); os.chmod(p, mode)
    need(full_digest(release) == spec['release_digest'], 'COPIED_RELEASE_PIN_MISMATCH')
    for kind, row in spec['services'].items():
        if 'config_source' in row:
            # Proposed task40 root0440 contract. Held until actual guard pin and
            # PG/memory shared-group confidentiality conflict are resolved.
            exclusive(CONF / kind / 'config.mjs', regular(row['config_source'], row['config_sha256']), 0o440,
                      0, grp.getgrnam('prime-' + kind).gr_gid)
    exclusive(CONF / 'preview-deployment.json', regular(spec['deployment_manifest_source'], spec['deployment_manifest_sha256']), 0o644)
    return dict(status='CODE_CONFIG_INSTALLED_NOT_STARTED', ipc_configs='REQUIRE_EXACT_ASSIGNED_IDS_AND_PRIVATE_IMPORT_CLOSURE',
                pg_children_changed=False, authority_store_setup='PENDING_C_REVIEWED_SETUP_API',
                app_bridge_config='PENDING_H_BOOT_MANIFEST_INTERFACE_AND_CLIENT_JOIN', autostart=False)

def install_units(spec):
    raise Refusal(WORKER_CONFIG_HOLD)
    linux_root(); verify_inputs(spec)
    need(full_digest(release_path(spec)) == spec['release_digest'], 'INSTALLED_RELEASE_PIN_MISMATCH')
    for name in UNITS.values():
        need(not Path('/etc/systemd/system', name).exists() and not Path('/etc/systemd/system', name).is_symlink(), 'UNIT_EXISTS_DO_NOT_REPLACE')
        need(not Path('/etc/systemd/system', name + '.d').exists(), 'UNIT_DROPINS_UNAPPROVED')
    for kind, name in UNITS.items():
        exclusive(Path('/etc/systemd/system', name), unit(kind, spec).encode(), 0o644)
    command(['/usr/bin/systemctl', 'daemon-reload'])
    return dict(status='UNITS_INSTALLED_STATIC', services_started=False, enabled=False,
                missing=['operator-owned private PG initialization and peer role', 'assigned-ID IPC configs',
                         'C reviewed setup API', 'H boot/manifest join', 'synthetic qualification'])

def peer_role_sql():
    """PG operator review text only. No connection, role creation or blind retry."""
    return ("CREATE ROLE prime_memory LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 6 PASSWORD NULL;\n"
            "CREATE DATABASE aukora_prime_synthetic OWNER prime_memory;\n"
            "REVOKE ALL ON DATABASE aukora_prime_synthetic FROM PUBLIC;\n"
            "\\connect aukora_prime_synthetic\nREVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
            "ALTER SCHEMA public OWNER TO prime_memory;\n")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=['plan', 'render', 'package-preflight', 'install-packages', 'provision-layout', 'install-code', 'install-units'])
    p.add_argument('--spec'); p.add_argument('--expected-spec-sha256'); p.add_argument('--out')
    p.add_argument('--expected-artifact-sha256')
    args = p.parse_args()
    if args.phase == 'plan':
        value = dict(status='SOURCE_PLAN', instance='OPERATOR_INSTANCE_REQUIRED', os='Ubuntu24.04',
            packages=PACKAGES, units=UNITS, source_only=True,
            mutations_by={'PG':'exclusive Nebius operator designated PostgreSQL operator','app_C_D_layout':'H coordinates with PG operator'},
            package_status='OPERATOR_REPORTED_INSTALLED_16_15_NOT_REVERIFIED_G',
            worker_config_guard_source='ca382593545c9877e0fce4f19e406c90f7a84027',
            blocked=[WORKER_CONFIG_HOLD, 'worker/app entrypoint and config pins',
                     'assigned UID/GID-bound config', 'protected Prime-contained pg Pool import',
                     'operator passwordless peer role setup', 'C reviewed authority-store setup API', 'H boot manifest API pin'],
            autostart=False, services_started=False, OpenShell='HELD', Docker='HELD', paid_inference=False)
    elif args.phase == 'provision-layout':
        need(args.expected_artifact_sha256, 'EXTERNALLY_PINNED_ARTIFACT_REQUIRED')
        regular(__file__, args.expected_artifact_sha256)
        value = provision_layout()
    else:
        need(args.spec and args.expected_spec_sha256, 'EXTERNALLY_PINNED_SPEC_REQUIRED')
        spec = json.loads(regular(args.spec, args.expected_spec_sha256), object_pairs_hook=pairs)
        if args.phase == 'render':
            need(args.out, 'NEW_RENDER_OUTPUT_REQUIRED'); value = render(spec, args.out)
        elif args.phase == 'package-preflight': value = package_preflight(spec)
        elif args.phase == 'install-packages': value = install_packages(spec)
        elif args.phase == 'install-code': value = install_code(spec)
        elif args.phase == 'install-units': value = install_units(spec)
        else: raise Refusal('UNSUPPORTED_PHASE')
    print(json.dumps(value, sort_keys=True))

if __name__ == '__main__':
    try: main()
    except (Refusal, OSError, ValueError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Refusal) else type(error).__name__
        print(json.dumps({'status': 'REFUSED', 'reason': reason, 'running_qualification': 'PENDING'}))
        sys.exit(1)
