#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""H-only source artifact: fresh Prime parents and no-login identities, never PG or services.
The trusted outer operator must stage and verify this file before privileged execution.
The in-process pin is only a drift guard, never an independent code identity proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

STATE = Path('/var/lib/aukora-prime')
RUN = Path('/run/aukora-prime')
WITNESS = Path('/var/lib/aukora-prime-witness/pilot')
GROUPS = ['prime-app', 'prime-authority', 'prime-memory', 'prime-authority-ipc', 'prime-memory-ipc', 'prime-pg-socket']
SUPPLEMENTARY = {'app': ['prime-memory-ipc'], 'authority': ['prime-authority-ipc'],
                 'memory': ['prime-authority-ipc', 'prime-memory-ipc', 'prime-pg-socket']}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
HASH = re.compile(r'[0-9a-f]{64}')

class Refusal(ValueError):
    pass

def need(condition, reason):
    if not condition:
        raise Refusal(reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def digest_value(value):
    need(isinstance(value, str) and HASH.fullmatch(value), 'EXACT_SHA256_REQUIRED')
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

def shared_layout():
    """H's disjoint parent/account scope; no PostgreSQL child or configuration."""
    dirs = [(STATE, 'root', 'root', '0711'), (RUN, 'root', 'root', '0711'),
            (WITNESS.parent, 'root', 'root', '0755'),
            (WITNESS, 'prime-authority', 'prime-authority', '0700')]
    dirs += [(STATE / k, 'prime-' + k, 'prime-' + k, '0700') for k in ['app', 'authority', 'memory']]
    dirs += [(RUN / 'authority', 'prime-authority', 'prime-authority-ipc', '0710'),
             (RUN / 'memory', 'prime-memory', 'prime-memory-ipc', '0710')]
    return [dict(path=str(p), owner=u, group=g, mode=m) for p, u, g, m in dirs]

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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['plan', 'provision-layout'])
    parser.add_argument('--expected-artifact-sha256')
    args = parser.parse_args()
    if args.phase == 'plan':
        value = dict(status='SOURCE_PARENT_UID_PLAN', source_only=True, directories=shared_layout(),
                     groups=GROUPS, supplementary_groups=SUPPLEMENTARY, postgres_account_changed=False,
                     postgres_expected_uid=113, postgres_expected_gid=114,
                     pg_operator_children=[str(STATE / 'postgres'), str(RUN / 'postgres')],
                     units_installed=False, services_started=False, autostart=False, qualification='PENDING')
    else:
        need(args.expected_artifact_sha256, 'EXTERNALLY_PINNED_ARTIFACT_REQUIRED')
        regular(__file__, args.expected_artifact_sha256)
        value = provision_layout()
    print(json.dumps(value, sort_keys=True))

if __name__ == '__main__':
    try: main()
    except (Refusal, OSError, ValueError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Refusal) else type(error).__name__
        print(json.dumps(dict(status='REFUSED', reason=reason, qualification='PENDING',
                             automatic_retry=False, partial_effects='RECONCILE_IF_MUTATION_BEGAN')))
        sys.exit(1)
