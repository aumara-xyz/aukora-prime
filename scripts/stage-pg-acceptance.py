#!/usr/bin/env python3
"""Manifest-bound source staging only; never runs Node, PostgreSQL, or services."""
import argparse, hashlib, json, os, pathlib, re, stat, sys

BASE = pathlib.Path('/opt/aukora-prime-acceptance')
PACKAGE = b'{"private":true,"type":"module"}\n'
VERSIONS = dict(zip(('pg','pg-cloudflare','pg-connection-string','pg-int8','pg-pool','pg-protocol','pg-types','pgpass','postgres-array','postgres-bytea','postgres-date','postgres-interval','split2','xtend'), ('8.16.3','1.4.1','2.14.1','1.0.1','3.14.0','1.16.1','2.2.0','1.0.5','2.0.0','1.0.1','1.0.7','1.2.0','4.2.0','4.0.2')))

def fail(reason):
    raise ValueError(reason)

def closed(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys): fail('CLOSED_SCHEMA_REQUIRED')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def pairs(items):
    result = {}
    for key, value in items:
        if key in result: fail('DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or value.startswith('//') or str(pathlib.Path(value)) != value or any(p in ('.','..') for p in value.split('/')): fail('CANONICAL_ABSOLUTE_PATH_REQUIRED')
    return pathlib.Path(value)

def ancestors(path, protected=False):
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode): fail('SYMLINK_REFUSED')
        if protected and (info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022): fail('PROTECTED_ROOT_ANCESTOR_REQUIRED')
        if item != path and not stat.S_ISDIR(info.st_mode): fail('DIRECTORY_ANCESTOR_REQUIRED')

def read_regular(path, limit=256 * 1024 * 1024):
    ancestors(path)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = next_directory
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally: os.close(directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (limit is not None and info.st_size > limit): fail('BOUNDED_REGULAR_FILE_REQUIRED')
        with os.fdopen(fd, 'rb', closefd=False) as stream: data = stream.read()
        if len(data) != info.st_size: fail('INPUT_CHANGED_DURING_READ')
        return data, info
    finally: os.close(fd)

def load_manifest(path, expected):
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected): fail('MANIFEST_PIN_REQUIRED')
    raw, _ = read_regular(absolute(str(path)), 4 * 1024 * 1024)
    if digest(raw) != expected: fail('MANIFEST_HASH_MISMATCH')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=lambda _: fail('INVALID_JSON_NUMBER'))

def plan(manifest):
    closed(manifest, ('version','kind','source_commit','source_root','pg_root','node','node_license','files'))
    if type(manifest['version']) is not int or manifest['version'] != 1 or manifest['kind'] != 'prime-pg-acceptance-input/v1' or not isinstance(manifest['source_commit'], str) or not re.fullmatch('[0-9a-f]{40}', manifest['source_commit']): fail('MANIFEST_VERSION_OR_COMMIT_INVALID')
    roots = {key:absolute(manifest[key]) for key in ('source_root','pg_root','node','node_license')}
    rows = manifest['files']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10000: fail('BOUNDED_FILE_LIST_REQUIRED')
    records, seen = [], set()
    for row in rows:
        closed(row, ('source','path','bytes','sha256','executable'))
        name = row['path']
        if not isinstance(name, str) or str(pathlib.PurePosixPath(name)) != name or name.startswith('/') or '\\' in name or any(ord(c) < 32 for c in name) or any(p in ('.','..','.git','.env','node_modules') for p in name.split('/')[3:]): fail('DESTINATION_PATH_INVALID')
        parts = name.split('/')
        if name in ('tools/node','tools/LICENSE'):
            expected_source = roots['node' if name == 'tools/node' else 'node_license']
        elif parts[:2] == ['source','packages'] and len(parts) > 3 and parts[2] in ('memory','contracts'):
            expected_source = roots['source_root'].joinpath(*parts[1:])
        elif parts[:2] == ['source','node_modules'] and len(parts) > 3 and parts[2] in VERSIONS:
            expected_source = roots['pg_root'].joinpath(*parts[1:])
        else: fail('DESTINATION_SCOPE_REFUSED')
        if absolute(row['source']) != expected_source or name in seen: fail('SOURCE_BINDING_OR_DUPLICATE_INVALID')
        seen.add(name)
        if type(row['bytes']) is not int or not 0 <= row['bytes'] <= 256 * 1024 * 1024 or type(row['executable']) is not bool or not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256']): fail('FILE_METADATA_INVALID')
        data, info = read_regular(expected_source)
        if len(data) != row['bytes'] or digest(data) != row['sha256'] or bool(info.st_mode & 0o111) != row['executable']: fail('SOURCE_BYTES_OR_MODE_MISMATCH')
        if name == 'tools/node' and not row['executable']: fail('NODE_EXECUTABLE_REQUIRED')
        if name == 'tools/LICENSE' and row['executable']: fail('LICENSE_EXECUTABLE_REFUSED')
        if name.startswith('source/node_modules/') and name.endswith('/package.json') and len(parts) == 4:
            metadata = json.loads(data.decode('utf-8'), object_pairs_hook=pairs)
            if metadata.get('name') != parts[2] or metadata.get('version') != VERSIONS[parts[2]]: fail('LOCKED_PG_METADATA_MISMATCH')
        records.append({key:row[key] for key in ('path','bytes','sha256','executable')})
    required = {'tools/node','tools/LICENSE','source/packages/memory/package.json','source/packages/contracts/package.json','source/packages/memory/src/index.mjs','source/packages/contracts/src/runtime.mjs','source/packages/memory/test/operator-postgres.mjs'} | {'source/node_modules/'+p+'/package.json' for p in VERSIONS}
    if not required <= seen: fail('REQUIRED_CLOSURE_FILE_MISSING')
    for name in seen:
        if any(str(p) in seen for p in pathlib.PurePosixPath(name).parents): fail('FILE_DIRECTORY_COLLISION')
    records.append(dict(path='source/package.json', bytes=len(PACKAGE), sha256=digest(PACKAGE), executable=False))
    records.sort(key=lambda r:r['path'])
    pin = digest(b'aukora-prime:pg-acceptance-source:v1\n' + json.dumps(records, sort_keys=True, separators=(',',':'), ensure_ascii=True).encode())
    return dict(status='PLANNED', qualification='PENDING', source_commit=manifest['source_commit'], source_closure_sha256=pin, pg_version=VERSIONS['pg'], node_sha256=next(r['sha256'] for r in records if r['path']=='tools/node'), deployment_root=str(BASE/pin), source_root=str(BASE/pin/'source'), node=str(BASE/pin/'tools/node'), records=records)

def copy_new(manifest, planned, destination):
    """Explicit fixture helper; production entry below enforces Linux/root/fixed path."""
    destination.mkdir(mode=0o755)  # Never replace, repair, or resume an existing attempt.
    directories = {destination}
    sources = {row['path']:absolute(row['source']) for row in manifest['files']}
    for record in planned['records']:
        target = destination / record['path']
        for parent in reversed(target.parents):
            if destination not in (parent, *parent.parents) or parent in directories: continue
            parent.mkdir(mode=0o755)
            directories.add(parent)
        data, info = (PACKAGE, None) if record['path']=='source/package.json' else read_regular(sources[record['path']])
        if len(data) != record['bytes'] or digest(data) != record['sha256']: fail('COPY_INPUT_DRIFT')
        if info is not None and bool(info.st_mode & 0o111)!=record['executable']: fail('COPY_INPUT_DRIFT')
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if record['executable'] else 0o644)
        try:
            os.fchmod(fd, 0o755 if record['executable'] else 0o644)
            with os.fdopen(fd,'wb',closefd=False) as stream: stream.write(data); stream.flush(); os.fsync(fd)
        finally: os.close(fd)
    verify_copy(planned, destination)
    for parent in directories:
        os.chmod(parent, 0o755)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

def verify_copy(planned, destination):
    for record in planned['records']:
        data, info = read_regular(destination / record['path'])
        if len(data)!=record['bytes'] or digest(data)!=record['sha256'] or stat.S_IMODE(info.st_mode)!=(0o755 if record['executable'] else 0o644): fail('COPIED_BYTES_OR_MODE_MISMATCH')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    manifest = load_manifest(args.manifest, args.expected_manifest_sha256)
    planned = plan(manifest)  # All preflight refusals precede writes.
    if not args.plan:
        if sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0: fail('LINUX_ROOT_STAGING_REQUIRED')
        ancestors(BASE.parent, protected=True)
        if BASE.exists():
            ancestors(BASE, protected=True)
            if not BASE.is_dir() or stat.S_IMODE(BASE.stat().st_mode)!=0o755: fail('PROTECTED_BASE_MODE_REQUIRED')
        else: BASE.mkdir(mode=0o755); BASE.chmod(0o755)
        copy_new(manifest, planned, pathlib.Path(planned['deployment_root']))
        ancestors(pathlib.Path(planned['deployment_root']), protected=True)
        for row in planned['records']: ancestors(pathlib.Path(planned['deployment_root'])/row['path'], protected=True)
        planned['status'] = 'STAGED'
    print(json.dumps({k:v for k,v in planned.items() if k!='records'}, sort_keys=True))

if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, UnicodeError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error), qualification='PENDING')), file=sys.stderr)
        sys.exit(1)
