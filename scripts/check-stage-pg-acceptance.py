#!/usr/bin/env python3
"""Disposable fixture checks; does not exercise root deployment or PostgreSQL."""
import copy, importlib.util, json, os, pathlib, stat, subprocess, sys, tempfile

sys.dont_write_bytecode = True
script = pathlib.Path(__file__).with_name('stage-pg-acceptance.py')
spec = importlib.util.spec_from_file_location('stage_pg', script)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
checks = 0

def expect_refused(reason, action):
    global checks
    try: action()
    except (ValueError, OSError) as error:
        assert reason in str(error), (reason, str(error))
    else: raise AssertionError('expected refusal: '+reason)
    checks += 1

with tempfile.TemporaryDirectory(prefix='prime-stage-pg-') as tmp:
    root = pathlib.Path(tmp).resolve()
    source, pg = root/'input', root/'pg'
    source.mkdir(); pg.mkdir()
    node, license_path = root/'node', root/'LICENSE'
    node.write_bytes(b'fixture-node-not-executed\n'); node.chmod(0o755)
    license_path.write_bytes(b'fixture official-license stand-in\n'); license_path.chmod(0o644)
    rows = []
    def row(source_path, path, data, executable=False):
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(data); source_path.chmod(0o755 if executable else 0o644)
        rows.append(dict(source=str(source_path), path=path, bytes=len(data), sha256=stage.digest(data), executable=executable))
    for package in ('memory','contracts'):
        row(source/'packages'/package/'package.json', 'source/packages/'+package+'/package.json', json.dumps(dict(name='@aukora-prime/'+package)).encode())
    for name in ('packages/memory/src/index.mjs','packages/contracts/src/runtime.mjs','packages/memory/test/operator-postgres.mjs'):
        row(source/name, 'source/'+name, b'export const synthetic = true;\n')
    for package, version in stage.VERSIONS.items():
        row(pg/'node_modules'/package/'package.json', 'source/node_modules/'+package+'/package.json', json.dumps(dict(name=package,version=version)).encode())
        row(pg/'node_modules'/package/'LICENSE', 'source/node_modules/'+package+'/LICENSE', b'fixture license\n')
    for path, name in ((node,'tools/node'),(license_path,'tools/LICENSE')):
        data = path.read_bytes()
        rows.append(dict(source=str(path),path=name,bytes=len(data),sha256=stage.digest(data),executable=name=='tools/node'))
    manifest = dict(version=1,kind='prime-pg-acceptance-input/v1',source_commit='0'*40,source_root=str(source),pg_root=str(pg),node=str(node),node_license=str(license_path),files=rows)
    planned = stage.plan(manifest)
    assert planned['qualification']=='PENDING' and planned['pg_version']=='8.16.3'
    assert stage.plan(dict(manifest, files=list(reversed(rows))))['source_closure_sha256']==planned['source_closure_sha256']
    checks += 2
    manifest_path = root/'manifest.json'
    manifest_path.write_text(json.dumps(manifest))
    pin = stage.digest(manifest_path.read_bytes())
    assert stage.load_manifest(str(manifest_path),pin)==manifest
    command = [sys.executable,str(script),'--manifest',str(manifest_path),'--expected-manifest-sha256',pin,'--plan']
    result = subprocess.run(command, capture_output=True,text=True)
    assert result.returncode==0 and json.loads(result.stdout)['status']=='PLANNED'
    checks += 2
    expect_refused('MANIFEST_HASH_MISMATCH',lambda:stage.load_manifest(str(manifest_path),'f'*64))
    duplicate = b'{"version":1,"version":1}'
    manifest_path.write_bytes(duplicate)
    expect_refused('DUPLICATE_JSON_KEY',lambda:stage.load_manifest(str(manifest_path),stage.digest(duplicate)))
    manifest_path.write_text(json.dumps(manifest))
    if sys.platform!='linux' or os.geteuid()!=0 or os.getegid()!=0:
        result = subprocess.run(command[:-1],capture_output=True,text=True)
        assert result.returncode==1 and json.loads(result.stderr)['reason']=='LINUX_ROOT_STAGING_REQUIRED'
        checks += 1
    bad = copy.deepcopy(manifest); bad['unexpected']=True
    expect_refused('CLOSED_SCHEMA',lambda:stage.plan(bad))
    bad = copy.deepcopy(manifest); bad['files'][0]['path']='source/packages/authority/package.json'
    expect_refused('DESTINATION_SCOPE_REFUSED',lambda:stage.plan(bad))
    bad = copy.deepcopy(manifest); bad['files'][0]['path']='source/packages/memory/../../outside'
    expect_refused('DESTINATION_PATH_INVALID',lambda:stage.plan(bad))
    bad = copy.deepcopy(manifest); bad['files'][0]['source']='//'+bad['files'][0]['source'][1:]
    expect_refused('CANONICAL_ABSOLUTE_PATH',lambda:stage.plan(bad))
    bad = copy.deepcopy(manifest); bad['files'].append(copy.deepcopy(rows[0]))
    expect_refused('SOURCE_BINDING_OR_DUPLICATE',lambda:stage.plan(bad))
    bad = copy.deepcopy(manifest); bad['files']=[r for r in bad['files'] if not r['path'].endswith('pgpass/package.json')]
    expect_refused('REQUIRED_CLOSURE_FILE_MISSING',lambda:stage.plan(bad))
    metadata_path = pg/'node_modules/pg/package.json'
    original_metadata = metadata_path.read_bytes()
    invalid_metadata = json.dumps(dict(name='pg',version='8.99.0')).encode()
    metadata_path.write_bytes(invalid_metadata)
    bad = copy.deepcopy(manifest)
    for entry in bad['files']:
        if entry['source']==str(metadata_path): entry.update(bytes=len(invalid_metadata),sha256=stage.digest(invalid_metadata))
    expect_refused('LOCKED_PG_METADATA_MISMATCH',lambda:stage.plan(bad))
    metadata_path.write_bytes(original_metadata)
    target = pathlib.Path(rows[0]['source'])
    original = target.read_bytes()
    target.write_bytes(original+b'changed')
    expect_refused('SOURCE_BYTES_OR_MODE_MISMATCH',lambda:stage.plan(manifest))
    expect_refused('COPY_INPUT_DRIFT',lambda:stage.copy_new(manifest,planned,root/'drift-attempt'))
    target.write_bytes(original)
    target.chmod(0o755)
    expect_refused('SOURCE_BYTES_OR_MODE_MISMATCH',lambda:stage.plan(manifest))
    target.chmod(0o644)
    hardlink = root/'linked-input'
    os.link(target, hardlink)
    expect_refused('BOUNDED_REGULAR_FILE_REQUIRED',lambda:stage.plan(manifest))
    hardlink.unlink()
    target.unlink(); target.symlink_to(license_path)
    expect_refused('SYMLINK_REFUSED',lambda:stage.plan(manifest))
    target.unlink(); target.write_bytes(original); target.chmod(0o644)
    alias = root/'source-alias'; alias.symlink_to(source, target_is_directory=True)
    bad = copy.deepcopy(manifest); bad['source_root']=str(alias)
    for entry in bad['files']:
        if entry['path'].startswith('source/packages/'):
            entry['source']=str(alias/pathlib.PurePosixPath(entry['path']).relative_to('source'))
    expect_refused('SYMLINK_REFUSED',lambda:stage.plan(bad))
    destination = root/'staged-fixture'
    stage.copy_new(manifest,planned,destination)
    for record in planned['records']:
        actual = destination/record['path']
        assert actual.read_bytes().__len__()==record['bytes'] and stage.digest(actual.read_bytes())==record['sha256']
        assert stat.S_IMODE(actual.stat().st_mode)==(0o755 if record['executable'] else 0o644)
    assert (destination/'source/package.json').read_bytes()==stage.PACKAGE
    checks += 1
    copied = destination/'source/packages/memory/src/index.mjs'
    copied.write_bytes(b'changed protected fixture bytes\n')
    expect_refused('COPIED_BYTES_OR_MODE_MISMATCH',lambda:stage.verify_copy(planned,destination))
    copied.write_bytes(b'export const synthetic = true;\n')
    copied.chmod(0o755)
    expect_refused('COPIED_BYTES_OR_MODE_MISMATCH',lambda:stage.verify_copy(planned,destination))
    copied.chmod(0o644)
    expect_refused('File exists',lambda:stage.copy_new(manifest,planned,destination))
    assert not list(root.rglob('*.sql'))  # No SQL, credential, or service artifact generated.
    checks += 1

print(json.dumps(dict(status='PASS',fixture_checks=checks,root_deployment='UNPERFORMED',postgresql='UNPERFORMED',qualification='PENDING')))
