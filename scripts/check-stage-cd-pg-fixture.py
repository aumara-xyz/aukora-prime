#!/usr/bin/env python3
"""Disposable source/link checks; no root staging, PG, worker, or service execution."""
import copy, importlib.util, json, os, pathlib, stat, subprocess, sys, tempfile
sys.dont_write_bytecode=True
script=pathlib.Path(__file__).with_name('stage-cd-pg-fixture.py')
spec=importlib.util.spec_from_file_location('stage_cd_pg',script)
stage=importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)
checks=0
def refused(reason,action):
    global checks
    try: action()
    except (ValueError,OSError) as error: assert reason in str(error),(reason,str(error))
    else: raise AssertionError('expected refusal: '+reason)
    checks+=1
with tempfile.TemporaryDirectory(prefix='prime-cd-pg-stage-') as temporary:
    root=pathlib.Path(temporary).resolve(); source=root/'input'; pg=root/'pg'
    source.mkdir(); pg.mkdir(); rows=[]
    def file_row(relative,data,executable=False,pg_file=False):
        actual=(pg if pg_file else source)/relative
        actual.parent.mkdir(parents=True,exist_ok=True); actual.write_bytes(data); actual.chmod(0o755 if executable else 0o644)
        row=dict(kind='file',source=str(actual),path='source/'+relative,bytes=len(data),sha256=stage.digest(data),executable=executable)
        rows.append(row); return actual
    file_row('LICENSE',b'fixture Prime license\n')
    for package in ('authority','contracts','memory','runtime-bridge','ui'):
        file_row('packages/'+package+'/package.json',json.dumps(dict(name='@aukora-prime/'+package)).encode())
    for name in ('packages/authority/src/index.mjs','packages/memory/src/index.mjs','packages/contracts/src/runtime.mjs','packages/runtime-bridge/src/worker.mjs','packages/ui/adapters/transport.mjs'):
        file_row(name,b'export const fixture = true;\n')
    file_row('packages/ui/licenses/LICENSE',b'fixture UI license\n')
    for package,version in stage.VERSIONS.items():
        file_row('node_modules/'+package+'/package.json',json.dumps(dict(name=package,version=version)).encode(),pg_file=True)
        file_row('node_modules/'+package+'/LICENSE',b'fixture package license\n',pg_file=True)
    for name,target in stage.LINKS.items():
        physical=stage.link_destination(name,target)
        noble=name.rsplit('/',1)[1]
        file_row(physical.removeprefix('source/')+'/package.json',json.dumps(dict(name='@noble/'+noble,version=stage.NOBLE[noble])).encode())
        file_row(physical.removeprefix('source/')+'/index.js',b'export const fixtureNoble = true;\n')
        leaf=source/pathlib.PurePosixPath(name).relative_to('source')
        leaf.parent.mkdir(parents=True,exist_ok=True); leaf.symlink_to(target)
        rows.append(dict(kind='link',source=str(leaf),path=name,target=target))
    for name in ('node','LICENSE'):
        actual=root/('node-bin' if name=='node' else 'node-LICENSE')
        data=b'not executed\n'; actual.write_bytes(data); actual.chmod(0o755 if name=='node' else 0o644)
        rows.append(dict(kind='file',source=str(actual),path='tools/'+name,bytes=len(data),sha256=stage.digest(data),executable=name=='node'))
    manifest=dict(version=1,kind='prime-cd-pg-fixture-input/v1',source_commit='0'*40,source_root=str(source),pg_root=str(pg),node=str(root/'node-bin'),node_license=str(root/'node-LICENSE'),files=rows)
    planned=stage.plan(manifest)
    assert planned['qualification']=='PENDING' and len([r for r in planned['records'] if r['kind']=='link'])==4
    assert stage.plan(dict(manifest,files=list(reversed(rows))))['source_closure_sha256']==planned['source_closure_sha256']
    checks+=2
    growth_file=root/'growth-input'; growth_file.write_bytes(b'original')
    initial_size=growth_file.stat().st_size; initial_inode=growth_file.stat().st_ino
    real_fstat,real_fdopen=stage.os.fstat,stage.os.fdopen
    observations=[]; changed=[False]
    def growing_fstat(fd):
        info=real_fstat(fd)
        if info.st_ino==initial_inode and not changed[0]:
            changed[0]=True
            with growth_file.open('ab') as writer: writer.write(b'g'*1024*1024)
        return info
    class BoundedReader:
        def __init__(self,stream): self.stream=stream
        def __enter__(self): self.stream.__enter__(); return self
        def __exit__(self,*args): return self.stream.__exit__(*args)
        def read(self,size=-1):
            assert size==initial_size+1,'read was not bounded to initial declared size + 1'
            data=self.stream.read(size); observations.append((size,len(data))); return data
    def observing_fdopen(*args,**kwargs): return BoundedReader(real_fdopen(*args,**kwargs))
    try:
        stage.os.fstat=growing_fstat; stage.os.fdopen=observing_fdopen
        refused('INPUT_CHANGED_DURING_READ',lambda:stage.read_regular(growth_file,32))
        assert observations==[(initial_size+1,initial_size+1)] and growth_file.stat().st_size>32
        checks+=1
    finally: stage.os.fstat=real_fstat; stage.os.fdopen=real_fdopen
    stable_file=root/'same-size-input'; stable_file.write_bytes(b'original')
    changed=[False]
    def same_size_fstat(fd):
        info=real_fstat(fd)
        if info.st_ino==stable_file.stat().st_ino and not changed[0]:
            changed[0]=True; stable_file.write_bytes(b'modified')
        return info
    try:
        stage.os.fstat=same_size_fstat
        refused('INPUT_CHANGED_DURING_READ',lambda:stage.read_regular(stable_file))
    finally: stage.os.fstat=real_fstat
    replaced_file=root/'replaced-input'; replaced_file.write_bytes(b'original')
    class ReplacingReader:
        def __init__(self,stream): self.stream=stream
        def __enter__(self): self.stream.__enter__(); return self
        def __exit__(self,*args):
            result=self.stream.__exit__(*args)
            replacement=root/'replacement'; replacement.write_bytes(b'original'); replacement.replace(replaced_file)
            return result
        def read(self,size): return self.stream.read(size)
    try:
        stage.os.fdopen=lambda *args,**kwargs:ReplacingReader(real_fdopen(*args,**kwargs))
        refused('INPUT_CHANGED_DURING_READ',lambda:stage.read_regular(replaced_file))
    finally: stage.os.fdopen=real_fdopen
    manifest_path=root/'manifest.json'; manifest_path.write_text(json.dumps(manifest)); pin=stage.digest(manifest_path.read_bytes())
    command=[sys.executable,str(script),'--manifest',str(manifest_path),'--expected-manifest-sha256',pin,'--plan']
    result=subprocess.run(command,capture_output=True,text=True)
    assert result.returncode==0 and json.loads(result.stdout)['status']=='PLANNED'
    checks+=1
    refused('MANIFEST_HASH_MISMATCH',lambda:stage.load_manifest(str(manifest_path),'f'*64))
    manifest_path.write_bytes(b'{"version":1,"version":1}')
    refused('DUPLICATE_JSON_KEY',lambda:stage.load_manifest(str(manifest_path),stage.digest(manifest_path.read_bytes())))
    manifest_path.write_text(json.dumps(manifest))
    if sys.platform!='linux' or os.geteuid()!=0 or os.getegid()!=0:
        result=subprocess.run(command[:-1],capture_output=True,text=True)
        assert result.returncode==1 and json.loads(result.stderr)['reason']=='LINUX_ROOT_STAGING_REQUIRED'
        checks+=1
    bad=copy.deepcopy(manifest); bad['extra']=True
    refused('CLOSED_SCHEMA',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); bad['files'][0]['extra']=True
    refused('CLOSED_SCHEMA',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); bad['files'][0]['kind']='directory'
    refused('ROW_KIND_INVALID',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); bad['files'].append(copy.deepcopy(rows[0]))
    refused('SOURCE_BINDING_OR_DUPLICATE',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); bad['files'][0]['path']='source/packages/execution/LICENSE'
    refused('DESTINATION_SCOPE_REFUSED',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); bad['files'][0]['path']='source/packages/ui/prime-authority/index.js'
    refused('DESTINATION_SCOPE_REFUSED',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); bad['files'][0]['path']='source/packages/authority/../outside'
    refused('DESTINATION_PATH_INVALID',lambda:stage.plan(bad))
    link_row=next(row for row in rows if row['kind']=='link')
    for target in ('/tmp/outside','../../../../../../outside','../../@noble/hashes@9.9.9'):
        bad=copy.deepcopy(manifest)
        next(row for row in bad['files'] if row['kind']=='link')['target']=target
        refused('LINK_ALLOWLIST_REFUSED',lambda:stage.plan(bad))
    bad=copy.deepcopy(manifest); extra=copy.deepcopy(link_row)
    extra['path']=stage.LINK_BASE+'extra'; extra['source']=str(source/pathlib.PurePosixPath(extra['path']).relative_to('source')); bad['files'].append(extra)
    refused('LINK_ALLOWLIST_REFUSED',lambda:stage.plan(bad))
    physical=stage.link_destination(link_row['path'],link_row['target'])+'/package.json'
    bad=copy.deepcopy(manifest); bad['files']=[row for row in bad['files'] if row['path']!=physical]
    refused('LINK_PHYSICAL_TARGET_MISSING',lambda:stage.plan(bad))
    metadata_path=source/pathlib.PurePosixPath(physical).relative_to('source')
    original_metadata=metadata_path.read_bytes(); changed_metadata=json.dumps(dict(name='@noble/wrong',version='2.2.0')).encode()
    metadata_path.write_bytes(changed_metadata)
    bad=copy.deepcopy(manifest)
    next(row for row in bad['files'] if row['path']==physical).update(bytes=len(changed_metadata),sha256=stage.digest(changed_metadata))
    refused('LOCKED_NOBLE_METADATA_MISMATCH',lambda:stage.plan(bad))
    metadata_path.write_bytes(original_metadata)
    bad=copy.deepcopy(manifest); bad['files']=[row for row in bad['files'] if row['path']!=link_row['path']]
    refused('REQUIRED_CLOSURE_FILE_MISSING',lambda:stage.plan(bad))
    leaf=pathlib.Path(link_row['source']); leaf.unlink(); leaf.symlink_to('../../@noble/hashes@9.9.9')
    refused('SOURCE_LINK_TARGET_MISMATCH',lambda:stage.plan(manifest))
    refused('COPY_LINK_DRIFT',lambda:stage.copy_new(manifest,planned,root/'drift-link-attempt'))
    leaf.unlink(); leaf.symlink_to(link_row['target'])
    file=pathlib.Path(rows[0]['source']); original=file.read_bytes(); file.write_bytes(original+b'changed')
    refused('SOURCE_BYTES_OR_MODE_MISMATCH',lambda:stage.plan(manifest))
    refused('COPY_INPUT_DRIFT',lambda:stage.copy_new(manifest,planned,root/'drift-file-attempt'))
    file.write_bytes(original)
    hardlink=root/'hardlink'; os.link(file,hardlink)
    refused('BOUNDED_REGULAR_FILE',lambda:stage.plan(manifest)); hardlink.unlink()
    file.unlink(); file.symlink_to(root/'node-LICENSE')
    refused('SYMLINK_REFUSED',lambda:stage.plan(manifest)); file.unlink(); file.write_bytes(original); file.chmod(0o644)
    alias=root/'alias'; alias.symlink_to(source,target_is_directory=True)
    bad=copy.deepcopy(manifest); bad['source_root']=str(alias)
    for row in bad['files']:
        if row['path'].startswith('source/packages/') or row['path']=='source/LICENSE': row['source']=str(alias/pathlib.PurePosixPath(row['path']).relative_to('source'))
    refused('SYMLINK_REFUSED',lambda:stage.plan(bad))
    destination=root/'copied'; stage.copy_new(manifest,planned,destination); stage.verify_copy(planned,destination)
    for row in planned['records']:
        copied=destination/row['path']
        if row['kind']=='link': assert copied.is_symlink() and os.readlink(copied)==row['target']
        else: assert stat.S_IMODE(copied.stat().st_mode)==(0o755 if row['executable'] else 0o644)
    assert (destination/'source/package.json').read_bytes()==stage.PACKAGE
    checks+=1
    copied_link=destination/link_row['path']; copied_link.unlink(); copied_link.symlink_to('/tmp/outside')
    refused('COPIED_LINK_MISMATCH',lambda:stage.verify_copy(planned,destination))
    copied_link.unlink(); copied_link.symlink_to(link_row['target'])
    copied_file=destination/'source/LICENSE'; copied_file.write_bytes(b'changed bytes')
    refused('COPIED_BYTES_OR_MODE_MISMATCH',lambda:stage.verify_copy(planned,destination))
    refused('File exists',lambda:stage.copy_new(manifest,planned,destination))
print(json.dumps(dict(status='PASS',fixture_checks=checks,root_staging='UNPERFORMED',postgresql='UNPERFORMED',qualification='PENDING')))
