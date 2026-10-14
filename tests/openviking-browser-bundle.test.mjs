// SPDX-License-Identifier: AGPL-3.0-or-later
// Refuse unpinned payloads and unsafe archives without downloads or execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const helper = process.env.AUKORA_OV_BUNDLE_SOURCE ?? path.join(root, 'ops/node-spawn/browser/openviking-bundle.py');
const court = String.raw`
import gzip, hashlib, importlib.util, io, json, os, pathlib, shutil, subprocess, sys, tarfile, tempfile, types, zipfile
spec = importlib.util.spec_from_file_location('bundle', sys.argv[1]); b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
case = sys.argv[2]
repo = pathlib.Path(sys.argv[3])
def sha(value): return hashlib.sha256(value).hexdigest()
def want(code, action):
    try: action()
    except b.Refusal as error:
        assert str(error) == 'OPENVIKING_BUNDLE_' + code, (code, str(error))
    else: raise AssertionError('protection removed: ' + code)
with tempfile.TemporaryDirectory(prefix='.openviking-bundle-test-', dir=repo) as temp:
    temp = pathlib.Path(temp); checkout = temp/'checkout'; tree = temp/'payload'; tree.mkdir()
    for value in ('vendor/openviking', 'host/pins'): (checkout/value).mkdir(parents=True)
    for value in ('wheels', 'models', 'llama'): (tree/value).mkdir()
    def wheel(name, version, filename):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr(name+'-'+version+'.dist-info/METADATA', 'Name: '+name+'\nVersion: '+version+'\n')
            py,abi,platform=filename[:-4].split('-')[-3:]
            tags=[a+'-'+c+'-'+d for a in py.split('.') for c in abi.split('.') for d in platform.split('.')]
            archive.writestr(name+'-'+version+'.dist-info/WHEEL', 'Wheel-Version: 1.0\n'+''.join('Tag: '+tag+'\n' for tag in tags))
        value=output.getvalue(); (tree/'wheels'/filename).write_bytes(value); return value
    ov = wheel('openviking', '0.4.21', b.WHEEL)
    depname='dependency-1.2-py3-none-any.whl'; dep=wheel('dependency','1.2',depname)
    assert b.pins(repo)[0]['version']=='0.4.21'
    assert b.WHEEL_SHA == 'e223518bd33b50bbd6b1c7860e4856cd7c477eb8656afdbe7871ff59355b37a6'
    b.WHEEL_SHA=sha(ov)
    lock=('openviking==0.4.21 --hash=sha256:'+sha(ov)+'\ndependency==1.2 --hash=sha256:'+sha(dep)+'\n').encode()
    pin={'version':'0.4.21','lock':{'path':'requirements.lock','sha256':sha(lock),'distributions':2,'python':'3.11'},
         'embeddingModel':{'file':'model.gguf','bytes':5,'sha256':sha(b'model'),'url':'https://example.invalid/model'}}
    llama={'version':'b11381','install_dir':'/opt/llama.cpp/b11381','entry':'llama-server','entry_sha256':sha(b'server'),
           'files':[{'path':'llama-server','sha256':sha(b'server')},{'path':'library.so.1','sha256':sha(b'library')}],
           'symlinks':[{'path':'library.so','target':'library.so.1'}]}
    def savepin(): (checkout/'vendor/openviking/upstream-openviking.json').write_text(json.dumps(pin))
    def savellama(): (checkout/'host/pins/llama-server-b11381.json').write_text(json.dumps(llama))
    savepin(); savellama(); (checkout/'vendor/openviking/requirements.lock').write_bytes(lock)
    (tree/'requirements.lock').write_bytes(lock); (tree/'models/model.gguf').write_bytes(b'model')
    (tree/'llama/llama-server').write_bytes(b'server'); (tree/'llama/library.so.1').write_bytes(b'library')
    (tree/'llama/library.so').symlink_to('library.so.1')
    manifest=b.validate_tree(tree, checkout, manifest=False)
    (tree/'manifest.json').write_text(json.dumps(manifest))
    def validate(): return b.validate_tree(tree,checkout)
    def archive(members=None):
        output=temp/'input.tar.gz'
        with tarfile.open(output,'w:gz') as stream:
            if members is None:
                files,links=b.tree_entries(tree)
                members=[(n,'file',(tree/n).read_bytes()) for n in files]+[(n,'link',t) for n,t in links.items()]
            for name,kind,value in members:
                row=tarfile.TarInfo(name)
                if kind=='file': row.size=len(value); stream.addfile(row,io.BytesIO(value))
                elif kind=='huge': row.size=value; stream.addfile(row)
                elif kind=='link': row.type=tarfile.SYMTYPE; row.linkname=value; stream.addfile(row)
                elif kind=='hard': row.type=tarfile.LNKTYPE; row.linkname=value; stream.addfile(row)
                elif kind=='directory': row.type=tarfile.DIRTYPE; stream.addfile(row)
                elif kind=='device': row.type=tarfile.CHRTYPE; stream.addfile(row)
        return output
    def extract(members=None): return b.extract_bundle(archive(members),temp/'extracted',checkout)
    b.platform.system=lambda:'Linux'; b.platform.machine=lambda:'x86_64'
    b.shutil.which=lambda name: '/synthetic/python3.11' if name=='python3.11' else '/synthetic/'+name
    b.subprocess.run=lambda *a,**k: types.SimpleNamespace(returncode=0)
    b.shutil.disk_usage=lambda _: types.SimpleNamespace(free=b.MAX_BYTES)
    def build(): return b.build(temp/'output.tar.gz',tree/'llama',checkout)
    if case=='valid':
        assert validate()==manifest; assert extract()==manifest
    elif case=='lock-digest':
        (checkout/'vendor/openviking/requirements.lock').write_bytes(b'changed'); want('LOCK_DIGEST_MISMATCH',validate)
    elif case=='lock-syntax':
        bad=b'--index-url https://evil.invalid\n'; (checkout/'vendor/openviking/requirements.lock').write_bytes(bad)
        pin['lock']['sha256']=sha(bad); savepin(); want('LOCK_INVALID',validate)
    elif case=='lock-count': pin['lock']['distributions']=1; savepin(); want('LOCK_INVALID',validate)
    elif case=='lock-python': pin['lock']['python']='3.12'; savepin(); want('LOCK_INVALID',validate)
    elif case=='wheel-pin': pin['version']='unreviewed'; savepin(); want('WHEEL_PIN_MISMATCH',validate)
    elif case=='llama-pin': llama['entry_sha256']='0'*64; savellama(); want('LLAMA_PIN_INVALID',validate)
    elif case=='llama-link-pin': llama['symlinks'][0]['target']='unknown.so'; savellama(); want('LLAMA_PIN_INVALID',validate)
    elif case=='llama-file': (tree/'llama/llama-server').write_bytes(b'unknown'); want('LLAMA_TREE_MISMATCH',validate)
    elif case=='llama-link': (tree/'llama/library.so').unlink(); (tree/'llama/library.so').symlink_to('/outside'); want('LLAMA_TREE_MISMATCH',validate)
    elif case=='model': (tree/'models/model.gguf').write_bytes(b'wrong'); want('MODEL_DIGEST_MISMATCH',validate)
    elif case=='payload-lock': (tree/'requirements.lock').write_bytes(b'wrong'); want('LOCK_DIGEST_MISMATCH',validate)
    elif case=='payload-lock-streamed':
        original_read=pathlib.Path.read_bytes
        def read_bytes(file):
            if file==tree/'requirements.lock': raise AssertionError('payload lock allocated wholesale')
            return original_read(file)
        pathlib.Path.read_bytes=read_bytes; assert validate()==manifest
    elif case=='closure': (tree/'wheels'/depname).unlink(); want('CLOSURE_INCOMPLETE',validate)
    elif case=='wheel-digest': (tree/'wheels'/depname).write_bytes(dep+b'append'); want('WHEEL_DIGEST_MISMATCH',validate)
    elif case=='wheel-platform':
        (tree/'wheels'/depname).rename(tree/'wheels/dependency-1.2-py3-none-macosx_14_0_arm64.whl'); want('WHEEL_PLATFORM_INVALID',validate)
    elif case=='wheel-name': (tree/'wheels'/depname).rename(tree/'wheels/dependency.zip'); want('WHEEL_INVALID',validate)
    elif case=='wheel-metadata':
        wheel('other','1.2',depname); want('WHEEL_METADATA_INVALID',lambda:b.wheel_identity(tree/'wheels'/depname))
    elif case=='wheel-before-zip':
        (tree/'wheels'/depname).write_bytes(b'unpinned ZIP')
        original_identity=b.wheel_identity
        def opened_unpinned(path):
            if path.name==depname: raise AssertionError('unpinned wheel parsed')
            return original_identity(path)
        b.wheel_identity=opened_unpinned; want('WHEEL_DIGEST_MISMATCH',validate)
    elif case=='wheel-tags':
        foreign='dependency-1.2-py3-none-macosx_14_0_arm64.whl'
        value=wheel('dependency','1.2',foreign); (tree/'wheels'/foreign).rename(tree/'wheels'/depname)
        newlock=lock.replace(sha(dep).encode(),sha(value).encode())
        (checkout/'vendor/openviking/requirements.lock').write_bytes(newlock); (tree/'requirements.lock').write_bytes(newlock)
        pin['lock']['sha256']=sha(newlock); savepin()
        want('WHEEL_METADATA_INVALID',lambda:b.wheel_identity(tree/'wheels'/depname)); want('WHEEL_METADATA_INVALID',validate)
    elif case=='wheel-duplicate': (tree/'wheels/dependency-1.2-1-py3-none-any.whl').write_bytes(dep); want('WHEEL_DUPLICATE',validate)
    elif case=='unlisted': (tree/'unlisted').write_bytes(b'unlisted'); want('TREE_UNLISTED',validate)
    elif case=='empty-directory': (tree/'empty').mkdir(); want('TREE_UNLISTED',validate)
    elif case=='hardlink': os.link(tree/'models/model.gguf',tree/'model-copy'); want('FILE_TYPE_INVALID',validate)
    elif case=='fifo': os.mkfifo(tree/'fifo'); want('FILE_TYPE_INVALID',validate)
    elif case=='manifest': (tree/'manifest.json').write_text('{}'); want('MANIFEST_MISMATCH',validate)
    elif case=='manifest-size': (tree/'manifest.json').write_bytes(b' '*(1024*1024+1)); want('MANIFEST_INVALID',validate)
    elif case=='payload-size': b.MAX_BYTES=1; want('SIZE_LIMIT',validate)
    elif case=='payload-count': b.MAX_ENTRIES=1; want('SIZE_LIMIT',validate)
    elif case=='path':
        for value in ('../escape','/absolute','a//b','a/./b','a/../b','a\\b','a\nb','a\rb',''):
            want('PATH_INVALID',lambda:b.relative(value))
    elif case=='archive-path': want('PATH_INVALID',lambda:extract([('../escape','file',b'unsafe')]))
    elif case=='archive-duplicate': want('ARCHIVE_DUPLICATE',lambda:extract([('a','file',b'a'),('a','file',b'a')]))
    elif case=='archive-link': want('ARCHIVE_LINK_INVALID',lambda:extract([('llama/library.so','link','/outside')]))
    elif case=='archive-type':
        for kind in ('directory','device','hard'):
            want('ARCHIVE_TYPE_INVALID',lambda:extract([('a',kind,'target')]))
    elif case in ('archive-pax', 'archive-longname'):
        row=tarfile.TarInfo('extension'); row.type=tarfile.XHDTYPE if case=='archive-pax' else tarfile.GNUTYPE_LONGNAME
        row.size=b.MAX_BYTES+512
        output=temp/'input.tar.gz'; output.write_bytes(gzip.compress(row.tobuf(tarfile.USTAR_FORMAT)+b'\0'*1024))
        def extension_processed(*args): raise AssertionError('extension processed before refusal')
        tarfile.TarInfo._proc_pax=extension_processed; tarfile.TarInfo._proc_gnulong=extension_processed
        want('ARCHIVE_TYPE_INVALID',lambda:b.extract_bundle(output,temp/'extracted',checkout))
    elif case=='archive-size': b.MAX_BYTES=1; want('SIZE_LIMIT',lambda:extract([('a','file',b'aa')]))
    elif case=='archive-count': b.MAX_ENTRIES=1; want('SIZE_LIMIT',lambda:extract([('a','file',b'a'),('b','file',b'b')]))
    elif case=='target':
        (temp/'extracted').mkdir(); want('TARGET_INVALID',extract)
    elif case=='platform': b.platform.machine=lambda:'aarch64'; want('LINUX_X86_64_REQUIRED',build)
    elif case=='preload': os.environ['LD_PRELOAD']='synthetic'; want('PRELOAD_FORBIDDEN',build)
    elif case=='python-missing': b.shutil.which=lambda _:None; want('PYTHON311_REQUIRED',build)
    elif case=='python-version': b.subprocess.run=lambda *a,**k:types.SimpleNamespace(returncode=1); want('PYTHON311_REQUIRED',build)
    elif case=='output': (temp/'output.tar.gz').write_bytes(b'existing'); want('OUTPUT_INVALID',build)
    elif case=='llama-input': want('LLAMA_INPUT_INVALID',lambda:b.build(temp/'output.tar.gz',temp/'missing',checkout))
    elif case=='disk': b.shutil.disk_usage=lambda _:types.SimpleNamespace(free=0); want('DISK_REQUIRED',build)
    elif case=='download':
        b.subprocess.run=lambda command,**k:types.SimpleNamespace(returncode=0 if command[1]=='-I' and command[2]=='-c' else 1)
        want('DOWNLOAD_FAILED',build)
    elif case in ('deterministic', 'fixed-target'):
        def downloads(command,**kwargs):
            if 'download' in command:
                platforms=['manylinux_2_%d_x86_64' % minor for minor in range(39,4,-1)]
                platforms+=['manylinux2014_x86_64','manylinux2010_x86_64','manylinux1_x86_64']
                expected=[value for name in platforms for value in ('--platform',name)]
                expected+=['--python-version','3.11','--implementation','cp','--abi','cp311','--abi','abi3','--abi','none']
                offset=command.index('--no-cache-dir')+1
                assert command[offset:offset+len(expected)]==expected, 'fixed Linux/Python target changed'
                out=pathlib.Path(command[command.index('--dest')+1]); (out/b.WHEEL).write_bytes(ov); (out/depname).write_bytes(dep)
            elif command[0]=='curl': pathlib.Path(command[command.index('--output')+1]).write_bytes(b'model')
            return types.SimpleNamespace(returncode=0)
        b.subprocess.run=downloads
        build(); first=(temp/'output.tar.gz').read_bytes(); (temp/'output.tar.gz').unlink(); build()
        assert first==(temp/'output.tar.gz').read_bytes()
        assert b.extract_bundle(temp/'output.tar.gz',temp/'extracted',checkout)==manifest
    else: raise AssertionError(case)
print('PASS '+case)
`;

const cases = ['valid', 'lock-digest', 'lock-syntax', 'lock-count', 'lock-python', 'wheel-pin', 'llama-pin',
  'llama-link-pin', 'llama-file', 'llama-link', 'model', 'payload-lock', 'payload-lock-streamed', 'closure', 'wheel-digest',
  'wheel-platform', 'wheel-name', 'wheel-metadata', 'wheel-before-zip', 'wheel-tags', 'wheel-duplicate', 'unlisted', 'empty-directory',
  'hardlink', 'fifo', 'manifest', 'manifest-size', 'payload-size', 'payload-count', 'path', 'archive-path',
  'archive-duplicate', 'archive-link', 'archive-type', 'archive-pax', 'archive-longname', 'archive-size', 'archive-count', 'target', 'platform',
  'preload', 'python-missing', 'python-version', 'output', 'llama-input', 'disk', 'download', 'fixed-target', 'deterministic'];
for (const name of cases) test(`offline OpenViking bundle ${name}`, () => {
  const result = spawnSync('python3', ['-I', '-S', '-B', '-', helper, name, root], { input: court, encoding: 'utf8', timeout: 15000 });
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stdout, new RegExp('PASS ' + name));
});
test('offline OpenViking bundle CLI refuses incomplete arguments and shell parses', () => {
  const result = spawnSync('python3', ['-I', '-S', '-B', helper], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /REFUSED OPENVIKING_BUNDLE_USAGE/);
  assert.equal(spawnSync('sh', ['-n', path.join(root, 'ops/node-spawn/browser/openviking-bundle.sh')]).status, 0);
  assert.match(fs.readFileSync(helper, 'utf8'), /https:\/\/pypi\.org\/simple/);
});

test('offline OpenViking bundle CLI refuses duplicate arguments', () => {
  const result = spawnSync('python3', ['-I', '-S', '-B', helper, '--output', '/synthetic', '--output', '/synthetic2', '--llama-tree', '/synthetic'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /REFUSED OPENVIKING_BUNDLE_DUPLICATE_ARGUMENT/);
});
