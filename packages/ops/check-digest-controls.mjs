// SPDX-License-Identifier: AGPL-3.0-or-later
// Owned disposable digest/archive fixtures only; no review candidate execution.
import assert from 'node:assert/strict'
import {mkdtempSync, realpathSync, mkdirSync, writeFileSync, readFileSync, readdirSync,
  symlinkSync, chmodSync, unlinkSync, rmSync, existsSync} from 'node:fs'
import {join, dirname} from 'node:path'
import {tmpdir} from 'node:os'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {fullTreeDigest, runGate} from './gates.mjs'
import {treeDigest, releaseBinding} from './vendor/release-digest.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const temporary = realpathSync(mkdtempSync(join(tmpdir(), 'prime-digest-controls-check-')))
const sha = value => createHash('sha256').update(value).digest('hex')
const encoded = (domain, rows) => sha(domain + '\0' + [...rows].sort().join('\n'))
const controls = [...Array(32).keys(), 127].map(value => String.fromCharCode(value))
const physicalControls = controls.filter(value => value !== '\0')
const checks = []
const check = (name, action) => {action(); checks.push(name)}
const refuse = (action, reason) => assert.throws(action, error => error.message === reason)
const python = process.env.PRIME_OPS_PYTHON ?? 'python3'
let pythonReport

try {
  const ordinary = join(temporary, 'ordinary')
  mkdirSync(join(ordinary, 'node_modules/.pnpm'), {recursive: true, mode: 0o755})
  const bytes = {'a.txt': 'alpha\n', 'node_modules/.pnpm/owned.mjs': 'export const owned=1\n',
    shell: '#!/bin/sh\nexit 0\n'}
  for (const [name, value] of Object.entries(bytes)) {
    writeFileSync(join(ordinary, name), value, {mode: 0o644}); chmodSync(join(ordinary, name), name === 'shell' ? 0o755 : 0o644)
  }
  symlinkSync('.pnpm/owned.mjs', join(ordinary, 'node_modules/owned.mjs'))
  const rows = ['f a.txt\0' + sha(bytes['a.txt']), 'f node_modules/.pnpm/owned.mjs\0' + sha(bytes['node_modules/.pnpm/owned.mjs']),
    'l node_modules/owned.mjs\0.pnpm/owned.mjs', 'x shell\0' + sha(bytes.shell)]
  const goldenFull = '5833259c0deda2fff3eb26a85d7ff3fd5a7cb13d07678b0a9915100efd0235d2'
  const goldenLegacy = '2c312931f3aca9c985d5809465e149bb3c7b991962c91167eef790063b3d7194'
  check('ordinary-v1-frozen-golden-and-independent-encoding', () => {
    assert.equal(encoded('aukora-prime:full-release:v1', rows), goldenFull)
    assert.equal(encoded('aukora:release-tree:v1', rows), goldenLegacy)
    assert.equal(fullTreeDigest(ordinary).digest, goldenFull)
    assert.equal(treeDigest(ordinary).digest, goldenLegacy)
    assert.equal(fullTreeDigest(ordinary).files, 4); assert.equal(treeDigest(ordinary).files, 4)
  })
  check('ordinary-file-mutation-and-executable-bit-remain-covered', () => {
    writeFileSync(join(ordinary, 'a.txt'), 'changed ordinary fixture\n')
    assert.notEqual(fullTreeDigest(ordinary).digest, goldenFull)
    assert.notEqual(treeDigest(ordinary).digest, goldenLegacy)
    writeFileSync(join(ordinary, 'a.txt'), bytes['a.txt'])
    chmodSync(join(ordinary, 'shell'), 0o644)
    assert.notEqual(fullTreeDigest(ordinary).digest, goldenFull)
    assert.notEqual(treeDigest(ordinary).digest, goldenLegacy)
    chmodSync(join(ordinary, 'shell'), 0o755)
    assert.equal(fullTreeDigest(ordinary).digest, goldenFull)
  })
  const collisionRoots = []
  const collisionBytes = {x: 'changed synthetic module bytes\n', 'x\nl b': 'expected synthetic module bytes\n',
    y: 'identical synthetic unused bytes\n'}
  const collisionRows = []
  for (const [variant, links] of [['expected', {a: 'x\nl b', c: 'y'}], ['changed', {a: 'x', 'b\nl c': 'y'}]]) {
    const root = join(temporary, variant); mkdirSync(root, {mode: 0o755}); collisionRoots.push(root)
    const records = []
    for (const [name, value] of Object.entries(collisionBytes)) {
      writeFileSync(join(root, name), value, {mode: 0o644}); records.push('f ' + name + '\0' + sha(value))
    }
    for (const [name, target] of Object.entries(links)) {
      symlinkSync(target, join(root, name)); records.push('l ' + name + '\0' + target)
    }
    collisionRows.push(records)
  }
  check('exact-reviewed-lf-collision-pair-is-refused-by-both-digests', () => {
    assert.equal(readFileSync(join(collisionRoots[0], 'a'), 'utf8'), collisionBytes['x\nl b'])
    assert.equal(readFileSync(join(collisionRoots[1], 'a'), 'utf8'), collisionBytes.x)
    assert.notEqual(readFileSync(join(collisionRoots[0], 'a'), 'utf8'), readFileSync(join(collisionRoots[1], 'a'), 'utf8'))
    assert.equal(encoded('aukora-prime:full-release:v1', collisionRows[0]),
      '12731719a3316c284ad42b814b5099855a7e95f02ce4e7a688fd21a4e1f10311')
    assert.equal(encoded('aukora-prime:full-release:v1', collisionRows[0]), encoded('aukora-prime:full-release:v1', collisionRows[1]))
    for (const root of collisionRoots) {
      assert.throws(() => fullTreeDigest(root), /RELEASE_(?:PATH|LINK)_CONTROL_CHARACTER/)
      assert.throws(() => treeDigest(root), /RELEASE_(?:PATH|LINK)_CONTROL_CHARACTER/)
    }
  })
  const single = join(temporary, 'single'); mkdirSync(single, {mode: 0o755})
  writeFileSync(join(single, 'safe'), 'ordinary target\n', {mode: 0o644})
  check('all-c0-and-del-root-strings-refused-before-filesystem', () => {
    for (const value of controls) {
      refuse(() => fullTreeDigest(single + value), 'RELEASE_PATH_CONTROL_CHARACTER')
      refuse(() => treeDigest(single + value), 'RELEASE_PATH_CONTROL_CHARACTER')
    }
  })
  check('raw-controls-cannot-be-canceled-by-dotdot-or-cli-normalization', () => {
    for (const value of controls) {
      const raw = temporary + '/discard' + value + '/../single'
      refuse(() => fullTreeDigest(raw), 'RELEASE_PATH_CONTROL_CHARACTER')
      refuse(() => treeDigest(raw), 'RELEASE_PATH_CONTROL_CHARACTER')
      refuse(() => releaseBinding({commit: '0'.repeat(40), release: raw, shell: single}), 'RELEASE_PATH_CONTROL_CHARACTER')
      refuse(() => releaseBinding({commit: '0'.repeat(40), release: single, shell: raw}), 'RELEASE_PATH_CONTROL_CHARACTER')
    }
    const result = spawnSync(process.execPath, [join(here, 'cli.mjs'), 'digest', '--root', temporary + '/discard\n/../single'],
      {encoding: 'utf8', timeout: 10_000, maxBuffer: 65536})
    assert.equal(result.error, undefined); assert.equal(result.status, 1)
    assert.deepEqual(JSON.parse(result.stdout), {status: 'REFUSED', reason: 'RELEASE_PATH_CONTROL_CHARACTER'})
  })
  check('safe-root-alias-to-control-directory-refuses-resolved-root', () => {
    const controlled = join(temporary, 'root\ncontrol'), alias = join(temporary, 'root-alias')
    mkdirSync(controlled, {mode: 0o755}); writeFileSync(join(controlled, 'safe'), 'ordinary fixture\n', {mode: 0o644})
    symlinkSync('root\ncontrol', alias)
    refuse(() => fullTreeDigest(alias), 'RELEASE_PATH_CONTROL_CHARACTER')
    refuse(() => treeDigest(alias), 'RELEASE_PATH_CONTROL_CHARACTER')
    refuse(() => releaseBinding({commit: '0'.repeat(40), release: alias, shell: single}), 'RELEASE_PATH_CONTROL_CHARACTER')
    refuse(() => releaseBinding({commit: '0'.repeat(40), release: single, shell: alias}), 'RELEASE_PATH_CONTROL_CHARACTER')
  })
  check('representable-c0-and-del-physical-names-and-targets-refused', () => {
    for (const value of physicalControls) {
      const name = 'entry' + value
      writeFileSync(join(single, name), 'not trusted\n', {mode: 0o644})
      try {
        refuse(() => fullTreeDigest(single), 'RELEASE_PATH_CONTROL_CHARACTER')
        refuse(() => treeDigest(single), 'RELEASE_PATH_CONTROL_CHARACTER')
      } catch (error) {
        throw new Error('PHYSICAL_NAME_FIXTURE:' + value.charCodeAt(0) + ':' + JSON.stringify(readdirSync(single)), {cause: error})
      } finally {rmSync(join(single, name))}
      symlinkSync('safe' + value, join(single, 'a'))
      try {
        refuse(() => fullTreeDigest(single), 'RELEASE_LINK_CONTROL_CHARACTER')
        refuse(() => treeDigest(single), 'RELEASE_LINK_CONTROL_CHARACTER')
      } finally {unlinkSync(join(single, 'a'))}
    }
  })
  check('existing-full-tree-absolute-and-escaping-link-refusals', () => {
    writeFileSync(join(temporary, 'outside'), 'owned disposable outside bytes\n', {mode: 0o644})
    for (const [target, reason] of [['../outside', 'RELEASE_LINK_ESCAPES_ROOT'], [join(single, 'safe'), 'ABSOLUTE_RELEASE_LINK']]) {
      symlinkSync(target, join(single, 'a'))
      try {refuse(() => fullTreeDigest(single), reason)} finally {unlinkSync(join(single, 'a'))}
    }
  })
  check('contained-dotdot-prefix-name-is-covered-and-parent-link-refused', () => {
    writeFileSync(join(single, '..name'), 'contained owned bytes\n', {mode: 0o644})
    symlinkSync('..name', join(single, 'a'))
    try {assert.equal(fullTreeDigest(single).files, 3)} finally {unlinkSync(join(single, 'a'))}
    symlinkSync('..', join(single, 'a'))
    try {refuse(() => fullTreeDigest(single), 'RELEASE_LINK_ESCAPES_ROOT')} finally {unlinkSync(join(single, 'a'))}
  })
  check('legacy-excluded-record-stays-excluded-but-link-controls-refuse', () => {
    const excluded = join(ordinary, '.dsh-build/plugin-set.json')
    mkdirSync(dirname(excluded), {mode: 0o755})
    writeFileSync(excluded, 'ordinary excluded record\n', {mode: 0o644})
    assert.equal(treeDigest(ordinary).digest, goldenLegacy)
    unlinkSync(excluded); symlinkSync('../a.txt', excluded)
    assert.equal(treeDigest(ordinary).digest, goldenLegacy)
    unlinkSync(excluded); symlinkSync('../a.txt\n', excluded)
    try {refuse(() => treeDigest(ordinary), 'RELEASE_LINK_CONTROL_CHARACTER')} finally {unlinkSync(excluded)}
    rmSync(dirname(excluded), {recursive: true})
    assert.equal(fullTreeDigest(ordinary).digest, goldenFull)
  })
  const insideEvidence = join(ordinary, '..evidence')
  await assert.rejects(runGate('G1', {root: ordinary, evidenceDir: insideEvidence}),
    error => error.message === 'EVIDENCE_MUST_BE_OUTSIDE_CANDIDATE')
  assert.equal(existsSync(insideEvidence), false)
  checks.push('dotdot-prefix-evidence-name-inside-candidate-refuses-before-writes')

  // Private inline Python exercises only the task-owned archive and pilot APIs.
  // Handcrafted manifests use an independent canonical artifact encoder and correct
  // retained digest. No review candidate, package manager or fixture shell is run.
  const pythonSource = String.raw`
import contextlib, hashlib, importlib.util, io, json, os, sys, tarfile
from pathlib import Path
sys.dont_write_bytecode = True
base, ops = Path(sys.argv[1]), Path(sys.argv[2])
def load(name, path):
 spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
m=load('owned_archive_control_check',ops/'archive.py')
pilot=load('owned_pilot_control_check',ops/'pilot/pilot.py')
count=0
def expect(action, reason):
 global count
 try: action()
 except m.Refusal as error: assert str(error) in (reason if isinstance(reason,tuple) else (reason,)),(str(error),reason)
 else: raise AssertionError('expected archive refusal')
 count+=1
def expect_pilot(action, reason):
 global count
 try: action()
 except pilot.Refusal as error: assert str(error)==reason,(str(error),reason)
 else: raise AssertionError('expected pilot refusal')
 count+=1
controls=[chr(value) for value in list(range(32))+[127]]
source=base/'single'; out=base/'refused-package.tar'
for char in controls:
 expect(lambda:m.safe_name('entry'+char),'INVALID_ARTIFACT_PATH')
 expect(lambda:m.validate_links([{'path':'a','type':'l','target':'safe'+char,'mode':0o777}],'release'),'RELEASE_LINK_CONTROL_CHARACTER')
 expect(lambda:m.package(str(source)+char,out,'release','fixture','0'*40,{'synthetic':True}),'ARTIFACT_PATH_CONTROL_CHARACTER')
 expect(lambda:m.package(source,str(out)+char,'release','fixture','0'*40,{'synthetic':True}),'ARTIFACT_PATH_CONTROL_CHARACTER')
 expect_pilot(lambda:pilot.full_digest(str(source)+char),'RELEASE_PATH_CONTROL_CHARACTER')
 if char!='\0':
  name=source/('entry'+char); name.write_bytes(b'not trusted\n')
  try:
   expect(lambda:m.package(source,out,'release','fixture','0'*40,{'synthetic':True}),'INVALID_ARTIFACT_PATH')
   expect_pilot(lambda:pilot.full_digest(source),'UNSAFE_RELEASE_NAME')
  finally:name.unlink()
  link=source/'a';link.symlink_to('safe'+char)
  try:
   expect(lambda:m.package(source,out,'release','fixture','0'*40,{'synthetic':True}),'RELEASE_LINK_CONTROL_CHARACTER')
   expect_pilot(lambda:pilot.full_digest(source),'RELEASE_LINK_CONTROL_CHARACTER')
  finally:link.unlink()
 assert not out.exists()
for variant in ['expected','changed']:
 expect(lambda:m.package(base/variant,out,'release','fixture','0'*40,{'synthetic':True}),('INVALID_ARTIFACT_PATH','RELEASE_LINK_CONTROL_CHARACTER'))
 assert not out.exists()
canonical=lambda value:json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
digest=lambda data:hashlib.sha256(data).hexdigest()
def handcrafted(label, files, payloads, kind='release'):
 value={'schema':'prime-artifact-v1','kind':kind,'version':'malicious-fixture','source_commit':'0'*40,
  'build_recipe':{'synthetic':True},'files':files,'restore_authority':False}
 expected=digest(b'aukora-prime:artifact:v1\0'+canonical(value))
 value['artifact_digest']=expected
 path=base/'crafted-control.tar'
 with tarfile.open(path,'w',format=tarfile.USTAR_FORMAT) as archive:
  data=canonical(value);item=tarfile.TarInfo('prime-artifact.json');item.mode=0o644;item.size=len(data);archive.addfile(item,io.BytesIO(data))
  for row in files:
   item=tarfile.TarInfo(row['path']);item.mode=row['mode']
   if row['type']=='l':item.type=tarfile.SYMTYPE;item.linkname=row['target'];archive.addfile(item)
   else:data=payloads[row['path']];item.size=len(data);archive.addfile(item,io.BytesIO(data))
 return path,expected,digest(path.read_bytes())
safe_payload=b'synthetic safe bytes\n'
safe_row={'path':'safe','type':'f','sha256':digest(safe_payload),'size':len(safe_payload),'mode':0o644}
targets=[base/'refused-memory-restore',base/'refused-release-stage']
for target in targets:target.mkdir(mode=0o700)
def refused_roundtrip(files, payloads, reason):
 path,expected,archive_sha=handcrafted('controls',files,payloads)
 before={p.name for p in base.iterdir()}
 expect(lambda:m.verify(path,expected,archive_sha),reason)
 expect(lambda:m.restore(path,targets[0],expected,archive_sha),reason)
 expect(lambda:m.restore(path,targets[1],expected,archive_sha,release=True),reason)
 assert {p.name for p in base.iterdir()}==before
 assert all(not any(target.iterdir()) for target in targets)
for char in controls:
 # NUL is not a representable USTAR member name: prove its wire-string validator
 # directly above, and its JSON symlink target through the complete archive path.
 if char!='\0':
  name='bad'+char;payload=b'untrusted fixture\n'
  row={'path':name,'type':'f','sha256':digest(payload),'size':len(payload),'mode':0o644}
  refused_roundtrip([row],{name:payload},'INVALID_ARTIFACT_PATH')
 refused_roundtrip([safe_row,{'path':'a','type':'l','target':'safe'+char,'mode':0o777}],{'safe':safe_payload},'RELEASE_LINK_CONTROL_CHARACTER')
for name in ['../escape','/escape','a\\b','a//b','a/./b','./a','a/']:
 expect(lambda:m.safe_name(name),'INVALID_ARTIFACT_PATH')
for target in ['../escape','/escape']:
 expect(lambda:m.validate_links([{'path':'a','type':'l','target':target,'mode':0o777}],'release'),'RELEASE_LINK_ESCAPES_ROOT')
ordinary=base/'ordinary'; artifact=base/'ordinary.tar'
pack=m.package(ordinary,artifact,'release','fixture','0'*40,{'synthetic':True})
golden_artifact='bf2d8df866abc475b4c2f77bc89306bec9ad3ae910c21a0c66edaf5ad3c65192'
assert pack['artifact_digest']==golden_artifact
# Frozen during development against exact owned historical archive.py 8356623.
# This check has no runtime Git/object/checkout dependency.
golden_archive_sha256='847d92e5fdf69d754b384ed8223ddf666f5606b60208f7fd41d7174f1c107588'
assert pack['archive_sha256']==golden_archive_sha256
assert digest(artifact.read_bytes())==golden_archive_sha256
count+=3
assert m.verify(artifact,pack['artifact_digest'],pack['archive_sha256'])['kind']=='release'
stage=base/'ordinary-staged';stage.mkdir(mode=0o700)
result=m.restore(artifact,stage,pack['artifact_digest'],pack['archive_sha256'],release=True)
assert result['status']=='STAGED' and result['activation']=='NOT_PERFORMED'
assert os.readlink(stage/'node_modules/owned.mjs')=='.pnpm/owned.mjs'
assert (stage/'shell').stat().st_mode&0o111
assert (stage/'a.txt').read_bytes()==b'alpha\n'
for char in controls:
 expect(lambda:m.verify(str(artifact)+char,pack['artifact_digest']),'ARTIFACT_PATH_CONTROL_CHARACTER')
 expect(lambda:m.restore(artifact,str(targets[0])+char,pack['artifact_digest']),'ARTIFACT_PATH_CONTROL_CHARACTER')
 recipe=base/'recipe.json';recipe.write_text('{"synthetic":true}')
 original=sys.argv
 try:
  sys.argv=[str(ops/'archive.py'),'package','--root',str(ordinary),'--out',str(out),'--kind','release','--version','fixture','--commit','0'*40,'--recipe',str(recipe)+char]
  output=io.StringIO()
  with contextlib.redirect_stdout(output):code=m.main()
  assert code==1 and json.loads(output.getvalue())['reason']=='ARTIFACT_PATH_CONTROL_CHARACTER'
 finally:sys.argv=original
 count+=1
 assert not out.exists()
print(json.dumps({'assertions':count,'ordinary_staged':str(stage),'controls':len(controls),
 'historical_reference_commit':'8356623','artifact_digest':pack['artifact_digest'],
 'archive_sha256':pack['archive_sha256'],'ordinary_archive_unchanged':True,
 'physical_control_chars':len(controls)-1,'nul':'OS_FILENAME_AND_SYMLINK_TARGET_NOT_REPRESENTABLE; ROOT_AND_WIRE_VALIDATORS_TESTED'}))
`
  const result = spawnSync(python, ['-I', '-B', '-c', pythonSource, temporary, here], {
    encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024,
    env: {PATH: '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin', HOME: temporary, LANG: 'C', LC_ALL: 'C'}})
  assert.equal(result.error, undefined, 'owned Python fixture must complete')
  assert.equal(result.status, 0, result.stderr)
  pythonReport = JSON.parse(result.stdout)
  check('archive-package-verify-restore-stage-controls-and-no-writes', () => {
    assert.equal(pythonReport.controls, 33); assert.equal(pythonReport.physical_control_chars, 32)
    assert.equal(existsSync(join(temporary, 'refused-package.tar')), false)
    for (const name of ['refused-memory-restore', 'refused-release-stage']) assert.deepEqual(readdirSync(join(temporary, name)), [])
  })
  check('contained-pnpm-release-roundtrip-keeps-both-golden-digests', () => {
    assert.equal(fullTreeDigest(pythonReport.ordinary_staged).digest, goldenFull)
    assert.equal(treeDigest(pythonReport.ordinary_staged).digest, goldenLegacy)
  })
  check('ordinary-artifact-and-archive-match-frozen-historical-goldens', () => {
    assert.equal(pythonReport.historical_reference_commit, '8356623')
    assert.equal(pythonReport.artifact_digest, 'bf2d8df866abc475b4c2f77bc89306bec9ad3ae910c21a0c66edaf5ad3c65192')
    assert.equal(pythonReport.archive_sha256, '847d92e5fdf69d754b384ed8223ddf666f5606b60208f7fd41d7174f1c107588')
    assert.equal(pythonReport.ordinary_archive_unchanged, true)
  })
  console.log(JSON.stringify({status: 'PASS', checks: checks.length, archive_pilot_assertions: pythonReport.assertions,
    control_characters: controls.length, physical_control_characters: physicalControls.length,
    nul: pythonReport.nul, scope: 'owned disposable digest/archive controls only', prime_acceptance: 'PENDING',
    historical_reference_commit: pythonReport.historical_reference_commit, artifact_digest: pythonReport.artifact_digest,
    archive_sha256: pythonReport.archive_sha256,
    ordinary_archive_unchanged: pythonReport.ordinary_archive_unchanged,
    review_candidate_executed: false, network: 'NOT_USED', activation: 'NOT_PERFORMED'}))
} finally {
  rmSync(temporary, {recursive: true, force: true})
}
