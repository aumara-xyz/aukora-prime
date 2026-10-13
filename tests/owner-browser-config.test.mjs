// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic root configuration and staged source exercise browser join pins without an installation.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { readJsonStrictBytes } from '../plugins/aukora-aumlok/lib/strict-read.mjs'
import { recordProjection } from '../plugins/aukora-aumlok/lib/record-v3.mjs'
import { createIdentityGenesis, aukoraIdFromGenesis } from '../plugins/aukora-aumlok/lib/genesis.mjs'

const url = new URL('../packages/boundary-gate/src/browser-join.mjs', import.meta.url)
const source = fs.readFileSync(url, 'utf8'), file = '/etc/aukora-boundary-gate/browser-join.json'
const config = { version: 1, kind: 'aukora-browser-join/v1', app_origin: 'https://app.example.test',
  binding_record: '/home/aukora-host/genesis/state/aumlok/local-control.json' }
let sequence = 0
async function load(text = source) {
  const fixture = { value: structuredClone(config), reads: [], realpath: value => value }
  const key = 'owner-browser-config-' + ++sequence
  globalThis[key] = fixture
  const stub = body => 'data:text/javascript;base64,' + Buffer.from(body).toString('base64')
  const rewritten = text.replace("import fs from 'node:fs'", `import fs from '${stub(`export default { realpathSync: file => globalThis[${JSON.stringify(key)}].realpath(file) }`)}'`)
    .replace("import { readProtectedJson } from './owner-state.mjs'", `import { readProtectedJson } from '${stub(`export const readProtectedJson = file => { const f = globalThis[${JSON.stringify(key)}]; f.reads.push(file); if (f.error) throw f.error; return structuredClone(f.value) }`)}'`)
  try { fixture.module = await import(stub(rewritten + '\n// ' + key)); return fixture }
  finally { fixture.close = () => { delete globalThis[key] } }
}
async function exercise(text, run) {
  const fixture = await load(text)
  try { await run(fixture.module, fixture) } finally { fixture.close() }
}
function rejectsConfig(module, fixture, change, code) {
  fixture.value = structuredClone(config); change(fixture.value)
  assert.throws(() => module.browserJoinReader(file), { code })
}

test('root-selected join validates closed schema, canonical HTTPS authority and exact public record path', async () => {
  await exercise(source, (module, fixture) => {
    assert.equal(module.BROWSER_JOIN_FILE, file)
    for (const selected of ['relative.json', '/etc/../etc/aukora-boundary-gate/browser-join.json']) {
      assert.throws(() => module.browserJoinReader(selected), { code: 'browser-join:path' })
    }
    for (const change of [value => { value.extra = true }, value => { delete value.binding_record },
      value => { value.version = 2 }, value => { value.kind = 'other' }]) rejectsConfig(module, fixture, change, 'browser-join:shape')
    for (const origin of ['invalid', 'http://app.example.test', 'https://app.example.test/',
      'https://user@app.example.test', 'https://APP.example.test', 'https://app.example.test:444',
      'https://localhost', 'https://127.0.0.1', 'https://app.example.123']) {
      rejectsConfig(module, fixture, value => { value.app_origin = origin }, 'browser-join:origin')
    }
    for (const record of [null, 'local-control.json', '/home/../home/local-control.json', '/home/other.json']) {
      rejectsConfig(module, fixture, value => { value.binding_record = record }, 'browser-join:record-path')
    }
  })
})
test('join performs the protected read before returning, rereads every use and refuses changed or lost configuration', async () => {
  await exercise(source, (module, fixture) => {
    fixture.error = Object.assign(new Error('protected fixture'), { code: 'owner-state-unprotected' })
    assert.throws(() => module.browserJoinReader(file), { code: 'owner-state-unprotected' })
    fixture.error = undefined
    const read = module.browserJoinReader(file)
    assert.equal(fixture.reads.length, 2)
    assert.deepEqual(read(), config); assert.equal(fixture.reads.length, 3)
    fixture.value.app_origin = 'https://second.example.test'
    assert.throws(read, { code: 'browser-join:changed' })
    fixture.value = structuredClone(config)
    fixture.error = Object.assign(new Error('missing fixture'), { code: 'ENOENT' })
    assert.throws(read, { code: 'ENOENT' })
  })
})
test('public record reader reuses bounded strict bytes and the genesis projection; aliases and malformed records refuse', async t => {
  const directory = fs.mkdtempSync(path.join(process.cwd(), '.browser-config-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const recordFile = path.join(directory, 'local-control.json')
  const genesis = createIdentityGenesis({ genesisNonce: '1'.repeat(64), initialRootKeySetId: '2'.repeat(64), amendmentRuleDigest: '3'.repeat(64) })
  const record = { version: 3, publicRoot: { rootId: '4'.repeat(64), genesis: { ...genesis } } }
  fs.writeFileSync(recordFile, JSON.stringify(record), { mode: 0o600 })
  const module = await import(url)
  const read = module.bindingRecordReader(recordFile, { readJsonStrictBytes, recordProjection })
  assert.deepEqual(read(), { subject: aukoraIdFromGenesis(genesis), rootId: '4'.repeat(64) })
  record.publicRoot.genesis.genesisNonce = '5'.repeat(64)
  fs.writeFileSync(recordFile, JSON.stringify(record)); assert.notEqual(read().subject, aukoraIdFromGenesis(genesis))
  const alias = path.join(directory, 'alias'); fs.symlinkSync(recordFile, alias)
  assert.throws(module.bindingRecordReader(alias, { readJsonStrictBytes, recordProjection }), { code: 'browser-join:record-alias' })
  fs.writeFileSync(recordFile, ' '.repeat(32769)); assert.throws(read, /artifact:too-large/u)
  fs.writeFileSync(recordFile, '{"version":3,"version":3}'); assert.throws(read, /json:duplicate-key/u)
  fs.writeFileSync(recordFile, '{}'); assert.throws(read, /recordProjection needs a v3 record/u)
})
test('configuration guard removal fails the focused behavioral checks', async t => {
  const mutants = [
    ['canonical absolute config path', "if (!path.isAbsolute(file) || path.resolve(file) !== file) fail('browser-join:path')", '', (module) => assert.throws(() => module.browserJoinReader('relative.json'), { code: 'browser-join:path' })],
    ['closed root configuration', "Object.keys(value).sort().join(',') !== 'app_origin,binding_record,kind,version'", 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.extra = true }, 'browser-join:shape')],
    ['configuration version', 'value.version !== 1', 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.version = 2 }, 'browser-join:shape')],
    ['configuration domain', "value.kind !== 'aukora-browser-join/v1'", 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.kind = 'other' }, 'browser-join:shape')],
    ['HTTPS app origin', "url.protocol !== 'https:'", 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.app_origin = 'http://app.example.test' }, 'browser-join:origin')],
    ['canonical app origin', 'url.origin !== value.app_origin', 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.app_origin += '/' }, 'browser-join:origin')],
    ['portless app authority', ' || url.port', '', (module, fixture) => rejectsConfig(module, fixture, value => { value.app_origin += ':444' }, 'browser-join:origin')],
    ['DNS app authority', "!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z][a-z0-9-]*$/.test(url.hostname)", 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.app_origin = 'https://127.0.0.1' }, 'browser-join:origin')],
    ['absolute canonical binding path', '!path.isAbsolute(value.binding_record)\n      || path.resolve(value.binding_record) !== value.binding_record', 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.binding_record = 'local-control.json' }, 'browser-join:record-path')],
    ['canonical binding path', 'path.resolve(value.binding_record) !== value.binding_record', 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.binding_record = '/home/../home/local-control.json' }, 'browser-join:record-path')],
    ['public record filename', "path.basename(value.binding_record) !== 'local-control.json'", 'false', (module, fixture) => rejectsConfig(module, fixture, value => { value.binding_record = '/home/other.json' }, 'browser-join:record-path')],
    ['immediate protected read', 'const selected = JSON.stringify(read())', 'const selected = JSON.stringify({})', (module, fixture) => { fixture.error = Object.assign(new Error('fixture'), { code: 'owner-state-unprotected' }); assert.throws(() => module.browserJoinReader(file), { code: 'owner-state-unprotected' }) }],
    ['current protected read', 'const current = read();', 'const current = JSON.parse(selected);', (module, fixture) => { const read = module.browserJoinReader(file); fixture.error = Object.assign(new Error('fixture'), { code: 'ENOENT' }); assert.throws(read, { code: 'ENOENT' }) }],
    ['root configuration pin', "if (JSON.stringify(current) !== selected) fail('browser-join:changed');", '', (module, fixture) => { const read = module.browserJoinReader(file); fixture.value.app_origin = 'https://second.example.test'; assert.throws(read, { code: 'browser-join:changed' }) }],
    ['record aliases', "if (fs.realpathSync(file) !== file) fail('browser-join:record-alias')", '', (module, fixture) => { fixture.realpath = () => '/different/local-control.json'; assert.throws(module.bindingRecordReader('/alias', { readJsonStrictBytes: () => ({ value: {} }), recordProjection: () => ({ subject: 'public', rootId: 'public' }) }), { code: 'browser-join:record-alias' }) }],
    ['strict public record byte bound', '{ maxBytes: 32768 }', '{}', (module) => { module.bindingRecordReader('/public/local-control.json', { readJsonStrictBytes: (_file, options) => { assert.equal(options.maxBytes, 32768); return { value: {} } }, recordProjection: () => ({}) })() }],
    ['existing subject projection', 'recordProjection(readJsonStrictBytes(file, { maxBytes: 32768 }).value)', 'readJsonStrictBytes(file, { maxBytes: 32768 }).value', (module) => { const value = { subject: 'forged', rootId: 'forged' }; const read = module.bindingRecordReader('/public/local-control.json', { readJsonStrictBytes: () => ({ value }), recordProjection: () => ({ subject: 'derived', rootId: 'derived' }) }); assert.deepEqual(read(), { subject: 'derived', rootId: 'derived' }) }],
  ]
  for (const [name, before, after, run] of mutants) await t.test(name, async () => {
    assert.ok(source.includes(before), 'mutation preimage ' + name)
    await assert.rejects(exercise(source.replace(before, after), run), assert.AssertionError, 'removed protection must fail ' + name)
  })
  t.diagnostic(`SOURCE-ONLY browser configuration mutations: ${mutants.length}/${mutants.length} killed`)
})

const bootstrap = path.resolve('packages/boundary-gate/host/install/gate-bootstrap.py')
const generator = path.resolve('packages/boundary-gate/host/install/generate-manifest.py')
const python = String.raw`
import contextlib, copy, io, json, os, sys
request=json.loads(sys.stdin.read())
source=open(request['file'],encoding='utf8').read()
if 'before' in request:
 assert request['before'] in source, 'mutation preimage'
 source=source.replace(request['before'],request['after'],1)
g={'__file__':request['file'],'__name__':'browser_config_fixture'}
exec(compile(source,request['file'],'exec'),g)
def refused(fn,code):
 try: fn()
 except g['Refused'] as error:
  assert str(error)==code,(str(error),code)
 else: raise AssertionError('protection removed: '+code)
if request['mode']=='bootstrap':
 profile={'root':g['BROWSER_AUMLOK_ROOT'],'files':{name:'a'*64 for name in ['package.json','lib/record-v3.mjs','lib/strict-read.mjs','lib/additional.mjs']}}
 args=['serve','--home','/home/aukora-gate','--run','/run/aukora-gate','--target-root','/var/lib/aukora-boundary/targets','--gid','1']
 selected=args+['--passkey-setup',g['PASSKEY_SETUP'],'--browser-join',g['BROWSER_JOIN']]
 g['serve_arguments'](selected)
 profiles={'launcher':{'root':g['LAUNCHER_ROOT'],'files':g['LAUNCHER_SOURCE_PINS']},'owner_key':{'root':g['OWNER_KEY_ROOT'],'files':{name:g['OWNER_KEY_SOURCE_PINS'].get(name,'a'*64) for name in g['OWNER_KEY_FILES']}},'passkey_authority':{'root':g['PASSKEY_ROOTS']['passkey_authority'],'files':{name:'a'*64 for name in ['package.json','src/passkey-enrollment.mjs','src/webauthn.mjs']}},'passkey_contracts':{'root':g['PASSKEY_ROOTS']['passkey_contracts'],'files':{name:'a'*64 for name in ['package.json','src/runtime.mjs']}},'browser_aumlok':profile}
 action=request.get('action','all')
 if action in ('all','fixed'):
  refused(lambda:g['serve_arguments'](args+['--passkey-setup',g['PASSKEY_SETUP'],'--browser-join','/alternate/browser-join.json']),'launch-fixed-path')
 if action in ('all','setup'):
  refused(lambda:g['serve_arguments'](args+['--browser-join',g['BROWSER_JOIN']]),'browser-passkey-required')
 if action in ('all','root'):
  bad=copy.deepcopy(profile);bad['root']='/opt/other'
  refused(lambda:g['validate_passkey_profile']('browser_aumlok',bad),'passkey-profile')
 if action in ('all','files'):
  bad=copy.deepcopy(profile);del bad['files']['lib/strict-read.mjs']
  refused(lambda:g['validate_passkey_profile']('browser_aumlok',bad),'passkey-profile-source')
 if action in ('all','pair'):
  bad=copy.deepcopy(profiles);del bad['passkey_authority'];del bad['passkey_contracts']
  refused(lambda:g['parse_profiles'](bad),'browser-passkey-profile')
 if action in ('all','closure'):
  calls=[];g['verify_package']=lambda root,files:calls.append((root,files))
  g['verify_source_profiles']({'version':1,'profiles':{'browser_aumlok':profile}})
  assert calls==[(g['BROWSER_AUMLOK_ROOT'],profile['files'])], 'complete browser profile not verified'
 if action in ('all','dispatch'):
  g['launch_arguments']=lambda args:(g['ENTRY'],selected)
  g['node_environment']=lambda environment:{}
  g['verify_installation']=lambda:{'version':1,'profiles':{key:profiles[key] for key in ['passkey_authority','passkey_contracts']}}
  g['require_node_profile']=lambda manifest,entry:None
  g['os'].chdir=lambda path:None
  class Dispatched(Exception): pass
  def dispatch(*args): raise Dispatched('unverified profile dispatched')
  g['os'].execve=dispatch
  with contextlib.redirect_stderr(io.StringIO()):
   assert g['main']()==2,'missing profile allowed'
 print(json.dumps({'ok':True}))
else:
 s=g['SOURCE'];root=request['root']
 s['validate_signer_epochs']=lambda data:None
 s['validate_owner_key_profile']=lambda profile:profile
 s['parse_manifest']=lambda data:json.loads(data)
 g['staging_launcher_files']=lambda path:s['LAUNCHER_SOURCE_PINS']
 if request.get('installed'):s['BROWSER_AUMLOK_ROOT']=root+'/browser'
 argv=['generator','--package',root+'/gate','--signer-epochs',root+'/epochs.json','--output',root+'/manifest.json','--browser-aumlok',root+'/browser','--owner-key',root+'/owner','--launcher-checkout',root+'/launcher']
 if request.get('profiles',True):argv+=['--passkey-authority',root+'/authority','--passkey-contracts',root+'/contracts']
 sys.argv=argv
 with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()) as errors:result=g['main']()
 if request.get('error'):assert result==2 and request['error'] in errors.getvalue(),(result,errors.getvalue())
 else:
  assert result==0,errors.getvalue()
  manifest=json.load(open(root+'/manifest.json'))
  files=manifest['profiles']['browser_aumlok']['files']
  assert set(files)=={'package.json','lib/record-v3.mjs','lib/strict-read.mjs','lib/additional.mjs'},files
  assert manifest['profiles']['browser_aumlok']['root']==s['BROWSER_AUMLOK_ROOT']
  for name,digest in files.items():
   import hashlib
   assert hashlib.sha256(open(root+'/browser/'+name,'rb').read()).hexdigest()==digest
 print(json.dumps({'ok':True}))
`
function runPython(request) {
  return spawnSync('/usr/bin/python3', ['-I', '-S', '-c', python], { input: JSON.stringify(request), encoding: 'utf8' })
}
function passed(result) { assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).ok, true) }
function staging(t) {
  const root = fs.mkdtempSync(path.join(process.cwd(), '.browser-stage-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const write = (name, value = 'synthetic public source\n') => { const target = path.join(root, name); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, value) }
  write('epochs.json', '{}')
  for (const name of ['gate', 'owner', 'launcher', 'authority', 'contracts', 'browser']) fs.mkdirSync(path.join(root, name), { recursive: true })
  const pins = spawnSync('/usr/bin/python3', ['-I', '-S', '-c', 'import json,runpy,sys;g=runpy.run_path(sys.argv[1]);print(json.dumps([g["ENTRY"],*g["OPERATOR_ENTRIES"].values()]))', bootstrap], { encoding: 'utf8' })
  assert.equal(pins.status, 0, pins.stderr)
  for (const name of ['package.json', ...JSON.parse(pins.stdout)]) write('gate/' + name)
  write('owner/package.json')
  for (const name of ['package.json', 'src/passkey-enrollment.mjs', 'src/webauthn.mjs']) write('authority/' + name)
  for (const name of ['package.json', 'src/runtime.mjs']) write('contracts/' + name)
  for (const name of ['package.json', 'lib/record-v3.mjs', 'lib/strict-read.mjs', 'lib/additional.mjs']) write('browser/' + name)
  return root
}
test('bootstrap browser join fixes configuration and requires passkey setup, pinned profile and full inventory before dispatch', () => {
  passed(runPython({ file: bootstrap, mode: 'bootstrap' }))
})
test('staging generator includes the complete browser plugin using the existing inventory/hash mechanism', t => {
  passed(runPython({ file: generator, mode: 'generator', root: staging(t) }))
  passed(runPython({ file: generator, mode: 'generator', root: staging(t), profiles: false, error: 'staging-browser-passkey-required' }))
  passed(runPython({ file: generator, mode: 'generator', root: staging(t), installed: true, error: 'staging-installed-path' }))
})
test('bootstrap and staging browser protection removals fail their focused checks', async t => {
  const mutants = [
    ['fixed join configuration', bootstrap, 'bootstrap', 'fixed', 'require(value == fixed[name], "launch-fixed-path")', 'require(name == "--browser-join" or value == fixed[name], "launch-fixed-path")'],
    ['browser requires setup', bootstrap, 'bootstrap', 'setup', 'require("--browser-join" not in seen or "--passkey-setup" in seen, "browser-passkey-required")', 'pass'],
    ['fixed browser source root', bootstrap, 'bootstrap', 'root', 'and value["root"] == (BROWSER_AUMLOK_ROOT if name == "browser_aumlok" else PASSKEY_ROOTS[name])', 'and (name == "browser_aumlok" or value["root"] == PASSKEY_ROOTS[name])'],
    ['required browser source files', bootstrap, 'bootstrap', 'files', '{"package.json", "lib/record-v3.mjs", "lib/strict-read.mjs"} if name == "browser_aumlok"', 'set() if name == "browser_aumlok"'],
    ['browser requires passkey profiles', bootstrap, 'bootstrap', 'pair', 'require(set(PASSKEY_ROOTS) <= set(value), "browser-passkey-profile")', 'pass'],
    ['browser complete source verification', bootstrap, 'bootstrap', 'closure', 'verify_package(BROWSER_AUMLOK_ROOT, profile["files"])', 'pass'],
    ['dispatch requires browser profile', bootstrap, 'bootstrap', 'dispatch', 'require("browser_aumlok" in manifest.get("profiles", {}), "browser-profile-unconfigured")', 'pass'],
    ['staging browser requires passkey', generator, 'generator', 'pair', 'require(not options.browser_aumlok or options.passkey_authority is not None, "staging-browser-passkey-required")', 'pass'],
    ['staging excludes installed browser root', generator, 'generator', 'installed', 'SOURCE["BROWSER_AUMLOK_ROOT"], *SOURCE["PASSKEY_ROOTS"].values()', '*SOURCE["PASSKEY_ROOTS"].values()'],
    ['complete staged browser inventory', generator, 'generator', 'inventory', '"files": staging_inventory(staged)', '"files": {k:v for k,v in staging_inventory(staged).items() if name != "browser_aumlok" or k != "lib/additional.mjs"}'],
  ]
  for (const [name, selected, mode, action, before, after] of mutants) await t.test(name, st => {
    const request = { file: selected, mode, action, before, after }
    if (mode === 'generator') {
      request.root = staging(st)
      if (action === 'pair') Object.assign(request, { profiles: false, error: 'staging-browser-passkey-required' })
      if (action === 'installed') Object.assign(request, { installed: true, error: 'staging-installed-path' })
    }
    const result = runPython(request)
    assert.notEqual(result.status, 0, 'mutant survived ' + name)
    assert.match(result.stderr, /AssertionError|Dispatched/u, 'mutation must fail behavioral assertion ' + name)
    assert.doesNotMatch(result.stderr, /mutation preimage/u)
  })
  t.diagnostic(`SOURCE-ONLY browser bootstrap/staging mutations: ${mutants.length}/${mutants.length} killed`)
})
