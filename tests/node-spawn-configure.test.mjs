// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise private door writes and protected host configuration with isolated fixture roots.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync, createHash } from 'node:crypto'
import { createInvite, redeemInvite } from '../packages/invites/index.mjs'
import { randomSecretKey, publicKeyOf } from '../plugins/aukora-nostr/lib/event.mjs'
// Fixtures stand in for protected system paths. A login shell whose umask leaves group write on (Ubuntu's
// default 002) would make every directory this test creates look unprotected, so the mask is fixed here.
process.umask(0o022)
const here = path.dirname(fileURLToPath(import.meta.url)), repo = path.dirname(here)
const doorSource = fs.readFileSync(process.env.SPAWN_CONFIGURE_MODULE ?? path.join(repo, 'ops/node-spawn/configure.mjs'), 'utf8')
const hostSource = fs.readFileSync(path.join(repo, 'ops/node-spawn/configure-host.py'), 'utf8')
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(here, '.node-spawn-configure-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const write = (name, value) => { const file = path.join(dir, name); fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 }); fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value)); return file }
  return { dir, write }
}
async function doorModule(f, source = doorSource) {
  const stub = f.write('relay.mjs', 'export async function verifyClosed(){return {closed:globalThis.spawnClosed}}')
  const transformed = source.replace("'../buzz-relay/member.mjs'", JSON.stringify(pathToFileURL(stub).href))
    .replace("'./invite.mjs'", JSON.stringify(pathToFileURL(path.join(repo, 'ops/node-spawn/invite.mjs')).href))
    .replace("'../../packages/invites/index.mjs'", JSON.stringify(pathToFileURL(path.join(repo, 'packages/invites/index.mjs')).href))
    .replace("'../../packages/boundary-gate/src/vendor/signer-epochs.mjs'", JSON.stringify(pathToFileURL(path.join(repo, 'packages/boundary-gate/src/vendor/signer-epochs.mjs')).href))
  return import(pathToFileURL(f.write('configure.mjs', transformed)).href)
}
test('gate signer requires a private Ed25519 file and its exact validated epoch', async t => {
  const f = fixture(t), { verifyGateSigner } = await doorModule(f), oldHome = process.env.HOME
  process.env.HOME = f.dir
  const pair = generateKeyPairSync('ed25519'), digest = createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
  const key = f.write('receipt.pem', pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
  fs.chmodSync(key, 0o600)
  const value = { version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: digest }] }
  const epochs = f.write('epochs.json', value)
  try {
    verifyGateSigner(key, epochs)
    const cli = spawnSync(process.execPath, [path.join(f.dir, 'configure.mjs'), 'signer', key, epochs], { encoding: 'utf8', env: { ...process.env, HOME: f.dir } })
    assert.equal(cli.status, 0); assert.equal(cli.stdout, 'SIGNER_OK\n')
    f.write('epochs.json', { ...value, epochs: [{ epoch: 1, gate_pubkey_sha256: '00'.repeat(32) }] })
    assert.throws(() => verifyGateSigner(key, epochs), /SPAWN_GATE_SIGNER_EPOCH$/u)
    f.write('epochs.json', { ...value, epochs: [{ epoch: 2, gate_pubkey_sha256: digest }] })
    assert.throws(() => verifyGateSigner(key, epochs), /SPAWN_GATE_SIGNER_EPOCHS/u); f.write('epochs.json', value)
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const ecDigest = createHash('sha256').update(ec.publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
    const other = f.write('ec.pem', ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()); fs.chmodSync(other, 0o600)
    f.write('epochs.json', { ...value, epochs: [{ epoch: 1, gate_pubkey_sha256: ecDigest }] })
    assert.throws(() => verifyGateSigner(other, epochs), /SPAWN_GATE_SIGNER_TYPE/u); f.write('epochs.json', value)
    fs.chmodSync(key, 0o644); assert.throws(() => verifyGateSigner(key, epochs), /SPAWN_GATE_SIGNER_KEY/u); fs.chmodSync(key, 0o600)
    const link = path.join(f.dir, 'linked.pem'); fs.symlinkSync(key, link)
    assert.throws(() => verifyGateSigner(link, epochs), /SPAWN_GATE_SIGNER_KEY/u); fs.unlinkSync(link)
    fs.linkSync(key, link); assert.throws(() => verifyGateSigner(key, epochs), /SPAWN_GATE_SIGNER_KEY/u); fs.unlinkSync(link)
    const originalStat = fs.fstatSync
    fs.fstatSync = (...args) => new Proxy(originalStat(...args), { get: (target, field) => field === 'uid' ? process.getuid() + 1 : Reflect.get(target, field) })
    try { assert.throws(() => verifyGateSigner(key, epochs), /SPAWN_GATE_SIGNER_KEY/u) } finally { fs.fstatSync = originalStat }
    fs.chmodSync(f.dir, 0o777); assert.throws(() => verifyGateSigner(key, epochs), /SPAWN_GATE_SIGNER_KEY/u); fs.chmodSync(f.dir, 0o700)
  } finally { if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome }
})
test('door writes only the signed node leaf and refuses owner assertions, admission input and unsafe writes', async t => {
  const f = fixture(t), { writeDoor } = await doorModule(f)
  const rootKey = randomSecretKey(), memberKey = randomSecretKey(), root = publicKeyOf(rootKey)
  const invite = createInvite({ root, secretKey: rootKey, now: 1800000000 })
  const record = { chain: [{ invite, redemption: redeemInvite({ invite, secretKey: memberKey, now: 1800000000 }) }] }
  const config = f.write('config.json', { root }), admission = f.write('admission.json', record)
  const value = { channel: '00000000-0000-4000-8000-000000000001', sessionId: 'fixture-session' }
  const source = f.write('source.json', value), target = path.join(f.dir, 'door.json')
  writeDoor(source, target, config, admission)
  assert.ok(JSON.parse(fs.readFileSync(target)).admit[0] === publicKeyOf(memberKey), 'signed leaf selected')
  assert.equal(fs.statSync(target).mode & 0o777, 0o600)
  assert.throws(() => writeDoor(source, target, config, admission), error => error.code === 'EEXIST')
  for (const bad of [{ ...value, ownerPubkey: publicKeyOf(rootKey) }, { ...value, ownerPubkey: null },
    { ...value, admit: [publicKeyOf(memberKey)] }, { ...value, admit: 'bad' }, { ...value, extra: true },
    { ...value, channel: 'bad' }, { ...value, sessionId: '' }]) {
    f.write('source.json', bad)
    assert.throws(() => writeDoor(source, path.join(f.dir, 'bad.json'), config, admission), /SPAWN_DOOR_INVALID/u)
  }
  f.write('source.json', value); fs.chmodSync(f.dir, 0o755)
  assert.throws(() => writeDoor(source, path.join(f.dir, 'bad.json'), config, admission), /SPAWN_DOOR_CUSTODY/u)
  fs.chmodSync(f.dir, 0o700)
  const originalStat = fs.lstatSync
  for (const field of ['uid', 'isDirectory']) {
    fs.lstatSync = (...args) => {
      const st = originalStat(...args)
      return new Proxy(st, { get: (target, name) => name === field ? (field === 'uid' ? st.uid + 1 : () => false) : Reflect.get(target, name) })
    }
    try { assert.throws(() => writeDoor(source, path.join(f.dir, 'bad.json'), config, admission), /SPAWN_DOOR_CUSTODY/u) }
    finally { fs.lstatSync = originalStat }
  }
  record.chain[0].invite.sig = '00'.repeat(64); f.write('admission.json', record)
  assert.throws(() => writeDoor(source, path.join(f.dir, 'bad.json'), config, admission), /invites:signature/u)
})
test('acceptance uses fixture installed readers and requires closure plus an authenticated admitted query', async t => {
  const f = fixture(t), { acceptance } = await doorModule(f), release = path.join(f.dir, 'release')
  f.write('release/plugins/aukora-buzz-door/lib/index.mjs', `import fs from 'node:fs';
export const loadKey=p=>fs.readFileSync(p,'utf8'); export const loadConfig=p=>JSON.parse(fs.readFileSync(p,'utf8'));
export const RELAY_HTTP='http://localhost:12345'; export const httpAuthHeader=()=> 'fixture-authorization';`)
  const key = f.write('fixture-key', randomSecretKey()), config = f.write('fixture-door.json', { channel: 'fixture', sessionId: 'fixture-session', ownerPubkey: null })
  const originalFetch = globalThis.fetch, originalLog = console.log; let calls = 0, status = 200
  globalThis.fetch = async (_url, opts) => { calls++; assert.equal(opts.redirect, 'error'); assert.equal(opts.headers.Authorization, 'fixture-authorization'); assert.ok(opts.signal instanceof AbortSignal); return new Response('{}', { status }) }
  console.log = () => {}
  try {
    globalThis.spawnClosed = false; await assert.rejects(() => acceptance(release, key, config), /SPAWN_RELAY_NOT_CLOSED/u); assert.equal(calls, 0)
    globalThis.spawnClosed = true; status = 403; await assert.rejects(() => acceptance(release, key, config), /SPAWN_AUMA_NOT_ADMITTED/u)
    status = 200; await acceptance(release, key, config)
    for (const bad of [{ sessionId: '', ownerPubkey: null }, { sessionId: 'fixture', ownerPubkey: 'owner' }]) {
      f.write('fixture-door.json', bad); await assert.rejects(() => acceptance(release, key, config), /SPAWN_DOOR_INVALID/u)
    }
  } finally { globalThis.fetch = originalFetch; console.log = originalLog; delete globalThis.spawnClosed }
})
const probe = String.raw`
import json, os, stat, sys, types
from pathlib import Path
scope={'__name__':'fixture'}; exec(compile(Path(sys.argv[1]).read_text(),sys.argv[1],'exec'),scope)
base=Path(sys.argv[2]); scenario=sys.argv[3]; root=base/'root'; root.mkdir(mode=0o700)
def put(p,data=b'fixture'):
 p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data); return p
def expect(code,fn):
 try: fn()
 except ValueError as e: assert str(e)==code,'HOST_GUARD_CODE'; return
 raise AssertionError('HOST_GUARD_MISSING '+code)
def main(action):
 sys.argv=['fixture',action,str(cfg),str(root)]; return scope['main']()
config={name:str(put(root/(name+'.json'))) for name in ('offer','auma_offer','door_config','public_signer_epochs')}; config['release_commit']='a'*40
cfg=put(root/'config.json',json.dumps(config).encode()); target=root/'etc/settings'; scope['write'](target,b'good',root)
if scenario=='write':
 before=target.stat(); scope['write'](target,b'good',root); assert target.stat().st_mtime_ns==before.st_mtime_ns,'HOST_GUARD_REWRITE'; expect('SPAWN_CONFIG_CONFLICT',lambda:scope['write'](target,b'bad',root))
elif scenario in ('root-mode','parent-mode','file-mode'):
 p={'root-mode':root,'parent-mode':target.parent,'file-mode':target}[scenario]; p.chmod(0o777); expect('SPAWN_CONFIG_CUSTODY',lambda:scope['write'](target,b'good',root))
elif scenario=='hardlink':
 os.link(target,root/'other'); expect('SPAWN_CONFIG_CUSTODY',lambda:scope['checked'](target)); expect('SPAWN_CONFIG_INPUT',lambda:scope['read'](target))
elif scenario=='nofollow':
 link=root/'link'; link.symlink_to(target)
 try: scope['read'](link)
 except OSError: pass
 else: raise AssertionError('HOST_GUARD_NOFOLLOW')
elif scenario=='read-size':
 put(target,b' '*262145); expect('SPAWN_CONFIG_INPUT',lambda:scope['read'](target))
elif scenario in ('owner','file-type','dir-type','read-type','read-length'):
 original=Path.lstat if scenario in ('owner','file-type','dir-type') else os.fstat
 def metadata(*args,**kwargs):
  v=original(*args,**kwargs); d={k:getattr(v,k) for k in ('st_uid','st_mode','st_nlink','st_size')}
  if scenario=='owner': d['st_uid']+=1
  elif scenario=='read-length': d['st_size']+=1
  else: d['st_mode']=stat.S_IFREG|0o600 if scenario=='dir-type' else stat.S_IFIFO|0o600
  return types.SimpleNamespace(**d)
 if scenario in ('owner','file-type','dir-type'):
  Path.lstat=metadata; expect('SPAWN_CONFIG_CUSTODY',lambda:scope['checked'](root if scenario=='dir-type' else target,scenario=='dir-type'))
 else:
  os.fstat=metadata; expect('SPAWN_CONFIG_INPUT',lambda:scope['read'](target))
elif scenario=='exclusive':
 original=Path.exists; Path.exists=lambda p:False if p==target else original(p)
 try: scope['write'](target,b'bad',root)
 except FileExistsError: pass
 else: raise AssertionError('HOST_GUARD_EXCLUSIVE')
elif scenario=='config-custody':
 cfg.chmod(0o666); expect('SPAWN_CONFIG_CUSTODY',lambda:main('phase'))
elif scenario=='root-link':
 link=base/'linked-root'; link.symlink_to(root); sys.argv=['fixture','phase',str(cfg),str(link)]; expect('SPAWN_ROOT_INVALID',scope['main'])
elif scenario=='resume':
 main('mark-1'); main('phase'); put(Path(config['offer']),b'changed'); expect('SPAWN_RESUME_CONFLICT',lambda:main('phase'))
elif scenario.startswith('resume-'):
 for home,key in [('aukora-member/.config/aukora-node','node-key'),('aukora-host/.config/aukora-buzz','auma.key')]:
  for name in (key,'spawn-config.json','offer.json','admission.json'): put(root/'home'/home/name)
 put(root/'home/aukora-host/.config/aukora-buzz/door.json'); put(root/'etc/aukora-genesis/release.env')
 for number in range(1,9): main('mark-'+str(number))
 targets={'resume-key':'home/aukora-member/.config/aukora-node/node-key','resume-admission':'home/aukora-member/.config/aukora-node/admission.json','resume-door':'home/aukora-host/.config/aukora-buzz/door.json','resume-env':'etc/aukora-genesis/release.env'}
 put(root/targets[scenario],b'changed'); expect('SPAWN_RESUME_CONFLICT',lambda:main('phase'))
elif scenario in ('commit','release'):
 record=put(root/'opt/aukora-genesis/release-aaaaaaa/.dsh-build/genesis-artifacts.json',json.dumps({'producer':{'genesisCommit':('b'*40 if scenario=='commit' else 'a'*40)}}).encode())
 if scenario=='commit': expect('SOURCE_RELEASE_MISMATCH',lambda:main('release-env'))
 else: main('release-env'); assert b'AUKORA_RECORD_SHA=' in (root/'etc/aukora-genesis/release.env').read_bytes(),'HOST_GUARD_RECORD'
elif scenario=='group':
 for unit in ('aukora-boundary-gate.service','aukora-genesis.service','aukora-selfcheck.service','aukora-selfcheck-periodic.service','aukora-selfcheck.timer'): put(root/'opt/aukora-genesis/src/packages/boundary-gate/host/systemd'/unit,b'Group=SKGATE_GID\n')
 put(root/'etc/group',b'skgate:x:bad:\n'); expect('SPAWN_GATE_GROUP_REQUIRED',lambda:main('units'))
elif scenario.startswith('prereq'):
 required=['usr/bin/openshell','usr/bin/openshell-gateway','etc/sudoers.d/aukora-boundary','etc/aukora-boundary-gate/owner-state.json','etc/aukora-boundary-gate/openshell-workspace.json','etc/aukora-boundary-gate/openshell-inventory.json']+['etc/systemd/system/'+n+'.service' for n in ('aukora-auma-local-deny','aukora-auma-podman','aukora-openshell-gateway','aukora-auma-sandbox')]
 for name in required: put(root/name)
 for name in ('receipt-ed25519.pem','owner-secret.json'): put(root/'home/aukora-gate'/name)
 for name in ('subuid','subgid'): put(root/'etc'/name,b'auma:165536:65536\n')
 dirs=['home/aukora-host/genesis/state','home/aukora-host/genesis/support','var/lib/aukora-boundary/targets']
 for name in dirs: (root/name).mkdir(parents=True)
 if scenario=='prereq-missing': (root/required[0]).unlink(); expect('SPAWN_HOST_PREREQUISITES_REQUIRED',lambda:main('prerequisites'))
 elif scenario=='prereq-custody': (root/required[0]).chmod(0o666); expect('SPAWN_CONFIG_CUSTODY',lambda:main('prerequisites'))
 elif scenario=='prereq-signer': (root/'home/aukora-gate/owner-secret.json').unlink(); expect('SPAWN_GATE_SIGNER_REQUIRED',lambda:main('prerequisites'))
 elif scenario=='prereq-range': put(root/'etc/subuid',b'auma:1:65536\n'); expect('SPAWN_AUMA_RANGE_REQUIRED',lambda:main('prerequisites'))
 elif scenario=='prereq-state': (root/dirs[0]).chmod(0o777); expect('SPAWN_HOST_PREREQUISITES_REQUIRED',lambda:main('prerequisites'))
 elif scenario=='prereq-type': (root/dirs[0]).rmdir(); put(root/dirs[0]); expect('SPAWN_HOST_PREREQUISITES_REQUIRED',lambda:main('prerequisites'))
 else: main('prerequisites')
else: raise AssertionError('HOST_GUARD_SCENARIO')
`
function hostCheck(t, source, scenario) {
  const f = fixture(t), helper = f.write('configure-host.py', source)
  return spawnSync('/usr/bin/python3', ['-I', '-S', '-c', probe, helper, f.dir, scenario], { encoding: 'utf8', timeout: 10000 })
}
test('host configuration guards protected writes, input snapshots, resume bindings and prerequisites', t => {
  for (const scenario of ['write', 'root-mode', 'parent-mode', 'file-mode', 'hardlink', 'nofollow', 'read-size',
    'owner', 'file-type', 'dir-type', 'read-type', 'read-length', 'exclusive', 'config-custody', 'root-link', 'resume',
    'resume-key', 'resume-admission', 'resume-door', 'resume-env', 'commit', 'release', 'group',
    'prereq', 'prereq-missing', 'prereq-custody', 'prereq-signer', 'prereq-range', 'prereq-state', 'prereq-type']) {
    const result = hostCheck(t, hostSource, scenario); assert.equal(result.status, 0, `${scenario}: ${result.stderr}`)
  }
})
test('host protection removals fail the relevant scenario', t => {
  const mutations = [
    ['owner', 'info.st_uid != os.geteuid()', 'False', 'owner'], ['mode', 'info.st_mode & 0o022', 'False', 'file-mode'],
    ['file-type', 'stat.S_ISREG(info.st_mode)', 'True', 'file-type'], ['directory-type', 'stat.S_ISDIR(info.st_mode)', 'True', 'dir-type'],
    ['link-count', 'info.st_nlink != 1', 'False', 'hardlink'], ['nofollow', ' | os.O_NOFOLLOW', '', 'nofollow'],
    ['read-size', 'info.st_size > 262144', 'False', 'read-size'], ['read-type', 'not stat.S_ISREG(info.st_mode)', 'False', 'read-type'],
    ['read-length', 'if len(data) != info.st_size:', 'if False:', 'read-length'], ['exclusive', ' | os.O_EXCL', '', 'exclusive'],
    ['root-custody', '    checked(root, True)', '', 'root-mode'], ['conflict', 'if read(path) != data:', 'if False:', 'write'],
    ['config-custody', '    checked(config_path)', '', 'config-custody'], ['resume', 'if read(marker) != binding(config_path, config, root, number):', 'if False:', 'resume'],
    ['root-link', 'if not root.is_absolute() or str(root) != os.path.realpath(root):', 'if False:', 'root-link'],
    ['key-binding', 'if phase >= 2:', 'if False:', 'resume-key'], ['record-binding', 'if phase >= 3:', 'if False:', 'resume-admission'],
    ['door-binding', 'if phase >= 4:', 'if False:', 'resume-door'], ['env-binding', 'if phase >= 7:', 'if False:', 'resume-env'],
    ['commit', "if metadata.get('producer', {}).get('genesisCommit') != commit:", 'if False:', 'commit'],
    ['group', 'if len(groups) != 1 or not groups[0].isdigit():', 'if False:', 'group'],
    ['prerequisite-custody', '            checked(destination(name))', '', 'prereq-custody'],
    ['signer-presence', "                read(destination('/home/aukora-gate/' + name))", '                None', 'prereq-signer'],
    ['auma-range', "if read(destination('/etc/' + name)).decode().splitlines().count('auma:165536:65536') != 1:", 'if False:', 'prereq-range'],
    ['state-directory', 'if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:', 'if False:', 'prereq-type'],
  ]
  for (const [name, before, after, scenario] of mutations) {
    assert.ok(hostSource.includes(before), `missing mutation ${name}`)
    const result = hostCheck(t, hostSource.replaceAll(before, after), scenario)
    assert.notEqual(result.status, 0, `survived ${name}`); assert.match(result.stderr, /AssertionError: HOST_GUARD_/u, `non-regression ${name}: ${result.stderr}`)
  }
  t.diagnostic(`HOST MUTATIONS ${mutations.length}/${mutations.length} KILLED`)
})
if (process.argv.includes('--mutations')) test('door protection removals fail their regression', t => {
  const f = fixture(t), mutations = [
    ['admission', 'value.admit.length !== 0', 'false'], ['owner', "!['channel', 'admit', 'sessionId'].includes(key)", "!['channel', 'admit', 'sessionId', 'ownerPubkey'].includes(key)"],
    ['channel', "!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.channel)", 'false'],
    ['session', "typeof value.sessionId !== 'string' || !value.sessionId.trim()", 'false'],
    ['parent-owner', 'parent.uid !== process.getuid()', 'false'], ['parent-directory', '!parent.isDirectory()', 'false'],
    ['private-parent', '(parent.mode & 0o077)', 'false'], ['exclusive', ' | fs.constants.O_EXCL', ''],
    ['signed-record', 'verifyRecord({ root: config.root, record }).member', 'record.chain.at(-1).redemption.pubkey'],
    ['closed-relay', 'if (!(await verifyClosed()).closed)', 'if (false)'], ['admitted-query', 'if (response.status !== 200)', 'if (false)'],
    ['acceptance-config', 'if (!config.sessionId || config.ownerPubkey != null)', 'if (false)'],
    ['query-auth', 'Authorization: installed.httpAuthHeader({ url, body, secretKeyHex: key })', "Authorization: ''"],
    ['signer-owner', 'st.uid !== uid || (st.mode & 0o777)', 'false || (st.mode & 0o777)'],
    ['signer-mode', '(st.mode & 0o777) !== 0o600', 'false'], ['signer-link-count', 'st.nlink !== 1 || st.uid', 'false || st.uid'],
    ['signer-type', "key.asymmetricKeyType !== 'ed25519'", 'false'],
    ['signer-epoch', 'if (!epochs.epochs.some(row => row.gate_pubkey_sha256 === digest))', 'if (false)'],
    ['signer-nofollow', 'fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK', 'fs.constants.O_RDONLY | fs.constants.O_NONBLOCK'],
    ['signer-parents', '(st.mode & 0o022)', 'false'],
  ]
  for (const [name, before, after] of mutations) {
    assert.ok(doorSource.includes(before), `missing mutation ${name}`)
    let mutant = doorSource.replaceAll(before, after)
    if (name === 'owner') mutant = mutant.replace('value.ownerPubkey !== undefined && value.ownerPubkey !== null', 'false')
    const file = f.write('mutant.mjs', mutant)
    const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern=^(gate signer|door writes|acceptance uses)', fileURLToPath(import.meta.url)], { encoding: 'utf8', timeout: 10000, env: { ...process.env, SPAWN_CONFIGURE_MODULE: file } })
    assert.equal(result.status, 1, `survived ${name}`); assert.match(result.stdout, /not ok \d+ - /u, `no regression ${name}`); assert.doesNotMatch(result.stdout + result.stderr, /SyntaxError/u)
  }
  t.diagnostic(`DOOR MUTATIONS ${mutations.length}/${mutations.length} KILLED`)
})
