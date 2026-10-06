// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only synthetic checks. Root metadata is simulated in memory; files remain private user fixtures.
// node --test packages/boundary-gate/checks/host-startup-summary.mjs
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { generateKeyPairSync, createHash, sign } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import { parseTrustedOwnerState } from '../host/owner-state.mjs'
import { readRedactedGateSummary } from '../host/redacted-summary.mjs'

const fixtureRoot = path.join(os.homedir(), '.aukora-h-startup-fixtures')
const rootInfo = fs.lstatSync(fixtureRoot)
assert(rootInfo.isDirectory() && rootInfo.uid === process.getuid() && (rootInfo.mode & 0o777) === 0o700,
  'precreate only the approved new private fixture root; never use repository or shared tmp fixtures')
const run = fs.mkdtempSync(path.join(fixtureRoot, 'source-'))
fs.chmodSync(run, 0o700)
const url = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`
const source = name => fs.readFileSync(new URL(name, import.meta.url), 'utf8')
let serial = 0
function replaceOnce(text, before, after) {
  assert.equal(text.split(before).length, 2, 'exact mutation/import preimage')
  return text.replace(before, after)
}
const p256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' })
const state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + '1'.repeat(64),
  owner_root_spki_base64: p256.toString('base64'), owner_root_id: createHash('sha256').update(p256).digest('hex'),
  owner_epoch: 1, registry_sha256: '2'.repeat(64), activation_sha256: '3'.repeat(64) }
const normalizedState = parseTrustedOwnerState(JSON.stringify(state))
const gatePin = 'a'.repeat(64)
const epochsText = JSON.stringify({ version: 1, kind: 'aukora-signer-epochs/v1', epochs: [
  { epoch: 1, gate_pubkey_sha256: 'b'.repeat(64) }, { epoch: 2, gate_pubkey_sha256: gatePin }] })
function profileFor(owner = normalizedState, over = {}) {
  return { version: 1, kind: 'aukora-boundary-gate-readiness/v1', ready: true, checked_at_ms: Date.now(),
    gate_pubkey_sha256: gatePin, owner_state_sha256: createHash('sha256').update(JSON.stringify(owner)).digest('hex'),
    owner_subject: owner.owner_subject, owner_root_id: owner.owner_root_id, owner_epoch: owner.owner_epoch,
    registry_sha256: owner.registry_sha256, activation_sha256: owner.activation_sha256,
    ledger: { entries: 1, head: 'c'.repeat(64) },
    consumed_effects: { retained: 0, unresolved: 0, applying: 0, incomplete: 0, conflict: 0 }, ...over }
}
function readinessSource(ownerModule, publicModule, mutant) {
  let code = source('../host/readiness.mjs')
  code = replaceOnce(code, "from '../src/vendor/signer-epochs.mjs'", `from '${new URL('../src/vendor/signer-epochs.mjs', import.meta.url).href}'`)
  code = replaceOnce(code, "from './owner-state.mjs'", `from '${ownerModule}'`)
  code = replaceOnce(code, "from './protected-public-data.mjs'", `from '${publicModule}'`)
  if (mutant) code = replaceOnce(code, mutant[0], mutant[1])
  return code
}
async function readinessModule(control = {}, mutant) {
  const key = `__hReadiness${serial++}`; globalThis[key] = control
  control.ownerReads = 0; control.pinReads = 0
  const ownerModule = url(`import {parseTrustedOwnerState} from '${new URL('../host/owner-state.mjs', import.meta.url).href}';
    export function readOwnerState(){const c=globalThis.${key};const n=++c.ownerReads;return parseTrustedOwnerState(JSON.stringify(c.owner ? c.owner(n) : ${JSON.stringify(state)}));}`)
  const publicModule = url(`export function readProtectedPublicText(file,maximum){const c=globalThis.${key};const n=++c.pinReads;
    if(file!=='/etc/aukora-boundary-gate/signer-epochs.json'||maximum!==16384) throw Error('wrong protected pin path');
    return c.pin ? c.pin(n) : ${JSON.stringify(epochsText)};}`)
  return import(url(readinessSource(ownerModule, publicModule, mutant)))
}

test('full readiness profile rejects coarse success, wrong owner/pin, stale time, unresolved work and open shapes', async () => {
  const check = await readinessModule(), binding = check.readGateReadinessBinding(), at = 1000
  const valid = profileFor(normalizedState, { checked_at_ms: at })
  const window = { startedAtMs: at, finishedAtMs: at }
  assert.equal(check.validateGateReadiness(valid, binding, window).ready, true)
  assert.equal(binding.gate_pubkey_sha256, gatePin); assert.equal(binding.signer_epoch, 2)
  assert.equal(binding.owner_state_sha256, valid.owner_state_sha256)
  const invalid = [{ ok: true }, Promise.resolve(valid), () => valid, [], { ...valid, extra: true }, { ...valid, [Symbol('extra')]: true },
    { ...valid, ready: false }, { ...valid, checked_at_ms: -0 }, { ...valid, checked_at_ms: at - 1 }, { ...valid, checked_at_ms: at + 1 },
    { ...valid, gate_pubkey_sha256: 'b'.repeat(64) }, { ...valid, owner_state_sha256: 'd'.repeat(64) },
    { ...valid, ledger: { entries: -0, head: 'GENESIS' } }, { ...valid, ledger: { entries: 1, head: 'GENESIS' } },
    { ...valid, ledger: { entries: 1, head: 'c'.repeat(64), extra: true } },
    { ...valid, consumed_effects: { ...valid.consumed_effects, retained: -0 } },
    { ...valid, consumed_effects: { ...valid.consumed_effects, extra: 0 } }, { ...valid, then() {} }]
  for (const field of ['owner_subject', 'owner_root_id', 'owner_epoch', 'registry_sha256', 'activation_sha256'])
    invalid.push({ ...valid, [field]: field === 'owner_epoch' ? 2 : 'mismatch' })
  for (const field of ['unresolved', 'applying', 'incomplete', 'conflict'])
    invalid.push({ ...valid, consumed_effects: { ...valid.consumed_effects, [field]: 1 } })
  let invoked = false
  invalid.push(Object.defineProperty({ ...valid }, 'ready', { enumerable: true, get() { invoked = true; return true } }))
  invalid.push({ ...valid, ledger: Object.defineProperty({ entries: 1 }, 'head', { enumerable: true, get() { invoked = true; return 'c'.repeat(64) } }) })
  for (const value of invalid) assert.throws(() => check.validateGateReadiness(value, binding, window), /gate-readiness:unavailable/u)
  assert.equal(invoked, false, 'response accessors must never run')
  assert.throws(() => check.validateGateReadiness(valid, { ...binding }, window), /unavailable/u, 'caller-created bindings do not establish trust')
  assert.throws(() => check.validateGateReadiness(valid, binding, { startedAtMs: 0, finishedAtMs: 5001 }), /unavailable/u)
  for (const descriptor of [{ value() {}, configurable: true }, { get() { invoked = true; return () => {} }, configurable: true }]) {
    Object.defineProperty(Object.prototype, 'then', descriptor)
    try { assert.throws(() => check.validateGateReadiness(valid, binding, window), /unavailable/u) }
    finally { delete Object.prototype.then }
  }
  assert.equal(invoked, false, 'inherited then accessors must never run')
  const noPin = await readinessModule({}, ['|| profile.gate_pubkey_sha256 !== binding.gate_pubkey_sha256', ''])
  assert.equal(noPin.validateGateReadiness({ ...valid, gate_pubkey_sha256: 'b'.repeat(64) }, noPin.readGateReadinessBinding(), window).ready, true,
    'RED: removing current gate pin binding accepts an older registered key')
  console.log('RED control caught: removing independent current gate pin accepts a mismatched readiness profile')
})

test('readiness brackets fresh owner/pin reads and refuses owner or registry drift', async () => {
  const normal = {}, good = await readinessModule(normal)
  assert.equal(good.checkGateReadiness(() => profileFor()).ready, true)
  assert.equal(normal.ownerReads, 2); assert.equal(normal.pinReads, 2)
  const changedOwner = parseTrustedOwnerState(JSON.stringify({ ...state, registry_sha256: '9'.repeat(64) }))
  const ownerDrift = await readinessModule({ owner: n => n === 1 ? state : changedOwner })
  assert.throws(() => ownerDrift.checkGateReadiness(() => profileFor(changedOwner)), /unavailable/u)
  const changedEpochs = epochsText.replace('b'.repeat(64), 'e'.repeat(64))
  const pinDrift = await readinessModule({ pin: n => n === 1 ? epochsText : changedEpochs })
  assert.throws(() => pinDrift.checkGateReadiness(() => profileFor()), /unavailable/u, 'registry drift refuses even if latest key stays the same')
  const noDrift = await readinessModule({ owner: n => n === 1 ? state : changedOwner },
    ['if (JSON.stringify(before) !== JSON.stringify(after)) refuse()', 'void 0'])
  assert.equal(noDrift.checkGateReadiness(() => profileFor(changedOwner)).ready, true,
    'RED: removing before/after binding guard accepts owner state changing during verification')
  console.log('RED control caught: removing owner/pin bracket admits protected binding drift')
})

test('owner state preserves the existing closed eight-field protocol and rejects ambiguous data', () => {
  assert.deepEqual({ ...parseTrustedOwnerState(JSON.stringify(state, null, 2)) }, state)
  assert(Object.isFrozen(parseTrustedOwnerState(JSON.stringify(state))))
  for (const text of [JSON.stringify({ ...state, extra: true }), JSON.stringify({ ...state, owner_epoch: 0 }),
    JSON.stringify({ ...state, owner_root_id: '4'.repeat(64) }), JSON.stringify(state).replace('"owner_epoch":1', '"owner_epoch":1.00000000000000001'),
    JSON.stringify(state).replace('"version":1', '"version":1,"version":1'),
    JSON.stringify(state).replace('"version":1', '"version":1,"\\u0076ersion":1'),
    '\ufeff' + JSON.stringify(state), JSON.stringify(state).replace(/}$/, ',}'), '{}', '[]', 'null', '{"version":{}}'])
    assert.throws(() => parseTrustedOwnerState(text), /trusted-owner-state:unavailable/u)
})

function syntheticFs(control = {}) {
  const fdPaths = new Map()
  const metadata = (info, name) => {
    const result = Object.assign(Object.create(Object.getPrototypeOf(info)), info, { uid: 0 })
    if (result.isDirectory()) { result.mode = (result.mode & ~0o777) | 0o750; result.gid = process.getgid() }
    if (control.path === name) {
      if (control.owner) result.uid = 12345
      if (control.writable) result.mode |= 0o020
      if (control.hardlink) result.nlink = 2
    }
    return result
  }
  return new Proxy(fs, { get(target, key) {
    if (key === 'openSync') return (...args) => { const fd = target.openSync(...args); fdPaths.set(fd, String(args[0])); return fd }
    if (key === 'lstatSync') return name => metadata(target.lstatSync(name), String(name))
    if (key === 'fstatSync') return fd => {
      const result = metadata(target.fstatSync(fd), fdPaths.get(fd))
      if (control.changed && control.read) result.ctimeMs++
      if (control.fdOwner) result.uid = 12345
      return result
    }
    if (key === 'readSync') return (...args) => { const result = target.readSync(...args); control.read = true; return result }
    if (key === 'fchownSync') return () => {} // Never perform a real UID/group change in a source fixture.
    return target[key]
  } })
}

async function protectedModule(control, mutant) {
  const name = `__hFs${serial++}`
  globalThis[name] = syntheticFs(control)
  let code = replaceOnce(source('../host/protected-public-data.mjs'), "import fs from 'node:fs'", `import fs from '${url(`export default globalThis.${name}`)}'`)
  if (mutant) code = replaceOnce(code, mutant[0], mutant[1])
  return { code, module: await import(url(code)) }
}

test('protected public reads reject missing, writable, wrong-owner, links, size and mutation', async () => {
  const file = path.join(run, 'owner-state.json')
  fs.writeFileSync(file, JSON.stringify(state), { mode: 0o600, flag: 'wx' })
  const good = await protectedModule({})
  assert.equal(good.module.readProtectedPublicText(file), JSON.stringify(state))
  for (const control of [{ path: file, owner: true }, { path: file, writable: true }, { path: run, owner: true },
    { path: run, writable: true }, { path: file, hardlink: true }, { fdOwner: true }, { changed: true }]) {
    const checked = await protectedModule(control)
    assert.throws(() => checked.module.readProtectedPublicText(file), /protected-public-data:unavailable/u)
  }
  assert.throws(() => good.module.readProtectedPublicText(file, 1), /unavailable/u)
  assert.throws(() => good.module.readProtectedPublicText(path.join(run, 'missing')), /unavailable/u)
  const symlink = path.join(run, 'owner-link.json'); fs.symlinkSync(file, symlink)
  assert.throws(() => good.module.readProtectedPublicText(symlink), /unavailable/u)
  const hardlink = path.join(run, 'owner-hardlink.json'); fs.linkSync(file, hardlink)
  assert.throws(() => good.module.readProtectedPublicText(file), /unavailable/u)
  const unsafe = path.join(run, 'writable-state.json'); fs.writeFileSync(unsafe, JSON.stringify(state), { mode: 0o620, flag: 'wx' })
  const removed = await protectedModule({}, ['(before.mode & 0o022) !== 0', 'false'])
  assert.equal(removed.module.readProtectedPublicText(unsafe), JSON.stringify(state), 'RED: removing file write guard admits untrusted writable registry')
})

const binReadinessUrl = url(readinessSource(
  url(`export function readOwnerState(){return ${JSON.stringify(normalizedState)}}`),
  url(`export function readProtectedPublicText(){return ${JSON.stringify(epochsText)}}`)))
const stub = url(`
const f = new Proxy({}, {get:(_target,key)=>globalThis.__hBinFixture[key]});
function profile(ready,over={}){return {...${JSON.stringify(profileFor())},checked_at_ms:Date.now(),ready,...over};}
export function readOwnerState() { console.log('OWNERREAD'); if(f.registryBad) throw Error('fixture unavailable'); return {}; }
export function loadOwnerSecret() {console.log('OWNERSECRET');return {};}
export function rotateBearer() {console.log('ROTATE');return {};}
export function gateTargets(){return {};}
export function gateStore(){return {};}
export function createGate(options) { console.log(options.readOwnerState === readOwnerState ? 'TRUSTEDREADER' : 'NOREADER');
 return {targets:{},fp:'fixture',verify:()=>({ok:f.preverify}), startup:()=>{console.log('STARTUP');return {ok:f.startup};},
 readiness:f.missingReadiness ? undefined : ()=>{console.log('READY');const p=f.legacyReady ? {ok:true} : profile(f.ready,f.instanceOverride);return f.readinessAsync ? Promise.resolve(p) : p;},close:()=>console.log('CLOSE')}; }
export function ownerAuthorizationReadiness(options) {console.log('READY_READONLY');const expectedHome=process.argv[2]==='check-ready' ? '/home/aukora-gate' : '/fixture/home';if(options.home !== expectedHome || options.readOwnerState !== readOwnerState) throw Error('wrong host readiness binding');const p=f.readonlyLegacy ? {ok:true} : profile(f.readonlyReady ?? f.ready,f.readonlyOverride);return (f.readonlyAsync ?? f.readinessAsync) ? Promise.resolve(p) : p;}
export async function serveGate(){console.log('SERVE');return {proposeSocket:'fixture',ownerSocket:'fixture',port:null};}
export function openDb(){} export function verifyLedger(){} export function loadOrCreateKey(){} export function keyFingerprint(){}
export function verifyReceipt(){}
`)
function runBin(fixture, mutant, command = 'serve', args, missingExport = false) {
  let code = source('../bin/gate.mjs').replace(/^#![^\n]*\n/u, '')
  code = replaceOnce(code, "from '../host/readiness.mjs'", `from '${binReadinessUrl}'`)
  let selectedStub = stub
  if (missingExport) selectedStub = url(Buffer.from(stub.slice(stub.indexOf(',') + 1), 'base64').toString().replace('export function ownerAuthorizationReadiness(options)', 'function ownerAuthorizationReadiness(options)'))
  code = code.replace(/from '[.][^']+'/gu, `from '${selectedStub}'`)
  if (mutant) code = replaceOnce(code, mutant[0], mutant[1])
  const selectedArgs = args ?? (command === 'serve' ? ['--home', '/fixture/home', '--run', '/fixture/run', '--target-root', '/fixture/targets'] : [])
  const harness = `globalThis.__hBinFixture=${JSON.stringify(fixture)}; process.argv=${JSON.stringify(['node', 'fixture', command, ...selectedArgs])};\n${code}`
  return spawnSync(process.execPath, ['--input-type=module'], { input: harness, encoding: 'utf8', timeout: 10000 })
}

test('ordinary entry passes the trusted reader and refuses before bearer rotation or sockets', () => {
  const ok = { preverify: true, startup: true, ready: true }
  const success = runBin(ok)
  assert.equal(success.status, 0, success.stderr)
  assert.match(success.stdout, /TRUSTEDREADER/u); assert.match(success.stdout, /SERVE/u)
  const missing = runBin({ ...ok, registryBad: true })
  assert.notEqual(missing.status, 0); assert.doesNotMatch(missing.stdout, /OWNERSECRET|ROTATE|SERVE/u)
  const broken = runBin({ ...ok, preverify: false })
  assert.notEqual(broken.status, 0); assert.doesNotMatch(broken.stdout, /ROTATE|STARTUP|SERVE/u)
  for (const fixture of [{ ...ok, ready: false }, { ...ok, missingReadiness: true }, { ...ok, readinessAsync: true },
    { ...ok, legacyReady: true }, { ...ok, instanceOverride: { gate_pubkey_sha256: 'b'.repeat(64) } }]) {
    const unready = runBin(fixture)
    assert.notEqual(unready.status, 0); assert.doesNotMatch(unready.stdout, /ROTATE|STARTUP|SERVE/u)
  }
  const failed = runBin({ ...ok, startup: false })
  assert.notEqual(failed.status, 0); assert.doesNotMatch(failed.stdout, /SERVE/u); assert.match(failed.stdout, /CLOSE/u)
  const removed = runBin({ ...ok, startup: false }, ["if (v?.ok !== true) throw new Error('boundary-gate:startup-verification-failed')", 'void 0'])
  assert.equal(removed.status, 0, removed.stderr); assert.match(removed.stdout, /SERVE/u, 'RED: removing startup verification admits failed startup')
  const noPreverify = runBin({ ...ok, preverify: false }, ["if (gate.verify().ok !== true) throw new Error('boundary-gate:startup-verification-failed')", 'void 0'])
  assert.equal(noPreverify.status, 0, noPreverify.stderr); assert.match(noPreverify.stdout, /ROTATE/u, 'RED: removing preverification rotates after a broken ledger')
  const noReady = runBin({ ...ok, readonlyReady: true, ready: false }, ["    checkGateReadiness(() => gate.readiness())\n    readOwnerState()", '    readOwnerState()'])
  assert.notEqual(noReady.status, 0, 'post-start readiness still refuses'); assert.match(noReady.stdout, /ROTATE|STARTUP/u,
    'RED: removing pre-start readiness admits bearer/startup work for failed owner readiness')
})

test('ordinary entry refuses missing/failed readonly readiness before secret loading or gate construction', () => {
  const ok = { preverify: true, startup: true, ready: true }
  for (const [fixture, missingExport] of [[ok, true], [{ ...ok, readonlyReady: false }, false], [{ ...ok, readonlyAsync: true }, false],
    [{ ...ok, readonlyLegacy: true }, false], [{ ...ok, readonlyOverride: { owner_state_sha256: 'd'.repeat(64) } }, false]]) {
    const refused = runBin(fixture, undefined, 'serve', undefined, missingExport)
    assert.notEqual(refused.status, 0)
    assert.match(refused.stdout, /OWNERREAD/u, 'fixed registry preflight runs before readonly core readiness')
    assert.doesNotMatch(refused.stdout, /OWNERSECRET|TRUSTEDREADER|NOREADER|ROTATE|STARTUP|SERVE|CLOSE/u,
      'readonly readiness refusal precedes every mutable constructor/secret API')
  }
  const removed = ["if (typeof gateCore.ownerAuthorizationReadiness !== 'function') throw new Error('boundary-gate:owner-authorization-unavailable')\n    checkGateReadiness(() => gateCore.ownerAuthorizationReadiness({ home, readOwnerState }))", 'void 0']
  for (const [fixture, missingExport] of [[ok, true], [{ ...ok, readonlyReady: false }, false]]) {
    const admitted = runBin(fixture, removed, 'serve', undefined, missingExport)
    assert.equal(admitted.status, 0, admitted.stderr)
    assert.match(admitted.stdout, /OWNERSECRET/u)
    assert.match(admitted.stdout, /TRUSTEDREADER/u, 'RED: removing readonly preflight reaches constructor writes')
    assert.match(admitted.stdout, /SERVE/u)
  }
  console.log('RED control caught: removing readonly readiness preflight admits mutable secret/constructor APIs')
})

test('fixed readonly readiness CLI refuses missing core API, false/async readiness and all caller arguments', () => {
  const ok = { ready: true }
  const success = runBin(ok, undefined, 'check-ready')
  assert.equal(success.status, 0, success.stderr); assert.match(success.stdout, /OWNER_AUTHORIZATION_READY/u)
  assert.doesNotMatch(success.stdout, /OWNERSECRET|ROTATE|TRUSTEDREADER|STARTUP|SERVE/u)
  for (const [fixture, missing] of [[{ ready: false }, false], [{ ready: true, registryBad: true }, false], [{ ready: true, readinessAsync: true }, false],
    [{ ready: true, readonlyLegacy: true }, false], [{ ready: true, readonlyOverride: { gate_pubkey_sha256: 'b'.repeat(64) } }, false], [ok, true]]) {
    const refused = runBin(fixture, undefined, 'check-ready', [], missing)
    assert.notEqual(refused.status, 0); assert.doesNotMatch(refused.stdout, /OWNER_AUTHORIZATION_READY|OWNERSECRET|ROTATE|TRUSTEDREADER|STARTUP|SERVE/u)
  }
  const missing = runBin(ok, undefined, 'check-ready', [], true)
  assert.doesNotMatch(missing.stdout, /OWNERREAD|READY_READONLY/u, 'missing API refusal precedes any state or key API')
  const override = runBin(ok, undefined, 'check-ready', ['--home', '/fixture/home'])
  assert.equal(override.status, 2); assert.doesNotMatch(override.stdout, /OWNERREAD|READY_READONLY/u)
})

function journal(name, events) {
  const home = path.join(run, name); fs.mkdirSync(home, { mode: 0o700 })
  const dbPath = path.join(home, 'gate.db'), db = new DatabaseSync(dbPath)
  db.exec('CREATE TABLE ledger(seq INTEGER PRIMARY KEY,at TEXT,event TEXT,proposal TEXT,target TEXT,base_sha TEXT,new_sha TEXT,detail TEXT,prev TEXT,hash TEXT,sig TEXT)')
  const key = generateKeyPairSync('ed25519')
  let head = 'GENESIS'
  events.forEach((event, index) => {
    const seq = index + 1, at = '2026-01-01T00:00:00.000Z', proposal = 'private-proposal-id', target = 'private-target', detail = '{"proof":"private-proof","note":"private-note"}'
    const hash = createHash('sha256').update(JSON.stringify([seq, at, event, proposal, target, null, null, detail, head])).digest('hex')
    db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(seq, at, event, proposal, target, null, null, detail, head, hash,
      sign(null, Buffer.from(hash, 'hex'), key.privateKey).toString('base64'))
    head = hash
  })
  const options = { dbPath, sourceId: 'private-source-id', publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    expectedKeySha256: createHash('sha256').update(key.publicKey.export({ type: 'spki', format: 'der' })).digest('hex') }
  return { home, db, head, options }
}

async function summaryModule(control = {}, signatureMutant = false, publicationMutant) {
  const protectedSource = await protectedModule(control)
  const name = `__hSummaryFs${serial++}`; globalThis[name] = syntheticFs(control)
  let code = source('../host/redacted-summary.mjs')
  code = replaceOnce(code, "import fs from 'node:fs'", `import fs from '${url(`export default globalThis.${name}`)}'`)
  code = replaceOnce(code, "from './protected-public-data.mjs'", `from '${url(protectedSource.code)}'`)
  code = replaceOnce(code, 'process.getuid() !== 0', 'false')
  const snapshotUrl = new URL('../../../scripts/aura/gate-snapshot.mjs', import.meta.url)
  let snapshot = fs.readFileSync(snapshotUrl, 'utf8')
  if (signatureMutant) snapshot = replaceOnce(snapshot, "if (!verify(null, Buffer.from(entry.hash, 'hex'), publicKeyOf(publicKey), signature))", 'if (false)')
  code = replaceOnce(code, "from '../../../scripts/aura/gate-snapshot.mjs'", `from '${url(snapshot)}'`)
  if (publicationMutant) code = replaceOnce(code, publicationMutant[0], publicationMutant[1])
  return import(url(code))
}

test('summary uses exact signed source, emits only diagnostic counts/head, and preserves last snapshot on failure', async () => {
  const fixture = journal('summary', ['gate-start', 'propose', 'propose', 'review-issued'])
  assert.equal(readRedactedGateSummary(fixture.options).selected_head.position, 4, 'actual static import uses the existing source verifier')
  const releaseRoot = path.join(run, 'release'); fs.mkdirSync(releaseRoot, { mode: 0o700 })
  const directory = path.join(releaseRoot, '.dsh-build'); fs.mkdirSync(directory, { mode: 0o700 })
  const summary = await summaryModule(), readerGid = process.getgid()
  const result = summary.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options, readerGid })
  assert.deepEqual(result.counts_by_event_type, { 'gate-start': 1, propose: 2, 'review-issued': 1 })
  assert.deepEqual(result.selected_head, { position: 4, hash: fixture.head })
  assert.equal(result.classification, 'diagnostic'); assert.equal(result.release_digest_coverage, 'excluded')
  assert.equal(result.grants_authority, false); assert.equal(result.freshness, 'selected-snapshot-only')
  const output = path.join(directory, 'host-ledger-summary.json'), before = fs.readFileSync(output, 'utf8')
  assert.equal(fs.statSync(output).mode & 0o777, 0o440)
  for (const secret of ['private-proposal-id', 'private-target', 'private-proof', 'private-note', 'private-source-id', fixture.options.expectedKeySha256])
    assert(!before.includes(secret))
  const forbidden = ['records', 'targets', 'details', 'proof', 'source', 'reason', 'verified_head']
  for (const field of forbidden) assert(!Object.hasOwn(result, field))
  fixture.db.prepare('UPDATE ledger SET sig=? WHERE seq=4').run(Buffer.alloc(64).toString('base64'))
  assert.throws(() => summary.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options, readerGid }), /unavailable/u)
  assert.equal(fs.readFileSync(output, 'utf8'), before, 'failed verification must preserve last selected snapshot')
  const removedSignature = await summaryModule({}, true)
  assert.equal(removedSignature.readRedactedGateSummary(fixture.options).selected_head.position, 4,
    'RED: removing exact snapshot signature verifier admits the corrupt signed source')
  fixture.db.close()
})

test('summary publication requires explicit existing protected directory and reader group', async () => {
  const fixture = journal('summary-refusals', ['gate-start']), readerGid = process.getgid()
  const releaseRoot = path.join(run, 'release-refusals'); fs.mkdirSync(releaseRoot, { mode: 0o700 })
  const summary = await summaryModule()
  assert.throws(() => summary.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options, readerGid }), /unavailable/u)
  const directory = path.join(releaseRoot, '.dsh-build'); fs.mkdirSync(directory, { mode: 0o700 })
  assert.throws(() => summary.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options }), /unavailable/u)
  assert.throws(() => summary.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options, readerGid: readerGid + 1 }), /unavailable/u)
  const unsafe = await summaryModule({ path: directory, writable: true })
  assert.throws(() => unsafe.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options, readerGid }), /unavailable/u)
  const output = path.join(directory, 'host-ledger-summary.json'); fs.symlinkSync(fixture.options.dbPath, output)
  assert.throws(() => summary.writeRedactedGateSummary({ releaseRoot, snapshotOptions: fixture.options, readerGid }), /unavailable/u)
  const unknown = journal('summary-unknown', ['private-event-identifier'])
  assert.throws(() => summary.readRedactedGateSummary(unknown.options), /unavailable/u)
  const missing = { ...fixture.options, dbPath: path.join(run, 'missing.db') }
  assert.throws(() => summary.readRedactedGateSummary(missing), /unavailable/u)
  fixture.db.close(); unknown.db.close()
})
