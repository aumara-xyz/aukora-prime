// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic installer records exercise claim selection and guard removals without installed files.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { projectRecordV3Control } from '../../../plugins/aukora-aumlok/lib/record-v3.mjs'
import '../src/owner-state.mjs'

const sourceUrl = new URL('../src/browser-passkey-claim.mjs', import.meta.url)
const source = fs.readFileSync(sourceUrl, 'utf8')
const url = text => 'data:text/javascript;base64,' + Buffer.from(text).toString('base64')
const origin = 'https://owner.example.test', appOrigin = 'https://app.example.test'
const recordFile = '/home/aukora-host/genesis/state/aumlok-binding/local-control.json'
const setupFile = '/etc/aukora-boundary-gate/passkey-setup.json', claimFile = '/var/lib/aukora-browser/passkey-claim.txt'
const joinFile = '/etc/aukora-boundary-gate/browser-join.json', dropinFile = '/etc/systemd/system/aukora-boundary-gate.service.d/browser-owner.conf'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const record = { version: 3, publicRoot: { rootId: 'a'.repeat(64), epoch: 0, boundAt: '2026-10-13T00:00:00.000Z',
  machines: [{ index: 0, ed25519: 'b'.repeat(64) }], revokedMachines: [] } }
const read = { value: record, bytes: Buffer.from(JSON.stringify(record)) }
const composition = `- id: aukora-aumlok\n  config:\n    directory: "/home/aukora-host/genesis/state/aumlok-binding"\n`
  + `- id: aukora-face-aumlok\n  config:\n    directory: "/home/aukora-host/genesis/state/aumlok-binding"\n`
  + `    browserBinding:\n      publicOrigin: "${appOrigin}"\n`
  + `      supportRoot: "/home/aukora-host/genesis/support"\n      stateRoot: "/home/aukora-host/genesis/state/home"\n`

let sequence = 0
async function load(text = source) {
  text = text.replace("import { DatabaseSync } from 'node:sqlite'", 'const DatabaseSync = globalThis.__browserClaimWorld.DatabaseSync')
  text = text.replace("import { mintPasskeyClaim, passkeySetup, readProtectedJson } from './owner-state.mjs'",
    `import { passkeySetup } from ${JSON.stringify(new URL('../src/owner-state.mjs', import.meta.url).href)};\nconst { mintPasskeyClaim, readProtectedJson } = globalThis.__browserClaimWorld`)
  text = text.replace("'/opt/aukora-aumlok/lib/strict-read.mjs'", JSON.stringify(url('export function readJsonStrictBytes(file, options) { globalThis.__browserClaimWorld.reads.push([file, options.maxBytes]); return globalThis.__browserClaimWorld.read }')))
  text = text.replace("'/opt/aukora-aumlok/lib/record-v3.mjs'", JSON.stringify(new URL('../../../plugins/aukora-aumlok/lib/record-v3.mjs', import.meta.url).href))
  return import(url(text + '\n// fixture ' + ++sequence))
}

async function world(exercise, text = source, changes = {}) {
  const files = new Map(), events = [], reads = [], opened = new Map()
  const pair = generateKeyPairSync('ed25519'), pub = pair.publicKey.export({ type: 'spki', format: 'pem' })
  const w = { files, events, reads, read, table: false, selected: false, enrolled: false, state: null, closed: 0, ...changes }
  const missing = () => { throw Object.assign(new Error('absent synthetic file'), { code: 'ENOENT' }) }
  const st = { uid: 0, mode: 0o600, nlink: 1, dev: 1, ino: 2, size: 44,
    isFile: () => true, isSymbolicLink: () => false }
  w.DatabaseSync = class {
    constructor(_file, options) { assert.equal(options.readOnly, true) }
    prepare(sql) { return { get: () => sql.includes("name='owner_browser_config'") ? w.table
      : sql.includes('FROM owner_browser_config') ? w.selected
      : sql.includes("event='owner-passkey-enrolled'") ? w.enrolled
      : sql.includes("name='owner_passkey_ceremony'") ? w.failed
      : sql.includes('SELECT failed') ? { failed: w.failed }
      : sql.includes("name='owner_passkey'") ? true : { state_text: w.state } } }
    close() { w.closed++ }
  }
  w.readProtectedJson = file => { events.push(['protected', file]); return JSON.parse(files.get(file)) }
  w.mintPasskeyClaim = args => {
    const code = 'x'.repeat(43)
    assert.equal(args.file, setupFile); assert.equal(args.claimFile, claimFile)
    if (files.has(setupFile) || files.has(claimFile)) throw new Error('exclusive-create')
    files.set(setupFile, JSON.stringify({ version: 1, kind: 'aukora-gate-passkey-setup/v1', gate: args.gate, node: args.node,
      origin: args.origin, rp_id: new URL(args.origin).hostname, binding: args.binding, claim_sha256: hash(code), expires_at_ms: Date.now() + 300000 }))
    files.set(claimFile, code + '\n'); events.push(['mint'])
  }
  const mocks = {
    realpathSync(file) { return (w.alias && file === recordFile) || (w.releaseAlias && file === '/synthetic/release') ? '/synthetic/alias' : file === '/synthetic/alias' ? '/synthetic/release' : file },
    lstatSync(file) { if (!files.has(file)) return missing(); return { ...st, ...(file === claimFile ? w.claimMetadata : {}) } },
    readFileSync(file) {
      if (typeof file === 'number') return files.get(opened.get(file))
      if (file === '/run/aukora-gate/receipt-ed25519.pub') return pub
      if (typeof file === 'string' && file.endsWith('/aukora-composition.patch.yml')) return composition
      return files.has(file) ? files.get(file) : missing()
    },
    openSync(file, flags) {
      if (w.noFollow && !(flags & fs.constants.O_NOFOLLOW)) { opened.set(99, file); return 99 }
      if (w.noFollow) throw Object.assign(new Error('link'), { code: 'ELOOP' })
      if (w.nonblock && !(flags & fs.constants.O_NONBLOCK)) { opened.set(99, file); return 99 }
      if (w.nonblock) throw Object.assign(new Error('blocked'), { code: 'EAGAIN' })
      opened.set(99, file); return 99
    },
    fstatSync() { return { ...st, ...w.openedMetadata } },
    closeSync(fd) { opened.delete(fd) },
  }
  const saved = Object.fromEntries(Object.keys(mocks).map(key => [key, fs[key]])), uid = process.getuid, version = Object.getOwnPropertyDescriptor(process,'version')
  globalThis.__browserClaimWorld = w
  Object.assign(fs, mocks); process.getuid = () => w.uid ?? 0
  Object.defineProperty(process,'version',{...version,value:w.version ?? version.value})
  try { const module = await load(text); return await exercise(module, w) }
  finally { Object.assign(fs, saved); process.getuid = uid; Object.defineProperty(process,'version',version); delete globalThis.__browserClaimWorld; assert.equal(opened.size, 0) }
}
const mint = (module, change = {}) => module.mintBrowserPasskeyClaim({ ownerOrigin: origin, appOrigin, release: '/synthetic/release', ...change })

test('browser-passkey-claim derives exact public control and prints a single owner fragment link', async () => world(async (m, w) => {
  assert.equal(m.BROWSER_BINDING_RECORD, recordFile)
  const current = await m.readCurrentBinding(), control = projectRecordV3Control({ record })
  assert.deepEqual(current, { subject: control.subject, control_digest: control.activeControlDigest,
    approval_key_did: control.approvalKeyDid, authorization_epoch: 1, source_sha256: hash(read.bytes) })
  assert.deepEqual(w.reads, [[recordFile, 32768]])
  const first = await mint(m), second = await mint(m)
  assert.equal(first, origin + '/owner/enroll#claim=' + 'x'.repeat(43)); assert.equal(second, first)
  assert.equal(w.events.filter(([event]) => event === 'mint').length, 1)
  const setup = JSON.parse(w.files.get(setupFile)), gate = setup.gate
  assert.equal(setup.node, hash('aukora-browser-node/v1\0' + gate)); assert.equal(setup.rp_id, 'owner.example.test')
  assert.equal(setup.binding.identity.subject, current.subject); assert.equal(setup.binding.identity.approval_key_did, current.approval_key_did)
  assert.ok(w.reads.every(([file]) => file === recordFile)); assert.equal(w.closed, 2)
}))

test('origins and installed composition refuse alternate RP, app, path and duplicate controller rows', async () => world(async m => {
  for (const bad of ['http://owner.example.test', 'https://owner.example.test:443', 'https://owner.example.test/', 'https://127.0.0.1', 'https://*.example.test', 'https://owner.example.test:444'])
    assert.throws(() => m.browserPasskeyOrigin(bad), /browser-passkey:origin/)
  m.verifyBrowserPasskeyComposition(composition, appOrigin)
  for (const text of [composition.replace('state/aumlok-binding', 'state/copied-binding'), composition.replace(appOrigin, origin), composition + '- id: aukora-aumlok\n', composition + '- id: aukora-face-aumlok\n'])
    assert.throws(() => m.verifyBrowserPasskeyComposition(text, appOrigin), /composition-binding/)
  await assert.rejects(() => mint(m, { appOrigin: origin }), /origins-not-separated/)
  await assert.rejects(() => mint(m, { release: '/synthetic/release/../release' }), /release-path/)
}))

test('root, exact public record, complete control, expiry and unchanged claim binding are required', async () => {
  await world(m => assert.rejects(() => mint(m), /root-required/), source, { uid: 1000 })
  await world(m => assert.rejects(() => mint(m), /node-version/), source, { version: 'v24.11.2' })
  await world(m => assert.rejects(() => mint(m), /release-path/), source, { releaseAlias: true })
  await world(m => assert.rejects(() => m.readCurrentBinding(), /binding-alias/), source, { alias: true })
  await world(async m => {
    for (const changed of [{ subject: 'bad' }, { activeControlDigest: 'bad' }, { approvalKeyDid: null }, { epoch: -1 }, { epoch: Number.MAX_SAFE_INTEGER }, { revoked: true }])
      assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), ...changed })), /binding-record/)
    const snapshot = m.browserBindingSnapshot(read, projectRecordV3Control), expected = { gate: 'c'.repeat(64), node: 'd'.repeat(64), origin, binding: m.browserPasskeyBinding(snapshot, origin, appOrigin) }
    const setup = { version: 1, kind: 'aukora-gate-passkey-setup/v1', ...expected, rp_id: 'owner.example.test', claim_sha256: hash('x'.repeat(43)), expires_at_ms: 1000 }
    assert.equal(m.savedBrowserPasskeyClaim(setup, 'x'.repeat(43) + '\n', expected, 999), 'x'.repeat(43))
    assert.throws(() => m.savedBrowserPasskeyClaim(setup, 'x'.repeat(43) + '\n', expected, 1000), /claim-expired/)
    for (const change of [{ node: 'e'.repeat(64) }, { gate: 'e'.repeat(64) }, { origin: 'https://other.example.test' }, { binding: { ...expected.binding, identity: { ...expected.binding.identity, subject: 'aukora:1:' + 'e'.repeat(64) } } }])
      assert.throws(() => m.savedBrowserPasskeyClaim(setup, 'x'.repeat(43) + '\n', { ...expected, ...change }, 999), /setup-changed/)
    assert.throws(() => m.savedBrowserPasskeyClaim(setup, 'z'.repeat(43) + '\n', expected, 999), /claim-changed/)
  })
})

test('enrollment and browser join selections cannot be replaced, including retained signed enrollment history', async () => {
  for (const changes of [{ table: true, selected: true }, { enrolled: true }, { state: '{}' }, { failed: true }])
    await world(m => assert.rejects(() => mint(m), /browser-join-selected|enrollment-closed/), source, changes)
  for (const [file, value] of [[joinFile, '{}'], [dropinFile, 'serve --browser-join /selected']])
    await world((m, w) => { w.files.set(file, value); return assert.rejects(() => mint(m), /browser-join-selected/) })
  await world((m, w) => { w.files.set(claimFile, 'x'.repeat(43) + '\n'); return assert.rejects(() => mint(m), /claim-without-setup/) })
})

test('saved claim has private root custody, one link, no aliases and the same protected descriptor', async () => {
  for (const changes of [{ uid: 501 }, { mode: 0o644 }, { nlink: 2 }, { size: 45 }, { isFile: () => false }, { isSymbolicLink: () => true }])
    await world(m => assert.rejects(() => mint(m), /claim-unprotected/), source, { claimMetadata: changes })
  for (const changes of [{ uid: 501 }, { mode: 0o644 }, { nlink: 2 }, { size: 45 }, { isFile: () => false }, { ino: 99 }, { dev: 99 }])
    await world(m => assert.rejects(() => mint(m), /claim-unprotected/), source, { openedMetadata: changes })
  await world(m => assert.rejects(() => mint(m), { code: 'ELOOP' }), source, { noFollow: true })
  await world(m => assert.rejects(() => mint(m), { code: 'EAGAIN' }), source, { nonblock: true })
})

if (process.argv.includes('--mutations')) test('browser-passkey-claim guard mutations fail their focused assertions', async t => {
  const mutations = [
    ['root', "process.getuid?.() !== 0", 'false', m => assert.rejects(() => mint(m), /root-required/), { uid: 1000 }],
    ['origin', "url.protocol !== 'https:'", 'false', m => assert.throws(() => m.browserPasskeyOrigin('http://owner.example.test'), /origin/)],
    ['separate origins', 'ownerOrigin === appOrigin', 'false', m => assert.rejects(() => mint(m, { appOrigin: origin }), /origins-not-separated/)],
    ['composition', '!text.includes(rows)', 'false', m => assert.throws(() => m.verifyBrowserPasskeyComposition(composition.replace(appOrigin, origin), appOrigin), /composition-binding/)],
    ['duplicate controller', "(text.match(/^- id: aukora-aumlok$/gmu) ?? []).length !== 1", 'false', m => assert.throws(() => m.verifyBrowserPasskeyComposition(composition + '- id: aukora-aumlok\n', appOrigin), /composition-binding/)],
    ['duplicate face', "(text.match(/^- id: aukora-face-aumlok$/gmu) ?? []).length !== 1", 'false', m => assert.throws(() => m.verifyBrowserPasskeyComposition(composition + '- id: aukora-face-aumlok\n', appOrigin), /composition-binding/)],
    ['record alias', 'fs.realpathSync(BROWSER_BINDING_RECORD) !== BROWSER_BINDING_RECORD', 'false', m => assert.rejects(() => m.readCurrentBinding(), /binding-alias/), { alias: true }],
    ['record bound', '{ maxBytes: 32768 }', '{ maxBytes: 65536 }', async (m, w) => { await m.readCurrentBinding(); assert.deepEqual(w.reads, [[recordFile, 32768]]) }],
    ['control revoked', 'p.revoked !== false', 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), revoked: true })), /binding-record/)],
    ['expiry', 'nowMs >= setup.expires_at_ms', 'false', async (m, w) => { await mint(m); const setup=JSON.parse(w.files.get(setupFile)); assert.throws(() => m.savedBrowserPasskeyClaim(setup,w.files.get(claimFile),setup,setup.expires_at_ms),/claim-expired/) }],
    ['setup selection', 'JSON.stringify(setup.binding) !== JSON.stringify(expected.binding)', 'false', async (m, w) => { await mint(m); const setup=JSON.parse(w.files.get(setupFile)); assert.throws(() => m.savedBrowserPasskeyClaim(setup,w.files.get(claimFile),{...setup,binding:{}},Date.now()),/setup-changed/) }],
    ['claim hash', 'hash(claim.trim()) !== setup.claim_sha256', 'false', async (m, w) => { await mint(m); const setup=JSON.parse(w.files.get(setupFile)); assert.throws(() => m.savedBrowserPasskeyClaim(setup,'z'.repeat(43)+'\n',setup,Date.now()),/claim-changed/) }],
    ['join configuration', 'present(JOIN)', 'false', (m,w) => { w.files.set(joinFile,'{}'); return assert.rejects(() => mint(m),/browser-join-selected/) }],
    ['join service', "present(DROPIN) && fs.readFileSync(DROPIN, 'utf8').includes('--browser-join')", 'false', (m,w) => { w.files.set(dropinFile,'serve --browser-join /selected'); return assert.rejects(() => mint(m),/browser-join-selected/) }],
    ['join database', "db.prepare('SELECT 1 FROM owner_browser_config LIMIT 1').get()", 'false', m => assert.rejects(() => mint(m),/browser-join-selected/), {table:true,selected:true}],
    ['enrollment history', "db.prepare(\"SELECT 1 FROM ledger WHERE event='owner-passkey-enrolled' LIMIT 1\").get()", 'false', m => assert.rejects(() => mint(m),/enrollment-closed/), {enrolled:true}],
    ['enrollment state', "db.prepare('SELECT state_text FROM owner_passkey WHERE singleton=1').get()?.state_text", 'false', m => assert.rejects(() => mint(m),/enrollment-closed/), {state:'{}'}],
    ['failed ceremony', "db.prepare('SELECT failed FROM owner_passkey_ceremony WHERE singleton=1').get()?.failed", 'false', m => assert.rejects(() => mint(m),/enrollment-closed/), {failed:true}],
    ['release path', 'path.resolve(release) !== release', 'false', m => assert.rejects(() => mint(m,{release:'/synthetic/release/../release'}),/release-path/)],
    ['claim orphan', 'if (present(CLAIM))', 'if (false)', (m,w) => { w.files.set(claimFile,'x'.repeat(43)+'\n'); return assert.rejects(() => mint(m),/claim-without-setup/) }],
    ['claim custody', 'claimInfo.uid !== 0', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {claimMetadata:{uid:501}}],
    ['opened custody', 'opened.uid !== 0', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{uid:501}}],
    ['opened identity', 'opened.ino !== claimInfo.ino', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{ino:99}}],
    ['no follow', ' | fs.constants.O_NOFOLLOW', '', m => assert.rejects(() => mint(m),{code:'ELOOP'}), {noFollow:true}],
    ['nonblocking', ' | fs.constants.O_NONBLOCK', '', m => assert.rejects(() => mint(m),{code:'EAGAIN'}), {nonblock:true}],
    ['node identity', "hash('aukora-browser-node/v1\\0' + gate)", "'a'.repeat(64)", async (m,w) => {await mint(m);const setup=JSON.parse(w.files.get(setupFile));assert.equal(setup.node,hash('aukora-browser-node/v1\0'+setup.gate))}],
    ['node version', "process.version !== 'v24.11.1'", 'false', m => assert.rejects(() => mint(m),/node-version/), {version:'v24.11.2'}],
    ['release alias', 'fs.realpathSync(release) !== release', 'false', m => assert.rejects(() => mint(m),/release-path/), {releaseAlias:true}],
    ['origin exact', 'url.origin !== value', 'false', m => assert.throws(() => m.browserPasskeyOrigin('https://owner.example.test/'), /origin/)],
    ['origin port', 'url.port', 'false', m => assert.throws(() => m.browserPasskeyOrigin('https://owner.example.test:444'), /origin/)],
    ['RP hostname', '!/^(?:[a-z0-9]', 'false && !/^(?:[a-z0-9]', m => assert.throws(() => m.browserPasskeyOrigin('https://127.0.0.1'), /origin/)],
    ['snapshot subject', '!/^aukora:1:[a-f0-9]{64}$/u.test(p.subject)', 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), subject:'bad' })), /binding-record/)],
    ['snapshot digest', '!/^[a-f0-9]{64}$/u.test(p.activeControlDigest)', 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), activeControlDigest:'bad' })), /binding-record/)],
    ['snapshot approval DID', "typeof p.approvalKeyDid !== 'string'", 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), approvalKeyDid:null })), /binding-record/)],
    ['snapshot epoch safe', '!Number.isSafeInteger(p.epoch)', 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), epoch:0.5 })), /binding-record/)],
    ['snapshot epoch nonnegative', 'p.epoch < 0', 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), epoch:-1 })), /binding-record/)],
    ['snapshot epoch increment safe', 'p.epoch >= Number.MAX_SAFE_INTEGER', 'false', m => assert.throws(() => m.browserBindingSnapshot(read, () => ({ ...projectRecordV3Control({ record }), epoch:Number.MAX_SAFE_INTEGER })), /binding-record/)],
    ['claim type', '!claimInfo.isFile()', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {claimMetadata:{isFile:()=>false}}],
    ['claim symlink', 'claimInfo.isSymbolicLink()', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {claimMetadata:{isSymbolicLink:()=>true}}],
    ['claim links', 'claimInfo.nlink !== 1', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {claimMetadata:{nlink:2}}],
    ['claim mode', '(claimInfo.mode & 0o077)', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {claimMetadata:{mode:0o644}}],
    ['claim size', 'claimInfo.size !== 44', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {claimMetadata:{size:45}}],
    ['opened type', '!opened.isFile()', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{isFile:()=>false}}],
    ['opened links', 'opened.nlink !== 1', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{nlink:2}}],
    ['opened mode', '(opened.mode & 0o077)', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{mode:0o644}}],
    ['opened size', 'opened.size !== 44', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{size:45}}],
    ['opened device', 'opened.dev !== claimInfo.dev', 'false', m => assert.rejects(() => mint(m),/claim-unprotected/), {openedMetadata:{dev:99}}],
    ['selected gate', 'setup.gate !== expected.gate', 'false', async (m,w) => {await mint(m);const s=JSON.parse(w.files.get(setupFile));assert.throws(()=>m.savedBrowserPasskeyClaim(s,w.files.get(claimFile),{...s,gate:'e'.repeat(64)},Date.now()),/setup-changed/)}],
    ['selected node', 'setup.node !== expected.node', 'false', async (m,w) => {await mint(m);const s=JSON.parse(w.files.get(setupFile));assert.throws(()=>m.savedBrowserPasskeyClaim(s,w.files.get(claimFile),{...s,node:'e'.repeat(64)},Date.now()),/setup-changed/)}],
    ['selected origin', 'setup.origin !== expected.origin', 'false', async (m,w) => {await mint(m);const s=JSON.parse(w.files.get(setupFile));assert.throws(()=>m.savedBrowserPasskeyClaim(s,w.files.get(claimFile),{...s,origin:'https://other.example.test'},Date.now()),/setup-changed/)}],
    ['app origin retained', "'root-selected-existing-browser-binding/v1:' + appOrigin", "'root-selected-existing-browser-binding/v1'", async (m,w) => {await mint(m);const s=JSON.parse(w.files.get(setupFile));assert.equal(s.binding.identity_provenance.approval_reference,'root-selected-existing-browser-binding/v1:'+appOrigin)}],
  ]
  let killed = 0
  for (const [name, before, after, exercise, changes] of mutations) {
    assert.ok(source.includes(before), 'mutation preimage: ' + name)
    await world(async (m,w) => { await assert.rejects(async () => exercise(m,w), assert.AssertionError, name); killed++ }, source.replace(before, after), changes)
  }
  t.diagnostic(`SOURCE-ONLY browser-passkey-claim mutations: ${killed}/${mutations.length} KILLED; 0 SURVIVED`)
})
