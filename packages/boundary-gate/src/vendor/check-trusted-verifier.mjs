// SPDX-License-Identifier: AGPL-3.0-or-later
// Source acceptance only: actual CLI/module buffers, real candidate files and Ed25519 signatures.
// Root metadata and Unix replies are synthetic. No installation/listener/permission change or runtime qualification.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import vm from 'node:vm'
import { fileURLToPath } from 'node:url'
import * as url from 'node:url'
import * as util from 'node:util'
import * as crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import { spawnSync } from 'node:child_process'
const self = fileURLToPath(import.meta.url), packageRoot = new URL('../../', import.meta.url)
const read = name => fs.readFileSync(new URL(name, packageRoot), 'utf8')
const ROOT = '/opt/aukora-boundary-gate', PIN = ROOT + '/src/vendor/trusted-verifier-pins.json'
const EPOCHS = '/etc/aukora-boundary-gate/signer-epochs.json'
const names = ['src/plugin-set-canon.mjs', 'src/release-floor.mjs', 'src/vendor/operator-data.mjs', 'src/vendor/plugin-set-content.mjs', 'src/vendor/signer-epochs.mjs']
const source = Object.fromEntries([...names, 'bin/plugin-set-approval.mjs', 'bin/release-floor.mjs'].map(n => [n, read(n)]))
const sha = b => crypto.createHash('sha256').update(b).digest('hex')
const pins = read('src/vendor/trusted-verifier-pins.json')
const mutants = {
  'candidate-import': ['const on = installedRelease', "await import('file://' + relDir + '/plugins/aukora-composition-gate/src/plugin-set.mjs'); const on = installedRelease", 1],
  'canon-hash': ["if (createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", "if (name !== 'src/plugin-set-canon.mjs' && createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", 1],
  'floor-hash': ["if (createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", "if (name !== 'src/release-floor.mjs' && createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", 1],
  'helper-hash': ["if (createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", "if (name !== 'src/vendor/operator-data.mjs' && createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", 1],
  'epoch-module-hash': ["if (createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", "if (name !== 'src/vendor/signer-epochs.mjs' && createHash('sha256').update(bytes).digest('hex') !== pins.files[name])", 1],
  'ancestor-owner': ["if (st.uid !== 0) throw trustedError('trusted-owner')", "if (false) throw trustedError('trusted-owner')", 1],
  'ancestor-mode': ["if ((st.mode & 0o022) !== 0) throw trustedError('trusted-mode')", "if (false) throw trustedError('trusted-mode')", 1],
  'ancestor-symlink': ["if (st.isSymbolicLink()) throw trustedError('trusted-symlink')", "if (false) throw trustedError('trusted-symlink')", 1],
  'hardlinks': ['st.nlink !== 1', 'false', 2],
  'entry-location': ["if (entry !== `${OPERATOR_ROOT}/bin/plugin-set-approval.mjs`)", 'if (false)', 1],
  'candidate-overlap': ['if (under(real, OPERATOR_ROOT) || under(OPERATOR_ROOT, real))', 'if (false)', 1],
  'checked-buffer': ["const checkedModule = bytes => import(`data:text/javascript;base64,${bytes.toString('base64')}`)", "const checkedModule = bytes => import('file://' + OPERATOR_ROOT + '/' + [...buffers].find(([, b]) => b === bytes)[0])", 1],
}
if (process.argv.includes('--mutations') || typeof vm.SourceTextModule !== 'function') {
  const run = m => spawnSync(process.execPath, ['--experimental-vm-modules', '--test', '--test-reporter=tap', self], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, TV_BOOTSTRAP_MUTANT: m ?? '', NODE_OPTIONS: '', NODE_PATH: '' },
  })
  const base = run(); process.stdout.write(base.stdout)
  if (base.status !== 0) { console.error('BASELINE FAILED'); process.exitCode = 1 }
  else if (process.argv.includes('--mutations')) for (const name of Object.keys(mutants)) {
    const r = run(name), expected = name === 'candidate-import' ? 2 : name.endsWith('-hash') ? 3 : name === 'entry-location' || name === 'candidate-overlap' ? 6 : name === 'checked-buffer' ? 7 : 4
    const failure = r.stdout.match(new RegExp('^not ok ' + expected + ' - .*$', 'mu'))?.[0]
    if (r.status === 0 || !failure) { console.error(`SURVIVED ${name}`); process.exitCode = 1 }
    else console.log(`KILLED ${name}: ${failure}`)
  }
} else {
const code = { ...source }, selected = process.env.TV_BOOTSTRAP_MUTANT
if (selected) {
  assert.ok(Object.hasOwn(mutants, selected)); const [before, after, count] = mutants[selected]
  assert.equal(code['bin/plugin-set-approval.mjs'].split(before).length - 1, count, 'exact named guard removal')
  code['bin/plugin-set-approval.mjs'] = code['bin/plugin-set-approval.mjs'].replaceAll(before, after)
}
const canon = await import(`data:text/javascript;base64,${Buffer.from(source[names[0]]).toString('base64')}`)
const data = await import(`data:text/javascript;base64,${Buffer.from(source[names[2]]).toString('base64')}`)
const retained = []
function world() {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'operator-pin-'))); retained.push(tmp)
  const release = path.join(tmp, 'release-abcdef0'), build = path.join(release, '.dsh-build')
  fs.mkdirSync(build, { recursive: true })
  const marker = path.join(tmp, 'candidate-marker'), helperMarker = path.join(tmp, 'candidate-helper-marker')
  const entries = {
    'plugins/aukora-composition-gate/src/plugin-set.mjs': `import './helper.mjs'; import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'UNAPPROVED');\n`,
    'plugins/aukora-composition-gate/src/helper.mjs': `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(helperMarker)}, 'UNAPPROVED');\n`,
  }
  for (const [name, text] of Object.entries(entries)) { const f = path.join(release, name); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, text) }
  const files = Object.fromEntries(Object.entries(entries).map(([p, t]) => [p, sha(Buffer.from(t))]))
  const artifact = { id: 'gate', entry: Object.keys(entries)[0], files, digest: canon.artifactDigest(files) }
  const record = { kind: canon.PLUGIN_SET_KIND, count: 1, artifacts: { gate: artifact }, setDigest: canon.pluginSetDigest({ gate: artifact }) }
  fs.writeFileSync(path.join(build, 'plugin-set.json'), JSON.stringify(record))
  fs.writeFileSync(path.join(build, 'aukora-release.json'), JSON.stringify({ tipSha: 'abcdef0' + 'a'.repeat(33) }))
  fs.writeFileSync(path.join(build, 'genesis-artifacts.json'), '{"artifacts":[]}')
  const fields = { ...data.installedRelease(tmp, 'release-abcdef0'), operation: canon.operationDigestOf(canon.setOperationContent(record)) }
  const content = data.pluginSetApprovalText(fields), key = crypto.generateKeyPairSync('ed25519')
  const pem = key.publicKey.export({ type: 'spki', format: 'pem' }), fp = sha(key.publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16)
  const receipt = { v: 2, kind: 'change', proposal: 'synthetic', target: data.PLUGIN_SET_TARGET, base_sha: 'absent', new_sha: sha(Buffer.from(content)),
    applied_at: '2026-10-04T00:00:00.000Z', approver: 'owner via owner.sock (synthetic)', approval_evidence_hmac: 'a'.repeat(64), pubkey_fp: fp }
  const target = path.join(tmp, 'targets', data.PLUGIN_SET_TARGET); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, content)
  const pin = { kind: canon.GATE_PIN_KIND, gatePubkeyPem: pem, gatePubkeyFp: fp, target: data.PLUGIN_SET_TARGET, approver: receipt.approver }
  const ordering = { seq:7 }
  const approval = () => {
    const receipt_sig = crypto.sign(null, Buffer.from(JSON.stringify(receipt)), key.privateKey).toString('base64')
    const row = { seq: ordering.seq, at: '2026-10-04T00:00:00.007Z', event: 'apply', proposal: receipt.proposal,
      target: receipt.target, base_sha: receipt.base_sha, new_sha: receipt.new_sha,
      detail: JSON.stringify({ receipt, receipt_sig }), prev: 'b'.repeat(64) }
    row.hash = sha(Buffer.from(JSON.stringify([row.seq,row.at,row.event,row.proposal,row.target,row.base_sha,row.new_sha,row.detail,row.prev])))
    row.sig = crypto.sign(null, Buffer.from(row.hash,'hex'),key.privateKey).toString('base64')
    return { kind: canon.GATE_APPROVAL_KIND, content, receipt, receipt_sig, ledger_entry: row }
  }
  const epochs = {version:1,kind:'aukora-signer-epochs/v1',epochs:[{epoch:1,gate_pubkey_sha256:sha(key.publicKey.export({type:'spki',format:'der'}))}]}
  return { tmp, release, marker, helperMarker, record, fields, content, pem, fp, receipt, pin, approval, epochs, ordering, requests: [] }
}
const noCandidate = w => { assert.equal(fs.existsSync(w.marker), false, 'candidate marker absent'); assert.equal(fs.existsSync(w.helperMarker), false, 'candidate helper marker absent') }
const synthetic = (exports, context) => new vm.SyntheticModule(Object.keys(exports), function () { for (const [k, v] of Object.entries(exports)) this.setExport(k, v) }, { context })
class Exit extends Error { constructor(code) { super(`exit ${code}`); this.code = code } }
async function cli(w, command, options = {}) {
  const entryName = options.floor ? 'release-floor.mjs' : 'plugin-set-approval.mjs', entry = 'bin/' + entryName
  const buffers = new Map(names.map(n => [ROOT + '/' + n, Buffer.from(source[n])]))
  buffers.set(EPOCHS, Buffer.from(JSON.stringify(w.epochs))); buffers.set(PIN, Buffer.from(pins)); buffers.set(ROOT + '/' + entry, Buffer.from(code[entry]))
  if (options.replace) for (const [name, text] of Object.entries(options.replace)) buffers.set(ROOT + '/' + name, Buffer.from(text))
  if (options.missingPin) buffers.delete(PIN)
  if (options.badPin) buffers.set(PIN, Buffer.from(options.badPin))
  const opened = new Map(), realOpened = new Map(); let fd = 100000; const loaded = []
  const metadata = file => {
    const b = buffers.get(file), directory = b === undefined
    return { uid: options.badOwner === file ? 501 : 0, mode: options.badMode === file ? 0o777 : directory ? 0o40755 : 0o100644,
      nlink: options.hardlink === file ? 2 : 1, size: b?.length ?? 0, dev: 1, ino: file.length,
      isDirectory: () => directory, isFile: () => !directory, isSymbolicLink: () => options.symlink === file }
  }
  const fixtureFs = { ...fs, constants: fs.constants,
    lstatSync(file) {
      if (file === '/' || file === '/opt' || file === '/etc' || file === path.dirname(EPOCHS) || file === EPOCHS || file.startsWith(ROOT)) return metadata(file)
      const st = fs.lstatSync(file)
      return { ...st, uid: 0, mode:st.mode & ~0o022, isDirectory: () => st.isDirectory(), isFile: () => st.isFile(), isSymbolicLink: () => st.isSymbolicLink() }
    },
    realpathSync(file) { if (options.alias === file) return file + '-alias'; return file.startsWith(ROOT) ? file : fs.realpathSync(file) },
    openSync(file, flags, mode) {
      if (!file.startsWith(ROOT) && file !== EPOCHS) { const n=fs.openSync(file,flags,mode); realOpened.set(n,file); return n }
      assert.ok(flags & fs.constants.O_NOFOLLOW, 'trusted open must use O_NOFOLLOW')
      if (!buffers.has(file)) throw Object.assign(new Error('missing fixture'), { code: 'ENOENT' })
      opened.set(++fd, file); return fd
    },
    fstatSync(n) { if (!opened.has(n)) { const st=fs.fstatSync(n); return {...st,uid:0,isFile:()=>st.isFile(),isDirectory:()=>st.isDirectory()} }; const st = metadata(opened.get(n)); if (options.changedIdentity === opened.get(n)) st.ino++; return st },
    readFileSync(file, encoding) {
      if (!opened.has(file)) return fs.readFileSync(file, encoding)
      const name = opened.get(file), bytes = buffers.get(name)
      if (options.flipAfterRead === name) buffers.set(name, Buffer.from(options.flipBytes))
      return bytes
    },
    writeFileSync(file,...args) {
      if (options.failCacheWrite && (typeof file==='string'?file:realOpened.get(file)??'').includes('/plugin-set-approval.json.tmp-')) throw new Error('fixture-cache-publication-failure')
      if (options.failFloorWrite && path.basename(realOpened.get(file) ?? '').startsWith('.release-floor.tmp-')) throw new Error('fixture-floor-write-failure')
      return fs.writeFileSync(file,...args)
    },
    closeSync(n) { if (opened.has(n)) opened.delete(n); else { realOpened.delete(n); fs.closeSync(n) } },
  }
  const logs = [], errors = [], argv = ['/usr/bin/node', ROOT + '/' + entry, command, '--floor', path.join(w.tmp, 'floor.json')]
  if (!options.noRelease) argv.push('--release-dir', options.release ?? w.release)
  if (options.floor) argv.push('--approval-state-root', path.join(w.tmp, 'state'))
  else argv.push('--target-root', path.join(w.tmp, 'targets'), ...(['install','recover-cache','migrate-clock-floor'].includes(command) ? ['--out', path.join(w.tmp, 'state/gate-state')] : []), ...(options.args ?? []))
  const proc = { argv, env: options.env ?? {}, execArgv: options.execArgv ?? [], pid: options.fixturePid ?? process.pid, getuid: () => 0,
    exit: n => { throw new Exit(n) } }
  const net = { createConnection() {
    const c = new EventEmitter(); c.destroy = () => {}; c.write = wire => {
      const r = JSON.parse(wire); w.requests.push(r); let result
      if (r.op === 'raise') result = { id: 'synthetic', expires: Date.now() + 10000 }
      if (r.op === 'log') result = { verify: { ok: true }, entries: [{ event: 'apply', seq: 7, detail: w.approval(), signed_entry: w.approval().ledger_entry }] }
      if (r.op === 'ping') result = { pubkey_pem: w.pem, pubkey_fp: w.fp }
      queueMicrotask(() => { c.emit('data', Buffer.from(JSON.stringify({ ok: true, result }))); c.emit('end') })
    }; queueMicrotask(() => c.emit('connect')); return c
  } }
  const context = vm.createContext({ process: proc, Buffer, console: { log: s => logs.push(s), error: s => errors.push(s) }, setTimeout, clearTimeout, URL })
  const builtins = { 'node:fs': { default: fixtureFs }, 'node:path': { default: path }, 'node:crypto': crypto, 'node:util': util, 'node:url': url, 'node:net': { default: net } }
  const linker = spec => { assert.ok(Object.hasOwn(builtins, spec), 'every executable module import is builtin-only'); return synthetic(builtins[spec], context) }
  async function dynamic(spec) {
    if (spec.startsWith('file://') && !spec.startsWith('file://' + ROOT + '/')) return import(spec) // a reintroduced candidate import really executes its trap
    let text
    if (spec.startsWith('data:text/javascript;base64,')) text = Buffer.from(spec.split(',')[1], 'base64').toString('utf8')
    else if (spec.startsWith('file://' + ROOT + '/')) text = buffers.get(fileURLToPath(spec)).toString('utf8') // read-again mutant only
    else assert.fail('unexpected dynamic module')
    loaded.push(spec.startsWith('data:') ? 'checked-buffer' : 'reread-file')
    const mod = new vm.SourceTextModule(text, { context, importModuleDynamically: dynamic }); await mod.link(linker); await mod.evaluate(); return mod
  }
  const mod = new vm.SourceTextModule(code[entry], { context, initializeImportMeta: m => { m.url = 'file://' + (options.entryPath ?? ROOT + '/' + entry) }, importModuleDynamically: dynamic })
  await mod.link(linker)
  try { await mod.evaluate() } catch (e) { if (!(e instanceof Exit && e.code === 0)) throw Object.assign(new Error(errors.join('\n') || e.message), { loaded, logs }) }
  return { logs, loaded }
}
test('pins match exact source; renderer and both builtin bootstraps preserve the existing protocol', () => {
  const p = JSON.parse(pins); for (const n of names) assert.equal(p.files[n], sha(Buffer.from(source[n])))
  assert.ok(source[names[0]].includes(source[names[3]].replace('export function setOperationContent(record)', 'function renderSetOperationContent(record)')))
  for (const n of names) for (const m of source[n].matchAll(/^import .* from '([^']+)'/gmu)) assert.ok(m[1].startsWith('node:'))
  const blocks = ['bin/plugin-set-approval.mjs', 'bin/release-floor.mjs'].map(n => source[n].split('// TRUSTED-BOOTSTRAP-BEGIN')[1].split('// TRUSTED-BOOTSTRAP-END')[0].replace('/bin/' + path.basename(n), '/bin/ENTRY'))
  assert.equal(blocks[0], blocks[1]); const w = world(); assert.equal(canon.parseGateApprovalContent(w.content).operation, w.fields.operation)
})
test('actual CLI show/raise/install never executes candidate verifier or helper markers', async () => {
  for (const command of ['show', 'raise', 'install']) for (const explicit of [false, true]) {
    const w = world(), r = await cli(w, command, { args: explicit ? ['--operation', w.fields.operation] : [] }); noCandidate(w)
    assert.ok(r.logs[0].includes(w.fields.operation)); assert.deepEqual(r.loaded, ['checked-buffer', 'checked-buffer', 'checked-buffer', 'checked-buffer'])
    if (command === 'install') assert.ok(fs.existsSync(path.join(w.tmp, 'state/gate-state/plugin-set-approval.json')))
  }
})
test('wrong hashes refuse before malicious trusted canon/floor/helper bytes can write a marker', async () => {
  for (const name of names) {
    const w = world(), marker = path.join(w.tmp, 'wrong-trusted-marker')
    const evil = `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'BAD'); export const bad=true;`
    let error; try { await cli(w, 'show', { replace: { [name]: evil } }) } catch (e) { error = e }
    assert.equal(fs.existsSync(marker), false, 'pin must precede top-level execution'); assert.match(error?.message ?? '', /trusted-hash/); assert.equal(error.loaded.length, 0)
  }
})
test('missing/malformed pins and owner/mode/symlink/hardlink inputs refuse', async () => {
  const w = world()
  for (const options of [{ missingPin: true }, { badPin: '{}' }, { badOwner: ROOT }, { badMode: ROOT }, { symlink: ROOT + '/src' },
    { badOwner: ROOT + '/' + names[0] }, { badMode: ROOT + '/' + names[0] }, { hardlink: ROOT + '/' + names[0] }]) {
    let error; try { await cli(w, 'show', options) } catch (e) { error = e }
    assert.ok(error, JSON.stringify(options)); assert.equal(error.loaded.length, 0); noCandidate(w)
  }
})
test('opened identity and bounded trusted reads refuse before code runs', async () => {
  const w = world()
  for (const options of [{ changedIdentity: ROOT + '/' + names[0] }, { replace: { [names[0]]: 'x'.repeat(128 * 1024 + 1) } }]) {
    await assert.rejects(cli(w, 'show', options), /trusted-(open-identity|size)/)
  }
})
test('fixed entrypoint, candidate disjointness/aliases and Node environment refuse', async () => {
  const w = world()
  for (const [options, reason] of [[{ entryPath: ROOT + '/src/copy.mjs' }, 'trusted-entrypoint'], [{ release: ROOT + '/release-abcdef0' }, 'candidate-trusted-overlap'],
    [{ alias: w.release }, 'candidate-path-alias'], [{ alias: ROOT }, 'trusted-root-alias'], [{ env: { NODE_OPTIONS: '--import=unapproved' } }, 'trusted-node-environment'],
    [{ env: { NODE_PATH: '/unapproved' } }, 'trusted-node-environment'], [{ execArgv: ['--import=unapproved'] }, 'trusted-node-environment']]) {
    await assert.rejects(cli(w, 'show', options), new RegExp(reason)); noCandidate(w)
  }
})
test('module bytes changed after a checked read are never re-read for execution', async () => {
  const w = world(), marker = path.join(w.tmp, 'reread-marker')
  const r = await cli(w, 'show', { flipAfterRead: ROOT + '/' + names[0], flipBytes: `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'BAD');` }).catch(e => e)
  assert.equal(fs.existsSync(marker), false, 'execute checked buffers rather than pathname imports'); assert.ok(r.logs[0].includes(w.fields.operation))
})
test('release-floor CLI uses checked modules and preserves monotonic signed approval enforcement', async () => {
  const w = world(); await cli(w, 'install'); const r = await cli(w, 'check', { floor: true }); assert.match(r.logs[0], /release-floor: OK/); noCandidate(w)
  const floor = path.join(w.tmp, 'floor.json'), f = JSON.parse(fs.readFileSync(floor)); f.ledger_seq = 8; fs.writeFileSync(floor, JSON.stringify(f))
  await assert.rejects(cli(w, 'check', { floor: true }), /release-below-floor/)
  await assert.rejects(cli(w, 'check', { floor: true, replace: { [names[0]]: '// changed\n' } }), /trusted-hash/)
})
test('same verifier validates genuine synthetic receipt and refuses signature/set/owner changes', () => {
  const w = world(), input = { record: w.record, approval: w.approval(), pin: w.pin }
  assert.equal(canon.verifyGateSetApproval(input).release, w.fields.release)
  const bad = structuredClone(input); bad.approval.receipt_sig = Buffer.alloc(64).toString('base64'); assert.throws(() => canon.verifyGateSetApproval(bad), /signature-invalid/)
  const other = structuredClone(input); other.record.setDigest = 'f'.repeat(64); assert.throws(() => canon.verifyGateSetApproval(other), /record-malformed/)
  const owner = structuredClone(input); owner.pin.approver = 'other'; assert.throws(() => canon.verifyGateSetApproval(owner), /approver-not-pinned/)
})
test('no disk helper closure or candidate subprocess survives in either operator entrypoint', () => {
  const unit = read('host/systemd/aukora-genesis.service')
  assert.match(unit, /^UnsetEnvironment=NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT$/mu)
  for (const name of ['bin/plugin-set-approval.mjs', 'bin/release-floor.mjs', ...names, 'src/vendor/trusted-verifier-pins.json']) assert.ok(unit.includes('--forbid-write ' + ROOT + '/' + name))
  assert.doesNotMatch(unit.split('\n').filter(l => l.startsWith('Exec')).join('\n'), /--allow-unapproved|--allow-ungated/)
  for (const n of ['bin/plugin-set-approval.mjs', 'bin/release-floor.mjs']) {
    for (const m of source[n].matchAll(/^import .* from '([^']+)'/gmu)) assert.ok(m[1].startsWith('node:'))
    assert.doesNotMatch(source[n], /import\([^`]*OPERATOR_ROOT|src\/server\.mjs|src\/targets\.mjs|child_process|createRequire/)
  }
})
test('actual install interruption cannot admit an uncommitted or stale approval cache', async () => {
  const w=world(); await cli(w,'install')
  const floor=path.join(w.tmp,'floor.json'), cache=path.join(w.tmp,'state/gate-state/plugin-set-approval.json')
  const cacheBefore=fs.readFileSync(cache,'utf8'); w.ordering.seq=8
  await assert.rejects(cli(w,'install',{failFloorWrite:true}),/fixture-floor-write-failure/)
  assert.equal(JSON.parse(fs.readFileSync(floor)).ledger_seq,7)
  assert.equal(fs.readFileSync(cache,'utf8'),cacheBefore)
  await cli(w,'check',{floor:true})
  await assert.rejects(cli(w,'install',{failCacheWrite:true}),/fixture-cache-publication-failure/)
  assert.equal(JSON.parse(fs.readFileSync(floor)).ledger_seq,8)
  assert.equal(fs.readFileSync(cache,'utf8'),cacheBefore)
  await assert.rejects(cli(w,'check',{floor:true}),/release-below-floor/)
  await assert.rejects(cli(w,'install'),/release-floor-not-newer/)
  const floorCommitted=fs.readFileSync(floor,'utf8')
  await cli(w,'recover-cache',{fixturePid:process.pid+1}); await cli(w,'check',{floor:true})
  assert.equal(fs.readFileSync(floor,'utf8'),floorCommitted,'recovery never advances or rewrites floor')
  w.ordering.seq=9; await cli(w,'install',{fixturePid:process.pid+2}); await cli(w,'check',{floor:true}); noCandidate(w)
})
test('explicit migration binds actual owner proof to legacy current floor; no ordinary reset', async () => {
  const w=world(), floor=path.join(w.tmp,'floor.json')
  const old={kind:'aukora-release-floor/v1',release:w.fields.release,release_dir:w.fields.release_dir,record:w.fields.record,applied_at:w.receipt.applied_at,history:[]}
  fs.writeFileSync(floor,JSON.stringify(old),{mode:0o600})
  assert.equal(fs.statSync(floor).mode & 0o022,0,'legacy fixture floor starts protected under every umask')
  await assert.rejects(cli(w,'install'),/release-floor-migration-required/)
  await cli(w,'migrate-clock-floor'); await cli(w,'check',{floor:true})
  assert.equal(JSON.parse(fs.readFileSync(floor)).ledger_seq,7)
  await assert.rejects(cli(w,'migrate-clock-floor'),/release-floor/)
  w.ordering.seq=8; await assert.rejects(cli(w,'recover-cache'),/release-floor-install-incomplete/)
})
test.after(() => console.log(`SOURCE_ONLY; SYNTHETIC_ROOT_METADATA_AND_UNIX_REPLIES; retained tiny fixtures ${retained.length}`))
}
