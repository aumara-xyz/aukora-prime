// Source checks for the boundary allowlist, the gate's filesystem store, approve/reject/revert with signed
// receipts, and the harness-side client. Real temp directories and sockets; no sudo, no network.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { tmpHome, approveViaReview } from './support/fixture.mjs'
import { createGate } from '../src/gate.mjs'
import { loadOwnerSecret, rotateBearer } from '../src/secrets.mjs'
import { openDb, sha256 } from '../src/ledger.mjs'
import { allowlist, assertTargetName, THEME_TARGET, readThemeText } from '../src/targets.mjs'
import { fsStore } from '../src/fs-store.mjs'
import { verifyReceipt, verifyReceiptSignature, verifyApprovalEvidence } from '../src/receipts.mjs'
import { gateTargets, gateStore } from '../src/wiring.mjs'
import { serveGate } from '../src/server.mjs'
import { resolveLayout } from '../src/layout.mjs'
import { gateClient, gateProbes } from '../src/gate-client.mjs'

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const theme = (hex) => `{"accent": "${hex}"}`

function realGate({ initial = theme('#FFD700') } = {}) {
  const root = tmpHome(), home = path.join(root, 'gate'), targetRoot = path.join(root, 'targets')
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(path.join(targetRoot, 'plugins/auma-theme'), { recursive: true })
  const file = path.join(targetRoot, THEME_TARGET)
  if (initial != null) fs.writeFileSync(file, initial)
  const clock = { t: Date.UTC(2026, 9, 3, 12) }
  const owner = loadOwnerSecret(home); rotateBearer(home, owner, () => clock.t)
  const gate = createGate({ home, owner, targets: gateTargets(targetRoot), store: gateStore(), now: () => clock.t })
  gate.startup({ pid: 1 })
  return { gate, clock, owner, root, home, targetRoot, file }
}
const base = (g) => g.proposeOps.read({ target: THEME_TARGET }).sha256
const propose = (g, hex, why = 'Accent update.') => g.proposeOps.propose({ target: THEME_TARGET, content: theme(hex), why, claimed_base: base(g) })

test('allowlist: exactly one declarative target; names under plugins/ only; code targets refused', () => {
  const reg = allowlist('/srv/aukora-boundary/targets')
  assert.deepEqual(Object.keys(reg), [THEME_TARGET]); assert.ok(Object.isFrozen(reg))
  assert.equal(reg[THEME_TARGET].file, '/srv/aukora-boundary/targets/plugins/auma-theme/theme.json')
  for (const bad of ['../x', '/etc/passwd', 'plugins/../x/y', 'plugins//y', 'plugins/./a/b', 'plugins/a', 'other/a/b', 'plugins/a\\b/c', 'plugins/a/b\n', ''])
    assert.throws(() => assertTargetName(bad), /target name refused/, JSON.stringify(bad))
  assert.equal(assertTargetName('plugins/auma-theme/theme.json'), THEME_TARGET)
  assert.throws(() => allowlist('relative'), /absolute/); assert.throws(() => allowlist('/'), /absolute/)
  const { gate } = realGate()
  for (const t of ['plugins/user/evil/index.js', 'plugins/auma-core/index.js', '../app/skunkworks.patch.yml', 'plugins/auma-theme/../auma-core/index.js', 'plugins/auma-theme/client.js'])
    assert.throws(() => gate.proposeOps.propose({ target: t, content: 'x', claimed_base: 'absent' }), /not on the allowlist/, t)
})

test('theme schema: canonical bytes only (with a hint), and the harness reader falls back to default', () => {
  const s = allowlist('/t')[THEME_TARGET]
  for (const ok of ['{"accent": "#FFD700"}', '{"accent": "default"}', '{"accent": "#1E90FF"}']) assert.doesNotThrow(() => s.validate(ok))
  assert.throws(() => s.validate('{"accent": "#ffd700"}'), /Canonical form of the parsed value would be \{"accent": "#FFD700"\}/)
  for (const bad of ['{"accent":"#FFD700"}', '{"accent": "#FFD700"}\n', '{"accent": "#FFD700"}\r\n', '{"accent": "#FFD70"}', '{"accent": "gold"}', '{"accent": "#FFD700", "x": 1}', '{"accent": "\\u0023FFD700"}', '\ufeff{"accent": "#FFD700"}'])
    assert.throws(() => s.validate(bad), /byte-exactly/, JSON.stringify(bad))
  assert.deepEqual(readThemeText('{"accent": "#FFD700"}'), { accent: '#FFD700', valid: true })
  assert.deepEqual(readThemeText('{"accent": "#FFD700", "accent": "#000000"}'), { accent: 'default', valid: false })
  assert.deepEqual(readThemeText(null), { accent: 'default', valid: false })
})

test('fs store: O_NOFOLLOW reads, symlink components refused, atomic 0640 writes, no temp leftovers', () => {
  const root = tmpHome(), store = fsStore(), dir = path.join(root, 'plugins/auma-theme'), file = path.join(dir, 'theme.json'), s = { file }
  assert.equal(store.read('t', s), null)
  store.write('t', s, Buffer.from(theme('#FFD700')), 'aaaa-1')
  assert.equal(store.read('t', s).toString(), theme('#FFD700'))
  assert.equal(fs.statSync(file).mode & 0o777, 0o640)
  assert.deepEqual(fs.readdirSync(dir), ['theme.json'])
  const outside = path.join(root, 'outside.json'); fs.writeFileSync(outside, 'secret')
  fs.rmSync(file); fs.symlinkSync(outside, file)
  assert.throws(() => store.read('t', s), /symlink in target path/)
  assert.throws(() => store.write('t', s, Buffer.from('x'), 'bbbb-2'), /symlink in target path/)
  assert.equal(fs.readFileSync(outside, 'utf8'), 'secret')
  fs.rmSync(file); fs.mkdirSync(file)
  assert.throws(() => store.read('t', s), /not a regular file|EISDIR/)
  const r2 = tmpHome(); fs.mkdirSync(path.join(r2, 'real')); fs.symlinkSync(path.join(r2, 'real'), path.join(r2, 'plugins'))
  assert.throws(() => store.write('t', { file: path.join(r2, 'plugins/x/theme.json') }, Buffer.from('x'), 'cccc-3'), /symlink in target path/)
  assert.deepEqual(fs.readdirSync(path.join(r2, 'real')), [])
})

test('approve: bytes written by the gate, receipt verifies against key and ledger; tampering is detected', () => {
  const { gate, owner, home, file } = realGate()
  assert.ok(gate.db.prepare("SELECT 1 FROM ledger WHERE event='genesis-target'").get())
  const p = propose(gate, '#1E90FF', 'Switch accent to blue.')
  assert.equal(fs.readFileSync(file, 'utf8'), theme('#FFD700'))
  const r = approveViaReview(gate, p.id)
  assert.equal(r.applied, true); assert.equal(fs.readFileSync(file, 'utf8'), theme('#1E90FF'))
  assert.equal(r.receipt.new_sha, sha256(theme('#1E90FF'))); assert.equal(r.receipt.base_sha, sha256(theme('#FFD700')))
  const db = openDb(path.join(home, 'gate.db'), { readOnly: true })
  const ok = verifyReceipt(db, r.receipt, r.receipt_sig, gate.pubPem)
  assert.equal(ok.ok, true, ok.errors.join('; ')); assert.equal(ok.ledger_seq, r.ledger_seq)
  assert.equal(verifyApprovalEvidence(r.receipt, owner.hmacKey), true)
  assert.equal(verifyApprovalEvidence(r.receipt, 'ab'.repeat(32)), false)
  const forged = { ...r.receipt, approver: 'harness popup' }
  assert.equal(verifyReceiptSignature(forged, r.receipt_sig, gate.pubPem).ok, false)
  assert.equal(verifyReceipt(db, forged, r.receipt_sig, gate.pubPem).ok, false)
  assert.equal(verifyApprovalEvidence(forged, owner.hmacKey), false)
  const otherKey = realGate().gate
  assert.match(verifyReceiptSignature(r.receipt, r.receipt_sig, otherKey.pubPem).errors.join(' '), /fingerprint mismatch/)
  const reordered = Object.fromEntries(Object.entries(r.receipt).reverse())
  assert.equal(verifyReceiptSignature(reordered, r.receipt_sig, gate.pubPem).ok, false)
})

test('reject and revert: owner reject is ledgered and signed; revert is a new owner-approved proposal with its own receipt', () => {
  const { gate, clock, home, file } = realGate()
  const p = propose(gate, '#1E90FF'); approveViaReview(gate, p.id)
  clock.t += 61_000
  const q = propose(gate, '#FF0000'); assert.equal(gate.ownerOps.reject({ id: q.id }, 'owner test').state, 'refused')
  assert.equal(fs.readFileSync(file, 'utf8'), theme('#1E90FF'))
  const dec = gate.db.prepare("SELECT detail FROM ledger WHERE proposal=? AND event='decide'").get(q.id); assert.equal(JSON.parse(dec.detail).outcome, 'rejected')
  clock.t += 61_000
  const h = gate.proposeOps.history({ target: THEME_TARGET })
  assert.equal(h.versions[0].current, true); assert.equal(h.versions[1].content, theme('#FFD700'))
  assert.throws(() => gate.proposeOps.revert({ target: THEME_TARGET, to_sha: sha256(theme('#FF0000')) }), /never an applied version/)
  assert.throws(() => gate.proposeOps.revert({ target: THEME_TARGET, to_sha: 'nope' }), /64-hex/)
  const rv = gate.proposeOps.revert({ target: THEME_TARGET, to_sha: 'previous', why: 'back to gold' })
  assert.equal(rv.kind, 'revert'); assert.equal(fs.readFileSync(file, 'utf8'), theme('#1E90FF'))
  assert.throws(() => gate.proposeOps.close({ id: rv.id, outcome: 'allowed-once' }), /cannot approve/)
  const r = approveViaReview(gate, rv.id)
  assert.equal(r.applied, true); assert.equal(r.receipt.kind, 'revert'); assert.equal(fs.readFileSync(file, 'utf8'), theme('#FFD700'))
  assert.equal(gate.db.prepare('SELECT event FROM ledger WHERE seq=?').get(r.ledger_seq).event, 'revert-applied')
  assert.equal(verifyReceipt(openDb(path.join(home, 'gate.db'), { readOnly: true }), r.receipt, r.receipt_sig, gate.pubPem).ok, true)
  assert.equal(gate.verify().ok, true)
})

test('start-up: non-canonical current bytes are not adopted; symlink swap at apply time fails closed', () => {
  const bad = realGate({ initial: '{"accent": "#FFD700", "accent": "#000000"}' })
  assert.ok(bad.gate.db.prepare("SELECT 1 FROM ledger WHERE event='genesis-target-invalid'").get())
  assert.equal(bad.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event='genesis-target'").get().n, 0)
  const { gate, file, root } = realGate()
  const p = propose(gate, '#1E90FF')
  const decoy = path.join(root, 'decoy'); fs.mkdirSync(decoy); fs.writeFileSync(path.join(decoy, 'theme.json'), theme('#FFD700'))
  const dir = path.dirname(file); fs.renameSync(dir, dir + '.moved'); fs.symlinkSync(decoy, dir)
  assert.throws(() => approveViaReview(gate, p.id), /symlink in target path/)
  assert.equal(fs.readFileSync(path.join(decoy, 'theme.json'), 'utf8'), theme('#FFD700'))
  assert.equal(gate.proposeOps.state({ id: p.id }).state, 'pending')   // refused before spending; nothing written
})

test('harness client over the real PROPOSE socket has no approve path; self-check gate probes are refused', async () => {
  const { gate, root, file } = realGate()
  const layout = resolveLayout({ run: path.join(root, 'run') })
  const srv = await serveGate(gate, { runDir: layout.run, ownerHttpPort: 0 })
  try {
    const c = gateClient(layout)
    for (const k of ['approve', 'decide', 'allow']) assert.equal(k in c, false)
    const cur = await c.read(THEME_TARGET)
    const p = await c.propose({ target: THEME_TARGET, content: theme('#1E90FF'), why: 'blue', base_sha256: cur.sha256 })
    await assert.rejects(c.propose({ target: THEME_TARGET, content: theme('#FF0000'), why: 'x', base_sha256: cur.sha256 }), /already pending/)
    const probes = gateProbes(layout)
    await assert.rejects(probes[1][1](), /unknown op/)
    await assert.rejects(probes[2][1](), /cannot approve/)
    await assert.rejects(c.state(p.id).then(s => { if (s.state !== 'pending') return; throw new Error('still pending') }), /still pending/)
    assert.equal((await c.reject(p.id)).state, 'refused')
    assert.equal(fs.readFileSync(file, 'utf8'), theme('#FFD700'))
    assert.equal(fs.statSync(layout.ownerSocket).mode & 0o777, 0o600)
    assert.equal((await c.verify()).ok, true)
  } finally { await srv.close() }
})

test('bin: serve requires a target root; verify-receipt accepts a real receipt and refuses a forged one', () => {
  const { gate, home } = realGate()
  const p = propose(gate, '#1E90FF'); const r = approveViaReview(gate, p.id)
  gate.db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
  const pub = path.join(home, 'pub.pem'); fs.writeFileSync(pub, gate.pubPem)
  const good = path.join(home, 'r.json'); fs.writeFileSync(good, JSON.stringify({ receipt: r.receipt, receipt_sig: r.receipt_sig }))
  const forged = path.join(home, 'f.json'); fs.writeFileSync(forged, JSON.stringify({ receipt: { ...r.receipt, new_sha: 'a'.repeat(64) }, receipt_sig: r.receipt_sig }))
  const run = (...a) => spawnSync(process.execPath, ['--no-warnings', path.join(PKG, 'bin/gate.mjs'), ...a], { encoding: 'utf8' })
  const ok = run('verify-receipt', '--db', path.join(home, 'gate.db'), '--pub', pub, '--receipt', good)
  assert.equal(ok.status, 0, ok.stdout + ok.stderr); assert.equal(JSON.parse(ok.stdout).ok, true)
  const no = run('verify-receipt', '--db', path.join(home, 'gate.db'), '--pub', pub, '--receipt', forged)
  assert.equal(no.status, 1); assert.match(no.stdout, /bad receipt signature/)
  const serve = run('serve', '--home', home, '--run', path.join(home, 'run'))
  assert.equal(serve.status, 2); assert.match(serve.stderr, /--target-root must be an absolute path/)
  const v = run('verify', '--home', home); assert.equal(v.status, 0)
})
