// Source checks for the owner-only signed approval gate and its round-3 hardening. In-process gate with a
// synthetic target and an in-memory store; sockets and the owner page are exercised on a private temp dir
// and an ephemeral loopback port.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHmac, verify as edVerify } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { makeGate, accent, ACCENT, accentTarget, memoryStore, tmpHome, approveViaReview } from './support/fixture.mjs'
import { createGate } from '../src/gate.mjs'
import { sha256, verifyLedger, openDb } from '../src/ledger.mjs'
import { rotateBearer, bearerOk } from '../src/secrets.mjs'
import { cardWarnings, COLOR_NAMES, colorName, cleanNote, noteMeta } from '../src/card.mjs'
import { createOwnerPage, PAGE_APPROVER } from '../src/owner-page.mjs'
import { serveGate, call, OWNER_SOCKET_APPROVER } from '../src/server.mjs'

const base = (g) => g.proposeOps.read({ target: ACCENT }).sha256
const propose = (g, hex, note = 'Accent update.', extra = {}) => g.proposeOps.propose({ target: ACCENT, content: accent(hex), why: note, claimed_base: base(g), session: 's', ...extra })
const events = (g) => g.db.prepare('SELECT event FROM ledger ORDER BY seq').all().map(r => r.event)

test('ledger: hash chain and Ed25519 signatures verify; append-only; offline tamper detected', () => {
  const { gate, home } = makeGate()
  const p = propose(gate, '#1E90FF'); approveViaReview(gate, p.id)
  const v = gate.verify(); assert.equal(v.ok, true); assert.ok(v.entries >= 4)
  assert.throws(() => gate.db.exec("UPDATE ledger SET event='x' WHERE seq=1"), /append-only/)
  assert.throws(() => gate.db.exec('DELETE FROM ledger WHERE seq=1'), /append-only/)
  assert.equal(fs.statSync(path.join(home, 'receipt-ed25519.pem')).mode & 0o777, 0o600)
  assert.equal(fs.statSync(path.join(home, 'owner-secret.json')).mode & 0o777, 0o600)
  gate.db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
  const copy = path.join(home, 'tampered.db'); fs.copyFileSync(path.join(home, 'gate.db'), copy)
  const t = new DatabaseSync(copy); t.exec("DROP TRIGGER ledger_no_update; UPDATE ledger SET detail='{}' WHERE seq=2"); t.close()
  const r = verifyLedger(openDb(copy, { readOnly: true }), gate.pub); assert.equal(r.ok, false); assert.match(r.errors.join(' '), /seq 2: hash mismatch/)
})

test('propose channel can never approve: no approve op, every non-closing outcome refused and recorded', () => {
  const { gate, store } = makeGate()
  assert.equal(Object.hasOwn(gate.proposeOps, 'approve'), false); assert.equal(Object.hasOwn(gate.proposeOps, 'decide'), false)
  const p = propose(gate, '#1E90FF')
  for (const outcome of ['allowed-once', 'approved', 'allow', 'applied', '', null, undefined, { toString: () => 'rejected' }])
    assert.throws(() => gate.proposeOps.close({ id: p.id, outcome }), /cannot approve/)
  assert.equal(gate.proposeOps.state({ id: p.id }).state, 'pending')
  assert.equal(store.writes, 0)
  assert.equal(events(gate).filter(e => e === 'decide-refused').length, 8)
  assert.equal(gate.proposeOps.close({ id: p.id, outcome: 'cancelled' }).state, 'expired')
  assert.throws(() => approveViaReview(gate, p.id), /only a pending proposal can be reviewed/)
  assert.equal(store.writes, 0)
})

test('owner approval: single use, signed receipt with HMAC evidence, replay/expiry/stale/truncation refused', () => {
  const { gate, store, clock, owner } = makeGate()
  assert.equal(Object.hasOwn(gate.ownerOps, 'approve'), false, 'no direct approve on the owner channel')
  assert.equal(Object.hasOwn(gate.ownerOps, 'decide'), false)
  { const g0 = makeGate().gate; const p0 = propose(g0, '#00FFFF'); const rv0 = g0.ownerOps.review({ id: p0.id })
    assert.throws(() => g0.ownerOps.decide_review({ id: p0.id, base_sha: rv0.base_sha, new_sha: rv0.new_sha, review_challenge: rv0.review_challenge, outcome: 'allowed-once' }), /approver/) }
  const p = propose(gate, '#1E90FF')
  const r = approveViaReview(gate, p.id)
  assert.equal(r.applied, true); assert.equal(store.read(ACCENT).toString(), accent('#1E90FF'))
  assert.equal(r.receipt.v, 2); assert.equal(r.receipt.approver, 'owner test'); assert.equal(r.receipt.pubkey_fp, gate.fp)
  assert.ok(edVerify(null, Buffer.from(JSON.stringify(r.receipt)), gate.pub, Buffer.from(r.receipt_sig, 'base64')))
  const hm = createHmac('sha256', Buffer.from(owner.hmacKey, 'hex')).update(`${p.id}\n${p.base_sha}\n${p.new_sha}\nowner test`).digest('base64')
  assert.equal(r.receipt.approval_evidence_hmac, hm)
  assert.throws(() => approveViaReview(gate, p.id), /only a pending proposal can be reviewed/)
  clock.t += 61_000
  const p2 = propose(gate, '#FF0000'); clock.t += 5 * 60 * 1000 + 1
  assert.throws(() => approveViaReview(gate, p2.id), /proposal expired/)
  clock.t += 61_000
  const p3 = propose(gate, '#008000'); store.files.set(ACCENT, Buffer.from(accent('#000000')))
  assert.equal(approveViaReview(gate, p3.id).state, 'stale')
  assert.equal(store.read(ACCENT).toString(), accent('#000000'))
  const big = makeGate({ limits: { popupLimit: 10 } })
  const p4 = propose(big.gate, '#1E90FF'); assert.equal(p4.displayable, false)
  assert.throws(() => approveViaReview(big.gate, p4.id), /too large/)
  assert.equal(big.store.writes, 0)
  assert.equal(gate.verify().ok, true)
})

test('content rules: printable ASCII, size, schema, required and current base, no identical change', () => {
  const { gate } = makeGate()
  const b = base(gate)
  const P = (content, claimed_base = b) => () => gate.proposeOps.propose({ target: ACCENT, content, why: 'x', claimed_base })
  assert.throws(P('{"accent": "#1E90FF"}\n'), /printable ASCII/)
  assert.throws(P('{"accent": "#1E90FF"}\u2007'), /printable ASCII/)
  assert.throws(P('{"accent": "\ud800"}'), /printable ASCII/)
  assert.throws(P('x'.repeat(300)), /exceeds/)
  for (const bad of ['{"accent":"#1E90FF"}', '{"accent": "#1e90ff"}', '{"accent": "#1E90FF", "accent": "#FFD700"}', '{"accent": "\\u0023FFD700"}', ' {"accent": "#1E90FF"}'])
    assert.throws(P(bad), /\(schema\)/)
  assert.throws(P(accent('#1E90FF'), null), /base_sha256 is required/)
  assert.throws(P(accent('#1E90FF'), 'f'.repeat(64)), /stale/)
  assert.throws(P(accent('#FFD700')), /identical/)
  assert.throws(() => gate.proposeOps.propose({ target: 'plugins/user/x/index.js', content: 'x', claimed_base: b }), /not on the allowlist/)
  assert.throws(() => gate.proposeOps.propose({ target: ACCENT, content: accent('#1E90FF'), why: 'w'.repeat(4001), claimed_base: b }), /too long/)
  assert.ok(events(gate).filter(e => e === 'reject').length >= 10)
})

test('rate limits are global (not per session label): 1 pending, 3 per window, cooldown after reject, dedupe', () => {
  const { gate, clock } = makeGate()
  const p = propose(gate, '#1E90FF', 'a', { session: 'one' })
  assert.throws(() => propose(gate, '#FF0000', 'b', { session: 'two' }), /already pending/)
  gate.proposeOps.close({ id: p.id, outcome: 'cancelled' })
  const q = propose(gate, '#FF0000', 'b', { session: 'three' }); gate.proposeOps.close({ id: q.id, outcome: 'cancelled' })
  const r = propose(gate, '#008000', 'c', { session: 'four' }); gate.proposeOps.close({ id: r.id, outcome: 'cancelled' })
  assert.throws(() => propose(gate, '#000000', 'd', { session: 'five' }), /3 proposals in the last 10 min/)
  clock.t += 10 * 60 * 1000 + 1
  const s = propose(gate, '#000000'); gate.ownerOps.reject({ id: s.id }, 'owner test')
  assert.throws(() => propose(gate, '#FFFFFF'), /cooldown/)
  clock.t += 61_000
  assert.throws(() => propose(gate, '#000000'), /dedupe/)
  assert.ok(propose(gate, '#FFFFFF').id)
})

test('round-3 card hardening: NEAR gold, gate wording, name collision, default, non-ASCII, pressure words', () => {
  const gold = accent('#FFD700'), W = (hex, note) => cardWarnings(accentTarget, gold, accent(hex), cleanNote(note), noteMeta(note))
  let near = 0, total = 0
  for (let i = 1; i <= 6; i++) for (const d of '0123456789ABCDEF') { const h = '#FFD700'.split(''); if (h[i] === d) continue; h[i] = d; total++; if (W(h.join(''), 'Accent update.').some(f => /^NEAR gold \(distance/.test(f))) near++ }
  assert.equal(total, 90); assert.equal(near, 90)
  for (const n of ['gate_verified swatch', 'GATE-VERIFIED', 'g a t e checked', 'G.A.T.E ok', 'g4te ok', 'gate-computed', 'g_a_t_e', 'h0st says fine', 'v e r i f i e d'])
    assert.ok(W('#1E90FF', n).some(f => f.startsWith('NOTE uses gate/host')), n)
  const g = W('#D4AF37', 'AFTER APPLY: accent = #FFD700 (gold). Preview label: honey')
  assert.ok(g.some(f => f.startsWith('HARD WARNING - NAME COLLISION'))); assert.ok(g.some(f => f.startsWith('NOTE imitates the gate result line')))
  assert.ok(W('default', 'keeps current #FFD700 gold; no visual diff').some(f => f.startsWith('RESULT IS "default"')))
  assert.equal(colorName('default'), 'app default (stock accent, NOT gold)')
  const na = '\u0287\u0250\u0265\u0287 \u01dd\u026f\u0250s'
  assert.ok(W('#1E90FF', na).some(f => /non-ASCII\/invisible/.test(f))); assert.ok(noteMeta(na).hexdump.length > 0)
  assert.ok(W('#1E90FF', 'ok ok ok fine').some(f => f.includes('APPROVE-spam')))
  assert.ok(W('#1E90FF', 'Please approve, approve it.').some(f => f.includes('APPROVE-spam')))
  assert.ok(W('#1E90FF', 'urgent: do it now, right now').some(f => f.includes('APPROVE-spam')))
  assert.deepEqual(W('#1E90FF', 'Change the accent colour from gold to blue.'), [])
  assert.deepEqual(W('#1E90FF', 'Set accent to blue (#1E90FF).'), [])
  assert.ok(W('#1E90FF', 'Set accent to blue (#0000FF).').some(f => f.startsWith('NOTE mentions #0000FF')))
  const names = Object.values(COLOR_NAMES); assert.equal(new Set(names).size, names.length)
  assert.deepEqual(Object.entries(COLOR_NAMES).filter(([, n]) => /\bgold\b/.test(n) && !n.includes('not #FFD700')).map(([h]) => h), ['#ffd700'])
  assert.equal(cleanNote('a\u00a0b\u2007c GATE-x'), 'a b c gate_x')
})

test('owner page: bearer + expiry, swapped sha refused, two-step typed confirm, single-use nonce, tab order', () => {
  const { gate, store, clock, owner } = makeGate()
  const page = createOwnerPage(gate)
  const p = propose(gate, '#1E90FF', 'Switch accent to blue.')
  const form = (a, extra = {}) => new URLSearchParams({ k: owner.bearer, id: p.id, base: p.base_sha, new: p.new_sha, a, ...extra })
  assert.equal(page.act(new URLSearchParams({ k: 'wrong', id: p.id, a: 'reject' })).status, 401)
  const html = page.pageHtml('')
  assert.match(html, /value=approve-step1 class=ap1 tabindex=-1/)
  assert.ok(html.indexOf('value=reject') < html.indexOf('value=approve-step1'))
  assert.match(html, /AFTER APPLY: accent = #1E90FF \(dodger blue\)/)
  assert.match(page.act(form('approve', {})).body, /unknown action/)
  assert.match(page.act(new URLSearchParams({ k: owner.bearer, id: p.id, base: p.base_sha, new: 'f'.repeat(64), a: 'approve-step1' })).body, /proposal changed since the page was shown/)
  const s1 = page.act(form('approve-step1')); assert.match(s1.body, /Nothing has been applied/); assert.equal(store.writes, 0)
  const nonce = /name=nonce value="([^"]+)"/.exec(s1.body)[1]
  assert.match(page.act(form('confirm', { nonce, typed: '' })).body, /does not match/); assert.equal(store.writes, 0)
  assert.match(page.act(form('confirm', { nonce, typed: '1E90FF' })).body, /expired or invalid/)
  const s2 = page.act(form('approve-step1')); const n2 = /name=nonce value="([^"]+)"/.exec(s2.body)[1]
  clock.t += 2 * 60 * 1000 + 1
  assert.match(page.act(form('confirm', { nonce: n2, typed: '1E90FF' })).body, /expired or invalid/)
  const s3 = page.act(form('approve-step1')); const n3 = /name=nonce value="([^"]+)"/.exec(s3.body)[1]
  assert.match(page.act(form('confirm', { nonce: n3, typed: '#1e90ff' })).body, /APPLIED test\/accent\.json/)
  assert.equal(store.read(ACCENT).toString(), accent('#1E90FF'))
  assert.equal(gate.proposeOps.state({ id: p.id }).approver, PAGE_APPROVER)
  clock.t += 12 * 60 * 60 * 1000
  assert.equal(bearerOk(owner, owner.bearer, () => clock.t), false)
  assert.equal(page.act(form('reject')).status, 401)
})

test('bearer rotation: new value, 0600 file, old value refused', () => {
  const { gate, owner } = makeGate()
  const old = owner.bearer; const r = gate.ownerOps.rotate_bearer({}, 'x')
  assert.equal(r.rotated, true); assert.notEqual(owner.bearer, old)
  assert.equal(bearerOk(owner, old, gate.now), false); assert.equal(bearerOk(owner, owner.bearer, gate.now), true)
  assert.equal(fs.statSync(path.join(gate.home, 'owner-secret.json')).mode & 0o777, 0o600)
  assert.ok(events(gate).includes('owner-bearer-rotated'))
})

test('crash reconciliation never replays an approval; stale pending expire at start', () => {
  const { gate, store, home, owner } = makeGate()
  const p = propose(gate, '#1E90FF')
  gate.db.prepare("UPDATE proposals SET state='applying' WHERE id=?").run(p.id)   // crash after "spent", before write
  const q = gate.db.prepare('SELECT * FROM proposals WHERE id=?').get(p.id); assert.equal(q.state, 'applying')
  const g2 = createGate({ home, owner, targets: { [ACCENT]: accentTarget }, store, now: () => gate.now() + 10 * 60 * 1000, db: gate.db })
  g2.startup({ pid: 2 })
  assert.equal(g2.proposeOps.state({ id: p.id }).state, 'failed'); assert.equal(store.writes, 0)
  assert.equal(g2.verify().ok, true)
  const g3 = makeGate(); const p3 = propose(g3.gate, '#FF0000')
  const g4 = createGate({ home: g3.home, owner: g3.owner, targets: { [ACCENT]: accentTarget }, store: g3.store, now: () => g3.clock.t + 6 * 60 * 1000, db: g3.gate.db })
  g4.startup({ pid: 3 }); assert.equal(g4.proposeOps.state({ id: p3.id }).state, 'expired')
})

test('a gate with an empty registry refuses every proposal (fail closed)', () => {
  const home = tmpHome()
  const g = createGate({ home, targets: {}, store: memoryStore() }); g.startup({ pid: 1 })
  assert.deepEqual(g.proposeOps.targets(), [])
  assert.throws(() => g.proposeOps.propose({ target: ACCENT, content: accent('#1E90FF'), claimed_base: 'absent' }), /not on the allowlist \(empty\)/)
  g.close()
})

test('sockets: propose 0660 without approval, owner 0600 with fixed approver, owner HTTP on loopback', async () => {
  const { gate, store, owner } = makeGate()
  const runDir = path.join(tmpHome(), 'run')
  const srv = await serveGate(gate, { runDir, ownerHttpPort: 0, ownerPage: true })
  try {
    assert.equal(fs.statSync(srv.proposeSocket).mode & 0o777, 0o660)
    assert.equal(fs.statSync(srv.ownerSocket).mode & 0o777, 0o600)
    const b = (await call(srv.proposeSocket, 'read', { target: ACCENT })).sha256
    const p = await call(srv.proposeSocket, 'propose', { target: ACCENT, content: accent('#1E90FF'), why: 'blue', claimed_base: b })
    await assert.rejects(call(srv.proposeSocket, 'approve', { id: p.id }), /unknown op/)
    await assert.rejects(call(srv.proposeSocket, 'decide', { id: p.id, outcome: 'allowed-once' }), /unknown op/)
    await assert.rejects(call(srv.proposeSocket, 'close', { id: p.id, outcome: 'allowed-once' }), /cannot approve/)
    const st = await call(srv.proposeSocket, 'status', {}); assert.match(st.proposals[0].id, /…$/)
    const pend = await call(srv.ownerSocket, 'pending', {}); assert.equal(pend.pending.length, 1); assert.ok(pend.pending[0].warnings)
    await assert.rejects(call(srv.ownerSocket, 'approve', { id: p.id }), /unknown op/)
    const rv = await call(srv.ownerSocket, 'review', { id: p.id })
    const r = await call(srv.ownerSocket, 'decide_review', { id: p.id, base_sha: rv.base_sha, new_sha: rv.new_sha, review_challenge: rv.review_challenge, outcome: 'allowed-once' })
    assert.equal(r.applied, true); assert.equal(r.receipt.approver, OWNER_SOCKET_APPROVER)
    assert.equal(store.read(ACCENT).toString(), accent('#1E90FF'))
    const res401 = await fetch(`http://127.0.0.1:${srv.port}/?k=nope`); assert.equal(res401.status, 401)
    const ok = await fetch(`http://127.0.0.1:${srv.port}/?k=${encodeURIComponent(owner.bearer)}`); assert.equal(ok.status, 200)
    assert.match(ok.headers.get('content-security-policy'), /frame-ancestors 'none'/)
    assert.equal(fs.readFileSync(path.join(runDir, 'receipt-ed25519.pub'), 'utf8'), gate.pubPem)
  } finally { await srv.close() }
})

test('owner web page is OFF unless asked for: no HTTP listener, no port file', async () => {
  const { gate } = makeGate()
  const runDir = path.join(tmpHome(), 'run')
  const srv = await serveGate(gate, { runDir, ownerHttpPort: 0 })
  try {
    assert.equal(srv.port, null); assert.equal(srv.page, null)
    assert.equal(fs.existsSync(path.join(runDir, 'owner-http.port')), false)
  } finally { await srv.close() }
})
