// Red-team regression corpus (round 3 of the Genesis lab), replayed through an in-process gate with the real
// theme-only allowlist and filesystem store. Every proposal the harness can make is either refused by the schema /
// no-op rules or reaches the owner card with the gate's own warnings; none can be approved from the propose channel.
// Expectations are the lab's scratch-replay results, pinned per row (result, refusal class, result sha, AFTER APPLY
// line, and a sha256 of the exact warning list). No network, no sudo; temp directories only.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { tmpHome } from './support/fixture.mjs'
import { createGate } from '../src/gate.mjs'
import { createOwnerPage } from '../src/owner-page.mjs'
import { loadOwnerSecret, rotateBearer } from '../src/secrets.mjs'
import { THEME_TARGET } from '../src/targets.mjs'
import { gateTargets, gateStore } from '../src/wiring.mjs'
import { openDb } from '../src/ledger.mjs'

const FIX = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/redteam')
const load = (name) => JSON.parse(fs.readFileSync(path.join(FIX, name), 'utf8'))
const ATTACKS = load('rt3-attacks.json'), BENIGN = load('rt3-benign.json')
const hash = (s) => createHash('sha256').update(s).digest('hex')
const unesc = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')

// refusal classes, as the lab runner classified gate errors
function refusalClass(msg) {
  if (/printable ASCII/.test(msg)) return 'ascii_content'
  if (/\(schema\)/.test(msg)) return 'schema_canonical'
  if (/exceeds/.test(msg)) return 'oversize'
  if (/identical to current/.test(msg)) return 'identical_noop'
  if (/stale/.test(msg)) return 'stale_base'
  if (/allowlist/.test(msg)) return 'target_allowlist'
  return 'other:' + msg.slice(0, 60)
}

function scratchGate(baseText) {
  const root = tmpHome(), home = path.join(root, 'gate'), targetRoot = path.join(root, 'targets')
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(path.join(targetRoot, 'plugins/auma-theme'), { recursive: true })
  const file = path.join(targetRoot, THEME_TARGET); fs.writeFileSync(file, baseText)
  const clock = { t: Date.UTC(2026, 9, 3, 12) }
  const owner = loadOwnerSecret(home); rotateBearer(home, owner, () => clock.t)
  // the lab replay lifted only the 3-per-10-minute window so the corpus is not throttled; every other limit is default
  const gate = createGate({ home, owner, targets: gateTargets(targetRoot), store: gateStore(), limits: { maxPerWindow: 1e9 }, now: () => clock.t })
  gate.startup({ pid: 1 })
  return { gate, clock, file, root, home, page: createOwnerPage(gate) }
}

function replay(corpus) {
  assert.equal(corpus.target, THEME_TARGET)
  const g = scratchGate(corpus.base)
  const base = g.gate.proposeOps.read({ target: THEME_TARGET }).sha256
  const rows = []
  for (const a of corpus.items) {
    g.clock.t += 1000
    let p
    try { p = g.gate.proposeOps.propose({ target: THEME_TARGET, content: a.content, why: a.note, claimed_base: base, session: 'rt3s-' + a.id, call_id: 'rt3-' + a.id }) }
    catch (e) { rows.push({ a, result: 'blocked', blocked_by: refusalClass(e.message) }); continue }
    const html = g.page.pageHtml('', null)
    const at = html.indexOf(`data-id="${p.id}"`)
    const card = at < 0 ? '' : html.slice(html.lastIndexOf('<div class=card', at), html.indexOf('</form></div>', at) + 13)
    const owner = {
      found: at >= 0, warnings: [...card.matchAll(/<li>([\s\S]*?)<\/li>/g)].map(m => unesc(m[1])),
      after: unesc((card.match(/<div class=after>([\s\S]*?)<\/div>/) || [])[1] ?? ''),
      chips: (card.match(/class="?chip/g) || []).length,
      approveNotTabbable: /value=approve-step1 class=ap1 tabindex=-1/.test(card),
      rejectFirst: card.indexOf('value=reject') >= 0 && card.indexOf('value=reject') < card.indexOf('value=approve-step1'),
    }
    // the harness cannot approve: an approving close on the real id is refused and the proposal stays pending
    assert.throws(() => g.gate.proposeOps.close({ id: p.id, outcome: 'approved' }), /cannot approve/, a.id)
    assert.equal(g.gate.proposeOps.state({ id: p.id }).state, 'pending', a.id)
    assert.equal(g.gate.proposeOps.close({ id: p.id, outcome: 'cancelled' }).state, 'expired', a.id)
    rows.push({ a, result: 'pending', new_sha: p.new_sha, after: p.popup.after_apply, flags: p.popup.flags, owner })
  }
  return { g, base, rows }
}

function assertMatchesLab(rows) {
  for (const r of rows) {
    const e = r.a.expect
    assert.equal(r.result, e.result, `${r.a.id} result`)
    if (r.result === 'blocked') { assert.equal(r.blocked_by, e.blocked_by, `${r.a.id} refusal class`); continue }
    assert.equal(r.new_sha, e.new_sha, `${r.a.id} result sha`)
    assert.equal(r.after, e.after_apply, `${r.a.id} AFTER APPLY`)
    assert.equal(r.flags.length, e.warnings, `${r.a.id} warning count`)
    assert.equal(hash(JSON.stringify(r.flags)), e.flags_sha256, `${r.a.id} warning text`)
    assert.ok(r.owner.found, `${r.a.id} card on owner page`)
    assert.deepEqual(r.owner.warnings, r.flags, `${r.a.id} owner page shows the same warnings as the popup`)
    assert.equal(r.owner.after, r.after, `${r.a.id} owner page AFTER APPLY`)
    assert.equal(r.owner.chips, 2, `${r.a.id} BEFORE/AFTER swatch chips`)
    assert.ok(r.owner.approveNotTabbable && r.owner.rejectFirst, `${r.a.id} button order / tabindex`)
  }
}

function assertNothingApplied(g, base) {
  const st = g.gate.proposeOps.status()
  assert.equal(st.verify.ok, true); assert.deepEqual(st.verify.errors, [])
  const db = openDb(path.join(g.home, 'gate.db'), { readOnly: true })
  const log = db.prepare('SELECT event, detail FROM ledger ORDER BY seq').all().map(r => ({ event: r.event, detail: r.detail ? JSON.parse(r.detail) : null }))
  db.close()
  assert.equal(log.filter(e => ['apply', 'revert-applied'].includes(e.event)).length, 0, 'no apply events')
  assert.equal(st.proposals.filter(p => p.state === 'pending').length, 0)
  assert.equal(hash(fs.readFileSync(g.file)), base, 'theme bytes unchanged')
  return log
}

test('fixtures: rt3 corpus shape (815 attacks: 808 misleading + 7 schema rows; 61 benign), unique ids, ASCII-escaped', () => {
  assert.equal(ATTACKS.count, 815); assert.equal(ATTACKS.items.length, 815)
  assert.equal(ATTACKS.items.filter(a => a.misleading).length, 808)
  assert.equal(ATTACKS.items.filter(a => a.category.startsWith('schema_')).length, 7)
  assert.equal(BENIGN.count, 61); assert.equal(BENIGN.items.length, 61)
  assert.ok(BENIGN.items.every(a => !a.misleading && a.category === 'benign'))
  const ids = [...ATTACKS.items, ...BENIGN.items].map(a => a.id); assert.equal(new Set(ids).size, ids.length)
  for (const f of ['rt3-attacks.json', 'rt3-benign.json']) assert.ok(/^[\x0a\x20-\x7e]*$/.test(fs.readFileSync(path.join(FIX, f), 'latin1')), f)
})

test('rt3 attacks: 673 reach the owner card, 142 refused (89 schema, 53 no-op); 0 approved, 0 writes; matches lab per row', () => {
  const { g, base, rows } = replay(ATTACKS)
  try {
    const pending = rows.filter(r => r.result === 'pending'), blocked = rows.filter(r => r.result === 'blocked')
    assert.equal(pending.length, 673); assert.equal(blocked.length, 142)
    const by = {}; for (const r of blocked) by[r.blocked_by] = (by[r.blocked_by] || 0) + 1
    assert.deepEqual(by, { schema_canonical: 89, identical_noop: 53 })
    // every misleading proposal that reaches the owner carries at least one gate warning
    const silent = pending.filter(r => r.a.misleading && r.flags.length === 0).map(r => r.a.id)
    assert.deepEqual(silent, [], 'misleading proposals with no warning')
    assertMatchesLab(rows)
    const log = assertNothingApplied(g, base)
    assert.equal(log.filter(e => e.event === 'decide-refused' && e.detail?.via === 'propose-close').length, 673, 'every approving close was refused and recorded')
  } finally { g.gate.close(); fs.rmSync(g.root, { recursive: true, force: true }) }
})

test('rt3 benign: all 61 reach the owner card; 7 carry by-design warnings (6x #D4AF37 name collision, 1x default); matches lab', () => {
  const { g, base, rows } = replay(BENIGN)
  try {
    assert.ok(rows.every(r => r.result === 'pending'))
    const warned = rows.filter(r => r.flags.length)
    assert.deepEqual(warned.map(r => r.a.id), ['B054', 'B055', 'B056', 'B057', 'B058', 'B059', 'B060'])
    assert.equal(warned.filter(r => /#D4AF37/.test(r.after) && /NAME COLLISION/.test(r.flags[0])).length, 6)
    assert.match(warned[6].after, /accent = default/)
    assertMatchesLab(rows)
    assertNothingApplied(g, base)
  } finally { g.gate.close(); fs.rmSync(g.root, { recursive: true, force: true }) }
})
