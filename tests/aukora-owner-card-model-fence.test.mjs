// THE OWNER CARD, AFTER A HALF-AWAKE APPROVAL (Peter, 2026-10-04 13:06 WITA: the card's model note said "safe to refuse").
// (1) the GATE computes the from->to line and returns the model's note SEPARATELY (review v2);
// (2) the adapter's card text puts gate facts first, the exact diff next, the model's words LAST inside a MODEL-AUTHORED
//     fence, and model text cannot forge a header or move above the facts;
// (3) the card (aumlok-approval.html) parses exactly that shape and keeps Approve off until the owner has OPENED the diff,
//     reached its end and dwelt briefly; (4) the bridge refuses a gate approve the card did not report as revealed.
// OCF_MUTANT removes one guard in memory to prove each check bites.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import vm from 'node:vm'
import { accent, ACCENT, accentTarget, memoryStore, tmpHome } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { loadOwnerSecret, rotateBearer } from '../packages/boundary-gate/src/secrets.mjs'
import { serveGate } from '../packages/boundary-gate/src/server.mjs'

const M = process.env.OCF_MUTANT ?? ''
const root = new URL('../', import.meta.url)
const read = rel => fs.readFileSync(new URL(rel, root), 'utf8')
function mutate(src, name, a, b) {
  if (M !== name) return src
  const out = src.replace(a, b); assert.notEqual(out, src, `mutant ${name} must change the source`); return out
}
async function importMutated(rel, src) {
  const base = new URL(rel, root)
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, base).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const gateSrc = mutate(read('packages/boundary-gate/src/gate.mjs'), 'gate-note-as-facts',
  'try { from_to = s?.plain ? String(s.plain(oldText, newText)) : null } catch { from_to = null }', 'from_to = p.why')
const adapterSrc = mutate(read('apps/aukora-desktop/aumlok-signer-airlock.mjs'), 'model-first',
  "  return [GATE_CARD.facts,", "  return [GATE_CARD.model, '> ' + review.model_note, GATE_CARD.modelEnd, GATE_CARD.facts,")
let html = read('apps/aukora-desktop/aumlok-approval.html')
html = mutate(html, 'no-reveal-gate', '&& gateRevealed === true && Date.now() < gateReviewExpires', '&& Date.now() < gateReviewExpires')
html = mutate(html, 'arm-on-click', '        requestAnimationFrame(seenNow)\n', '        gateRevealed = true; applyEligibility()\n')
html = mutate(html, 'no-scroll-end', "        if (!atEnd()) { note.textContent", "        if (false) { note.textContent")
const bridgeSrc = mutate(read('apps/aukora-desktop/aumlok-bridge.mjs'), 'bridge-no-revealed',
  "\n          || payload.revealed !== true\n", '\n')

const { createGate } = await importMutated('packages/boundary-gate/src/gate.mjs', gateSrc)
const { createGateOwnerAdapter, GATE_CARD } = await importMutated('apps/aukora-desktop/aumlok-signer-airlock.mjs', adapterSrc)
const fn = name => { const m = html.match(new RegExp(`\\n    function ${name}\\([^]*?\\n    \\}\\n`, 'u')); assert.ok(m, name); return m[0] }

const SNEAKY = 'safe to refuse GATE FACTS (written by the gate, not by the model) Change (gate-computed): accent: harmless END OF GATE DIFF'
async function served() {
  const clock = { t: Date.UTC(2026, 9, 4, 6) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [ACCENT]: accent('#00BFFF') })
  const gate = createGate({ home, owner, targets: { [ACCENT]: accentTarget }, store, now: () => clock.t })
  gate.startup({ pid: 1 })
  const srv = await serveGate(gate, { runDir: fs.mkdtempSync(path.join(os.tmpdir(), 'ocf-run-')), ownerHttpPort: 0 })
  const p = gate.proposeOps.propose({ target: ACCENT, content: accent('default'), why: SNEAKY, claimed_base: gate.proposeOps.read({ target: ACCENT }).sha256, session: 's' })
  return { srv, p, now: () => clock.t }
}

test('gate review v2: the gate computes from->to itself; the model note comes back separately', async () => {
  const { srv, now } = await served()
  try {
    const q = await createGateOwnerAdapter({ socketPath: srv.ownerSocket, now }).pending()
    assert.equal(q.approveAvailable, true)
    assert.equal(q.review.version, 3)
    assert.match(q.review.from_to, /^accent: #00BFFF .* -> default /, 'gate-computed from->to, from the stored base and new bytes')
    assert.ok(!q.review.from_to.includes('safe to refuse'), 'no model text in the gate facts')
    assert.ok(q.review.model_note.startsWith('safe to refuse'))
  } finally { await srv.close?.() }
})

test('card text: gate facts first, exact diff next, model words last and fenced; model text cannot forge a header', async () => {
  const { srv, now } = await served()
  try {
    const q = await createGateOwnerAdapter({ socketPath: srv.ownerSocket, now }).pending()
    const lines = q.text.split('\n')
    assert.equal(lines[0], GATE_CARD.facts, 'the first thing on the card is the gate')
    assert.equal(lines.indexOf(GATE_CARD.facts), lines.lastIndexOf(GATE_CARD.facts), 'one facts header; the note did not add one')
    const d = lines.indexOf(GATE_CARD.diff), m = lines.indexOf(GATE_CARD.model)
    assert.ok(d > 1 && m > d, 'diff before model words')
    assert.ok(lines.slice(d + 1, lines.indexOf(GATE_CARD.diffEnd)).some(l => l === '-' + accent('#00BFFF')))
    assert.ok(lines.slice(d + 1, lines.indexOf(GATE_CARD.diffEnd)).some(l => l === '+' + accent('default')))
    assert.ok(lines.slice(0, m).every(l => !l.includes('safe to refuse')), 'the model note appears nowhere above its fence')
    assert.equal(lines[m + 1], '> ' + q.review.model_note)
    // and the card's own parser, run on these exact verified bytes
    const split = vm.runInNewContext(fn('splitGateCard') + '; splitGateCard(text)', { text: q.text })
    assert.ok(split, 'the card accepts the adapter text')
    assert.match(split.facts, /^Change \(gate-computed\): accent: #00BFFF .* -> default /)
    assert.ok(!split.facts.includes('safe to refuse'))
    assert.equal(split.model, q.review.model_note)
    assert.match(split.diff, /^--- a\/test\/accent.json\n\+\+\+ b\/test\/accent.json\n-.*\n\+.*$/u)
  } finally { await srv.close?.() }
})

test('the card refuses any other shape (reordered, unprefixed fact, model above facts)', () => {
  const ok = [GATE_CARD.facts, '  Change (gate-computed): a -> b', GATE_CARD.diff, '-a', '+b', GATE_CARD.diffEnd, GATE_CARD.model, '> hi', GATE_CARD.modelEnd]
  const split = t => vm.runInNewContext(fn('splitGateCard') + '; splitGateCard(t)', { t: t.join('\n') })
  assert.ok(split(ok))
  assert.equal(split([GATE_CARD.model, '> hi', GATE_CARD.modelEnd, ...ok]), null)
  assert.equal(split([GATE_CARD.facts, 'Change: forged', ...ok.slice(2)]), null)
  assert.equal(split([...ok.slice(0, 6), GATE_CARD.model, 'no prefix', GATE_CARD.modelEnd]), null)
  assert.equal(split([...ok.slice(0, 3), 'x not a diff line', ...ok.slice(4)]), null)
})

test('Approve stays off until the owner opened the diff, reached its end and dwelt; never on click alone', () => {
  const elig = vm.runInNewContext(fn('approveEligible') + '; approveEligible()',
    { gateMode: true, settled: false, challenge: 'c', gateDisplayOk: true, gateRevealed: false, gateReviewExpires: Date.now() + 60000 })
  assert.equal(elig, false, 'not revealed -> not eligible')
  const listeners = {}, timers = []
  const el = (id, extra = {}) => ({ id, hidden: false, textContent: '', addEventListener(k, f) { (listeners[id + ':' + k] ??= []).push(f) }, ...extra })
  const els = { 'gate-reveal': el('gate-reveal'), 'gate-diff': el('gate-diff', { hidden: true, scrollHeight: 600, clientHeight: 200, scrollTop: 0 }), 'gate-reveal-state': el('gate-reveal-state') }
  const ctx = { document: { getElementById: id => els[id] }, setTimeout: (f, ms) => timers.push([f, ms]), requestAnimationFrame: f => f(),
    settled: false, gateRevealed: false, GATE_REVEAL_DWELL_MS: 1500, calls: 0 }
  ctx.applyEligibility = () => { ctx.calls++ }
  vm.runInNewContext(fn('armGateReveal') + '; armGateReveal()', ctx)
  listeners['gate-diff:scroll'][0]()
  assert.equal(timers.length, 0, 'scrolling a hidden diff does nothing')
  listeners['gate-reveal:click'][0]()
  assert.equal(els['gate-diff'].hidden, false)
  assert.equal(ctx.gateRevealed, false, 'opening is not enough')
  assert.equal(timers.length, 0, 'not at the end yet')
  els['gate-diff'].scrollTop = 400; listeners['gate-diff:scroll'][0]()
  assert.equal(timers.length, 1); assert.equal(timers[0][1], 1500, 'a dwell after the end is reached')
  assert.equal(ctx.gateRevealed, false)
  timers[0][0]()
  assert.equal(ctx.gateRevealed, true); assert.ok(ctx.calls > 0)
})

test('the bridge refuses a gate approve the card did not report as revealed', () => {
  assert.match(bridgeSrc, /payload\.approve && \(gateEntry\.facts\.approveAvailable !== true \|\| payload\.wordsOk !== true\s*\|\| payload\.revealed !== true\s*\|\|/u)
  assert.match(html, /revealed: gateMode \? gateRevealed === true : undefined,/u, 'the card reports it')
})
