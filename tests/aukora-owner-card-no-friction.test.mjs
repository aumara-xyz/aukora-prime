// NO FRICTION ON THE OWNER CARD + "PLUGIN SET UNCHANGED" GATE FACT (Peter, 2026-10-04 14:52 WITA, overriding 14:28).
// Approve is available as soon as the gate review is on the card: no reveal, scroll, dwell or typed characters, on any
// target (theme or plugin set). The gate facts stay first and the model's words stay fenced (owner-card test). The
// plugin-set card states as a gate fact whether the set is byte-equal to the owner's previous approval.
// NF_MUTANT puts one piece of friction back (or breaks the fact) in memory to prove each check bites.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import vm from 'node:vm'
import { accent, ACCENT, accentTarget, memoryStore, tmpHome } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { loadOwnerSecret, rotateBearer } from '../packages/boundary-gate/src/secrets.mjs'
import { serveGate } from '../packages/boundary-gate/src/server.mjs'

const M = process.env.NF_MUTANT ?? ''
const root = new URL('../', import.meta.url)
const read = rel => fs.readFileSync(new URL(rel, root), 'utf8')
const mutate = (src, name, a, b) => { if (M !== name) return src; const o = src.replace(a, b); assert.notEqual(o, src, name); return o }
async function importMutated(rel, src) {
  const base = new URL(rel, root)
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, base).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const targetsSrc = mutate(read('packages/boundary-gate/src/targets.mjs'), 'always-unchanged',
  'const same = b && b.plugin_set === a.plugin_set', 'const same = b')
const adapterSrc = mutate(read('apps/aukora-desktop/aumlok-signer-airlock.mjs'), 'adapter-bound-400',
  "/^[\\x20-\\x7e]{1,600}$/u.test(value.from_to)", "/^[\\x20-\\x7e]{1,400}$/u.test(value.from_to)")
let html = read('apps/aukora-desktop/aumlok-approval.html')
html = mutate(html, 'reveal-gate-back', '&& Date.now() < gateReviewExpires', '&& gateRevealed === true && Date.now() < gateReviewExpires')
html = mutate(html, 'dwell-back', "btn.addEventListener('click', function () { pre.hidden = false; btn.hidden = true })",
  "btn.addEventListener('click', function () { pre.hidden = false; btn.hidden = true; setTimeout(function () {}, 1500) })")
const bridgeSrc = mutate(read('apps/aukora-desktop/aumlok-bridge.mjs'), 'bridge-revealed-back',
  '|| payload.wordsOk !== true))) {', '|| payload.wordsOk !== true || payload.revealed !== true))) {')

const { createGate } = await import('../packages/boundary-gate/src/gate.mjs')
const targetsMod = await importMutated('packages/boundary-gate/src/targets.mjs', targetsSrc)
const { createGateOwnerAdapter } = await importMutated('apps/aukora-desktop/aumlok-signer-airlock.mjs', adapterSrc)
const fn = name => { const m = html.match(new RegExp(`\\n    function ${name}\\([^]*?\\n    \\}\\n`, 'u')); assert.ok(m, name); return m[0] }
const h = c => c.repeat(64)
const approval = (rel, set, rec) => targetsMod.pluginSetApprovalText({ release: rel, release_dir: 'release-' + rel.slice(0, 7), plugin_set: set, operation: h('b'), record: rec })
const R1 = '7561a97f270e34768dc271f083e091574f7078d2', R2 = '524b8f52906240799ff2ff4727caed637b2dfd73'

test('gate fact: "plugin set unchanged since your approval of <release>" only when the set digest is byte-equal', () => {
  const spec = targetsMod.pluginSetTarget('/var/lib/x', { releasesRoot: '/nonexistent', floorFile: path.join(tmpHome(), 'release-floor.json') })
  assert.equal(spec.approvalTier, undefined, 'no typed-approval tier on the plugin-set target')
  const prev = approval(R1, h('a'), h('c')), same = approval(R2, h('a'), h('d')), changed = approval(R2, h('e'), h('d'))
  assert.match(spec.plain(prev, same), /^GATE FACT: plugin set UNCHANGED since your approval of release-7561a97 \(7561a97f270e\), operation unchanged \| ADMIT/)
  assert.match(spec.plain(prev, changed), /^GATE FACT: plugin set CHANGED since your approval of release-7561a97 \| ADMIT/)
  assert.match(spec.plain('', same), /^GATE FACT: first plugin-set approval on this gate \| ADMIT/)
  assert.ok(spec.plain(prev, same).length > 400 && spec.plain(prev, same).length <= 600, 'needs the 600-char from_to bound')
})

test('gate + adapter: review v2 has no tier; a plain Approve applies with no typed confirmation; the long fact reaches the card', async () => {
  const clock = { t: Date.UTC(2026, 9, 4, 7) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  // A test target whose from->to is the real (long) plugin-set fact line, applied through the normal owner path.
  const LONG = 'test/long.json'
  const longTarget = { ...accentTarget, entry: 'test-long', plain: () => targetsMod.pluginSetTarget('/x', { releasesRoot: '/nonexistent', floorFile: path.join(home, 'release-floor.json') }).plain(approval(R1, h('a'), h('c')), approval(R2, h('a'), h('d'))) }
  const store = memoryStore({ [ACCENT]: accent('#00BFFF'), [LONG]: accent('#111111') })
  const gate = createGate({ home, owner, targets: { [ACCENT]: accentTarget, [LONG]: longTarget }, store, now: () => clock.t })
  gate.startup({ pid: 1 })
  const srv = await serveGate(gate, { runDir: fs.mkdtempSync(path.join(os.tmpdir(), 'nf-run-')), ownerHttpPort: 0 })
  try {
    const r = gate.ownerOps.review({ id: gate.proposeOps.propose({ target: ACCENT, content: accent('#1E90FF'), why: 'TEST', claimed_base: gate.proposeOps.read({ target: ACCENT }).sha256, session: 's' }).id })
    assert.equal(r.version, 2); assert.equal(Object.hasOwn(r, 'tier'), false)
    assert.throws(() => gate.ownerOps.decide_review({ id: r.id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome: 'allowed-once', confirm: r.new_sha.slice(0, 4) }, 'owner-socket'), /exactly/)
    const r2 = gate.ownerOps.review({ id: r.id })
    assert.equal(gate.ownerOps.decide_review({ id: r2.id, base_sha: r2.base_sha, new_sha: r2.new_sha, review_challenge: r2.review_challenge, outcome: 'allowed-once' }, 'owner-socket').applied, true, 'theme: plain approve applies')
    gate.proposeOps.propose({ target: LONG, content: accent('#222222'), why: 'TEST', claimed_base: gate.proposeOps.read({ target: LONG }).sha256, session: 's' })
    const a = createGateOwnerAdapter({ socketPath: srv.ownerSocket, now: () => clock.t })
    const q = await a.pending()
    assert.equal(q.approveAvailable, true, 'the 400..600-char gate fact is accepted by the card adapter')
    assert.match(q.review.from_to, /^GATE FACT: plugin set UNCHANGED since your approval of release-7561a97/)
    const out = await a.decide(q.uiQuestionId, true, () => true)
    assert.equal(out.applied, true, 'a plain Approve, no typed characters')
    assert.equal(store.read(LONG).toString(), accent('#222222'))
  } finally { await srv.close?.() }
})

test('card: Approve is available as soon as the review is shown; "Show the exact change" only reveals; bridge needs no reveal', () => {
  const elig = vm.runInNewContext(fn('approveEligible') + '; approveEligible()',
    { gateMode: true, settled: false, challenge: 'c', gateDisplayOk: true, gateRevealed: false, gateReviewExpires: Date.now() + 60000 })
  assert.equal(elig, true, 'not revealed, no dwell -> Approve available')
  assert.equal(vm.runInNewContext(fn('approveEligible') + '; approveEligible()',
    { gateMode: true, settled: false, challenge: 'c', gateDisplayOk: false, gateReviewExpires: Date.now() + 60000 }), false, 'an unverified review still cannot be approved')
  const listeners = {}, timers = []
  const el = (id, extra = {}) => ({ id, hidden: false, textContent: '', addEventListener(k, f) { (listeners[id + ':' + k] ??= []).push(f) }, ...extra })
  const els = { 'gate-reveal': el('gate-reveal'), 'gate-diff': el('gate-diff', { hidden: true }) }
  vm.runInNewContext(fn('armGateReveal') + '; armGateReveal()', { document: { getElementById: id => els[id] }, setTimeout: (f, ms) => timers.push([f, ms]) })
  listeners['gate-reveal:click'][0]()
  assert.equal(els['gate-diff'].hidden, false); assert.equal(timers.length, 0, 'no dwell timer')
  assert.doesNotMatch(html, /gateRevealed|GATE_REVEAL_DWELL_MS|gate-typed|gateTypedOk/u, 'no reveal/dwell/typed state left in the card')
  assert.doesNotMatch(bridgeSrc, /payload\.revealed|payload\.confirm/u, 'the bridge asks for no reveal and no typed confirmation')
  assert.match(bridgeSrc, /payload\.approve && \(gateEntry\.facts\.approveAvailable !== true \|\| payload\.wordsOk !== true\)\)\) \{/u)
})
