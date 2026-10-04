// TIERED OWNER APPROVAL + "PLUGIN SET UNCHANGED" GATE FACT (Peter, 2026-10-04 14:28 WITA).
// Theme targets keep the reveal check. Plugin-set (and future code) targets are tier 'hash4': the GATE refuses an approve
// unless the owner typed the first 4 characters of the new SHA-256; the adapter, bridge and card hold the same line.
// The plugin-set card states as a gate fact when the set is byte-equal to the owner's previous approval.
// TIER_MUTANT removes one guard in memory to prove each check bites.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import vm from 'node:vm'
import { accent, ACCENT, accentTarget, memoryStore, tmpHome } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { loadOwnerSecret, rotateBearer } from '../packages/boundary-gate/src/secrets.mjs'
import { serveGate } from '../packages/boundary-gate/src/server.mjs'

const M = process.env.TIER_MUTANT ?? ''
const root = new URL('../', import.meta.url)
const read = rel => fs.readFileSync(new URL(rel, root), 'utf8')
const mutate = (src, name, a, b) => { if (M !== name) return src; const o = src.replace(a, b); assert.notEqual(o, src, name); return o }
async function importMutated(rel, src) {
  const base = new URL(rel, root)
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, base).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const gateSrc = mutate(read('packages/boundary-gate/src/gate.mjs'), 'gate-no-hash4',
  "      && (typeof args.confirm !== 'string' || args.confirm.toLowerCase() !== p.new_sha.slice(0, 4))) refuse(", '      && false) refuse(')
const targetsSrc = mutate(read('packages/boundary-gate/src/targets.mjs'), 'always-unchanged',
  'const same = b && b.plugin_set === a.plugin_set', 'const same = b')
const adapterSrc = mutate(read('apps/aukora-desktop/aumlok-signer-airlock.mjs'), 'adapter-no-typed',
  "      if (typed && (typeof confirm !== 'string' || confirm.toLowerCase() !== expected.review.new_sha.slice(0, 4))) {", '      if (false) {')
const html = mutate(read('apps/aukora-desktop/aumlok-approval.html'), 'html-no-typed', '&& gateTypedOk() === true ', '')
const bridgeSrc = mutate(read('apps/aukora-desktop/aumlok-bridge.mjs'), 'bridge-no-confirm',
  "          || (gateEntry.facts.review?.tier === 'hash4'", "          || (false")

const { createGate } = await importMutated('packages/boundary-gate/src/gate.mjs', gateSrc)
const { parsePluginSetApproval, pluginSetApprovalText } = await importMutated('packages/boundary-gate/src/targets.mjs', targetsSrc)
const targetsMod = await importMutated('packages/boundary-gate/src/targets.mjs', targetsSrc)
const { createGateOwnerAdapter } = await importMutated('apps/aukora-desktop/aumlok-signer-airlock.mjs', adapterSrc)
const fn = name => { const m = html.match(new RegExp(`\\n    function ${name}\\([^]*?\\n    \\}\\n`, 'u')); assert.ok(m, name); return m[0] }

const CODE = 'test/code.json'
const codeTarget = { ...accentTarget, entry: 'test-code', approvalTier: 'hash4' }
function world() {
  const clock = { t: Date.UTC(2026, 9, 4, 6, 30) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [ACCENT]: accent('#00BFFF'), [CODE]: accent('#111111') })
  const gate = createGate({ home, owner, targets: { [ACCENT]: accentTarget, [CODE]: codeTarget }, store, now: () => clock.t })
  gate.startup({ pid: 1 })
  const propose = (t, hex) => gate.proposeOps.propose({ target: t, content: accent(hex), why: 'TEST', claimed_base: gate.proposeOps.read({ target: t }).sha256, session: 's' })
  const decide = (r, extra = {}) => gate.ownerOps.decide_review({ id: r.id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome: 'allowed-once', ...extra }, 'owner-socket')
  return { gate, store, clock, propose, decide }
}

test('gate: a hash4 target applies only with the typed first 4 of the new SHA-256; a reveal target takes none', () => {
  const w = world()
  const p = w.propose(CODE, '#222222')
  let r = w.gate.ownerOps.review({ id: p.id })
  assert.equal(r.version, 3); assert.equal(r.tier, 'hash4')
  assert.throws(() => w.decide(r), /typed confirmation missing or wrong/)
  r = w.gate.ownerOps.review({ id: p.id })
  assert.throws(() => w.decide(r, { confirm: 'ffff' === r.new_sha.slice(0, 4) ? '0000' : 'ffff' }), /typed confirmation missing or wrong/)
  assert.equal(w.store.read(CODE).toString(), accent('#111111'), 'nothing applied')
  r = w.gate.ownerOps.review({ id: p.id })
  const out = w.decide(r, { confirm: r.new_sha.slice(0, 4).toUpperCase() })
  assert.equal(out.applied, true); assert.equal(w.store.read(CODE).toString(), accent('#222222'))
  // reject needs no typing
  const q = w.propose(CODE, '#333333'); const rq = w.gate.ownerOps.review({ id: q.id })
  assert.equal(w.gate.ownerOps.decide_review({ id: q.id, base_sha: rq.base_sha, new_sha: rq.new_sha, review_challenge: rq.review_challenge, outcome: 'rejected' }, 'owner-socket').state, 'refused')
  // a theme (reveal) target refuses a confirm key and applies without it (past the 60 s post-reject cooldown)
  w.clock.t += 61000
  const t = w.propose(ACCENT, '#1E90FF'); let rt = w.gate.ownerOps.review({ id: t.id })
  assert.equal(rt.tier, 'reveal')
  assert.throws(() => w.decide(rt, { confirm: rt.new_sha.slice(0, 4) }), /takes no typed confirmation/)
  rt = w.gate.ownerOps.review({ id: t.id })
  assert.equal(w.decide(rt).applied, true)
})

test('gate fact: "plugin set unchanged since your approval of <release>" only when the set digest is byte-equal', () => {
  const h = c => c.repeat(64), spec = targetsMod.pluginSetTarget('/var/lib/x', { releasesRoot: '/nonexistent' })
  assert.equal(spec.approvalTier, 'hash4', 'the plugin-set target is typed tier')
  const prev = pluginSetApprovalText({ release: '7561a97f270e34768dc271f083e091574f7078d2', release_dir: 'release-7561a97', plugin_set: h('a'), operation: h('b'), record: h('c') })
  const same = pluginSetApprovalText({ release: '524b8f52906240799ff2ff4727caed637b2dfd73', release_dir: 'release-524b8f5', plugin_set: h('a'), operation: h('b'), record: h('d') })
  const changed = pluginSetApprovalText({ release: '524b8f52906240799ff2ff4727caed637b2dfd73', release_dir: 'release-524b8f5', plugin_set: h('e'), operation: h('b'), record: h('d') })
  assert.match(spec.plain(prev, same), /^GATE FACT: plugin set UNCHANGED since your approval of release-7561a97 \(7561a97f270e\), operation unchanged \| ADMIT/)
  assert.match(spec.plain(prev, changed), /^GATE FACT: plugin set CHANGED since your approval of release-7561a97 \| ADMIT/)
  assert.match(spec.plain('', same), /^GATE FACT: first plugin-set approval on this gate \| ADMIT/)
  assert.ok(spec.plain(prev, same).length <= 600, 'fits the v3 from_to bound')
  assert.ok(parsePluginSetApproval(same))
})

test('adapter: a hash4 approve without the typed prefix is refused locally and the question stays answerable', async () => {
  const w = world()
  const srv = await serveGate(w.gate, { runDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tier-run-')), ownerHttpPort: 0 })
  try {
    w.propose(CODE, '#444444')
    const a = createGateOwnerAdapter({ socketPath: srv.ownerSocket, now: () => w.clock.t })
    const q = await a.pending()
    assert.equal(q.review.tier, 'hash4'); assert.match(q.text, /Approval tier: TYPED/)
    const no = await a.decide(q.uiQuestionId, true, () => true, null)
    assert.equal(no.applied, false); assert.equal(no.reason, 'gate:typed-confirmation-required')
    const ok = await a.decide(q.uiQuestionId, true, () => true, q.review.new_sha.slice(0, 4))
    assert.equal(ok.applied, true, 'same question, now with the typed prefix')
  } finally { await srv.close?.() }
})

test('card + bridge: Approve needs the typed prefix on a hash4 card; the bridge refuses an approve without it', () => {
  const typedOk = v => vm.runInNewContext(fn('gateTypedOk') + '; gateTypedOk()', { gateTier: 'hash4', gateNewSha: 'ab12' + 'c'.repeat(60), document: { getElementById: () => ({ value: v }) } })
  assert.equal(typedOk(''), false); assert.equal(typedOk('ab13'), false); assert.equal(typedOk('AB12'), true)
  const elig = typed => vm.runInNewContext(fn('gateTypedOk') + fn('approveEligible') + '; approveEligible()', { gateMode: true, settled: false, challenge: 'c', gateDisplayOk: true,
    gateRevealed: true, gateReviewExpires: Date.now() + 60000, gateTier: 'hash4', gateNewSha: 'ab12' + 'c'.repeat(60), document: { getElementById: () => ({ value: typed }) } })
  assert.equal(elig('zz'), false, 'revealed but not typed -> no Approve'); assert.equal(elig('ab12'), true)
  assert.match(bridgeSrc, /\(gateEntry\.facts\.review\?\.tier === 'hash4' && \(typeof payload\.confirm !== 'string'\s*\|\| payload\.confirm\.toLowerCase\(\) !== String\(gateEntry\.facts\.review\.new_sha\)\.slice\(0, 4\)\)\)/u)
})
