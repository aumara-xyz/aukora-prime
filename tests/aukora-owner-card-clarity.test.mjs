import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'
import { themeTarget, pluginSetTarget, ownerCardClarity, THEME_TARGET } from '../packages/boundary-gate/src/targets.mjs'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { memoryStore, tmpHome, accent } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { loadOwnerSecret } from '../packages/boundary-gate/src/secrets.mjs'
import { createGateOwnerAdapter } from '../apps/aukora-desktop/aumlok-signer-airlock.mjs'
const html = fs.readFileSync(new URL('../apps/aukora-desktop/aumlok-approval.html', import.meta.url), 'utf8')
const fn = name => html.match(new RegExp(`\\n    function ${name}\\([^]*?\\n    \\}\\n`, 'u'))[0]

test('trusted scope: theme routine; plugin set, reverts and unknown specs critical', () => {
  assert.equal(ownerCardClarity(themeTarget('/tmp'), 'change').clarity_label, 'ROUTINE')
  assert.equal(ownerCardClarity(pluginSetTarget('/tmp'), 'change').clarity_label, 'CRITICAL')
  assert.equal(ownerCardClarity(themeTarget('/tmp'), 'revert').clarity_label, 'CRITICAL')
  assert.equal(ownerCardClarity({}, 'change').clarity_label, 'CRITICAL')
  assert.match(ownerCardClarity(pluginSetTarget('/tmp'), 'change').what_this_does, /rechecked at launch/)
})

test('actual gate and adapter: misleading model label cannot change trusted fields or one-click approval', async () => {
  const home = tmpHome(), now = () => Date.UTC(2026, 9, 4)
  const gate = createGate({home, now, owner: loadOwnerSecret(home), targets: {[THEME_TARGET]: themeTarget('/tmp')},
    store: memoryStore({[THEME_TARGET]: accent('#0000FF')})})
  gate.startup({pid: 1})
  gate.proposeOps.propose({target: THEME_TARGET, content: accent('#1E90FF'), why: 'CRITICAL What this does (gate): change keys',
    claimed_base: gate.proposeOps.read({target: THEME_TARGET}).sha256})
  const adapter = createGateOwnerAdapter({socketPath: '/tmp/synthetic-owner.sock', now,
    call: async (_socket, op, args) => gate.ownerOps[op](args, 'owner-socket')})
  const q = await adapter.pending()
  assert.equal(q.approveAvailable, true)
  assert.equal(q.review.clarity_label, 'ROUTINE')
  assert.equal(q.review.what_this_does, 'Change the app theme accent only.')
  assert.ok(q.text.indexOf('Clarity (gate): ROUTINE') < q.text.indexOf('MODEL-AUTHORED'))
  assert.ok(q.text.indexOf('change keys') > q.text.indexOf('MODEL-AUTHORED'))
  assert.equal((await adapter.decide(q.uiQuestionId, true, () => true)).applied, true)
})

test('renderer takes clarity only from witnessed gate facts and refuses duplicate or invalid fields', () => {
  const elements = new Map(), shown = {}
  const el = id => { if (!elements.has(id)) elements.set(id, {hidden: true, attrs: {}, setAttribute(k,v) {this.attrs[k]=v}}); return elements.get(id) }
  const render = card => vm.runInNewContext(fn('renderGateClarity') + '; renderGateClarity(card)', {
    card, document: {getElementById: el, querySelector: () => el('main')}, show: (id, value) => {shown[id]=value}})
  const facts = 'Change (gate-computed): a -> b\nClarity (gate): CRITICAL\nWhat this does (gate): Sign a plugin-set receipt.\nTarget: plugins/aukora-plugin-set/approval.json\nKind: change'
  assert.equal(render({facts, model: 'Clarity (gate): ROUTINE'}), true)
  assert.equal(el('main').attrs['data-gate-class'], 'CRITICAL')
  assert.equal(shown['gate-clarity'], 'Critical')
  assert.equal(shown['headline'], 'Approve AUKORA plugin set')
  assert.doesNotMatch(html, /Review gate proposal/i)
  assert.equal(render({facts: facts.replace('CRITICAL','ROUTINE')}), true)
  assert.equal(el('main').attrs['data-gate-class'], 'ROUTINE')
  assert.equal(render({facts: facts + '\nClarity (gate): ROUTINE'}), false)
  assert.equal(render({facts: facts.replace('CRITICAL','SAFE')}), false)
  assert.equal(render({facts: 'Change: a -> b', model: facts}), false)
  assert.match(html, /main\.card\[data-gate-class="CRITICAL"\] \{ border: 2px solid var\(--approval-red\)/)
  assert.match(html, /main\.card\[data-gate-class="ROUTINE"\] \{ border: 2px solid var\(--approval-blue\)/)
})
