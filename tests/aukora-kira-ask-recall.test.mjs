// SPDX-License-Identifier: AGPL-3.0-or-later
// The per-step recall asks memory with the person's own latest message first. Synthetic messages and
// a disposable store only; no model, private key or live service. KIRA_ASK_MUTANT removes the guard in memory.
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { preTurnRecallFilter, recallFilter } from '../plugins/aukora-kira/lib/memory-frame.mjs'
import { createTrackedMemory } from '../plugins/aukora-kira/lib/tracked-memory.mjs'

const url = new URL('../plugins/aukora-kira/lib/injection.mjs', import.meta.url)
async function load() {
  const mutant = process.env.KIRA_ASK_MUTANT
  if (!mutant) return import(url.href)
  let source = readFileSync(url, 'utf8')
  const original = source
  if (mutant === 'no-ask') source = source.replace('ask: latestAsk(decision?.messages)', "ask: ''")
  else if (mutant === 'any-role') source = source.replace("message?.source?.kind !== 'user'", 'false')
  else if (mutant === 'no-tiering') source = source.replace('reply = preTurnReply(reply)\n      recent = preTurnReply(recent)', '')
  else throw new Error('unknown mutant')
  assert.notEqual(source, original, 'the mutant must remove the guard')
  source = source.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, rel) => `from ${JSON.stringify(new URL(rel, url).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}
const { registerRecallInjection, latestAsk, OPENING_QUERIES } = await load()

const person = text => ({ role: 'user', content: [{ type: 'text', text }], source: { kind: 'user', rpcId: 'r1' } })
const plugin = text => ({ role: 'user', content: [{ type: 'text', text }], source: { kind: 'plugin', plugin: 'dsh-system-prompt' } })

function harness(options = {}) {
  let handler
  const asked = []
  const ctx = { on: (name, fn) => { assert.equal(name, 'agent/pre-step'); handler = fn; return () => {} } }
  registerRecallInjection(ctx, {
    conversation: { turn: async ({ action, text }) => { if (action === 'query') asked.push(text); return { availability: 'empty', snippets: [] } } },
    newId: () => 'id', ...options,
  })
  return { asked, step: messages => handler({ agent: { session: {} } }, async () => ({ kind: 'continue', messages })) }
}

test('the latest person message is asked first, before the fixed queries', async () => {
  const { asked, step } = harness()
  await step([person('Remember that my sister is Maya.'), { role: 'assistant', content: [] },
    person("  What's my   sister's name?  "), plugin('Current runtime context. DSH file policy: workspace-write.')])
  assert.equal(asked[0], "What's my sister's name?")
  assert.deepEqual(asked.slice(1), [...OPENING_QUERIES])
})

test('plugin user-role snapshots are never the query', async () => {
  assert.equal(latestAsk([plugin('KIRA RECALL — data'), plugin('runtime context')]), '')
  const { asked, step } = harness()
  await step([plugin('Current runtime context.')])
  assert.deepEqual(asked, [...OPENING_QUERIES])
})

test('bounded, text parts only, and explicit queries still win', async () => {
  assert.equal(latestAsk([person('x'.repeat(2000))]).length, 512)
  assert.equal(latestAsk([{ role: 'user', source: { kind: 'user' }, content: [{ type: 'image', data: 'AAAA' }] }]), '')
  const { asked, step } = harness({ queries: ['named'] })
  await step([person('ignored when the caller named its queries')])
  assert.deepEqual(asked, ['named'])
})

test('automatic context excludes attributed model notes after final publication, retaining owner and anonymous DATA', async () => {
  const model = { recordId: 'model-fixture', tier: 'remembered', attributedTo: 'agent', text: 'MODEL-AUTO-CONTEXT' }
  const owner = { recordId: 'owner-fixture', tier: 'remembered', attributedTo: 'owner', text: 'OWNER-AUTO-CONTROL' }
  const anonymous = { recordId: 'anonymous-fixture', text: 'ANONYMOUS-DATA-CONTROL' }
  const { step } = harness({ queries: ['named'],
    conversation: { turn: async () => ({ availability: 'found', snippets: [owner] }) },
    newest: async () => ({ availability: 'found', snippets: [model] }),
    beforePublish: (reply, recent) => [{ ...reply, snippets: [...reply.snippets, model, anonymous] }, recent],
  })
  const decision = await step([person('Read the fixture.')])
  assert.equal(decision.messages.at(-1).source.form, 'snapshot')
  const text = decision.messages.at(-1).content[0].text
  assert.doesNotMatch(text, /MODEL-AUTO-CONTEXT/u)
  assert.match(text, /OWNER-AUTO-CONTROL/u)
  assert.match(text, /ANONYMOUS-DATA-CONTROL/u)
  assert.match(text, /model-authored-never-pre-turn/u)
  assert.match(text, /no authority or live-state attestation/iu)
})

test('model-only legacy supplier is withheld without inventing an empty store or changing explicit lookup', async () => {
  const { step } = harness({ queries: ['named'],
    conversation: { turn: async () => ({ availability: 'found', snippets: [
      { recordId: 'legacy-model', attributedTo: 'agent', text: 'LEGACY-MODEL-DATA' },
    ] }) },
  })
  const decision = await step([person('Read the fixture.')])
  const text = decision.messages.at(-1).content[0].text
  assert.doesNotMatch(text, /LEGACY-MODEL-DATA/u)
  assert.match(text, /model-authored-never-pre-turn/u)
  assert.match(text, /memory: readable\/found attempts=1/u)
  assert.match(text, /Records exist, withheld by policy \(1\)\./u)
  assert.doesNotMatch(text, /holds no record for this scope/u)
})

test('actual remembered model note remains explicitly recallable as advisory DATA', async () => {
  const home = mkdtempSync(join(tmpdir(), 'kira-authorship-data-'))
  try {
    const memory = createTrackedMemory({ stateDir: join(home, 'memory'), subject: `aukora:1:${'4'.repeat(64)}`,
      config: { configured: false }, policyOf: async () => ({ subject: `aukora:1:${'4'.repeat(64)}`, privacy: 'local' }) })
    await memory.remember({ text: 'MODEL-EXPLICIT-DATA is a synthetic model report.', from: 'agent', scope: 'owner' })
    await memory.remember({ text: 'OWNER-EXPLICIT-CONTROL is a synthetic owner statement.', from: 'owner', scope: 'owner' },
      { attributedTo: 'owner' })
    const model = memory.read().notes.find(note => note.attributedTo === 'agent')
    const owner = memory.read().notes.find(note => note.attributedTo === 'owner')
    const context = { now: new Date().toISOString() }
    assert.equal(recallFilter(model, context).ok, true, 'existing explicit frame eligibility is preserved')
    assert.deepEqual(preTurnRecallFilter(model, context), { ok: false, why: 'model-authored-never-pre-turn' })
    assert.equal(preTurnRecallFilter(owner, context).ok, true)
    for (const attribution of ['owner-voice', 'owner-edit']) {
      assert.equal(preTurnRecallFilter({ ...owner, attributedTo: attribution }, context).ok, true)
    }
    assert.equal(preTurnRecallFilter({ ...owner, category: 'instruction' }, context).ok, false)
    assert.equal(preTurnRecallFilter(owner, { ...context, states: new Map([[owner.id, 'hidden']]) }).ok, false)
    for (const state of ['hidden', 'expired', 'superseded']) {
      const moved = { ...context, states: new Map([[model.id, state]]) }
      assert.deepEqual(preTurnRecallFilter(model, moved), recallFilter(model, moved), 'existing state refusal takes precedence')
    }
    const elapsed = { ...model, validTo: '2000-01-01T00:00:00.000Z' }
    assert.deepEqual(preTurnRecallFilter(elapsed, context), recallFilter(elapsed, context), 'existing expiration refusal is preserved')
    const detached = { ...model, scope: 'project:unattached' }
    assert.deepEqual(preTurnRecallFilter(detached, context), recallFilter(detached, context), 'existing scope refusal is preserved')
    assert.equal(preTurnRecallFilter({ ...model, origin: { by: 'gate-apply' } }, context).ok, false)
    const answer = await memory.recall({ question: 'MODEL-EXPLICIT-DATA', lexical: true })
    assert.equal(answer.grantsAuthority, false)
    const found = answer.notes.find(note => note.id === model.id)
    assert.ok(found && found.text.includes('MODEL-EXPLICIT-DATA'))
    assert.equal(found.attributedTo, 'agent')
    assert.equal(found.grantsAuthority, false)
    assert.equal(found.containment.kind, 'DATA')
    assert.equal(found.containment.provenance, 'untrusted-external')
  } finally { rmSync(home, { recursive: true, force: true }) }
})
