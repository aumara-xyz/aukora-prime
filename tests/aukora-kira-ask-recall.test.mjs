// SPDX-License-Identifier: AGPL-3.0-or-later
// The per-step recall asks memory with the person's own latest message first. Synthetic messages only;
// no store, model, key or live service. KIRA_ASK_MUTANT removes the guard in memory to prove the test bites.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const url = new URL('../plugins/aukora-kira/lib/injection.mjs', import.meta.url)
async function load() {
  const mutant = process.env.KIRA_ASK_MUTANT
  if (!mutant) return import(url.href)
  let source = readFileSync(url, 'utf8')
  const original = source
  if (mutant === 'no-ask') source = source.replace('ask: latestAsk(decision?.messages)', "ask: ''")
  else if (mutant === 'any-role') source = source.replace("message?.source?.kind !== 'user'", 'false')
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
