#!/usr/bin/env node
/** Complete semantic recall retains semantic order while reciprocal ranks admit strong lexical matches. */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { registerHooks } from 'node:module'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { compileIndex, rankRecords } from '../plugins/aukora-kira/lib/retrieval.mjs'

const trackedUrl = new URL('../plugins/aukora-kira/lib/tracked-memory.mjs', import.meta.url)
const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const mutations = {
  'semantic-only': ['const hits = fuseRecallHits(semanticHits, unsafeSemanticDrop ? [] : lexicalHits(true), count)', 'const hits = semanticHits.slice(0, count)'],
  'unsafe-drop': ['unsafeSemanticDrop ? [] : lexicalHits(true)', 'lexicalHits(true)'],
}
let mutationApplied = false
if (mutant) {
  assert.ok(mutations[mutant], 'known fusion mutation')
  registerHooks({
  load(url, context, next) {
    const loaded = next(url, context)
    if (url !== trackedUrl.href) return loaded
    const source = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8')
    const [before, after] = mutations[mutant]
    assert.equal(source.split(before).length, 2, 'fusion mutation target')
    mutationApplied = true
    return { ...loaded, source: source.replace(before, after) }
  },
  })
}
const { createTrackedMemory, contentHash } = await import(trackedUrl.href)

const root = mkdtempSync(join(tmpdir(), 'kira-recall-fusion-'))
const question = 'what is still waiting on Peter'
const targetText = 'Waiting on Peter: choose which key signs on the pilot.'
const planText = `${'Deployment sequencing, release evidence, staging checks, and operator observations fill this plan section. '.repeat(80)} Peter reviews the remaining sequence.`
const ruleText = `${'The general operating rule covers approvals, receipts, branches, releases, and verification. '.repeat(60)} Peter owns the final decision.`
let semanticOrder = [], unsafeDrop = false
const client = {
  configured: true,
  sync: async () => ({ added: 0, pending: 0, failed: [], failures: [], requests: 0 }),
  recall: async ({ limit }) => ({ available: true,
    hits: (unsafeDrop ? [] : semanticOrder.slice(0, limit)).map((note, index) => ({ id: note.id, score: 0.98 - index * 0.01, note,
      uri: `viking://user/owner/resources/kira/content/${note.contentHash}.md`, relevance: 'semantic-threshold' })),
    dropped: { unmapped: [], tampered: unsafeDrop ? ['viking://user/owner/resources/kira/content/tampered.md'] : [],
      unreadable: [], belowThreshold: 0, outsideWindow: 0, invalidScore: 0, quality: 0 },
    coverage: { indexed: 3, total: 3, partial: false }, threshold: 0.4, ledgerComplete: true, failures: [] }),
}
const memory = createTrackedMemory({ stateDir: join(root, 'memory'), subject: `aukora:1:${'3c'.repeat(32)}`,
  config: { configured: true, user: 'owner' }, client })
try {
  for (const text of [planText, ruleText, targetText]) await memory.remember({ text, from: 'agent' })
  const notes = memory.read().notes
  const byText = text => notes.find(note => note.statement === text)
  semanticOrder = [byText(planText), byText(ruleText), byText(targetText)]
  assert.ok(semanticOrder.every(Boolean))
  const records = notes.map(note => ({ recordId: note.id, text: note.statement }))
  const lexical = rankRecords(compileIndex(records), records, question)
  assert.equal(lexical[0].recordId, byText(targetText).id)
  const beforeRank = semanticOrder.findIndex(note => note.id === byText(targetText).id) + 1
  const answer = await memory.recall({ question, limit: 2 })
  const afterRank = answer.notes.findIndex(note => note.id === byText(targetText).id) + 1
  assert.equal(beforeRank, 3)
  assert.equal(afterRank, 2)
  assert.equal(answer.notes[0].id, byText(planText).id)
  assert.equal(answer.method, 'openviking-semantic')
  const semanticOnly = await memory.recall({ question: 'canine dwelling', limit: 2 })
  assert.deepEqual(semanticOnly.notes.map(note => note.id), semanticOrder.slice(0, 2).map(note => note.id))
  unsafeDrop = true
  assert.equal((await memory.recall({ question, limit: 2 })).notes.length, 0)
  unsafeDrop = false
  if (!mutant) {
    for (const name of Object.keys(mutations)) {
      const mutation = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--mutant', name], { encoding: 'utf8' })
      assert.notEqual(mutation.status, 0, `${name} mutation survived`)
      console.log(`kira-recall-fusion mutation ${name}: CAUGHT`)
    }
  }
  console.log(`kira-recall-fusion: before rank ${beforeRank}, after rank ${afterRank}; semantic top result preserved`)
} finally { rmSync(root, { recursive: true, force: true }) }
if (mutant) assert(mutationApplied, 'fusion mutation was not applied')
