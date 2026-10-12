// SPDX-License-Identifier: AGPL-3.0-or-later
// Hostile text retains outside-word provenance and one exact manifest record.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'
import { loadRails, replaceOnce } from './helpers/conversation-rails.mjs'

// Ported inputs and mutation recipe from the owner's aukora-fuzz.mjs. Its
// {key,value} membrane/refusal contract is not implemented by these prompt rails.
// This court tests rail metadata, not JSON admission, model obedience or effects.
const corpus = [
  '', 'not json at all', '{"key": "k", "value": 1', '{"key": "k", "value": }',
  'prefix {"key": "k", "value": 1} suffix',
  '{"key": "k", "value": 1, "extra": true}', '{"value": 1}', '{"key": "k"}',
  '{"key": "k", "value": 1, "value": 2}', '{"KEY": "k", "VALUE": 1}',
  '{"key": "", "value": 1}', '{"key": 5, "value": 1}', '{"key": null, "value": 1}',
  '{"key": "' + 'x'.repeat(65) + '", "value": 1}', '{"key": "k\n", "value": 1}',
  '{"key": "k", "value": -1}', '{"key": "k", "value": 1.5}',
  '{"key": "k", "value": "1"}', '{"key": "k", "value": null}',
  '{"key": "k", "value": ' + Number.MAX_SAFE_INTEGER + '1}',
  '{"key": "k", "value": [1]}', '[{"key": "k", "value": 1}]',
  '{"key": {"nested": 1}, "value": 1}',
  '{"__proto__": {"polluted": true}, "value": 1}',
  '{"key": "k", "value": 1}', 'noise {"key":"k","value":0} noise',
]
const blocks = ['organism', 'organismState', 'claims', 'crossLane', 'lanes', 'screen', 'repo']
const operations = ['delete-char', 'dup-char', 'swap-chars', 'insert-json-punct',
  'insert-digit', 'insert-unicode', 'insert-key-token', 'insert-value-token', 'truncate', 'uppercase-key']
const valid = '{"key": "lotus-pond", "value": 27}'
const full = process.env.AUKORA_CONVERSATION_FUZZ_FULL
assert.ok(full === undefined || full === '1', 'court:fuzz-full-must-be-1-or-unset')
const count = full === '1' ? 20_000 : 2_000
const trust = await loadRails('turn-trust.ts')
const manifest = await loadRails('reply-manifest.ts')

function fuzz(count) {
  let seed = 0x0a11ce
  const rng = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
  const pick = array => array[Math.floor(rng() * array.length)]
  const texts = []
  const exercised = new Set()
  for (let i = 0; i < count; i++) {
    let s = valid
    const ops = 1 + Math.floor(rng() * 3)
    for (let j = 0; j < ops; j++) {
      const op = pick(operations)
      const at = Math.floor(rng() * (s.length + 1))
      exercised.add(op)
      if (op === 'delete-char') s = s.slice(0, at) + s.slice(at + 1)
      else if (op === 'dup-char') s = s.slice(0, at) + s.charAt(Math.min(at, s.length - 1)) + s.slice(at)
      else if (op === 'swap-chars') s = s.slice(0, at) + s.charAt(at + 1) + s.charAt(at) + s.slice(at + 2)
      else if (op === 'insert-json-punct') s = s.slice(0, at) + pick(['{', '}', '[', ']', ':', ',', '"']) + s.slice(at)
      else if (op === 'insert-digit') s = s.slice(0, at) + String(Math.floor(rng() * 10)) + s.slice(at)
      else if (op === 'insert-unicode') s = s.slice(0, at) + pick(['é', '中', '😀', '\\', '\n', '\u0000']) + s.slice(at)
      else if (op === 'insert-key-token') s = s.slice(0, at) + pick(['"key"', '"__proto__"', '"constructor"', 'null', 'true']) + s.slice(at)
      else if (op === 'insert-value-token') s = s.slice(0, at) + pick(['1e999', '-0', '0.0', 'NaN', '"7"', '[]', '{}']) + s.slice(at)
      else if (op === 'truncate') s = s.slice(0, Math.max(0, s.length - Math.floor(rng() * 5)))
      else if (op === 'uppercase-key') s = s.replace(/"key"/, '"KEY"')
    }
    texts.push(s)
  }
  return { texts, exercised }
}

function checkTrust(rail, texts) {
  for (const [index, text] of texts.entries()) {
    for (const block of blocks) {
      const context = { [block]: text }
      const present = /\S/u.test(text)
      assert.equal(rail.turnStartsWithUntrusted(context), present, `court:trust:${index}:${block}`)
      assert.deepEqual(rail.untrustedBlockNames(context), present ? [block] : [], `court:provenance:${index}:${block}`)
    }
  }
}

function checkManifest(rail, text, index) {
  const digest = createHash('sha256').update(text).digest('hex')
  assert.equal(rail.replyIdOf('synthetic-fuzz', index + 1), `synthetic-fuzz:${index + 1}`, 'court:reply-identity')
  const line = {
    replyId: rail.replyIdOf('synthetic-fuzz', index + 1), at: '2026-10-12T00:00:00Z',
    groups: [{ block: 'repo', items: [{ id: text, sha256: digest, source: 'synthetic', outsideWords: true }] }],
  }
  const writes = []
  rail.appendReplyManifest({ dshHome: 'synthetic-state', manifest: line, write: (_path, bytes) => writes.push(bytes) })
  assert.equal(writes.length, 1, `court:manifest-write:${index}`)
  assert.equal(writes[0].split('\n').length, 2, `court:manifest-jsonl:${index}`)
  assert.deepEqual(JSON.parse(writes[0]), line, `court:manifest-bytes:${index}`)
}

test('fuzz: 26 lab corpus strings and bounded seeded mutations retain rail provenance', { timeout: 50_000 }, t => {
  const { texts, exercised } = fuzz(count)
  assert.equal(exercised.size, operations.length, 'court:unexercised-mutation')
  const unchanged = texts.filter(text => text === valid).length
  const unique = new Set(texts).size
  assert.ok(unchanged < count && unique > 1, 'court:vacuous-fuzz')
  const inputs = [...corpus, ' \n\t', ...texts]
  checkTrust(trust, inputs)
  inputs.forEach((text, index) => checkManifest(manifest, text, index))
  t.diagnostic(`FUZZ corpus=${corpus.length} mutations=${count} seed=0x0a11ce operators=${exercised.size} unchanged=${unchanged} unique=${unique} duplicates=${count - unique}`)
  t.diagnostic('SOURCE ONLY: lab membrane refusal/admission contract and live-model effects were not run; manifest digests are supplied by this fixture.')
})

test('fuzz: removing either trust result is caught by the same corpus assertions', async t => {
  for (const [from, to] of [
    ["return OUTSIDE_WORD_BLOCKS.some((name) => (blocks[name] ?? '').trim().length > 0)", 'return false'],
    ["return OUTSIDE_WORD_BLOCKS.filter(name => (blocks[name] ?? '').trim().length > 0)", 'return []'],
  ]) {
    const mutant = await loadRails('turn-trust.ts', source => replaceOnce(source, from, to))
    assert.throws(() => checkTrust(mutant, corpus), { code: 'ERR_ASSERTION' })
  }
  t.diagnostic('MUTATIONS caught=2/2 (trust decision, named provenance); source files unchanged')
})

test('fuzz: corrupting reply identity or dropping the manifest write is caught', async t => {
  for (const [from, to] of [
    ['return `${sessionId}:${String(turn)}`', "return 'synthetic-fuzz:1'"],
    ['write(path, line); return path', 'return path'],
  ]) {
    const mutant = await loadRails('reply-manifest.ts', source => replaceOnce(source, from, to))
    assert.throws(() => checkManifest(mutant, valid, 1), { code: 'ERR_ASSERTION' })
  }
  t.diagnostic('MUTATIONS caught=2/2 (reply identity, manifest write); source files unchanged')
})
