// SPDX-License-Identifier: AGPL-3.0-or-later
// Kira text cuts retain complete graphemes and their existing UTF-16 budgets.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const here = fileURLToPath(import.meta.url), root = fileURLToPath(new URL('../', import.meta.url))
const mutations = {
  'grapheme-helper': ['memory-tiers.mjs', '  let end = 0\n', "  return source.slice(0, limit).replace(/[\\uD800-\\uDBFF]$/u, '')\n  let end = 0\n", 'shared cutter'],
  'non-string-helper': ['memory-tiers.mjs', "const source = typeof text === 'string' ? text : ''", "const source = String(text ?? '')", 'non-string'],
  'candidate-note': ['autostage.mjs', 'cutText(ask, MAX_CANDIDATE_CHARS)', 'ask.slice(0, MAX_CANDIDATE_CHARS)', 'auto-stage candidate'],
  'hook-ask': ['autostage-hook.mjs', 'cutText(lastRealAsk(surface?.events), MAX_ASK_CHARS)', 'lastRealAsk(surface?.events).slice(0, MAX_ASK_CHARS)', 'auto-stage hook'],
  'latest-ask': ['injection.mjs', "const text = cutText(parts.map(part => (part?.type === 'text' && typeof part.text === 'string' ? part.text : '')).join(' ')\n      .replace(/\\s+/gu, ' ').trim(), ASK_QUERY_CHARS)", "const text = parts.map(part => (part?.type === 'text' && typeof part.text === 'string' ? part.text : '')).join(' ')\n      .replace(/\\s+/gu, ' ').trim().slice(0, ASK_QUERY_CHARS)", 'latest person ask'],
  'lane-seed': ['injection.mjs', "cutText(seed.trim().replace(/\\s+/gu, ' '), LANE_SEED_CHARS)", "seed.trim().replace(/\\s+/gu, ' ').slice(0, LANE_SEED_CHARS)", 'lane seed'],
  'context-finish': ['injection.mjs', "cutText(`${diagnostic ? `${diagnostic}\\n\\n` : ''}${text}`, total)", "`${diagnostic ? `${diagnostic}\\n\\n` : ''}${text}`.slice(0, total)", 'recalled context'],
  'voice-quote': ['memory-frame.mjs', 'cutText(escapeForInjection(note.evidence[0].quote), 60)', 'escapeForInjection(note.evidence[0].quote).slice(0, 60)', 'voice quote'],
  'whole-frame': ['memory-frame.mjs', 'cutText(text, FRAME_BUDGETS.totalChars - 1)', 'text.slice(0, FRAME_BUDGETS.totalChars - 1)', 'whole frame'],
  'project-snippet': ['project-memory.mjs', 'cutText(note.statement ?? note.text, 600)', "String(note.statement ?? note.text ?? '').slice(0, 600)", 'project snippet'],
  'semantic-snippet': ['recall-openviking.mjs', 'cutText(text, chars)', 'text.slice(0, chars)', 'semantic snippet'],
  'lexical-snippet': ['tools.mjs', 'cutText(note.text, 600)', 'String(note.text).slice(0, 600)', 'lexical snippet'],
  'queue-display': ['../bin/kira-approve-queue.mjs', 'cutText(row.text, 160)', 'row.text.slice(0, 160)', 'queue display'],
}

if (process.argv.includes('--mutations')) {
  const run = name => spawnSync(process.execPath, ['--test', '--test-reporter=tap', here], { encoding: 'utf8', timeout: 30_000,
    env: { ...process.env, KIRA_UNICODE_MUTANT: name ?? '' } })
  const plain = run(), killed = []
  assert.equal(plain.status, 0, plain.stdout + plain.stderr)
  for (const [name, [, , , arm]] of Object.entries(mutations)) {
    const child = run(name), output = child.stdout + child.stderr
    assert.notEqual(child.status, 0, `${name} survived`)
    assert.ok(output.includes(`not ok`) && output.includes(arm), `${name} did not fail its regression: ${output}`)
    assert.doesNotMatch(output, /mutation site|mutation not loaded/u, `${name} did not remove its protection`)
    killed.push(name)
  }
  process.stdout.write(`KIRA UNICODE MUTATIONS: ${killed.length}/${Object.keys(mutations).length} protections removed made their tests fail\n`)
  process.exit(0)
}

const mutant = process.env.KIRA_UNICODE_MUTANT
let applied = 0
if (mutant && mutant !== 'queue-display') {
  assert.ok(mutations[mutant], 'known mutation')
  const [file, from, to] = mutations[mutant]
  const target = new URL(`../plugins/aukora-kira/lib/${file}`, import.meta.url).href
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source)
    assert.equal(source.split(from).length - 1, 1, 'exact production mutation site')
    applied++
    return { ...loaded, source: source.replace(from, to) }
  } })
}

const { cutText, sha256Hex } = await import('../plugins/aukora-kira/lib/memory-tiers.mjs')
const { autoStageCandidate } = await import('../plugins/aukora-kira/lib/autostage.mjs')
const { registerAutoStage } = await import('../plugins/aukora-kira/lib/autostage-hook.mjs')
const { latestAsk, laneQueries, recalledContextLine, renderQueryPart } = await import('../plugins/aukora-kira/lib/injection.mjs')
const { lineFor, frameOf, FRAME_BUDGETS } = await import('../plugins/aukora-kira/lib/memory-frame.mjs')
const { rememberedSnippet } = await import('../plugins/aukora-kira/lib/project-memory.mjs')
const { semanticNotes } = await import('../plugins/aukora-kira/lib/recall-openviking.mjs')
const { recallRemembered } = await import('../plugins/aukora-kira/lib/tools.mjs')
const { verifyMemoryRecordHashes } = await import('../plugins/aukora-kira/lib/memory-quality.mjs')
const { createMemoryOwner } = await import('../plugins/aukora-kira/lib/memory-owner.mjs')
const { stageKiraMemoryRecord } = await import('../plugins/aukora-kira/lib/record.mjs')
if (mutant && mutant !== 'queue-display') assert.equal(applied, 1, 'mutation not loaded')

const clusters = ['🌒', '🇮🇩', '👍🏽', 'e\u0301', '👩🏽‍💻']
const straddling = (budget, cluster, prefix = '') => {
  const kept = prefix + 'x'.repeat(budget - prefix.length - (cluster === '🌒' || cluster === 'e\u0301' ? 1 : 2))
  return { text: kept + cluster + 'tail', kept }
}
const noteOf = statement => ({ id: 'synthetic-note', statement, contentHash: sha256Hex(statement), tier: 'remembered' })
const checkProjection = (shown, original, kept, start = 0) => {
  assert.equal(shown.text, kept)
  assert.equal(shown.contentHash, original.contentHash)
  assert.equal(shown.statementHash, original.contentHash)
  assert.equal(shown.partHash, sha256Hex(kept))
  assert.deepEqual(shown.byteRange, { start, end: start + Buffer.byteLength(kept), unit: 'utf8-bytes' })
  assert.equal(verifyMemoryRecordHashes(shown).ok, true)
}

test('shared cutter keeps emoji, flags, skin tones, combining marks and ZWJ sequences within UTF-16 budgets', () => {
  for (const cluster of clusters) {
    for (let partial = 1; partial < cluster.length; partial++) assert.equal(cutText(`ab${cluster}tail`, 2 + partial), 'ab')
    assert.equal(cutText(`ab${cluster}tail`, 2 + cluster.length), `ab${cluster}`)
  }
  assert.equal(cutText('hello', 0), '')
  assert.equal(cutText('hello', -1), '')
  assert.equal(cutText('hello', 2.9), 'he')
  assert.equal(cutText('a\ud83d', 9), 'a')
})

test('non-string cutter input is empty without invoking conversion', () => {
  for (const value of [null, undefined, 42, { toString: () => 'synthetic-object' }]) assert.equal(cutText(value, 600), '')
})

test('auto-stage candidate classifies and stores the same complete bounded note', () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(400, cluster, 'I prefer ')
    const result = autoStageCandidate({ sessionId: 'synthetic-session', turn: 1, at: '2026-10-12T00:00:00Z', ask: text }, `aukora:1:${'3'.repeat(64)}`, 'local')
    assert.equal(result.category, 'preference')
    assert.equal(result.record.content.note, kept)
    assert.ok(result.record.content.note.length <= 400)
  }
})

test('auto-stage hook forwards a complete bounded ask', async () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(400, cluster), digests = []
    let handler
    registerAutoStage({ on: (_name, fn) => { handler = fn; return () => {} }, reflect: { get: () => ({
      listSessions: async () => [{ header: { id: 'synthetic-session' } }],
      readSurface: async () => ({ events: [{ type: 'user/message', data: { content: text, source: { kind: 'user' } } }] }),
    }) } }, { now: () => new Date('2026-10-12T00:00:00Z'), stageFromDigest: async digest => { digests.push(digest); return { staged: false } } })
    await handler({ agent: { session: { id: 'synthetic-session' } }, turn: 1 })
    assert.equal(digests.length, 1)
    assert.equal(digests[0].ask, kept)
  }
})

test('latest person ask retains complete graphemes at its query bound', () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(512, cluster)
    assert.equal(latestAsk([{ role: 'user', source: { kind: 'user' }, content: text }]), kept)
  }
})

test('lane seed retains complete graphemes at its stored-summary bound', () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(160, cluster)
    assert.equal(laneQueries('fixture', text)[0], `summary FIXTURE ${kept}`)
  }
})

test('recalled context finishes on a complete grapheme within its total bound', () => {
  for (const cluster of clusters) {
    const reply = { availability: 'found', snippets: [], status: `synthetic-${cluster}-status` }
    const full = renderQueryPart(reply), at = full.indexOf(cluster)
    const partial = cluster === '🌒' || cluster === 'e\u0301' ? 1 : 2
    assert.equal(recalledContextLine(reply, undefined, { maxChars: at + partial }), full.slice(0, at))
  }
})

test('voice quote keeps complete graphemes at its 60-unit bound', () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(60, cluster)
    const line = lineFor({ statement: 'synthetic statement', attributedTo: 'owner-voice', evidence: [{ quote: text }] }, 'm1')
    assert.ok(line.includes(` "${kept}" synthetic statement`))
  }
})

test('whole frame keeps a complete grapheme before its truncation marker', () => {
  for (const cluster of clusters) {
    const prefix = '[KIRA nonce=', { text, kept } = straddling(FRAME_BUDGETS.totalChars - 1, cluster, prefix)
    const frame = frameOf({ nonce: text.slice(prefix.length) })
    assert.equal(frame.text, `${kept}…`)
    assert.ok(frame.text.length <= FRAME_BUDGETS.totalChars)
  }
})

test('project snippet keeps graphemes and the original hash domain', () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(600, cluster), note = noteOf(text)
    checkProjection(rememberedSnippet(note), note, kept)
  }
})

test('semantic snippet keeps graphemes and UTF-8 matching-part offsets', () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(600, cluster), prefix = 'older 星 ', note = noteOf(prefix + text)
    const start = Buffer.byteLength(prefix), semanticSpan = { unit: 'utf8-bytes', start, end: Buffer.byteLength(note.statement) }
    const result = semanticNotes({ hits: [{ id: note.id, note, score: 1, semanticSpan }],
      dropped: { unmapped: [], tampered: [], unreadable: [] } }).notes[0]
    checkProjection(result, note, kept, start)
    assert.deepEqual(result.semanticSpan, semanticSpan)
  }
})

test('lexical snippet keeps graphemes and the original statement commitment', async () => {
  for (const cluster of clusters) {
    const { text, kept } = straddling(600, cluster, 'orchard '), note = noteOf(text)
    const result = await recallRemembered(async () => [note], 'orchard')
    assert.equal(result.state, 'found')
    checkProjection(result.notes[0], note, kept)
  }
})

test('queue display keeps complete graphemes without writing memory or approval', () => {
  const home = mkdtempSync(join(root, '.kira-unicode-'))
  try {
    const state = join(home, 'memory'), owner = createMemoryOwner({ stateDir: state })
    const { text, kept } = straddling(160, '🇮🇩')
    owner.enqueuePending(stageKiraMemoryRecord({ subject: `aukora:1:${'4'.repeat(64)}`, kind: 'preference',
      content: { note: text }, source: [], links: [], privacy: 'local', createdAt: '2026-10-12T00:00:00Z' }))
    const cli = new URL('../plugins/aukora-kira/bin/kira-approve-queue.mjs', import.meta.url)
    let args = [fileURLToPath(cli), '--state', state, '--list']
    if (mutant === 'queue-display') {
      const [, from, to] = mutations[mutant]
      args = ['--input-type=module', '-e', `import { registerHooks } from 'node:module';
        registerHooks({ load(url, context, nextLoad) { const loaded = nextLoad(url, context);
          if (url !== ${JSON.stringify(cli.href)}) return loaded;
          const source = String(loaded.source), from = ${JSON.stringify(from)};
          if (source.split(from).length !== 2) throw Error('exact production mutation site');
          return { ...loaded, source: source.replace(from, ${JSON.stringify(to)}) }; } });
        process.argv = ${JSON.stringify(['node', fileURLToPath(cli), '--state', state, '--list'])};
        await import(${JSON.stringify(cli.href)});`]
    }
    const child = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 10_000 })
    assert.equal(child.status, 0, child.stderr)
    assert.ok(child.stdout.includes(`\n      ${kept}\n`), child.stdout)
    assert.equal(owner.listPending().pending, 1)
  } finally { rmSync(home, { recursive: true, force: true }) }
})
