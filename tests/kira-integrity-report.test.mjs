// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic commitments expose changed objects without displaying their content.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync, rmSync, unlinkSync, symlinkSync, linkSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { registerHooks } from 'node:module'
import { spawnSync } from 'node:child_process'
import { createTrackedMemory, contentHash } from '../plugins/aukora-kira/lib/tracked-memory.mjs'
import { nextEntry } from '../plugins/aukora-kira/lib/memory-journal.mjs'

const tool = new URL('../scripts/kira/integrity-report.mjs', import.meta.url)
const mutant = process.env.KIRA_INTEGRITY_MUTANT
const mutations = {
  'state-existence': ["catch { refuse('state-unavailable') }", 'catch { continue }'],
  'state-directory': ["if (!stat.isDirectory() || stat.isSymbolicLink()) refuse('state-invalid')", ''],
  'absolute-path': ["if (typeof stateDir !== 'string' || !isAbsolute(stateDir)) refuse('state-not-absolute')", ''],
  'argument-count': ["if (argv.length !== 1) refuse('usage')", ''],
  'file-link': ["if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) refuse('object-invalid')", 'if (false) refuse(\'object-invalid\')'],
  'id-output': ["if (!ID.test(note.id)) refuse('record-id-invalid')", ''],
  'reason-output': ["REASONS.has(note.recallRefusal) ? note.recallRefusal : 'unreadable-object'", 'note.recallRefusal'],
  'envelope-diagnosis': ['envelopeMatches = recomputeNoteId(original) === note.id', 'envelopeMatches = true'],
  'capture-membership': ["!captured.has(note.id) ? 'capture-not-established'", "false ? 'capture-not-established'"],
  'withheld-output': ['records.length, records }', 'records.length, records: [] }'],
  'private-output': ['verified_objects: live.notes.length,', 'notes: live.notes, verified_objects: live.notes.length,'],
  'exit-status': ['return report.withheld === 0 ? 0 : 1', 'return 0'],
  'chain-refusal': ["catch { refuse('store-unverifiable') }", 'catch (error) { throw error }'],
}
if (mutant) {
  assert.ok(mutations[mutant], 'known guard removal')
  registerHooks({ load(url, context, next) {
    const result = next(url, context)
    if (url !== tool.href) return result
    const source = String(result.source), [before, after] = mutations[mutant]
    assert.equal(source.split(before).length, 2, 'one production mutation site')
    return { ...result, source: source.replace(before, after) }
  } })
}
const { integrityReport, main } = await import(tool.href)
const subject = `aukora:1:${'1c'.repeat(32)}`
const root = fileURLToPath(new URL('../', import.meta.url))
const withFixture = async run => {
  const dir = mkdtempSync(join(root, '.kira-integrity-'))
  try {
    const state = join(dir, 'state'), memory = createTrackedMemory({ stateDir: state, subject })
    const notes = []
    for (let n = 0; n < 5; n++) {
      const result = await memory.remember({ text: `Synthetic cafe\u0301 calibration ${n} is preserved.`, from: 'fixture' })
      notes.push(result.notes[0])
    }
    const file = note => join(state, 'remembered', `${note.id.slice(4)}.json`)
    await run({ dir, state, notes, file })
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('unchanged UTF-8 commitments pass without Unicode normalization or writes', async () => withFixture(({ state, notes, file }) => {
  const before = notes.map(note => readFileSync(file(note)))
  const report = integrityReport(state)
  assert.equal(report.canonical_form, 'exact-utf8-statement')
  assert.equal(report.verified_objects, 5)
  assert.equal(report.withheld, 0)
  assert.deepEqual(report.records, [])
  assert.notEqual(contentHash(notes[0].statement), contentHash(notes[0].statement.normalize('NFC')))
  assert.deepEqual(notes.map(note => readFileSync(file(note))), before)
  const lines = []
  assert.equal(main([state], line => lines.push(line)), 0)
  assert.doesNotMatch(lines.join(''), /Synthetic|calibration|aukora:1:|evidence|subject/)
}))

test('changed capture, invalid commitment and missing object have distinct ID-only reports', async () => withFixture(({ state, notes, file }) => {
  writeFileSync(file(notes[0]), JSON.stringify({ ...notes[0], statement: 'Synthetic replacement is different.' }))
  writeFileSync(file(notes[1]), JSON.stringify({ ...notes[1], contentHash: contentHash(notes[1].statement.normalize('NFC')) }))
  unlinkSync(file(notes[2]))
  const expected = [
    { id: notes[0].id, reason: 'content-hash-mismatch', diagnosis: 'capture-envelope-changed', cause: 'undetermined' },
    { id: notes[1].id, reason: 'content-hash-mismatch', diagnosis: 'content-commitment-invalid', cause: 'undetermined' },
    { id: notes[2].id, reason: 'missing-object' },
  ].sort((a, b) => a.id.localeCompare(b.id))
  assert.deepEqual(integrityReport(state).records, expected)
  const lines = []
  assert.equal(main([state], line => lines.push(line)), 1)
  assert.doesNotMatch(lines.join(''), /Synthetic|replacement|calibration|aukora:1:|evidence|subject/)
  assert.deepEqual(JSON.parse(lines[0]).records, expected)
}))

test('forgotten missing objects are excluded and malformed bytes produce a fixed reason', async () => withFixture(({ state, notes, file }) => {
  const journalFile = join(state, 'remembered/journal.jsonl')
  const lines = readFileSync(journalFile, 'utf8').trim().split('\n'), previous = JSON.parse(lines.at(-1))
  const entry = nextEntry({ previous, op: 'forget', id: notes[0].id, objectDigest: notes[0].contentHash,
    actor: 'synthetic', at: '2026-10-13T00:00:00Z' })
  writeFileSync(journalFile, `${lines.join('\n')}\n${JSON.stringify(entry)}\n`)
  unlinkSync(file(notes[0]))
  writeFileSync(file(notes[1]), '{"statement":"synthetic-do-not-print",')
  const report = integrityReport(state)
  assert.equal(report.withheld, 1)
  assert.deepEqual(report.records, [{ id: notes[1].id, reason: 'unreadable-object' }])
}))

test('an orphan mismatch cannot establish that a captured envelope changed', async () => withFixture(({ state, notes }) => {
  const id = `rem:${'a'.repeat(64)}`
  writeFileSync(join(state, 'remembered', `${id.slice(4)}.json`), JSON.stringify({ ...notes[0], id, contentHash: 'b'.repeat(64) }))
  assert.deepEqual(integrityReport(state).records, [{ id, reason: 'content-hash-mismatch', diagnosis: 'capture-not-established', cause: 'undetermined' }])
}))

test('missing state, links, unsafe identifiers and damaged chains refuse without private diagnostics', async () => withFixture(({ state, notes, file, dir }) => {
  assert.throws(() => integrityReport(join(dir, 'absent')), /state-unavailable/)
  assert.throws(() => integrityReport('relative'), /state-not-absolute/)
  assert.throws(() => main([]), /usage/)
  const linked = join(dir, 'linked')
  symlinkSync(state, linked)
  assert.throws(() => integrityReport(linked), /state-invalid/)
  const noteFile = file(notes[0]), saved = readFileSync(noteFile)
  unlinkSync(noteFile); symlinkSync(file(notes[1]), noteFile)
  assert.throws(() => integrityReport(state), /object-invalid/)
  unlinkSync(noteFile); linkSync(file(notes[1]), noteFile)
  assert.throws(() => integrityReport(state), /object-invalid/)
  unlinkSync(noteFile); writeFileSync(noteFile, JSON.stringify({ ...notes[0], id: 'synthetic-do-not-print' }))
  assert.throws(() => integrityReport(state), /record-id-invalid/)
  writeFileSync(noteFile, saved)
  writeFileSync(join(state, 'remembered/aura.jsonl'), 'synthetic-do-not-print')
  assert.throws(() => integrityReport(state), /store-unverifiable/)
  const result = spawnSync(process.execPath, [fileURLToPath(tool), state], { encoding: 'utf8', timeout: 3000 })
  assert.equal(result.status, 1)
  assert.equal(result.stderr, 'kira.integrity-report:store-unverifiable\n')
  assert.equal(result.stdout, '')
}))

if (!mutant) test('each production guard removal fails a synthetic assertion', () => {
  const env = { ...process.env }
  delete env.NODE_TEST_CONTEXT
  for (const name of Object.keys(mutations)) {
    const child = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], {
      encoding: 'utf8', timeout: 5000, env: { ...env, KIRA_INTEGRITY_MUTANT: name },
    })
    assert.equal(child.status, 1, `${name}: mutation must fail`)
    assert.match(child.stdout, /ERR_ASSERTION/, `${name}: assertion must catch guard removal`)
    assert.doesNotMatch(child.stdout, /one production mutation site/)
  }
  console.log(`PASS integrity-report mutations: ${Object.keys(mutations).length} caught, 0 survived`)
})
