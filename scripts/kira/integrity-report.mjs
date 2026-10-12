#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Report verified-store refusals by ID without changing or displaying memory.
import { lstatSync, readdirSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readTrackedMemory } from '../../plugins/aukora-kira/lib/tracked-memory.mjs'
import { recomputeNoteId } from '../../plugins/aukora-kira/lib/memory-tiers.mjs'
import { readJsonStrict } from '../../plugins/aukora-kira/lib/strict-read.mjs'

const ID = /^rem:[0-9a-f]{64}$/u
const REASONS = new Set(['content-hash-mismatch', 'missing-object', 'unchained'])
const refuse = code => { throw Object.assign(new Error(`kira.integrity-report:${code}`), { code: `kira.integrity-report:${code}` }) }

function checkStore(stateDir) {
  for (const directory of [stateDir, join(stateDir, 'remembered')]) {
    let stat
    try { stat = lstatSync(directory) } catch { refuse('state-unavailable') }
    if (!stat.isDirectory() || stat.isSymbolicLink()) refuse('state-invalid')
  }
  // Chain reads in the existing store reader follow paths; refuse links before that read.
  for (const name of readdirSync(join(stateDir, 'remembered'))) {
    if (!/^(?:[0-9a-f]{64}\.json|aura\.jsonl|journal\.jsonl)$/u.test(name)) continue
    const stat = lstatSync(join(stateDir, 'remembered', name))
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) refuse('object-invalid')
  }
}

export function integrityReport(stateDir) {
  if (typeof stateDir !== 'string' || !isAbsolute(stateDir)) refuse('state-not-absolute')
  stateDir = resolve(stateDir)
  checkStore(stateDir)
  let live
  try { live = readTrackedMemory(stateDir) } catch { refuse('store-unverifiable') }
  const captured = new Set(live.chain.filter(entry => ['add', 'remember', 'index-content'].includes(entry.op) && entry.entryHash).map(entry => entry.id))
  const records = live.withheld.map(note => {
    if (!ID.test(note.id)) refuse('record-id-invalid')
    const reason = REASONS.has(note.recallRefusal) ? note.recallRefusal : 'unreadable-object'
    if (reason !== 'content-hash-mismatch') return { id: note.id, reason }
    let original, envelopeMatches = false
    try {
      original = readJsonStrict(join(stateDir, 'remembered', `${note.id.slice(4)}.json`))
      envelopeMatches = recomputeNoteId(original) === note.id
    } catch { /* Unverifiable bytes cannot establish an unchanged envelope. */ }
    return { id: note.id, reason, diagnosis: !captured.has(note.id) ? 'capture-not-established'
      : envelopeMatches ? 'content-commitment-invalid' : 'capture-envelope-changed',
      cause: 'undetermined' }
  }).sort((a, b) => a.id.localeCompare(b.id))
  return { canonical_form: 'exact-utf8-statement', verified_objects: live.notes.length, withheld: records.length, records }
}

export function main(argv, output = console.log) {
  if (argv.length !== 1) refuse('usage')
  const report = integrityReport(argv[0])
  output(JSON.stringify(report))
  return report.withheld === 0 ? 0 : 1
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.exitCode = main(process.argv.slice(2)) }
  catch (error) {
    console.error(/^kira\.integrity-report:[a-z-]+$/u.test(error?.code) ? error.code : 'kira.integrity-report:unavailable')
    process.exitCode = 1
  }
}
