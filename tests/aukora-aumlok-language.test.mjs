#!/usr/bin/env node
// Bind validates the selected list and carries only public phrase metadata.
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bindV3 } from '../plugins/aukora-aumlok/lib/bind-v3.mjs'
import { generatePhrase } from '../plugins/aukora-aumlok/lib/ceremony-phrase.mjs'
import { deriveRootFromPhrase } from '../plugins/aukora-aumlok/lib/derive-v3.mjs'
import { buildRecordV3, controlFieldsOfRecordV3Projection, isRecordV3, recordProjection }
  from '../plugins/aukora-aumlok/lib/record-v3.mjs'
import { refreshBindingV3, verifySuccessionV3 } from '../plugins/aukora-aumlok/lib/refresh-v3.mjs'
import { loadLocalAumlokPublicControl } from '../plugins/aukora-aumlok/lib/store.mjs'

const scratch = mkdtempSync(fileURLToPath(new URL('../.aumlok-language-', import.meta.url)))
const handle = 'language.fixture'
const at = '2026-10-12T12:00:00Z'
let assertions = 0
const same = (actual, expected) => { assert.deepEqual(actual, expected); assertions += 1 }
try {
  const unknownDirectory = join(scratch, 'unknown')
  await assert.rejects(bindV3({ handle, words: ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'notaword'],
    phraseLanguage: 'en', directory: unknownDirectory, boundAt: at }), error => error.word === 'notaword'
      && error.message.includes('notaword'))
  assertions += 1
  same(existsSync(unknownDirectory), false)
  await assert.rejects(bindV3({ handle, words: ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb'],
    phraseLanguage: 'xx', directory: unknownDirectory, boundAt: at }))
  assertions += 1
  same(existsSync(unknownDirectory), false)

  const drawn = generatePhrase({ language: 'ja', randomBytes: size => Buffer.alloc(size, 0) })
  const directory = join(scratch, 'new')
  const bound = await bindV3({ handle, words: drawn.words, phraseLanguage: drawn.language, directory, boundAt: at })
  const disk = JSON.parse(readFileSync(join(directory, 'local-control.json'), 'utf8'))
  const projected = loadLocalAumlokPublicControl(directory).projection
  for (const publicValue of [disk.publicRoot, bound.projection, projected]) {
    same(publicValue.phraseLanguage, 'ja')
    same(publicValue.phraseLegacy, false)
  }
  const control = controlFieldsOfRecordV3Projection(projected)
  same(Object.hasOwn(control, 'phraseLanguage'), false)
  same(Object.hasOwn(control, 'phraseLegacy'), false)
  same(control.activeControlDigest, disk.publicRoot.rootId)
  same(isRecordV3({ ...disk, publicRoot: { ...disk.publicRoot, phraseLanguage: 'xx' } }), false)
  same(isRecordV3({ ...disk, publicRoot: { ...disk.publicRoot, phraseLegacy: 'false' } }), false)
  const incomplete = structuredClone(disk)
  delete incomplete.publicRoot.phraseLegacy
  same(isRecordV3(incomplete), false)
  const oldRecord = structuredClone(disk)
  delete oldRecord.publicRoot.phraseLanguage
  delete oldRecord.publicRoot.phraseLegacy
  same(isRecordV3(oldRecord), true)
  same(Object.hasOwn(recordProjection(oldRecord), 'phraseLanguage'), false)

  const oldRoot = await deriveRootFromPhrase(drawn.phrase, { handle })
  assert.throws(() => buildRecordV3({ root: oldRoot, boundAt: at, phraseLanguage: 'xx', phraseLegacy: false }),
    { code: 'aumlok:phrase-metadata-malformed' })
  assertions += 1
  const legacyWords = ['corals', 'cliff', 'oasis', 'ring', 'amity', 'light', 'summit']
  const legacyDirectory = join(scratch, 'legacy')
  const legacyBound = await bindV3({ handle, words: legacyWords, directory: legacyDirectory, boundAt: at })
  same(legacyBound.projection.phraseLanguage, 'en')
  same(legacyBound.projection.phraseLegacy, true)
  const newRoot = await deriveRootFromPhrase(legacyWords.join(' '), { handle })
  const refreshed = refreshBindingV3({ directory, oldRoot, newRoot, refreshedAt: at,
    phraseLanguage: 'en', phraseLegacy: true })
  same(refreshed.projection.phraseLanguage, 'en')
  same(refreshed.projection.phraseLegacy, true)
  same(verifySuccessionV3({ record: refreshed.record }).ok, true)
  const afterRefresh = loadLocalAumlokPublicControl(directory).projection
  same(afterRefresh.phraseLanguage, 'en')
  same(afterRefresh.phraseLegacy, true)
  console.log(`AUMLOK LANGUAGE: PASS (${assertions} assertions; synthetic bindings and refresh; no installed app)`)
} finally {
  rmSync(scratch, { recursive: true, force: true })
}
