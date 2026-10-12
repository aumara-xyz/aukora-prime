// Desktop draws use the shared generator; the face preserves language and labels legacy strength.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { Script } from 'node:vm'
import { PHRASE_LANGUAGES, generatePhrase, validatePhrase } from '../plugins/aukora-aumlok/lib/ceremony-phrase.mjs'
import { createAumlokDraw, DRAW_REFUSE } from '../apps/aukora-desktop/aumlok-draw.mjs'
import * as face from '../plugins/aukora-face/aumlok/src/client/binding-bridge.ts'
import { parseAumlokRecordControlProjection } from '../plugins/aukora-face/aumlok/src/client/record-projection.ts'
import { en, zh } from '../plugins/aukora-face/aumlok/src/client/locales.ts'

const drawSource = readFileSync(new URL('../apps/aukora-desktop/aumlok-draw.mjs', import.meta.url), 'utf8')
const faceSource = readFileSync(new URL('../plugins/aukora-face/aumlok/src/client/binding-bridge.ts', import.meta.url), 'utf8')
const metadataUrl = new URL('../plugins/aukora-face/aumlok/src/client/record-projection.ts', import.meta.url)
const metadataSource = readFileSync(metadataUrl, 'utf8')
const stableLibrary = { generatePhrase: options => generatePhrase({ ...options, randomBytes: size => new Uint8Array(size) }), validatePhrase }
const owner = {}, outsider = {}
async function drawChecks(factory) {
  let lastBound
  const draw = factory({ library: stableLibrary, ceremony: input => { lastBound = input; return { projection: { subject: 'test' } } } })
  assert.equal(factory().draw(owner, 'bind', '').reason, DRAW_REFUSE.NO_LISTS)
  assert.equal(draw.draw(owner, 'other', '').reason, DRAW_REFUSE.INTENT_UNKNOWN)
  for (const { tag } of PHRASE_LANGUAGES) {
    const drawn = draw.draw(owner, 'bind', '', { language: tag })
    assert.equal(drawn.ok, true)
    assert.equal(drawn.language, tag)
    assert.equal(drawn.entropyBits, 77)
    assert.deepEqual(drawn.words, stableLibrary.generatePhrase({ language: tag }).words)
    assert.equal((await draw.submit(outsider, 'bind', drawn.words)).reason, DRAW_REFUSE.FORBIDDEN_SENDER)
    assert.equal((await draw.submit(owner, 'bind', drawn.words.map(word => word.normalize('NFC')))).ok, true)
    assert.equal(lastBound.phraseLanguage, tag)
    assert.deepEqual(lastBound.words, drawn.words)
    assert.equal((await draw.submit(owner, 'bind', drawn.words)).reason, DRAW_REFUSE.NO_PENDING_DRAW)
  }
  let drawn = draw.draw(owner, 'bind', '')
  for (const typo of ['notaword', 'notaword1']) {
    drawn = draw.draw(owner, 'bind', '')
    const wrong = [...drawn.words]; wrong[2] = typo
    const invalid = await draw.submit(owner, 'bind', wrong)
    assert.equal(invalid.reason, 'aumlok:phrase-word-unknown')
    assert.equal(invalid.invalidWord, typo)
    assert.equal(invalid.drawSpent, true)
    assert.equal((await draw.submit(owner, 'bind', drawn.words)).reason, DRAW_REFUSE.NO_PENDING_DRAW)
  }
  for (const malformed of ['x'.repeat(65), 4, null]) {
    drawn = draw.draw(owner, 'bind', '')
    assert.equal((await draw.submit(owner, 'bind', [malformed, ...drawn.words.slice(1)])).reason, DRAW_REFUSE.PHRASE_SHAPE)
  }
  drawn = draw.draw(owner, 'bind', '')
  assert.equal((await draw.submit(owner, 'bind', ['ability', ...drawn.words.slice(1)])).reason, DRAW_REFUSE.PHRASE_MISMATCH)
  drawn = draw.draw(owner, 'bind', '')
  assert.equal((await draw.submit(owner, 'bind', drawn.words.slice(1))).reason, DRAW_REFUSE.PHRASE_SHAPE)
  assert.equal(draw.isPending(), false)
  draw.draw(owner, 'bind', '')
  draw.forget()
  assert.equal(draw.isPending(), false)
}
async function faceChecks(api) {
  assert.deepEqual(api.AUMLOK_PHRASE_LANGUAGES.map(item => item.tag), PHRASE_LANGUAGES.map(item => item.tag))
  let received
  const bridge = api.readAumlokCeremonyBridge({ available: true,
    draw: async (intent, language) => { received = { intent, language }; return { ok: true, ...stableLibrary.generatePhrase({ language }) } },
    submit: async () => ({ ok: false, reason: 'aumlok:phrase-word-unknown', invalidWord: 'notaword', drawSpent: true }) })
  for (const { tag } of PHRASE_LANGUAGES) {
    const result = await api.drawAumlokPhrase(bridge, 'bind', tag)
    assert.equal(result.ok, true)
    assert.equal(result.language, tag)
    assert.equal(result.entropyBits, 77)
    assert.deepEqual(received, { intent: 'bind', language: tag })
  }
  const known = { ok: true, ...stableLibrary.generatePhrase({ language: 'en' }) }
  assert.equal(api.parseAumlokDrawnPhrase({ ...known, entropyBits: 14 }).ok, false)
  assert.equal(api.parseAumlokDrawnPhrase({ ...known, language: 'made-up' }).ok, false)
  assert.equal(api.parseAumlokDrawnPhrase({ ...known, words: known.words.slice(1) }).ok, false)
  assert.equal((await api.submitAumlokPhrase(bridge, 'bind', known.words)).invalidWord, 'notaword')
  assert.equal(api.parseAumlokCeremonyResult({ ok: false, invalidWord: 'notaword1' }).invalidWord, 'notaword1')
  assert.equal(api.parseAumlokCeremonyResult({ ok: false, invalidWord: 'x'.repeat(65) }).invalidWord, undefined)
  assert.equal(api.phraseStrengthKey(false), 'phrase.strength.new')
  assert.equal(api.phraseStrengthKey(true), 'phrase.strength.legacy')
  assert.equal(api.phraseStrengthKey(undefined), 'phrase.strength.legacy')
}
const projection = { domain: 'aukora:aumlok-public-control:v1', subject: `aukora:1:${'a'.repeat(64)}`,
  epoch: 0, activeControlDigest: 'b'.repeat(64), revoked: false, approvalKeyDid: 'did:key:z' + '1'.repeat(30),
  custodyClass: 'same-uid-posix-mode-only', boundAt: '2026-01-01T00:00:00Z' }
function metadataChecks(parse) {
  assert.equal(parse(projection).phraseLegacy, undefined)
  for (const { tag } of PHRASE_LANGUAGES) {
    const result = parse({ ...projection, phraseLanguage: tag, phraseLegacy: false })
    assert.equal(result.phraseLanguage, tag)
    assert.equal(result.phraseLegacy, false)
  }
  assert.throws(() => parse({ ...projection, phraseLanguage: 'en' }))
  assert.throws(() => parse({ ...projection, phraseLanguage: 'fake', phraseLegacy: false }))
  assert.throws(() => parse({ ...projection, phraseLanguage: 'en', phraseLegacy: 'false' }))
  assert.throws(() => parse({ ...projection, privateKey: 'synthetic' }))
}
await drawChecks(createAumlokDraw)
await faceChecks(face)
metadataChecks(parseAumlokRecordControlProjection)
for (const locale of [en, zh]) {
  assert.match(locale['phrase.strength.new'], /77/u)
  assert.match(locale['phrase.strength.new'], /2048/u)
  assert.match(locale['phrase.strength.legacy'], /14\.3/u)
}
// Exercise the actual preload bridge so the selected tag cannot be dropped before IPC.
const preload = readFileSync(new URL('../apps/aukora-desktop/aumlok-bridge-preload.cjs', import.meta.url), 'utf8')
let exposed, crossing
new Script(preload).runInNewContext({ require: () => ({
  contextBridge: { exposeInMainWorld: (_, value) => { exposed = value } },
  ipcRenderer: { invoke: (channel, payload) => { crossing = { channel, payload } } },
}) })
exposed.draw('bind', 'ja')
assert.equal(crossing.channel, 'aumlok:approval:draw')
assert.equal(crossing.payload.language, 'ja')
exposed.draw('bind')
assert.equal(crossing.payload.language, 'en')
const surface = readFileSync(new URL('../plugins/aukora-face/aumlok/src/client/AumlokSurface.tsx', import.meta.url), 'utf8')
assert.match(surface, /data-aumlok-phrase-language/u)
function languageVisibility(text) {
  const condition = text.match(/\{([^\n]+) \? <label className=\{css.handleLabel\}>/u)?.[1]
  assert.ok(condition, 'language selector condition missing')
  for (const [state, changingHandle, shown] of [['unbound', false, true], ['bound', false, false], ['bound', true, true], ['refresh', true, true]]) {
    assert.equal(new Script(condition).runInNewContext({ state, changingHandle }), shown)
  }
}
languageVisibility(surface)
assert.throws(() => languageVisibility(surface.replace("state !== 'bound' || changingHandle ? <label", "state !== 'bound' ? <label")), { name: 'AssertionError' })
console.log('AUMLOK UI MUTATION: KILLED refresh language selector hidden')
assert.match(surface, /drawPhrase\(intent, language\)/u)
assert.match(surface, /data-aumlok-first-word>\{words\?\.\[AUMLOK_ANCHOR_POSITION\]\}/u)
assert.match(surface, /phraseStrengthKey\(projection\.status/u)
console.log('AUMLOK UI: PASS shared generator, ten languages, Unicode type-back, invalid word, spent draw, metadata and legacy label')

async function mutant(name, source, before, after, check, typescript = false) {
  assert.ok(source.includes(before), `missing mutation site: ${name}`)
  const changed = source.replace(before, after)
  const code = typescript ? stripTypeScriptTypes(changed) : changed
  const module = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}#${encodeURIComponent(name)}`)
  await assert.rejects(async () => check(module), { name: 'AssertionError' }, `survived: ${name}`)
  console.log(`AUMLOK UI MUTATION: KILLED ${name}`)
}
await mutant('language dropped', drawSource, "language: context.language ?? 'en'", "language: 'en'", module => drawChecks(module.createAumlokDraw))
await mutant('sender guard removed', drawSource,
  "if (pending.owner !== owner) return { ok: false, reason: DRAW_REFUSE.FORBIDDEN_SENDER }", '', module => drawChecks(module.createAumlokDraw))
await mutant('draw reusable', drawSource, 'pending = null\n      if (!Array.isArray(words)', '/* reused */\n      if (!Array.isArray(words)', module => drawChecks(module.createAumlokDraw))
await mutant('mismatch accepted', drawSource, 'if (offered.some((word, at) => word !== expected.words[at]))', 'if (false)', module => drawChecks(module.createAumlokDraw))
await mutant('invalid word hidden', drawSource, '? { invalidWord: error.word } : {}', '? {} : {}', module => drawChecks(module.createAumlokDraw))
await mutant('oversized typed word accepted', drawSource, ' && word.length <= 64', '', module => drawChecks(module.createAumlokDraw))
await mutant('oversized error displayed', faceSource, " && record['invalidWord'].length <= 64", '', faceChecks, true)
await mutant('face drops language', faceSource, 'await bridge.draw(intent, language)', "await bridge.draw(intent, 'en')", faceChecks, true)
await mutant('legacy called strong', faceSource, "return legacy === false ? 'phrase.strength.new'", "return true ? 'phrase.strength.new'", faceChecks, true)
await mutant('strength contract removed', faceSource, " || record['entropyBits'] !== 77", '', faceChecks, true)
await mutant('metadata validation removed', metadataSource.replace("'./binding-bridge.ts'", JSON.stringify(new URL('../plugins/aukora-face/aumlok/src/client/binding-bridge.ts', import.meta.url).href)),
  "if (!AUMLOK_PHRASE_LANGUAGES.some(item => item.tag === phraseLanguage) || typeof phraseLegacy !== 'boolean')", 'if (false)',
  module => metadataChecks(module.parseAumlokRecordControlProjection), true)
console.log('AUMLOK UI MUTATIONS: 12/12 KILLED; source fixtures only, installed Electron NOT RUN')
