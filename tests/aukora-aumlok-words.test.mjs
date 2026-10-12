// Pin uniform seven-word generation, dictionary validation and the existing v3 identity.
import assert from 'node:assert/strict'
import crypto, { createHash } from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import test from 'node:test'

const source = fileURLToPath(new URL('../plugins/aukora-aumlok/lib/', import.meta.url))
const lib = process.env.AUKORA_WORDS_TEST_LIB ?? source
const modulePath = join(lib, 'ceremony-phrase.mjs')
const vendor = join(lib, 'vendor/bip39-wordlists')
const scratch = mkdtempSync(join(tmpdir(), 'aumlok-words-'))
process.on('exit', () => rmSync(scratch, { recursive: true, force: true }))

if (process.argv.includes('--mutate')) {
  const baseline = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], {
    env: process.env, encoding: 'utf8', timeout: 120000,
  })
  assert.equal(baseline.status, 0, 'baseline must pass before mutation: ' + baseline.stdout + baseline.stderr)
  const mutations = [
    ['word-count', 'export const PHRASE_LENGTH = 7', 'export const PHRASE_LENGTH = 6'],
    ['full-list', '& 2047', '& 1023'],
    ['independent-positions', 'bytes[index * 2]', 'bytes[0]'],
    ['default-csprng', 'randomBytes = platformRandomBytes', 'randomBytes = n => new Uint8Array(n)'],
    ['rng-shape', 'bytes.length !== PHRASE_LENGTH * 2', 'false'],
    ['unknown-word', 'unknown !== undefined && !legacy', 'false'],
    ['legacy-vocabulary', '&& words.slice(1).every((word, index) => pools[Math.floor(index / 2)].has(word))', '&& true'],
    ['legacy-case', ".toLowerCase().trim()", ".trim()"],
    ['nfkd', "String(value ?? '').normalize('NFKD')", "String(value ?? '')"],
    ['list-hash', "createHash('sha256').update(bytes).digest('hex') !== entry.sha256", 'false'],
    ['list-unique', 'new Set(words).size !== words.length', 'false'],
    ['list-nfkd', "word !== word.normalize('NFKD')", 'false'],
    ['missing-list-name', "refuse(PHRASE_REFUSE.LIST, 'the pinned word list is missing or unreadable')", "throw new Error('missing list')"],
    ['list-count', 'words.length !== 2048', 'false'],
    ['legacy-overlap', "const legacy = language === 'en' && isLegacyPhrase(words)", "const legacy = unknown !== undefined && language === 'en' && isLegacyPhrase(words)"],
    ['legacy-kdf', "export const AUMLOK_KDF_ID = 'aumlok-kdf-v1'", "export const AUMLOK_KDF_ID = 'aumlok-kdf-v2'", 'derive-v3.mjs'],
  ]
  let caught = 0
  for (const [name, from, to, file = 'ceremony-phrase.mjs'] of mutations) {
    const copy = join(scratch, name)
    cpSync(lib, join(copy, 'lib'), { recursive: true })
    cpSync(join(lib, '../data'), join(copy, 'data'), { recursive: true })
    if (caught === 0) {
      const copiedBaseline = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], {
        env: { ...process.env, AUKORA_WORDS_TEST_LIB: join(copy, 'lib') }, encoding: 'utf8', timeout: 120000,
      })
      assert.equal(copiedBaseline.status, 0, 'copied library baseline must pass: ' + copiedBaseline.stdout + copiedBaseline.stderr)
    }
    const path = join(copy, 'lib', file)
    const text = readFileSync(path, 'utf8')
    assert.equal(text.split(from).length - 1, 1, `${name}: stale mutation`)
    writeFileSync(path, text.replace(from, to))
    const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], {
      env: { ...process.env, AUKORA_WORDS_TEST_LIB: join(copy, 'lib') }, encoding: 'utf8', timeout: 120000,
    })
    const output = result.stdout + result.stderr
    const killed = result.status !== 0 && /not ok \d+ -/u.test(output)
    console.log(`MUTATION ${name}: ${killed ? 'CAUGHT' : 'SURVIVED OR CRASHED'}`)
    if (killed) caught += 1
    rmSync(copy, { recursive: true, force: true })
  }
  console.log(`AUMLOK WORD MUTATIONS: ${caught}/${mutations.length} caught`)
  process.exit(caught === mutations.length ? 0 : 1)
}

const words = await import(pathToFileURL(modulePath))
const derive = await import(pathToFileURL(join(lib, 'derive-v3.mjs')))
const manifest = JSON.parse(readFileSync(join(vendor, 'manifest.json')))
const tags = ['en', 'es', 'fr', 'it', 'pt', 'cs', 'ja', 'ko', 'zh-Hans', 'zh-Hant']
const cheap = { N: 1024, r: 8, p: 1, keyLen: 64, maxmem: 16 * 1024 * 1024 }

function fixedRng() {
  let counter = 0
  return size => createHash('sha256').update(`aumlok-test-${counter++}`).digest().subarray(0, size)
}

test('ten pinned lists have 2048 unique NFKD lines and the canonical English hash', () => {
  assert.deepEqual(words.PHRASE_LANGUAGES.map(item => item.tag), tags)
  assert.equal(manifest.source.package, '@scure/bip39')
  assert.equal(manifest.source.version, '2.0.1')
  assert.equal(manifest.lists[0].sha256, '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda')
  for (const entry of manifest.lists) {
    const bytes = readFileSync(join(vendor, entry.file))
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256)
    assert.equal(bytes.toString().endsWith('\n'), true)
    const list = bytes.toString().trimEnd().split('\n')
    assert.equal(list.length, 2048)
    assert.equal(new Set(list).size, 2048)
    assert.deepEqual(list, list.map(word => word.normalize('NFKD')))
  }
})

test('uniform over all 2048 entries in every position (fixed SHA-256 test RNG)', () => {
  const list = words.phraseWordList('en')
  const index = new Map(list.map((word, i) => [word, i]))
  const counts = Array.from({ length: 7 }, () => new Uint32Array(2048))
  const randomBytes = fixedRng()
  const draws = 30000
  for (let i = 0; i < draws; i++) {
    const phrase = words.generatePhrase({ randomBytes })
    assert.equal(phrase.words.length, 7)
    phrase.words.forEach((word, slot) => { counts[slot][index.get(word)] += 1 })
    assert.equal(phrase.entropyBits, 77)
  }
  for (const [slot, row] of counts.entries()) {
    const expected = draws / 2048
    const statistic = row.reduce((sum, n) => sum + (n - expected) ** 2 / expected, 0)
    assert.ok(statistic < 2400, `slot ${slot}: chi-square ${statistic}, df=2047`)
    assert.ok(row.every(n => n > 0), `slot ${slot}: unreachable words`)
  }
})

test('the default RNG calls node:crypto; each position uses fresh bits and repetitions are allowed', () => {
  const original = crypto.randomBytes
  let requested = 0
  try {
    crypto.randomBytes = size => { requested = size; return Buffer.from([0, 0, 0, 1, 1, 0, 4, 0, 7, 255, 3, 1, 2, 0]) }
    syncBuiltinESMExports()
    const generated = words.generatePhrase()
    assert.equal(requested, 14)
    const list = words.phraseWordList()
    assert.deepEqual(generated.words, [0, 1, 256, 1024, 2047, 769, 512].map(i => list[i]))
  } finally {
    crypto.randomBytes = original
    syncBuiltinESMExports()
  }
  const repeated = words.generatePhrase({ randomBytes: size => new Uint8Array(size) })
  assert.deepEqual(repeated.words, Array(7).fill('abandon'))
  assert.equal(repeated.legacy, false)
  assert.deepEqual(words.generateAcrosticPhrase({ randomBytes: size => new Uint8Array(size) }), repeated)
  assert.throws(() => words.generatePhrase({ randomBytes: () => new Uint8Array(1) }), { code: words.PHRASE_REFUSE.RANDOM })
})

test('every language generates, normalizes, validates and derives the same root after NFC/space entry', async () => {
  for (const language of tags) {
    const generated = words.generatePhrase({ language, randomBytes: fixedRng() })
    const typed = generated.words.map(word => word.normalize('NFC')).join(language === 'ja' ? '\u3000' : ' ')
    const checked = words.validatePhrase(typed, { language })
    assert.equal(checked.phrase, generated.phrase)
    assert.equal(checked.legacy, false)
    const a = await derive.deriveRootFromPhrase(generated.phrase, { handle: 'round.trip', params: cheap })
    const b = await derive.deriveRootFromPhrase(typed, { handle: 'round.trip', params: cheap })
    assert.equal(a.rootId, b.rootId, language)
  }
})

test('unknown language, wrong count and first unknown word refuse by name', () => {
  assert.throws(() => words.generatePhrase({ language: '../en' }), { code: words.PHRASE_REFUSE.LANGUAGE })
  assert.throws(() => words.validatePhrase('abandon '.repeat(6)), { code: words.PHRASE_REFUSE.LENGTH })
  for (const language of tags) {
    const phrase = words.generatePhrase({ language, randomBytes: fixedRng() })
    phrase.words[2] = 'wrongword'
    phrase.words[5] = 'anotherwrongword'
    assert.throws(() => words.validatePhrase(phrase.words.join(' '), { language }), error =>
      error.code === words.PHRASE_REFUSE.WORD && error.word === 'wrongword'
      && error.message.includes('wrongword') && !error.message.includes('anotherwrongword'))
  }
  assert.throws(() => words.validatePhrase('corals wrongword oasis ring amity light summit'), { code: words.PHRASE_REFUSE.WORD })
  assert.throws(() => words.validatePhrase('corals cliff oasis ring amity light szzzz'), error =>
    error.code === words.PHRASE_REFUSE.WORD && error.word === 'szzzz')
})

test('existing cold-root legacy vector keeps its root at the unchanged production scrypt cost', async () => {
  // Public synthetic vector taken from tests/aukora-aumlok-cold-root.test.mjs before the change.
  const phrase = 'corals cliff oasis ring amity light summit'
  assert.equal(words.normalizePhrase('  CORALS_cliff  oasis-ring AMITY_light_summit  '), phrase.replaceAll(' ', '-'))
  const checked = words.validatePhrase(phrase)
  assert.equal(checked.legacy, true)
  assert.equal(checked.entropyBits, null)
  const list = words.phraseWordList()
  const themes = JSON.parse(readFileSync(join(lib, '../data/aumlok-themes.json'))).themes
  const anchors = JSON.parse(readFileSync(join(lib, '../data/aumlok-anchors.json'))).anchors
  const slots = ['NATURE', 'NATURE', 'PEOPLE', 'PEOPLE', 'SPIRIT', 'SPIRIT']
  const overlap = anchors.filter(word => list.includes(word)).map(anchor =>
    [anchor, ...[...anchor].map((letter, i) => themes[slots[i]][letter].find(word => list.includes(word)))])
    .find(phrase => phrase.every(Boolean))
  assert.ok(overlap, 'the old/new vocabulary intersection is exercised')
  assert.equal(words.validatePhrase(overlap.join(' ')).legacy, true, 'an old acrostic cannot acquire 77 bits from list membership')
  assert.deepEqual(derive.PHRASE_KDF_V3, { N: 131072, r: 8, p: 5, keyLen: 64, maxmem: 268435456 })
  const root = await derive.deriveRootFromPhrase(phrase, { handle: 'cold.root' })
  assert.equal(root.rootId, 'f1b053860e7fd539d6b7c436e8806b3de601331eb16e96ef07139a66caa4070d')
  assert.equal(root.ed25519PublicKeyHex, 'df6763e594b036a966c3024c8329ba8c75920b00300cebea8e20f895b605ed66')
})

test('runtime refuses changed list bytes, duplicate entries and a non-2048 list', async () => {
  for (const kind of ['hash', 'unique', 'count', 'nfkd', 'missing']) {
    const copy = join(scratch, `integrity-${kind}`)
    cpSync(modulePath, `${copy}.mjs`)
    // Relative imports are absent; each copied module uses its own vendored data.
    cpSync(vendor, join(scratch, 'vendor/bip39-wordlists'), { recursive: true, force: true })
    const file = join(scratch, 'vendor/bip39-wordlists/english.txt')
    const lines = readFileSync(file, 'utf8').trimEnd().split('\n')
    if (kind === 'hash') [lines[0], lines[1]] = [lines[1], lines[0]]
    if (kind === 'unique') lines[0] = lines[1]
    if (kind === 'count') lines.pop()
    if (kind === 'nfkd') lines[0] = 'éclair'
    const changed = `${lines.join('\n')}\n`
    writeFileSync(file, changed)
    if (kind === 'missing') rmSync(file)
    if (kind !== 'hash') {
      const pin = structuredClone(manifest)
      pin.lists[0].sha256 = createHash('sha256').update(changed).digest('hex')
      writeFileSync(join(scratch, 'vendor/bip39-wordlists/manifest.json'), JSON.stringify(pin))
    }
    const isolated = await import(pathToFileURL(`${copy}.mjs`))
    assert.throws(() => isolated.generatePhrase(), { code: words.PHRASE_REFUSE.LIST }, kind)
  }
})
