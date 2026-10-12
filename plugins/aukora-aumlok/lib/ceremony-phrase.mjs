// Seven independent uniform BIP-39 word draws; legacy tables are read only for compatibility.
import { randomBytes as platformRandomBytes, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

export const PHRASE_LENGTH = 7
export const PHRASE_ENTROPY_BITS = 77
export const PHRASE_REFUSE = Object.freeze({
  LANGUAGE: 'aumlok:phrase-language-unknown',
  LENGTH: 'aumlok:phrase-length',
  WORD: 'aumlok:phrase-word-unknown',
  LIST: 'aumlok:word-list-integrity',
  RANDOM: 'aumlok:phrase-random-source',
})

function refuse(code, detail, word) {
  const error = new TypeError(`${code}: ${detail}`)
  error.code = code
  if (word !== undefined) error.word = word
  throw error
}

const vendor = new URL('./vendor/bip39-wordlists/', import.meta.url)
const manifest = JSON.parse(readFileSync(new URL('manifest.json', vendor), 'utf8'))
export const PHRASE_LANGUAGES = Object.freeze(manifest.lists.map(({ language, name }) =>
  Object.freeze({ tag: language, name })))
const lists = new Map()

export function phraseWordList(language = 'en') {
  const entry = manifest.lists.find(item => item.language === language)
  if (!entry) refuse(PHRASE_REFUSE.LANGUAGE, 'choose a supported phrase language')
  if (!lists.has(language)) {
    let bytes
    try { bytes = readFileSync(new URL(entry.file, vendor)) } catch {
      refuse(PHRASE_REFUSE.LIST, 'the pinned word list is missing or unreadable')
    }
    const text = bytes.toString('utf8')
    const words = text.slice(0, -1).split('\n')
    if (!text.endsWith('\n') || words.length !== 2048 || new Set(words).size !== words.length
      || words.some(word => !word || word !== word.normalize('NFKD') || /[\s_-]/u.test(word))
      || createHash('sha256').update(bytes).digest('hex') !== entry.sha256) {
      refuse(PHRASE_REFUSE.LIST, 'the pinned 2048-word list is required')
    }
    lists.set(language, Object.freeze(words))
  }
  return lists.get(language)
}

// Preserve the v3 lowercase/dash preimage; NFKD adds canonical spelling for the new languages.
export function normalizePhrase(value) {
  return String(value ?? '').normalize('NFKD').toLowerCase().trim().replace(/[\s_-]+/gu, '-')
}

let legacyPools
function legacyVocabulary() {
  if (legacyPools) return legacyPools
  const current = JSON.parse(readFileSync(new URL('../data/aumlok-themes.json', import.meta.url), 'utf8')).themes
  legacyPools = ['NATURE', 'PEOPLE', 'SPIRIT'].map((theme, index) => {
    const document = JSON.parse(readFileSync(new URL(`../data/theme-${theme.toLowerCase()}.json`, import.meta.url), 'utf8'))
    const old = document.letters ?? document
    return new Set([
      ...Object.values(WORDS_THEMED[['root', 'unite', 'rise'][index]]).flat(),
      ...Object.values(current[theme]).flat(), ...Object.values(old).flat(),
    ])
  })
  return legacyPools
}

// Only words in retained legacy vocabularies can bypass the selected BIP-39 list on recovery.
export function isLegacyPhrase(words) {
  if (words.length !== 7 || !/^[a-z]{6}$/u.test(words[0])
    || !words.slice(1).every((word, index) => /^[a-z]+$/u.test(word) && word[0] === words[0][index])) return false
  const pools = legacyVocabulary()
  return (ANCHOR_WORDS.includes(words[0]) || pools.some(pool => pool.has(words[0])))
    && words.slice(1).every((word, index) => pools[Math.floor(index / 2)].has(word))
}

export function validatePhrase(value, { language = 'en' } = {}) {
  const list = phraseWordList(language)
  const phrase = normalizePhrase(value)
  const words = phrase.split('-')
  if (words.length !== PHRASE_LENGTH) refuse(PHRASE_REFUSE.LENGTH, 'enter exactly seven words')
  let unknown = words.find(word => !list.includes(word))
  const legacy = language === 'en' && isLegacyPhrase(words)
  if (unknown !== undefined && !legacy) {
    if (language === 'en' && !list.includes(words[0]) && /^[a-z]{6}$/u.test(words[0])) {
      const pools = legacyVocabulary()
      if (ANCHOR_WORDS.includes(words[0]) || pools.some(pool => pool.has(words[0]))) {
        unknown = words.slice(1).find((word, index) =>
          word[0] !== words[0][index] || !pools[Math.floor(index / 2)].has(word)) ?? unknown
      }
    }
    refuse(PHRASE_REFUSE.WORD, `word "${unknown}" is not in the ${language} list`, unknown)
  }
  return { phrase, words, language, legacy, entropyBits: legacy ? null : PHRASE_ENTROPY_BITS }
}

export function generatePhrase({ language = 'en', randomBytes = platformRandomBytes } = {}) {
  const list = phraseWordList(language)
  const bytes = randomBytes(PHRASE_LENGTH * 2)
  if (!(bytes instanceof Uint8Array) || bytes.length !== PHRASE_LENGTH * 2) {
    refuse(PHRASE_REFUSE.RANDOM, 'the random source must return fourteen bytes')
  }
  // Each index uses eleven fresh bits. 2048 divides 65536, so masking introduces no bias.
  const words = Array.from({ length: PHRASE_LENGTH }, (_, index) =>
    list[((bytes[index * 2] << 8) | bytes[index * 2 + 1]) & 2047])
  return { phrase: words.join('-'), words, tokens: words, language, legacy: false, entropyBits: PHRASE_ENTROPY_BITS }
}

// Old callers also receive the uniform generator; no acrostic generator remains.
export function generateAcrosticPhrase(options) { return generatePhrase(options) }

const THEME_BY_ROW = ['root', 'root', 'unite', 'unite', 'rise', 'rise']
const WORDS_THEMED = {
  root: { // green — nature, of the earth
    a: ['amber', 'aspen', 'alder', 'acorn'], b: ['birch', 'brook', 'bramble', 'basin'],
    c: ['cedar', 'coral', 'clover', 'cliff'], d: ['delta', 'dune', 'drift', 'dawn'],
    e: ['elm', 'ember', 'estuary', 'eddy'], f: ['fern', 'flint', 'fjord', 'frost'],
    g: ['grove', 'glade', 'granite', 'garnet'], h: ['hazel', 'heath', 'hollow', 'harbor'],
    i: ['iris', 'ivy', 'island', 'inlet'], j: ['juniper', 'jasper', 'jade'],
    k: ['kelp', 'kestrel', 'knoll'], l: ['larch', 'lagoon', 'lichen', 'loam'],
    m: ['maple', 'marsh', 'meadow', 'moss'], n: ['nettle', 'nimbus', 'north', 'nectar'],
    o: ['ochre', 'otter', 'oasis', 'oak'], p: ['pebble', 'pine', 'petal', 'prairie'],
    q: ['quartz', 'quince', 'quarry'], r: ['rowan', 'reef', 'river', 'reed'],
    s: ['sage', 'slate', 'storm', 'spruce'], t: ['thorn', 'timber', 'tide', 'tundra'],
    u: ['umber', 'upland', 'ursa'], v: ['vale', 'verdant', 'vine', 'violet'],
    w: ['willow', 'wren', 'walnut', 'winter'], y: ['yarrow', 'yew', 'yonder'], z: ['zephyr', 'zinnia', 'zinc'],
  },
  unite: { // blue — people, of each other
    a: ['ally', 'accord', 'amity', 'anthem'], b: ['banter', 'bond', 'bridge', 'brother'],
    c: ['circle', 'chorus', 'comrade', 'cradle'], d: ['dance', 'duet', 'dwell', 'dinner'],
    e: ['embrace', 'ensemble', 'elder', 'emissary'], f: ['friend', 'family', 'fellow', 'feast'],
    g: ['gather', 'guest', 'guide', 'gift'], h: ['hearth', 'harmony', 'hello', 'haven'],
    i: ['invite', 'inn', 'icon'], j: ['jest', 'join', 'jubilee'],
    k: ['kin', 'kindred', 'keepsake'], l: ['laughter', 'link', 'lodge', 'lullaby'],
    m: ['mingle', 'mirth', 'mentor', 'market'], n: ['neighbor', 'nest', 'nomad'],
    o: ['offer', 'oath', 'opus'], p: ['partner', 'parley', 'pact', 'plaza'],
    q: ['quorum', 'quilt', 'quip'], r: ['rally', 'rapport', 'refuge', 'ring'],
    s: ['supper', 'salon', 'smile', 'shelter'], t: ['tribe', 'trust', 'toast', 'tavern'],
    u: ['unity', 'union', 'usher'], v: ['vow', 'voice', 'visit', 'village'],
    w: ['welcome', 'waltz', 'weave'], y: ['yarn', 'youth'], z: ['zeal', 'zest'],
  },
  rise: { // purple — higher purpose, of what lifts
    a: ['ascend', 'aura', 'altar', 'arrow'], b: ['beacon', 'bless', 'beyond'],
    c: ['calling', 'cosmos', 'crown', 'compass'], d: ['destiny', 'devotion', 'dharma'],
    e: ['eternal', 'exalt', 'essence'], f: ['faith', 'flame', 'favor'],
    g: ['grace', 'glory', 'gleam'], h: ['halo', 'heaven', 'horizon', 'hymn'],
    i: ['ideal', 'infinite', 'inspire'], j: ['journey', 'justice', 'jewel'],
    k: ['karma', 'keystone', 'kindle'], l: ['light', 'lumen', 'lodestar', 'legacy'],
    m: ['mercy', 'miracle', 'muse', 'myth'], n: ['noble', 'nirvana', 'nova'],
    o: ['oracle', 'omen', 'onward'], p: ['prayer', 'pilgrim', 'pinnacle', 'psalm'],
    q: ['quest', 'quasar'], r: ['radiant', 'rise', 'reverie', 'realm'],
    s: ['sacred', 'spirit', 'soul', 'summit'], t: ['temple', 'truth', 'totem'],
    u: ['uplift', 'upward', 'ultra'], v: ['vision', 'virtue', 'vessel'],
    w: ['wisdom', 'wonder', 'worship'], y: ['yearn', 'yonder'], z: ['zenith', 'zen'],
  },
}
// 6-letter anchor words — every letter must have a bucket in EVERY theme (letters can land on any row).
const ANCHOR_WORDS = ['harbor', 'cinder', 'garnet', 'meadow', 'willow', 'timber', 'sorrel', 'frosty',
  'velvet', 'silver', 'copper', 'walnut', 'embers', 'thorns', 'ravens', 'pewter', 'corals', 'winter']

// Retained for legacy inventory readers, never used to generate a phrase.
export const PHRASE_TABLES = Object.freeze({
  THEME_BY_ROW: Object.freeze([...THEME_BY_ROW]), WORDS_THEMED,
  ANCHOR_WORDS: Object.freeze([...ANCHOR_WORDS]),
})
export const PHRASE_BANDS = Object.freeze(['root', 'unite', 'rise'])
