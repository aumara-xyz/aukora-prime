// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe hints for displaying exact Unicode text. No authority, normalization, or replacement.
const FORMAT_CONTROL = /\p{Cf}/u
const LATIN = /\p{Script=Latin}/u
const GREEK = /\p{Script=Greek}/u
const CYRILLIC = /\p{Script=Cyrillic}/u
const TOKEN = /[\p{L}\p{M}\p{N}_]+/gu
// Deliberately bounded examples of Greek/Cyrillic letters that resemble ASCII letters.
// This is a presentation hint, not a complete Unicode confusable detector.
const ASCII_LOOKALIKES = Object.freeze({
  'Α':'A', 'Β':'B', 'Ε':'E', 'Ζ':'Z', 'Η':'H', 'Ι':'I', 'Κ':'K', 'Μ':'M', 'Ν':'N', 'Ο':'O',
  'Ρ':'P', 'Τ':'T', 'Υ':'Y', 'Χ':'X', 'ο':'o', 'ρ':'p', 'ν':'v',
  'А':'A', 'В':'B', 'Е':'E', 'К':'K', 'М':'M', 'Н':'H', 'О':'O', 'Р':'P', 'С':'C', 'Т':'T', 'Х':'X',
  'а':'a', 'е':'e', 'о':'o', 'р':'p', 'с':'c', 'у':'y', 'х':'x', 'і':'i', 'ј':'j', 'ѕ':'s',
})
const LIMIT = 16
const codePoint = character => 'U+' + character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')
const script = character => LATIN.test(character) ? 'Latin' : GREEK.test(character) ? 'Greek'
  : CYRILLIC.test(character) ? 'Cyrillic' : null
const freeze = value => {
  for (const child of Object.values(value)) if (child && typeof child === 'object') freeze(child)
  return Object.freeze(value)
}

/** UTF-16 indexes address the unchanged JavaScript string; code points make invisible characters reviewable. */
export function capturePresentationWarnings(statement) {
  if (typeof statement !== 'string') throw new TypeError('memory:capture-presentation-invalid')
  const controls = [], lookalikes = [], mixed = []
  let controlCount = 0, lookalikeCount = 0, mixedCount = 0, index = 0
  for (const character of statement) {
    if (FORMAT_CONTROL.test(character)) {
      controlCount++
      if (controls.length < LIMIT) controls.push({ index, code_point: codePoint(character) })
    }
    if (Object.hasOwn(ASCII_LOOKALIKES, character)) {
      lookalikeCount++
      if (lookalikes.length < LIMIT) lookalikes.push({ index, code_point: codePoint(character),
        resembles: ASCII_LOOKALIKES[character], script: script(character) })
    }
    index += character.length
  }
  for (const token of statement.matchAll(TOKEN)) {
    const scripts = [...new Set([...token[0]].map(script).filter(Boolean))]
    if (scripts.length < 2) continue
    mixedCount++
    if (mixed.length < LIMIT) mixed.push({ index: token.index, length: token[0].length, scripts })
  }
  const warnings = []
  if (controlCount) warnings.push({ code: 'format-controls', count: controlCount, examples: controls,
    text: 'Text contains Unicode format controls that can change its presentation. Exact characters are preserved.' })
  if (lookalikeCount) warnings.push({ code: 'ascii-lookalikes', count: lookalikeCount, examples: lookalikes,
    text: 'Some Greek or Cyrillic letters may resemble Latin letters. This is a limited hint; exact characters are preserved.' })
  if (mixedCount) warnings.push({ code: 'mixed-scripts', count: mixedCount, examples: mixed,
    text: 'Some words mix Latin, Greek, or Cyrillic scripts. Script mixing can be legitimate; inspect the exact characters.' })
  return freeze(warnings)
}
