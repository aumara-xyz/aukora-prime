// Scan display text without rewriting operation bytes; receipts contain hashes and categories only.
import { createHash } from 'node:crypto'

export const DISPLAY_MAX_BYTES = 16384
const AUTHORITY_WORDS = ['auth', 'apply', 'admin', 'root', 'grant', 'sudo', 'exec', 'signer', 'aumlok', 'authorize', 'production', 'live', 'permit', 'kernel']
// Deliberately partial confusable coverage, not a complete Unicode spoof detector.
const LOOKALIKES = new Map()
for (const [ascii, characters] of Object.entries({
  a: 'аАαΑɑᎪ', b: 'ВΒᏏ', c: 'сСᴄ', d: 'ԁᎠ', e: 'еЕΕ', g: 'ɡᏬ', h: 'һнНʜ',
  i: 'іιıɩɪ', j: 'јȷ', k: 'кКκ', l: 'Ꮮ', m: 'мМ', n: 'ɴ', o: 'оОοΟᴏ',
  p: 'рРρΡᴘ', r: 'ʀᏆ', s: 'ѕʂᏎ', t: 'тТ', u: 'υ', v: 'вν', w: 'Ꮃ', x: 'хХχ', y: 'у',
})) for (const character of characters) LOOKALIKES.set(character, ascii)
const MATH_STARTS = [0x1d400, 0x1d41a, 0x1d468, 0x1d482, 0x1d5a0, 0x1d5ba,
  0x1d5d4, 0x1d5ee, 0x1d608, 0x1d622, 0x1d63c, 0x1d656, 0x1d670, 0x1d68a]

function fold(character) {
  if (LOOKALIKES.has(character)) return LOOKALIKES.get(character)
  const point = character.codePointAt(0)
  if (point >= 0xff21 && point <= 0xff3a) return String.fromCharCode(point - 0xff21 + 97)
  if (point >= 0xff41 && point <= 0xff5a) return String.fromCharCode(point - 0xff41 + 97)
  for (const start of MATH_STARTS) if (point >= start && point < start + 26) return String.fromCharCode(point - start + 97)
  return null
}

function hiddenCategory(character) {
  const point = character.codePointAt(0)
  if ([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff].includes(point)) return 'zero_width'
  if (/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(character)) return 'bidi_control'
  if (point >= 0xe0000 && point <= 0xe007f) return 'tag_char'
  if (/\p{Co}/u.test(character)) return 'private_use'
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(character)) return 'control_char'
  if (/[\p{Cf}\p{Default_Ignorable_Code_Point}]/u.test(character)) return 'format_char'
  return null
}

const hash = text => createHash('sha256').update(text, 'utf8').digest('hex')
function refuse(code) { throw Object.assign(new Error(code), { code }) }

export function scanAuthorityDisplay(text) {
  if (typeof text !== 'string') refuse('authority-display:text-required')
  if (Buffer.byteLength(text, 'utf8') > DISPLAY_MAX_BYTES) refuse('authority-display:too-large')
  if (!text.isWellFormed()) refuse('authority-display:invalid-unicode')
  const categories = new Set(), changed = []
  let skeleton = '', canonical = ''
  for (const character of text.normalize('NFC')) {
    const category = hiddenCategory(character), target = fold(character)
    if (category) categories.add(category)
    else canonical += target ?? character
    const piece = target ?? character.replace(/[A-Z]/g, c => c.toLowerCase())
    skeleton += piece
    for (let i = 0; i < piece.length; i++) changed.push(target !== null)
  }
  let occurrences = 0
  for (const word of AUTHORITY_WORDS) {
    for (let at = skeleton.indexOf(word); at !== -1; at = skeleton.indexOf(word, at + 1)) {
      if (changed.slice(at, at + word.length).some(Boolean)) occurrences++
    }
  }
  if (occurrences) categories.add('confusable_authority')
  const ok = categories.size === 0
  const code = ok ? null : 'authority-display:illegible'
  return { ok, code, receipt: {
    schema: 'aukora-authority-display/v1', raw_sha256: hash(text), canonical_sha256: hash(canonical),
    categories: [...categories].sort(), confusable_matches: occurrences,
    action: ok ? 'allow' : 'refuse', grants_authority: false,
  } }
}
