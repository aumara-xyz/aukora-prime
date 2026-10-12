// Exercise display refusals and byte-preserving receipts, including guard-removal controls.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, rmSync } from 'node:fs'
import * as scanner from '../src/authority-display.mjs'
import * as card from '../src/card.mjs'
import { ACCENT, accent, makeGate, approveViaReview } from './support/fixture.mjs'

const cp = String.fromCodePoint
const hash = value => createHash('sha256').update(value).digest('hex')
const sourceUrl = new URL('../src/authority-display.mjs', import.meta.url)
const source = readFileSync(sourceUrl, 'utf8')
const cardUrl = new URL('../src/card.mjs', import.meta.url)
const cardSource = readFileSync(cardUrl, 'utf8')
const load = text => import('data:text/javascript;base64,' + Buffer.from(text).toString('base64'))
const hidden = {
  zero_width: [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff],
  bidi_control: [0x061c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069],
  tag_char: [0xe0000, 0xe0001, 0xe0020, 0xe007f],
  private_use: [0xe000, 0xf8ff, 0xf0000, 0xffffd, 0x100000, 0x10fffd],
  control_char: [0, 8, 11, 12, 14, 31, 0x7f, 0x85, 0x9f],
  format_char: [0xfe00, 0xfe0f, 0x00ad, 0x180e, 0xfff9, 0x2061, 0xe0100, 0xe01ef,
    0x206a, 0x206f, 0x3164, 0xffa0, 0x115f, 0x1160, 0x034f],
}

function refused(module, text, category, count) {
  const result = module.scanAuthorityDisplay(text)
  assert.equal(result.ok, false)
  assert.equal(result.code, 'authority-display:illegible')
  assert.equal(result.receipt.action, 'refuse')
  assert.ok(result.receipt.categories.includes(category))
  if (count !== undefined) assert.equal(result.receipt.confusable_matches, count)
  assert.equal(result.receipt.grants_authority, false)
}
function accepts(module) {
  for (const text of ['please apply', 'AUTH authorize admin', 'hello world', 'café résumé naïve',
    '// автор: Иван. привет мир', 'const σ = 0.5; // Greek sigma label', '日本語 中文 한국어 — // i18n', 'a\t\n\rb']) {
    const result = module.scanAuthorityDisplay(text)
    assert.equal(result.ok, true, 'ordinary text remains usable')
    assert.equal(result.code, null)
    assert.equal(result.receipt.action, 'allow')
    assert.deepEqual(result.receipt.categories, [])
  }
}
function mixed(module) {
  const risky = cp(0x0430) + 'pply'
  for (const text of [`apply ${risky}`, `${risky} apply`, `😀 apply ${risky}`, `APPLY ${risky}`, `apply ${risky} ${risky}`])
    refused(module, text, 'confusable_authority', text.split(risky).length - 1)
}
function hashes(module) {
  const raw = `e\u0301 ${cp(0x200b)}${cp(0x0430)}pply`
  const before = Buffer.from(raw), result = module.scanAuthorityDisplay(raw)
  assert.deepEqual(Buffer.from(raw), before)
  assert.equal(result.receipt.raw_sha256, hash(before))
  assert.equal(result.receipt.canonical_sha256, hash('é apply'))
  assert.notEqual(result.receipt.raw_sha256, result.receipt.canonical_sha256)
  assert.equal(module.scanAuthorityDisplay('e\u0301').receipt.raw_sha256, hash('e\u0301'))
}
function privateReceipt(module) {
  for (const raw of ['synthetic-private-payload', `synthetic-private-payload ${cp(0x200b)}`]) {
    const result = module.scanAuthorityDisplay(raw)
    assert.deepEqual(Object.keys(result).sort(), ['code', 'ok', 'receipt'])
    assert.deepEqual(Object.keys(result.receipt).sort(), ['action', 'canonical_sha256', 'categories',
      'confusable_matches', 'grants_authority', 'raw_sha256', 'schema'])
    assert.equal(result.receipt.schema, 'aukora-authority-display/v1')
    assert.equal(result.receipt.grants_authority, false)
    assert.doesNotMatch(JSON.stringify(result), /synthetic-private-payload/)
    for (const field of ['raw_sha256', 'canonical_sha256']) assert.match(result.receipt[field], /^[0-9a-f]{64}$/)
  }
}
function noteReceipt(module) {
  const raw = `apply ${cp(0x0430)}pply`, meta = module.noteMeta(raw)
  assert.equal(meta.authority_display.raw_sha256, hash(raw))
  assert.equal(meta.authority_display.action, 'refuse')
  assert.deepEqual(meta.authority_display.categories, ['confusable_authority'])
  assert.doesNotMatch(JSON.stringify(meta.authority_display), /apply/)
  assert.equal(module.cleanNote(raw), 'apply pply')
  assert.ok(module.cardWarnings({}, '', '', module.cleanNote(raw), meta).some(w => /authority-display scan/.test(w)))
  assert.deepEqual(module.noteMeta(null), { nonascii: 0 })
  assert.deepEqual(module.noteMeta('plain note'), { nonascii: 0 })
  assert.ok(!module.cardWarnings({}, '', '', 'café', module.noteMeta('café')).some(w => /authority-display scan/.test(w)))
  let malformed, oversized
  assert.doesNotThrow(() => { malformed = module.noteMeta('x\ud800y'); oversized = module.noteMeta('é'.repeat(8193)) })
  assert.equal(malformed.authority_display, null, 'malformed commentary keeps existing sanitation without a misleading UTF-8 hash')
  assert.equal(module.cleanNote('x\ud800y'), 'x y')
  assert.equal(oversized.authority_display, null, 'oversized commentary does not invoke the bounded scanner')
}

for (const [category, points] of Object.entries(hidden)) test(`${category} display vectors refuse`, () => {
  for (const point of points) refused(scanner, `x${cp(point)}y`, category)
})
test('confusable authority occurrences cannot be suppressed by ASCII elsewhere or astral offsets', () => mixed(scanner))
test('Cyrillic, Greek, IPA, Cherokee, fullwidth and mathematical authority words refuse', () => {
  for (const text of [cp(0x0430) + 'pply', cp(0x03b1) + 'dmin', cp(0x0251) + 'pply', 'adm' + cp(0x0131) + 'n',
    cp(0x13aa) + 'pply', 'ａｐｐｌｙ', 'ＡＰＰＬＹ', cp(0x1d5ee) + 'dmin', cp(0x1d400) + 'pply'])
    refused(scanner, text, 'confusable_authority')
})
test('ordinary multilingual display and ASCII authority words stay usable', () => accepts(scanner))
test('receipt hashes bind original bytes separately from the analysis form; no sanitized output', () => hashes(scanner))
test('receipts contain only hashes and fixed metadata, never payload or authority', () => privateReceipt(scanner))
test('invalid, malformed and oversized input refuses with fixed codes', () => {
  for (const value of [undefined, null, 1, {}, Buffer.from('apply')])
    assert.throws(() => scanner.scanAuthorityDisplay(value), { code: 'authority-display:text-required' })
  for (const value of ['\ud800', '\udc00', 'x\ud800y'])
    assert.throws(() => scanner.scanAuthorityDisplay(value), { code: 'authority-display:invalid-unicode' })
  for (const value of ['a'.repeat(16385), 'é'.repeat(8193)])
    assert.throws(() => scanner.scanAuthorityDisplay(value), { code: 'authority-display:too-large' })
  assert.equal(scanner.scanAuthorityDisplay('é'.repeat(8192)).ok, true)
  assert.equal(scanner.scanAuthorityDisplay(`x${cp(0x200b)}`, { authorityBound: false }).ok, false)
})
test('raw model notes carry a scanner receipt and warning before existing sanitization', () => noteReceipt(card))
test('gate carries the advisory receipt while approval still binds and writes original operation bytes', t => {
  const { gate, store, home } = makeGate()
  t.after(() => { gate.close(); rmSync(home, { recursive: true, force: true }) })
  const content = accent('#1E90FF'), why = `apply ${cp(0x0430)}pply`
  const proposal = gate.proposeOps.propose({ target: ACCENT, content, why, claimed_base: hash(accent('#FFD700')) })
  assert.equal(proposal.note_meta.authority_display.raw_sha256, hash(why))
  assert.equal(proposal.note_meta.authority_display.action, 'refuse')
  assert.ok(proposal.popup.flags.some(w => /authority-display scan/.test(w)))
  assert.equal(store.writes, 0)
  assert.equal(gate.ownerOps.review({ id: proposal.id }).new_sha, hash(content))
  const result = approveViaReview(gate, proposal.id)
  assert.equal(result.applied, true)
  assert.equal(result.receipt.new_sha, hash(content))
  assert.deepEqual(store.files.get(ACCENT), Buffer.from(content))
  assert.equal(gate.verify().ok, true)
})

if (process.argv.includes('--mutations')) test('removed protections fail the same focused assertions', async t => {
  const controls = [
    ['input type', "if (typeof text !== 'string')", 'if (false)', m => assert.throws(() => m.scanAuthorityDisplay(null), { code: 'authority-display:text-required' })],
    ['byte bound', "Buffer.byteLength(text, 'utf8') > DISPLAY_MAX_BYTES", 'false', m => assert.throws(() => m.scanAuthorityDisplay('é'.repeat(8193)), { code: 'authority-display:too-large' })],
    ['well formed UTF-8', '!text.isWellFormed()', 'false', m => assert.throws(() => m.scanAuthorityDisplay('\ud800'), { code: 'authority-display:invalid-unicode' })],
    ...Object.keys(hidden).map(category => [`${category} refusal`, 'if (category) categories.add(category)', `if (category && category !== '${category}') categories.add(category)`,
      m => refused(m, `x${cp(hidden[category][0])}y`, category)]),
    ['default ignorables', '\\p{Default_Ignorable_Code_Point}', '', m => refused(m, `x${cp(0xfe00)}y`, 'format_char')],
    ['mapped confusables', 'if (LOOKALIKES.has(character))', 'if (false)', m => refused(m, cp(0x0430) + 'pply', 'confusable_authority')],
    ['fullwidth uppercase', 'point >= 0xff21 && point <= 0xff3a', 'false', m => refused(m, 'ＡＰＰＬＹ', 'confusable_authority')],
    ['fullwidth lowercase', 'point >= 0xff41 && point <= 0xff5a', 'false', m => refused(m, 'ａｐｐｌｙ', 'confusable_authority')],
    ['mathematical letters', 'point >= start && point < start + 26', 'false', m => refused(m, cp(0x1d5ee) + 'dmin', 'confusable_authority')],
    ['ASCII suppression bypass', 'changed.slice(at, at + word.length).some(Boolean)', 'changed.slice(at, at + word.length).some(Boolean) && !text.toLowerCase().includes(word)', mixed],
    ['later occurrences', 'skeleton.indexOf(word, at + 1)', 'skeleton.indexOf(word, skeleton.length)', mixed],
    ['astral alignment', 'i < piece.length', 'i < 1', mixed],
    ['confusable refusal', "if (occurrences) categories.add('confusable_authority')", '', mixed],
    ['ASCII false refusal', 'changed.slice(at, at + word.length).some(Boolean)', 'true', accepts],
    ['original hash binding', 'raw_sha256: hash(text)', 'raw_sha256: hash(canonical)', hashes],
    ['analysis hash binding', 'canonical_sha256: hash(canonical)', 'canonical_sha256: hash(text)', hashes],
    ['NFC analysis', "text.normalize('NFC')", 'text', hashes],
    ['raw payload leak', "schema: 'aukora-authority-display/v1'", "text, schema: 'aukora-authority-display/v1'", privateReceipt],
    ['non-authority receipt', 'grants_authority: false', 'grants_authority: true', privateReceipt],
    ['refusal result', 'const ok = categories.size === 0', 'const ok = true', mixed],
  ]
  for (const [name, before, after, check] of controls) await t.test(name, async () => {
    assert.equal(source.split(before).length, 2, 'unique mutation anchor')
    const module = await load(source.replace(before, after))
    assert.throws(() => check(module), { code: 'ERR_ASSERTION' }, 'guard removal must fail its assertion')
  })
  const cardControls = [
    ['raw note scan', 'scanAuthorityDisplay(raw).receipt', "scanAuthorityDisplay('clean').receipt"],
    ['card warning', "meta?.authority_display?.action === 'refuse'", 'false'],
    ['malformed commentary compatibility', 'raw.isWellFormed() &&', 'true &&'],
    ['oversized commentary compatibility', 'b.length <= DISPLAY_MAX_BYTES', 'true'],
  ]
  for (const [name, before, after] of cardControls) await t.test(name, async () => {
    assert.equal(cardSource.split(before).length, 2)
    const module = await load(cardSource.replace(before, after).replace("'./authority-display.mjs'", JSON.stringify(sourceUrl.href)))
    assert.throws(() => noteReceipt(module), { code: 'ERR_ASSERTION' })
  })
  console.log(`authority-display: ${controls.length + cardControls.length} guard-removal mutants killed`)
})
