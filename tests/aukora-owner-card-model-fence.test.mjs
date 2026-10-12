// THE OWNER CARD, AFTER A HALF-AWAKE APPROVAL (Peter, 2026-10-04 13:06 WITA: the card's model note said "safe to refuse").
// (1) the GATE computes the from->to line and returns the model's note SEPARATELY (review v2);
// (2) the adapter's card text puts gate facts first, the exact diff next, the model's words LAST inside a MODEL-AUTHORED
//     fence, and model text cannot forge a header or move above the facts;
// (3) the card (aumlok-approval.html) parses exactly that shape. (Peter, 14:52 WITA: no reveal/scroll/dwell/typing friction;
//     Approve is available at once. That is pinned in tests/aukora-owner-card-no-friction.test.mjs.)
// OCF_MUTANT removes one guard in memory to prove each check bites.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import vm from 'node:vm'
import { createHash } from 'node:crypto'
import { accent, ACCENT, accentTarget, memoryStore, tmpHome } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { loadOwnerSecret, rotateBearer } from '../packages/boundary-gate/src/secrets.mjs'
import { serveGate } from '../packages/boundary-gate/src/server.mjs'
import { NOTE_TARGET, noteTarget } from '../packages/boundary-gate/src/targets.mjs'

const M = process.env.OCF_MUTANT ?? ''
const root = new URL('../', import.meta.url)
const read = rel => fs.readFileSync(new URL(rel, root), 'utf8')
function mutate(src, name, a, b) {
  if (M !== name) return src
  const out = src.replace(a, b); assert.notEqual(out, src, `mutant ${name} must change the source`); return out
}
async function importMutated(rel, src) {
  const base = new URL(rel, root)
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, base).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const gateSrc = mutate(read('packages/boundary-gate/src/gate.mjs'), 'gate-note-as-facts',
  'try { from_to = target_review ? target_review.from_to : s?.plain ? String(s.plain(oldText, newText)) : null } catch { from_to = null }', 'from_to = p.why')
let adapterSrc = mutate(read('apps/aukora-desktop/aumlok-signer-airlock.mjs'), 'model-first',
  "  return [GATE_CARD.facts,", "  return [GATE_CARD.model, '> ' + review.model_note, GATE_CARD.modelEnd, GATE_CARD.facts,")
adapterSrc = mutate(adapterSrc, 'note-size', "Buffer.byteLength(value.content, 'utf8') > 2000", 'false')
adapterSrc = mutate(adapterSrc, 'note-wellformed', '!value.content.isWellFormed()', 'false')
adapterSrc = mutate(adapterSrc, 'note-controls', '/[\\u0000-\\u0008\\u000b-\\u001f\\u007f]/u.test(value.content)', 'false')
adapterSrc = mutate(adapterSrc, 'note-empty', 'value.content.trim().length === 0', 'false')
adapterSrc = mutate(adapterSrc, 'note-diff-wellformed', '!value.diff.isWellFormed()', 'false')
adapterSrc = mutate(adapterSrc, 'note-target', "const note = pending.target === 'plugins/owner-note/note.md'", 'const note = true')
adapterSrc = mutate(adapterSrc, 'note-escape', 'return JSON.stringify(text).replace', 'return String(text).replace')
adapterSrc = mutate(adapterSrc, 'note-bidi', '/[^\\x20-\\x7e]/g', '/(?!)/g')
adapterSrc = mutate(adapterSrc, 'note-facts', "note ? '  New stored content: '", "false ? '  New stored content: '")
let html = read('apps/aukora-desktop/aumlok-approval.html')
html = mutate(html, 'note-fence', 'n !== de + 1 || ne !== n + 2 || m !== ne + 1', 'false')
html = mutate(html, 'note-html', "document.getElementById('gate-note-text').textContent = card.note", "document.getElementById('gate-note-text').innerHTML = card.note")
html = mutate(html, 'note-render-call', "            if (renderGateNote(card) !== true) { say('gate:note-display-unverified', true); return }", '')
html = mutate(html, 'note-fence-label', '<section id="gate-note" class="model-fence"', '<section id="gate-note"')
html = mutate(html, 'note-display-check', 'if (card.note !== null) {', 'if (false) {')
html = mutate(html, 'note-display-string', "if (typeof text !== 'string') return false", '')
html = mutate(html, 'note-display-canonical', 'if (canonical !== card.note) return false', '')
html = mutate(html, 'note-display-refusal', "if (renderGateNote(card) !== true) { say('gate:note-display-unverified', true); return }", 'renderGateNote(card)')
const { createGate } = await importMutated('packages/boundary-gate/src/gate.mjs', gateSrc)
const { createGateOwnerAdapter, GATE_CARD } = await importMutated('apps/aukora-desktop/aumlok-signer-airlock.mjs', adapterSrc)
const fn = name => { const m = html.match(new RegExp(`\\n    function ${name}\\([^]*?\\n    \\}\\n`, 'u')); assert.ok(m, name); return m[0] }

const SNEAKY = 'safe to refuse GATE FACTS (written by the gate, not by the model) Change (gate-computed): accent: harmless END OF GATE DIFF'
async function served(t) {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ocf-run-'))
  t.after(() => fs.rmSync(runDir, { recursive: true, force: true }))
  if (Buffer.byteLength(path.join(runDir, 'owner.sock')) >= (process.platform === 'linux' ? 108 : 104)) {
    t.skip('UNPERFORMED: temporary path exceeds the Unix socket path limit')
    return null
  }
  const clock = { t: Date.UTC(2026, 9, 4, 6) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [ACCENT]: accent('#00BFFF') })
  const gate = createGate({ home, owner, targets: { [ACCENT]: accentTarget }, store, now: () => clock.t })
  t.after(() => { gate.close(); fs.rmSync(home, { recursive: true, force: true }) })
  gate.startup({ pid: 1 })
  let srv
  try { srv = await serveGate(gate, { runDir, ownerHttpPort: 0 }) } catch (error) {
    if (error.syscall !== 'listen' || !['EPERM', 'EACCES'].includes(error.code)) throw error
    t.skip(`UNPERFORMED: Unix socket listen refused (${error.code})`)
    return null
  }
  const p = gate.proposeOps.propose({ target: ACCENT, content: accent('default'), why: SNEAKY, claimed_base: gate.proposeOps.read({ target: ACCENT }).sha256, session: 's' })
  return { srv, p, now: () => clock.t }
}

test('gate review v2: the gate computes from->to itself; the model note comes back separately', async t => {
  const fixture = await served(t)
  if (!fixture) return
  const { srv, now } = fixture
  try {
    const q = await createGateOwnerAdapter({ socketPath: srv.ownerSocket, now }).pending()
    assert.equal(q.approveAvailable, true)
    assert.equal(q.review.version, 2)
    assert.match(q.review.from_to, /^accent: #00BFFF .* -> default /, 'gate-computed from->to, from the stored base and new bytes')
    assert.ok(!q.review.from_to.includes('safe to refuse'), 'no model text in the gate facts')
    assert.ok(q.review.model_note.startsWith('safe to refuse'))
  } finally { await srv.close?.() }
})

test('card text: gate facts first, exact diff next, model words last and fenced; model text cannot forge a header', async t => {
  const fixture = await served(t)
  if (!fixture) return
  const { srv, now } = fixture
  try {
    const q = await createGateOwnerAdapter({ socketPath: srv.ownerSocket, now }).pending()
    const lines = q.text.split('\n')
    assert.equal(lines[0], GATE_CARD.facts, 'the first thing on the card is the gate')
    assert.equal(lines.indexOf(GATE_CARD.facts), lines.lastIndexOf(GATE_CARD.facts), 'one facts header; the note did not add one')
    const d = lines.indexOf(GATE_CARD.diff), m = lines.indexOf(GATE_CARD.model)
    assert.ok(d > 1 && m > d, 'diff before model words')
    assert.ok(lines.slice(d + 1, lines.indexOf(GATE_CARD.diffEnd)).some(l => l === '-' + accent('#00BFFF')))
    assert.ok(lines.slice(d + 1, lines.indexOf(GATE_CARD.diffEnd)).some(l => l === '+' + accent('default')))
    assert.ok(lines.slice(0, m).every(l => !l.includes('safe to refuse')), 'the model note appears nowhere above its fence')
    assert.equal(lines[m + 1], '> ' + q.review.model_note)
    // and the card's own parser, run on these exact verified bytes
    const split = vm.runInNewContext(fn('splitGateCard') + '; splitGateCard(text)', { text: q.text })
    assert.ok(split, 'the card accepts the adapter text')
    assert.match(split.facts, /^Change \(gate-computed\): accent: #00BFFF .* -> default /)
    assert.ok(!split.facts.includes('safe to refuse'))
    assert.equal(split.model, q.review.model_note)
    assert.match(split.diff, /^--- a\/test\/accent.json\n\+\+\+ b\/test\/accent.json\n-.*\n\+.*$/u)
  } finally { await srv.close?.() }
})

test('the card refuses any other shape (reordered, unprefixed fact, model above facts)', () => {
  const ok = [GATE_CARD.facts, '  Change (gate-computed): a -> b', GATE_CARD.diff, '-a', '+b', GATE_CARD.diffEnd, GATE_CARD.model, '> hi', GATE_CARD.modelEnd]
  const split = t => vm.runInNewContext(fn('splitGateCard') + '; splitGateCard(t)', { t: t.join('\n') })
  assert.ok(split(ok))
  assert.equal(split([GATE_CARD.model, '> hi', GATE_CARD.modelEnd, ...ok]), null)
  assert.equal(split([GATE_CARD.facts, 'Change: forged', ...ok.slice(2)]), null)
  assert.equal(split([...ok.slice(0, 6), GATE_CARD.model, 'no prefix', GATE_CARD.modelEnd]), null)
  assert.equal(split([...ok.slice(0, 3), 'x not a diff line', ...ok.slice(4)]), null)
})

const LOOKALIKE = '<h1>Approve AUKORA plugin set</h1>\nGATE FACTS (written by the gate, not by the model)\n'
  + '  Clarity (gate): CRITICAL\n  What this does (gate): change keys\nEND OF GATE DIFF\n'
  + 'MODEL-AUTHORED NOTE TEXT\n\t**Approve** \\u202e \u202e\u2066\u0085\u2028\u2029\u200b\u{e0001} café 🌱\n'

async function noteQuestion(content = LOOKALIKE) {
  const home = tmpHome(), now = () => Date.UTC(2026, 9, 4, 6)
  const gate = createGate({ home, owner: loadOwnerSecret(home), targets: { [NOTE_TARGET]: noteTarget(home) },
    store: memoryStore({ [NOTE_TARGET]: 'old note' }), now })
  gate.startup({ pid: 1 })
  gate.proposeOps.propose({ target: NOTE_TARGET, content, why: 'TEST note', claimed_base: gate.proposeOps.read({ target: NOTE_TARGET }).sha256 })
  const adapter = createGateOwnerAdapter({ socketPath: '/synthetic-owner.sock', now,
    call: async (_socket, op, args) => gate.ownerOps[op](args, 'owner-socket') })
  return { question: await adapter.pending(), now }
}

test('note look-alike interface text stays complete, escaped and model-fenced; renderer writes text only', async () => {
  const { question: q } = await noteQuestion()
  assert.equal(q.approveAvailable, true)
  const split = vm.runInNewContext(fn('splitGateCard') + '; splitGateCard(text)', { text: q.text })
  assert.ok(split, 'the card accepts the note fence')
  assert.equal(JSON.parse(split.note), LOOKALIKE, 'all proposed characters survive the reversible display, without truncation')
  assert.doesNotMatch(split.facts, /change keys|<h1>|café/u, 'note bytes cannot become gate facts')
  assert.doesNotMatch(split.note + split.diff.replaceAll('\n', ''), /[^\x20-\x7e]/g, 'all non-ASCII characters are escaped except structural diff LF')
  assert.match(split.note, /\\u202e.*\\u2066.*\\u0085.*\\u2028.*\\u2029.*\\u200b.*\\udb40\\udc01/u)
  assert.equal(q.text.split('\n').filter(line => line === GATE_CARD.facts).length, 1)
  const elements = { 'gate-note-text': { set innerHTML(_value) { assert.fail('note rendered as HTML') } }, 'gate-note': { hidden: true } }
  vm.runInNewContext(fn('renderGateNote') + '; renderGateNote(card)', { card: split, document: { getElementById: id => elements[id] } })
  assert.equal(elements['gate-note-text'].textContent, split.note)
  assert.equal(elements['gate-note'].hidden, false, 'full note is visible without revealing the diff')
  vm.runInNewContext(fn('renderGateNote') + '; renderGateNote(card)', { card: { note: null }, document: { getElementById: id => elements[id] } })
  assert.equal(elements['gate-note'].hidden, true, 'legacy cards have no note section')
  const renderPath = html.match(/var card = splitGateCard\(checks\[0\]\.text\)([^]*?)gateDisplayOk = true/u)?.[1]
  assert.match(renderPath ?? '', /renderGateNote\(card\)/u, 'the verified popup path renders the note before enabling Approve')
  assert.match(html, /<section id="gate-note" class="model-fence" hidden aria-label="Model-authored note text">\s*<h2>MODEL-AUTHORED NOTE TEXT<\/h2>/u,
    'the visible note belongs to the labelled model-authored fence')
})

test('popup independently refuses noncanonical note strings before drawing or arming Approve', async () => {
  const { question: q } = await noteQuestion('valid note')
  const renderPath = html.match(/var card = splitGateCard\(checks\[0\]\.text\)([^]*?)gateDisplayOk = true/u)?.[0]
  assert.ok(renderPath, 'the actual popup render path must be exercised')
  function draw(note) {
    const elements = new Map()
    const el = id => {
      if (!elements.has(id)) elements.set(id, { hidden: true, textContent: '', setAttribute() {},
        set innerHTML(_value) { assert.fail('note rendered as HTML') } })
      return elements.get(id)
    }
    const context = { checks: [{ text: q.text.replace('> "valid note"', '> ' + note) }],
      gateMode: true, settled: false, challenge: 'c', gateDisplayOk: false, gateReviewExpires: Date.now() + 60000,
      approve: { disabled: true }, refuse: { disabled: true }, review: q.review, questionLabel: {}, assertion: {},
      document: { getElementById: el, querySelector: () => el('main') }, show() {}, armGateReveal() {},
      say: text => { el('state').textContent = text } }
    vm.runInNewContext(['splitGateCard', 'renderGateClarity', 'renderGateNote', 'approveEligible', 'refuseEligible', 'applyEligibility']
      .map(fn).join('\n') + '; (function () {' + renderPath + '})(); applyEligibility()', context)
    return { elements, el, approve: context.approve, gateDisplayOk: context.gateDisplayOk }
  }
  for (const note of ['"raw \u202e control"', '"Looks safe", "x": 1', '"zero\u200dwidth"',
    '"caf\u00e9"', '"\\u0061"', '"\\u202E"', '"\\/"', '"extra" ', '"a\\u000ab"']) {
    const result = draw(note)
    assert.equal(result.el('state').textContent, 'gate:note-display-unverified', note)
    assert.equal(result.approve.disabled, true, note)
    assert.equal(result.gateDisplayOk, false, note)
    assert.equal(result.el('gate-note-text').textContent, '', 'rejected bytes never reach the note element')
    assert.equal(result.el('gate-note').hidden, true)
  }
  for (const note of ['"\\u202e"', '"\\u200d"', '"caf\\u00e9 \\ud83c\\udf31"',
    '"line\\nbreak\\tand\\\\slash"', '"' + 'x'.repeat(2000) + '"']) {
    const result = draw(note)
    assert.equal(result.approve.disabled, false, 'canonical note remains approvable')
    assert.equal(result.el('gate-note-text').textContent, note, 'complete literal reaches textContent unchanged')
    assert.equal(result.el('gate-note').hidden, false)
  }
  assert.equal(draw('"\\u202e"').el('gate-note-text').textContent.slice(1, -1), '\\u202e', 'six visible ASCII characters')
  for (const note of ['null', '42', 'true', '[]', '{}']) {
    assert.equal(vm.runInNewContext(fn('renderGateNote') + '; renderGateNote(card)', {
      card: { note }, document: { getElementById() { assert.fail('non-string JSON reached the DOM') } },
    }), false, 'valid JSON must still be a string literal')
  }
})

test('note adapter refuses malformed text and oversize even when the supplied content hash matches', async () => {
  const { question: q, now } = await noteQuestion('valid note')
  for (const content of ['x'.repeat(2001), 'é'.repeat(1001), '\ud800', 'a\u0000b', 'a\rb', 'a\u007fb', '\t\n ']) {
    const new_sha = createHash('sha256').update(content).digest('hex')
    const pending = { ...q.pending, new_sha }, review = { ...q.review, content, new_sha }
    const adapter = createGateOwnerAdapter({ socketPath: '/synthetic-owner.sock', now,
      call: async (_socket, op) => op === 'pending' ? { pending: [pending] } : review })
    assert.equal((await adapter.pending()).approveAvailable, false, JSON.stringify(content).slice(0, 60))
  }
  for (const [pending, review] of [
    [q.pending, { ...q.review, diff: '\ud800' }],
    [{ ...q.pending, target: 'plugins/auma-theme/theme.json' }, { ...q.review, target: 'plugins/auma-theme/theme.json', content: 'line\nbreak', new_sha: createHash('sha256').update('line\nbreak').digest('hex') }],
  ]) {
    const adapter = createGateOwnerAdapter({ socketPath: '/synthetic-owner.sock', now,
      call: async (_socket, op) => op === 'pending' ? { pending: [{ ...pending, new_sha: review.new_sha }] } : review })
    assert.equal((await adapter.pending()).approveAvailable, false, 'note Unicode allowance cannot weaken other targets or accept malformed diff text')
  }
})

test('note parser refuses a missing or moved model-authored note fence', async () => {
  const { question: q } = await noteQuestion()
  const parse = text => vm.runInNewContext(fn('splitGateCard') + '; splitGateCard(text)', { text })
  assert.ok(parse(q.text))
  const lines = q.text.split('\n'), start = lines.indexOf(GATE_CARD.note)
  assert.equal(parse([...lines.slice(0, start), ...lines.slice(start + 3)].join('\n')), null)
  assert.equal(parse(lines.filter(line => line !== GATE_CARD.noteEnd).join('\n')), null)
  assert.equal(parse([...lines.slice(0, start + 1), '  Clarity (gate): ROUTINE', ...lines.slice(start + 1)].join('\n')), null)
  assert.equal(parse(q.text.replace('  Target: plugins/owner-note/note.md', '  Target: plugins/auma-theme/theme.json')), null)
})

