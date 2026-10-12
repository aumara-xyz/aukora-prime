// The packaged approval display uses the shared derivation and clears invalid or superseded pictures.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'
import { createHash, webcrypto } from 'node:crypto'
import { loadCore, readPortalHtml } from './load-core.mjs'

const desktop = new URL('../../../../apps/aukora-desktop/', import.meta.url)
let html = fs.readFileSync(new URL('aumlok-approval.html', desktop), 'utf8')
const manifest = JSON.parse(fs.readFileSync(new URL('package.json', desktop)))
const vectors = JSON.parse(fs.readFileSync(new URL('pentora-vectors.json', import.meta.url)))
const mutant = process.env.PENTORA_VIEW_MUTANT || ''
let source = fs.readFileSync(new URL('pentora-view.mjs', desktop), 'utf8')
const mutations = {
  shape: ["if (!/^[0-9a-fA-F]{64}$/.test(head))", 'if (false)'],
  stale: ["if (current !== revision || source.textContent !== head)", 'if (false)'],
  clear: ['target.replaceChildren()\n    target.hidden = true', ''],
  hash: ["return 'pentora:hash-unavailable'", 'digits = new Uint8Array(110)'],
  digits: ['digit = digits[i]', 'digit = 0'],
  palette: ['fill: colors[digit]', 'fill: colors[0]'],
  observer: ['new Observer(() => { void refresh() })', 'new Observer(() => {})'],
}
if (mutant === 'mount') {
  html = html.replace('watchPentora(document, MutationObserver)', '')
} else if (mutant === 'package') {
  manifest.build.files = manifest.build.files.filter(file => file !== 'pentora.mjs')
} else if (mutant) {
  assert.ok(mutations[mutant], 'known mutant')
  const [before, after] = mutations[mutant]
  assert.ok(source.includes(before), 'mutation applied')
  source = source.replace(before, after)
}
source = source.replace("'./pentora.mjs'", JSON.stringify(new URL('pentora.mjs', desktop).href))
const { watchPentora } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))

function fixture(hash) {
  const node = (name = '') => ({ name, textContent: '', children: [], attributes: {}, hidden: false,
    setAttribute(key, value) { this.attributes[key] = value },
    appendChild(child) { this.children.push(child) },
    replaceChildren(...children) { this.children = children },
  })
  const digest = node(), target = node()
  let observed, changed
  const document = { getElementById: id => ({ 'f-digest': digest, pentora: target })[id],
    createElementNS: (_ns, name) => node(name), createElement: name => node(name) }
  class Observer {
    constructor(callback) { changed = callback }
    observe(element, options) { observed = { element, options } }
  }
  const refresh = watchPentora(document, Observer, hash)
  return { digest, target, refresh, document, Observer, changed, observed }
}

test('packaged page starts the digest observer from its local module', () => {
  const code = html.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1]
  assert.ok(code, 'desktop module script')
  assert.match(code, /import \{ watchPentora \} from '\.\/pentora-view\.mjs'/)
  assert.match(html, /script-src 'self' 'unsafe-inline'/)
  assert.match(html, /id="pentora" hidden/)
  for (const file of ['aumlok-approval.html', 'pentora.mjs', 'pentora-view.mjs']) {
    assert.ok(manifest.build.files.includes(file), `desktop carries ${file}`)
  }
  const f = fixture()
  let mounted = 0
  vm.runInNewContext(code.replace(/import[^\n]+/, ''), {
    watchPentora(...args) { mounted++; return watchPentora(...args) },
    document: f.document, MutationObserver: f.Observer,
  })
  assert.equal(mounted, 1, 'page actually starts the display')
  assert.equal(f.observed.element, f.digest)
  assert.deepEqual(f.observed.options, { childList: true, characterData: true, subtree: true })
})

test('desktop caller renders all vector digits in the same cells as the frozen portal', async () => {
  const portal = loadCore(), f = fixture()
  const colors = JSON.parse(readPortalHtml().match(/const CELL = (\[\[[^;]+?\]\])/)[1])
    .map(rgb => `rgb(${rgb.join(',')})`)
  for (const vector of vectors) {
    f.digest.textContent = vector.head
    assert.equal(await f.refresh(), 'pentora:displayed')
    assert.equal(f.target.hidden, false)
    const [svg, label] = f.target.children
    const cells = svg.children.filter(n => n.attributes['data-cell'] !== undefined)
    assert.deepEqual(cells.map(n => Number(n.attributes['data-cell'])), portal.PENTORA.mutable)
    const displayed = cells.map(n => Number(n.attributes['data-digit']))
    assert.deepEqual(cells.map(n => n.attributes.fill), displayed.map(digit => colors[digit]))
    assert.deepEqual(displayed, [...await portal.pentoraDigits(Uint8Array.from(Buffer.from(vector.head, 'hex')))])
    assert.equal(Buffer.from(displayed).toString('hex'), vector.wire_hex)
    assert.match(label.textContent, /do not identify a person or approve an operation/)
    assert.equal(svg.children.filter(n => n.name === 'line').length, 60)
    assert.equal(svg.children.filter(n => n.name === 'circle').length, 111)
  }
})

test('observer renders a digest that arrives after the page module starts', async () => {
  const f = fixture(bytes => new Uint8Array(createHash('sha256').update(bytes).digest()))
  assert.equal(f.target.hidden, true)
  f.digest.textContent = vectors[0].head
  f.changed()
  await new Promise(setImmediate)
  assert.equal(f.target.hidden, false)
  const cells = f.target.children[0].children.filter(n => n.attributes['data-digit'] !== undefined)
  assert.equal(Buffer.from(cells.map(n => Number(n.attributes['data-digit']))).toString('hex'), vectors[0].wire_hex)
})

test('malformed digest and unavailable hash erase the previous picture', async () => {
  const f = fixture()
  for (const bad of ['', '0'.repeat(62), '0'.repeat(66), 'g'.repeat(64), ' ' + vectors[0].head, vectors[0].head + '\n']) {
    f.digest.textContent = vectors[0].head
    assert.equal(await f.refresh(), 'pentora:displayed')
    f.digest.textContent = bad
    assert.equal(await f.refresh(), 'pentora:head-invalid')
    assert.equal(f.target.hidden, true)
    assert.deepEqual(f.target.children, [])
  }
  for (const hash of [() => { throw new Error('unavailable') }, () => new Uint8Array(20)]) {
    const broken = fixture(hash)
    broken.digest.textContent = vectors[0].head
    assert.equal(await broken.refresh(), 'pentora:hash-unavailable')
    assert.equal(broken.target.hidden, true)
    assert.deepEqual(broken.target.children, [])
  }
})

test('a slow old hash cannot replace a newer picture or resurrect a cleared one', async () => {
  const pending = []
  const f = fixture(bytes => new Promise(resolve => pending.push(() => resolve(webcrypto.subtle.digest('SHA-256', bytes)))))
  f.digest.textContent = vectors[0].head
  const old = f.refresh()
  f.digest.textContent = vectors[1].head
  const next = f.refresh()
  pending[1]()
  assert.equal(await next, 'pentora:displayed')
  const picture = f.target.children[0]
  pending[0]()
  assert.equal(await old, 'pentora:stale')
  assert.equal(f.target.children[0], picture)
  const late = f.refresh()
  f.digest.textContent = '—'
  await f.refresh()
  pending[2]()
  assert.equal(await late, 'pentora:stale')
  assert.equal(f.target.hidden, true)
  assert.deepEqual(f.target.children, [])
})
