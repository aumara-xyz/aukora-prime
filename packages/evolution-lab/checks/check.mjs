import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { resolve, join } from 'node:path'
import { parseManifest, EMPTY_MANIFEST_JSON, MANIFEST_MAX_BYTES, ManifestError } from '../src/manifest.mjs'
import { createEvolutionController } from '../src/controller.mjs'
import { createEvolutionComponents, receiptHref } from '../src/view.mjs'

let assertions = 0, refusals = 0
const check = (value) => { assertions++; assert.ok(value) }
const fixture = JSON.parse(await readFile(new URL('../fixtures/synthetic.json', import.meta.url), 'utf8'))
const historicalText = await readFile(new URL('../fixtures/historical-memory.json', import.meta.url), 'utf8')
const copy = () => structuredClone(fixture)
function refused(jsonText) {
  assertions++; refusals++
  assert.throws(() => parseManifest(jsonText), error => error instanceof ManifestError &&
    /^Evolution Lab /.test(error.message) && !error.message.includes('sensitive-value'))
}
function mutation(edit) { const value = copy(); edit(value); refused(JSON.stringify(value)) }

const empty = parseManifest(EMPTY_MANIFEST_JSON)
check(empty.availability === 'unavailable' && empty.entries.length === 0)
const synthetic = parseManifest(JSON.stringify(fixture))
check(synthetic.entries[0].costUsd === 0 && synthetic.entries[0].wallTimeSeconds === null)
check(Object.isFrozen(synthetic) && Object.isFrozen(synthetic.entries[0].artifacts[0]))
const historical = parseManifest(historicalText)
check(historical.entries.length === 1 && historical.entries[0].kind === 'experiment')
check(historical.entries[0].evidenceClass === 'historical-reported' && historical.entries[0].execution === 'RECORDED')
check(historical.entries[0].command === null && historical.entries[0].costUsd === null && historical.entries[0].wallTimeSeconds === null)
const approvedSummary = await readFile(new URL('../../../docs/evidence/bounded-memory-experiment.json', import.meta.url))
check(createHash('sha256').update(approvedSummary).digest('hex') === historical.entries[0].artifacts[0].sha256)
check(historical.entries[0].artifacts[0].receipt === null)
const syntheticReceipt = { path: 'docs/evidence/synthetic-fixture.json', revision: 'a'.repeat(40) }
check(receiptHref(syntheticReceipt) === `https://github.com/aumara-xyz/aukora-prime/blob/${'a'.repeat(40)}/docs/evidence/synthetic-fixture.json`)

mutation(v => { v.schemaVersion = 2 })
mutation(v => { v.extra = 'sensitive-value' })
mutation(v => { delete v.entries[0].evidenceClass })
mutation(v => { v.entries[0].extra = 'sensitive-value' })
mutation(v => { v.entries[0].artifacts[0].extra = 'sensitive-value' })
mutation(v => { v.entries[0].modelProvenance.extra = 'sensitive-value' })
mutation(v => { v.entries[1].prediction.extra = 'sensitive-value' })
mutation(v => { v.entries[1].outcome.extra = 'sensitive-value' })
mutation(v => { v.entries[0].costUsd = -1 })
mutation(v => { v.entries[0].costUsd = 1e10 })
refused(JSON.stringify(fixture).replace('"costUsd":0', '"costUsd":1e999'))
refused(JSON.stringify(fixture).replace('"costUsd":0', '"costUsd":-0'))
mutation(v => { v.entries[0].command = 'x'.repeat(257) })
mutation(v => { v.entries[0].failures = Array(17).fill('x') })
mutation(v => { v.entries = Array(33).fill(v.entries[0]) })
mutation(v => { v.entries[1].id = v.entries[0].id })
mutation(v => { v.entries[1].parentIds = ['missing-parent'] })
mutation(v => { v.entries[0].parentIds = ['fixture-child'] })
mutation(v => { v.entries[1].parentIds = ['fixture-parent', 'fixture-parent'] })
mutation(v => { v.entries[1].artifacts[0].id = 'fixture-artifact' })
mutation(v => { v.entries[1].artifacts[0].parentIds = ['missing-artifact'] })
mutation(v => { v.entries[0].artifacts[0].parentIds = ['fixture-child-artifact'] })
mutation(v => { v.entries[0].sourcePin = 'not-a-source-pin' })
mutation(v => { v.entries[0].artifacts[0].sha256 = 'not-a-hash' })
mutation(v => { v.entries[1].prediction.preregisteredAt = '2026-02-30T12:00:00Z' })
mutation(v => { v.entries[1].prediction.preregisteredAt = '2026-10-01T12:00:00+01:00' })
mutation(v => { v.availability = 'empty' })
mutation(v => { v.availability = 'unavailable' })
mutation(v => { v.entries = [] })
mutation(v => { v.entries[0].evidenceClass = 'measured' })
mutation(v => { v.entries[0].artifacts[0].evidenceClass = 'measured' })
mutation(v => { v.entries[1].outcome.evidenceClass = 'measured' })
mutation(v => { v.entries[0].modelProvenance.evidenceClass = 'measured' })
mutation(v => { v.entries[1].prediction.evidenceClass = 'measured' })
mutation(v => { v.mode = 'sanitized-reference'; v.entries[0].evidenceClass = 'measured' })
mutation(v => { v.mode = 'sanitized-reference'; v.entries[0].evidenceClass = 'historical-reported' })
mutation(v => { v.mode = 'sanitized-reference'; v.entries[0].evidenceClass = 'unperformed'; v.entries[0].execution = 'UNPERFORMED' })
for (const path of ['docs/evidence/../private.json', '/docs/evidence/x.json', 'https://example.invalid/x.json',
  'docs/evidence/x.json?secret', 'research/evidence/%2e%2e/x.json', 'docs/evidence/x.html', 'docs/evidence/x.json#fragment']) {
  mutation(v => { v.entries[0].artifacts[0].receipt = { path, revision: 'a'.repeat(40) } })
}
mutation(v => { v.entries[0].artifacts[0].receipt = { path: 'docs/evidence/x.json', revision: null } })
for (const sensitive of [['', 'Users', 'example', 'private'].join('/'), ['', 'home', 'example', 'private'].join('/'),
  [127, 0, 0, 1].join('.'), ['2001', 'db8', '', '1'].join(':'),
  'api_key=sensitive-value', 'Bearer sensitive-value', 'https://name:sensitive-value@example.invalid', 'text\u202einvisible', 'text\nnewline']) {
  mutation(v => { v.entries[0].command = sensitive })
}
refused(JSON.stringify(fixture).replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'))
refused(JSON.stringify(fixture).replace('"schemaVersion":1', '"schemaVersion":1,"schema\\u0056ersion":1'))
refused(' '.repeat(MANIFEST_MAX_BYTES + 1))
refused('['.repeat(20) + '0' + ']'.repeat(20))
refused('{')
let getterRead = false
refused({ get schemaVersion() { getterRead = true; return 1 } })
check(!getterRead)
const unperformed = copy()
unperformed.mode = 'sanitized-reference'
unperformed.entries[0].evidenceClass = 'unperformed'
unperformed.entries[0].execution = 'UNPERFORMED'
unperformed.entries[0].costUsd = null
check(parseManifest(JSON.stringify(unperformed)).entries[0].costUsd === null)
mutation(v => {
  v.entries[1].prediction.preregisteredAt = '2026-10-01T13:00:00Z'
  v.entries[1].outcome.observedAt = '2026-10-01T12:00:00Z'
})
mutation(v => {
  v.entries[1].prediction.preregisteredAt = '2026-10-01T12:00:00Z'
  v.entries[1].outcome.observedAt = '2026-10-01T12:00:00Z'
})
const prior = copy()
prior.entries[1].prediction.preregisteredAt = '2026-10-01T12:00:00Z'
prior.entries[1].outcome.observedAt = '2026-10-01T13:00:00Z'
check(parseManifest(JSON.stringify(prior)).entries[1].prediction.preregisteredAt !== null)

const controller = createEvolutionController()
let notifications = 0
const unsubscribe = controller.subscribe(() => { notifications++ })
check(controller.updateManifest(JSON.stringify(fixture)) && controller.getSnapshot().manifest.entries.length === 2)
check(!controller.updateManifest('sensitive-value') && controller.getSnapshot().manifest.entries.length === 0)
check(controller.getSnapshot().status === 'refused' && !controller.getSnapshot().error.includes('sensitive-value'))
unsubscribe(); controller.updateManifest(JSON.stringify(fixture)); check(notifications === 2)
const disposedState = controller.getSnapshot()
controller.dispose(); check(!controller.updateManifest(EMPTY_MANIFEST_JSON) && controller.getSnapshot() === disposedState)

const flags = process.argv.slice(2)
let reactRendering = 'UNPERFORMED: optional pinned React runtime was not supplied'
if (flags.length) {
  assert.equal(flags.length, 4, 'usage: check.mjs [--react-runtime <dir> --react-dom-runtime <dir>]')
  assert.equal(flags[0], '--react-runtime'); assert.equal(flags[2], '--react-dom-runtime')
  const require = createRequire(import.meta.url)
  const React = require(resolve(flags[1]))
  const { renderToStaticMarkup } = require(join(resolve(flags[3]), 'server.node.js'))
  check(React.version === '18.3.1')
  const h = React.createElement
  // These inert wrappers exercise text escaping and semantics, not Layout pixels.
  const Card = ({ children, ...props }) => h('div', props, children)
  const SectionHeader = ({ children, ...props }) => h('header', props, children)
  const ActionButton = ({ children, variant, ...props }) => h('button', props, children)
  const PortalButton = ({ title, subtitle, containerProps, children }) => h('div', containerProps,
    h('button', null, title, subtitle), children)
  const { EvolutionSurface, EvolutionMenu } = createEvolutionComponents(React, { Card, SectionHeader, ActionButton, PortalButton })
  const displayController = createEvolutionController(JSON.stringify(fixture))
  const html = renderToStaticMarkup(h(EvolutionSurface, { activeSurface: 'evolution-lab', controller: displayController }))
  check(html.includes('SYNTHETIC FIXTURE') && html.includes('Preregistration unestablished'))
  check(html.includes('No failure report supplied') && html.includes('Unavailable / unmeasured'))
  check(html.includes('Cost (USD)') && html.includes('<dd>0</dd>'))
  const attack = copy()
  attack.entries[0].artifacts[0].receipt = syntheticReceipt
  attack.entries[0].title = '<img src=x onerror="globalThis.evidenceInstructionRan=true">'
  attack.entries[0].command = '$(echo evidence-instructions) <script>globalThis.evidenceInstructionRan=true</script>'
  attack.entries[1].outcome.summary = '</script><script>globalThis.evidenceInstructionRan=true</script>'
  globalThis.evidenceInstructionRan = false
  displayController.updateManifest(JSON.stringify(attack))
  const escaped = renderToStaticMarkup(h(EvolutionSurface, { activeSurface: 'evolution-lab', controller: displayController }))
  check(!escaped.includes('<script>') && !escaped.includes('<img src=x'))
  check(escaped.includes('&lt;script&gt;') && escaped.includes('&quot;globalThis.evidenceInstructionRan=true&quot;'))
  check(escaped.includes('$(echo evidence-instructions)') && !globalThis.evidenceInstructionRan)
  check(escaped.includes(`href="${receiptHref(syntheticReceipt)}"`))
  displayController.updateManifest(historicalText)
  const recorded = renderToStaticMarkup(h(EvolutionSurface, { activeSurface: 'evolution-lab', controller: displayController }))
  check(recorded.includes('historical-reported') && recorded.includes('RECORDED') && !recorded.includes('SYNTHETIC FIXTURE'))
  check(recorded.includes('No sanitized repository receipt supplied.') && !recorded.includes('href="https://github.com'))
  displayController.updateManifest('sensitive-value')
  const cleared = renderToStaticMarkup(h(EvolutionSurface, { activeSurface: 'evolution-lab', controller: displayController }))
  check(cleared.includes('Evidence manifest refused') && !cleared.includes('One historical synthetic save'))
  const emptyLedger = JSON.parse(EMPTY_MANIFEST_JSON)
  emptyLedger.availability = 'empty'; emptyLedger.reason = 'An intentionally empty supplied ledger.'
  displayController.updateManifest(JSON.stringify(emptyLedger))
  const emptyHtml = renderToStaticMarkup(h(EvolutionSurface, { activeSurface: 'evolution-lab', controller: displayController }))
  check(emptyHtml.includes('Empty evidence ledger') && !emptyHtml.includes('Evidence unavailable'))
  let navigation
  const menu = EvolutionMenu({ activeSurface: undefined, openSurface: (...args) => { navigation = args } })
  menu.props.onClick(); check(JSON.stringify(navigation) === '["evolution-lab",null,"contained"]')
  check(renderToStaticMarkup(h(EvolutionSurface, { activeSurface: 'other', controller: displayController })).includes('hidden=""'))
  reactRendering = 'RAN: React 18.3.1 server rendering with inert Layout wrappers; browser/Layout pixels UNPERFORMED'
}

const client = await readFile(new URL('../src/client/index.mjs', import.meta.url), 'utf8')
const view = await readFile(new URL('../src/view.mjs', import.meta.url), 'utf8')
check(!/fetch\s*\(|XMLHttpRequest|WebSocket|eval\s*\(|new Function|dangerouslySetInnerHTML|innerHTML/.test(client + view))
check(client.includes("id: 'evolution-lab'") && !client.includes('shell.overlay'))
console.log(JSON.stringify({ result: 'PASS', assertions, mutation_refusals: refusals,
  schema_and_controller: 'RAN', react_rendering: reactRendering,
  composed_build: 'UNPERFORMED', browser_and_hot_corner_geometry: 'UNPERFORMED',
  actual_models_or_current_runtime: 'UNPERFORMED', source_scope: 'packages/evolution-lab/**' }, null, 2))
