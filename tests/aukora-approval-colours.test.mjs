// Optional face colours cannot replace signer functions or bypass opacity checks.
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Script } from 'node:vm'
import { loadOrganLibrary } from '../apps/aukora-desktop/aumlok-bridge-state.mjs'
import { readFaceTokenValues, safeApprovalTokens, SAFE_APPROVAL_TOKENS } from '../apps/aukora-desktop/aumlok-approval-view.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const statePath = new URL('../apps/aukora-desktop/aumlok-bridge-state.mjs', import.meta.url)
const viewPath = new URL('../apps/aukora-desktop/aumlok-approval-view.mjs', import.meta.url)
const stateSource = readFileSync(statePath, 'utf8')
const viewSource = readFileSync(viewPath, 'utf8')
async function changedModule(source, base, before, after) {
  assert.ok(source.includes(before), 'mutation target exists')
  const changed = source.replace(before, after).replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, base).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`)
}

async function loaderCourt(load) {
  mkdirSync(join(root, '.runtime'), { recursive: true })
  const scratch = mkdtempSync(join(root, '.runtime/approval-colours-'))
  try {
    async function fixture(name, tokens, signer = '') {
      const release = join(scratch, name), lib = join(release, 'plugins/aukora-aumlok/lib')
      mkdirSync(lib, { recursive: true })
      for (const module of ['derive-v3', 'record-v3', 'store', 'bind-v3', 'owner-signer', 'ceremony-phrase', 'owner-approval']) {
        writeFileSync(join(lib, `${module}.mjs`), module === 'owner-signer'
          ? `export const signerSentinel = 'authority';\n${signer}` : 'export {};\n')
      }
      if (tokens !== undefined) writeFileSync(join(lib, 'ceremony-tokens.mjs'), tokens)
      return load(release)
    }
    const ordinary = await fixture('ordinary', "export const ceremonyTokenValues = () => 'colours'; export const signerSentinel = 'overwritten';")
    assert.equal(ordinary.ceremonyTokenValues(), 'colours')
    assert.equal(ordinary.signerSentinel, 'authority')
    assert.equal(Object.hasOwn(ordinary.library, 'ceremonyTokenValues'), false)
    const prior = await fixture('prior', "export const ceremonyTokenValues = () => 'colours';",
      "export const ceremonyTokenValues = () => 'existing';")
    assert.equal(prior.ceremonyTokenValues(), 'existing')
    for (const [name, tokens] of [['absent', undefined], ['broken', "throw new Error('synthetic colour failure')"],
      ['non-function', 'export const ceremonyTokenValues = 7;']]) {
      const library = await fixture(name, tokens)
      assert.equal(library.signerSentinel, 'authority')
      assert.equal(Object.hasOwn(library, 'ceremonyTokenValues'), false)
    }
  } finally { rmSync(scratch, { recursive: true, force: true }) }
}

function hexCourt(safe) {
  const border = '--dsw-alias-border-l2', label = '--dsw-alias-label-primary', surface = '--dsw-alias-bg-layer-1'
  for (const value of ['#fff', '#ffffff', '#fff2', '#ffffff1f']) {
    assert.equal(safe({ [border]: value }).values[border], value)
  }
  for (const value of ['#ffff', '#f9fafbff']) assert.equal(safe({ [label]: value }).values[label], value)
  for (const value of ['#fff8', '#ffffff80']) {
    const result = safe({ [label]: value })
    assert.equal(result.values[label], SAFE_APPROVAL_TOKENS[label])
    assert.ok(result.reasons.some(reason => reason.includes('alpha')))
  }
  for (const value of ['#0008', '#00000080']) {
    const result = safe({ [surface]: value })
    assert.equal(result.values[surface], SAFE_APPROVAL_TOKENS[surface])
    assert.ok(result.reasons.some(reason => reason.includes('alpha')))
  }
  const unreadable = safe({ [label]: '#000f' })
  assert.equal(unreadable.values[label], SAFE_APPROVAL_TOKENS[label])
  assert.ok(unreadable.reasons.some(reason => reason.includes('contrast')))
  for (const value of ['#fffff', '#fffffff', '#gggg', '#ffffff1f;display:none']) {
    assert.equal(safe({ [border]: value }).fellBack, true)
  }
}

const bridgeSource = readFileSync(new URL('../apps/aukora-desktop/aumlok-bridge.mjs', import.meta.url), 'utf8')
async function loggingCourt(source) {
  const callback = source.match(/view\.webContents\.on\('did-finish-load', \(\) => \{([^]*?)\n    \}\)/u)?.[1]
  assert.ok(callback)
  const logs = []
  new Script(`(() => {${callback}\n})()`).runInNewContext({
    view: {}, theme: 'dark', say: line => logs.push(line),
    applySiteTokens: async () => { throw new Error('synthetic colour failure') },
  })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(logs.length, 1)
  assert.match(logs[0], /face colours not applied.*synthetic colour failure/u)
}

test('the shipped loader reads face tokens and isolates optional colour exports', async () => {
  const library = await loadOrganLibrary(root)
  assert.equal(typeof library.ceremonyTokenValues, 'function')
  assert.ok(Object.keys(readFaceTokenValues(root, library)).length > 0)
  await loaderCourt(loadOrganLibrary)
})

test('short and long alpha hex preserve border alpha and refuse translucent text and surfaces', () => hexCourt(safeApprovalTokens))
test('failed token application is reported while the checked fallback remains', () => loggingCourt(bridgeSource))

test('removing colour joins or opacity protections makes the same courts fail', async t => {
  for (const [name, before, after] of [
    ['missing reader', 'if (existsSync(tokens)) {', 'if (false) {'],
    ['flattened exports', "modules.ceremonyTokenValues = ceremonyTokenValues", "Object.assign(modules, await import(pathToFileURL(tokens).href))"],
    ['overwritten signer export', " && !('ceremonyTokenValues' in modules)", ''],
    ['mandatory colours', '} catch { /* the sheet retains its checked fallback colours */ }', '} catch (error) { throw error }'],
  ]) {
    const mutant = await changedModule(stateSource, statePath, before, after)
    await assert.rejects(loaderCourt(mutant.loadOrganLibrary))
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  for (const [name, before, after] of [
    ['short hex absent', '[0-9a-f]{3,4}', '[0-9a-f]{3}'],
    ['long hex absent', '|[0-9a-f]{8}', ''],
    ['alpha discarded', 'return [r, g, b, a / 255]', 'return [r, g, b, 1]'],
  ]) {
    const mutant = await changedModule(viewSource, viewPath, before, after)
    assert.throws(() => hexCourt(mutant.safeApprovalTokens), assert.AssertionError)
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  const silent = bridgeSource.replace(/\.catch\(error => say\(`aumlok approval: face colours not applied[^]*?\)\)/u, '.catch(() => {})')
  assert.notEqual(silent, bridgeSource)
  await assert.rejects(loggingCourt(silent), assert.AssertionError)
  t.diagnostic('MUTATION CAUGHT silent colour failure')
})
