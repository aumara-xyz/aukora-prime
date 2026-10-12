// SPDX-License-Identifier: AGPL-3.0-or-later
// Pin both face derivations to the maintained desktop bytes and reject display drift.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const canonicalUrl = new URL('../apps/aukora-desktop/pentora.mjs', import.meta.url)
const canonicalBytes = readFileSync(canonicalUrl)
const faces = ['plugins/aukora-face/settings', 'packages/ui/faces/settings']
const copyPaths = faces.map(face => join(root, face, 'src/aura/pentora.mjs'))
const helperUrl = new URL('../plugins/aukora-face/settings/src/aura/pentora-cells.mjs', import.meta.url)
const helperSource = readFileSync(helperUrl, 'utf8')
const config = JSON.parse(readFileSync(join(root, 'apps/aukora-desktop/package.json'), 'utf8')).build
const vectors = JSON.parse(readFileSync(new URL('../packages/copresence/portal-v0/tests/pentora-vectors.json', import.meta.url), 'utf8'))
const hash = bytes => new Uint8Array(createHash('sha256').update(bytes).digest())
const unhex = head => Uint8Array.from(Buffer.from(head, 'hex'))

function checkCopiedBytes(bytes) {
  assert.deepEqual(bytes, canonicalBytes, 'face Pentora is byte-identical to apps/aukora-desktop/pentora.mjs')
}

function checkDesktopPackage(build) {
  assert.ok(build.files.includes('pentora.mjs'), 'desktop carries its maintained derivation')
  assert.ok(!build.extraFiles.some(entry => /aukora-face\/settings/.test(entry.from)), 'desktop has no dependency on the settings face')
}

function auraFiles() {
  const files = new Map()
  function readTree(directory, prefix) {
    if (!existsSync(directory)) return
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name), name = `${prefix}/${entry.name}`
      assert.ok(!entry.isSymbolicLink(), 'face source/asset symlink refused')
      if (entry.isDirectory()) readTree(path, name)
      else files.set(name, readFileSync(path, 'utf8'))
    }
  }
  for (const face of faces) {
    for (const directory of ['src', 'assets']) readTree(join(root, face, directory), `${face}/${directory}`)
  }
  return files
}

function checkAuraSources(files) {
  for (const [path, bytes] of files) {
    assert.doesNotMatch(path, /tesseract/i, `tesseract asset absent: ${path}`)
    assert.doesNotMatch(bytes, /tesseract/i, `tesseract source/import absent: ${path}`)
  }
  const surface = files.get('plugins/aukora-face/settings/src/client/AuraCoherenceSurface.tsx')
  assert.match(surface, /import \{ PENTORA \} from '\.\.\/aura\/pentora\.mjs'/, 'page imports maintained geometry')
  assert.match(surface, /PENTORA\.mutable\.map/, 'page maps canonical cells to their canonical points')
  assert.match(surface, /PENTORA\.edges\.map/, 'page draws canonical edges')
}

async function checkCells(api, useDefault = false) {
  for (const vector of vectors) {
    const head = unhex(vector.head)
    const cells = await api.pentoraCells(head, useDefault ? undefined : hash)
    assert.equal(Buffer.from(cells).toString('hex'), vector.wire_hex)
    assert.equal(Buffer.from(head).toString('hex'), vector.head, 'head input remains unchanged')
  }
}

async function checkHashUnavailable(api) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined })
    await assert.rejects(api.pentoraCells(new Uint8Array(32)), { code: 'pentora:hash-unavailable' })
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor)
    else delete globalThis.crypto
  }
}

async function helperMutant(from, to) {
  assert.equal(helperSource.split(from).length, 2, 'mutation matches exactly one actual source anchor')
  const source = helperSource.replace(from, to).replace("'./pentora.mjs'", JSON.stringify(new URL('./pentora.mjs', helperUrl).href))
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}

test('both standalone faces carry the maintained derivation byte-for-byte and preserve its exports', async () => {
  const canonical = await import(canonicalUrl.href)
  assert.deepEqual(Object.keys(canonical).sort(), ['PENTORA', 'pentoraDigest', 'pentoraDigits'])
  for (const path of copyPaths) {
    checkCopiedBytes(readFileSync(path))
    const api = await import(pathToFileURL(path).href)
    assert.deepEqual(Object.keys(api), Object.keys(canonical))
    assert.deepEqual(api.PENTORA, canonical.PENTORA)
    for (const vector of vectors) {
      assert.equal(Buffer.from(await api.pentoraDigest(unhex(vector.head), hash)).toString('hex'), vector.sha256)
      assert.equal(Buffer.from(await api.pentoraDigits(unhex(vector.head), hash)).toString('hex'), vector.wire_hex)
    }
  }
  checkDesktopPackage(config)
})

test('separate face cells helper delegates expansion and supplies browser hashing', async () => {
  const api = await import(helperUrl.href)
  await checkCells(api)
  await checkCells(api, true)
  await checkHashUnavailable(api)
  const mirror = await import(new URL('../packages/ui/faces/settings/src/aura/pentora-cells.mjs', import.meta.url).href)
  await checkCells(mirror, true)
})

test('Aura uses maintained Pentora geometry and has no tesseract source, import or asset', () => {
  checkAuraSources(auraFiles())
})

test('mutations of copied bytes, geometry use, package independence and helper protections are killed', async () => {
  let killed = 0
  const text = canonicalBytes.toString('utf8')
  for (const path of copyPaths) {
    for (const [from, to] of [
      ['pentora.display.v1', 'pentora.display.v2'],
      ['[-0.934172,0,-0.356822]', '[-0.934171,0,-0.356822]'],
      ['centre: 55', 'centre: 54'],
      ['0,1,2,3,4,5,6,7,8,9', '1,0,2,3,4,5,6,7,8,9'],
      ['[10,12],[10,16]', '[10,13],[10,16]'],
    ]) {
      assert.ok(text.includes(from), `missing byte mutation anchor in ${path}`)
      assert.throws(() => checkCopiedBytes(Buffer.from(text.replace(from, to))), assert.AssertionError)
      killed += 1
    }
  }
  for (const mutate of [
    build => { build.files = build.files.filter(file => file !== 'pentora.mjs') },
    build => { build.extraFiles.push({ from: '../../plugins/aukora-face/settings/src/aura', to: 'face' }) },
  ]) {
    const changed = structuredClone(config)
    mutate(changed)
    assert.throws(() => checkDesktopPackage(changed), assert.AssertionError)
    killed += 1
  }
  const surfacePath = 'plugins/aukora-face/settings/src/client/AuraCoherenceSurface.tsx'
  for (const [path, mutate] of [
    [surfacePath, () => "import './tesseract.ts'"],
    ['plugins/aukora-face/settings/assets/tesseract.svg', () => '<svg/>'],
    [surfacePath, text => text.replace("import { PENTORA } from '../aura/pentora.mjs'", '')],
    [surfacePath, text => text.replace('PENTORA.mutable.map', 'geometry.mutable.map')],
    [surfacePath, text => text.replace('PENTORA.edges.map', 'geometry.edges.map')],
  ]) {
    const changed = auraFiles()
    changed.set(path, mutate(changed.get(path)))
    assert.throws(() => checkAuraSources(changed), assert.AssertionError)
    killed += 1
  }
  for (const [from, to, check] of [
    ['return pentoraDigits(head32, sha256)', 'return new Uint8Array(110)', api => checkCells(api)],
    ["return globalThis.crypto.subtle.digest('SHA-256', bytes)", 'return new Uint8Array(32)', api => checkCells(api, true)],
    ["if (!globalThis.crypto?.subtle) throw Object.assign(new TypeError('pentora:hash-unavailable'), { code: 'pentora:hash-unavailable' })", '', checkHashUnavailable],
  ]) {
    await assert.rejects(check(await helperMutant(from, to)), undefined, `surviving mutant: ${from}`)
    killed += 1
  }
  console.log(`MUTATION aura-pentora-sharing: ${killed}/${killed} killed`)
})
