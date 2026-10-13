// Checks retained copies against their canonical files.
import assert from 'node:assert/strict'
import { lstatSync, readFileSync, readdirSync, readlinkSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const donorExceptions = new Set([
  'packages/authority/upstream/plugins/aukora-aumlok/lib/ceilings.mjs',
  'packages/authority/upstream/plugins/aukora-aumlok/lib/prime-verifier.mjs',
  'packages/authority/upstream/plugins/aukora-kira/lib/strict-read.mjs',
  'packages/authority/upstream/scripts/aukora/decide.mjs',
  'packages/authority/upstream/scripts/aumlok/PROVENANCE.md',
  'packages/memory/genesis/plugins/aukora-kira/lib/cite-service.mjs',
  'packages/memory/genesis/plugins/aukora-kira/lib/memory-tiers.mjs',
  'packages/memory/genesis/plugins/aukora-kira/lib/memory-verify.mjs',
  'packages/memory/genesis/plugins/aukora-kira/lib/strict-read.mjs',
])

function files(directory) {
  return readdirSync(join(root, directory)).sort().flatMap(name => {
    const path = `${directory}/${name}`
    return lstatSync(join(root, path)).isDirectory() ? files(path) : [path]
  })
}

function payload(path) {
  const absolute = join(root, path), stat = lstatSync(absolute)
  if (stat.isFile()) return { kind: 'file', bytes: readFileSync(absolute) }
  if (stat.isSymbolicLink()) return { kind: 'symlink', bytes: Buffer.from(readlinkSync(absolute)) }
  throw new Error(`PINNED_COPY_TYPE ${path}`)
}

function compareCopy(canonical, copy, read = payload) {
  const source = read(canonical), retained = read(copy)
  if (source.kind !== retained.kind) throw new Error(`PINNED_COPY_TYPE ${copy}`)
  if (!source.bytes.equals(retained.bytes)) throw new Error(`PINNED_COPY_DRIFT ${copy}`)
}

test('retained copies match canonical bytes and differing copies refuse', t => {
  const donor = ['packages/authority/upstream', 'packages/memory/genesis'].flatMap(directory =>
    files(directory).filter(copy => !donorExceptions.has(copy)).map(copy => [copy.slice(directory.length + 1), copy]))
  assert.equal(donor.length, 401, 'PINNED_COPY_COUNT donor closures')
  const noble = files('plugins/aukora-aumlok/lib/vendor/noble-curves')
    .filter(copy => !copy.endsWith('/upstream-noble-curves.json'))
    .map(copy => [copy.replace('aukora-aumlok/', 'aukora-nostr/'), copy])
  assert.equal(noble.length, 27, 'PINNED_COPY_COUNT Noble closure')
  const stock = 'plugins/aukora-face/apps/vendor/'
  const wasm = 'plugins/aukora-kira/lib/wasm-cell/'
  const families = {
    donor,
    noble,
    inference: [['plugins/aukora-face/apps/src/auma-live/model-request-store.ts', 'packages/inference/src/owned/model-request-store.ts']],
    stock: [
      ['auma-lingwa/runtime/app/auma/canon-v16.json', 'auma-lingwa/canonical/auma-canon-v16.json'],
      ['auma-live/runtime/app/field-directives.js', 'auma-live/source/app/field-directives.js'],
      ['auma-live/runtime/app/field-directives.js', 'auma-live/original-closure/spatial/app/field-directives.js'],
      ['auma-live/runtime/app/field-directives.d.ts', 'auma-live/source/app/field-directives.d.ts'],
      ['auma-live/source/server/crossLane.ts', 'auma-live/original-closure/spatial/crossLane.ts'],
      ['auma-live/source/server/presenceLane.ts', 'auma-live/original-closure/spatial/presenceLane.ts'],
      ['auma-live/voice/test_lazy_engines.py', 'auma-live/source/voice/test_lazy_engines.py'],
    ].map(pair => pair.map(path => stock + path)),
    wasm: ['aukora/broker/memory-put-args.mjs', 'aukora/guest/wasm-proposal-cell.d.mts', 'aukora/kernel-seed/canonical-json.mjs']
      .map(path => [`plugins/aukora-box/${path}`, wasm + path]),
    capture: [
      ['packages/memory/src/capture-presentation.mjs', 'packages/ui/adapters/capture-presentation.mjs'],
      ['packages/memory/src/capture-presentation.mjs', 'packages/ui/prime-authority/lib/types/adapters/capture-presentation.mjs'],
      ['packages/ui/adapters/capture-presentation.d.mts', 'packages/ui/prime-authority/lib/types/adapters/capture-presentation.d.mts'],
    ],
    membrane: [['vendor/aukora-membrane/minimal/verify.py', 'vendor/append-only/verify.py']],
  }
  let compared = 0
  for (const [family, pairs] of Object.entries(families)) {
    for (const [canonical, copy] of pairs) { compareCopy(canonical, copy); compared++ }
    const [canonical, copy] = pairs[0]
    const changed = path => {
      const original = payload(path)
      return path === copy ? { ...original, bytes: Buffer.concat([original.bytes, Buffer.from('\ncopy-drift')]) } : original
    }
    assert.throws(() => compareCopy(canonical, copy, changed), { message: `PINNED_COPY_DRIFT ${copy}` }, `${family}: changed bytes must refuse`)
    const changedKind = path => path === copy ? { ...payload(path), kind: 'directory' } : payload(path)
    assert.throws(() => compareCopy(canonical, copy, changedKind), { message: `PINNED_COPY_TYPE ${copy}` }, `${family}: changed type must refuse`)
  }
  t.diagnostic(`pinned copies: PASS (${compared} pairs; ${Object.keys(families).length} byte mutations and ${Object.keys(families).length} type mutations refused)`)
})
