// Memory support pins bind the current codec bytes without repinning at runtime.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { CASES } from '../packages/ops/fast-verify/manifest.mjs'

const codecPath = 'packages/memory/src/codecs.mjs'
const digest = createHash('sha256').update(readFileSync(new URL('../' + codecPath, import.meta.url))).digest('hex')
for (const id of ['memory-control-retention-coordinator', 'memory-owner-serialization', 'memory-retained-memory-participant']) {
  test(`${id} pins the reviewed codec bytes`, () => {
    const pins = CASES.find(row => row.id === id)?.pins.filter(pin => pin.path === codecPath)
    assert.equal(pins?.length, 1, 'exactly one codec support pin is required')
    assert.equal(pins[0].sha256, digest, 'codec changes require a reviewed literal pin update')
  })
}
