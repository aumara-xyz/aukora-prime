// SPDX-License-Identifier: AGPL-3.0-or-later
// Check canonical solid frames and deterministic, visibly transitional frames.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import * as motion from '../plugins/aukora-face/settings/src/aura/pentora-motion.mjs'
import { pentoraCells } from '../plugins/aukora-face/settings/src/aura/pentora-cells.mjs'

const moduleUrl = new URL('../plugins/aukora-face/settings/src/aura/pentora-motion.mjs', import.meta.url)
const dependencyUrl = new URL('./pentora-cells.mjs', moduleUrl)
const source = readFileSync(moduleUrl, 'utf8')
const vectors = JSON.parse(readFileSync(new URL('../packages/copresence/portal-v0/tests/pentora-vectors.json', import.meta.url), 'utf8'))
const hash = bytes => new Uint8Array(createHash('sha256').update(bytes).digest())
const heads = ['00', '11', '22', '33'].map(byte => byte.repeat(32))
const cellsOf = async head => Array.from(await pentoraCells(Uint8Array.from(Buffer.from(head, 'hex')), hash))

async function checkSequence(api) {
  for (let index = 1; index < heads.length; index += 1) {
    const state = await api.createPentoraMotion(heads[index - 1], heads[index], hash)
    const previous = await cellsOf(heads[index - 1])
    const expected = await cellsOf(heads[index])
    const changed = expected.map((value, cell) => value !== previous[cell])
    for (const elapsed of [0, 40, 199, 399, 400, 800, 1199, 1200, 1800]) {
      const frame = api.pentoraMotionFrame(state, elapsed)
      const progress = Math.min(1, elapsed / 400)
      const moved = Math.floor(110 * progress)
      assert.equal(frame.progress, progress)
      assert.deepEqual(frame.cells, expected.map((value, cell) => cell < moved ? value : previous[cell]))
      assert.deepEqual(frame.changedCells, changed)
      if (elapsed < 1200) {
        assert.equal(frame.status, 'in-motion')
        assert.equal(frame.head, null)
      } else {
        assert.equal(frame.status, 'solid')
        assert.equal(frame.head, heads[index])
      }
      if (frame.status === 'solid') assert.deepEqual(frame.cells, expected)
    }
  }
}

async function checkReference(api) {
  const vector = vectors[0]
  const state = await api.createPentoraMotion(vector.head, vector.head, hash)
  const frame = api.pentoraMotionFrame(state, 0)
  assert.equal(frame.status, 'solid')
  assert.equal(frame.head, vector.head)
  assert.equal(Buffer.from(frame.cells).toString('hex'), vector.wire_hex)
}

async function checkInterrupted(api) {
  const first = await api.createPentoraMotion(heads[0], heads[1], hash)
  const before = api.pentoraMotionFrame(first, 160)
  const interrupted = await api.createPentoraMotion(heads[1], heads[2], hash)
  const previous = await cellsOf(heads[1])
  const next = await cellsOf(heads[2])
  for (let elapsed = 0; elapsed <= 1300; elapsed += 13) {
    const frame = api.pentoraMotionFrame(interrupted, elapsed)
    if (elapsed < 1200) {
      assert.equal(frame.status, 'in-motion')
      assert.equal(frame.head, null)
    } else {
      assert.equal(frame.status, 'solid')
      assert.equal(frame.head, heads[2])
      assert.deepEqual(frame.cells, next)
    }
    const moved = Math.floor(110 * Math.min(1, elapsed / 400))
    assert.deepEqual(frame.cells, next.map((value, cell) => cell < moved ? value : previous[cell]))
  }
  assert.deepEqual(api.pentoraMotionFrame(first, 160), before)
  assert.deepEqual(api.pentoraMotionFrame(interrupted, 0).cells, previous)
}

async function checkPurity(api) {
  const state = await api.createPentoraMotion(heads[0], heads[1], hash)
  const first = api.pentoraMotionFrame(state, 120)
  api.pentoraMotionFrame(state, 1200)
  const again = api.pentoraMotionFrame(state, 120)
  assert.deepEqual(again, first)
  const independentlyPrepared = await api.createPentoraMotion(heads[0], heads[1], hash)
  assert.deepEqual(api.pentoraMotionFrame(independentlyPrepared, 120), first)
  const previous = await cellsOf(heads[0])
  const next = await cellsOf(heads[1])
  const moved = Math.floor(110 * 120 / 400)
  assert.deepEqual(first.cells, next.map((value, index) => index < moved ? value : previous[index]))
}

async function checkSameHead(api) {
  const state = await api.createPentoraMotion(heads[0], heads[0], hash)
  const expected = await cellsOf(heads[0])
  for (const elapsed of [0, 200, 800, 1200, 1_000_000]) {
    const frame = api.pentoraMotionFrame(state, elapsed)
    assert.equal(frame.status, 'solid')
    assert.equal(frame.head, heads[0])
    assert.deepEqual(frame.cells, expected)
  }
}

async function checkReducedMotion(api) {
  const state = await api.createPentoraMotion(heads[0], heads[1], hash)
  const frame = api.pentoraMotionFrame(state, 0, true)
  assert.equal(frame.status, 'solid')
  assert.equal(frame.head, heads[1])
  assert.deepEqual(frame.cells, await cellsOf(heads[1]))
}

async function checkHeadRefusal(api) {
  await assert.rejects(api.createPentoraMotion('zz'.repeat(32), heads[1], hash), { code: 'aura:pentora-head' })
  await assert.rejects(api.createPentoraMotion(heads[0], 'AB'.repeat(32), hash), { code: 'aura:pentora-head' })
  await assert.rejects(api.createPentoraMotion(heads[0], '00', hash), { code: 'aura:pentora-head' })
}

async function checkTimeRefusal(api) {
  const state = await api.createPentoraMotion(heads[0], heads[1], hash)
  for (const elapsed of [-1, NaN, Infinity]) {
    assert.throws(() => api.pentoraMotionFrame(state, elapsed), { code: 'aura:pentora-time' })
  }
}

async function checkPreparedRefusal(api) {
  assert.throws(() => api.pentoraMotionFrame({ previousHead: heads[0], nextHead: heads[1] }, 1200), { code: 'aura:pentora-motion' })
}

async function checkImmutable(api) {
  const state = await api.createPentoraMotion(heads[0], heads[1], hash)
  const frame = api.pentoraMotionFrame(state, 1200)
  assert.throws(() => { state.nextHead = heads[0] }, TypeError)
  assert.throws(() => { frame.cells[0] = (frame.cells[0] + 1) % 3 }, TypeError)
  assert.throws(() => { frame.changedCells[0] = !frame.changedCells[0] }, TypeError)
  assert.throws(() => { frame.status = 'in-motion' }, TypeError)
}

for (const [label, check] of [
  ['scripted heads settle in order; every solid frame equals its canonical head', checkSequence],
  ['known solid head equals the independent portal reference cells', checkReference],
  ['interrupted transitions restart from the previous real head and settle only at the next', checkInterrupted],
  ['transition is pure of previous head, next head, elapsed time', checkPurity],
  ['unchanged head never animates', checkSameHead],
  ['reduced motion changes directly to the new canonical cells', checkReducedMotion],
  ['malformed heads have a named refusal', checkHeadRefusal],
  ['invalid elapsed time has a named refusal', checkTimeRefusal],
  ['unprepared head-cell claims have a named refusal', checkPreparedRefusal],
  ['prepared heads and frame cells cannot be changed by callers', checkImmutable],
]) test(label, () => check(motion))

test('mutations of motion protections are all detected', async () => {
  const mutants = [
    ['solid before settle', "status: solid ? 'solid' : 'in-motion'", "status: 'solid'", checkSequence],
    ['wrong solid cells', 'index < moved ? value : cells.previousCells[index]', 'cells.previousCells[index]', checkSequence],
    ['transition endpoint cells', 'elapsedMs / PENTORA_TRANSITION_MS', 'elapsedMs / PENTORA_SETTLE_MS', checkSequence],
    ['wrong solid head', 'head: solid ? motion.nextHead : null', 'head: solid ? motion.previousHead : null', checkSequence],
    ['interpolated frame claims a head', 'head: solid ? motion.nextHead : null', 'head: motion.nextHead', checkInterrupted],
    ['previous head discarded', 'const previousCells = Array.from(await pentoraCells(previousBytes, sha256))', 'const previousCells = Array.from(await pentoraCells(nextBytes, sha256))', checkInterrupted],
    ['call-count transition', 'const progress = reducedMotion || !changed ? 1 : Math.min(1, elapsedMs / PENTORA_TRANSITION_MS)', 'const progress = Math.min(1, ++frameCount / 10)', checkPurity],
    ['unchanged head animates', 'const changed = motion.previousHead !== motion.nextHead', 'const changed = true', checkSameHead],
    ['reduced motion ignored', 'reducedMotion || !changed', '!changed', checkReducedMotion],
    ['head check removed', "if (typeof head !== 'string' || !/^[a-f0-9]{64}$/.test(head)) refuse('aura:pentora-head')", '', checkHeadRefusal],
    ['time check removed', "if (!Number.isFinite(elapsedMs) || elapsedMs < 0) refuse('aura:pentora-time')", '', checkTimeRefusal],
    ['prepared check removed', "if (cells === undefined) refuse('aura:pentora-motion')", '', checkPreparedRefusal],
    ['mutable motion', 'const motion = Object.freeze({ previousHead, nextHead })', 'const motion = { previousHead, nextHead }', checkImmutable],
    ['mutable frame cells', 'cells: Object.freeze(cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index]))', 'cells: cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index])', checkImmutable],
    ['mutable changed-cell marks', 'changedCells: Object.freeze(cells.nextCells.map((value, index) => value !== cells.previousCells[index]))', 'changedCells: cells.nextCells.map((value, index) => value !== cells.previousCells[index])', checkImmutable],
    ['mutable frame label', 'return Object.freeze({', 'return ((value) => value)({', checkImmutable],
  ]
  for (const [label, from, to, check] of mutants) {
    assert.ok(source.includes(from), `missing mutation anchor: ${label}`)
    let changed = source.replaceAll(from, to)
    if (label === 'call-count transition') changed = `let frameCount = 0\n${changed}`
    changed = changed.replace("'./pentora-cells.mjs'", JSON.stringify(dependencyUrl.href))
    const api = await import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`)
    await assert.rejects(check(api), undefined, `surviving mutant: ${label}`)
  }
  console.log(`MUTATION aura-pentora-motion: ${mutants.length}/${mutants.length} killed`)
})
