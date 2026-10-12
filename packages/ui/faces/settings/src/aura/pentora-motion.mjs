// SPDX-License-Identifier: AGPL-3.0-or-later
// Show only head-derived cells; a changed head settles before its frame is solid.
import { pentoraCells } from './pentora-cells.mjs'

export const PENTORA_TRANSITION_MS = 400
export const PENTORA_SETTLE_MS = 1200
const prepared = new WeakMap()

function refuse(code) {
  throw Object.assign(new TypeError(code), { code })
}

function headBytes(head) {
  if (typeof head !== 'string' || !/^[a-f0-9]{64}$/.test(head)) refuse('aura:pentora-head')
  return Uint8Array.from(head.match(/../g), pair => Number.parseInt(pair, 16))
}

export async function createPentoraMotion(previousHead, nextHead, sha256) {
  const previousBytes = headBytes(previousHead)
  const nextBytes = headBytes(nextHead)
  const previousCells = Array.from(await pentoraCells(previousBytes, sha256))
  const nextCells = previousHead === nextHead
    ? previousCells
    : Array.from(await pentoraCells(nextBytes, sha256))
  const motion = Object.freeze({ previousHead, nextHead })
  prepared.set(motion, { previousCells, nextCells })
  return motion
}

export function pentoraMotionFrame(motion, elapsedMs, reducedMotion = false) {
  const cells = prepared.get(motion)
  if (cells === undefined) refuse('aura:pentora-motion')
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) refuse('aura:pentora-time')
  const changed = motion.previousHead !== motion.nextHead
  const progress = reducedMotion || !changed ? 1 : Math.min(1, elapsedMs / PENTORA_TRANSITION_MS)
  const solid = reducedMotion || !changed || elapsedMs >= PENTORA_SETTLE_MS
  const moved = Math.floor(cells.nextCells.length * progress)
  return Object.freeze({
    cells: Object.freeze(cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index])),
    status: solid ? 'solid' : 'in-motion',
    head: solid ? motion.nextHead : null,
    progress,
  })
}
