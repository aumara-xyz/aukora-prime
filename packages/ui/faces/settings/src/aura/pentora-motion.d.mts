// SPDX-License-Identifier: AGPL-3.0-or-later
export const PENTORA_TRANSITION_MS: 400
export const PENTORA_SETTLE_MS: 1200
export interface PentoraMotion {
  readonly previousHead: string
  readonly nextHead: string
}
export interface PentoraMotionFrame {
  readonly cells: readonly number[]
  readonly status: 'solid' | 'in-motion'
  readonly head: string | null
  readonly progress: number
}
export function createPentoraMotion(
  previousHead: string,
  nextHead: string,
  sha256?: (bytes: Uint8Array) => Promise<Uint8Array | ArrayBuffer> | Uint8Array | ArrayBuffer,
): Promise<PentoraMotion>
export function pentoraMotionFrame(motion: PentoraMotion, elapsedMs: number, reducedMotion?: boolean): PentoraMotionFrame
