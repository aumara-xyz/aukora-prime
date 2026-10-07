// SPDX-License-Identifier: AGPL-3.0-or-later
// AUKORA ID aperture bridge (P7, LAB SEAM, staging): registers one tool,
// aukora_id_emit, which runs one relay-post-shaped operation through the vendored
// AUKORA ID aperture (request -> admission -> owner-signed approval -> consumption
// BEFORE dispatch -> fixed LOCAL sink -> receipt coordinates). Inert off Linux and
// without config.stateDir. Never posts to any relay; the caller's text is never
// dispatched (the variable-payload adapter profile is unfrozen — D12).
import { runLabEmit } from './lab-flow.mjs'

export const ID_EMIT_TOOL = 'aukora_id_emit'

export function apply(ctx, config = {}) {
  if (process.platform !== 'linux') return // The seam proves itself on staging (Linux); elsewhere inert.
  const stateDir = typeof config.stateDir === 'string' && config.stateDir.startsWith('/') ? config.stateDir : null
  if (!stateDir) {
    console.warn('AUKORA_ID_APERTURE_INERT', 'no stateDir configured')
    return
  }
  ctx.tools.register({
    name: ID_EMIT_TOOL,
    description: 'LAB SEAM (staging only): emit one relay-post-shaped operation through the vendored AUKORA ID aperture — request, admission, owner-signed approval, consumption before dispatch, fixed LOCAL sink, receipt. The text argument is never dispatched.',
    parameters: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false },
    execute: async args => {
      try {
        return JSON.stringify({ ok: true, ...(await runLabEmit(stateDir)) })
      } catch (error) {
        return JSON.stringify({ ok: false, state: 'error', reason: String(error?.message ?? error) })
      }
    },
  })
  console.info('AUKORA_ID_APERTURE_REGISTERED', ID_EMIT_TOOL)
}
