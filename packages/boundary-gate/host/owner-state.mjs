// SPDX-License-Identifier: AGPL-3.0-or-later
// Existing public active registry only. This adapter does not enroll or activate an owner.
import { ownerAuthorizationOwnerState } from '../../owner-key/src/authorization.mjs'
import { readProtectedPublicText } from './protected-public-data.mjs'

export const OWNER_STATE_PATH = '/etc/aukora-boundary-gate/owner-state.json'
const unavailable = () => { throw new Error('trusted-owner-state:unavailable') }

/** The registry has eight scalar fields. Parse exact integer tokens and reject duplicate decoded keys. */
export function parseTrustedOwnerState(text) {
  try {
    if (typeof text !== 'string' || text.charCodeAt(0) === 0xfeff || Buffer.byteLength(text) > 4096) unavailable()
    let at = 0
    const white = () => { while (/[\x20\t\r\n]/u.test(text[at] ?? '\0')) at++ }
    white(); if (text[at++] !== '{') unavailable()
    const value = Object.create(null)
    const field = /"(?:[^"\\]|\\.)*"\s*:\s*(?:"(?:[^"\\]|\\.)*"|-?(?:0|[1-9][0-9]*))/uy
    white()
    while (text[at] !== '}') {
      field.lastIndex = at
      const matched = field.exec(text)
      if (!matched) unavailable()
      const entry = JSON.parse(`{${matched[0]}}`), [key] = Object.keys(entry)
      if (Object.hasOwn(value, key)) unavailable()
      value[key] = entry[key]
      at = field.lastIndex; white()
      if (text[at] !== ',') break
      at++; white(); if (text[at] === '}') unavailable()
    }
    if (text[at++] !== '}') unavailable()
    white(); if (at !== text.length) unavailable()
    return ownerAuthorizationOwnerState(value)
  } catch { unavailable() }
}

/** Fixed independently protected public file; synchronous reread on every gate check. */
export function readOwnerState() {
  try { return parseTrustedOwnerState(readProtectedPublicText(OWNER_STATE_PATH)) }
  catch { unavailable() }
}
