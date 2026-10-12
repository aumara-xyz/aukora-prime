// SPDX-License-Identifier: AGPL-3.0-or-later
// Use the maintained display expansion with browser hashing when none is supplied.
import { pentoraDigits } from './pentora.mjs'

async function browserSha256(bytes) {
  if (!globalThis.crypto?.subtle) throw Object.assign(new TypeError('pentora:hash-unavailable'), { code: 'pentora:hash-unavailable' })
  return globalThis.crypto.subtle.digest('SHA-256', bytes)
}

export async function pentoraCells(head32, sha256 = browserSha256) {
  return pentoraDigits(head32, sha256)
}
