// SPDX-License-Identifier: AGPL-3.0-or-later
// Load the repository's face rails; mutate isolated module bytes, never source files.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'

const root = new URL('../../plugins/aukora-face/apps/src/auma-live/', import.meta.url)
const files = new Set(['honesty.ts', 'turn-trust.ts', 'claims-packet.ts', 'reply-manifest.ts'])
let instance = 0

export async function loadRails(file, transform) {
  assert.ok(files.has(file), 'court:rail-not-allowed')
  const url = new URL(file, root)
  if (transform === undefined) return import(url.href)
  const source = transform(readFileSync(url, 'utf8'))
  const js = stripTypeScriptTypes(source, { mode: 'strip' })
  return import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}#${instance++}`)
}

export function replaceOnce(source, from, to) {
  assert.equal(source.split(from).length, 2, 'court:mutation-anchor-not-unique')
  return source.replace(from, to)
}
