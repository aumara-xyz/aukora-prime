// SPDX-License-Identifier: AGPL-3.0-or-later
// Root selects the app origin and public binding record; requests cannot replace either.
import fs from 'node:fs'
import path from 'node:path'
import { readProtectedJson } from './owner-state.mjs'

export const BROWSER_JOIN_FILE = '/etc/aukora-boundary-gate/browser-join.json'
const fail = code => { throw Object.assign(new Error(code), { code }) }
export function browserJoinReader(file) {
  if (!path.isAbsolute(file) || path.resolve(file) !== file) fail('browser-join:path')
  const read = () => {
    const value = readProtectedJson(file)
    if (!value || Object.keys(value).sort().join(',') !== 'app_origin,binding_record,kind,version'
      || value.version !== 1 || value.kind !== 'aukora-browser-join/v1') fail('browser-join:shape')
    let url
    try { url = new URL(value.app_origin) } catch { fail('browser-join:origin') }
    if (url.protocol !== 'https:' || url.origin !== value.app_origin || url.port
      || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/.test(url.hostname)) fail('browser-join:origin')
    if (typeof value.binding_record !== 'string' || !path.isAbsolute(value.binding_record)
      || path.resolve(value.binding_record) !== value.binding_record
      || path.basename(value.binding_record) !== 'local-control.json') fail('browser-join:record-path')
    return Object.freeze(value)
  }
  const selected = JSON.stringify(read())
  return () => { const current = read(); if (JSON.stringify(current) !== selected) fail('browser-join:changed'); return current }
}

// Only the public record is read; the existing projection derives its subject from genesis.
export function bindingRecordReader(file, { readJsonStrictBytes, recordProjection }) {
  return () => {
    if (fs.realpathSync(file) !== file) fail('browser-join:record-alias')
    const projection = recordProjection(readJsonStrictBytes(file, { maxBytes: 32768 }).value)
    return { subject: projection.subject, rootId: projection.rootId }
  }
}
