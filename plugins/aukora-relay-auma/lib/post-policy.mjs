// SPDX-License-Identifier: AGPL-3.0-or-later
// HOST ONLY: explicit protected inputs remain inside this process. No discovery,
// permission changes, exported operational digests, or model-selected policy.
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { types } from 'node:util'
import { secretShapesIn } from '../../../scripts/aukora/evidence-secret-gate.mjs'
import { parseStrictJson } from '../../../packages/contracts/src/shared.mjs'

export const POST_POLICY_PROFILE = Object.freeze({
  version: 1, kind: 'aukora-relay-post-policy/v1', algorithm: 'sha256',
  domain: 'aukora-relay:protected-secret:v1', encoding: 'strict-utf8-no-bom/v1',
  normalization: 'literal-and-ecmascript-trim/v1', matching_unit: 'contiguous-utf8-byte-window/v1',
  refresh: 'per-post-stable-read/v1',
})
export const PROTECTED_CATEGORIES = Object.freeze(['credentials', 'auma-key', 'nostr-identity', 'launch-token'])
const MAX_FILE_BYTES = 65536
const MAX_TEXT_BYTES = 2000
const DOMAIN_BYTES = Buffer.from(POST_POLICY_PROFILE.domain + '\0', 'utf8')

export class PostPolicyError extends Error {
  constructor(code) {
    super(code === 'REFUSED' ? 'relay post refused' : 'relay post policy unavailable')
    this.name = 'PostPolicyError'; this.code = code
  }
}
const unavailable = () => { throw new PostPolicyError('UNAVAILABLE') }
const refused = () => { throw new PostPolicyError('REFUSED') }
function exact(value, keys) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) unavailable()
  const fields = Reflect.ownKeys(value)
  if (fields.length !== keys.length || !keys.every(key => fields.includes(key))) unavailable()
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) unavailable()
  }
}
function dense(value, max) {
  if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length < 1 || value.length > max
    || Reflect.ownKeys(value).length !== value.length + 1) unavailable()
  for (let i = 0; i < value.length; i++) {
    if (!Object.hasOwn(value, i) || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, i), 'value')) unavailable()
  }
}
function captureConfig(input) {
  exact(input, [...Object.keys(POST_POLICY_PROFILE), 'reader_uid', 'files'])
  for (const [key, expected] of Object.entries(POST_POLICY_PROFILE)) if (input[key] !== expected) unavailable()
  if (!Number.isSafeInteger(input.reader_uid) || input.reader_uid <= 0 || input.reader_uid !== process.getuid?.()) unavailable()
  dense(input.files, 16)
  const categories = new Set(), paths = new Set()
  const files = input.files.map(file => {
    exact(file, ['category', 'path', 'owner_uid', 'selectors'])
    if (!PROTECTED_CATEGORIES.includes(file.category) || typeof file.path !== 'string'
      || !file.path.isWellFormed() || file.path.includes('\0')
      || !path.isAbsolute(file.path) || path.normalize(file.path) !== file.path || paths.has(file.path)
      || !Number.isSafeInteger(file.owner_uid) || file.owner_uid < 0) unavailable()
    categories.add(file.category); paths.add(file.path); dense(file.selectors, 8)
    const selected = new Set()
    const selectors = file.selectors.map(selector => {
      exact(selector, ['kind', 'pointer'])
      if (!['whole-utf8', 'json-pointer', 'url-query-token'].includes(selector.kind) || typeof selector.pointer !== 'string'
        || (selector.kind === 'whole-utf8' && selector.pointer !== '')
        || (selector.kind !== 'whole-utf8' && (!selector.pointer.startsWith('/') || selector.pointer.length > 512
          || /~(?![01])/u.test(selector.pointer) || !selector.pointer.isWellFormed()))) unavailable()
      if (selector.kind === 'url-query-token' && file.category !== 'launch-token') unavailable()
      const key = selector.kind + ':' + selector.pointer
      if (selected.has(key)) unavailable()
      selected.add(key)
      return Object.freeze({ kind: selector.kind, pointer: selector.pointer })
    })
    return Object.freeze({ category: file.category, path: file.path, owner_uid: file.owner_uid, selectors: Object.freeze(selectors) })
  })
  if (!PROTECTED_CATEGORIES.every(category => categories.has(category))) unavailable()
  return Object.freeze({ reader_uid: input.reader_uid, files: Object.freeze(files) })
}
function identity(before, after) {
  return before.dev === after.dev && before.ino === after.ino && before.size === after.size
    && before.uid === after.uid && before.mode === after.mode && before.nlink === after.nlink
    && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs
}
function protectedAncestors(file, uid) {
  const snapshots = []
  for (let at = path.dirname(file); ; at = path.dirname(at)) {
    const stat = fs.lstatSync(at)
    if (!stat.isDirectory() || stat.isSymbolicLink() || ![0, uid].includes(stat.uid) || (stat.mode & 0o022) !== 0) unavailable()
    snapshots.push([at, stat])
    if (at === path.dirname(at)) return snapshots
  }
}
function checkFile(stat, uid) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== uid || stat.nlink !== 1
    || (stat.mode & 0o077) !== 0 || (stat.mode & 0o7111) !== 0 || stat.size < 1 || stat.size > MAX_FILE_BYTES) unavailable()
}
function recheckAncestors(ancestors) {
  for (const [at, snapshot] of ancestors) {
    const current = fs.lstatSync(at)
    if (!current.isDirectory() || current.isSymbolicLink() || !identity(snapshot, current)) unavailable()
  }
}
function readProtected(file, reader) {
  const ancestors = protectedAncestors(file.path, reader)
  const before = fs.lstatSync(file.path); checkFile(before, file.owner_uid)
  let fd, storage, complete = false
  try {
    if (!Number.isSafeInteger(fs.constants.O_NOFOLLOW)) unavailable()
    fd = fs.openSync(file.path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    const opened = fs.fstatSync(fd); checkFile(opened, file.owner_uid)
    if (!identity(before, opened)) unavailable()
    storage = Buffer.alloc(MAX_FILE_BYTES + 1)
    let size = 0, count
    while ((count = fs.readSync(fd, storage, size, storage.length - size, null)) > 0) {
      size += count
      if (size > MAX_FILE_BYTES) unavailable()
    }
    if (size !== before.size || !identity(opened, fs.fstatSync(fd)) || !identity(before, fs.lstatSync(file.path))) unavailable()
    recheckAncestors(ancestors)
    complete = true
    return { bytes: storage.subarray(0, size), storage, before, ancestors }
  } finally {
    try { if (fd !== undefined) fs.closeSync(fd) }
    catch (error) { storage?.fill(0); throw error }
    finally { if (!complete) storage?.fill(0) }
  }
}
function pointerValue(value, pointer) {
  for (const encoded of pointer.slice(1).split('/')) {
    const key = encoded.replaceAll('~1', '/').replaceAll('~0', '~')
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, key)) unavailable()
    value = value[key]
  }
  if (typeof value !== 'string' || !value.isWellFormed()) unavailable()
  return value
}
const digest = bytes => createHash('sha256').update(DOMAIN_BYTES).update(bytes).digest('hex')
function launchToken(value) {
  // A protected launch descriptor binds both its URL and its decoded token.
  // Shape screening alone does not catch a bare base64url token in prose.
  let url
  try { url = new URL(value) } catch { unavailable() }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash
    || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || url.pathname !== '/') unavailable()
  const keys = [...url.searchParams.keys()], token = url.searchParams.get('token')
  if (keys.length !== 1 || keys[0] !== 'token' || typeof token !== 'string'
    || !/^[A-Za-z0-9_-]{43}$/u.test(token)) unavailable()
  return token
}
function protectedDigests(config) {
  const byLength = new Map(), snapshots = []
  for (const file of config.files) {
    const loaded = readProtected(file, config.reader_uid)
    try {
      if (loaded.bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) unavailable()
      const text = new TextDecoder('utf-8', { fatal: true }).decode(loaded.bytes)
      let parsed
      for (const selector of file.selectors) {
        if (selector.kind !== 'whole-utf8' && parsed === undefined) parsed = parseStrictJson(text, { maxBytes: MAX_FILE_BYTES, maxDepth: 32 })
        const selectedValue = selector.kind === 'whole-utf8' ? text : pointerValue(parsed, selector.pointer)
        const literal = selector.kind === 'url-query-token' ? launchToken(selectedValue) : selectedValue
        for (const projected of new Set([literal, literal.trim()])) {
          const bytes = Buffer.from(projected, 'utf8')
          try {
            if (bytes.length < 1 || bytes.length > MAX_TEXT_BYTES) unavailable()
            if (!byLength.has(bytes.length)) byLength.set(bytes.length, new Set())
            byLength.get(bytes.length).add(digest(bytes))
          } finally { bytes.fill(0) }
        }
      }
      snapshots.push([file, loaded.before, loaded.ancestors])
    } finally { loaded.storage.fill(0) }
  }
  for (const [file, before, ancestors] of snapshots) {
    const current = fs.lstatSync(file.path)
    checkFile(current, file.owner_uid)
    if (!identity(before, current)) unavailable()
    recheckAncestors(ancestors)
  }
  return byLength
}
function textBytes(text) {
  if (typeof text !== 'string' || !text.isWellFormed() || !text.trim()
    || /[\u0000-\u0008\u000b-\u001f\u007f]/u.test(text)) refused()
  const bytes = Buffer.from(text, 'utf8')
  if (bytes.length > MAX_TEXT_BYTES) refused()
  return bytes
}
function shaped(text) {
  return secretShapesIn(text).length > 0 || /\b[0-9a-f]{32,}\b/iu.test(text)
    || /-----BEGIN[^\r\n]*PRIVATE KEY-----/u.test(text)
    || /\b(?:Bearer\s+|(?:token|api[_-]?key|secret|password)\s*[:=]\s*)\S+/iu.test(text)
}

/** Synchronous host closure; config has paths/selectors, never precomputed secrets.
 * Inputs are read only when this host method is invoked. Unsupported encodings,
 * stale custody and missing/malformed policy always refuse. No digest exporter.
 */
export function createProtectedPostPolicy(input) {
  let config
  try { config = captureConfig(input) } catch { unavailable() }
  const forbiddenDigestCheck = text => {
    try {
      if (process.getuid?.() !== config.reader_uid) unavailable()
      const bytes = textBytes(text)
      try {
        if (shaped(text)) return true
        const forbidden = protectedDigests(config)
        for (const [length, hashes] of forbidden) {
          for (let start = 0; start + length <= bytes.length; start++) {
            if (hashes.has(digest(bytes.subarray(start, start + length)))) return true
          }
        }
        return false
      } finally { bytes.fill(0) }
    } catch (error) { if (error instanceof PostPolicyError) throw error; unavailable() }
  }
  const assertAllowed = text => { if (forbiddenDigestCheck(text)) refused() }
  return Object.freeze({ assertAllowed, forbiddenDigestCheck })
}
