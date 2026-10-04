#!/usr/bin/env node
// Source-only, read-only aid for an explicit one-time operator edit. No discovery or writer.
// The returned text may contain credentials: callers must keep it private and never log it.
import { closeSync, constants as FS, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

export const MAX_PREVIEW_CONFIG_BYTES = 64 * 1024
export const MAX_PREVIEW_CONFIG_DEPTH = 64

class MigrationRefusal extends Error {
  constructor(code) {
    super(`preview-config-migration:${code}`)
    this.code = this.message
  }
}

const refuse = code => { throw new MigrationRefusal(code) }

/** Validate every object's decoded key names and retain the top-level member spans. */
function rootMembers(text) {
  let offset = 0
  let members
  const whitespace = () => { while (/[\x20\t\r\n]/u.test(text[offset] ?? '')) offset += 1 }
  const string = () => {
    const start = offset++
    while (text[offset] !== '"') offset += text[offset] === '\\' ? 2 : 1
    offset += 1
    return JSON.parse(text.slice(start, offset))
  }
  const value = depth => {
    if (depth > MAX_PREVIEW_CONFIG_DEPTH) refuse('json-depth-refused')
    whitespace()
    if (text[offset] === '"') { string(); return }
    if (text[offset] === '[') {
      offset += 1
      whitespace()
      if (text[offset] !== ']') for (;;) {
        value(depth + 1)
        whitespace()
        if (text[offset] === ']') break
        offset += 1
      }
      offset += 1
      return
    }
    if (text[offset] === '{') {
      offset += 1
      const keys = new Set()
      const objectMembers = []
      let beforeComma
      for (;;) {
        const start = offset
        whitespace()
        if (text[offset] === '}') { offset += 1; break }
        const key = string()
        if (keys.has(key)) refuse('json-duplicate-key-refused')
        keys.add(key)
        whitespace()
        offset += 1 // The colon: JSON.parse already validated the grammar.
        whitespace()
        const valueStart = offset
        value(depth + 1)
        const end = offset
        whitespace()
        const afterComma = text[offset] === ',' ? offset : undefined
        objectMembers.push({ key, start, valueStart, end, beforeComma, afterComma })
        if (afterComma === undefined) { offset += 1; break }
        beforeComma = offset++
      }
      if (depth === 1) members = objectMembers
      return
    }
    while (offset < text.length && !/[\x20\t\r\n,\]}]/u.test(text[offset])) offset += 1
  }
  value(1)
  return members
}

/**
 * Remove ONLY an own top-level legacy field whose JSON value is the literal false.
 * No file is read or written. All remaining value bytes, including URL tokens and
 * numeric spellings, are preserved; no preview waiver or approval is added.
 */
export function planLegacyPreviewConfigMigration(text) {
  if (typeof text !== 'string') refuse('json-malformed')
  if (Buffer.byteLength(text, 'utf8') > MAX_PREVIEW_CONFIG_BYTES) refuse('json-size-refused')
  let config
  try { config = JSON.parse(text) } catch { refuse('json-malformed') }
  if (config === null || typeof config !== 'object' || Array.isArray(config)) refuse('json-object-required')
  const members = rootMembers(text)
  if (Object.hasOwn(config, 'unsafePreviewAllowUnapproved')) refuse('unsafe-preview-setting-refused')
  if (!Object.hasOwn(config, 'allowUnapproved')) return Object.freeze({ changed: false, text })
  if (config.allowUnapproved !== false) refuse('legacy-value-refused')
  const legacy = members.find(member => member.key === 'allowUnapproved')
  if (text.slice(legacy.valueStart, legacy.end) !== 'false') refuse('legacy-value-refused')
  const start = legacy.afterComma === undefined && legacy.beforeComma !== undefined
    ? legacy.beforeComma : legacy.start
  const end = legacy.afterComma === undefined ? legacy.end : legacy.afterComma + 1
  return Object.freeze({ changed: true, text: text.slice(0, start) + text.slice(end) })
}

const unchanged = (before, after) => ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
  .every(field => before[field] === after[field])

function privateOwned(info, directory = false) {
  if (typeof process.getuid !== 'function'
    || info.uid !== BigInt(process.getuid()) || info.nlink < 1n
    || (info.mode & 0o7777n) !== (directory ? 0o700n : 0o600n)
    || (directory ? !info.isDirectory() : !info.isFile() || info.nlink !== 1n)) refuse('private-file-required')
}

/** Read exactly one explicit private file, with bounded reads and path/descriptor guards. */
export function inspectLegacyPreviewConfigFile(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path
    || /[\u0000-\u001f\u007f]/u.test(path)) refuse('absolute-config-path-required')
  let handle
  try {
    if (!Number.isInteger(FS.O_NOFOLLOW) || !Number.isInteger(FS.O_NONBLOCK)) refuse('strict-open-unavailable')
    if (realpathSync(path) !== path) refuse('canonical-config-path-required')
    const directory = dirname(path)
    const parent = lstatSync(directory, { bigint: true })
    privateOwned(parent, true)
    const named = lstatSync(path, { bigint: true })
    privateOwned(named)
    handle = openSync(path, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK)
    const opened = fstatSync(handle, { bigint: true })
    privateOwned(opened)
    if (!unchanged(named, opened)) refuse('file-changed-refused')
    if (opened.size > BigInt(MAX_PREVIEW_CONFIG_BYTES)) refuse('json-size-refused')
    const bytes = Buffer.alloc(MAX_PREVIEW_CONFIG_BYTES + 1)
    let length = 0
    for (;;) {
      const count = readSync(handle, bytes, length, bytes.length - length, null)
      if (count === 0) break
      length += count
      if (length > MAX_PREVIEW_CONFIG_BYTES) refuse('json-size-refused')
    }
    if (BigInt(length) !== opened.size || !unchanged(opened, fstatSync(handle, { bigint: true }))
      || !unchanged(opened, lstatSync(path, { bigint: true }))
      || !unchanged(parent, lstatSync(directory, { bigint: true }))
      || realpathSync(path) !== path) refuse('file-changed-refused')
    let text
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length)) }
    catch { refuse('json-malformed') }
    return planLegacyPreviewConfigMigration(text)
  } catch (error) {
    if (error instanceof MigrationRefusal) throw error
    refuse('file-refused')
  } finally {
    if (handle !== undefined) closeSync(handle)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--config') refuse('explicit-config-argument-required')
    const plan = inspectLegacyPreviewConfigFile(process.argv[3])
    process.stdout.write(plan.changed
      ? 'preview-config-migration:eligible: remove only the own allowUnapproved:false setting after a private backup; no changes made.\n'
      : 'preview-config-migration:unchanged: obsolete setting absent; no changes made.\n')
  } catch (error) {
    process.stderr.write((error instanceof MigrationRefusal ? error.code : 'preview-config-migration:file-refused')
      + '; review the explicitly named file privately; no changes made.\n')
    process.exitCode = 1
  }
}
