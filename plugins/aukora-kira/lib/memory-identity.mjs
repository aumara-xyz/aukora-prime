// SPDX-License-Identifier: AGPL-3.0-or-later
/** Read an existing deployment identity. This module creates no identity or state. */
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { readTextStrict } from './strict-read.mjs'

export const MEMORY_OVERLAY_NAME = 'kira-deployment-overlay.patch.yml'
export const UNLINKED_MEMORY_SUBJECT = 'aumlok:subject:owner'
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/u
const CONTROLS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u

/** Diagnostics name fields, never the value or contents of an owner configuration. */
export class MemoryIdentityError extends Error {
  constructor(code, field) {
    super(`memory.identity:${code}: ${field}`)
    this.name = 'MemoryIdentityError'
    this.code = `memory.identity:${code}`
    this.field = field
  }
}
const refuse = (code, field) => { throw new MemoryIdentityError(code, field) }
const usefulLine = line => line.trim() !== '' && !line.trimStart().startsWith('#')
const indentOf = line => line.length - line.trimStart().length

function scalar(raw, field) {
  const value = raw.trim()
  if (value.startsWith("'")) {
    const matched = /^'((?:[^']|'')*)'\s*(?:#.*)?$/u.exec(value)
    if (!matched) refuse('field-invalid', field)
    return matched[1].replaceAll("''", "'")
  }
  if (value.startsWith('"')) {
    const matched = /^("(?:[^"\\]|\\.)*")\s*(?:#.*)?$/u.exec(value)
    if (!matched) refuse('field-invalid', field)
    try { return JSON.parse(matched[1]) } catch { refuse('field-invalid', field) }
  }
  return value.replace(/\s+#.*$/u, '').trim()
}

function childBlock(lines, at) {
  const indentation = indentOf(lines[at])
  let end = at + 1
  while (end < lines.length && (!usefulLine(lines[end]) || indentOf(lines[end]) > indentation)) end++
  return lines.slice(at + 1, end)
}

function directField(lines, name, label, required = true) {
  const useful = lines.filter(usefulLine)
  if (!useful.length) {
    if (required) refuse('field-missing', label)
    return undefined
  }
  const indentation = Math.min(...useful.map(indentOf))
  const matches = lines.flatMap((line, index) => {
    if (!usefulLine(line) || indentOf(line) !== indentation) return []
    const match = /^\s*([A-Za-z][A-Za-z0-9]*):(?:\s*(.*))?$/u.exec(line)
    return match?.[1] === name ? [{ index, raw: match[2] ?? '' }] : []
  })
  if (matches.length > 1) refuse('field-duplicate', label)
  if (!matches.length && required) refuse('field-missing', label)
  return matches[0]
}

/**
 * Read only the exact aukora-kira row's config.memoryOwner block. The supported
 * overlay is the existing block-style deployment patch; tags/aliases and flow
 * mappings are not evaluated. Other plugins' subject/stateDir fields are ignored.
 */
export function readKiraDeploymentOverlay(text) {
  if (typeof text !== 'string' || text.includes('\t')) refuse('overlay-invalid', 'aukora-kira.config.memoryOwner')
  const lines = text.split(/\r?\n/u)
  const rows = lines.flatMap((line, index) => {
    const match = /^\s*-\s+id:\s*(.+)$/u.exec(line)
    return match && scalar(match[1], 'plugin.id') === 'aukora-kira' ? [index] : []
  })
  if (rows.length > 1) refuse('field-duplicate', 'aukora-kira')
  if (!rows.length) refuse('field-missing', 'aukora-kira.config.memoryOwner.subject')
  const row = childBlock(lines, rows[0])
  const config = directField(row, 'config', 'aukora-kira.config')
  if (config.raw !== '' && !config.raw.startsWith('#')) refuse('field-invalid', 'aukora-kira.config')
  const fields = childBlock(row, config.index)
  const owner = directField(fields, 'memoryOwner', 'aukora-kira.config.memoryOwner')
  if (owner.raw !== '' && !owner.raw.startsWith('#')) refuse('field-invalid', 'aukora-kira.config.memoryOwner')
  const memory = childBlock(fields, owner.index)
  const subject = directField(memory, 'subject', 'memoryOwner.subject')
  const stateDir = directField(memory, 'stateDir', 'memoryOwner.stateDir', false)
  return Object.freeze({
    subject: scalar(subject.raw, 'memoryOwner.subject'),
    ...(stateDir ? { stateDir: scalar(stateDir.raw, 'memoryOwner.stateDir') } : {}),
  })
}

function pathField(value, field) {
  if (typeof value !== 'string' || !isAbsolute(value) || CONTROLS.test(value)) refuse('field-invalid', field)
  return value
}

/**
 * Resolve exact existing owner fields, checking explicit and installed values
 * agree. Linux never guesses a Mac support directory. The injectable reader is
 * for pure source checks; the production reader is strict, bounded and read-only.
 */
export function resolveMemoryIdentity({ stateDir, subject, supportRoot, installed = false,
  allowLegacyPlaceholder = false, env = process.env, platform = process.platform,
  readText = readTextStrict } = {}) {
  const placeholder = subject === UNLINKED_MEMORY_SUBJECT
  if (subject !== undefined && subject !== '' && !placeholder
    && (typeof subject !== 'string' || !SUBJECT.test(subject))) {
    refuse('field-invalid', 'memoryOwner.subject')
  }
  // The launcher forwards AUKORA_SUPPORT_ROOT to the backend and not AUKORA_STATE (measured on the Nebius pilot,
  // 2026-10-04: Kira refused field-missing with the overlay in place). It is consulted only when the installed
  // identity is needed, so a complete explicit composition stays isolated from the support root.
  const root = supportRoot ?? env?.AUKORA_STATE
    ?? (installed ? env?.AUKORA_SUPPORT_ROOT : undefined)
    ?? (installed && platform === 'darwin' ? join(homedir(), 'Library/Application Support/AUKORA') : undefined)
  let owner
  if (root !== undefined) {
    const absoluteRoot = pathField(root, 'AUKORA_STATE/supportRoot')
    let text
    try { text = readText(join(absoluteRoot, MEMORY_OVERLAY_NAME), { maxBytes: 64 * 1024 }) }
    catch (error) {
      if (error?.code !== 'ENOENT') refuse('configuration-unreadable', 'kira-deployment-overlay.patch.yml')
    }
    if (text !== undefined) {
      owner = readKiraDeploymentOverlay(text)
      if (typeof owner.subject !== 'string' || !SUBJECT.test(owner.subject)) refuse('field-invalid', 'memoryOwner.subject')
      if (owner.stateDir !== undefined) pathField(owner.stateDir, 'memoryOwner.stateDir')
    }
  }
  if (owner && subject !== undefined && subject !== '' && !placeholder && subject !== owner.subject) {
    refuse('field-mismatch', 'memoryOwner.subject')
  }
  if (owner?.stateDir !== undefined && stateDir !== undefined && stateDir !== owner.stateDir) {
    refuse('field-mismatch', 'memoryOwner.stateDir')
  }
  const resolvedSubject = owner?.subject ?? subject
  if (typeof resolvedSubject !== 'string' || !SUBJECT.test(resolvedSubject)) {
    if (!(placeholder && allowLegacyPlaceholder && platform === 'darwin' && owner === undefined)) {
      refuse('field-missing', 'memoryOwner.subject (existing owner deployment configuration)')
    }
  }
  const resolvedState = stateDir ?? owner?.stateDir
  if (resolvedState === undefined || resolvedState === '') refuse('field-missing', 'memoryOwner.stateDir')
  return Object.freeze({ stateDir: pathField(resolvedState, 'memoryOwner.stateDir'), subject: resolvedSubject })
}
