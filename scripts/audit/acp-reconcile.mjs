#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Adapted from aumara-xyz/aukora-phi a099901ad5a2d623c5343263de6ae5f9994d3159,
// core/acp/reconcile.ts. Compares supplied declarations and gate decisions; grants no authority.
import { readFileSync } from 'node:fs'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { argsDigest } from '../../plugins/aukora-action-gate/lib/receipts.mjs'
import { parseStrictText } from '../../plugins/aukora-kira/lib/strict-read.mjs'

export const REFUSE = Object.freeze({
  SESSION: 'acp-reconcile:session-required',
  READ: 'acp-reconcile:input-unreadable',
  JSON: 'acp-reconcile:malformed-json',
  ACP: 'acp-reconcile:malformed-update',
  RECEIPT: 'acp-reconcile:malformed-receipt',
  DUPLICATE: 'acp-reconcile:duplicate-call-id',
  SEGMENT: 'acp-reconcile:incomplete-segment',
  EFFECT: 'acp-reconcile:malformed-effect-window',
  USAGE: 'acp-reconcile:usage',
})
const LIMIT = 'Supplied records only; receipt authentication and log completeness are unchecked. '
  + 'An allow decision does not prove execution or owner approval. File changes do not say which process changed them. '
  + 'Effect accounting recognizes write/write_file/edit/edit_file/notebook_edit and str_replace_editor mutations only, '
  + 'using lexical paths without alias resolution. Accounted paths are declarations, not proven effects. '
  + 'No containment or authority is established.'
const PATH_FIELDS = ['file_path', 'path', 'notebook_path', 'filePath', 'target']
const NON_TOOL_UPDATES = new Set(['agent_thought_chunk', 'agent_message_chunk', 'user_message_chunk',
  'plan', 'available_commands_update', 'current_mode_update'])
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const text = value => typeof value === 'string' && value.trim().length > 0
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const failure = (code, input, line = null) => ({ ok: false, kind: 'uninspected', agrees: false, code, input, line, limit: LIMIT })

function readInput(path, input, jsonl = true) {
  let raw
  try {
    if (!text(path)) return failure(REFUSE.READ, input)
    raw = readFileSync(path, 'utf8')
  } catch { return failure(REFUSE.READ, input) }
  const rows = []
  const lines = jsonl ? raw.split('\n') : [raw]
  for (let index = 0; index < lines.length; index++) {
    if (jsonl && !lines[index].trim()) continue
    let value
    try { value = parseStrictText(lines[index], input) } catch { return failure(REFUSE.JSON, input, index + 1) }
    if (!object(value)) return failure(REFUSE.JSON, input, index + 1)
    rows.push({ value, line: index + 1 })
  }
  return { ok: true, rows }
}

export function acpToolCalls(updatesPath, session) {
  if (!text(session)) return failure(REFUSE.SESSION, 'session')
  const read = readInput(updatesPath, 'updates')
  if (!read.ok) return read
  const calls = []
  const ids = new Set()
  for (const { value: row, line } of read.rows) {
    const params = row.params
    const update = params?.update
    if (row.method !== 'session/update' || !object(params) || !text(params.sessionId)
      || !object(update) || !text(update.sessionUpdate)) return failure(REFUSE.ACP, 'updates', line)
    if (NON_TOOL_UPDATES.has(update.sessionUpdate)) continue
    if (update.sessionUpdate === 'tool_call_update') {
      if (!text(update.toolCallId) || update.rawInput !== undefined
        || (params.sessionId === session && !ids.has(update.toolCallId))) return failure(REFUSE.ACP, 'updates', line)
      continue
    }
    if (update.sessionUpdate !== 'tool_call') return failure(REFUSE.ACP, 'updates', line)
    const input = update.rawInput
    if (!text(update.toolCallId) || !text(update.title) || !object(input)
      || PATH_FIELDS.some(key => Object.hasOwn(input, key)
        && (typeof input[key] !== 'string' || input[key].includes('\0')))) return failure(REFUSE.ACP, 'updates', line)
    if (params.sessionId !== session) continue
    if (ids.has(update.toolCallId)) return failure(REFUSE.DUPLICATE, 'updates', line)
    ids.add(update.toolCallId)
    const tool = update.title.toLowerCase()
    const mutating = ['write', 'write_file', 'edit', 'edit_file', 'notebook_edit'].includes(tool)
      || (tool === 'str_replace_editor' && ['create', 'str_replace', 'insert', 'undo_edit'].includes(input.command))
    calls.push({ id: update.toolCallId, name: update.title, argsDigest: argsDigest(input), mutating,
      paths: PATH_FIELDS.map(key => input[key]).filter(value => typeof value === 'string' && value.length > 0) })
  }
  return { ok: true, calls }
}

function gateReceipts(receiptsPath, session) {
  const read = readInput(receiptsPath, 'receipts')
  if (!read.ok) return read
  const entries = []
  const ids = new Set()
  for (const { value: row, line } of read.rows) {
    if (row.op === 'segment') return failure(REFUSE.SEGMENT, 'receipts', line)
    // Read the action-gate's existing tool.decision shape, never donor verdict/path records.
    if (row.op !== 'tool.decision' || row.by !== 'aukora-action-gate/v1'
      || !text(row.session) || !text(row.callId) || !text(row.tool) || !hex(row.argsDigest)
      || !['allow', 'deny'].includes(row.decision) || typeof row.nested !== 'boolean'
      || !text(row.rule) || !text(row.kernelCode) || !text(row.at) || !Number.isFinite(Date.parse(row.at))
      || !Number.isSafeInteger(row.sequence) || row.sequence < 1 || !text(row.prev) || !hex(row.hash)) {
      return failure(REFUSE.RECEIPT, 'receipts', line)
    }
    if (row.session !== session) continue
    if (ids.has(row.callId)) return failure(REFUSE.DUPLICATE, 'receipts', line)
    ids.add(row.callId)
    entries.push({ id: row.callId, name: row.tool, argsDigest: row.argsDigest, decision: row.decision })
  }
  return { ok: true, entries }
}

function repoKey(root, path) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) return null
  const key = relative(root, resolve(root, path)).split(sep).join('/')
  return key === '' || key === '..' || key.startsWith('../') || isAbsolute(key) ? null : key
}

function validEffect(effect) {
  if (!object(effect) || !text(effect.repoRoot) || !isAbsolute(effect.repoRoot) || effect.repoRoot.includes('\0')) return false
  const diff = effect.diff
  if (!object(diff) || !Array.isArray(diff.changed) || !Array.isArray(diff.unknown) || !object(diff.ruleFor)) return false
  const paths = [...diff.changed, ...diff.unknown]
  // Supplied sweep keys must be unique, repo-relative and disjoint from unknowns.
  return paths.every(path => typeof path === 'string' && repoKey(effect.repoRoot, path) === path)
    && new Set(paths).size === paths.length
    && Object.values(diff.ruleFor).every(rule => rule === null || typeof rule === 'string')
}

export function reconcile(updatesPath, receiptsPath, session, effect) {
  const acp = acpToolCalls(updatesPath, session)
  if (!acp.ok) return acp
  const receipts = gateReceipts(receiptsPath, session)
  if (!receipts.ok) return receipts
  if (effect !== undefined && !validEffect(effect)) return failure(REFUSE.EFFECT, 'effects')
  const pool = new Map(receipts.entries.map(entry => [entry.id, entry]))
  const missingFromChain = []
  const allowed = new Set(), refused = new Set(), declared = new Set()
  for (const call of acp.calls) {
    const receipt = pool.get(call.id)
    const matched = receipt !== undefined && receipt.name === call.name && receipt.argsDigest === call.argsDigest
    if (matched) pool.delete(call.id)
    else missingFromChain.push(call)
    if (effect && call.mutating) {
      for (const path of call.paths) {
        const key = repoKey(effect.repoRoot, path)
        if (key === null) continue
        declared.add(key)
        if (matched) (receipt.decision === 'allow' ? allowed : refused).add(key)
      }
    }
  }
  const unmatchedInChain = [...pool.values()]
  const recordsConcur = missingFromChain.length === 0 && unmatchedInChain.length === 0
  const recordKind = recordsConcur ? 'agree' : receipts.entries.length === 0 ? 'no-record' : 'gap'
  const undeclaredPaths = [], accountedPaths = []
  const unknownPaths = effect ? [...effect.diff.unknown] : []
  for (const path of effect?.diff.changed ?? []) {
    if (declared.has(path) && (allowed.has(path) || !refused.has(path))) accountedPaths.push(path)
    else undeclaredPaths.push({ path, rule: Object.hasOwn(effect.diff.ruleFor, path) ? effect.diff.ruleFor[path] : null })
  }
  return {
    ok: true, session, acpCalls: acp.calls.length, chainEntries: receipts.entries.length,
    missingFromChain, unmatchedInChain, refusals: receipts.entries.filter(entry => entry.decision === 'deny').length,
    recordsConcur, recordKind, kind: undeclaredPaths.length ? 'undeclared' : recordKind,
    agrees: recordsConcur && undeclaredPaths.length === 0 && unknownPaths.length === 0,
    effectsChecked: effect !== undefined, undeclaredPaths, accountedPaths, unknownPaths,
    matching: 'session, call ID, exact tool name and argument digest', limit: LIMIT,
  }
}

// Usage: node scripts/audit/acp-reconcile.mjs UPDATES.jsonl RECEIPTS.jsonl SESSION [EFFECTS.json]
export function main(argv) {
  if (argv.length !== 3 && argv.length !== 4) return failure(REFUSE.USAGE, 'arguments')
  let effect
  if (argv.length === 4) {
    const read = readInput(argv[3], 'effects', false)
    if (!read.ok) return read
    effect = read.rows[0].value
  }
  return reconcile(argv[0], argv[1], argv[2], effect)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const result = main(process.argv.slice(2))
  console.log(JSON.stringify(result, null, 2))
  process.exitCode = !result.ok ? 2 : result.agrees ? 0 : 1
}
