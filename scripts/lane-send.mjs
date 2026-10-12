#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Sends one bounded loopback request using the existing owner-only token reader.
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readTokenFile } from '../plugins/aukora-eye/lib/token-file.mjs'
import { LANE_REFUSE } from '../apps/aukora-desktop/lane-dispatch.mjs'

const LIMIT_BYTES = 64 * 1024
const SESSION = /^session-[0-9a-f-]{36}$/u
const LANE = /^[a-z][a-z0-9-]{0,31}$/u
const DOOR_CODES = new Set(Object.values(LANE_REFUSE))
const CLIENT_CODES = new Set([
  'lane.port-absent', 'lane.port-invalid', 'lane.no-such-session', 'lane.ambiguous-session',
  'lane.arguments', 'lane.lane-required', 'lane.session-required', 'lane.text-required',
  'lane.bad-origin', 'lane.bad-session', 'lane.body-too-large', 'lane.redirect-refused',
  'lane.response-too-large', 'lane.response-invalid', 'lane.refused', 'lane.send-timeout',
  'lane.send-failed', 'lane.token-file-absent', 'lane.token-file-unreadable',
  'lane.token-file-symlink', 'lane.token-file-not-regular', 'lane.token-file-owner',
  'lane.token-file-mode', 'lane.token-file-empty',
])

function refuse(code) {
  throw Object.assign(new Error(code), { code })
}

export function listSessions(stateRoot) {
  const directory = join(stateRoot, 'home', 'storages', 'session_projcache', 'sessions')
  if (!existsSync(directory)) return []
  const rows = []
  for (const name of readdirSync(directory)) {
    if (!name.endsWith('.json') || !SESSION.test(name.slice(0, -5))) continue
    try {
      const { record } = JSON.parse(readFileSync(join(directory, name), 'utf8'))
      const title = record?.rows?.title?.val
      const lastPromptAt = record?.rows?.sessionListMetadata?.val?.lastPromptAt
      rows.push({
        session: name.slice(0, -5),
        title: typeof title === 'string' ? title : '',
        lastPromptAt: Number.isFinite(lastPromptAt) && Math.abs(lastPromptAt) <= 8.64e15 ? lastPromptAt : 0,
      })
    } catch { /* Incomplete projection records are not candidates. */ }
  }
  return rows.sort((left, right) => right.lastPromptAt - left.lastPromptAt)
}

export function resolveTitle(rows, title) {
  const exact = rows.filter(row => row.title === title)
  const matches = exact.length ? exact : rows.filter(row => row.title.includes(title))
  if (matches.length === 0) refuse('lane.no-such-session')
  if (matches.length > 1) refuse('lane.ambiguous-session')
  return matches[0].session
}

const GOAL_SUBCOMMANDS = ['clear', 'resume', 'status', 'pause', 'stop', 'list']
export function isGoalSubcommand(text) {
  return typeof text === 'string' && GOAL_SUBCOMMANDS.includes(
    /^\/goal\s+([a-z]+)\s*$/iu.exec(text.trim())?.[1]?.toLowerCase())
}

function isGoal(text) {
  return typeof text === 'string' && /^\/goal\b/iu.test(text.trim()) && !isGoalSubcommand(text)
}

export function completionConditionOfGoal(text) {
  if (!isGoal(text)) return null
  return /\bDONE\s+WHEN\s*:[^\S\r\n]*([^\r\n]*)/iu.exec(text)?.[1]?.trim() || null
}

const PERMISSION_VERBS = [
  ['push', 'push'], ['merge', 'merge'], ['cutover', 'cut[- ]?over'],
  ['publish', 'publish'], ['release-cut', '(?:cut|ship|tag)\\s+(?:a\\s+|the\\s+)?release'], ['spend', 'spend'],
]
const NEGATION = /\b(?:no|not|never|without|cannot|can't|don't|forbid(?:den)?|prohibit(?:ed)?)\b[^.;!?,\n]{0,60}$/iu
const NEGATION_AFTER = /^\s+(?:is|are|was|were)\s+(?:forbidden|prohibited|banned|not allowed|disallowed)\b/iu
const CLAUSE = /[.;!?\n]|\b(?:but|however|yet|although|though|instead|rather|except|then)\b/iu
const LIST_VERB = new RegExp(`^(?:${PERMISSION_VERBS.map(([, pattern]) => pattern).join('|')})$`, 'iu')

function negated(before, after) {
  if (NEGATION_AFTER.test(after)) return true
  const clauses = before.split(CLAUSE)
  const parts = clauses.at(-1).split(/,|\b(?:and|or)\b/iu)
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    if (NEGATION.test(parts[index])) return true
    if (parts[index].trim() !== '' && !LIST_VERB.test(parts[index].trim())) return false
  }
  return false
}

// Prose findings are advisory; they neither grant authority nor prove a goal will stop.
export function permissionsCarriedByGoal(text) {
  if (!isGoal(text)) return []
  return PERMISSION_VERBS.filter(([, verb]) => {
    const pattern = new RegExp(`(?<![\\w/.-])${verb}(?![\\w/.-])`, 'giu')
    return [...text.matchAll(pattern)].some(match =>
      !negated(text.slice(0, match.index), text.slice(match.index + match[0].length)))
  }).map(([verb]) => verb)
}

function readPort(directory) {
  let value
  try { value = readFileSync(join(directory, 'port'), 'utf8').trim() }
  catch { refuse('lane.port-absent') }
  if (!/^[0-9]{1,5}$/u.test(value) || Number(value) < 1 || Number(value) > 65535) refuse('lane.port-invalid')
  return Number(value)
}

export async function sendLane({ stateRoot, lane, session, text, fetchImpl = fetch, timeoutMs = 10_000 }) {
  if (typeof lane !== 'string' || !LANE.test(lane)) refuse('lane.bad-origin')
  if (typeof session !== 'string' || !SESSION.test(session)) refuse('lane.bad-session')
  if (typeof text !== 'string' || text.trim() === '') refuse('lane.text-required')
  const payload = JSON.stringify({ session, text, origin: lane })
  if (Buffer.byteLength(payload) > LIMIT_BYTES) refuse('lane.body-too-large')
  const directory = join(stateRoot, 'lane-door')
  const token = readTokenFile({ path: join(directory, 'door.token'), prefix: 'lane' })
  const port = readPort(directory)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  let reader
  try {
    const response = await fetchImpl(`http://127.0.0.1:${port}/lane/send`, {
      method: 'POST', redirect: 'manual', signal: controller.signal,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: payload,
    })
    if (response.status >= 300 && response.status < 400) refuse('lane.redirect-refused')
    reader = response.body?.getReader()
    if (!reader) refuse('lane.response-invalid')
    const chunks = []
    let bytes = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > LIMIT_BYTES) refuse('lane.response-too-large')
      chunks.push(value)
    }
    let body
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) }
    catch { refuse('lane.response-invalid') }
    if (!response.ok || body?.ok !== true) refuse(DOOR_CODES.has(body?.code) ? body.code : 'lane.refused')
    if (!['prompt', 'command:goal', 'command:compact'].includes(body.kind) || body.session !== session) {
      refuse('lane.response-invalid')
    }
    return { ok: true, kind: body.kind, session }
  } catch (error) {
    if (controller.signal.aborted) refuse('lane.send-timeout')
    if (CLIENT_CODES.has(error?.code) || DOOR_CODES.has(error?.code)) throw error
    refuse('lane.send-failed')
  } finally {
    clearTimeout(timer)
    controller.abort()
    void reader?.cancel().catch(() => {})
  }
}

function parseArgs(argv) {
  const options = { text: [] }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--') { options.text.push(...argv.slice(index + 1)); break }
    if (['--lane', '--session', '--title'].includes(arg)) {
      const key = arg.slice(2)
      const value = argv[++index]
      if (options[key] !== undefined || !value || value.startsWith('--')) refuse('lane.arguments')
      options[key] = value
    } else if (arg === '--list') options.list = true
    else if (arg.startsWith('--')) refuse('lane.arguments')
    else options.text.push(arg)
  }
  if (options.session !== undefined && options.title !== undefined) refuse('lane.arguments')
  if (options.list && (options.lane || options.session || options.title || options.text.length)) refuse('lane.arguments')
  return options
}

export async function main(argv, {
  stateRoot = process.env.AUKORA_STATE_ROOT ?? join(homedir(), 'Library', 'Application Support', 'AUKORA', 'state'),
  fetchImpl = fetch, timeoutMs, stdout = console.log, stderr = console.error,
} = {}) {
  try {
    const options = parseArgs(argv)
    if (options.list) {
      const rows = listSessions(stateRoot)
      if (rows.length === 0) stdout('no sessions in the projection cache')
      for (const row of rows.slice(0, 40)) {
        stdout(`${row.session}  ${new Date(row.lastPromptAt).toISOString()}  ${JSON.stringify(row.title)}`)
      }
      return 0
    }
    if (!options.lane) refuse('lane.lane-required')
    if (!options.session && !options.title) refuse('lane.session-required')
    const text = options.text.join(' ')
    const carried = permissionsCarriedByGoal(text)
    if (carried.length) stderr(`advisory goal-carries-permission: ${carried.join(', ')}; prose grants no authority`)
    if (isGoal(text) && completionConditionOfGoal(text) === null) {
      stderr('advisory goal-without-condition: add DONE WHEN: <condition>; prose does not enforce completion')
    }
    const session = options.session ?? resolveTitle(listSessions(stateRoot), options.title)
    const result = await sendLane({ stateRoot, lane: options.lane, session, text, fetchImpl, timeoutMs })
    stdout(`lane accepted: ${result.kind} into ${result.session}`)
    return 0
  } catch (error) {
    const code = CLIENT_CODES.has(error?.code) || DOOR_CODES.has(error?.code) ? error.code : 'lane.client-failed'
    stderr(`${code}: send not confirmed; if dispatch began, outcome may be unknown; no automatic retry`)
    return 1
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2))
}
