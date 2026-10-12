// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Viviani / Aumara
// Rewritten from EPSILON 62dc809ce app/lib/continuitySource.ts (working-tree version).
// Apache-2.0 text: ../../../licenses/upstream/prime-source/packages/execution/licenses/Apache-2.0.txt
/** Append unsigned session metadata; derive the head and overlap hint from the memory ledger. */
import { isAbsolute, join } from 'node:path'
import { AURA_RECORD_DOMAIN, auraEntryHash, chainAuraEntries } from './memory-owner.mjs'
import { canonicalJSON } from './record.mjs'
import { STORE_PATHS } from './memory-store.mjs'
import { durableAppend, ensureDirectory, parseStrictText, readBytesStrict, readTextStrict, withFileLock } from './strict-read.mjs'

const OP = 'continuity-touch/v1'
const WINDOW_MS = 15 * 60 * 1000

function refuse(code) {
  throw Object.assign(new Error(`kira.continuity:${code}`), { code: `kira.continuity:${code}` })
}

function ledgerPath(stateDir) {
  if (typeof stateDir !== 'string' || !isAbsolute(stateDir) || /[\u0000-\u001f\u007f]/u.test(stateDir)) refuse('state-root-invalid')
  return join(stateDir, STORE_PATHS.rememberedAura)
}

function nextHead(previous, { sessionId, messageCount, ts }) {
  if (typeof sessionId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(sessionId)) refuse('session-invalid')
  if (!Number.isSafeInteger(messageCount) || messageCount < 0) refuse('message-count-invalid')
  const time = typeof ts === 'string' ? Date.parse(ts) : NaN
  if (!Number.isFinite(time) || new Date(time).toISOString() !== ts) refuse('timestamp-invalid')
  const ageMs = previous === null ? null : time - Date.parse(previous.ts)
  if (ageMs !== null && ageMs < 0) refuse('timestamp-regressed')
  const possibleFork = previous !== null && previous.sessionId !== sessionId && ageMs <= WINDOW_MS
    ? { detected: true, previousSessionId: previous.sessionId, previousTs: previous.ts, ageSeconds: Math.round(ageMs / 1000) }
    : null
  return { ts, sessionId, messageCount, possibleFork, grantsAuthority: false }
}

function readHead(file) {
  let text
  try { text = readTextStrict(file, { label: 'continuity memory ledger' }) }
  catch (error) {
    if (error?.code === 'ENOENT') return null
    refuse('ledger-unreadable')
  }
  if (text === '') return null
  if (!text.endsWith('\n')) refuse('ledger-torn')
  let prev = AURA_RECORD_DOMAIN, sequence = 0, head = null
  for (const line of text.slice(0, -1).split('\n')) {
    let entry
    try { entry = parseStrictText(line, 'continuity memory ledger') }
    catch { refuse('ledger-malformed') }
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) refuse('ledger-malformed')
    const { prev: named, hash, ...body } = entry
    if (named !== prev || body.sequence !== ++sequence || auraEntryHash(prev, body) !== hash) refuse('ledger-broken')
    prev = hash
    if (body.op !== OP) continue
    const expected = nextHead(head, body)
    if (canonicalJSON(body) !== canonicalJSON({ op: OP, tier: 'remembered', ...expected, sequence })) refuse('head-invalid')
    head = expected
  }
  return head
}

export function readContinuityHead({ stateDir } = {}) {
  return readHead(ledgerPath(stateDir))
}

export function touchContinuityHead({ stateDir, ...input } = {}) {
  const file = ledgerPath(stateDir)
  if (Object.keys(input).some(key => !['sessionId', 'messageCount', 'ts'].includes(key))) refuse('fields-invalid')
  nextHead(null, { ...input, ts: input.ts === undefined ? new Date().toISOString() : input.ts })
  const directory = join(stateDir, STORE_PATHS.remembered)
  ensureDirectory(directory)
  return withFileLock(file, () => {
    const snapshot = { ...input, ts: input.ts === undefined ? new Date().toISOString() : input.ts }
    const head = nextHead(readHead(file), snapshot)
    const [entry] = chainAuraEntries(stateDir, [{ op: OP, tier: 'remembered', ...head }], { file })
    durableAppend(file, `${JSON.stringify(entry)}\n`, {
      dir: directory, readExisting: path => readBytesStrict(path, { label: 'continuity memory ledger' }).bytes,
    })
    return head
  })
}
