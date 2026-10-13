#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Drain release Kira index batches without deleting index content or exposing note bodies.
import { realpathSync } from 'node:fs'
import { isAbsolute, relative, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isMainModule } from '../lib/is-main.mjs'
import { readReleaseConfig } from './release-recall-probe.mjs'

const ID = /^(?:rem|kira):[0-9a-f]{64}$/u
const fail = code => { throw Object.assign(new Error(code), { code: `kira.viking-sync:${code}` }) }
const codeOf = error => /^kira\.viking-sync:[a-z-]+$/u.test(error?.code) ? error.code : 'kira.viking-sync:operation-failed'
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0
const ids = values => [...new Set((Array.isArray(values) ? values : []).filter(id => typeof id === 'string' && ID.test(id)))].sort()
const token = value => typeof value === 'string' && /^[a-z][a-z0-9._:-]{0,63}$/u.test(value) ? value : undefined
const refusal = value => typeof value === 'string' && value.includes('is not valid UTF-8; a lossy decode')
  ? 'invalid-utf8' : token(value) ?? 'index-failed'
function failureRow(value) {
  if (!ids([value?.id]).length) return null
  const row = { id: value.id, reason: refusal(value.reason) }
  if (Number.isInteger(value.httpStatus) && value.httpStatus >= 100 && value.httpStatus <= 599) row.httpStatus = value.httpStatus
  if (token(value.vectorStatus)) row.vectorStatus = value.vectorStatus
  if (Number.isSafeInteger(value.attempts) && value.attempts >= 0) row.attempts = value.attempts
  if (Number.isFinite(value.nextRetryAt) && value.nextRetryAt >= 0) row.nextRetryAt = value.nextRetryAt
  if (value.capped === true) row.capped = true
  if (['acknowledgement', 'content-bytes', 'document', 'note-content-hash', 'part-hash'].includes(value.comparison)) row.comparison = value.comparison
  for (const name of ['expectedBytes', 'actualBytes']) {
    if ((Number.isSafeInteger(value[name]) && value[name] >= 0) || value[name] === 'unknown') row[name] = value[name]
  }
  if ((Number.isSafeInteger(value.firstDiffByte) && value.firstDiffByte >= -1) || value.firstDiffByte === 'unknown') row.firstDiffByte = value.firstDiffByte
  if (['prefix', 'suffix', 'infix', 'absent'].includes(value.expectedPlacement)) row.expectedPlacement = value.expectedPlacement
  if (/^[0-9a-f]{64}$/u.test(value.extraBytesSha256)) row.extraBytesSha256 = value.extraBytesSha256
  return row
}
const eligible = report => Number.isSafeInteger(report.retryable) ? count(report.retryable) : count(report.pending)
const failureCounts = report => {
  const counts = new Map()
  for (const value of report.recordFailures ?? []) {
    const row = failureRow(value)
    if (row) counts.set(row.reason, (counts.get(row.reason) ?? 0) + 1)
  }
  return [...counts].sort(([a], [b]) => a.localeCompare(b)).map(([reason, total]) => `${reason}:${total}`).join(',') || 'none'
}

export function syncArgs(argv) {
  if (![1, 3].includes(argv.length) || (argv.length === 3 && argv[1] !== '--max-minutes')) fail('usage')
  if (!isAbsolute(argv[0])) fail('release-not-absolute')
  const maxMinutes = argv.length === 3 ? Number(argv[2]) : 5
  if (!Number.isFinite(maxMinutes) || maxMinutes <= 0 || maxMinutes > 1440) fail('max-minutes-invalid')
  return { release: argv[0], maxMinutes }
}

function releaseStoreUrl(loaded) {
  const file = realpathSync(fileURLToPath(new URL('./tracked-memory.mjs', loaded.kiraUrl)))
  const suffix = relative(loaded.release, file)
  if (suffix === '..' || suffix.startsWith(`..${sep}`) || isAbsolute(suffix)) fail('release-file-outside')
  return pathToFileURL(file).href
}

export function syncTransport(config, signal, request = globalThis.fetch) {
  const endpoint = new URL(config.url)
  if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname)
    || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/') fail('local-url-required')
  return async (url, options = {}) => {
    if ((options.method ?? 'GET').toUpperCase() === 'DELETE') fail('delete-refused')
    if (new URL(url).origin !== endpoint.origin) fail('request-outside')
    return request(url, { ...options, redirect: 'error', signal: options.signal ? AbortSignal.any([options.signal, signal]) : signal })
  }
}

export function syncLine(report, final = false) {
  const line = `${final ? 'kira-viking-sync' : 'progress'}: indexed=${count(report.indexed)} pending=${count(report.pending)} failed=${ids(report.failedIds).length}`
  return final ? `${line} failure-reasons=${failureCounts(report)}` : line
}

export function syncFailureLine(value, skipped = false) {
  const row = failureRow(value)
  if (!row) return null
  const details = Object.entries(row).filter(([key]) => key !== 'id').map(([key, value]) => `${key}=${value}`).join(' ')
  return `${skipped ? 'skipped-id' : 'failed-id'}: ${row.id} ${details}`
}

export async function syncRelease({ release, maxMinutes = 5, signal, onProgress = () => {} }, { request = globalThis.fetch, now = Date.now } = {}) {
  if (!Number.isFinite(maxMinutes) || maxMinutes <= 0 || maxMinutes > 1440) fail('max-minutes-invalid')
  const controller = new AbortController(), started = now(), deadline = started + maxMinutes * 60_000
  const interrupted = () => controller.abort()
  signal?.addEventListener('abort', interrupted, { once: true })
  if (signal?.aborted) interrupted()
  const timer = setTimeout(interrupted, maxMinutes * 60_000)
  timer.unref()
  try {
    const loaded = await readReleaseConfig(release)
    const storeUrl = releaseStoreUrl(loaded)
    const { readConfig } = await import(loaded.kiraUrl)
    const effective = readConfig(loaded.config)
    if (!effective.openVikingHome || !effective.memoryOwner) fail('release-openviking-unconfigured')
    const { readBridgeConfig, OPERATOR_SYNC_VERSION } = await import(loaded.bridgeUrl)
    if (OPERATOR_SYNC_VERSION !== 2) fail('release-sync-unsupported')
    const config = readBridgeConfig(effective.openVikingHome)
    if (!config.configured) fail('bridge-configuration-unavailable')
    const { createTrackedMemory } = await import(storeUrl)
    const memory = createTrackedMemory({ ...effective.memoryOwner, config, now, fetch: syncTransport(config, controller.signal, request) })
    const failedIds = new Set(), skipped = new Set(), recordFailures = new Map()
    const rememberFailures = report => {
      for (const value of report.recordFailures ?? []) {
        const row = failureRow(value)
        if (row) { recordFailures.set(row.id, row); failedIds.add(row.id) }
      }
      for (const id of ids(report.failedIds)) {
        failedIds.add(id)
        if (!recordFailures.has(id)) recordFailures.set(id, { id, reason: refusal(report.failed?.[0]) })
      }
    }
    let last = await memory.bridge.sync(() => memory.ledger(), { budget: 0, removeStale: false, preserveQuarantined: true })
    rememberFailures(last)
    let reason = 'complete', batches = 0, audited = 0
    while (eligible(last) > 0 || audited < count(last.indexed)) {
      if (controller.signal.aborted || now() >= deadline) { reason = signal?.aborted ? 'interrupted' : 'time-limit'; break }
      const before = eligible(last), priorPending = new Set(ids(last.pendingIds))
      last = await memory.bridge.sync(() => memory.ledger(), { budget: 8, removeStale: false, preserveQuarantined: true,
        skipUris: [...skipped], verifyAcknowledged: before === 0, retryKnownBad: true, timeoutMs: 60_000 })
      batches++
      audited = eligible(last) > 0 ? 0 : audited + count(last.audit?.requests)
      rememberFailures(last)
      for (const uri of last.failedUris ?? []) if (typeof uri === 'string') skipped.add(uri)
      for (const id of [...failedIds]) if (priorPending.has(id) && !ids(last.failedIds).includes(id)) {
        failedIds.delete(id); recordFailures.delete(id)
      }
      onProgress({ indexed: count(last.indexed), pending: count(last.pending), failedIds: [...failedIds] })
      if (controller.signal.aborted) { reason = signal?.aborted ? 'interrupted' : 'time-limit'; break }
      if (last.audit?.failed?.length || last.audit?.tampered?.length) { reason = 'index-failed'; break }
      if (eligible(last) > 0 && eligible(last) >= before && !ids(last.failedIds).length && !count(last.added)
        && !count(last.audit?.requests)) { reason = 'no-progress'; break }
      if (eligible(last) === 0 && audited < count(last.indexed) && !count(last.audit?.requests) && !count(last.added)
        && !ids(last.failedIds).length) { reason = 'no-progress'; break }
    }
    if (failedIds.size) reason = reason === 'complete' ? 'record-failed' : reason
    const finalStore = memory.read()
    const skippedRows = []
    if (!finalStore.complete) {
      for (const note of finalStore.withheld ?? []) {
        const row = failureRow({ id: note.id, reason: note.recallRefusal })
        if (row) { skippedRows.push(row); failedIds.add(row.id); recordFailures.set(row.id, row) }
      }
      if (reason === 'complete') reason = 'memory-store-incomplete'
    }
    return { indexed: count(last.indexed), pending: count(last.pending), failedIds: [...failedIds].sort(), batches, reason,
      retryable: eligible(last), deferred: count(last.deferred),
      recordFailures: [...recordFailures.values()].sort((a, b) => a.id.localeCompare(b.id)),
      skippedIds: ids(skippedRows.map(row => row.id)), skipped: skippedRows.sort((a, b) => a.id.localeCompare(b.id)),
      ok: last.pending === 0 && failedIds.size === 0 && finalStore.complete && reason === 'complete' }
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', interrupted) }
}

if (isMainModule(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort()
  process.once('SIGINT', stop); process.once('SIGTERM', stop)
  try {
    const report = await syncRelease({ ...syncArgs(process.argv.slice(2)), signal: controller.signal,
      onProgress: row => process.stdout.write(`${syncLine(row)}\n`) })
    process.stdout.write(`${syncLine(report, true)} reason=${report.reason}\n`)
    const skipped = new Set(ids(report.skippedIds))
    for (const value of report.recordFailures) {
      const line = syncFailureLine(value, skipped.has(value.id))
      if (line) process.stdout.write(`${line}\n`)
    }
    process.exitCode = report.ok ? 0 : 1
  } catch (error) { process.stderr.write(`REFUSED: ${codeOf(error)}\n`); process.exitCode = 1 }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop) }
}
