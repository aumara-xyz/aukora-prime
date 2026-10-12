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
  return `${final ? 'kira-viking-sync' : 'progress'}: indexed=${count(report.indexed)} pending=${count(report.pending)} failed=${ids(report.failedIds).length}`
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
    if (OPERATOR_SYNC_VERSION !== 1) fail('release-sync-unsupported')
    const config = readBridgeConfig(effective.openVikingHome)
    if (!config.configured) fail('bridge-configuration-unavailable')
    const { createTrackedMemory } = await import(storeUrl)
    const memory = createTrackedMemory({ ...effective.memoryOwner, config, fetch: syncTransport(config, controller.signal, request) })
    const failedIds = new Set(), skipped = new Set()
    let last = await memory.bridge.sync(() => memory.ledger(), { budget: 0, removeStale: false, preserveQuarantined: true })
    let reason = 'complete', batches = 0, audited = 0
    while (last.pending > 0 || audited < count(last.indexed)) {
      if (controller.signal.aborted || now() >= deadline) { reason = signal?.aborted ? 'interrupted' : 'time-limit'; break }
      const before = count(last.pending), priorPending = new Set(ids(last.pendingIds))
      last = await memory.bridge.sync(() => memory.ledger(), { budget: 8, removeStale: false, preserveQuarantined: true,
        skipIds: [...skipped], verifyAcknowledged: true })
      batches++
      audited = last.pending > 0 ? 0 : audited + count(last.audit?.requests)
      for (const id of ids(last.failedIds)) failedIds.add(id)
      for (const id of [...failedIds]) if (priorPending.has(id) && !ids(last.pendingIds).includes(id)) failedIds.delete(id)
      onProgress({ indexed: count(last.indexed), pending: count(last.pending), failedIds: [...failedIds] })
      if (controller.signal.aborted) { reason = signal?.aborted ? 'interrupted' : 'time-limit'; break }
      if (last.failed?.length) {
        const recordRefused = last.failures?.length && last.failures.every(failure => [400, 413, 422].includes(failure.httpStatus))
        if (recordRefused) for (const id of ids(last.failedIds)) skipped.add(id)
        else { reason = 'index-failed'; break }
      }
      if (last.pending > 0 && count(last.pending) >= before && !ids(last.failedIds).some(id => skipped.has(id))) { reason = 'no-progress'; break }
    }
    if (failedIds.size) reason = reason === 'complete' ? 'record-failed' : reason
    const finalStore = memory.read()
    if (!finalStore.complete) {
      for (const id of ids(finalStore.withheld?.map(note => note.id))) failedIds.add(id)
      if (reason === 'complete') reason = 'memory-store-incomplete'
    }
    return { indexed: count(last.indexed), pending: count(last.pending), failedIds: [...failedIds].sort(), batches, reason,
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
    for (const id of ids(report.failedIds)) process.stdout.write(`failed-id: ${id}\n`)
    process.exitCode = report.ok ? 0 : 1
  } catch (error) { process.stderr.write(`REFUSED: ${codeOf(error)}\n`); process.exitCode = 1 }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop) }
}
